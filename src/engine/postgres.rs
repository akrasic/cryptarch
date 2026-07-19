//! PostgreSQL implementation of [`DbEngine`].
//!
//! Isolation model: each provisioned database gets its own `LOGIN` role that
//! *owns* the database, and `CONNECT` is revoked from `PUBLIC` so no other role
//! can reach it. Identifiers are validated by the caller against a strict
//! allowlist before they arrive here; we additionally quote them to make
//! injection-via-name impossible even if that guard ever regresses.

use super::{ConnString, DbEngine, DbStats, DbUsage, ServerOverview, TableInfo};
use anyhow::Context;
use async_trait::async_trait;
use sqlx::{postgres::PgPoolOptions, PgPool, Row};

/// Holds the admin connection to one managed Postgres server.
pub struct PostgresEngine {
    /// Admin pool — the connecting role must have `CREATEDB CREATEROLE`,
    /// and must **not** be a superuser.
    pool: PgPool,
    /// The admin DSN, kept to derive per-tenant-database connections for
    /// catalog reads (pg_class is not readable across databases).
    admin_dsn: String,
    /// Host:port, used to build the returned connection string.
    host: String,
    port: u16,
}

impl PostgresEngine {
    /// Connect to a managed server using its admin DSN.
    pub async fn connect(admin_dsn: &str, host: String, port: u16) -> anyhow::Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(admin_dsn)
            .await
            .context("connecting to managed Postgres server as admin")?;
        Ok(Self { pool, admin_dsn: admin_dsn.to_string(), host, port })
    }

    /// Postgres identifier quoting: wrap in double quotes, double any embedded
    /// quote. Combined with the caller's allowlist regex, this closes
    /// injection-via-identifier entirely.
    fn quote_ident(ident: &str) -> String {
        format!("\"{}\"", ident.replace('"', "\"\""))
    }

    /// The admin DSN pointed at `db` instead of its maintenance database.
    /// `db` has passed the strict name allowlist, so raw substitution is safe.
    fn tenant_dsn(&self, db: &str) -> String {
        swap_db_in_dsn(&self.admin_dsn, db)
    }

    async fn connect_tenant(&self, dsn: &str) -> anyhow::Result<PgPool> {
        Ok(PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(4))
            .connect(dsn)
            .await?)
    }

    /// Self-heal CONNECT access to a tenant database: the panel role holds
    /// non-inherited membership in the owner (granted at create time), so it
    /// may SET ROLE to the owner and grant itself CONNECT. Metadata access
    /// only — INHERIT FALSE means tenant *data* stays unreadable.
    async fn grant_self_connect(&self, name: &str) -> anyhow::Result<()> {
        let qrole = Self::quote_ident(name);
        let qdb = Self::quote_ident(name);
        let mut conn = self.pool.acquire().await.context("acquiring admin connection")?;
        let panel: String = sqlx::query_scalar("SELECT current_user::text")
            .fetch_one(&mut *conn)
            .await
            .context("reading panel role name")?;
        let qpanel = Self::quote_ident(&panel);
        // Defensive for tenants created before the membership grant existed;
        // failure is fine — SET ROLE below reports honestly.
        let _ = sqlx::query(&format!(
            "GRANT {qrole} TO CURRENT_USER WITH INHERIT FALSE, SET TRUE"
        ))
        .execute(&mut *conn)
        .await;
        sqlx::query(&format!("SET ROLE {qrole}"))
            .execute(&mut *conn)
            .await
            .context("becoming tenant owner for CONNECT grant")?;
        let grant = sqlx::query(&format!("GRANT CONNECT ON DATABASE {qdb} TO {qpanel}"))
            .execute(&mut *conn)
            .await;
        let _ = sqlx::query("RESET ROLE").execute(&mut *conn).await;
        grant.context("granting CONNECT on tenant database")?;
        Ok(())
    }

    /// Catalog-level table list, largest first. Requires entering the tenant
    /// database — pg_class is per-database.
    async fn table_list(&self, name: &str) -> anyhow::Result<Vec<TableInfo>> {
        let dsn = self.tenant_dsn(name);
        let pool = match self.connect_tenant(&dsn).await {
            Ok(p) => p,
            Err(first) => {
                // Likely "no CONNECT privilege" — heal and retry once.
                self.grant_self_connect(name)
                    .await
                    .with_context(|| format!("tenant connect failed ({first}); self-grant also failed"))?;
                self.connect_tenant(&dsn)
                    .await
                    .context("connecting to tenant database after CONNECT self-grant")?
            }
        };
        let rows = sqlx::query(
            "SELECT c.relname::text, c.reltuples::bigint, pg_total_relation_size(c.oid) \
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE c.relkind IN ('r', 'p') \
               AND n.nspname NOT IN ('pg_catalog', 'information_schema') \
             ORDER BY pg_total_relation_size(c.oid) DESC, c.relname \
             LIMIT 500",
        )
        .fetch_all(&pool)
        .await
        .context("listing tenant tables");
        pool.close().await;
        Ok(rows?
            .into_iter()
            .map(|r| TableInfo { name: r.get(0), approx_rows: r.get(1), total_bytes: r.get(2) })
            .collect())
    }

    fn conn_string(&self, role: &str, password: &str, db: &str) -> ConnString {
        // IPv6 advertised hosts need brackets or libpq misparses the URL.
        let host: std::borrow::Cow<str> = if self.host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{}]", self.host).into()
        } else {
            (&self.host).into()
        };
        ConnString(format!(
            "postgresql://{role}:{password}@{host}:{port}/{db}",
            port = self.port,
        ))
    }
}

/// Rewrite a Postgres DSN to point at `db`, preserving userinfo, host, and any
/// query string. The path is the first `/` *after* the `@` — a password that
/// itself contains `/` (raw, unencoded) must not be mistaken for the path
/// separator. `db` is name-allowlisted by the caller, so raw substitution is
/// safe.
fn swap_db_in_dsn(dsn: &str, db: &str) -> String {
    let (base, query) = match dsn.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (dsn, None),
    };
    let authority_start = base.find("://").map(|i| i + 3).unwrap_or(0);
    // Userinfo (which may carry a raw '/') ends at '@'; start the path search
    // there when present, so only the real host/path '/' is found.
    let path_search_from = base[authority_start..]
        .find('@')
        .map(|at| authority_start + at + 1)
        .unwrap_or(authority_start);
    let trimmed = match base[path_search_from..].find('/') {
        Some(rel) => &base[..path_search_from + rel],
        None => base,
    };
    match query {
        Some(q) => format!("{trimmed}/{db}?{q}"),
        None => format!("{trimmed}/{db}"),
    }
}

#[async_trait]
impl DbEngine for PostgresEngine {
    fn kind(&self) -> &'static str {
        "postgres"
    }

    async fn create_user_db(&self, name: &str, password: &str) -> anyhow::Result<ConnString> {
        let role = name;
        let db = name;
        let qrole = Self::quote_ident(role);
        let qdb = Self::quote_ident(db);

        // Send the SCRAM verifier, never the plaintext. A literal password in
        // CREATE/ALTER ROLE lands in the managed server's statement logs (and
        // sqlx's slow-query WARN logs); the verifier is the stored form, so the
        // role still authenticates with the plaintext we hand back in the
        // connection string. Same posture the auth role uses in edge.rs. The
        // verifier is ASCII base64/`$`/`:` — no single quotes to escape.
        let verifier = postgres_protocol::password::scram_sha_256(password.as_bytes());

        sqlx::query(&format!("CREATE ROLE {qrole} LOGIN PASSWORD '{verifier}'"))
            .execute(&self.pool)
            .await
            .context("creating login role")?;

        // The panel role is deliberately NOT superuser, and on PG16+
        // CREATEROLE no longer implies it can act as the roles it creates:
        // CREATE DATABASE ... OWNER requires membership in the owning role.
        // INHERIT FALSE is load-bearing: the panel role must NOT passively
        // hold every tenant's privileges (that would hand a leaked panel DSN
        // full read/write on all tenant data). SET TRUE lets lifecycle ops
        // (drop) explicitly become the tenant when needed. Verified on PG17:
        // this combination creates-as-owner but does not inherit.
        if let Err(e) = sqlx::query(&format!(
            "GRANT {qrole} TO CURRENT_USER WITH INHERIT FALSE, SET TRUE"
        ))
        .execute(&self.pool)
        .await
        {
            let _ = sqlx::query(&format!("DROP ROLE IF EXISTS {qrole}")).execute(&self.pool).await;
            return Err(anyhow::Error::new(e).context("granting new role to panel role"));
        }

        // From here on, clean up the role on failure — an orphaned role
        // otherwise blocks every retry of the same name with a confusing
        // "role already exists".
        if let Err(e) = sqlx::query(&format!("CREATE DATABASE {qdb} OWNER {qrole}"))
            .execute(&self.pool)
            .await
        {
            let _ = sqlx::query(&format!("DROP ROLE IF EXISTS {qrole}")).execute(&self.pool).await;
            return Err(anyhow::Error::new(e).context("creating database"));
        }

        // Lock the new database down to its owner only.
        if let Err(e) = sqlx::query(&format!("REVOKE CONNECT ON DATABASE {qdb} FROM PUBLIC"))
            .execute(&self.pool)
            .await
        {
            let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {qdb} WITH (FORCE)"))
                .execute(&self.pool)
                .await;
            let _ = sqlx::query(&format!("DROP ROLE IF EXISTS {qrole}")).execute(&self.pool).await;
            return Err(anyhow::Error::new(e).context("revoking public connect"));
        }

        Ok(self.conn_string(role, password, db))
    }

    async fn drop_user_db(&self, name: &str) -> anyhow::Result<()> {
        let qrole = Self::quote_ident(name);
        let qdb = Self::quote_ident(name);
        // DROP DATABASE requires *ownership*, which non-inherited membership
        // does not confer — so we SET ROLE to the owner for the drop. This
        // needs one dedicated connection: SET ROLE is session state, and
        // DROP DATABASE refuses to run inside a multi-statement transaction.
        let mut conn = self.pool.acquire().await.context("acquiring admin connection")?;
        // Defensive for roles provisioned before the membership grant existed
        // (superuser-era rows). Ignore failure — role may be gone entirely.
        let _ = sqlx::query(&format!(
            "GRANT {qrole} TO CURRENT_USER WITH INHERIT FALSE, SET TRUE"
        ))
        .execute(&mut *conn)
        .await;
        // SET ROLE failing (role already dropped) is fine — the DROP DATABASE
        // below then runs as the panel role and reports honestly if it can't.
        let became_owner = sqlx::query(&format!("SET ROLE {qrole}"))
            .execute(&mut *conn)
            .await
            .is_ok();
        let drop_db = sqlx::query(&format!("DROP DATABASE IF EXISTS {qdb} WITH (FORCE)"))
            .execute(&mut *conn)
            .await;
        if became_owner {
            let _ = sqlx::query("RESET ROLE").execute(&mut *conn).await;
        }
        drop_db.context("dropping database")?;
        sqlx::query(&format!("DROP ROLE IF EXISTS {qrole}"))
            .execute(&mut *conn)
            .await
            .context("dropping role")?;
        Ok(())
    }

    async fn set_login(&self, name: &str, enabled: bool) -> anyhow::Result<()> {
        let qrole = Self::quote_ident(name);
        let clause = if enabled { "LOGIN" } else { "NOLOGIN" };
        sqlx::query(&format!("ALTER ROLE {qrole} {clause}"))
            .execute(&self.pool)
            .await
            .context("toggling role login")?;
        Ok(())
    }

    async fn rotate_password(&self, name: &str, password: &str) -> anyhow::Result<ConnString> {
        let qrole = Self::quote_ident(name);
        // SCRAM verifier, not plaintext — see create_user_db. Keeps the rotated
        // password out of the managed server's statement logs.
        let verifier = postgres_protocol::password::scram_sha_256(password.as_bytes());
        sqlx::query(&format!("ALTER ROLE {qrole} PASSWORD '{verifier}'"))
            .execute(&self.pool)
            .await
            .context("rotating role password")?;
        Ok(self.conn_string(name, password, name))
    }

    async fn stats(&self, name: &str) -> anyhow::Result<DbStats> {
        // pg_database_size takes the db name as a value — safe to bind.
        let size: i64 = sqlx::query("SELECT pg_database_size($1)")
            .bind(name)
            .fetch_one(&self.pool)
            .await
            .context("reading database size")?
            .get(0);

        let active: bool =
            sqlx::query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname = $1)")
                .bind(name)
                .fetch_one(&self.pool)
                .await
                .context("reading activity")?
                .get(0);

        // Size and activity are cross-database reads and always work; the
        // table list needs a way INTO the tenant db and may not have one
        // (e.g. a tenant provisioned by a different role). Degrade to None
        // rather than failing the whole stats read.
        let tables = match self.table_list(name).await {
            Ok(t) => Some(t),
            Err(e) => {
                tracing::warn!("table list for '{name}' unavailable: {e:#}");
                None
            }
        };

        Ok(DbStats {
            size_bytes: size,
            active,
            tables,
        })
    }

    async fn server_overview(&self) -> anyhow::Result<ServerOverview> {
        let row = sqlx::query(
            "SELECT current_setting('server_version'), \
                    EXTRACT(EPOCH FROM now() - pg_postmaster_start_time())::bigint, \
                    (SELECT COUNT(*) FROM pg_stat_activity), \
                    current_setting('max_connections')::bigint",
        )
        .fetch_one(&self.pool)
        .await
        .context("reading server overview")?;
        let (version, uptime_secs, total_connections, max_connections): (String, i64, i64, i64) =
            (row.get(0), row.get(1), row.get(2), row.get(3));

        let databases = sqlx::query(
            "SELECT d.datname::text, pg_database_size(d.datname), \
                    (SELECT COUNT(*) FROM pg_stat_activity a WHERE a.datname = d.datname) \
             FROM pg_database d WHERE NOT d.datistemplate \
             ORDER BY pg_database_size(d.datname) DESC",
        )
        .fetch_all(&self.pool)
        .await
        .context("reading per-database usage")?
        .into_iter()
        .map(|r| DbUsage { name: r.get(0), size_bytes: r.get(1), connections: r.get(2) })
        .collect();

        Ok(ServerOverview {
            version,
            uptime_secs,
            total_connections,
            max_connections,
            databases,
        })
    }

    async fn ping(&self) -> anyhow::Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_ident_doubles_embedded_quotes() {
        assert_eq!(PostgresEngine::quote_ident("alice_app"), "\"alice_app\"");
        assert_eq!(PostgresEngine::quote_ident("a\"b"), "\"a\"\"b\"");
    }

    #[test]
    fn swap_db_preserves_authority_and_query() {
        assert_eq!(
            swap_db_in_dsn("postgres://admin:pw@10.0.0.5:5432/postgres", "alice_app"),
            "postgres://admin:pw@10.0.0.5:5432/alice_app"
        );
        assert_eq!(
            swap_db_in_dsn("postgres://admin:pw@10.0.0.5:5432/postgres?sslmode=require", "alice_app"),
            "postgres://admin:pw@10.0.0.5:5432/alice_app?sslmode=require"
        );
    }

    #[test]
    fn swap_db_handles_slash_in_password() {
        // A raw '/' in the password must not be read as the path separator.
        assert_eq!(
            swap_db_in_dsn("postgres://admin:p/w@10.0.0.5:5432/postgres", "alice_app"),
            "postgres://admin:p/w@10.0.0.5:5432/alice_app"
        );
        // No path in the source DSN: append one.
        assert_eq!(
            swap_db_in_dsn("postgres://admin:a/b@host:5432", "alice_app"),
            "postgres://admin:a/b@host:5432/alice_app"
        );
    }
}

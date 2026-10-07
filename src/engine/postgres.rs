//! PostgreSQL implementation of [`DbEngine`].
//!
//! Isolation model: each provisioned database gets its own `LOGIN` role that
//! *owns* the database, and `CONNECT` is revoked from `PUBLIC` so no other role
//! can reach it.
//!
//! # Injection safety: quoting is the guarantee, validation is the belt
//!
//! Identifiers cannot be bind parameters, so this module builds DDL by
//! interpolation. Every such site is wrapped in [`sqlx::AssertSqlSafe`], which
//! is sqlx 0.9's marker for "a human audited this" — not a formality. What that
//! audit rests on, stated in the order that is actually true:
//!
//! 1. **`quote_ident` / `quote_literal` carry the safety, universally.** Every
//!    interpoland at every site goes through one of them. This alone is what
//!    makes injection-via-name impossible.
//! 2. **`names::valid_db_name` is defence in depth, and is NOT universal.** It
//!    guards tenant-supplied names. It is deliberately absent on `qpanel`
//!    (read back from `SELECT current_user`) and on the CRYPTARCH-78 repair
//!    marker, which *fails* the allowlist on purpose — `repair.rs` asserts
//!    `!valid_db_name(REPAIR_MARKER_ROLE)` so a tenant can never provision a
//!    name that collides with it.
//!
//! Getting that order backwards is the live hazard: if the guarantee is
//! recorded as "these are safe because they were validated", a later editor
//! who sees an already-validated value may drop the quoting as redundant. That
//! is harmless at the tenant-name sites and fatal at `qpanel` and the marker,
//! where the validation was never there to fall back on. **Do not remove
//! quoting because a value looks pre-validated.**
//!
//! `quote_ident` is complete for every input except an interior NUL, which
//! cannot be escaped in an identifier — a NUL truncates the query at the wire
//! protocol and yields a syntax error, not an injection. It fails safe.
//!
//! The sibling surface with the *opposite* guard is [`swap_db_in_dsn`]: a
//! connection-string path component cannot be quoted at all, so that one is
//! carried by `valid_db_name` alone. Do not generalise this module's
//! "quoting is the guarantee" rule onto it.

use super::{
    ConnString, DbEngine, DbStats, DbUsage, DumpStream, MaintenanceFinding, MaintenanceReport,
    RestoreSink, ServerOverview, Severity, Survey, TableInfo,
};
use anyhow::Context;
use async_trait::async_trait;
use sqlx::{postgres::PgPoolOptions, AssertSqlSafe, PgPool, Row};

/// Scrubs session state from a connection being returned to the pool.
///
/// Two statements, so it CANNOT be prepared and must go through `sqlx::raw_sql`
/// — see `pool_options`. Named rather than inlined so the test that proves it
/// executes runs this exact string.
pub const POOL_RESET_SQL: &str = "RESET ROLE; RESET ALL; CLOSE ALL";

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
    /// How long a restore may wait on any one lock; see [`RESTORE_LOCK_WAIT`].
    restore_lock_wait: std::time::Duration,
}

impl PostgresEngine {
    /// Override [`RESTORE_LOCK_WAIT`]. For tests, which cannot spend fifteen
    /// seconds proving a bound.
    pub fn with_restore_lock_wait(mut self, wait: std::time::Duration) -> Self {
        self.restore_lock_wait = wait;
        self
    }

    /// Connect to a managed server using its admin DSN.
    pub async fn connect(admin_dsn: &str, host: String, port: u16) -> anyhow::Result<Self> {
        let pool = Self::pool_options()
            .connect(admin_dsn)
            .await
            .context("connecting to managed Postgres server as admin")?;
        Ok(Self {
            pool,
            admin_dsn: admin_dsn.to_string(),
            host,
            port,
            restore_lock_wait: RESTORE_LOCK_WAIT,
        })
    }

    /// Pool configuration for every managed-server connection (CRYPTARCH-83).
    ///
    /// Public so tests exercise the real configuration rather than a
    /// hand-rolled copy that could drift from it.
    ///
    /// # Why session state is scrubbed on release
    ///
    /// This codebase issues `SET ROLE` on pooled connections — `drop_user_db`
    /// becomes the tenant to drop their database, and the edge bootstrap
    /// becomes the auth role to verify the shim. Both unwind it, but
    /// correctness then depends on every `SET ROLE` site remembering to unwind
    /// itself on *every* path, forever. One did not: a `?` on a probe returned
    /// before its `RESET ROLE`, dropping a connection back into the admin pool
    /// still wearing the auth role.
    ///
    /// A leaked role is quiet and awful: later admin work runs as a role with
    /// almost no privileges, provisioning fails on `CREATE ROLE`
    /// *intermittently* depending on which connection it draws, and the
    /// symptom surfaces in a different feature from the cause. It also made
    /// the Tier B survey enumerate the wrong role's memberships and return
    /// empty — "checked, none found" having never asked.
    ///
    /// So the pool removes the state rather than trusting call sites: a
    /// connection cannot re-enter it carrying session state, and the third
    /// `SET ROLE` site does not need to be careful.
    ///
    /// # `RESET ALL`, deliberately not `DISCARD ALL`
    ///
    /// `DISCARD ALL` is the tempting one because it sounds the most thorough,
    /// and the thoroughness is what breaks it: it includes `DEALLOCATE ALL`,
    /// while sqlx caches prepared statements *per connection*. Deallocating
    /// behind that cache leaves it naming statements the server no longer has,
    /// and a later query on that connection fails with "prepared statement
    /// does not exist".
    ///
    /// That failure needs a *reused* connection which has already prepared
    /// something — so a fresh-connection test passes cleanly and production
    /// does not. `CLOSE ALL` adds cursor cleanup and is also cache-safe.
    ///
    /// # `RESET ROLE` is separate, and its absence was the original bug
    ///
    /// This used to be `RESET ALL; CLOSE ALL`, on the stated reasoning that
    /// "`SET ROLE` sets the `role` GUC, and `RESET ALL` restores every
    /// configuration parameter to its default". **That is false.** `RESET ALL`
    /// leaves `role` exactly where `SET ROLE` put it; only `RESET ROLE` clears
    /// it. Verified directly against Postgres 17:
    ///
    /// ```text
    /// SET ROLE probe;   -- current_role = probe
    /// RESET ALL;        -- current_role = probe   <-- still
    /// RESET ROLE;       -- current_role = postgres
    /// ```
    ///
    /// So the scrub never removed the one piece of state it was written to
    /// remove. What actually protected the pool was the FALLBACK: the reset
    /// statement itself was failing, the handler retired the connection, and a
    /// retired connection cannot leak anything. The guard worked; the mechanism
    /// named in its own comment did not.
    ///
    /// That is also why `a_released_connection_cannot_keep_a_set_role` passed
    /// for years: it never distinguished "scrubbed and reused" from "thrown
    /// away", and only the second was ever happening. It now asserts the
    /// connection is the same one, so it can only pass through the mechanism it
    /// claims to test.
    ///
    /// # `raw_sql`, not `query` — and why that is not a style choice
    ///
    /// These are TWO statements, and `query()` prepares. Postgres refuses
    /// multiple commands in a prepared statement, so `query()` fails here with
    /// "cannot insert multiple commands into a prepared statement". Under sqlx
    /// 0.8 it happened to work: a query with no bind parameters took the
    /// unprepared path. 0.9 always prepares, which turned this into a failure
    /// the moment the dependency moved.
    ///
    /// The failure was invisible in tests because it is deliberately swallowed
    /// — the handler returns `Ok(false)`, which RETIRES the connection instead
    /// of returning a possibly-dirty one. That is the safe direction, so
    /// nothing broke and nothing failed. It just meant every pooled connection
    /// to every managed server was thrown away after a single use, which is
    /// precisely the churn this pool exists to avoid. It surfaced as a WARN on
    /// a real boot, not in the suite.
    ///
    /// `raw_sql` is the API for statement lists: it does not prepare and does
    /// not cache. `POOL_RESET_SQL` is a named const so the test can exercise
    /// the real statement rather than a copy that can drift from it.
    pub fn pool_options() -> PgPoolOptions {
        PgPoolOptions::new().max_connections(4).after_release(|conn, _meta| {
            Box::pin(async move {
                sqlx::raw_sql(POOL_RESET_SQL)
                    .execute(&mut *conn)
                    .await
                    .map(|_| true)
                    .or_else(|e| {
                        // Returning false retires the connection instead of
                        // returning a possibly-dirty one to the pool. Failing
                        // open here would reintroduce exactly the leak.
                        tracing::warn!("could not reset a pooled connection ({e}); retiring it");
                        Ok(false)
                    })
            })
        })
    }

    /// Postgres identifier quoting: wrap in double quotes, double any embedded
    /// quote. Combined with the caller's allowlist regex, this closes
    /// injection-via-identifier entirely.
    fn quote_ident(ident: &str) -> String {
        format!("\"{}\"", ident.replace('"', "\"\""))
    }

    /// Postgres string-literal quoting: wrap in single quotes, double any
    /// embedded quote. Needed because `COMMENT ON ROLE … IS` takes a literal
    /// and DDL cannot use bind parameters — the same reason identifiers get
    /// `quote_ident`. Only ever applied to text this crate owns; it is not a
    /// licence to put user input in DDL.
    pub(crate) fn quote_literal(text: &str) -> String {
        format!("'{}'", text.replace('\'', "''"))
    }

    /// The admin DSN pointed at `db` instead of its maintenance database.
    ///
    /// Fallible because the name allowlist is enforced inside `swap_db_in_dsn`
    /// rather than assumed of callers — see the note there. A name that cannot
    /// be safely placed in a DSN path yields no DSN at all.
    fn tenant_dsn(&self, db: &str) -> anyhow::Result<String> {
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
        let _ = sqlx::query(AssertSqlSafe(format!(
            "GRANT {qrole} TO CURRENT_USER WITH INHERIT FALSE, SET TRUE"
        )))
        .execute(&mut *conn)
        .await;
        sqlx::query(AssertSqlSafe(format!("SET ROLE {qrole}")))
            .execute(&mut *conn)
            .await
            .context("becoming tenant owner for CONNECT grant")?;
        let grant = sqlx::query(AssertSqlSafe(format!("GRANT CONNECT ON DATABASE {qdb} TO {qpanel}")))
            .execute(&mut *conn)
            .await;
        let _ = sqlx::query("RESET ROLE").execute(&mut *conn).await;
        grant.context("granting CONNECT on tenant database")?;
        Ok(())
    }

    /// Catalog-level table list, largest first. Requires entering the tenant
    /// database — pg_class is per-database.
    async fn table_list(&self, name: &str) -> anyhow::Result<Vec<TableInfo>> {
        let dsn = self.tenant_dsn(name)?;
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

    /// Read one optional `pg_database` column, recording WHY if it cannot be
    /// read rather than folding the failure into an indistinguishable `None`.
    ///
    /// `column` is a literal from this file, never caller input — it cannot be
    /// a bind parameter and must never become one. `&'static str` rather than
    /// `&str` is what makes that a guarantee instead of a promise: the type
    /// rejects a runtime-built column name at the call site, the same way
    /// `JobLog::table` does in backup.rs. Do not widen it.
    async fn optional_db_column(
        &self,
        name: &str,
        column: &'static str,
    ) -> crate::manifest::Recorded<String> {
        match sqlx::query_scalar::<_, Option<String>>(AssertSqlSafe(format!(
            "SELECT {column} FROM pg_database WHERE datname = $1"
        )))
        .bind(name)
        .fetch_one(&self.pool)
        .await
        {
            Ok(v) => crate::manifest::Recorded::Value(v),
            Err(e) => crate::manifest::Recorded::NotRecorded {
                why: format!("{column} could not be read: {e}"),
            },
        }
    }

    /// Extensions and whether each can be created without a superuser.
    async fn survey_extensions(
        &self,
        pool: &PgPool,
    ) -> anyhow::Result<Vec<crate::manifest::Extension>> {
        Ok(sqlx::query(
            "SELECT e.extname::text, e.extversion, \
                    COALESCE(av.trusted, false) \
             FROM pg_extension e \
             LEFT JOIN pg_available_extension_versions av \
                    ON av.name = e.extname AND av.version = e.extversion \
             WHERE e.extname <> 'plpgsql' ORDER BY e.extname",
        )
        .fetch_all(pool)
        .await
        .context("listing extensions")?
        .into_iter()
        .map(|r| crate::manifest::Extension {
            name: r.get(0),
            version: r.get(1),
            trusted: r.get(2),
        })
        .collect())
    }

    /// Everything that makes restoring under a different identity risky.
    ///
    /// Note what is NOT selected: `pg_policies.qual`. Policy expressions embed
    /// literals — `USING (tenant_id = 'acme-corp')` is tenant data — and this
    /// record is described to operators as containing none.
    async fn survey_hazards(
        &self,
        pool: &PgPool,
        owner: &str,
    ) -> anyhow::Result<crate::manifest::Hazards> {
        let rls = sqlx::query(
            "SELECT c.relname::text, c.relrowsecurity, c.relforcerowsecurity \
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE c.relkind IN ('r','p') AND c.relrowsecurity \
               AND n.nspname NOT IN ('pg_catalog','information_schema')",
        )
        .fetch_all(pool)
        .await
        .context("listing row-level security")?;
        let mut rls_tables = Vec::new();
        let mut force_rls_tables = Vec::new();
        for r in rls {
            let name: String = r.get(0);
            if r.get::<bool, _>(2) {
                force_rls_tables.push(name.clone());
            }
            if r.get::<bool, _>(1) {
                rls_tables.push(name);
            }
        }

        let policies = sqlx::query(
            // polroles is never empty: `TO PUBLIC` is stored as {0}. Filtering
            // oid 0 out made an empty role list silently encode "applies to
            // everyone" — absence encoding a meaning, in the feature built to
            // eliminate exactly that. PUBLIC is recorded by name.
            "SELECT p.polname::text, c.relname::text, \
                    COALESCE(ARRAY(SELECT CASE WHEN u = 0 THEN 'PUBLIC' \
                                               ELSE pg_get_userbyid(u) END \
                                   FROM unnest(p.polroles) u), '{}')::text[] \
             FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid ORDER BY c.relname, p.polname",
        )
        .fetch_all(pool)
        .await
        .context("listing policies")?
        .into_iter()
        .map(|r| crate::manifest::PolicyRef {
            name: r.get(0),
            table: r.get(1),
            roles: r.get(2),
        })
        .collect();

        // Grants to anyone other than the owner: on the deleted-database restore
        // path these REPLAY, and a grant naming a role that no longer exists
        // aborts the whole restore under --single-transaction.
        //
        // Read from the catalogs rather than information_schema.role_table_grants,
        // which by definition shows only grants where the grantor or grantee is a
        // CURRENTLY ENABLED role — a grant between two tenant roles the panel is
        // not a member of would be invisible, and invisible renders as an empty
        // list, which renders as "no hazards".
        //
        // Spanning several catalogs, not just tables: a restore replays grants on
        // sequences, foreign tables, schemas, functions and default ACLs too, so
        // enumerating only relkind r/p/v/m would let a role named in a sequence
        // grant pass a pre-flight and then abort the restore. Sequences in
        // particular are ordinary in real applications.
        //
        // grantor is deliberately NOT compared: `grantor <> grantee` was redundant
        // (grantee <> owner already excludes the owner's self-grant) and it dropped
        // a real hazard — after an ownership change the old owner's self-granted
        // ACL entry has grantor = grantee, and that role is no longer the owner.
        //
        // PUBLIC (grantee oid 0) is excluded on purpose: it always exists, so it
        // always resolves. See the scope note in manifest.rs — that is an exposure
        // question, not an identity one.
        //
        // Database-level ACLs are absent because pg_dump only emits them under
        // --create, which this never uses.
        let non_owner_grants = sqlx::query(
            "WITH acls AS ( \
                 SELECT CASE c.relkind WHEN 'S' THEN 'sequence' WHEN 'v' THEN 'view' \
                                       WHEN 'm' THEN 'matview' WHEN 'f' THEN 'foreign table' \
                                       ELSE 'table' END AS kind, \
                        c.relname::text AS object, a.grantee, a.privilege_type \
                 FROM pg_class c \
                 JOIN pg_namespace n ON n.oid = c.relnamespace \
                 CROSS JOIN LATERAL aclexplode(c.relacl) a \
                 WHERE c.relkind IN ('r','p','v','m','S','f') \
                   AND n.nspname NOT IN ('pg_catalog','information_schema') \
                 UNION ALL \
                 SELECT 'schema', n.nspname::text, a.grantee, a.privilege_type \
                 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) a \
                 WHERE n.nspname NOT IN ('pg_catalog','information_schema') \
                 UNION ALL \
                 SELECT 'function', p.proname::text, a.grantee, a.privilege_type \
                 FROM pg_proc p \
                 JOIN pg_namespace n ON n.oid = p.pronamespace \
                 CROSS JOIN LATERAL aclexplode(p.proacl) a \
                 WHERE n.nspname NOT IN ('pg_catalog','information_schema') \
                 UNION ALL \
                 SELECT 'default', d.defaclobjtype::text, a.grantee, a.privilege_type \
                 FROM pg_default_acl d CROSS JOIN LATERAL aclexplode(d.defaclacl) a \
             ) \
             SELECT kind, object, pg_get_userbyid(grantee)::text, privilege_type::text \
             FROM acls \
             WHERE grantee <> 0 AND pg_get_userbyid(grantee) <> $1 \
             ORDER BY 1, 2, 3, 4",
        )
        .bind(owner)
        .fetch_all(pool)
        .await
        .context("listing grants")?
        .into_iter()
        .map(|r| crate::manifest::GrantRef {
            kind: r.get(0),
            object: r.get(1),
            grantee: r.get(2),
            privilege: r.get(3),
        })
        .collect();

        let security_definer_functions = sqlx::query(
            "SELECT p.proname::text FROM pg_proc p \
             JOIN pg_namespace n ON n.oid = p.pronamespace \
             WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog','information_schema') \
             ORDER BY p.proname",
        )
        .fetch_all(pool)
        .await
        .context("listing security definer functions")?
        .into_iter()
        .map(|r| r.get(0))
        .collect();

        // Foreign servers keep a dbname in their options, which still points at
        // the ORIGINAL database after a restore.
        let foreign_servers = sqlx::query("SELECT srvname::text FROM pg_foreign_server ORDER BY 1")
            .fetch_all(pool)
            .await
            .context("listing foreign servers")?
            .into_iter()
            .map(|r| r.get(0))
            .collect();

        let event_triggers = sqlx::query("SELECT evtname::text FROM pg_event_trigger ORDER BY 1")
            .fetch_all(pool)
            .await
            .context("listing event triggers")?
            .into_iter()
            .map(|r| r.get(0))
            .collect();

        let large_objects: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_largeobject_metadata")
            .fetch_one(pool)
            .await
            .unwrap_or(0);

        Ok(crate::manifest::Hazards {
            rls_tables,
            force_rls_tables,
            policies,
            non_owner_grants,
            security_definer_functions,
            foreign_servers,
            event_triggers,
            large_objects,
        })
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
/// separator.
///
/// # This is the one interpolation surface with a single guard (CRYPTARCH-91)
///
/// Everywhere else in this module, safety is carried by `quote_ident` and
/// `valid_db_name` is defence in depth (see the module docs). Here it is the
/// reverse, and there is no second layer: a connection-string path component
/// **cannot be quoted**. There is no escaping construct to fall back on, so
/// `valid_db_name` is not a belt — it is the whole guarantee.
///
/// What a name that skipped it could do is not SQL injection, it is worse in
/// kind: `?` starts the parameter list, `@` restarts the authority, and `/`
/// re-cuts the path — so `evil?host=attacker.example` or `x@attacker.example/y`
/// redirects where the panel CONNECTS, sending admin credentials to a server of
/// the attacker's choosing. `valid_db_name` admits only `[a-z][a-z0-9_]*`,
/// which contains none of those characters.
///
/// So the check happens HERE rather than being assumed of callers. It used to
/// be a sentence in this comment asserting the callers had done it; a comment
/// is not a guard, and this is the last place to notice before the bytes become
/// a connection. `&'static str` cannot express it — `db` is a runtime tenant
/// name — so the enforcement has to be a runtime check that fails closed.
///
/// Note `_cryptarch_meta` deliberately fails `valid_db_name` and never reaches
/// here: its backup uses the metadata DSN directly, not a tenant DSN.
fn swap_db_in_dsn(dsn: &str, db: &str) -> anyhow::Result<String> {
    anyhow::ensure!(
        crate::names::valid_db_name(db),
        "refusing to build a connection string for '{db}': it is not an allowlisted \
         database name, and a DSN path cannot be quoted"
    );
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
    Ok(match query {
        Some(q) => format!("{trimmed}/{db}?{q}"),
        None => format!("{trimmed}/{db}"),
    })
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
        // connection string. Same posture the auth role uses in edge.rs.
        //
        // SCRAM output is ASCII base64/`$`/`:` and so cannot contain a single
        // quote whatever the password was — but that is a remembered fact
        // about another crate's output, so it goes through `quote_literal`
        // anyway. Same reasoning as `column: &'static str` above: prefer the
        // enforced guard over the correct memory.
        let verifier = Self::quote_literal(&postgres_protocol::password::scram_sha_256(
            password.as_bytes(),
        ));

        sqlx::query(AssertSqlSafe(format!("CREATE ROLE {qrole} LOGIN PASSWORD {verifier}")))
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
        if let Err(e) = sqlx::query(AssertSqlSafe(format!(
            "GRANT {qrole} TO CURRENT_USER WITH INHERIT FALSE, SET TRUE"
        )))
        .execute(&self.pool)
        .await
        {
            let _ = sqlx::query(AssertSqlSafe(format!("DROP ROLE IF EXISTS {qrole}"))).execute(&self.pool).await;
            return Err(anyhow::Error::new(e).context("granting new role to panel role"));
        }

        // From here on, clean up the role on failure — an orphaned role
        // otherwise blocks every retry of the same name with a confusing
        // "role already exists".
        if let Err(e) = sqlx::query(AssertSqlSafe(format!("CREATE DATABASE {qdb} OWNER {qrole}")))
            .execute(&self.pool)
            .await
        {
            let _ = sqlx::query(AssertSqlSafe(format!("DROP ROLE IF EXISTS {qrole}"))).execute(&self.pool).await;
            return Err(anyhow::Error::new(e).context("creating database"));
        }

        // Lock the new database down to its owner only.
        if let Err(e) = sqlx::query(AssertSqlSafe(format!("REVOKE CONNECT ON DATABASE {qdb} FROM PUBLIC")))
            .execute(&self.pool)
            .await
        {
            let _ = sqlx::query(AssertSqlSafe(format!("DROP DATABASE IF EXISTS {qdb} WITH (FORCE)")))
                .execute(&self.pool)
                .await;
            let _ = sqlx::query(AssertSqlSafe(format!("DROP ROLE IF EXISTS {qrole}"))).execute(&self.pool).await;
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

        // CRYPTARCH-79 — FAIL SAFE, FIRST. Everything below can fail partway,
        // and until this runs, a failure leaves a *working credential for a
        // database that is being deleted*. The database is dropped WITH
        // (FORCE) below, so a surviving role protects nothing: the only thing
        // it can still do is authenticate.
        //
        // Runs as the PANEL role, deliberately outside the SET ROLE block
        // below — the panel holds ADMIN OPTION on tenant roles, so it may
        // ALTER them, and putting this inside the block would couple the
        // security step to the ownership dance succeeding.
        //
        // Ignoring the error here would defeat the point, so it propagates.
        // A failure at this step is the safe one: nothing has been destroyed,
        // the database still works, and the caller reports a failed delete.
        // Note the residue is then a `deleting` row over a live database with
        // an enabled role — invisible to the Tier B login report by
        // construction, because there is no disabled login to report. That
        // state belongs to the stranded-`deleting` sweep and the portal-side
        // retry (CRYPTARCH-80), which answers a different question: "Cryptarch
        // started something and did not finish."
        sqlx::query(AssertSqlSafe(format!("ALTER ROLE {qrole} NOLOGIN")))
            .execute(&mut *conn)
            .await
            .context("disabling login before dropping")?;

        // Defensive for roles provisioned before the membership grant existed
        // (superuser-era rows). Ignore failure — role may be gone entirely.
        let _ = sqlx::query(AssertSqlSafe(format!(
            "GRANT {qrole} TO CURRENT_USER WITH INHERIT FALSE, SET TRUE"
        )))
        .execute(&mut *conn)
        .await;
        // SET ROLE failing (role already dropped) is fine — the DROP DATABASE
        // below then runs as the panel role and reports honestly if it can't.
        let became_owner = sqlx::query(AssertSqlSafe(format!("SET ROLE {qrole}")))
            .execute(&mut *conn)
            .await
            .is_ok();

        // CRYPTARCH-80 — a tenant can make their own database permanently
        // undeletable. Ownership alone is enough to set the template flag:
        //
        //     tenant: ALTER DATABASE theirs WITH IS_TEMPLATE true;
        //     panel:  DROP DATABASE theirs WITH (FORCE);
        //             ERROR: cannot drop a template database
        //
        // WITH (FORCE) does not help — it terminates sessions, and that is all
        // it does. Left unhandled, the database can never be deleted by the
        // user OR an admin, its quota slot is pinned, and restore-replace is
        // permanently blocked, since that begins with a drop.
        //
        // Verified on PG 17.10 that the panel recovers WITHOUT superuser: we
        // are inside SET ROLE, so this exercises the OWNER's own privilege,
        // not ours. The non-superuser spine holds.
        //
        // Failure is ignored on purpose, matching the defensive GRANT above:
        // DROP DATABASE is the honest reporter. If the ALTER fails and the
        // database really is a template, the drop fails with "cannot drop a
        // template database" — a true message naming the real obstacle.
        //
        // Checked BEFORE unsetting, not just unset: silently clearing the flag
        // and moving on destroys the only evidence that it was ever set — and
        // a tenant setting it is the attack. Closing a vector and knowing
        // whether anyone is using it are different things, and a tenant doing
        // this repeatedly is a pattern worth being able to see.
        let was_template: bool = sqlx::query_scalar(
            "SELECT COALESCE((SELECT datistemplate FROM pg_database WHERE datname = $1), false)",
        )
        .bind(name)
        .fetch_one(&mut *conn)
        .await
        .unwrap_or(false);
        if was_template {
            tracing::warn!(
                "database '{name}' was flagged IS_TEMPLATE, which blocks deletion                  (CRYPTARCH-80). Clearing it. A tenant can set this on their own                  database with ownership alone — if this recurs for the same owner,                  it is deliberate."
            );
        }
        let _ = sqlx::query(AssertSqlSafe(format!("ALTER DATABASE {qdb} WITH IS_TEMPLATE false")))
            .execute(&mut *conn)
            .await;

        let drop_db = sqlx::query(AssertSqlSafe(format!("DROP DATABASE IF EXISTS {qdb} WITH (FORCE)")))
            .execute(&mut *conn)
            .await;
        if became_owner {
            let _ = sqlx::query("RESET ROLE").execute(&mut *conn).await;
        }
        drop_db.context("dropping database")?;
        sqlx::query(AssertSqlSafe(format!("DROP ROLE IF EXISTS {qrole}")))
            .execute(&mut *conn)
            .await
            .context("dropping role")?;
        Ok(())
    }

    async fn login_states(&self, exclude: &[&str]) -> anyhow::Result<Vec<crate::engine::RoleLogin>> {
        let rows: Vec<(String, bool)> =
            sqlx::query_as(crate::repair::PANEL_ADMINISTERED_ROLES_SQL)
                .bind(exclude.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .fetch_all(&self.pool)
                .await
                .context("listing panel-administered roles")?;
        Ok(rows
            .into_iter()
            .map(|(role_name, can_login)| crate::engine::RoleLogin { role_name, can_login })
            .collect())
    }

    async fn database_exists(&self, name: &str) -> anyhow::Result<bool> {
        // Bind, not interpolate: this one is a value, not an identifier.
        let found: Option<i32> =
            sqlx::query_scalar("SELECT 1 FROM pg_database WHERE datname = $1")
                .bind(name)
                .fetch_optional(&self.pool)
                .await
                .context("checking whether the database exists")?;
        Ok(found.is_some())
    }

    async fn claim_repair_attempt(&self, marker: &str, comment: &str) -> anyhow::Result<bool> {
        let qrole = Self::quote_ident(marker);
        // CREATE ROLE fails on a duplicate name, and that failure IS the
        // answer — no read-then-write, so two upgrades racing cannot both
        // conclude they won. NOLOGIN because it is a marker, not an account.
        match sqlx::query(AssertSqlSafe(format!("CREATE ROLE {qrole} NOLOGIN")))
            .execute(&self.pool)
            .await
        {
            Ok(_) => {
                // Best-effort: the claim is the CREATE, not the comment. A
                // server that refuses the comment has still been claimed, and
                // reporting failure here would spend the attempt twice.
                let _ = sqlx::query(AssertSqlSafe(format!(
                    "COMMENT ON ROLE {qrole} IS {}",
                    Self::quote_literal(comment)
                )))
                .execute(&self.pool)
                .await;
                Ok(true)
            }
            Err(e) => {
                // Distinguish "already spent" from "could not ask". Treating a
                // connection failure as "already attempted" would silently
                // skip the repair on a server we never reached — the exact
                // shape this whole change exists to avoid.
                if let Some(dbe) = e.as_database_error() {
                    // 42710 = duplicate_object.
                    if dbe.code().as_deref() == Some("42710") {
                        return Ok(false);
                    }
                }
                Err(anyhow::Error::new(e).context("claiming the repair attempt"))
            }
        }
    }

    async fn enable_login(&self, name: &str) -> anyhow::Result<()> {
        let qrole = Self::quote_ident(name);
        // LOGIN is hard-coded, not parameterised: see the trait's doc comment.
        // There is deliberately no way to emit NOLOGIN from here.
        sqlx::query(AssertSqlSafe(format!("ALTER ROLE {qrole} LOGIN")))
            .execute(&self.pool)
            .await
            .context("enabling role login")?;
        Ok(())
    }

    async fn rotate_password(&self, name: &str, password: &str) -> anyhow::Result<ConnString> {
        let qrole = Self::quote_ident(name);
        // SCRAM verifier, not plaintext — see create_user_db. Keeps the rotated
        // password out of the managed server's statement logs. Quoted there and
        // here for the same reason.
        let verifier = Self::quote_literal(&postgres_protocol::password::scram_sha_256(
            password.as_bytes(),
        ));
        sqlx::query(AssertSqlSafe(format!("ALTER ROLE {qrole} PASSWORD {verifier}")))
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

    /// What this cluster says about the ways it can quietly stop working.
    ///
    /// Every check is cluster-scoped and answered over the existing admin
    /// connection — no per-database connections, no catalog scans. This runs
    /// from a page an operator loads when they are already worried, so it must
    /// not be the thing that makes a struggling server worse.
    ///
    /// The through-line is VACUUM. Postgres reclaims dead rows and advances the
    /// frozen-transaction horizon in one mechanism, so almost everything that
    /// goes wrong slowly is "vacuum is not getting to do its job": something
    /// holds an old transaction open, vacuum cannot advance past it, dead rows
    /// pile up, and the transaction-ID budget drains. The checks are ordered to
    /// report the CAUSES next to the symptom rather than leaving an operator to
    /// connect them.
    async fn maintenance(&self) -> anyhow::Result<MaintenanceReport> {
        let mut findings = Vec::new();

        // ---- 1. Transaction ID headroom -----------------------------------
        // The catastrophic one. Postgres has ~2.1 billion usable transaction
        // ids; if a database's oldest unfrozen row gets that far behind, the
        // server REFUSES WRITES and only single-user-mode recovery gets it
        // back. Nothing warns you at the application level first.
        let xid: Option<(String, i64)> = sqlx::query_as(
            "SELECT datname::text, age(datfrozenxid)::bigint FROM pg_database \
             ORDER BY age(datfrozenxid) DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .context("reading transaction id age")?;

        if let Some((db, age)) = xid {
            // 2^31. The shutdown threshold is a little under this; the point of
            // the percentage is proportion, not a countdown to the exact stop.
            const LIMIT: i64 = 2_147_483_648;
            let pct = (age as f64 / LIMIT as f64) * 100.0;
            let (severity, advice) = if age > 1_000_000_000 {
                (Severity::Urgent,
                 "Find what is holding the oldest transaction open (below), end it, then let \
                  autovacuum catch up — or run a manual VACUUM FREEZE on that database. If this \
                  reaches the limit the server stops accepting writes entirely and needs \
                  single-user-mode recovery.".to_string())
            } else if age > 200_000_000 {
                (Severity::Watch,
                 "Past the point where autovacuum should be freezing aggressively. Usually fine \
                  and self-correcting; worth watching that it comes back down rather than \
                  keeping on climbing.".to_string())
            } else {
                (Severity::Ok,
                 "Plenty of headroom. Autovacuum is advancing the frozen horizon normally.".to_string())
            };
            findings.push(MaintenanceFinding {
                severity,
                title: "Transaction ID headroom".into(),
                summary: format!("'{db}' is the furthest behind, {pct:.1}% of the way to the limit ({age} transactions)"),
                advice,
                metrics: vec![("txid_age", age as f64), ("txid_used_ratio", pct / 100.0)],
            });
        }

        // Can this role see other people's backends at all?
        //
        // THIS DECIDES WHETHER THE NEXT CHECK IS ALLOWED TO SAY "FINE".
        // pg_stat_activity shows an unprivileged role only its OWN sessions —
        // every other backend appears with its columns nulled. The panel role
        // is deliberately not superuser, so without `pg_read_all_stats` the
        // transaction check below can see nothing except Cryptarch's own
        // connections. It would then report a confident all-clear while a
        // TENANT's idle transaction holds the vacuum horizon — which is both
        // the most likely cause of the problem and the one thing this check
        // exists to find. A check that reports healthy because it cannot see is
        // worse than no check, so blindness is reported as the finding.
        let can_see_all: bool = sqlx::query_scalar(
            "SELECT pg_has_role(current_user, 'pg_read_all_stats', 'USAGE') \
                 OR current_setting('is_superuser')::bool",
        )
        .fetch_one(&self.pool)
        .await
        .unwrap_or(false);

        // ---- 2. What is blocking vacuum -----------------------------------
        // A single long-lived transaction pins the horizon for the WHOLE
        // cluster: vacuum may not reclaim anything newer than the oldest
        // running transaction, anywhere. This is the usual cause of finding 1,
        // and `idle in transaction` is the usual cause of this — a client that
        // opened a transaction and went away.
        //
        // Every text column coalesced (CRYPTARCH-127). PostgreSQL 18 lists
        // backends that are still AUTHENTICATING: their transaction has begun
        // (the auth lookups run in one) but they have no user or database yet.
        // Decoding those as non-null failed the whole report for anyone whose
        // check landed while somebody was logging in.
        let oldest: Option<(f64, String, String, String)> = sqlx::query_as(
            "SELECT EXTRACT(EPOCH FROM now() - xact_start)::float8, \
                    coalesce(state::text, '?'), coalesce(usename::text, '?'), \
                    coalesce(datname::text, '?') \
             FROM pg_stat_activity \
             WHERE xact_start IS NOT NULL AND backend_type = 'client backend' \
               AND pid <> pg_backend_pid() \
             ORDER BY xact_start LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .context("reading the oldest open transaction")?;

        match oldest {
            Some((secs, state, user, db)) if secs > 900.0 => {
                let idle = state == "idle in transaction";
                findings.push(MaintenanceFinding {
                    severity: if secs > 3600.0 { Severity::Urgent } else { Severity::Watch },
                    title: "Oldest open transaction".into(),
                    summary: format!(
                        "{} has been open {} on '{db}' as '{user}'",
                        if idle { "An idle transaction" } else { "A transaction" },
                        crate::web::human_duration(secs as i64),
                    ),
                    advice: if idle {
                        "A client opened a transaction and stopped using it. Nothing anywhere on \
                         this server can be vacuumed past it, so dead rows accumulate and the \
                         transaction ID budget drains. Find the client and fix it, or terminate \
                         the backend."
                            .into()
                    } else {
                        "A genuinely long-running query. It blocks vacuum for the whole cluster \
                         while it runs, so it is worth knowing whether it is meant to take this \
                         long."
                            .into()
                    },
                    metrics: vec![("oldest_transaction_seconds", secs)],
                });
            }
            // Nothing found — but "nothing found" only means something if we
            // could have found it. See `can_see_all`.
            _ if !can_see_all => {
                // The remedy is spelled out in full, with this server's actual
                // role name, because the operator cannot get it anywhere else:
                // the bootstrap SQL is only rendered when init reports
                // `needs_bootstrap`, so a server that was set up before this
                // check existed — which is every server that already works —
                // never sees it. Advice that points at something invisible is
                // the same as no advice.
                let panel: String = sqlx::query_scalar("SELECT current_user::text")
                    .fetch_one(&self.pool)
                    .await
                    .unwrap_or_else(|_| "the panel role".into());
                findings.push(MaintenanceFinding {
                    severity: Severity::Watch,
                    title: "Oldest open transaction".into(),
                    summary: "Cannot check — this role only sees its own connections".into(),
                    advice: format!(
                        "Cryptarch's role is not a superuser, so pg_stat_activity hides every \
                         session but its own. A tenant could be holding a transaction open — \
                         blocking cleanup across the whole server — and this page would not \
                         know. Run this once as a superuser on this server:\n\n    \
                         GRANT pg_read_all_stats TO {};\n\nIt grants read-only visibility of \
                         sessions and no ability to read or change any data.",
                        Self::quote_ident(&panel)
                    ),
                    // No number: the point of this finding is that we could
                    // not measure. Emitting 0 would publish a false healthy
                    // series, which is the graph version of the same lie.
                    metrics: Vec::new(),
                })
            }
            _ => findings.push(MaintenanceFinding {
                severity: Severity::Ok,
                title: "Oldest open transaction".into(),
                summary: "No transaction has been open long enough to hold vacuum back".into(),
                advice: "Vacuum is free to reclaim dead rows and advance the frozen horizon.".into(),
                metrics: vec![("oldest_transaction_seconds", 0.0)],
            }),
        }

        // ---- 3. Autovacuum keeping up -------------------------------------
        // A worker running for hours means vacuum cannot keep pace with the
        // write rate. It is not itself a failure — it is the warning that
        // finding 1 is coming.
        let vac: Vec<(f64, String)> = sqlx::query_as(
            "SELECT EXTRACT(EPOCH FROM now() - xact_start)::float8, \
                    coalesce(datname::text, '?') \
             FROM pg_stat_activity WHERE backend_type = 'autovacuum worker' \
               AND xact_start IS NOT NULL \
             ORDER BY xact_start",
        )
        .fetch_all(&self.pool)
        .await
        .context("reading autovacuum workers")?;

        if !can_see_all {
            // Blind, not quiet (CRYPTARCH-128). Without pg_read_all_stats every
            // other role's backend shows `backend_type` NULL, so the filter
            // above finds no workers whatever is running — and "none running"
            // would be reported as healthy, with a published count of zero.
            // No metric at all is the honest output: an absent series is
            // "unknown", a zero is a claim.
            let panel: String = sqlx::query_scalar("SELECT current_user::text")
                .fetch_one(&self.pool)
                .await
                .unwrap_or_else(|_| "the panel role".into());
            findings.push(MaintenanceFinding {
                severity: Severity::Watch,
                title: "Autovacuum".into(),
                summary: "Cannot check — this role cannot see autovacuum workers".into(),
                advice: format!(
                    "Without pg_read_all_stats, other sessions' backend types are hidden, so a \
                     struggling autovacuum is invisible from here. Run, as a superuser on this \
                     server: GRANT pg_read_all_stats TO {};",
                    Self::quote_ident(&panel)
                ),
                metrics: vec![],
            });
        } else if let Some((secs, db)) = vac.first().filter(|(s, _)| *s > 3600.0) {
            findings.push(MaintenanceFinding {
                severity: Severity::Watch,
                title: "Autovacuum".into(),
                summary: format!(
                    "A worker has been vacuuming '{db}' for {} ({} running)",
                    crate::web::human_duration(*secs as i64),
                    vac.len()
                ),
                advice: "Over an hour means autovacuum is struggling to keep up with how fast \
                         this server is being written to. Tune it to run more often rather than \
                         waiting for it to fall further behind."
                    .into(),
                metrics: vec![("autovacuum_workers", vac.len() as f64),
                              ("autovacuum_longest_seconds", *secs)],
            });
        } else {
            findings.push(MaintenanceFinding {
                severity: Severity::Ok,
                title: "Autovacuum".into(),
                summary: if vac.is_empty() {
                    "No workers running right now".into()
                } else {
                    format!("{} worker(s) running, none for long", vac.len())
                },
                advice: "Dead rows are being reclaimed as they appear.".into(),
                metrics: vec![
                    ("autovacuum_workers", vac.len() as f64),
                    ("autovacuum_longest_seconds", vac.first().map(|(s, _)| *s).unwrap_or(0.0)),
                ],
            });
        }

        // ---- 4. Things that hold the horizon forever ----------------------
        // Rare, and neither resolves on its own. A prepared transaction that
        // nobody commits, or a replication slot nobody reads, pins the frozen
        // horizon indefinitely — these turn finding 1 from "watch it" into
        // "it will arrive".
        let prepared: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_prepared_xacts")
            .fetch_one(&self.pool)
            .await
            .unwrap_or(0);
        if prepared > 0 {
            findings.push(MaintenanceFinding {
                severity: Severity::Urgent,
                title: "Prepared transactions".into(),
                summary: format!("{prepared} prepared transaction(s) are sitting uncommitted"),
                advice: "A prepared transaction holds its locks and pins the vacuum horizon \
                         until someone commits or rolls it back — it will never resolve itself. \
                         If no distributed transaction manager is in use here, these are \
                         orphans: ROLLBACK PREPARED them."
                    .into(),
                metrics: vec![("prepared_transactions", prepared as f64)],
            });
        }

        let dead_slots: Vec<(String,)> = sqlx::query_as(
            "SELECT slot_name::text FROM pg_replication_slots WHERE NOT active",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();
        if !dead_slots.is_empty() {
            findings.push(MaintenanceFinding {
                severity: Severity::Urgent,
                title: "Replication slots".into(),
                summary: format!(
                    "{} inactive slot(s): {}",
                    dead_slots.len(),
                    dead_slots.iter().map(|s| s.0.as_str()).collect::<Vec<_>>().join(", ")
                ),
                advice: "An inactive slot keeps every WAL segment its consumer has not read, and \
                         pins the vacuum horizon with it. A slot whose consumer is gone for good \
                         will fill the disk. Drop it if it is not coming back."
                    .into(),
                metrics: vec![("inactive_replication_slots", dead_slots.len() as f64)],
            });
        }

        // ---- 5. Connections ------------------------------------------------
        // Not a vacuum problem: a capacity one. Running out means new
        // connections are refused, including the panel's own.
        let conns: Option<(i64, i64)> = sqlx::query_as(
            "SELECT (SELECT count(*) FROM pg_stat_activity)::bigint, \
                    current_setting('max_connections')::bigint",
        )
        .fetch_optional(&self.pool)
        .await
        .context("reading connection counts")?;
        if let Some((used, max)) = conns {
            let pct = if max > 0 { (used as f64 / max as f64) * 100.0 } else { 0.0 };
            findings.push(MaintenanceFinding {
                severity: if pct >= 90.0 {
                    Severity::Urgent
                } else if pct >= 75.0 {
                    Severity::Watch
                } else {
                    Severity::Ok
                },
                title: "Connections".into(),
                summary: format!("{used} of {max} in use ({pct:.0}%)"),
                advice: if pct >= 75.0 {
                    "Close to the limit. Once it is reached the server refuses new connections — \
                     including this panel's, which is how a full server becomes an unmanageable \
                     one. Route tenants through the bouncer rather than raising max_connections."
                        .into()
                } else {
                    "Comfortable. Tenant traffic arrives through the bouncer, which is what keeps \
                     this number flat as databases are added."
                        .into()
                },
                metrics: vec![
                    ("connections", used as f64),
                    ("connections_max", max as f64),
                ],
            });
        }

        Ok(MaintenanceReport { findings })
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

    async fn survey(&self, name: &str) -> anyhow::Result<Survey> {
        // Database-level facts are readable from the maintenance connection;
        // everything else needs to be inside the database, same as the table
        // list.
        let row = sqlx::query(
            "SELECT current_setting('server_version'), \
                    pg_encoding_to_char(d.encoding), d.datcollate, d.datctype, \
                    pg_get_userbyid(d.datdba) \
             FROM pg_database d WHERE d.datname = $1",
        )
        .bind(name)
        .fetch_one(&self.pool)
        .await
        .context("reading database properties")?;
        let server_version: String = row.get(0);
        let (encoding, collate, ctype, owner): (String, String, String, String) =
            (row.get(1), row.get(2), row.get(3), row.get(4));

        // These columns vary by major version, so each is read on its own.
        // Bundling them cost us the collation version entirely: `daticulocale`
        // was renamed `datlocale` in PostgreSQL 17, so on every 17+ server the
        // combined query errored and a single `unwrap_or` took `datcollversion`
        // and `datlocprovider` down with it — silently recording "no collation
        // version" for the value the whole glibc-drift check depends on.
        let locale_provider = self.optional_db_column(name, "datlocprovider::text").await;
        let icu_locale = match self.optional_db_column(name, "datlocale").await {
            crate::manifest::Recorded::Value(v) => crate::manifest::Recorded::Value(v),
            // Pre-17 servers still call it daticulocale.
            not_recorded => match self.optional_db_column(name, "daticulocale").await {
                crate::manifest::Recorded::Value(v) => crate::manifest::Recorded::Value(v),
                _ => not_recorded,
            },
        };
        let coll_version = self.optional_db_column(name, "datcollversion").await;

        let dsn = self.tenant_dsn(name)?;
        let pool = match self.connect_tenant(&dsn).await {
            Ok(p) => p,
            Err(first) => {
                self.grant_self_connect(name).await.with_context(|| {
                    format!("tenant connect failed ({first}); self-grant also failed")
                })?;
                self.connect_tenant(&dsn)
                    .await
                    .context("connecting to tenant database to survey it")?
            }
        };
        let hazards = self.survey_hazards(&pool, &owner).await;
        let extensions = self.survey_extensions(&pool).await;
        pool.close().await;

        Ok(Survey {
            server_version,
            owner,
            properties: crate::manifest::DbProperties {
                encoding,
                collate,
                ctype,
                locale_provider,
                icu_locale,
                coll_version,
            },
            extensions: extensions?,
            hazards: hazards?,
        })
    }

    async fn dump_stream(&self, name: &str) -> anyhow::Result<DumpStream> {
        // pg_dump connects as the panel role, so it needs CONNECT on the
        // tenant database for the same reason the catalog reads do.
        self.grant_self_connect(name)
            .await
            .with_context(|| format!("granting CONNECT before dumping '{name}'"))?;

        // Become the database's owner for the dump. Rides the same
        // non-inherited `WITH SET TRUE` membership every other lifecycle
        // operation uses — the panel role still cannot passively read tenant
        // data.
        let mut cmd = dump_command(&self.admin_dsn, name, Some(name))?;
        let described = DumpStream::describe(&cmd);
        let child = cmd
            .spawn()
            .context("spawning pg_dump — is postgresql-client installed in this image?")?;
        DumpStream::labelled(child, described)
    }

    async fn restore_stream(&self, name: &str) -> anyhow::Result<RestoreSink> {
        // Same CONNECT grant the dump needs, for the same reason: the panel
        // role connects, then becomes the owner via --role.
        self.grant_self_connect(name)
            .await
            .with_context(|| format!("granting CONNECT before restoring '{name}'"))?;

        // The database name IS the owning role in this system (migration 0010),
        // so the target and the role it is restored as are the same string.
        let tag = format!("cryptarch-restore-{}", uuid::Uuid::new_v4().simple());
        let mut cmd = restore_command(&self.admin_dsn, name, name, &tag)?;
        let described = DumpStream::describe(&cmd);
        let child = cmd
            .spawn()
            .context("spawning pg_restore — is postgresql-client installed in this image?")?;
        let verdict = std::sync::Arc::new(std::sync::Mutex::new(None));
        let watchdog = tokio::spawn(restore_lock_watchdog(
            self.pool.clone(),
            tag,
            name.to_string(),
            self.restore_lock_wait,
            verdict.clone(),
        ));
        Ok(RestoreSink::new(child, described)?
            .with_watchdog(crate::engine::RestoreWatchdog::new(watchdog, verdict)))
    }
}

/// Build a `pg_restore` invocation that replaces the contents of `db`.
///
/// Three flags carry the entire safety story, so none of them is optional:
///
/// * `--single-transaction` — the restore is all-or-nothing. Postgres already
///   has the wheel here; an earlier design renamed the live database aside and
///   swapped it back on failure, which is the same guarantee reinvented at
///   several times the cost. On failure the database is byte-for-byte what it
///   was.
/// * `--clean --if-exists` — drop each object before recreating it, inside that
///   transaction. Without `--if-exists`, restoring into a database missing any
///   object errors on the DROP; with it, a restore into an empty database
///   works, which is the case a tenant hits after wiping something by mistake.
/// * `--role` — the restore runs with the TENANT's privileges rather than the
///   panel's, which is the same least-authority rule every other lifecycle
///   operation follows.
///
/// A claim worth not making about `--role`: it is NOT what preserves ownership.
/// The dump carries explicit `OWNER TO` statements, so the tenant still owns
/// its tables afterwards even without it — verified by removing the flag and
/// watching the ownership assertion still pass. It is defence in depth for
/// anything the archive does not name an owner for, not the mechanism.
///
/// Deliberately NOT `--jobs`: parallel restore is incompatible with a single
/// transaction, and the transaction is worth more than the speed. If a database
/// ever grows big enough for that to hurt, the answer is a maintenance window,
/// not a restore that can half-apply.
fn restore_command(
    dsn: &str,
    db: &str,
    role: &str,
    app_name: &str,
) -> anyhow::Result<tokio::process::Command> {
    let parts = PgDsnParts::parse(dsn).context("parsing DSN for pg_restore")?;
    let mut cmd = tokio::process::Command::new("pg_restore");
    cmd.arg("--host").arg(&parts.host)
        .arg("--port").arg(parts.port.to_string())
        .arg("--username").arg(&parts.user)
        .arg("--dbname").arg(db)
        .arg("--role").arg(role)
        .arg("--no-password")
        .arg("--clean")
        .arg("--if-exists")
        .arg("--single-transaction")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        // CRYPTARCH-113: reaped with the wrapper rather than reparented to
        // init. Dropping a `Child` without this detaches the process — on
        // shutdown, or on any path that abandons the sink, pg_restore would
        // outlive the runtime that spawned it and keep a transaction open
        // against the tenant database.
        .kill_on_drop(true);
    // The tag the lock watchdog finds this session by (CRYPTARCH-128).
    cmd.env("PGAPPNAME", app_name);
    // NOT lock_timeout: pg_restore's own script opens with `SET lock_timeout
    // = 0`, so a bound passed this way is silently overridden — which an
    // earlier version of this function did, with a test that only checked the
    // variable was set. The bound is the watchdog's job instead.
    //
    // This setting pg_restore does not reset. Without it, a restore whose
    // client dies while waiting for a lock (a crash, a SIGKILL, `kill_on_drop`
    // below) leaves its SERVER backend queued for that lock indefinitely, and
    // every tenant query queues behind it — an outage that outlives Cryptarch.
    // With it, the server notices the dead client within seconds and gives up.
    cmd.env("PGOPTIONS", format!("-c client_connection_check_interval={RESTORE_CLIENT_CHECK}"));
    // Password via the environment, never argv — same reasoning as the dump.
    if let Some(pw) = &parts.password {
        cmd.env("PGPASSWORD", pw);
    }
    Ok(cmd)
}

/// How long a restore may wait for any one lock before it is cancelled.
///
/// `--clean` drops every table it replaces, which needs ACCESS EXCLUSIVE. With
/// a tenant transaction open on one of them the restore would wait unbounded —
/// and every query the tenant sends after it queues behind that wait, so an
/// "in progress" restore quietly takes the tenant's application down with it.
/// Inside `--single-transaction` a cancel is an ordinary error: the whole
/// restore rolls back and the database is exactly as it was, which is a far
/// better failure than a hang until the six-hour abandoned sweep.
///
/// Per lock, not cumulative, so a large restore is not cut short by this; only
/// a wait on something someone else is holding is.
pub const RESTORE_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(15);

/// How often the server checks a restore's client is still there.
const RESTORE_CLIENT_CHECK: &str = "5s";

/// The restore session tagged `tag` on database `db`, if it is waiting on a
/// lock: its pid, how long it has waited, and who it is waiting behind.
///
/// Matched on the tag AND on being the panel's own session on that database
/// (CRYPTARCH-128). `application_name` is visible to every role and settable by
/// any client, so on the tag alone a tenant could read a running restore's tag
/// from pg_stat_activity, give one of its own sessions the same name and park
/// it on a lock — and the watchdog would aim at THAT session, fail to cancel
/// it, and leave the real restore unbounded. A tenant cannot make a session
/// whose `usesysid` is the panel role.
#[doc(hidden)]
pub async fn blocked_restore(
    pool: &PgPool,
    tag: &str,
    db: &str,
) -> Result<Option<(i32, f64, Vec<i32>)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT a.pid, EXTRACT(EPOCH FROM now() - min(l.waitstart))::float8, \
                pg_blocking_pids(a.pid) \
         FROM pg_stat_activity a JOIN pg_locks l ON l.pid = a.pid \
         WHERE a.application_name = $1 AND a.datname = $2 \
           AND a.usesysid = (SELECT oid FROM pg_roles WHERE rolname = session_user) \
           AND NOT l.granted AND l.waitstart IS NOT NULL \
         GROUP BY a.pid ORDER BY 2 DESC LIMIT 1",
    )
    .bind(tag)
    .bind(db)
    .fetch_optional(pool)
    .await
}

/// Cancel the restore tagged `tag` once it has waited `limit` for one lock, and
/// record who it was waiting on (CRYPTARCH-128).
///
/// Polls rather than relying on a server-side timeout because pg_restore
/// overrides `lock_timeout` itself; see `restore_command`. `pg_locks.waitstart`
/// says how long the wait has lasted, `pg_blocking_pids` who it is behind, and
/// `pg_cancel_backend` works without superuser because the restore connects as
/// the panel role — it is cancelling its own session.
///
/// Aborted by the sink when the restore ends, so it only ever runs alongside it.
async fn restore_lock_watchdog(
    pool: PgPool,
    tag: String,
    db: String,
    limit: std::time::Duration,
    verdict: std::sync::Arc<std::sync::Mutex<Option<String>>>,
) {
    let mut complained = false;
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let (pid, waited, blockers) = match blocked_restore(&pool, &tag, &db).await {
            Ok(Some(w)) => w,
            Ok(None) => continue,
            Err(e) => {
                // Said once: a watchdog that cannot see is worth knowing about,
                // and a log line per half-second is not.
                if !complained {
                    tracing::warn!("restore lock watchdog for {tag} cannot read pg_locks: {e}");
                    complained = true;
                }
                continue;
            }
        };
        if waited < limit.as_secs_f64() {
            continue;
        }
        // Who holds it. Without pg_read_all_stats the panel role sees another
        // role's session but not its state, hence the coalesce.
        let holders: Vec<(i32, String, String)> = sqlx::query_as(
            "SELECT pid, coalesce(usename::text, '?'), coalesce(state, 'state hidden') \
             FROM pg_stat_activity WHERE pid = ANY($1) ORDER BY pid",
        )
        .bind(&blockers)
        .fetch_all(&pool)
        .await
        .unwrap_or_default();
        let who = if holders.is_empty() {
            "a session that could not be identified".to_string()
        } else {
            holders
                .iter()
                .map(|(p, u, s)| format!("pid {p} as '{u}' ({s})"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        match sqlx::query_scalar::<_, bool>("SELECT pg_cancel_backend($1)")
            .bind(pid)
            .fetch_one(&pool)
            .await
        {
            // The verdict is recorded only once the cancel has happened — it
            // explains a failure THIS caused, and must not be pinned on some
            // unrelated failure later.
            Ok(true) => {
                if let Ok(mut v) = verdict.lock() {
                    *v = Some(format!(
                        "gave up after waiting {}s for a lock held by another session on this \
                         database: {who}. Nothing was changed — the restore is all-or-nothing. \
                         Finish or close that session, then restore again",
                        limit.as_secs()
                    ));
                }
                return;
            }
            // Keep watching rather than give up: returning here would leave
            // the restore with no bound at all, which is the thing this exists
            // to prevent. Logged each time, since each is a real failure.
            Ok(false) => tracing::error!("could not cancel lock-blocked restore {tag} (pid {pid})"),
            Err(e) => tracing::error!("cancelling lock-blocked restore {tag} (pid {pid}): {e}"),
        }
    }
}

/// Build a `pg_dump` invocation against `dsn`, dumping `db` (optionally after
/// `SET ROLE role`).
///
/// Shared with the metadata-database backup (CRYPTARCH-62), which dumps over
/// Cryptarch's own DSN and has no owner role to assume — the flags and the
/// password handling should not be written twice.
pub fn dump_command(
    dsn: &str,
    db: &str,
    role: Option<&str>,
) -> anyhow::Result<tokio::process::Command> {
    let parts = PgDsnParts::parse(dsn).context("parsing DSN for pg_dump")?;
    let mut cmd = tokio::process::Command::new("pg_dump");
    cmd.arg("--host").arg(&parts.host)
        .arg("--port").arg(parts.port.to_string())
        .arg("--username").arg(&parts.user)
        .arg("--dbname").arg(db)
        .arg("--no-password")
        .arg("--format").arg("custom")
        .arg("--compress").arg("zstd")
        // Deliberately NOT --enable-row-security. An owner bypasses its own
        // RLS, so the normal case dumps every row; a table with FORCE ROW LEVEL
        // SECURITY subjects even the owner to its policies, and we want pg_dump
        // to ERROR there. With --enable-row-security it would instead succeed
        // while silently dumping only the visible subset — a partial backup
        // that looks complete, which is the worst thing a backup tool can do.
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        // CRYPTARCH-113. An orphaned pg_dump is worse than untidy: it holds a
        // repeatable-read snapshot for as long as it lives, which is exactly
        // the condition this engine's own maintenance report flags as "nothing
        // anywhere on this server can be vacuumed past it".
        .kill_on_drop(true);
    if let Some(role) = role {
        cmd.arg("--role").arg(role);
    }
    // Password via the environment, never argv: /proc/<pid>/cmdline is
    // world-readable, /proc/<pid>/environ is not.
    if let Some(pw) = &parts.password {
        cmd.env("PGPASSWORD", pw);
    }
    Ok(cmd)
}

/// The database a DSN points at, for callers that must dump exactly that one.
pub fn database_in_dsn(dsn: &str) -> Option<String> {
    let after_scheme = dsn.split("://").nth(1)?;
    let after_userinfo = match after_scheme.rfind('@') {
        Some(i) => &after_scheme[i + 1..],
        None => after_scheme,
    };
    let path = after_userinfo.split('/').nth(1)?;
    let db = path.split('?').next().unwrap_or(path);
    (!db.is_empty()).then(|| db.to_string())
}

/// The pieces of a Postgres URL a client tool needs as separate flags.
///
/// Passing the whole DSN as `-d <uri>` would be simpler but puts the password
/// in argv where any local process can read it; splitting lets the password go
/// through `PGPASSWORD` instead. Userinfo is percent-decoded — a password with
/// `@` or `:` in it is only expressible in a URL when encoded, so skipping the
/// decode would authenticate with the wrong string.
#[derive(Debug, PartialEq)]
struct PgDsnParts {
    user: String,
    password: Option<String>,
    host: String,
    port: u16,
}

impl PgDsnParts {
    fn parse(dsn: &str) -> anyhow::Result<Self> {
        let base = dsn.split('?').next().unwrap_or(dsn);
        let after_scheme = match base.find("://") {
            Some(i) => &base[i + 3..],
            None => base,
        };
        // Split userinfo off FIRST, at the last '@'. Doing it the other way
        // round — authority ends at the first '/' — breaks on a password that
        // contains a raw '/', which is legal input and would silently truncate
        // the host. Database names are allowlisted, so no '@' follows the
        // authority to confuse the search.
        let (userinfo, rest) = match after_scheme.rfind('@') {
            Some(i) => (&after_scheme[..i], &after_scheme[i + 1..]),
            None => ("", after_scheme),
        };
        let hostport = match rest.find('/') {
            Some(i) => &rest[..i],
            None => rest,
        };
        let (user, password) = match userinfo.split_once(':') {
            Some((u, p)) => (pct_decode(u), Some(pct_decode(p))),
            None => (pct_decode(userinfo), None),
        };
        // An IPv6 literal is bracketed; its colons are not the port separator.
        let (host, port) = if let Some(end) = hostport.rfind(']') {
            let host = hostport[..end + 1].trim_start_matches('[').trim_end_matches(']');
            let port = hostport[end + 1..].strip_prefix(':').unwrap_or("");
            (host.to_string(), port)
        } else {
            match hostport.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), p),
                None => (hostport.to_string(), ""),
            }
        };
        if host.is_empty() {
            anyhow::bail!("DSN has no host");
        }
        Ok(Self {
            user,
            password,
            host,
            port: if port.is_empty() { 5432 } else { port.parse().context("DSN port")? },
        })
    }
}

/// Percent-decode URL userinfo. Invalid escapes are left as-is rather than
/// erroring: a password that merely *contains* a '%' is legal input.
fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(hi), Some(lo)) =
                ((b[i + 1] as char).to_digit(16), (b[i + 2] as char).to_digit(16))
        {
            out.push((hi * 16 + lo) as u8);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The command carries what the watchdog and the server need to bound a
    /// stuck restore. Configuration only — the behaviour itself is proven
    /// against a real lock in backup_e2e.rs, because a test of this shape is
    /// exactly what let an overridden lock_timeout pass before (CRYPTARCH-128).
    #[test]
    fn restore_is_tagged_and_checks_its_client() {
        let cmd = restore_command(
            "postgres://admin:pw@10.0.0.5:5432/postgres", "alice_app", "alice_app", "cryptarch-restore-x",
        )
        .expect("building the restore command");
        let env = |key: &str| {
            cmd.as_std()
                .get_envs()
                .find(|(k, _)| *k == key)
                .and_then(|(_, v)| v)
                .map(|v| v.to_string_lossy().into_owned())
        };
        assert_eq!(env("PGAPPNAME").as_deref(), Some("cryptarch-restore-x"));
        let opts = env("PGOPTIONS").expect("pg_restore must be given PGOPTIONS");
        assert!(opts.contains("client_connection_check_interval="), "got {opts:?}");
        assert!(!opts.contains("lock_timeout"), "pg_restore overrides lock_timeout; do not rely on it");
        // The password still travels by environment, never argv.
        assert!(env("PGPASSWORD").is_some());
        assert!(!cmd.as_std().get_args().any(|a| a.to_string_lossy().contains("pw")));
    }

    #[test]
    fn quote_ident_doubles_embedded_quotes() {
        assert_eq!(PostgresEngine::quote_ident("alice_app"), "\"alice_app\"");
        assert_eq!(PostgresEngine::quote_ident("a\"b"), "\"a\"\"b\"");
    }

    #[test]
    fn swap_db_preserves_authority_and_query() {
        assert_eq!(
            swap_db_in_dsn("postgres://admin:pw@10.0.0.5:5432/postgres", "alice_app").unwrap(),
            "postgres://admin:pw@10.0.0.5:5432/alice_app"
        );
        assert_eq!(
            swap_db_in_dsn("postgres://admin:pw@10.0.0.5:5432/postgres?sslmode=require", "alice_app").unwrap(),
            "postgres://admin:pw@10.0.0.5:5432/alice_app?sslmode=require"
        );
    }

    #[test]
    fn dsn_parts_split_userinfo_from_hostport() {
        let p = PgDsnParts::parse("postgres://admin:pw@10.0.0.5:5432/postgres").unwrap();
        assert_eq!(p.user, "admin");
        assert_eq!(p.password.as_deref(), Some("pw"));
        assert_eq!(p.host, "10.0.0.5");
        assert_eq!(p.port, 5432);
    }

    #[test]
    fn dsn_parts_percent_decode_password() {
        // A password containing '@' and ':' is only expressible encoded; handing
        // pg_dump the raw encoded form would authenticate with the wrong string.
        let p = PgDsnParts::parse("postgres://admin:p%40ss%3Aword@host:6432/db").unwrap();
        assert_eq!(p.password.as_deref(), Some("p@ss:word"));
        assert_eq!(p.host, "host");
        assert_eq!(p.port, 6432);
    }

    #[test]
    fn dsn_parts_handle_ipv6_and_defaults() {
        let p = PgDsnParts::parse("postgres://admin@[fd00::1]/postgres").unwrap();
        assert_eq!(p.host, "fd00::1");
        assert_eq!(p.port, 5432, "unspecified port defaults");
        assert_eq!(p.password, None);

        let p = PgDsnParts::parse("postgres://admin:pw@[fd00::1]:5433/postgres").unwrap();
        assert_eq!(p.host, "fd00::1");
        assert_eq!(p.port, 5433);
    }

    #[test]
    fn dsn_parts_tolerate_slash_in_password_and_query_suffix() {
        let p = PgDsnParts::parse("postgres://admin:a/b@host:5432/db?sslmode=require").unwrap();
        assert_eq!(p.password.as_deref(), Some("a/b"));
        assert_eq!(p.host, "host");
    }

    #[test]
    fn swap_db_handles_slash_in_password() {
        // A raw '/' in the password must not be read as the path separator.
        assert_eq!(
            swap_db_in_dsn("postgres://admin:p/w@10.0.0.5:5432/postgres", "alice_app").unwrap(),
            "postgres://admin:p/w@10.0.0.5:5432/alice_app"
        );
        // No path in the source DSN: append one.
        assert_eq!(
            swap_db_in_dsn("postgres://admin:a/b@host:5432", "alice_app").unwrap(),
            "postgres://admin:a/b@host:5432/alice_app"
        );
    }

    /// CRYPTARCH-91: a name that could re-cut the DSN is refused here.
    ///
    /// This is the one interpolation surface in the crate with no second guard
    /// — a connection-string path component cannot be quoted — so the allowlist
    /// is the whole guarantee rather than defence in depth, and it has to be
    /// enforced at this boundary rather than assumed of callers.
    ///
    /// Each name below is chosen for the DSN grammar it would reach, not for
    /// looking hostile: `?` opens the parameter list, `@` restarts the
    /// authority, `/` re-cuts the path. The first two would send the panel's
    /// admin credentials to a host of the attacker's choosing.
    #[test]
    fn a_name_that_could_redirect_the_connection_is_refused() {
        const ADMIN: &str = "postgres://admin:pw@10.0.0.5:5432/postgres";
        for hostile in [
            "evil?host=attacker.example",           // injects a connection parameter
            "x@attacker.example/y",                 // restarts the authority
            "a/b",                                  // re-cuts the path
            "has space",
            "UPPER",
            "robert'; DROP DATABASE postgres; --",
        ] {
            // Positive precondition: the guard must be the ALLOWLIST rejecting
            // this name, not some unrelated parse failure. Without this, a
            // swap_db_in_dsn that errored on every input would pass.
            assert!(
                !crate::names::valid_db_name(hostile),
                "{hostile:?} is allowlisted, so this case tests nothing"
            );

            let err = swap_db_in_dsn(ADMIN, hostile)
                .expect_err("a non-allowlisted name produced a connection string");
            let msg = format!("{err:#}");
            assert!(
                msg.contains(hostile) && msg.contains("allowlisted"),
                "refused for an unrelated reason ({msg}), so this would pass even if the \
                 allowlist check were removed"
            );
        }

        // And the other half of the claim: the check REJECTS rather than
        // rejecting everything. A guard that refused all names would satisfy
        // every assertion above while breaking every tenant.
        assert!(
            swap_db_in_dsn(ADMIN, "alice_app").is_ok(),
            "a legitimate name was refused; the guard is not discriminating"
        );
    }
}


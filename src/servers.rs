//! Managed-server registry.
//!
//! v0.2 (CRYPTARCH-8/10): DB-backed and live-mutable. Admin DSNs are stored
//! AES-256-GCM-encrypted in `managed_servers` and decrypted to connect
//! engines — at boot for every active row, and at runtime when an admin adds,
//! updates, or re-enables a server through the CRUD (admin_servers module).
//! The env seed, when present, upserts its row before the boot load — dev
//! bootstrap keeps working, but the database is authoritative.
//!
//! Upgrade note: rows created by v0.1 have an empty `admin_dsn_enc` and are
//! skipped at load. One boot with the seed env set backfills the encrypted
//! DSN for the seed server; other legacy rows need re-adding via the CRUD.
//!
//! Failure policy: a server that can't be used (empty blob, undecryptable
//! blob, unknown engine, dead connection) is skipped with a loud error —
//! one bad row must not take boot down with it. The worst case (wrong key
//! file → every server skipped) still boots, logs an error per server, and
//! disables provisioning, which is visible immediately in the UI.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use anyhow::Context;
use uuid::Uuid;

use crate::config::SeedServer;
use crate::crypto::Crypto;
use crate::engine::{postgres::PostgresEngine, DbEngine};

/// A managed server as the UI sees it (metadata only — no creds).
#[derive(Clone)]
pub struct ServerInfo {
    pub id: Uuid,
    pub name: String,
    pub engine: String,
}

#[derive(Default)]
struct Inner {
    engines: HashMap<Uuid, Arc<dyn DbEngine>>,
    info: Vec<ServerInfo>,
}

/// Live engines keyed by managed-server id, plus display metadata.
/// Cheap to clone; interior mutability so admin CRUD can add/remove servers
/// without a restart. Lock discipline: short critical sections only, never
/// held across an await.
#[derive(Clone, Default)]
pub struct ServerRegistry(Arc<RwLock<Inner>>);

/// A managed_servers row as loaded for engine connection.
#[derive(sqlx::FromRow)]
pub struct ServerRow {
    pub id: Uuid,
    pub name: String,
    pub engine: String,
    pub host: String,
    pub port: i32,
    pub admin_dsn_enc: Vec<u8>,
}

impl ServerRegistry {
    /// Build the registry from the database. The env seed, if present, upserts
    /// its row first (with the DSN encrypted at rest); then every active
    /// server row is decrypted and its admin engine connected.
    pub async fn build(
        db: &sqlx::PgPool,
        crypto: &Crypto,
        seed: Option<&SeedServer>,
        allow_superuser: bool,
    ) -> anyhow::Result<Self> {
        if let Some(s) = seed {
            upsert_server_row(db, crypto, s).await?;
        }

        let rows = sqlx::query_as::<_, ServerRow>(
            "SELECT id, name, engine, host, port, admin_dsn_enc \
             FROM managed_servers WHERE is_active ORDER BY name",
        )
        .fetch_all(db)
        .await?;

        let reg = ServerRegistry::default();
        for row in rows {
            match connect_row(crypto, &row, allow_superuser).await {
                Ok(engine) => reg.register(row.id, row.name.clone(), row.engine.clone(), engine),
                Err(e) => tracing::error!("managed server '{}': {e} — skipping", row.name),
            }
        }
        if reg.list().is_empty() {
            tracing::warn!("no usable managed server — provisioning disabled");
        }
        Ok(reg)
    }

    pub fn get(&self, id: Uuid) -> Option<Arc<dyn DbEngine>> {
        self.0.read().unwrap().engines.get(&id).cloned()
    }

    /// Servers available to provision onto, for the picker.
    pub fn list(&self) -> Vec<ServerInfo> {
        self.0.read().unwrap().info.clone()
    }

    /// Add or replace a live engine (admin CRUD add / DSN rotation / re-enable).
    pub fn register(&self, id: Uuid, name: String, engine_kind: String, engine: Arc<dyn DbEngine>) {
        let mut inner = self.0.write().unwrap();
        inner.engines.insert(id, engine);
        inner.info.retain(|i| i.id != id);
        inner.info.push(ServerInfo { id, name: name.clone(), engine: engine_kind });
        inner.info.sort_by(|a, b| a.name.cmp(&b.name));
        tracing::info!("registered managed server '{name}' ({id})");
    }

    /// Remove a server from live service (disable). Metadata row stays.
    pub fn unregister(&self, id: Uuid) {
        let mut inner = self.0.write().unwrap();
        inner.engines.remove(&id);
        inner.info.retain(|i| i.id != id);
    }
}

/// Decrypt a row's admin DSN, enforce the role gate, and connect its engine.
/// Shared by boot load and admin CRUD (add / rotate / re-enable).
///
/// The role gate runs EVERY time an engine goes live, not just when a DSN is
/// first typed into a form — otherwise "add a compliant role, ALTER it to
/// SUPERUSER later, disable/enable the server" silently bypasses the spine.
/// `allow_superuser` exists solely for the dev seed (CRYPTARCH_ALLOW_SUPERUSER_ADMIN);
/// production leaves it off and a role that grew superuser is refused loudly.
pub async fn connect_row(
    crypto: &Crypto,
    row: &ServerRow,
    allow_superuser: bool,
) -> anyhow::Result<Arc<dyn DbEngine>> {
    if row.admin_dsn_enc.is_empty() {
        anyhow::bail!("no stored admin DSN (v0.1 row — re-seed or re-add it)");
    }
    let dsn = crypto
        .open(&row.admin_dsn_enc)
        .map_err(|e| anyhow::anyhow!("decrypting admin DSN failed ({e}) — wrong/rotated key file?"))?;
    if row.engine != "postgres" {
        anyhow::bail!("unsupported engine '{}'", row.engine);
    }
    let port = match u16::try_from(row.port) {
        Ok(p) if p != 0 => p,
        _ => anyhow::bail!("invalid advertised port {}", row.port),
    };

    let check = check_admin_role(&dsn).await.context("role gate check")?;
    if check.is_superuser && !allow_superuser {
        anyhow::bail!(
            "admin role '{}' is SUPERUSER — refused (set CRYPTARCH_ALLOW_SUPERUSER_ADMIN=1 only for dev)",
            check.role
        );
    }
    if !check.is_superuser && (!check.can_createdb || !check.can_createrole) {
        anyhow::bail!(
            "admin role '{}' lacks CREATEDB/CREATEROLE (createdb={}, createrole={})",
            check.role, check.can_createdb, check.can_createrole
        );
    }
    let engine = PostgresEngine::connect(&dsn, row.host.clone(), port).await?;
    // Bound every operation: DDL on a wedged server must fail the request
    // in seconds, not hang it until the client gives up.
    Ok(crate::engine::TimeoutEngine::wrap(
        Arc::new(engine),
        std::time::Duration::from_secs(15),
    ))
}

/// What `SELECT ... FROM pg_roles WHERE rolname = current_user` says about a
/// candidate admin DSN. The CRUD refuses superuser and demands both create
/// attributes — the security spine, enforced at the door.
pub struct RoleCheck {
    pub role: String,
    pub is_superuser: bool,
    pub can_createdb: bool,
    pub can_createrole: bool,
    pub server_version: String,
}

/// Connect with a candidate admin DSN (short timeout, single connection) and
/// report the role's attributes. Errors are connection/auth failures.
pub async fn check_admin_role(dsn: &str) -> anyhow::Result<RoleCheck> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(4))
        .connect(dsn)
        .await?;
    let row: (String, bool, bool, bool, String) = sqlx::query_as(
        "SELECT current_user::text, rolsuper, rolcreatedb, rolcreaterole, \
                current_setting('server_version') \
         FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&pool)
    .await?;
    pool.close().await;
    Ok(RoleCheck {
        role: row.0,
        is_superuser: row.1,
        can_createdb: row.2,
        can_createrole: row.3,
        server_version: row.4,
    })
}

/// One additional listener address for a server (dial target, labeled).
#[derive(sqlx::FromRow, Clone)]
pub struct Listener {
    pub id: Uuid,
    pub host: String,
    pub port: i32,
    pub label: String,
}

/// Additional listeners for a server, in display order. The primary address
/// (managed_servers.host/port) is not in this list — callers render it first.
pub async fn listeners_for(db: &sqlx::PgPool, server_id: Uuid) -> Vec<Listener> {
    sqlx::query_as::<_, Listener>(
        "SELECT id, host, port, label FROM server_listeners \
         WHERE server_id = $1 ORDER BY position, label",
    )
    .bind(server_id)
    .fetch_all(db)
    .await
    .unwrap_or_else(|e| {
        tracing::warn!("loading listeners for {server_id}: {e} — rendering without them");
        Vec::new()
    })
}

/// TCP reachability probe for an advertised address, 3s timeout.
/// Returns Err with a human-readable reason.
pub async fn tcp_check(host: &str, port: u16) -> Result<(), String> {
    let addr = format!("{host}:{port}");
    match tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(format!("{addr}: {e}")),
        Err(_) => Err(format!("{addr}: connect timed out")),
    }
}

/// Strict IP-or-CIDR validation for "Allowed from" style inputs. No
/// hostnames, ever — these lines land in rendered edge config. The native
/// CIDR column is the backstop; this is the friendly front door.
pub fn valid_cidr(s: &str) -> bool {
    let (ip_part, prefix_part) = match s.split_once('/') {
        Some((ip, pfx)) => (ip, Some(pfx)),
        None => (s, None),
    };
    let ip: std::net::IpAddr = match ip_part.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    match prefix_part {
        None => true,
        Some(p) => {
            // reject "+8", " 8", "08"-style artifacts: digits only
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) || (p.len() > 1 && p.starts_with('0')) {
                return false;
            }
            let Ok(n) = p.parse::<u8>() else { return false };
            // Host bits must be zero — Postgres's CIDR type refuses
            // '10.1.2.3/24' ("bits set to right of mask"), so accepting it
            // here would let a natural admin typo through to a raw DB error.
            match ip {
                std::net::IpAddr::V4(v4) => {
                    n <= 32 && {
                        let bits = u32::from(v4);
                        n == 32 || (bits & (u32::MAX >> n)) == 0
                    }
                }
                std::net::IpAddr::V6(v6) => {
                    n <= 128 && {
                        let bits = u128::from(v6);
                        n == 128 || (bits & (u128::MAX >> n)) == 0
                    }
                }
            }
        }
    }
}

/// Listener-host validation: an IP (v4/v6) or an FQDN. Dial targets only —
/// never used in hba rules, so hostnames are fine here (and only here).
/// FQDN rules: 1-253 chars, dot-separated labels of [a-z0-9-] (case
/// tolerated, no leading/trailing hyphen per label), single-label names
/// like "localhost" allowed.
pub fn valid_listener_host(s: &str) -> bool {
    if s.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if s.is_empty() || s.len() > 253 || s.contains("..") {
        return false;
    }
    // An all-digit final label is an IP typo (e.g. 300.1.2.3), not a TLD.
    if s.rsplit('.').next().is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit())) {
        return false;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// Server-name validation for the registry: short, lowercase, dns-ish.
pub fn valid_server_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Insert or update the metadata row for the env-seeded server, storing its
/// admin DSN encrypted at rest.
///
/// The seed is a dev/bootstrap mechanism and it is authoritative for its own
/// row: it overwrites the stored DSN and reactivates the row on every boot.
/// That means a stale seed env can resurrect a rotated credential — hence the
/// loud log line. Production setups should drop the seed env once the CRUD
/// manages servers.
async fn upsert_server_row(db: &sqlx::PgPool, crypto: &Crypto, s: &SeedServer) -> anyhow::Result<()> {
    let dsn_enc = crypto.seal(&s.admin_dsn)?;
    // Seed CIDR: validated here (a bad env var must not kill boot), and only
    // applied when present — an admin's edited default survives a seed boot
    // that doesn't set one.
    let seed_cidr = match s.default_consumer_cidr.as_deref() {
        Some(c) if valid_cidr(c) => c,
        Some(c) => {
            tracing::warn!("CRYPTARCH_SEED_SERVER_DEFAULT_CIDR '{c}' is not a valid IP/CIDR — ignored");
            ""
        }
        None => "",
    };
    sqlx::query(
        "INSERT INTO managed_servers (name, engine, host, port, admin_dsn_enc, default_consumer_cidr) \
         VALUES ($1, 'postgres', $2, $3, $4, NULLIF($5, '')::cidr) \
         ON CONFLICT (name) DO UPDATE \
             SET host = EXCLUDED.host, port = EXCLUDED.port, \
                 admin_dsn_enc = EXCLUDED.admin_dsn_enc, \
                 default_consumer_cidr = COALESCE(NULLIF($5, '')::cidr, \
                                                  managed_servers.default_consumer_cidr), \
                 is_active = TRUE",
    )
    .bind(&s.name)
    .bind(&s.host)
    .bind(i32::from(s.port))
    .bind(&dsn_enc)
    .bind(seed_cidr)
    .execute(db)
    .await?;
    // The seed CIDR also materialises as the first named source (CRYPTARCH-39)
    // so the provision form's checkbox story works out of the box. DO NOTHING
    // on conflict: an admin's renames/edits win over the seed.
    if !seed_cidr.is_empty() {
        let _ = sqlx::query(
            "INSERT INTO server_sources (server_id, label, cidr, is_default) \
             SELECT id, 'db network', $2::cidr, TRUE FROM managed_servers WHERE name = $1 \
             ON CONFLICT DO NOTHING",
        )
        .bind(&s.name)
        .bind(seed_cidr)
        .execute(db)
        .await;
    }
    // In-stack dial path (CRYPTARCH-40): materialise "host:port" from the
    // env as a listener labeled "db network". DO NOTHING on conflict — the
    // admin owns the row after first boot.
    if let Some(spec) = s.stack_listener.as_deref() {
        match spec.rsplit_once(':').and_then(|(h, p)| {
            let port: u16 = p.parse().ok().filter(|p| *p != 0)?;
            valid_listener_host(h).then(|| (h.to_string(), port))
        }) {
            Some((host, port)) => {
                let _ = sqlx::query(
                    "INSERT INTO server_listeners (server_id, host, port, label, position) \
                     SELECT id, $2, $3, 'db network', 0 FROM managed_servers WHERE name = $1 \
                     ON CONFLICT (server_id, host, port) DO NOTHING",
                )
                .bind(&s.name)
                .bind(&host)
                .bind(i32::from(port))
                .execute(db)
                .await;
            }
            None => tracing::warn!(
                "CRYPTARCH_SEED_SERVER_STACK_LISTENER '{spec}' is not host:port — ignored"
            ),
        }
    }
    tracing::info!(
        "seed server '{}' upserted from env — its stored DSN now matches CRYPTARCH_SEED_SERVER_DSN",
        s.name
    );
    Ok(())
}

/// A named ingress range on a server ("db network" → 172.18.0.0/16).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct NamedSource {
    pub id: Uuid,
    pub label: String,
    pub cidr: String,
    pub is_default: bool,
}

/// All named sources for one server, defaults first then by label.
pub async fn sources_for(db: &sqlx::PgPool, server_id: Uuid) -> Vec<NamedSource> {
    sqlx::query_as::<_, NamedSource>(
        "SELECT id, label, cidr::text AS cidr, is_default FROM server_sources \
         WHERE server_id = $1 ORDER BY is_default DESC, label",
    )
    .bind(server_id)
    .fetch_all(db)
    .await
    .unwrap_or_default()
}

/// Resolve chosen source ids to (cidr, label) — scoped to the server, so a
/// crafted id from another server's list resolves to nothing.
pub async fn resolve_sources(
    db: &sqlx::PgPool,
    server_id: Uuid,
    ids: &[Uuid],
) -> Vec<(String, String)> {
    if ids.is_empty() {
        return Vec::new();
    }
    sqlx::query_as::<_, (String, String)>(
        "SELECT cidr::text, label FROM server_sources \
         WHERE server_id = $1 AND id = ANY($2) ORDER BY label",
    )
    .bind(server_id)
    .bind(ids)
    .fetch_all(db)
    .await
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_accepts_sane_inputs() {
        for ok in ["10.10.12.33", "10.10.100.0/24", "0.0.0.0/0", "192.168.1.1/32", "::1", "fd00::/8"] {
            assert!(valid_cidr(ok), "{ok} should be valid");
        }
    }

    #[test]
    fn cidr_rejects_garbage() {
        for bad in [
            "", "db.internal", "10.10.100.0/33", "::1/129", "10.0.0.0/+8", "10.0.0.0/08",
            "10.0.0.0/", "1.2.3/24", "10.0.0.1\nhost all all 0.0.0.0/0 trust", "10.0.0.1 md5",
        ] {
            assert!(!valid_cidr(bad), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn cidr_rejects_host_bits_set() {
        // Postgres CIDR type semantics: host bits right of the mask must be 0.
        for bad in ["10.1.2.3/24", "10.1.2.3/8", "192.168.1.1/0", "fd00::1/8"] {
            assert!(!valid_cidr(bad), "{bad} has host bits set — must be rejected");
        }
        for ok in ["10.1.2.3/32", "10.1.2.0/24", "::/0", "fd00::/8"] {
            assert!(valid_cidr(ok), "{ok} should be valid");
        }
    }

    #[test]
    fn listener_hosts() {
        for ok in ["localhost", "192.168.8.14", "10.8.107.202", "::1", "pg.jebe.sh",
                   "wuwuzla.tail-net.ts.net", "a-b.c-d.example"] {
            assert!(valid_listener_host(ok), "{ok} should be valid");
        }
        for bad in ["", "-lead.example", "trail-.example", "a..b", "host name",
                    "under_score.example", "pg.jebe.sh\nhost all all 0.0.0.0/0 trust",
                    "300.1.2.3", "999.999.999.999", &"x".repeat(254)] {
            assert!(!valid_listener_host(bad), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn server_names() {
        for ok in ["local", "pg-prod-1", "db_2"] {
            assert!(valid_server_name(ok), "{ok}");
        }
        for bad in ["", "UPPER", "1leading", "-lead", "a b", &"x".repeat(65), "naïve"] {
            assert!(!valid_server_name(bad), "{bad:?}");
        }
    }
}

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

    /// Every server we hold a live engine for.
    ///
    /// Deliberately not [`ServerRegistry::list`], which answers "what can a
    /// user provision onto" and may legitimately be narrower. Maintenance
    /// passes want every server they can actually reach — a server excluded
    /// from the picker still has databases on it, and skipping it would make
    /// "not surveyed" indistinguishable from "surveyed, nothing found".
    pub fn ids(&self) -> Vec<Uuid> {
        self.0.read().unwrap().engines.keys().copied().collect()
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
    if let Some(why) = check.version_refusal() {
        anyhow::bail!("{why}");
    }
    if let Some(why) = check.switch_refusal() {
        anyhow::bail!("{why}");
    }
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

/// What the server says about a candidate admin DSN's role. The CRUD refuses
/// superuser and demands both create attributes — the security spine,
/// enforced at the door.
///
/// THE LOGIN, NOT JUST THE CURRENT ROLE (S8b audit P1). A DSN can carry
/// `options=-c role=x`: the connection authenticates as one role and then
/// acts as another, so `current_user` alone would vet `x` while the stored
/// credential is the login's — a superuser's, recoverable with `SET ROLE
/// NONE`. So the check reads `session_user` too, refuses a DSN whose role
/// differs from its login, and counts as superuser a login that is a member
/// of any superuser role, since it can `SET ROLE` to it.
pub struct RoleCheck {
    pub role: String,
    /// `session_user`: who the DSN authenticates as.
    pub login: String,
    /// The login or the role is a superuser, or the login is a member of a
    /// superuser role.
    pub is_superuser: bool,
    pub can_createdb: bool,
    pub can_createrole: bool,
    pub server_version: String,
    /// `server_version_num`, e.g. 180006 — compared, never parsed from the text.
    pub server_version_num: i32,
}

/// The oldest PostgreSQL a managed server may run (CRYPTARCH-128).
///
/// Restores depend on two things PostgreSQL 14 introduced: `pg_locks.waitstart`,
/// which is how the lock watchdog measures a wait, and
/// `client_connection_check_interval`, which is what stops a dead restore client
/// leaving its backend queued. On 13 the second is an unknown startup option, so
/// EVERY restore would fail at connect — refused at the door instead.
pub const MIN_SERVER_VERSION_NUM: i32 = 140000;

impl RoleCheck {
    /// Why this DSN is refused for acting as a role other than the one it
    /// logs in as, if it does.
    pub fn switch_refusal(&self) -> Option<String> {
        (self.login != self.role).then(|| {
            format!(
                "the DSN logs in as '{}' and then acts as '{}' — connect as the panel role \
                 itself, without a role option",
                self.login, self.role
            )
        })
    }

    /// Why this server is too old to manage, if it is.
    pub fn version_refusal(&self) -> Option<String> {
        (self.server_version_num < MIN_SERVER_VERSION_NUM).then(|| {
            format!(
                "PostgreSQL {} is too old — Cryptarch needs 14 or newer (restores rely on \
                 features 14 introduced)",
                self.server_version
            )
        })
    }
}

/// Connect with a candidate admin DSN (short timeout, single connection) and
/// report the role's attributes. Errors are connection/auth failures.
pub async fn check_admin_role(dsn: &str) -> anyhow::Result<RoleCheck> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(4))
        .connect(dsn)
        .await?;
    let row: (String, String, bool, bool, bool, String, i32) = sqlx::query_as(
        "SELECT c.rolname::text, s.rolname::text, \
                s.rolsuper OR c.rolsuper OR EXISTS ( \
                    SELECT 1 FROM pg_roles su \
                    WHERE su.rolsuper AND pg_has_role(s.oid, su.oid, 'MEMBER')), \
                c.rolcreatedb, c.rolcreaterole, \
                current_setting('server_version'), current_setting('server_version_num')::int \
         FROM pg_roles s, pg_roles c \
         WHERE s.rolname = session_user AND c.rolname = current_user",
    )
    .fetch_one(&pool)
    .await?;
    pool.close().await;
    Ok(RoleCheck {
        role: row.0,
        login: row.1,
        is_superuser: row.2,
        can_createdb: row.3,
        can_createrole: row.4,
        server_version: row.5,
        server_version_num: row.6,
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

/// The widest range a tenant may allow at the edge by themselves (CRYPTARCH-142;
/// Antun, 2026-10-06). Wider is an admin's call — or an admin's named source /
/// server default, which IS that call, made in advance for exactly that range.
pub const TENANT_WIDEST_V4: u8 = 16;
pub const TENANT_WIDEST_V6: u8 = 48;

/// A valid IP or CIDR as (network, prefix), IPv4-mapped IPv6 ranges judged as
/// the IPv4 range they carry (`::ffff:10.0.0.0/104` is `10.0.0.0/8`), so the
/// limit cannot be stepped around by spelling a range in the other family.
fn net(s: &str) -> Option<(std::net::IpAddr, u8)> {
    use std::net::IpAddr;
    if !valid_cidr(s) {
        return None;
    }
    let (ip, n) = match s.split_once('/') {
        Some((ip, n)) => (ip.parse::<IpAddr>().ok()?, n.parse::<u8>().ok()?),
        None => {
            let ip = s.parse::<IpAddr>().ok()?;
            (ip, if ip.is_ipv4() { 32 } else { 128 })
        }
    };
    Some(match ip {
        IpAddr::V6(v6) if n >= 96 => match v6.to_ipv4_mapped() {
            Some(v4) => (IpAddr::V4(v4), n - 96),
            None => (ip, n),
        },
        _ => (ip, n),
    })
}

/// Whether a range reaches 0.0.0.0 / :: — "everything", never a tenant's at
/// any width: IPv4 0.0.0.0/8 and anything containing it, IPv6 ::/n, and an
/// IPv6 range that contains the whole IPv4-mapped block.
fn reaches_everything(ip: std::net::IpAddr, n: u8) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.octets()[0] == 0,
        std::net::IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let mapped = u128::from(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0));
            let mask = if n == 0 { 0 } else { u128::MAX << (128 - n) };
            bits == 0 || (n <= 96 && mapped & mask == bits)
        }
    }
}

/// Whether a NON-admin may allow `cidr`: /16 (IPv6 /48) or narrower, or exactly
/// one of `approved` (the server's admin-configured ranges), and in either case
/// never a range reaching 0.0.0.0. Admins are not asked. False for anything
/// that is not a valid range.
pub fn tenant_may_allow(cidr: &str, approved: &[String]) -> bool {
    let Some((ip, n)) = net(cidr) else { return false };
    if reaches_everything(ip, n) {
        return false;
    }
    let narrow = match ip {
        std::net::IpAddr::V4(_) => n >= TENANT_WIDEST_V4,
        std::net::IpAddr::V6(_) => n >= TENANT_WIDEST_V6,
    };
    narrow || approved.iter().any(|a| net(a) == Some((ip, n)))
}

/// The ranges an admin has configured for `server_id` — its named sources and
/// its default consumer CIDR — which a tenant may allow whatever their width.
pub async fn approved_ranges(db: &sqlx::PgPool, server_id: Uuid) -> Vec<String> {
    let mut out: Vec<String> = sources_for(db, server_id).await.into_iter().map(|s| s.cidr).collect();
    let default: Option<String> = sqlx::query_scalar(
        "SELECT default_consumer_cidr::text FROM managed_servers WHERE id = $1",
    )
    .bind(server_id)
    .fetch_optional(db)
    .await
    .ok()
    .flatten();
    out.extend(default);
    out
}

/// The refusal both doors show for a range [`tenant_may_allow`] rejects.
pub fn range_too_broad_message(cidr: &str) -> String {
    format!(
        "Only an admin can allow '{cidr}': ranges wider than /{TENANT_WIDEST_V4} \
         (IPv6 /{TENANT_WIDEST_V6}), or reaching 0.0.0.0, are admin-only unless an admin \
         has named that range for this server. Use a narrower range, or ask an admin."
    )
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

    /// CRYPTARCH-142 (Antun, 2026-10-06): tenants allow /16 (IPv6 /48) or
    /// narrower by themselves; wider is admin-only unless an admin named that
    /// exact range for the server; anything reaching 0.0.0.0 never is.
    #[test]
    fn tenant_range_limits() {
        let none: &[String] = &[];
        for ok in ["10.1.0.0/16", "10.10.100.0/24", "203.0.113.7", "203.0.113.7/32",
                   "2001:db8:1::/48", "2001:db8::1", "::ffff:10.1.0.0/112", "::1"] {
            assert!(tenant_may_allow(ok, none), "{ok} should be a tenant's to allow");
        }
        for broad in ["10.0.0.0/15", "10.0.0.0/8", "128.0.0.0/1", "0.0.0.0/0",
                      "2001:db8::/47", "::/0", "::ffff:10.0.0.0/104"] {
            assert!(!tenant_may_allow(broad, none), "{broad} is wider than a tenant may allow");
        }
        // Reaching 0.0.0.0 is never a tenant's, at any width, approved or not.
        let zeros = ["0.0.0.0", "0.0.0.0/16", "0.1.0.0/16", "::", "::/64",
                     "::ffff:0.0.0.0/96", "::ffff:0.0.0.0/120", "::fffe:0:0/95"];
        let approved: Vec<String> = zeros.iter().map(|z| z.to_string()).collect();
        for z in zeros {
            assert!(!tenant_may_allow(z, &approved), "{z} reaches everything");
        }
        // An admin-named range is approval for exactly that range.
        let named = vec!["10.0.0.0/8".to_string(), "2001:db8::/32".to_string()];
        assert!(tenant_may_allow("10.0.0.0/8", &named));
        assert!(tenant_may_allow("2001:db8::/32", &named));
        assert!(!tenant_may_allow("10.0.0.0/7", &named), "approval is for the named range, not wider");
        assert!(!tenant_may_allow("0.0.0.0/0", &["0.0.0.0/0".to_string()]));
        // Garbage is never allowed (callers validate first; this must not be the gap).
        assert!(!tenant_may_allow("not-an-ip", none));
    }

    fn check_at(num: i32, text: &str) -> RoleCheck {
        RoleCheck {
            role: "cryptarch_admin".into(),
            login: "cryptarch_admin".into(),
            is_superuser: false,
            can_createdb: true,
            can_createrole: true,
            server_version: text.into(),
            server_version_num: num,
        }
    }

    #[test]
    fn servers_older_than_14_are_refused_and_14_is_not() {
        assert!(check_at(130_016, "13.16").version_refusal().is_some(), "13 must be refused");
        assert!(check_at(MIN_SERVER_VERSION_NUM, "14.0").version_refusal().is_none(), "14.0 is the floor");
        assert!(check_at(180_006, "18.6").version_refusal().is_none());
    }

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

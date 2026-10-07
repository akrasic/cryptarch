//! Admin CRUD for the managed-server registry (CRYPTARCH-10).
//!
//! The add flow is the security spine's front door: it verifies the candidate
//! admin DSN actually connects, then REFUSES superuser roles outright and
//! demands CREATEDB + CREATEROLE. DSNs are encrypted before they touch the
//! metadata DB. Every mutation audits before returning.

use serde::Deserialize;
use uuid::Uuid;

use crate::provision::{audit, audit_in};
use crate::servers::{self, ServerRow};
use crate::web::AppState;

/// Full row for the admin views (no cred material — flags only).
#[derive(sqlx::FromRow, serde::Serialize)]
pub struct AdminServerRow {
    pub id: Uuid,
    pub name: String,
    pub engine: String,
    pub host: String,
    pub port: i32,
    pub is_active: bool,
    pub pool_mode: String,
    pub default_pool_size: i32,
    pub max_client_conn: i32,
    pub max_db_connections: i32,
    pub max_user_connections: i32,
    pub tls_mode: String,
    pub backend_kind: String,
    pub default_consumer_cidr: Option<String>,
    pub has_admin_dsn: bool,
    pub has_bouncer_dsn: bool,
    pub db_count: i64,
    pub init_status: String,
    pub bouncer_conf_dir: Option<String>,
    pub edge_dirty: bool,
    pub edge_synced_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Why a server action did not happen.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("That server doesn't exist — it may have been removed.")]
    NotFound,
    #[error("Something went wrong — see the server log.")]
    Internal,
}

pub async fn list_servers(db: &sqlx::PgPool) -> Result<Vec<AdminServerRow>, sqlx::Error> {
    sqlx::query_as::<_, AdminServerRow>(LIST_SERVERS_SQL).fetch_all(db).await
}

pub async fn find_server(db: &sqlx::PgPool, id: Uuid) -> Result<Option<AdminServerRow>, sqlx::Error> {
    sqlx::query_as::<_, AdminServerRow>(ONE_SERVER_SQL).bind(id).fetch_optional(db).await
}

/// "disabled", "active" (an engine is registered) or "unreachable" (enabled,
/// but no engine could be connected).
pub fn live_status(state: &AppState, s: &AdminServerRow) -> &'static str {
    if !s.is_active {
        "disabled"
    } else if state.servers.list().iter().any(|i| i.id == s.id) {
        "active"
    } else {
        "unreachable"
    }
}

/// One database's pool-override row for the server detail page.
#[derive(sqlx::FromRow, serde::Serialize)]
pub struct DbKnobRow {
    pub id: Uuid,
    pub name: String,
    pub status: String,
    /// `None`: the server's mode applies.
    pub pool_mode: Option<String>,
    /// `None`: the server's limit applies.
    pub max_connections: Option<i32>,
}

// A macro rather than a `const` so the two full queries below can be built
// with `concat!` and stay `&'static str`. Joining a const to a suffix needs
// `format!`, and a query built by `format!` is the shape that is safe today
// and an injection the day someone interpolates a variable into it — sqlx 0.9
// rejects it for exactly that reason. Keeping the whole string static means
// these two sites need no `AssertSqlSafe` and cannot rot into one.
macro_rules! select_server {
    () => {
    "SELECT s.id, s.name, s.engine, s.host, s.port, s.is_active, s.pool_mode, \
            s.default_pool_size, s.max_client_conn, s.max_db_connections, s.max_user_connections, \
            s.tls_mode, \
            s.backend_kind, s.default_consumer_cidr::text AS default_consumer_cidr, \
            octet_length(s.admin_dsn_enc) > 0 AS has_admin_dsn, \
            octet_length(s.bouncer_admin_dsn_enc) > 0 AS has_bouncer_dsn, \
            (SELECT COUNT(*) FROM databases d WHERE d.server_id = s.id) AS db_count, \
            s.init_status, s.bouncer_conf_dir, s.edge_dirty, s.edge_synced_at \
     FROM managed_servers s"
    };
}

// `pub` so `every_sql_const_parses_against_a_real_server` can hand them to a
// real server, the same reason `repair::PANEL_ADMINISTERED_ROLES_SQL` is.
pub const LIST_SERVERS_SQL: &str = concat!(select_server!(), " ORDER BY s.name");
pub const ONE_SERVER_SQL: &str = concat!(select_server!(), " WHERE s.id = $1");

// ---- list ---------------------------------------------------------------

// ---- add ----------------------------------------------------------------

#[derive(Deserialize)]
pub struct AddInput {
    pub name: String,
    pub admin_dsn: String,
    pub bouncer_dsn: Option<String>,
    pub host: String,
    /// String, not u16: out-of-range input must produce a friendly re-rendered
    /// form, not axum's bare 422 that eats everything the admin typed.
    pub port: String,
    pub pool_mode: String,
    pub tls_mode: String,
    pub backend_kind: String,
    pub default_consumer_cidr: Option<String>,
}

/// Why a server was not added, or its credentials not changed. The messages
/// are the admin's to read: none of them repeats a DSN.
#[derive(Debug, thiserror::Error)]
pub enum AddError {
    /// A field is malformed.
    #[error("{0}")]
    Invalid(String),
    /// The DSN did not connect, or its role could not be read.
    #[error("{0}")]
    CheckFailed(String),
    /// It connected, and the role is not one Cryptarch will hold: superuser,
    /// missing CREATEDB/CREATEROLE, or a server too old.
    #[error("{0}")]
    Refused(String),
    #[error("A server named '{0}' already exists.")]
    NameTaken(String),
    #[error("That server doesn't exist — it may have been removed.")]
    NotFound,
    #[error("Saving failed — see the server log.")]
    Internal,
}

/// Connect with a candidate admin DSN and decide whether its role is one the
/// security spine allows: never superuser, always CREATEDB and CREATEROLE, on
/// a supported version. Shared by adding a server and rotating its login.
/// A connection error, with the DSN's password taken out wherever it appears.
/// The drivers' messages repeat parts of what was typed (an unknown sslmode
/// value, say), and a password pasted into the wrong place would come back
/// with them.
fn scrub_password(dsn: &str, message: &str) -> String {
    let password = dsn
        .split_once("://")
        .and_then(|(_, rest)| rest.split_once('@'))
        .and_then(|(userinfo, _)| userinfo.split_once(':'))
        .map(|(_, pw)| pw)
        .filter(|pw| !pw.is_empty());
    match password {
        Some(pw) => message.replace(pw, "****"),
        None => message.to_string(),
    }
}

async fn vet_admin_dsn(dsn: &str) -> Result<servers::RoleCheck, AddError> {
    let check = servers::check_admin_role(dsn)
        .await
        .map_err(|e| AddError::CheckFailed(format!("Admin DSN check failed: {}", scrub_password(dsn, &e.to_string()))))?;
    if let Some(why) = check.version_refusal() {
        return Err(AddError::Refused(format!("Refused: {why}.")));
    }
    if let Some(why) = check.switch_refusal() {
        return Err(AddError::Refused(format!("Refused: {why}.")));
    }
    if check.is_superuser {
        return Err(AddError::Refused(format!(
            "Refused: role '{}' is SUPERUSER, or can become one. Cryptarch's spine is a CREATEDB CREATEROLE role — \
             create one (CREATE ROLE cryptarch_admin LOGIN CREATEDB CREATEROLE PASSWORD '...') and use that.",
            check.role
        )));
    }
    if !check.can_createdb || !check.can_createrole {
        return Err(AddError::Refused(format!(
            "Refused: role '{}' needs both CREATEDB and CREATEROLE (has createdb={}, createrole={}).",
            check.role, check.can_createdb, check.can_createrole
        )));
    }
    Ok(check)
}

/// Validate → role-check (refuse superuser) → encrypt → insert and audit in
/// one transaction → register live.
pub async fn add_server(state: &AppState, actor: &str, input: &AddInput) -> Result<Uuid, AddError> {
    let name = input.name.trim();
    if !servers::valid_server_name(name) {
        return Err(AddError::Invalid(
            "Server name: lowercase letter first; lowercase letters, digits, - and _ only; max 64.".into(),
        ));
    }
    let port = validate_common(input).map_err(AddError::Invalid)?;

    // The front door: connect with the candidate DSN and inspect the role.
    let check = vet_admin_dsn(input.admin_dsn.trim()).await?;

    let seal = |d: &str| {
        state.crypto.seal(d).map_err(|e| {
            tracing::error!("sealing a DSN for '{name}': {e}");
            AddError::Internal
        })
    };
    let admin_enc = seal(input.admin_dsn.trim())?;
    let bouncer_enc = match input.bouncer_dsn.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(d) => seal(d)?,
        None => Vec::new(),
    };
    let cidr = input.default_consumer_cidr.as_deref().map(str::trim).filter(|s| !s.is_empty());

    let internal = |e: sqlx::Error| {
        tracing::error!("adding server '{name}': {e}");
        AddError::Internal
    };
    let mut tx = state.db.begin().await.map_err(internal)?;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO managed_servers \
             (name, engine, host, port, admin_dsn_enc, bouncer_admin_dsn_enc, \
              pool_mode, tls_mode, backend_kind, default_consumer_cidr) \
         VALUES ($1, 'postgres', $2, $3, $4, $5, $6, $7, $8, NULLIF($9, '')::cidr) \
         RETURNING id",
    )
    .bind(name)
    .bind(input.host.trim())
    .bind(i32::from(port))
    .bind(&admin_enc)
    .bind(&bouncer_enc)
    .bind(&input.pool_mode)
    .bind(&input.tls_mode)
    .bind(&input.backend_kind)
    .bind(cidr.unwrap_or(""))
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        if e.as_database_error().is_some_and(|d| d.is_unique_violation()) {
            AddError::NameTaken(name.to_string())
        } else {
            internal(e)
        }
    })?;
    crate::provision::audit_in(
        &mut tx,
        actor,
        "add_server",
        Some(name),
        Some(&format!("role={} pg={} advertised={}:{}", check.role, check.server_version, input.host.trim(), port)),
    )
    .await
    .map_err(internal)?;
    tx.commit().await.map_err(internal)?;

    // Register live so provisioning works without a restart.
    let row = ServerRow {
        id,
        name: name.to_string(),
        engine: "postgres".into(),
        host: input.host.trim().to_string(),
        port: i32::from(port),
        admin_dsn_enc: admin_enc,
    };
    match servers::connect_row(&state.crypto, &row, state.allow_superuser).await {
        Ok(engine) => {
            state.servers.register(id, name.to_string(), "postgres".into(), engine);
            recheck_still_active(state, id).await;
        }
        Err(e) => tracing::error!("server '{name}' saved but engine connect failed: {e}"),
    }
    Ok(id)
}

/// Validate the shared (non-DSN) fields; returns the parsed advertised port.
fn validate_common(input: &AddInput) -> Result<u16, String> {
    if !servers::valid_listener_host(input.host.trim()) {
        return Err(
            "Advertised host must be an IP or a valid host name — it's what lands in user connection strings."
                .into(),
        );
    }
    let port: u16 = match input.port.trim().parse() {
        Ok(p) if p != 0 => p,
        _ => return Err("Advertised port must be 1-65535.".into()),
    };
    if !["session", "transaction"].contains(&input.pool_mode.as_str()) {
        return Err("Invalid pool mode.".into());
    }
    if !["off", "edge"].contains(&input.tls_mode.as_str()) {
        return Err("Invalid TLS mode.".into());
    }
    if !["docker", "vm"].contains(&input.backend_kind.as_str()) {
        return Err("Invalid backend kind.".into());
    }
    if let Some(c) = input.default_consumer_cidr.as_deref().map(str::trim).filter(|s| !s.is_empty())
        && !servers::valid_cidr(c)
    {
        return Err(format!(
            "'{c}' is not a valid IP or CIDR (hostnames are not allowed, and network \
             prefixes must have zero host bits — 10.1.2.0/24, not 10.1.2.3/24)."
        ));
    }
    Ok(port)
}

/// Parse one pool knob with a range that mirrors the schema CHECK — the form
/// must fail friendlier than a constraint violation would.
fn parse_knob(label: &str, raw: &str, min: i32, max: i32) -> Result<i32, String> {
    match raw.trim().parse::<i32>() {
        Ok(v) if (min..=max).contains(&v) => Ok(v),
        _ => Err(format!("{label} must be a number between {min} and {max}.")),
    }
}

/// The four numeric pool knobs, validated: (default_pool_size,
/// max_client_conn, max_db_connections, max_user_connections).
fn validate_knobs(input: &PoolingInput) -> Result<(i32, i32, i32, i32), String> {
    Ok((
        parse_knob("Default pool size", &input.default_pool_size, 1, 1000)?,
        parse_knob("Max client connections", &input.max_client_conn, 1, 10000)?,
        parse_knob("Max connections per database (0 = unlimited)", &input.max_db_connections, 0, 10000)?,
        parse_knob("Max connections per user (0 = unlimited)", &input.max_user_connections, 0, 10000)?,
    ))
}

// ---- detail / update ------------------------------------------------------

// Settings save per card (CRYPTARCH-34): each card on the settings page is
// its own form with its own endpoint — validate its few fields, update its
// columns, audit, then do only the follow-up that card's change requires
// (edge sync for rendered config, engine reconnect for identity/DSN).

#[derive(Deserialize)]
pub struct AddressInput {
    pub host: String,
    /// String, not u16: out-of-range input must produce a friendly
    /// re-rendered form, not axum's bare 422.
    pub port: String,
}

#[derive(Deserialize)]
pub struct PoolingInput {
    pub pool_mode: String,
    /// Strings, not ints: friendly re-render on bad input, not a 422.
    pub default_pool_size: String,
    pub max_client_conn: String,
    pub max_db_connections: String,
    pub max_user_connections: String,
}

#[derive(Deserialize)]
pub struct EdgeInput {
    pub tls_mode: String,
    pub backend_kind: String,
    pub default_consumer_cidr: Option<String>,
    /// Empty clears it (falls back to manual edge-config placement).
    pub bouncer_conf_dir: Option<String>,
}

/// Which stored logins a rotation replaced. Neither: both fields were empty,
/// and nothing changed.
pub struct Rotated {
    pub admin: bool,
    pub bouncer: bool,
    /// After a new admin login: `None` when the server is disabled (nothing
    /// to reconnect), else whether Cryptarch is connected with it.
    pub reconnected: Option<bool>,
}

/// Replace a server's stored admin and/or bouncer console DSN. An empty field
/// keeps what is stored; a new admin DSN is vetted exactly as when adding a
/// server. The change and its audit are one transaction; then the live
/// engine reconnects with the new login.
pub async fn rotate_credentials(
    state: &AppState,
    actor: &str,
    id: Uuid,
    admin_dsn: Option<&str>,
    bouncer_dsn: Option<&str>,
) -> Result<Rotated, AddError> {
    let internal = |e: sqlx::Error| {
        tracing::error!("rotating credentials of server {id}: {e}");
        AddError::Internal
    };
    if find_server(&state.db, id).await.map_err(internal)?.is_none() {
        return Err(AddError::NotFound);
    }
    let seal = |d: &str| {
        state.crypto.seal(d).map_err(|e| {
            tracing::error!("sealing a DSN for server {id}: {e}");
            AddError::Internal
        })
    };
    let admin_enc = match admin_dsn.map(str::trim).filter(|s| !s.is_empty()) {
        Some(dsn) => {
            vet_admin_dsn(dsn).await?;
            Some(seal(dsn)?)
        }
        None => None,
    };
    let bouncer_enc = match bouncer_dsn.map(str::trim).filter(|s| !s.is_empty()) {
        Some(d) => Some(seal(d)?),
        None => None,
    };
    let mut rotated = Rotated { admin: admin_enc.is_some(), bouncer: bouncer_enc.is_some(), reconnected: None };
    if !rotated.admin && !rotated.bouncer {
        return Ok(rotated);
    }

    let mut tx = state.db.begin().await.map_err(internal)?;
    let updated = sqlx::query(
        "UPDATE managed_servers SET admin_dsn_enc = COALESCE($2, admin_dsn_enc), \
         bouncer_admin_dsn_enc = COALESCE($3, bouncer_admin_dsn_enc) WHERE id = $1",
    )
    .bind(id)
    .bind(admin_enc.as_ref())
    .bind(bouncer_enc.as_ref())
    .execute(&mut *tx)
    .await
    .map_err(internal)?
    .rows_affected();
    if updated == 0 {
        return Err(AddError::NotFound);
    }
    crate::provision::audit_in(
        &mut tx,
        actor,
        "update_server_credentials",
        Some(&id.to_string()),
        Some(&format!("rotated_admin_dsn={} rotated_bouncer_dsn={}", rotated.admin, rotated.bouncer)),
    )
    .await
    .map_err(internal)?;
    tx.commit().await.map_err(internal)?;

    if rotated.admin {
        rotated.reconnected = reconnect_engine(state, id).await;
    }
    Ok(rotated)
}

/// Reconnect the live engine if the server is active (address or DSN changed).
/// `None`: it is not active, so there was nothing to reconnect; otherwise
/// whether an engine is live with the new settings.
async fn reconnect_engine(state: &AppState, id: Uuid) -> Option<bool> {
    if let Ok(Some(row)) = sqlx::query_as::<_, ServerRow>(
        "SELECT id, name, engine, host, port, admin_dsn_enc FROM managed_servers \
         WHERE id = $1 AND is_active",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    {
        match servers::connect_row(&state.crypto, &row, state.allow_superuser).await {
            Ok(engine) => {
                state.servers.register(row.id, row.name.clone(), row.engine.clone(), engine);
                return recheck_still_active(state, id).await.then_some(true);
            }
            Err(e) => {
                state.servers.unregister(id);
                tracing::error!("server '{}' updated but engine reconnect failed: {e}", row.name);
                return Some(false);
            }
        }
    }
    None
}

/// Close the register/disable race: a concurrent disable between our row
/// fetch and register would leave a live engine on a disabled server. After
/// registering, re-read is_active and back out if it flipped. Answers whether
/// it is still active.
async fn recheck_still_active(state: &AppState, id: Uuid) -> bool {
    let still_active: Option<bool> =
        sqlx::query_scalar("SELECT is_active FROM managed_servers WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
    if still_active != Some(true) {
        state.servers.unregister(id);
        return false;
    }
    true
}

// ---- enable / disable -------------------------------------------------------

/// Where an enable or disable left the server. `active` is the state it is in
/// now — a disable that landed while an enable was connecting wins, and is
/// reported as disabled rather than as a failed connect.
pub struct ActiveOutcome {
    pub active: bool,
    /// Enabled: whether an engine could be connected. Disabled: `None`.
    pub connected: Option<bool>,
}

/// Enable or disable a server: the flag and its audit in one transaction,
/// then the live engine follows.
pub async fn set_active_for(
    state: &AppState,
    actor: &str,
    id: Uuid,
    active: bool,
) -> Result<ActiveOutcome, ServerError> {
    let internal = |e: sqlx::Error| {
        tracing::error!("setting server {id} active={active}: {e}");
        ServerError::Internal
    };
    let mut tx = state.db.begin().await.map_err(internal)?;
    let updated = sqlx::query("UPDATE managed_servers SET is_active = $1 WHERE id = $2")
        .bind(active)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(internal)?
        .rows_affected();
    if updated == 0 {
        return Err(ServerError::NotFound);
    }
    crate::provision::audit_in(
        &mut tx,
        actor,
        if active { "enable_server" } else { "disable_server" },
        Some(&id.to_string()),
        None,
    )
    .await
    .map_err(internal)?;
    tx.commit().await.map_err(internal)?;

    if !active {
        state.servers.unregister(id);
        return Ok(ActiveOutcome { active: false, connected: None });
    }
    let row = sqlx::query_as::<_, ServerRow>(
        "SELECT id, name, engine, host, port, admin_dsn_enc FROM managed_servers \
         WHERE id = $1 AND is_active",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(internal)?;
    // Disabled again in between: not ours to connect, and said as disabled.
    let Some(row) = row else { return Ok(ActiveOutcome { active: false, connected: None }) };
    match servers::connect_row(&state.crypto, &row, state.allow_superuser).await {
        Ok(engine) => {
            state.servers.register(row.id, row.name.clone(), row.engine.clone(), engine);
            if !recheck_still_active(state, id).await {
                return Ok(ActiveOutcome { active: false, connected: None });
            }
            Ok(ActiveOutcome { active: true, connected: Some(true) })
        }
        Err(e) => {
            tracing::error!("server '{}' enabled but connect failed: {e}", row.name);
            Ok(ActiveOutcome { active: true, connected: Some(false) })
        }
    }
}

// ---- listeners (CRYPTARCH-14) ---------------------------------------------------

#[derive(Deserialize)]
pub struct ListenerAddInput {
    pub host: String,
    pub port: String,
    pub label: String,
}

// ---- named sources (CRYPTARCH-39) -----------------------------------------------

#[derive(Deserialize)]
pub struct SourceAddInput {
    pub label: String,
    pub cidr: String,
    pub is_default: Option<String>,
}

// ---- per-db pool overrides (CRYPTARCH-32) ---------------------------------------

#[derive(Deserialize)]
pub struct DbKnobsInput {
    pub pool_mode: String,
    pub max_connections: Option<String>,
}

// ---- server configuration, shared with the API (CRYPTARCH-136, S8c) ------------

/// Why a configuration change did not happen.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A field is malformed.
    #[error("{0}")]
    Invalid(String),
    /// It would duplicate one that exists.
    #[error("{0}")]
    Duplicate(String),
    #[error("That server doesn't exist — it may have been removed.")]
    NotFound,
    /// The listener, source or database is not this server's (any more).
    #[error("That is not on this server — it may already have been removed.")]
    NoSuchItem,
    #[error("Saving failed — see the server log.")]
    Internal,
}

/// What pushing a change to the edge did.
pub enum EdgeSync {
    /// Written and reloaded; the rule count.
    Applied(usize),
    /// No conf dir: rendered for the operator to place by hand.
    Manual { hba: String, knobs: String },
    /// The change is saved, but the edge did not take it.
    Failed(String),
}

impl EdgeSync {
    /// The notice after `what` was saved.
    pub fn note(&self, what: &str) -> String {
        match self {
            EdgeSync::Applied(_) => format!("{what} — edge synced."),
            EdgeSync::Manual { .. } => {
                format!("{what}. No conf dir — apply the change with \"Sync edge now\" (manual placement).")
            }
            EdgeSync::Failed(e) => format!("{what}, but edge sync FAILED: {e}"),
        }
    }
}

async fn sync_after(state: &AppState, id: Uuid) -> EdgeSync {
    match crate::acl::sync_edge(&state.db, &state.crypto, id).await {
        Ok(crate::acl::SyncOutcome::Applied(n)) => EdgeSync::Applied(n),
        Ok(crate::acl::SyncOutcome::ManualPlacement { hba, knobs }) => EdgeSync::Manual { hba, knobs },
        Err(e) => EdgeSync::Failed(e.to_string()),
    }
}

/// Where Cryptarch writes edge files: an absolute path, not the root, with no
/// `..` and no control characters. Edge sync also requires it to hold a
/// pgbouncer.ini before writing anything there.
fn valid_conf_dir(dir: &str) -> bool {
    let path = std::path::Path::new(dir);
    path.is_absolute()
        && dir != "/"
        && !dir.chars().any(char::is_control)
        && path.components().all(|c| !matches!(c, std::path::Component::ParentDir))
}

/// A label shown to users beside a range or an address: 1-32 characters,
/// none of them control characters.
fn check_label(raw: &str) -> Result<&str, ConfigError> {
    let label = raw.trim();
    let n = label.chars().count();
    if n == 0 || n > 32 || label.chars().any(char::is_control) {
        return Err(ConfigError::Invalid("Label required (max 32 characters, no control characters).".into()));
    }
    Ok(label)
}

fn parse_port(raw: &str, what: &str) -> Result<u16, ConfigError> {
    match raw.trim().parse::<u16>() {
        Ok(p) if p != 0 => Ok(p),
        _ => Err(ConfigError::Invalid(format!("{what} must be 1-65535."))),
    }
}

fn cidr_message(c: &str) -> String {
    format!(
        "'{c}' is not a valid IP or CIDR (hostnames are not allowed, and network \
         prefixes must have zero host bits — 10.1.2.0/24, not 10.1.2.3/24)."
    )
}

/// Open the change's transaction with the server's row locked: a change to a
/// server that is gone is NotFound, never a dangling insert.
async fn lock_server(state: &AppState, id: Uuid) -> Result<sqlx::Transaction<'static, sqlx::Postgres>, ConfigError> {
    let internal = |e: sqlx::Error| {
        tracing::error!("changing server {id}: {e}");
        ConfigError::Internal
    };
    let mut tx = state.db.begin().await.map_err(internal)?;
    // NO KEY: provisioning takes KEY SHARE on this row through its foreign
    // key, and need not queue behind a settings change.
    let found: Option<i32> = sqlx::query_scalar("SELECT 1 FROM managed_servers WHERE id = $1 FOR NO KEY UPDATE")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?;
    if found.is_none() {
        return Err(ConfigError::NotFound);
    }
    Ok(tx)
}

fn internal_for(id: Uuid) -> impl Fn(sqlx::Error) -> ConfigError {
    move |e| {
        tracing::error!("changing server {id}: {e}");
        ConfigError::Internal
    }
}

/// The advertised address: what lands in every new connection string. The
/// live engine is re-registered with it; answers whether it reconnected
/// (`None`: the server is disabled).
pub async fn update_address_for(
    state: &AppState,
    actor: &str,
    id: Uuid,
    input: &AddressInput,
) -> Result<Option<bool>, ConfigError> {
    let host = input.host.trim();
    if !servers::valid_listener_host(host) {
        return Err(ConfigError::Invalid(
            "Advertised host must be an IP or a valid host name — it's what lands in user connection strings."
                .into(),
        ));
    }
    let port = parse_port(&input.port, "Advertised port")?;
    let internal = internal_for(id);
    let mut tx = lock_server(state, id).await?;
    sqlx::query("UPDATE managed_servers SET host = $2, port = $3 WHERE id = $1")
        .bind(id)
        .bind(host)
        .bind(i32::from(port))
        .execute(&mut *tx)
        .await
        .map_err(&internal)?;
    audit_in(&mut tx, actor, "update_server_address", Some(&id.to_string()), Some(&format!("advertised={host}:{port}")))
        .await
        .map_err(&internal)?;
    tx.commit().await.map_err(&internal)?;
    // The registry row carries the advertised address (it builds connection
    // strings) — re-register so provisioning sees the new one.
    Ok(reconnect_engine(state, id).await)
}

pub async fn update_pooling_for(
    state: &AppState,
    actor: &str,
    id: Uuid,
    input: &PoolingInput,
) -> Result<EdgeSync, ConfigError> {
    if !["session", "transaction"].contains(&input.pool_mode.as_str()) {
        return Err(ConfigError::Invalid("Invalid pool mode.".into()));
    }
    let (pool_size, client_conn, db_conns, user_conns) = validate_knobs(input).map_err(ConfigError::Invalid)?;
    let internal = internal_for(id);
    let mut tx = lock_server(state, id).await?;
    sqlx::query(
        "UPDATE managed_servers SET pool_mode = $2, default_pool_size = $3, \
         max_client_conn = $4, max_db_connections = $5, max_user_connections = $6 \
         WHERE id = $1",
    )
    .bind(id)
    .bind(&input.pool_mode)
    .bind(pool_size)
    .bind(client_conn)
    .bind(db_conns)
    .bind(user_conns)
    .execute(&mut *tx)
    .await
    .map_err(&internal)?;
    audit_in(
        &mut tx,
        actor,
        "update_server_pooling",
        Some(&id.to_string()),
        Some(&format!(
            "pool={} pool_size={pool_size} max_client={client_conn} max_db={db_conns} max_user={user_conns}",
            input.pool_mode
        )),
    )
    .await
    .map_err(&internal)?;
    tx.commit().await.map_err(&internal)?;
    Ok(sync_after(state, id).await)
}

pub async fn update_edge_for(
    state: &AppState,
    actor: &str,
    id: Uuid,
    input: &EdgeInput,
) -> Result<EdgeSync, ConfigError> {
    if !["off", "edge"].contains(&input.tls_mode.as_str()) {
        return Err(ConfigError::Invalid("Invalid TLS mode.".into()));
    }
    if !["docker", "vm"].contains(&input.backend_kind.as_str()) {
        return Err(ConfigError::Invalid("Invalid backend kind.".into()));
    }
    let cidr = input.default_consumer_cidr.as_deref().map(str::trim).filter(|s| !s.is_empty());
    if let Some(c) = cidr
        && !servers::valid_cidr(c)
    {
        return Err(ConfigError::Invalid(cidr_message(c)));
    }
    let conf_dir = input.bouncer_conf_dir.as_deref().map(str::trim).unwrap_or("");
    if !conf_dir.is_empty() && !valid_conf_dir(conf_dir) {
        return Err(ConfigError::Invalid(
            "The bouncer conf dir must be an absolute path to a directory, without '..'.".into(),
        ));
    }
    let internal = internal_for(id);
    let mut tx = lock_server(state, id).await?;
    // Two servers sharing a conf dir would each overwrite the other's hba on
    // every sync.
    if !conf_dir.is_empty() {
        let taken: Option<String> = sqlx::query_scalar(
            "SELECT name FROM managed_servers WHERE bouncer_conf_dir = $1 AND id <> $2",
        )
        .bind(conf_dir)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(&internal)?;
        if let Some(other) = taken {
            return Err(ConfigError::Duplicate(format!("Server '{other}' already uses that conf dir.")));
        }
    }
    sqlx::query(
        "UPDATE managed_servers SET tls_mode = $2, backend_kind = $3, \
         default_consumer_cidr = NULLIF($4, '')::cidr, bouncer_conf_dir = NULLIF($5, '') \
         WHERE id = $1",
    )
    .bind(id)
    .bind(&input.tls_mode)
    .bind(&input.backend_kind)
    .bind(cidr.unwrap_or(""))
    .bind(conf_dir)
    .execute(&mut *tx)
    .await
    .map_err(&internal)?;
    audit_in(
        &mut tx,
        actor,
        "update_server_edge",
        Some(&id.to_string()),
        Some(&format!(
            "tls={} backend={} conf_dir_set={}",
            input.tls_mode,
            input.backend_kind,
            !conf_dir.is_empty()
        )),
    )
    .await
    .map_err(&internal)?;
    tx.commit().await.map_err(&internal)?;
    // tls_mode switches host/hostssl in the hba; the conf dir is where
    // renders land — both demand a sync.
    Ok(sync_after(state, id).await)
}

pub async fn add_listener_for(
    state: &AppState,
    actor: &str,
    id: Uuid,
    input: &ListenerAddInput,
) -> Result<(), ConfigError> {
    let host = input.host.trim();
    if !servers::valid_listener_host(host) {
        return Err(ConfigError::Invalid("Listener host must be an IP or a valid FQDN.".into()));
    }
    let port = parse_port(&input.port, "Listener port")?;
    let label = check_label(&input.label)?;
    let internal = internal_for(id);
    let mut tx = lock_server(state, id).await?;
    let added = sqlx::query(
        "INSERT INTO server_listeners (server_id, host, port, label, position) \
         VALUES ($1, $2, $3, $4, \
                 (SELECT COALESCE(MAX(position), 0) + 1 FROM server_listeners WHERE server_id = $1)) \
         ON CONFLICT (server_id, host, port) DO NOTHING",
    )
    .bind(id)
    .bind(host)
    .bind(i32::from(port))
    .bind(label)
    .execute(&mut *tx)
    .await
    .map_err(&internal)?
    .rows_affected();
    if added == 0 {
        // ON CONFLICT skipped it — an action that didn't happen is not audited.
        return Err(ConfigError::Duplicate("A listener with that host:port already exists.".into()));
    }
    audit_in(&mut tx, actor, "listener_add", Some(&id.to_string()), Some(&format!("{label}={host}:{port}")))
        .await
        .map_err(&internal)?;
    tx.commit().await.map_err(&internal)
}

pub async fn remove_listener_for(state: &AppState, actor: &str, id: Uuid, listener_id: Uuid) -> Result<(), ConfigError> {
    let internal = internal_for(id);
    let mut tx = lock_server(state, id).await?;
    let removed: Option<String> = sqlx::query_scalar(
        "DELETE FROM server_listeners WHERE id = $1 AND server_id = $2 \
         RETURNING label || '=' || host || ':' || port",
    )
    .bind(listener_id)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(&internal)?;
    let Some(what) = removed else { return Err(ConfigError::NoSuchItem) };
    audit_in(&mut tx, actor, "listener_remove", Some(&id.to_string()), Some(&what)).await.map_err(&internal)?;
    tx.commit().await.map_err(&internal)
}

/// A named source: a labelled range offered on the provision form, and one a
/// tenant may then allow however wide it is (Security Spine rule 8) — an
/// admin naming it is the approval. `servers::tenant_may_allow` still never
/// lets a tenant reach everything.
pub async fn add_source_for(
    state: &AppState,
    actor: &str,
    id: Uuid,
    label: &str,
    cidr: &str,
    is_default: bool,
) -> Result<(), ConfigError> {
    let label = check_label(label)?;
    let cidr = cidr.trim();
    if !servers::valid_cidr(cidr) {
        return Err(ConfigError::Invalid(cidr_message(cidr)));
    }
    let internal = internal_for(id);
    let mut tx = lock_server(state, id).await?;
    let added = sqlx::query(
        "INSERT INTO server_sources (server_id, label, cidr, is_default) \
         VALUES ($1, $2, $3::cidr, $4) ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(label)
    .bind(cidr)
    .bind(is_default)
    .execute(&mut *tx)
    .await
    .map_err(&internal)?
    .rows_affected();
    if added == 0 {
        return Err(ConfigError::Duplicate("A source with that label or range already exists on this server.".into()));
    }
    audit_in(&mut tx, actor, "source_add", Some(&id.to_string()), Some(&format!("{label}={cidr} default={is_default}")))
        .await
        .map_err(&internal)?;
    tx.commit().await.map_err(&internal)
}

/// Removing a named source never touches existing ACL entries — it only stops
/// being offered. Revocation stays an explicit per-database act.
pub async fn remove_source_for(state: &AppState, actor: &str, id: Uuid, source_id: Uuid) -> Result<(), ConfigError> {
    let internal = internal_for(id);
    let mut tx = lock_server(state, id).await?;
    let removed: Option<String> = sqlx::query_scalar(
        "DELETE FROM server_sources WHERE id = $1 AND server_id = $2 RETURNING label || '=' || cidr",
    )
    .bind(source_id)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(&internal)?;
    let Some(what) = removed else { return Err(ConfigError::NoSuchItem) };
    audit_in(&mut tx, actor, "source_remove", Some(&id.to_string()), Some(&what)).await.map_err(&internal)?;
    tx.commit().await.map_err(&internal)
}

/// One database's pool override on this server; `inherit` and an empty limit
/// fall back to the server's defaults. Answers the database's name.
pub async fn set_db_pool_for(
    state: &AppState,
    actor: &str,
    id: Uuid,
    db_id: Uuid,
    input: &DbKnobsInput,
) -> Result<(String, EdgeSync), ConfigError> {
    let mode: Option<&str> = match input.pool_mode.as_str() {
        "inherit" | "" => None,
        m @ ("session" | "transaction") => Some(m),
        _ => return Err(ConfigError::Invalid("Invalid pool mode.".into())),
    };
    let max: Option<i32> = match input.max_connections.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => None,
        Some(raw) => match raw.parse::<i32>() {
            Ok(v) if (1..=10000).contains(&v) => Some(v),
            _ => return Err(ConfigError::Invalid("Connection limit must be 1-10000, or empty to inherit.".into())),
        },
    };
    let internal = internal_for(id);
    let mut tx = lock_server(state, id).await?;
    // server_id in the WHERE: the URL's server must actually own the db, or
    // a crafted id pair could edit another server's tenant.
    let name: Option<String> = sqlx::query_scalar(
        "UPDATE databases SET pool_mode = $3, max_connections = $4 \
         WHERE id = $1 AND server_id = $2 RETURNING name",
    )
    .bind(db_id)
    .bind(id)
    .bind(mode)
    .bind(max)
    .fetch_optional(&mut *tx)
    .await
    .map_err(&internal)?;
    let Some(name) = name else { return Err(ConfigError::NoSuchItem) };
    audit_in(
        &mut tx,
        actor,
        "db_pool_override",
        Some(&name),
        Some(&format!(
            "pool_mode={} max_connections={}",
            mode.unwrap_or("inherit"),
            max.map_or("inherit".into(), |v| v.to_string())
        )),
    )
    .await
    .map_err(&internal)?;
    tx.commit().await.map_err(&internal)?;
    Ok((name, sync_after(state, id).await))
}

/// Push the current ACL and pool settings to the edge now. Audited with what
/// happened.
pub async fn sync_for(state: &AppState, actor: &str, id: Uuid) -> Result<EdgeSync, ConfigError> {
    if find_server(&state.db, id).await.map_err(internal_for(id))?.is_none() {
        return Err(ConfigError::NotFound);
    }
    let sync = sync_after(state, id).await;
    let note = match &sync {
        EdgeSync::Applied(n) => format!("Edge synced — {n} rule(s) applied."),
        EdgeSync::Manual { .. } => {
            "No conf dir — place these rendered files on the bouncer host, then RELOAD it.".to_string()
        }
        EdgeSync::Failed(e) => format!("Edge sync FAILED: {e}"),
    };
    audit(&state.db, actor, "edge_sync", Some(&id.to_string()), Some(&note)).await;
    Ok(sync)
}

/// What the server page lists besides the row: its pool overrides, named
/// sources and listeners.
pub struct ServerConfig {
    pub databases: Vec<DbKnobRow>,
    pub sources: Vec<servers::NamedSource>,
    pub listeners: Vec<servers::Listener>,
}

pub async fn server_config(state: &AppState, id: Uuid) -> Result<ServerConfig, ConfigError> {
    let internal = internal_for(id);
    let databases = sqlx::query_as::<_, DbKnobRow>(
        "SELECT id, name, status, pool_mode, max_connections FROM databases WHERE server_id = $1 ORDER BY name",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await
    .map_err(&internal)?;
    Ok(ServerConfig {
        databases,
        sources: servers::sources_for(&state.db, id).await,
        listeners: servers::listeners_for(&state.db, id).await,
    })
}

// ---- edge health + sync (CRYPTARCH-13) ------------------------------------------

/// What the edge looks like from here, computed when an admin looks.
pub struct EdgeHealth {
    /// The rendered hba file: a verdict, and what it amounts to.
    pub hba: (String, EdgeState),
    /// The pool-settings fragment, the same way.
    pub knobs: (String, EdgeState),
    /// The bouncer console's `SHOW POOLS`: headers and rows. `None` when the
    /// console is unavailable or not configured.
    pub pools: Option<(Vec<String>, Vec<Vec<String>>)>,
}

/// What one edge check amounts to. `Unknown` is its own state: a file that
/// could not be compared, or a desired state that could not be computed, is
/// not evidence the edge is right, and used to render green beside the ones
/// that were.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EdgeState {
    Ok,
    Bad,
    Unknown,
}

/// On-view edge health: dirty flag, on-disk file drift (checksum + desired
/// compare), and a live pool snapshot from the console. No daemon — the
/// truth is computed when an admin looks, which is when it matters.
pub async fn edge_health_data(state: &AppState, s: &AdminServerRow) -> EdgeHealth {
    // Desired state: fresh render of current acl_entries.
    let desired = match crate::acl::load_rules(&state.db, s.id).await {
        Ok(rules) => Some(crate::acl::render_hba(&rules, &s.tls_mode, crate::acl::console_cidr())),
        Err(_) => None,
    };

    // On-disk state, when we can see the conf dir.
    use EdgeState::{Bad, Ok as Good, Unknown};
    let file_verdict: (String, EdgeState) = match s.bouncer_conf_dir.as_deref().filter(|d| !d.is_empty()) {
        None => (
            "no conf dir — manual placement mode, drift not checkable from here".into(),
            if s.edge_dirty { Bad } else { Unknown },
        ),
        Some(dir) => {
            let path = std::path::Path::new(dir).join("pgbouncer_hba.conf");
            match tokio::fs::read_to_string(&path).await {
                Err(_) => ("hba file missing — run an ACL change or server init".into(), Bad),
                Ok(content) => {
                    let claimed = crate::acl::claimed_checksum(&content).map(str::to_string);
                    let actual = crate::acl::body_checksum(&content);
                    match claimed {
                        None => ("hba not cryptarch-managed (no checksum header)".into(), Bad),
                        Some(c) if c != actual => ("hba HAND-EDITED since last render (checksum mismatch)".into(), Bad),
                        Some(_) => match &desired {
                            Some(d) if *d == content => ("hba matches desired ACL state".into(), Good),
                            Some(_) => ("hba intact but STALE vs current ACL state — sync needed".into(), Bad),
                            None => ("hba intact (desired state unavailable)".into(), Unknown),
                        },
                    }
                }
            }
        }
    };

    // Knobs fragment (CRYPTARCH-32): same drift logic as the hba, plus one
    // extra failure mode — the fragment can be perfect yet inert when
    // pgbouncer.ini doesn't %include it.
    let desired_knobs = match (
        crate::bouncer::load_server_knobs(&state.db, s.id).await,
        crate::bouncer::load_overrides(&state.db, s.id).await,
    ) {
        (Ok(k), Ok(o)) => Some(crate::bouncer::render_knobs(&k, &o)),
        _ => None,
    };
    let knobs_verdict: (String, EdgeState) = match s.bouncer_conf_dir.as_deref().filter(|d| !d.is_empty()) {
        None => ("no conf dir — manual placement mode, drift not checkable from here".into(), Unknown),
        Some(dir) => {
            let dir = std::path::Path::new(dir);
            // `None`: pgbouncer.ini could not be read, so whether it includes
            // the fragment is unknown — not "it does".
            let included = tokio::fs::read_to_string(dir.join("pgbouncer.ini")).await.ok().map(|ini| {
                ini.lines().any(|l| {
                    let l = l.trim_start();
                    l.starts_with("%include") && l.contains(crate::bouncer::KNOBS_FILE)
                })
            });
            let file = match tokio::fs::read_to_string(dir.join(crate::bouncer::KNOBS_FILE)).await {
                Err(_) => ("knobs file missing — run server init or an edge sync".to_string(), Bad),
                Ok(content) => {
                    let claimed = crate::bouncer::claimed_checksum(&content).map(str::to_string);
                    let actual = crate::bouncer::body_checksum(&content);
                    match claimed {
                        None => ("knobs file not cryptarch-managed (no checksum header)".into(), Bad),
                        Some(c) if c != actual => ("knobs HAND-EDITED since last render (checksum mismatch)".into(), Bad),
                        Some(_) => match &desired_knobs {
                            Some(d) if *d == content => ("knobs match desired pool settings".into(), Good),
                            Some(_) => ("knobs intact but STALE vs current settings — sync needed".into(), Bad),
                            None => ("knobs intact (desired state unavailable)".into(), Unknown),
                        },
                    }
                }
            };
            match (included, file) {
                (Some(false), _) => ("pgbouncer.ini does not %include the knobs file — run server init".into(), Bad),
                (None, (_, Good)) => (
                    "knobs match desired pool settings, but pgbouncer.ini could not be read to confirm it \
                     includes them"
                        .into(),
                    Unknown,
                ),
                (_, file) => file,
            }
        }
    };

    // Pool snapshot via console.
    let pools: Option<(Vec<String>, Vec<Vec<String>>)> = if s.has_bouncer_dsn {
        let enc: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT bouncer_admin_dsn_enc FROM managed_servers WHERE id = $1",
        )
        .bind(s.id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
        match enc.and_then(|e| state.crypto.open(&e).ok()) {
            // Tight outer timeout: this runs on every detail-page view, and
            // a hung bouncer must not make its own diagnosis page slow.
            Some(dsn) => tokio::time::timeout(
                std::time::Duration::from_secs(2),
                crate::edge::console_table(&dsn, "SHOW POOLS"),
            )
            .await
            .ok()
            .and_then(Result::ok),
            None => None,
        }
    } else {
        None
    };

    EdgeHealth { hba: file_verdict, knobs: knobs_verdict, pools }
}

// ---- server-init ---------------------------------------------------------------

/// Why server init did not produce a report.
#[derive(Debug, thiserror::Error)]
pub enum InitError {
    #[error("That server doesn't exist — it may have been removed.")]
    NotFound,
    /// It stopped before reporting steps — a stored secret that will not
    /// decrypt, the metadata database unreachable.
    #[error("{0}")]
    Aborted(String),
}

/// Run the idempotent server init and audit what it did, step by step.
pub async fn init_server(state: &AppState, actor: &str, id: Uuid) -> Result<crate::edge::InitOutcome, InitError> {
    match find_server(&state.db, id).await {
        Ok(Some(_)) => {}
        Ok(None) => return Err(InitError::NotFound),
        Err(e) => {
            tracing::error!("loading server {id}: {e}");
            return Err(InitError::Aborted("loading the server failed".into()));
        }
    }
    let outcome = match crate::edge::run_init(&state.db, &state.crypto, id).await {
        Ok(o) => o,
        Err(e) => {
            tracing::error!("server-init {id}: {e:#}");
            audit(&state.db, actor, "server_init", Some(&id.to_string()), Some(&format!("aborted: {e}"))).await;
            return Err(InitError::Aborted(e.to_string()));
        }
    };
    audit(&state.db, actor, "server_init", Some(&id.to_string()),
          Some(&format!("status={} steps={}", outcome.status,
                        outcome.steps.iter().map(|s| format!("{}:{}", s.step, if s.outcome.is_ok() {"ok"} else {"FAIL"}))
                            .collect::<Vec<_>>().join(", "))))
        .await;
    Ok(outcome)
}

// ---- connect-test -------------------------------------------------------------

/// Check the server from Cryptarch's side: the stored admin DSN decrypts,
/// connects, and is a CREATEDB CREATEROLE role that is not a superuser on a
/// supported version; and the advertised address answers. Audited.
pub async fn connect_test(
    state: &AppState,
    actor: &str,
    id: Uuid,
) -> Result<Vec<(String, Result<String, String>)>, ServerError> {
    let row = sqlx::query_as::<_, ServerRow>(
        "SELECT id, name, engine, host, port, admin_dsn_enc FROM managed_servers WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("loading server {id}: {e}");
        ServerError::Internal
    })?
    .ok_or(ServerError::NotFound)?;

    let mut results: Vec<(String, Result<String, String>)> = Vec::new();

    // 1. Admin DSN: decrypt + connect + role attributes.
    match state.crypto.open(&row.admin_dsn_enc) {
        Ok(dsn) => match servers::check_admin_role(&dsn).await {
            Ok(c) => {
                let verdict = if let Some(why) = c.version_refusal() {
                    Err(why)
                } else if let Some(why) = c.switch_refusal() {
                    Err(why)
                } else if c.is_superuser {
                    Err(format!("role '{}' is SUPERUSER — replace it with a CREATEDB CREATEROLE role", c.role))
                } else if !c.can_createdb || !c.can_createrole {
                    Err(format!("role '{}' lacks CREATEDB/CREATEROLE", c.role))
                } else {
                    Ok(format!("role '{}' ok (createdb+createrole, not superuser), PostgreSQL {}", c.role, c.server_version))
                };
                results.push(("Admin connection".into(), verdict));
            }
            Err(e) => results.push(("Admin connection".into(), Err(e.to_string()))),
        },
        Err(e) => results.push(("Admin DSN decrypt".into(), Err(e.to_string()))),
    }

    // 2. Advertised address reachability from Cryptarch's vantage point.
    let port = u16::try_from(row.port).unwrap_or(0);
    results.push((
        format!("Advertised address {}:{}", row.host, row.port),
        servers::tcp_check(&row.host, port).await.map(|_| "reachable".into()),
    ));

    audit(&state.db, actor, "test_server", Some(&row.name),
          Some(&format!("{} checks, {} failed", results.len(),
                        results.iter().filter(|(_, r)| r.is_err()).count())))
        .await;
    Ok(results)
}

// ---- rendering ---------------------------------------------------------------

/// The server's own view of itself, for the dashboard: each read bounded at
/// 3s on top of the engine's op timeout, since this is the page an operator
/// opens when a server is already misbehaving — an unreachable server costs
/// it a note, not a hang. `None` is "did not answer", never "nothing to say".
pub struct ServerSnapshot {
    pub overview: Option<crate::engine::ServerOverview>,
    pub maintenance: Option<crate::engine::MaintenanceReport>,
    /// Which databases on the server are Cryptarch's, for badging.
    pub managed: std::collections::HashSet<String>,
}

pub async fn snapshot(state: &AppState, id: Uuid) -> ServerSnapshot {
    let engine = state.servers.get(id);
    let bound = std::time::Duration::from_secs(3);
    let (overview, maintenance) = match &engine {
        Some(engine) => tokio::join!(
            async { tokio::time::timeout(bound, engine.server_overview()).await.ok().and_then(Result::ok) },
            async { tokio::time::timeout(bound, engine.maintenance()).await.ok().and_then(Result::ok) },
        ),
        None => (None, None),
    };
    let managed = sqlx::query_scalar::<_, String>("SELECT name FROM databases WHERE server_id = $1")
        .bind(id)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default()
        .into_iter()
        .collect();
    ServerSnapshot { overview, maintenance, managed }
}

// ---- settings page ---------------------------------------------------------------


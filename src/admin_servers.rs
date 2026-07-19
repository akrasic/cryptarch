//! Admin CRUD for the managed-server registry (CRYPTARCH-10).
//!
//! The add flow is the security spine's front door: it verifies the candidate
//! admin DSN actually connects, then REFUSES superuser roles outright and
//! demands CREATEDB + CREATEROLE. DSNs are encrypted before they touch the
//! metadata DB. Every mutation audits before returning.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::AdminUser;
use crate::provision::audit;
use crate::servers::{self, ServerRow};
use crate::web::{shell, status_badge, AppState};

/// Full row for the admin views (no cred material — flags only).
#[derive(sqlx::FromRow)]
struct AdminServerRow {
    id: Uuid,
    name: String,
    engine: String,
    host: String,
    port: i32,
    is_active: bool,
    pool_mode: String,
    default_pool_size: i32,
    max_client_conn: i32,
    max_db_connections: i32,
    max_user_connections: i32,
    tls_mode: String,
    backend_kind: String,
    default_consumer_cidr: Option<String>,
    has_admin_dsn: bool,
    has_bouncer_dsn: bool,
    db_count: i64,
    init_status: String,
    bouncer_conf_dir: Option<String>,
    edge_dirty: bool,
    edge_synced_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// One database's pool-override row for the server detail page.
#[derive(sqlx::FromRow)]
struct DbKnobRow {
    id: Uuid,
    name: String,
    status: String,
    pool_mode: Option<String>,
    max_connections: Option<i32>,
}

const SELECT_SERVER: &str =
    "SELECT s.id, s.name, s.engine, s.host, s.port, s.is_active, s.pool_mode, \
            s.default_pool_size, s.max_client_conn, s.max_db_connections, s.max_user_connections, \
            s.tls_mode, \
            s.backend_kind, s.default_consumer_cidr::text AS default_consumer_cidr, \
            octet_length(s.admin_dsn_enc) > 0 AS has_admin_dsn, \
            octet_length(s.bouncer_admin_dsn_enc) > 0 AS has_bouncer_dsn, \
            (SELECT COUNT(*) FROM databases d WHERE d.server_id = s.id) AS db_count, \
            s.init_status, s.bouncer_conf_dir, s.edge_dirty, s.edge_synced_at \
     FROM managed_servers s";

// ---- list ---------------------------------------------------------------

pub async fn list(State(state): State<AppState>, AdminUser(session): AdminUser) -> Response {
    let rows = match sqlx::query_as::<_, AdminServerRow>(&format!("{SELECT_SERVER} ORDER BY s.name"))
        .fetch_all(&state.db)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("loading server list: {e}");
            return crate::web::error_page(&session, axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong", "Loading the server list failed — try again.");
        }
    };
    let live: Vec<Uuid> = state.servers.list().iter().map(|s| s.id).collect();

    shell(
        "Servers · Admin",
        &session,
        html! {
            (crate::admin::admin_nav("servers"))
            h1 { "Managed servers" }
            @if rows.is_empty() {
                p.muted { "None registered. Add the first below." }
            } @else {
                div.table-scroll {
                    table.dbs {
                        thead { tr {
                            th { "Name" } th { "Engine" } th { "Advertised" } th { "Databases" }
                            th { "Pool" } th { "Status" } th { "Health" } th { "" }
                        } }
                        tbody {
                            @for s in &rows {
                                tr {
                                    td { a href={ "/admin/servers/" (s.id) } { code { (s.name) } } }
                                    td { (s.engine) }
                                    td { code { (s.host) ":" (s.port) } }
                                    td.tnum { (s.db_count) }
                                    td { (s.pool_mode) }
                                    td {
                                        @if !s.is_active { (status_badge("disabled")) }
                                        @else if live.contains(&s.id) { (status_badge("active")) }
                                        @else { (status_badge("unreachable")) }
                                    }
                                    td {
                                        @match state.health.get(s.id) {
                                            None => { span.muted { "no data yet" } },
                                            Some(h) if h.all_ok() => { span.st.st-active { span.dot {} "healthy" } },
                                            Some(_) => { span.st.st-bad { span.dot {} "attention" } },
                                        }
                                    }
                                    td {
                                        a.link href={ "/admin/servers/" (s.id) }
                                            aria-label={ "Manage server " (s.name) } { "manage" }
                                        " · "
                                        a.link href={ "/admin/servers/" (s.id) "/settings" }
                                            aria-label={ "Settings for server " (s.name) } { "settings" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            p { a.button href="/admin/servers/new" { "+ Add server" } }
        },
    )
    .into_response()
}

// ---- add ----------------------------------------------------------------

pub async fn new_form(State(_): State<AppState>, AdminUser(session): AdminUser) -> Markup {
    add_page(&session, None, None)
}

#[derive(Deserialize)]
pub struct AddInput {
    name: String,
    admin_dsn: String,
    bouncer_dsn: Option<String>,
    host: String,
    /// String, not u16: out-of-range input must produce a friendly re-rendered
    /// form, not axum's bare 422 that eats everything the admin typed.
    port: String,
    pool_mode: String,
    tls_mode: String,
    backend_kind: String,
    default_consumer_cidr: Option<String>,
}

pub async fn create(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    Form(input): Form<AddInput>,
) -> Response {
    match create_inner(&state, &session.username, &input).await {
        Ok(id) => Redirect::to(&format!("/admin/servers/{id}")).into_response(),
        Err(msg) => add_page(&session, Some(&msg), Some(&input)).into_response(),
    }
}

/// Validate → role-check (refuse superuser) → encrypt → insert → register live.
async fn create_inner(state: &AppState, actor: &str, input: &AddInput) -> Result<Uuid, String> {
    let name = input.name.trim();
    if !servers::valid_server_name(name) {
        return Err("Server name: lowercase letter first; lowercase letters, digits, - and _ only; max 64.".into());
    }
    let port = validate_common(input)?;

    // The front door: connect with the candidate DSN and inspect the role.
    let check = servers::check_admin_role(input.admin_dsn.trim())
        .await
        .map_err(|e| format!("Admin DSN check failed: {e}"))?;
    if check.is_superuser {
        return Err(format!(
            "Refused: role '{}' is SUPERUSER. Cryptarch's spine is a CREATEDB CREATEROLE role — \
             create one (CREATE ROLE cryptarch_admin LOGIN CREATEDB CREATEROLE PASSWORD '...') and use that.",
            check.role
        ));
    }
    if !check.can_createdb || !check.can_createrole {
        return Err(format!(
            "Refused: role '{}' needs both CREATEDB and CREATEROLE (has createdb={}, createrole={}).",
            check.role, check.can_createdb, check.can_createrole
        ));
    }

    let admin_enc = state.crypto.seal(input.admin_dsn.trim()).map_err(|e| e.to_string())?;
    let bouncer_enc = match input.bouncer_dsn.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(d) => state.crypto.seal(d).map_err(|e| e.to_string())?,
        None => Vec::new(),
    };
    let cidr = input.default_consumer_cidr.as_deref().map(str::trim).filter(|s| !s.is_empty());

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
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        if e.as_database_error().is_some_and(|d| d.is_unique_violation()) {
            format!("A server named '{name}' already exists.")
        } else {
            format!("Saving failed: {e}")
        }
    })?;

    audit(&state.db, actor, "add_server", Some(name),
          Some(&format!("role={} pg={} advertised={}:{}", check.role, check.server_version, input.host.trim(), port)))
        .await;

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
        Ok(engine) => state.servers.register(id, name.to_string(), "postgres".into(), engine),
        Err(e) => tracing::error!("server '{name}' saved but engine connect failed: {e}"),
    }
    Ok(id)
}

/// Validate the shared (non-DSN) fields; returns the parsed advertised port.
fn validate_common(input: &AddInput) -> Result<u16, String> {
    if input.host.trim().is_empty() {
        return Err("Advertised host is required — it's what lands in user connection strings.".into());
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
    if let Some(c) = input.default_consumer_cidr.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        if !servers::valid_cidr(c) {
            return Err(format!(
                "'{c}' is not a valid IP or CIDR (hostnames are not allowed, and network \
                 prefixes must have zero host bits — 10.1.2.0/24, not 10.1.2.3/24)."
            ));
        }
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

pub async fn detail(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    Path(id): Path<Uuid>,
    axum::extract::Query(flash): axum::extract::Query<crate::web::FlashQuery>,
) -> Response {
    detail_page(&state, &session, id, None, flash.msg()).await
}

// Settings save per card (CRYPTARCH-34): each card on the settings page is
// its own form with its own endpoint — validate its few fields, update its
// columns, audit, then do only the follow-up that card's change requires
// (edge sync for rendered config, engine reconnect for identity/DSN).

#[derive(Deserialize)]
pub struct AddressInput {
    host: String,
    /// String, not u16: out-of-range input must produce a friendly
    /// re-rendered form, not axum's bare 422.
    port: String,
}

pub async fn update_address(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    Path(id): Path<Uuid>,
    Form(input): Form<AddressInput>,
) -> Response {
    if input.host.trim().is_empty() {
        return settings_page(&state, &session, id,
            Some("Advertised host is required — it's what lands in user connection strings."), None).await;
    }
    let port: u16 = match input.port.trim().parse() {
        Ok(p) if p != 0 => p,
        _ => return settings_page(&state, &session, id, Some("Advertised port must be 1-65535."), None).await,
    };
    if let Err(r) = save_columns(&state, &session, id,
        sqlx::query("UPDATE managed_servers SET host = $2, port = $3 WHERE id = $1")
            .bind(id).bind(input.host.trim()).bind(i32::from(port))).await
    {
        return r;
    }
    audit(&state.db, &session.username, "update_server_address", Some(&id.to_string()),
          Some(&format!("advertised={}:{port}", input.host.trim()))).await;
    // The registry row carries the advertised address (it builds connection
    // strings) — re-register so provisioning sees the new one.
    reconnect_engine(&state, id).await;
    settings_page(&state, &session, id, None, Some("Address saved.")).await
}

#[derive(Deserialize)]
pub struct PoolingInput {
    pool_mode: String,
    /// Strings, not ints: friendly re-render on bad input, not a 422.
    default_pool_size: String,
    max_client_conn: String,
    max_db_connections: String,
    max_user_connections: String,
}

pub async fn update_pooling(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    Path(id): Path<Uuid>,
    Form(input): Form<PoolingInput>,
) -> Response {
    if !["session", "transaction"].contains(&input.pool_mode.as_str()) {
        return settings_page(&state, &session, id, Some("Invalid pool mode."), None).await;
    }
    let (pool_size, client_conn, db_conns, user_conns) = match validate_knobs(&input) {
        Ok(k) => k,
        Err(msg) => return settings_page(&state, &session, id, Some(&msg), None).await,
    };
    if let Err(r) = save_columns(&state, &session, id,
        sqlx::query(
            "UPDATE managed_servers SET pool_mode = $2, default_pool_size = $3, \
             max_client_conn = $4, max_db_connections = $5, max_user_connections = $6 \
             WHERE id = $1")
            .bind(id).bind(&input.pool_mode).bind(pool_size)
            .bind(client_conn).bind(db_conns).bind(user_conns)).await
    {
        return r;
    }
    audit(&state.db, &session.username, "update_server_pooling", Some(&id.to_string()),
          Some(&format!("pool={} pool_size={pool_size} max_client={client_conn} \
                         max_db={db_conns} max_user={user_conns}", input.pool_mode)))
        .await;
    // Pool knobs are rendered config — a save that never reached the edge
    // must say so, not smile and nod.
    let note = sync_note(&state, id, "Pooling saved").await;
    settings_page(&state, &session, id, None, Some(&note)).await
}

#[derive(Deserialize)]
pub struct EdgeInput {
    tls_mode: String,
    backend_kind: String,
    default_consumer_cidr: Option<String>,
    /// Empty clears it (falls back to manual edge-config placement).
    bouncer_conf_dir: Option<String>,
}

pub async fn update_edge(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    Path(id): Path<Uuid>,
    Form(input): Form<EdgeInput>,
) -> Response {
    if !["off", "edge"].contains(&input.tls_mode.as_str()) {
        return settings_page(&state, &session, id, Some("Invalid TLS mode."), None).await;
    }
    if !["docker", "vm"].contains(&input.backend_kind.as_str()) {
        return settings_page(&state, &session, id, Some("Invalid backend kind."), None).await;
    }
    let cidr = input.default_consumer_cidr.as_deref().map(str::trim).filter(|s| !s.is_empty());
    if let Some(c) = cidr {
        if !servers::valid_cidr(c) {
            return settings_page(&state, &session, id, Some(&format!(
                "'{c}' is not a valid IP or CIDR (hostnames are not allowed, and network \
                 prefixes must have zero host bits — 10.1.2.0/24, not 10.1.2.3/24)."
            )), None).await;
        }
    }
    if let Err(r) = save_columns(&state, &session, id,
        sqlx::query(
            "UPDATE managed_servers SET tls_mode = $2, backend_kind = $3, \
             default_consumer_cidr = NULLIF($4, '')::cidr, bouncer_conf_dir = NULLIF($5, '') \
             WHERE id = $1")
            .bind(id).bind(&input.tls_mode).bind(&input.backend_kind)
            .bind(cidr.unwrap_or(""))
            .bind(input.bouncer_conf_dir.as_deref().map(str::trim).unwrap_or(""))).await
    {
        return r;
    }
    audit(&state.db, &session.username, "update_server_edge", Some(&id.to_string()),
          Some(&format!("tls={} backend={} conf_dir_set={}", input.tls_mode, input.backend_kind,
                        input.bouncer_conf_dir.as_deref().is_some_and(|d| !d.trim().is_empty()))))
        .await;
    // tls_mode switches host/hostssl in the hba; the conf dir is where
    // renders land — both demand a sync.
    let note = sync_note(&state, id, "Edge settings saved").await;
    settings_page(&state, &session, id, None, Some(&note)).await
}

#[derive(Deserialize)]
pub struct CredsInput {
    /// Empty = keep current. Non-empty = rotate (role-checked like add).
    admin_dsn: Option<String>,
    bouncer_dsn: Option<String>,
}

pub async fn update_credentials(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    Path(id): Path<Uuid>,
    Form(input): Form<CredsInput>,
) -> Response {
    let new_admin_dsn = input.admin_dsn.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let mut admin_enc: Option<Vec<u8>> = None;
    if let Some(dsn) = new_admin_dsn {
        match servers::check_admin_role(dsn).await {
            Ok(c) if c.is_superuser => {
                return settings_page(&state, &session, id,
                    Some(&format!("Refused: role '{}' is SUPERUSER.", c.role)), None).await;
            }
            Ok(c) if !c.can_createdb || !c.can_createrole => {
                return settings_page(&state, &session, id,
                    Some(&format!("Refused: role '{}' needs CREATEDB and CREATEROLE.", c.role)), None).await;
            }
            Ok(_) => match state.crypto.seal(dsn) {
                Ok(enc) => admin_enc = Some(enc),
                Err(e) => return settings_page(&state, &session, id, Some(&e.to_string()), None).await,
            },
            Err(e) => {
                return settings_page(&state, &session, id,
                    Some(&format!("New admin DSN check failed: {e}")), None).await;
            }
        }
    }
    let bouncer_enc = match input.bouncer_dsn.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(d) => match state.crypto.seal(d) {
            Ok(enc) => Some(enc),
            Err(e) => return settings_page(&state, &session, id, Some(&e.to_string()), None).await,
        },
        None => None,
    };
    if admin_enc.is_none() && bouncer_enc.is_none() {
        return settings_page(&state, &session, id, None,
            Some("Nothing to rotate — both fields were left empty.")).await;
    }
    if let Err(r) = save_columns(&state, &session, id,
        sqlx::query(
            "UPDATE managed_servers SET admin_dsn_enc = COALESCE($2, admin_dsn_enc), \
             bouncer_admin_dsn_enc = COALESCE($3, bouncer_admin_dsn_enc) WHERE id = $1")
            .bind(id).bind(admin_enc.as_ref()).bind(bouncer_enc.as_ref())).await
    {
        return r;
    }
    audit(&state.db, &session.username, "update_server_credentials", Some(&id.to_string()),
          Some(&format!("rotated_admin_dsn={} rotated_bouncer_dsn={}",
                        admin_enc.is_some(), bouncer_enc.is_some())))
        .await;
    if admin_enc.is_some() {
        reconnect_engine(&state, id).await;
    }
    settings_page(&state, &session, id, None, Some("Credentials saved.")).await
}

/// Run one settings UPDATE; map failure and gone-server to full responses so
/// card handlers can stay linear.
async fn save_columns(
    state: &AppState,
    session: &crate::auth::Session,
    id: Uuid,
    query: sqlx::query::Query<'_, sqlx::Postgres, sqlx::postgres::PgArguments>,
) -> Result<(), Response> {
    match query.execute(&state.db).await {
        Err(e) => Err(settings_page(state, session, id, Some(&format!("Update failed: {e}")), None).await),
        Ok(r) if r.rows_affected() == 0 => Err(crate::web::error_page(
            session, axum::http::StatusCode::NOT_FOUND,
            "No such server", "That server doesn't exist — it may have been removed.")),
        Ok(_) => Ok(()),
    }
}

/// Reconnect the live engine if the server is active (address or DSN changed).
async fn reconnect_engine(state: &AppState, id: Uuid) {
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
                recheck_still_active(state, id).await;
            }
            Err(e) => {
                state.servers.unregister(id);
                tracing::error!("server '{}' updated but engine reconnect failed: {e}", row.name);
            }
        }
    }
}

/// Run an edge sync after a mutation and fold the outcome into the notice.
async fn sync_note(state: &AppState, id: Uuid, prefix: &str) -> String {
    match crate::acl::sync_edge(&state.db, &state.crypto, id).await {
        Ok(crate::acl::SyncOutcome::Applied(_)) => format!("{prefix} — edge synced."),
        Ok(crate::acl::SyncOutcome::ManualPlacement { .. }) => format!(
            "{prefix}. No conf dir — apply the change with \"Sync edge now\" (manual placement)."
        ),
        Err(e) => format!("{prefix}, but edge sync FAILED: {e}"),
    }
}

/// Close the register/disable race: a concurrent disable between our row
/// fetch and register would leave a live engine on a disabled server. After
/// registering, re-read is_active and back out if it flipped.
async fn recheck_still_active(state: &AppState, id: Uuid) {
    let still_active: Option<bool> =
        sqlx::query_scalar("SELECT is_active FROM managed_servers WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
    if still_active != Some(true) {
        state.servers.unregister(id);
    }
}

// ---- enable / disable -------------------------------------------------------

#[derive(Deserialize)]
pub struct ActiveInput {
    active: bool,
}

pub async fn set_active(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    Path(id): Path<Uuid>,
    Form(input): Form<ActiveInput>,
) -> Response {
    let res = sqlx::query("UPDATE managed_servers SET is_active = $1 WHERE id = $2")
        .bind(input.active)
        .bind(id)
        .execute(&state.db)
        .await;
    match res {
        Ok(r) if r.rows_affected() > 0 => {}
        _ => return crate::web::error_page(&session, axum::http::StatusCode::NOT_FOUND,
            "No such server", "That server doesn't exist — it may have been removed."),
    }
    audit(&state.db, &session.username,
          if input.active { "enable_server" } else { "disable_server" },
          Some(&id.to_string()), None)
        .await;

    if input.active {
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
                    recheck_still_active(&state, id).await;
                }
                Err(e) => tracing::error!("server '{}' enabled but connect failed: {e}", row.name),
            }
        }
    } else {
        state.servers.unregister(id);
    }
    let ok = if input.active { "server_enabled" } else { "server_disabled" };
    Redirect::to(&format!("/admin/servers/{id}?ok={ok}")).into_response()
}

// ---- listeners (CRYPTARCH-14) ---------------------------------------------------

#[derive(Deserialize)]
pub struct ListenerAddInput {
    host: String,
    port: String,
    label: String,
}

pub async fn listener_add(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    Path(id): Path<Uuid>,
    Form(input): Form<ListenerAddInput>,
) -> Response {
    let host = input.host.trim();
    if !servers::valid_listener_host(host) {
        return detail_page(&state, &session, id,
            Some("Listener host must be an IP or a valid FQDN."), None).await;
    }
    let port: u16 = match input.port.trim().parse() {
        Ok(p) if p != 0 => p,
        _ => return detail_page(&state, &session, id, Some("Listener port must be 1-65535."), None).await,
    };
    let label = input.label.trim();
    if label.is_empty() || label.len() > 32 {
        return detail_page(&state, &session, id, Some("Label required (max 32 chars)."), None).await;
    }
    let res = sqlx::query(
        "INSERT INTO server_listeners (server_id, host, port, label, position) \
         VALUES ($1, $2, $3, $4, \
                 (SELECT COALESCE(MAX(position), 0) + 1 FROM server_listeners WHERE server_id = $1)) \
         ON CONFLICT (server_id, host, port) DO NOTHING",
    )
    .bind(id)
    .bind(host)
    .bind(i32::from(port))
    .bind(label)
    .execute(&state.db)
    .await;
    match res {
        Ok(r) if r.rows_affected() == 0 => {
            // ON CONFLICT skipped it — don't audit an action that didn't happen.
            detail_page(&state, &session, id,
                Some("A listener with that host:port already exists."), None).await
        }
        Ok(_) => {
            audit(&state.db, &session.username, "listener_add", Some(&id.to_string()),
                  Some(&format!("{label}={host}:{port}"))).await;
            detail_page(&state, &session, id, None, Some("Listener added.")).await
        }
        Err(e) => {
            tracing::error!("listener add {id}: {e:#}");
            detail_page(&state, &session, id, Some("Saving listener failed."), None).await
        }
    }
}

pub async fn listener_remove(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    Path((id, listener_id)): Path<(Uuid, Uuid)>,
) -> Response {
    let removed: Option<String> = sqlx::query_scalar(
        "DELETE FROM server_listeners WHERE id = $1 AND server_id = $2 \
         RETURNING label || '=' || host || ':' || port",
    )
    .bind(listener_id)
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);
    if let Some(what) = removed {
        audit(&state.db, &session.username, "listener_remove", Some(&id.to_string()), Some(&what)).await;
    }
    Redirect::to(&format!("/admin/servers/{id}?ok=listener_removed")).into_response()
}

// ---- named sources (CRYPTARCH-39) -----------------------------------------------

#[derive(Deserialize)]
pub struct SourceAddInput {
    label: String,
    cidr: String,
    is_default: Option<String>,
}

pub async fn source_add(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    Path(id): Path<Uuid>,
    Form(input): Form<SourceAddInput>,
) -> Response {
    let label = input.label.trim();
    if label.is_empty() || label.len() > 32 {
        return detail_page(&state, &session, id, Some("Label required (max 32 chars)."), None).await;
    }
    let cidr = input.cidr.trim();
    if !servers::valid_cidr(cidr) {
        return detail_page(&state, &session, id, Some(&format!(
            "'{cidr}' is not a valid IP or CIDR (hostnames are not allowed, and network \
             prefixes must have zero host bits)."))
            , None).await;
    }
    let is_default = input.is_default.as_deref() == Some("1");
    let res = sqlx::query(
        "INSERT INTO server_sources (server_id, label, cidr, is_default) \
         VALUES ($1, $2, $3::cidr, $4) ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(label)
    .bind(cidr)
    .bind(is_default)
    .execute(&state.db)
    .await;
    match res {
        Ok(r) if r.rows_affected() == 0 => {
            detail_page(&state, &session, id,
                Some("A source with that label or range already exists on this server."), None).await
        }
        Ok(_) => {
            audit(&state.db, &session.username, "source_add", Some(&id.to_string()),
                  Some(&format!("{label}={cidr} default={is_default}"))).await;
            detail_page(&state, &session, id, None, Some("Named source added.")).await
        }
        Err(e) => {
            tracing::error!("source add {id}: {e:#}");
            detail_page(&state, &session, id, Some("Saving the source failed."), None).await
        }
    }
}

pub async fn source_remove(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    Path((id, source_id)): Path<(Uuid, Uuid)>,
) -> Response {
    // Removing a named source never touches existing ACL entries — it only
    // stops being offered. Revocation stays an explicit per-database act.
    let removed: Option<String> = sqlx::query_scalar(
        "DELETE FROM server_sources WHERE id = $1 AND server_id = $2 \
         RETURNING label || '=' || cidr",
    )
    .bind(source_id)
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);
    if let Some(what) = removed {
        audit(&state.db, &session.username, "source_remove", Some(&id.to_string()), Some(&what)).await;
    }
    Redirect::to(&format!("/admin/servers/{id}?ok=source_removed")).into_response()
}

// ---- per-db pool overrides (CRYPTARCH-32) ---------------------------------------

#[derive(Deserialize)]
pub struct DbKnobsInput {
    pool_mode: String,
    max_connections: Option<String>,
}

pub async fn db_knobs(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    Path((id, db_id)): Path<(Uuid, Uuid)>,
    Form(input): Form<DbKnobsInput>,
) -> Response {
    let mode: Option<&str> = match input.pool_mode.as_str() {
        "inherit" | "" => None,
        m @ ("session" | "transaction") => Some(m),
        _ => return detail_page(&state, &session, id, Some("Invalid pool mode."), None).await,
    };
    let max: Option<i32> = match input.max_connections.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => None,
        Some(raw) => match raw.parse::<i32>() {
            Ok(v) if (1..=10000).contains(&v) => Some(v),
            _ => return detail_page(&state, &session, id,
                Some("Connection limit must be 1-10000, or empty to inherit."), None).await,
        },
    };

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
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    let Some(name) = name else {
        return crate::web::error_page(&session, axum::http::StatusCode::NOT_FOUND,
            "No such database", "That database doesn't exist on this server.");
    };
    audit(&state.db, &session.username, "db_pool_override", Some(&name),
          Some(&format!("pool_mode={} max_connections={}",
                        mode.unwrap_or("inherit"),
                        max.map_or("inherit".into(), |v| v.to_string()))))
        .await;
    let note = sync_note(&state, id, &format!("Override for {name} saved")).await;
    detail_page(&state, &session, id, None, Some(&note)).await
}

// ---- edge health + sync (CRYPTARCH-13) ------------------------------------------

/// On-view edge health: dirty flag, on-disk file drift (checksum + desired
/// compare), and a live pool snapshot from the console. No daemon — the
/// truth is computed when an admin looks, which is when it matters.
async fn edge_health(state: &AppState, s: &AdminServerRow) -> Markup {
    // Desired state: fresh render of current acl_entries.
    let desired = match crate::acl::load_rules(&state.db, s.id).await {
        Ok(rules) => Some(crate::acl::render_hba(&rules, &s.tls_mode)),
        Err(_) => None,
    };

    // On-disk state, when we can see the conf dir.
    let file_verdict: (String, bool) = match s.bouncer_conf_dir.as_deref().filter(|d| !d.is_empty()) {
        None => ("no conf dir — manual placement mode, drift not checkable from here".into(), s.edge_dirty),
        Some(dir) => {
            let path = std::path::Path::new(dir).join("pgbouncer_hba.conf");
            match std::fs::read_to_string(&path) {
                Err(_) => ("hba file missing — run an ACL change or server init".into(), true),
                Ok(content) => {
                    let claimed = crate::acl::claimed_checksum(&content).map(str::to_string);
                    let actual = crate::acl::body_checksum(&content);
                    match claimed {
                        None => ("hba not cryptarch-managed (no checksum header)".into(), true),
                        Some(c) if c != actual => ("hba HAND-EDITED since last render (checksum mismatch)".into(), true),
                        Some(_) => match &desired {
                            Some(d) if *d == content => ("hba matches desired ACL state".into(), false),
                            Some(_) => ("hba intact but STALE vs current ACL state — sync needed".into(), true),
                            None => ("hba intact (desired state unavailable)".into(), false),
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
    let knobs_verdict: (String, bool) = match s.bouncer_conf_dir.as_deref().filter(|d| !d.is_empty()) {
        None => ("no conf dir — manual placement mode, drift not checkable from here".into(), false),
        Some(dir) => {
            let dir = std::path::Path::new(dir);
            let not_included = std::fs::read_to_string(dir.join("pgbouncer.ini"))
                .map(|ini| {
                    !ini.lines().any(|l| {
                        let l = l.trim_start();
                        l.starts_with("%include") && l.contains(crate::bouncer::KNOBS_FILE)
                    })
                })
                .unwrap_or(false);
            if not_included {
                ("pgbouncer.ini does not %include the knobs file — run server init".into(), true)
            } else {
                match std::fs::read_to_string(dir.join(crate::bouncer::KNOBS_FILE)) {
                    Err(_) => ("knobs file missing — run server init or an edge sync".into(), true),
                    Ok(content) => {
                        let claimed = crate::bouncer::claimed_checksum(&content).map(str::to_string);
                        let actual = crate::bouncer::body_checksum(&content);
                        match claimed {
                            None => ("knobs file not cryptarch-managed (no checksum header)".into(), true),
                            Some(c) if c != actual => ("knobs HAND-EDITED since last render (checksum mismatch)".into(), true),
                            Some(_) => match &desired_knobs {
                                Some(d) if *d == content => ("knobs match desired pool settings".into(), false),
                                Some(_) => ("knobs intact but STALE vs current settings — sync needed".into(), true),
                                None => ("knobs intact (desired state unavailable)".into(), false),
                            },
                        }
                    }
                }
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

    let (verdict, is_bad) = file_verdict;
    let bg = state.health.get(s.id);
    html! {
        h2 #edge { "Edge health" }
        dl.creds {
            dt { "Live checks" } dd {
                @match &bg {
                    None => { span.muted { "no sweep yet — the health loop runs every interval after boot" } }
                    Some(h) => {
                        @match &h.edge {
                            Ok(_) => { span.st.st-active { span.dot {} "edge listener" } },
                            Err(e) => { span.st.st-bad { span.dot {} "edge listener — " (e) } },
                        }
                        " "
                        @match &h.postgres {
                            Ok(_) => { span.st.st-active { span.dot {} "postgres" } },
                            Err(e) => { span.st.st-bad { span.dot {} "postgres — " (e) } },
                        }
                        " "
                        span.muted {
                            "checked "
                            (crate::web::human_duration((chrono::Utc::now() - h.checked_at).num_seconds()))
                            " ago"
                        }
                    }
                }
            }
            dt { "Sync state" } dd {
                @if s.edge_dirty { span.st.st-bad { span.dot {} "dirty — last sync failed or pending" } }
                @else { span.st.st-active { span.dot {} "synced" } }
                @if let Some(t) = s.edge_synced_at {
                    " " span.muted { "(last good sync " (t.format("%Y-%m-%d %H:%M:%S UTC").to_string()) ")" }
                }
            }
            dt { "Rendered file" } dd {
                @if is_bad { span.st.st-suspended { span.dot {} (verdict) } }
                @else { span.st.st-active { span.dot {} (verdict) } }
            }
            dt { "Pool knobs" } dd {
                @if knobs_verdict.1 { span.st.st-suspended { span.dot {} (knobs_verdict.0) } }
                @else { span.st.st-active { span.dot {} (knobs_verdict.0) } }
            }
            dt { "Bouncer pools" } dd {
                @match &pools {
                    Some((_, rows)) if rows.is_empty() => { span.muted { "console ok, no active pools" } },
                    Some((headers, rows)) => {
                        div.table-scroll {
                            table.dbs {
                                thead { tr { @for h in headers { th { (h) } } } }
                                tbody {
                                    @for row in rows {
                                        tr { @for cell in row { td.tnum { (cell) } } }
                                    }
                                }
                            }
                        }
                    },
                    None => { span.muted { "console unavailable or not configured" } },
                }
            }
        }
        form method="post" action={ "/admin/servers/" (s.id) "/sync" } .inline {
            button type="submit" { "Sync edge now" }
        }
    }
}

pub async fn sync(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    Path(id): Path<Uuid>,
) -> Response {
    let (note, manual) = match crate::acl::sync_edge(&state.db, &state.crypto, id).await {
        Ok(crate::acl::SyncOutcome::Applied(n)) => (format!("Edge synced — {n} rule(s) applied."), None),
        Ok(crate::acl::SyncOutcome::ManualPlacement { hba, knobs }) => (
            "No conf dir — place these rendered files on the bouncer host, then RELOAD it.".to_string(),
            Some((hba, knobs)),
        ),
        Err(e) => (format!("Edge sync FAILED: {e}"), None),
    };
    audit(&state.db, &session.username, "edge_sync", Some(&id.to_string()), Some(&note)).await;
    let extra = manual.map(|(hba, knobs)| {
        html! {
            h2 { "Rendered hba (manual placement)" }
            pre.conn { (hba) }
            h2 { "Rendered pool settings (manual placement)" }
            p.muted { "Save as " code { (crate::bouncer::KNOBS_FILE) } " in the bouncer conf dir and make "
                      code { "pgbouncer.ini" } " end with " code { "%include" } " of it." }
            pre.conn { (knobs) }
        }
    });
    detail_page_full(&state, &session, id, None, Some(&note), extra).await
}

// ---- server-init ---------------------------------------------------------------

pub async fn init(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    Path(id): Path<Uuid>,
) -> Response {
    let outcome = match crate::edge::run_init(&state.db, &state.crypto, id).await {
        Ok(o) => o,
        Err(e) => {
            tracing::error!("server-init {id}: {e:#}");
            audit(&state.db, &session.username, "server_init", Some(&id.to_string()),
                  Some(&format!("aborted: {e}")))
                .await;
            return detail_page(&state, &session, id, Some(&format!("Init failed: {e}")), None).await;
        }
    };
    audit(&state.db, &session.username, "server_init", Some(&id.to_string()),
          Some(&format!("status={} steps={}", outcome.status,
                        outcome.steps.iter().map(|s| format!("{}:{}", s.step, if s.outcome.is_ok() {"ok"} else {"FAIL"}))
                            .collect::<Vec<_>>().join(", "))))
        .await;

    let report = html! {
        h2 { "Server init" }
        div.table-scroll {
            table.dbs {
                tbody {
                    @for s in &outcome.steps {
                        tr {
                            td { (s.step) }
                            td {
                                @match &s.outcome {
                                    Ok(msg) => { span.st.st-active { span.dot {} (msg) } },
                                    Err(msg) => { span.st.st-bad { span.dot {} (msg) } },
                                }
                            }
                        }
                    }
                }
            }
        }
        @if outcome.status == "needs_bootstrap" {
            p.muted { "Run this once as a superuser on the managed server, then re-run init:" }
            pre.conn { (crate::edge::bootstrap_sql(outcome.panel_role.as_deref().unwrap_or("cryptarch_admin"))) }
        }
        @if let Some(line) = &outcome.manual_userlist_line {
            p.muted { strong { "Shown once: " } "add this line to the bouncer's userlist.txt "
                "(no conf dir is configured, so Cryptarch can't write it):" }
            pre.conn { (line) }
        }
    };
    detail_page_full(&state, &session, id, None, None, Some(report)).await
}

// ---- connect-test -------------------------------------------------------------

pub async fn test(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    Path(id): Path<Uuid>,
) -> Response {
    let row = match sqlx::query_as::<_, ServerRow>(
        "SELECT id, name, engine, host, port, admin_dsn_enc FROM managed_servers WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return crate::web::error_page(&session, axum::http::StatusCode::NOT_FOUND,
            "No such server", "That server doesn't exist — it may have been removed."),
        Err(e) => {
            tracing::error!("loading server {id}: {e}");
            return crate::web::error_page(&session, axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong", "Loading the server failed — try again.");
        }
    };

    let mut results: Vec<(String, Result<String, String>)> = Vec::new();

    // 1. Admin DSN: decrypt + connect + role attributes.
    match state.crypto.open(&row.admin_dsn_enc) {
        Ok(dsn) => match servers::check_admin_role(&dsn).await {
            Ok(c) => {
                let verdict = if c.is_superuser {
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

    audit(&state.db, &session.username, "test_server", Some(&row.name),
          Some(&format!("{} checks, {} failed", results.len(),
                        results.iter().filter(|(_, r)| r.is_err()).count())))
        .await;

    let report = html! {
        h2 { "Connect test" }
        div.table-scroll {
            table.dbs {
                tbody {
                    @for (what, outcome) in &results {
                        tr {
                            td { (what) }
                            td {
                                @match outcome {
                                    Ok(msg) => { span.st.st-active { span.dot {} (msg) } },
                                    Err(msg) => { span.st.st-bad { span.dot {} (msg) } },
                                }
                            }
                        }
                    }
                }
            }
        }
        p.muted { "Bouncer console checks arrive with the server-init task (CRYPTARCH-11)." }
    };
    detail_page_full(&state, &session, id, None, None, Some(report)).await
}

// ---- rendering ---------------------------------------------------------------

fn add_page(session: &crate::auth::Session, error: Option<&str>, prefill: Option<&AddInput>) -> Markup {
    use crate::web::srow;
    let p = |f: fn(&AddInput) -> String| prefill.map(f).unwrap_or_default();
    shell(
        "Add server · Admin",
        session,
        html! {
            (crate::admin::admin_nav("servers"))
            p { a.link href="/admin/servers" { "← Servers" } }
            h1 { "Add managed server" }
            p.sdesc { "The DSN is verified on submit: it must connect, and its role must be \
                       CREATEDB CREATEROLE — never superuser. Pool sizes and limits start \
                       at sane defaults, adjustable in Settings afterwards." }
            @if let Some(msg) = error { p.error role="alert" { (msg) } }
            form method="post" action="/admin/servers" {
                div.scard {
                    (srow("Name",
                        "How this server appears across the portal. Lowercase, digits, - and _.",
                        html! { input type="text" name="name" value=(p(|i| i.name.clone())) placeholder="pg-shared-1" required; }))
                    (srow("Admin DSN",
                        "The panel's own role on the server. Superuser is refused — CREATEDB \
                         CREATEROLE is the ceiling.",
                        html! { input type="text" name="admin_dsn" placeholder="postgres://cryptarch_admin:...@10.0.0.5:5432/postgres" autocomplete="off" required; }))
                    (srow("Bouncer console DSN",
                        "Lets Cryptarch RELOAD the edge and read pool stats. Optional until \
                         server init.",
                        html! { input type="text" name="bouncer_dsn" autocomplete="off" placeholder="postgres://pgbadmin:...@10.0.0.5:6432/pgbouncer"; }))
                }
                div.scard {
                    (srow("Advertised host",
                        "Where users connect — the edge's listener, not Postgres itself.",
                        html! { input type="text" name="host" value=(p(|i| i.host.clone())) placeholder="10.0.0.5" required; }))
                    (srow("Advertised port",
                        "The edge listener's port.",
                        html! { input type="number" name="port" value=(p(|i| i.port.clone())) min="1" max="65535" placeholder="6432" required; }))
                    (srow("Pool mode",
                        "How long a client holds a real Postgres connection. When unsure, \
                         keep session — it's fully transparent.",
                        html! {
                            select name="pool_mode" {
                                option value="session" selected[prefill.is_none_or(|i| i.pool_mode == "session")] { "session — everything works (default)" }
                                option value="transaction" selected[prefill.is_some_and(|i| i.pool_mode == "transaction")] { "transaction — scales further, breaks session state" }
                            }
                        }))
                    (srow("TLS mode",
                        "Whether the edge requires TLS from connecting clients.",
                        html! {
                            select name="tls_mode" {
                                option value="off" selected[prefill.is_none_or(|i| i.tls_mode == "off")] { "off — trusted network" }
                                option value="edge" selected[prefill.is_some_and(|i| i.tls_mode == "edge")] { "edge — TLS terminated at the bouncer" }
                            }
                        }))
                    (srow("Backend kind",
                        "How the Postgres behind the edge is hosted. Informational for now.",
                        html! {
                            select name="backend_kind" {
                                option value="docker" selected[prefill.is_none_or(|i| i.backend_kind == "docker")] { "docker" }
                                option value="vm" selected[prefill.is_some_and(|i| i.backend_kind == "vm")] { "vm / bare metal" }
                            }
                        }))
                    (srow("Default \"Allowed from\"",
                        "Prefills the access rule when someone provisions a database here. \
                         Optional.",
                        html! { input type="text" name="default_consumer_cidr" value=(p(|i| i.default_consumer_cidr.clone().unwrap_or_default())) placeholder="10.10.100.0/24"; }))
                    div.sfoot {
                        a.link href="/admin/servers" { "Cancel" }
                        button.primary type="submit" { "Verify & add" }
                    }
                }
            }
        },
    )
}

async fn detail_page(
    state: &AppState,
    session: &crate::auth::Session,
    id: Uuid,
    error: Option<&str>,
    notice: Option<&str>,
) -> Response {
    detail_page_full(state, session, id, error, notice, None).await
}

/// Load the server row for a page render, or a styled error page — never a
/// bare text response.
async fn load_server(
    state: &AppState,
    session: &crate::auth::Session,
    id: Uuid,
) -> Result<AdminServerRow, Response> {
    match sqlx::query_as::<_, AdminServerRow>(&format!("{SELECT_SERVER} WHERE s.id = $1"))
        .bind(id)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(r)) => Ok(r),
        Ok(None) => Err(crate::web::error_page(session, axum::http::StatusCode::NOT_FOUND,
            "No such server", "That server doesn't exist — it may have been removed.")),
        Err(e) => {
            tracing::error!("loading server {id}: {e}");
            Err(crate::web::error_page(session, axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong", "Loading the server failed — try again."))
        }
    }
}

async fn detail_page_full(
    state: &AppState,
    session: &crate::auth::Session,
    id: Uuid,
    error: Option<&str>,
    notice: Option<&str>,
    extra: Option<Markup>,
) -> Response {
    let s = match load_server(state, session, id).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let is_live = state.servers.list().iter().any(|i| i.id == s.id);
    let health = edge_health(state, &s).await;
    let listeners = servers::listeners_for(&state.db, s.id).await;
    let named_sources = servers::sources_for(&state.db, s.id).await;
    let db_knobs = sqlx::query_as::<_, DbKnobRow>(
        "SELECT id, name, status, pool_mode, max_connections \
         FROM databases WHERE server_id = $1 ORDER BY name",
    )
    .bind(s.id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    // Dashboard snapshot: bounded at 3s on top of the engine's op timeout —
    // an unreachable server must cost this page a note, not a hang.
    let overview = match state.servers.get(s.id) {
        Some(engine) => tokio::time::timeout(
            std::time::Duration::from_secs(3),
            engine.server_overview(),
        )
        .await
        .ok()
        .and_then(Result::ok),
        None => None,
    };
    // Which databases on this server are Cryptarch-managed, for badging.
    let managed: std::collections::HashSet<String> = sqlx::query_scalar::<_, String>(
        "SELECT name FROM databases WHERE server_id = $1",
    )
    .bind(s.id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default()
    .into_iter()
    .collect();
    let dashboard = html! {
        h2 #dashboard { "Server dashboard" }
        @match &overview {
            None => {
                p.muted { "Server dashboard unavailable — the managed server didn't respond \
                           (or isn't connected). Refresh to try again." }
            }
            Some(o) => {
                div.cards {
                    div.card {
                        span.n { (o.version.split_whitespace().next().unwrap_or(&o.version)) }
                        span.l { "postgresql" }
                    }
                    div.card {
                        span.n { (crate::web::human_duration(o.uptime_secs)) }
                        span.l { "uptime" }
                    }
                    div.card {
                        span.n { (o.total_connections) " / " (o.max_connections) }
                        span.l { "connections" }
                    }
                }
                div.table-scroll {
                    table.dbs {
                        thead { tr { th { "Database" } th { "Size" } th { "Connections" } th { "" } } }
                        tbody {
                            @for d in &o.databases {
                                tr {
                                    td {
                                        @if managed.contains(&d.name) {
                                            a href={ "/db/" (d.name) } { code { (d.name) } }
                                        } @else {
                                            code { (d.name) }
                                        }
                                    }
                                    td.tnum { (crate::web::human_bytes(d.size_bytes)) }
                                    td.tnum { (d.connections) }
                                    td {
                                        @if managed.contains(&d.name) {
                                            span.st.st-active { span.dot {} "managed" }
                                        } @else {
                                            span.muted { "external" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    };

    shell(
        &format!("{} · Admin", s.name),
        session,
        html! {
            (crate::admin::admin_sidebar("servers", Some(&crate::admin::ServerNavCtx {
                id: s.id, name: s.name.clone(), here: "detail" })))
            p { a.link href="/admin/servers" { "← Servers" } }
            h1 { code { (s.name) } }
            @if let Some(msg) = error { p.error role="alert" { (msg) } }
            @if let Some(msg) = notice { p.notice role="status" { (msg) } }
            @if let Some(report) = extra { (report) }
            dl.creds {
                dt { "Engine" } dd { (s.engine) }
                dt { "Status" } dd {
                    @if !s.is_active { (status_badge("disabled")) }
                    @else if is_live { (status_badge("active")) }
                    @else { (status_badge("unreachable")) }
                }
                dt { "Databases" } dd { (s.db_count) }
                dt { "Admin DSN" } dd { @if s.has_admin_dsn { "stored (encrypted)" } @else { span.error { "missing" } } }
                dt { "Bouncer DSN" } dd { @if s.has_bouncer_dsn { "stored (encrypted)" } @else { span.muted { "not set" } } }
                dt { "Init" } dd {
                    @match s.init_status.as_str() {
                        "ready" => { (status_badge("active")) },
                        "pending" => { span.st { span.dot {} "pending — run server init" } },
                        "needs_bootstrap" => { span.st.st-suspended { span.dot {} "needs superuser bootstrap" } },
                        _ => { (status_badge("failed")) },
                    }
                }
                dt { "Conf dir" } dd {
                    @if let Some(d) = &s.bouncer_conf_dir { code { (d) } }
                    @else { span.muted { "not set — edge config offered for manual placement" } }
                }
            }
            div.actions {
                form method="post" action={ "/admin/servers/" (s.id) "/init" } .inline {
                    button type="submit" { "Run server init" }
                }
                form method="post" action={ "/admin/servers/" (s.id) "/test" } .inline {
                    button type="submit" { "Run connect test" }
                }
                form method="post" action={ "/admin/servers/" (s.id) "/active" } .inline
                    hx-confirm=[s.is_active.then(|| format!(
                        "Disable {}? Provisioning onto it stops until re-enabled.", s.name))] {
                    input type="hidden" name="active" value=(!s.is_active);
                    button type="submit" { @if s.is_active { "Disable" } @else { "Enable" } }
                }
                a.button href={ "/admin/servers/" (s.id) "/settings" } { "Settings" }
            }
            (dashboard)
            (health)
            h2 #pools { "Pool overrides" }
            p.muted { "This server pools connections in " code { (s.pool_mode) } " mode and "
                      "allows " @if s.max_user_connections == 0 { "unlimited" }
                      @else { (s.max_user_connections) } " Postgres connections per user "
                      "(change the defaults in Settings). A database listed here can differ: "
                      "its own pool mode, or a cap on how many Postgres connections it can "
                      "hold at once. \"inherit\" and an empty limit mean the server default "
                      "applies. Apply pushes the change to the edge immediately." }
            @if db_knobs.is_empty() {
                p.muted { "No databases on this server yet." }
            } @else {
                div.table-scroll {
                    table.dbs {
                        thead { tr {
                            th { "Database" } th { "Pool mode" } th { "Connection limit" } th { "" }
                        } }
                        tbody {
                            @for d in &db_knobs {
                                @let form_id = format!("knobs-{}", d.id);
                                tr {
                                    td {
                                        code { (d.name) }
                                        @if d.status != "active" { " " (status_badge(&d.status)) }
                                    }
                                    td {
                                        select name="pool_mode" form=(form_id) {
                                            option value="inherit" selected[d.pool_mode.is_none()] { "inherit" }
                                            option value="session" selected[d.pool_mode.as_deref() == Some("session")] { "session" }
                                            option value="transaction" selected[d.pool_mode.as_deref() == Some("transaction")] { "transaction" }
                                        }
                                    }
                                    td {
                                        input type="number" name="max_connections" form=(form_id)
                                            value=[d.max_connections] placeholder="inherit"
                                            min="1" max="10000" style="width:7em";
                                    }
                                    td {
                                        button type="submit" form=(form_id)
                                            aria-label={ "Apply pool override for " (d.name) } { "Apply" }
                                    }
                                }
                            }
                        }
                    }
                }
                // The row forms themselves — a <form> can't span table cells,
                // so inputs reference these by the HTML form attribute.
                @for d in &db_knobs {
                    form id={ "knobs-" (d.id) } method="post"
                        action={ "/admin/servers/" (s.id) "/db/" (d.id) "/knobs" } {}
                }
            }
            h2 #sources { "Named sources" }
            p.sdesc { "Labeled ingress ranges users pick from when provisioning — \
                       \"db network\", \"LAN\" — instead of typing CIDRs. Defaults come \
                       pre-ticked on the provision form. Removing one only stops \
                       offering it; existing access rules stay until revoked per \
                       database." }
            @if !named_sources.is_empty() {
                div.table-scroll {
                    table.dbs {
                        thead { tr { th { "Label" } th { "Range" } th { "Default" } th { "" } } }
                        tbody {
                            @for src in &named_sources {
                                tr {
                                    td { (src.label) }
                                    td { code { (src.cidr) } }
                                    td { @if src.is_default { span.st.st-active { span.dot {} "pre-ticked" } }
                                         @else { span.muted { "opt-in" } } }
                                    td {
                                        form method="post" action={ "/admin/servers/" (s.id) "/sources/" (src.id) "/remove" } .inline
                                            hx-confirm={ "Remove named source " (src.label) " (" (src.cidr)
                                                         ")? It stops being offered; existing rules stay." } {
                                            button.link type="submit"
                                                aria-label={ "Remove source " (src.label) } { "remove" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            form method="post" action={ "/admin/servers/" (s.id) "/sources" } .scard {
                (srow("Label",
                    "What users see on the provision form — \"LAN\", \"tailnet\".",
                    html! { input type="text" name="label" placeholder="LAN / tailnet" required; }))
                (srow("Range",
                    "The IP or CIDR the label stands for.",
                    html! { input type="text" name="cidr" placeholder="192.168.8.0/24" autocomplete="off" required; }))
                (srow("Pre-ticked",
                    "Default sources come already checked when someone provisions here.",
                    html! {
                        select name="is_default" {
                            option value="" selected { "opt-in" }
                            option value="1" { "yes, pre-ticked" }
                        }
                    }))
                (sfoot(Some("Offered on the provision form immediately."), "Add source"))
            }
            h2 #listeners { "Listeners" }
            p.muted { "Dial addresses shown to users as connection strings — the primary \
                       (advertised host above) plus any of these. Listeners are where you dial; \
                       \"Allowed from\" rules are where you arrive from. FQDNs welcome here." }
            div.table-scroll {
                table.dbs {
                    thead { tr { th { "Label" } th { "Address" } th { "" } } }
                    tbody {
                        tr {
                            td { "primary" }
                            td { code { (s.host) ":" (s.port) } }
                            td { span.muted { "edit in Settings" } }
                        }
                        @for l in &listeners {
                            tr {
                                td { (l.label) }
                                td { code { (l.host) ":" (l.port) } }
                                td {
                                    form method="post" action={ "/admin/servers/" (s.id) "/listeners/" (l.id) "/remove" } .inline
                                        hx-confirm={ "Remove listener " (l.label) " (" (l.host) ":" (l.port)
                                                     ")? Its connection strings stop being offered." } {
                                        button.link type="submit"
                                            aria-label={ "Remove listener " (l.label) } { "remove" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            form method="post" action={ "/admin/servers/" (s.id) "/listeners" } .scard {
                (srow("Label",
                    "How this address is titled next to its connection string.",
                    html! { input type="text" name="label" placeholder="lan / tailnet / public" required; }))
                (srow("Host",
                    "IP or FQDN users dial. FQDNs welcome here.",
                    html! { input type="text" name="host" placeholder="192.168.8.14 or pg.jebe.sh" required; }))
                (srow("Port",
                    "Usually the bouncer's published port.",
                    html! { input type="number" name="port" placeholder="6432" min="1" max="65535" required; }))
                (sfoot(Some("Offered with every connection string from now on."), "Add listener"))
            }
        },
    )
    .into_response()
}

// ---- settings page ---------------------------------------------------------------

pub async fn settings(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    Path(id): Path<Uuid>,
) -> Response {
    settings_page(&state, &session, id, None, None).await
}

use crate::web::{sfoot, srow};

async fn settings_page(
    state: &AppState,
    session: &crate::auth::Session,
    id: Uuid,
    error: Option<&str>,
    notice: Option<&str>,
) -> Response {
    let s = match load_server(state, session, id).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let base = format!("/admin/servers/{}/settings", s.id);
    shell(
        &format!("{} settings · Admin", s.name),
        session,
        html! {
            (crate::admin::admin_sidebar("servers", Some(&crate::admin::ServerNavCtx {
                id: s.id, name: s.name.clone(), here: "settings" })))
            p { a.link href={ "/admin/servers/" (s.id) } { "← " (s.name) } }
            h1 { code { (s.name) } " · settings" }
            p.sdesc { "Connections, pooling, and edge configuration. Each section saves on its own." }
            @if let Some(msg) = error { p.error role="alert" { (msg) } }
            @if let Some(msg) = notice { p.notice role="status" { (msg) } }

            h2 { "Advertised address" }
            p.sdesc { "Where users connect — the edge's listener, not Postgres itself. "
                      "Extra dial addresses live under Listeners on the server page." }
            form method="post" action={ (base) "/address" } .scard {
                (srow("Host", "An IP or name reachable by your users.",
                    html! { input type="text" name="host" value=(s.host) required; }))
                (srow("Port", "The edge listener's port.",
                    html! { input type="number" name="port" value=(s.port) min="1" max="65535" required; }))
                (sfoot(Some("Lands in every new connection string."), "Save"))
            }

            h2 { "Connection pooling" }
            p.sdesc { "Real Postgres connections are expensive, so the edge keeps a small pool "
                      "of them and shares it among app clients. Per-database overrides live on "
                      "the server page." }
            form method="post" action={ (base) "/pooling" } .scard {
                (srow("Pool mode",
                    "How long a client holds a real connection. Session: for its whole stay — \
                     everything works, idle clients occupy a slot. Transaction: only while a \
                     transaction runs — serves far more clients, but breaks LISTEN/NOTIFY, \
                     session variables, and friends. When unsure, keep session.",
                    html! {
                        select name="pool_mode" {
                            option value="session" selected[s.pool_mode == "session"] { "session — everything works (default)" }
                            option value="transaction" selected[s.pool_mode == "transaction"] { "transaction — scales further, breaks session state" }
                        }
                    }))
                (srow("Default pool size",
                    "Real Postgres connections each database's pool keeps open.",
                    html! { div.unit { input type="number" name="default_pool_size" value=(s.default_pool_size) min="1" max="1000" required; span { "connections" } } }))
                (srow("Max client connections",
                    "App connections the edge accepts in total, across all databases.",
                    html! { div.unit { input type="number" name="max_client_conn" value=(s.max_client_conn) min="1" max="10000" required; span { "clients" } } }))
                (srow("Max per database",
                    "Ceiling on real Postgres connections one database may use. 0 means unlimited.",
                    html! { div.unit { input type="number" name="max_db_connections" value=(s.max_db_connections) min="0" max="10000" required; span { "connections" } } }))
                (srow("Max per user",
                    "Ceiling on real Postgres connections one user may hold. 0 means unlimited.",
                    html! { div.unit { input type="number" name="max_user_connections" value=(s.max_user_connections) min="0" max="10000" required; span { "connections" } } }))
                (sfoot(Some("Applied to the edge immediately on save."), "Save"))
            }

            h2 { "Edge & access" }
            p.sdesc { "How the edge terminates connections and where its config lives." }
            form method="post" action={ (base) "/edge" } .scard {
                (srow("TLS mode",
                    "Whether the edge requires TLS from connecting clients.",
                    html! {
                        select name="tls_mode" {
                            option value="off" selected[s.tls_mode == "off"] { "off — trusted network" }
                            option value="edge" selected[s.tls_mode == "edge"] { "edge — TLS terminated at the bouncer" }
                        }
                    }))
                (srow("Backend kind",
                    "How the Postgres behind the edge is hosted. Informational for now.",
                    html! {
                        select name="backend_kind" {
                            option value="docker" selected[s.backend_kind == "docker"] { "docker" }
                            option value="vm" selected[s.backend_kind == "vm"] { "vm / bare metal" }
                        }
                    }))
                (srow("Default \"Allowed from\"",
                    "Prefills the access rule when someone provisions a database here.",
                    html! { input type="text" name="default_consumer_cidr" value=(s.default_consumer_cidr.clone().unwrap_or_default()) placeholder="10.10.100.0/24"; }))
                (srow("Bouncer conf dir",
                    "A local path Cryptarch can write edge config into. Empty means config is \
                     rendered for manual placement instead.",
                    html! { input type="text" name="bouncer_conf_dir" value=(s.bouncer_conf_dir.clone().unwrap_or_default()) placeholder="/etc/pgbouncer"; }))
                (sfoot(Some("TLS and conf dir changes re-sync the edge."), "Save"))
            }

            h2 { "Credentials" }
            p.sdesc { "Stored encrypted; leave a field empty to keep what's there." }
            form method="post" action={ (base) "/credentials" } .scard {
                (srow("Rotate admin DSN",
                    "The panel's own role on this server. Superuser is refused — CREATEDB \
                     CREATEROLE is the ceiling.",
                    html! { input type="text" name="admin_dsn" autocomplete="off" placeholder="unchanged"; }))
                (srow("Bouncer console DSN",
                    "Lets Cryptarch RELOAD the edge and read pool stats.",
                    html! { input type="text" name="bouncer_dsn" autocomplete="off" placeholder="unchanged"; }))
                (sfoot(None, "Save"))
            }
        },
    )
    .into_response()
}

//! The admin API, managed servers part one (CRYPTARCH-136, S8a): the list, a
//! server's page, enabling and disabling one, and the connect test.
//!
//! A server's pages read in parts, not at once. The row and the health loop's
//! last result answer at once; the dashboard and maintenance report (the
//! Overview and Maintenance pages) ask the server itself, and Edge health
//! reads the bouncer's files and console — each bounded, each able to come
//! back empty on a bad day. Split, a page shows what it knows while the slow
//! parts are still answering.
//!
//! Nothing here carries credential material: the rows say only whether a DSN
//! is stored (`crate::admin_servers::AdminServerRow`).

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::admin::Done;
use super::{ApiAdmin, ApiError, ApiJson, ApiPath, ApiResult};
use crate::admin_servers::{self as srv, AdminServerRow, ServerError};
use crate::web::AppState;

fn server_error(e: ServerError) -> ApiError {
    match e {
        ServerError::NotFound => not_found(),
        ServerError::Internal => ApiError::internal(),
    }
}

fn not_found() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        "server_not_found",
        "That server doesn't exist — it may have been removed.",
    )
}

/// The health loop's last look at a server.
#[derive(Serialize)]
pub struct Health {
    /// Every check passed, including drift when it could be checked.
    all_ok: bool,
    edge: Check,
    postgres: Check,
    /// The rendered files against the desired state; null when it cannot be
    /// checked from here (no conf dir).
    drift: Option<Check>,
    checked_at: chrono::DateTime<chrono::Utc>,
    /// "4m", in words.
    checked_ago: String,
}

#[derive(Serialize)]
pub struct Check {
    ok: bool,
    error: Option<String>,
}

fn check(r: &crate::health::CheckResult) -> Check {
    Check { ok: r.is_ok(), error: r.as_ref().err().cloned() }
}

/// `null` until the loop has swept once: "no data yet" is not "healthy".
fn health(state: &AppState, id: Uuid) -> Option<Health> {
    state.health.get(id).map(|h| Health {
        all_ok: h.all_ok(),
        edge: check(&h.edge),
        postgres: check(&h.postgres),
        drift: h.drift.as_ref().map(check),
        checked_at: h.checked_at,
        checked_ago: crate::web::human_duration((chrono::Utc::now() - h.checked_at).num_seconds()),
    })
}

#[derive(Serialize)]
pub struct Server {
    #[serde(flatten)]
    row: AdminServerRow,
    /// "disabled", "active", or "unreachable": enabled, but no engine.
    status: &'static str,
    health: Option<Health>,
}

fn server(state: &AppState, row: AdminServerRow) -> Server {
    Server { status: srv::live_status(state, &row), health: health(state, row.id), row }
}

#[derive(Serialize)]
pub struct Servers {
    servers: Vec<Server>,
}

/// `GET /api/v1/admin/servers` — every registered server, by name.
pub async fn list(State(state): State<AppState>, ApiAdmin(_): ApiAdmin) -> ApiResult<Json<Servers>> {
    let rows = srv::list_servers(&state.db).await.map_err(|e| {
        tracing::error!("loading the server list: {e}");
        ApiError::internal()
    })?;
    Ok(Json(Servers { servers: rows.into_iter().map(|r| server(&state, r)).collect() }))
}

async fn load(state: &AppState, id: Uuid) -> ApiResult<AdminServerRow> {
    srv::find_server(&state.db, id)
        .await
        .map_err(|e| {
            tracing::error!("loading server {id}: {e}");
            ApiError::internal()
        })?
        .ok_or_else(not_found)
}

/// `GET /api/v1/admin/servers/{id}` — the row and the health loop's verdict.
pub async fn detail(
    State(state): State<AppState>,
    ApiAdmin(_): ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
) -> ApiResult<Json<Server>> {
    let row = load(&state, id).await?;
    Ok(Json(server(&state, row)))
}

#[derive(Serialize)]
pub struct DbUsage {
    name: String,
    size_bytes: i64,
    connections: i64,
    /// A database Cryptarch provisioned, rather than one it found there.
    managed: bool,
}

#[derive(Serialize)]
pub struct Dashboard {
    version: String,
    uptime_secs: i64,
    uptime: String,
    total_connections: i64,
    max_connections: i64,
    databases: Vec<DbUsage>,
}

#[derive(Serialize)]
pub struct Finding {
    /// "ok", "watch" or "urgent".
    severity: &'static str,
    title: String,
    summary: String,
    advice: String,
}

#[derive(Serialize)]
pub struct Maintenance {
    /// Empty: the engine reports no checks — silence, not a clean bill.
    findings: Vec<Finding>,
}

#[derive(Serialize)]
pub struct Overview {
    /// `null`: the server did not answer, or is not connected.
    dashboard: Option<Dashboard>,
    maintenance: Option<Maintenance>,
}

/// `GET /api/v1/admin/servers/{id}/overview` — what the server says about
/// itself, each part bounded at a few seconds.
pub async fn overview(
    State(state): State<AppState>,
    ApiAdmin(_): ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
) -> ApiResult<Json<Overview>> {
    load(&state, id).await?;
    let snap = srv::snapshot(&state, id).await;
    let dashboard = snap.overview.map(|o| Dashboard {
        uptime: crate::web::human_duration(o.uptime_secs),
        databases: o
            .databases
            .into_iter()
            .map(|d| DbUsage { managed: snap.managed.contains(&d.name), name: d.name, size_bytes: d.size_bytes, connections: d.connections })
            .collect(),
        version: o.version,
        uptime_secs: o.uptime_secs,
        total_connections: o.total_connections,
        max_connections: o.max_connections,
    });
    let maintenance = snap.maintenance.map(|r| Maintenance {
        findings: r
            .findings
            .into_iter()
            .map(|f| Finding {
                severity: match f.severity {
                    crate::engine::Severity::Ok => "ok",
                    crate::engine::Severity::Watch => "watch",
                    crate::engine::Severity::Urgent => "urgent",
                },
                title: f.title,
                summary: f.summary,
                advice: f.advice,
            })
            .collect(),
    });
    Ok(Json(Overview { dashboard, maintenance }))
}

#[derive(Serialize)]
pub struct Verdict {
    verdict: String,
    /// "ok", "bad" (needs attention), or "unknown": it could not be checked.
    state: srv::EdgeState,
}

#[derive(Serialize)]
pub struct Pools {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

#[derive(Serialize)]
pub struct Edge {
    /// The last sync failed or one is pending.
    dirty: bool,
    synced_at: Option<chrono::DateTime<chrono::Utc>>,
    hba: Verdict,
    knobs: Verdict,
    /// The bouncer console's pools; `null` when it is unavailable or not
    /// configured.
    pools: Option<Pools>,
}

/// `GET /api/v1/admin/servers/{id}/edge` — the rendered files against what
/// they should be, and the bouncer's pools.
pub async fn edge(
    State(state): State<AppState>,
    ApiAdmin(_): ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
) -> ApiResult<Json<Edge>> {
    let row = load(&state, id).await?;
    let h = srv::edge_health_data(&state, &row).await;
    Ok(Json(Edge {
        dirty: row.edge_dirty,
        synced_at: row.edge_synced_at,
        hba: Verdict { verdict: h.hba.0, state: h.hba.1 },
        knobs: Verdict { verdict: h.knobs.0, state: h.knobs.1 },
        pools: h.pools.map(|(headers, rows)| Pools { headers, rows }),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveBody {
    active: bool,
}

#[derive(Serialize)]
pub struct Active {
    /// The state it is in now, which a concurrent change may have decided.
    active: bool,
    /// Enabling: whether an engine could be connected. Disabling: null.
    connected: Option<bool>,
}

/// `POST /api/v1/admin/servers/{id}/active` — `{"active": bool}`.
pub async fn set_active(
    State(state): State<AppState>,
    ApiAdmin(session): ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
    ApiJson(body): ApiJson<ActiveBody>,
) -> ApiResult<Json<Active>> {
    let o = srv::set_active_for(&state, &session.actor(), id, body.active).await.map_err(server_error)?;
    Ok(Json(Active { active: o.active, connected: o.connected }))
}

#[derive(Serialize)]
pub struct TestCheck {
    check: String,
    ok: bool,
    detail: String,
}

#[derive(Serialize)]
pub struct TestReport {
    checks: Vec<TestCheck>,
}

/// `POST /api/v1/admin/servers/{id}/test` — check the stored admin login and
/// the advertised address from here. Audited.
pub async fn test(
    State(state): State<AppState>,
    ApiAdmin(session): ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
) -> ApiResult<Json<TestReport>> {
    let results = srv::connect_test(&state, &session.actor(), id).await.map_err(server_error)?;
    Ok(Json(TestReport {
        checks: results
            .into_iter()
            .map(|(check, r)| {
                let (ok, detail) = match r {
                    Ok(m) => (true, m),
                    Err(m) => (false, m),
                };
                TestCheck { check, ok, detail }
            })
            .collect(),
    }))
}

// ---- S8b: adding a server, init, credentials -------------------------------

fn add_error(e: srv::AddError) -> ApiError {
    use srv::AddError;
    let message = e.to_string();
    match e {
        AddError::Invalid(_) => ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid", message),
        AddError::CheckFailed(_) => ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "dsn_check_failed", message),
        AddError::Refused(_) => ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "role_refused", message),
        AddError::NameTaken(_) => ApiError::new(StatusCode::CONFLICT, "name_taken", message),
        AddError::NotFound => not_found(),
        AddError::Internal => ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", message),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewServer {
    name: String,
    admin_dsn: String,
    #[serde(default)]
    bouncer_dsn: Option<String>,
    host: String,
    /// Range-checked with the rest, so 70000 is "1-65535", not a parse error.
    port: u32,
    pool_mode: String,
    tls_mode: String,
    backend_kind: String,
    #[serde(default)]
    default_consumer_cidr: Option<String>,
}

#[derive(Serialize)]
pub struct Added {
    id: Uuid,
}

/// `POST /api/v1/admin/servers` — 201 with the new server's id. The admin DSN
/// must connect, and its role must be CREATEDB CREATEROLE and never superuser;
/// both DSNs are sealed before they are stored.
pub async fn create(
    State(state): State<AppState>,
    ApiAdmin(session): ApiAdmin,
    ApiJson(body): ApiJson<NewServer>,
) -> ApiResult<(StatusCode, Json<Added>)> {
    let input = srv::AddInput {
        name: body.name,
        admin_dsn: body.admin_dsn,
        bouncer_dsn: body.bouncer_dsn,
        host: body.host,
        port: body.port.to_string(),
        pool_mode: body.pool_mode,
        tls_mode: body.tls_mode,
        backend_kind: body.backend_kind,
        default_consumer_cidr: body.default_consumer_cidr,
    };
    let id = srv::add_server(&state, &session.actor(), &input).await.map_err(add_error)?;
    Ok((StatusCode::CREATED, Json(Added { id })))
}

#[derive(Serialize)]
pub struct InitStep {
    step: String,
    ok: bool,
    detail: String,
}

#[derive(Serialize)]
pub struct InitReport {
    /// "ready", "needs_bootstrap" or "failed".
    status: &'static str,
    steps: Vec<InitStep>,
    /// For "needs_bootstrap": the SQL a superuser runs once on the server,
    /// rendered for the role the panel actually connects as.
    bootstrap_sql: Option<String>,
    /// The bouncer auth role's userlist.txt line — a password in the clear —
    /// when there is no conf dir to write it to. In this response only; the
    /// API is no-store.
    userlist_line: Option<String>,
}

/// `POST /api/v1/admin/servers/{id}/init` — the idempotent server init, its
/// steps, and anything the operator has to place by hand.
pub async fn init(
    State(state): State<AppState>,
    ApiAdmin(session): ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
) -> ApiResult<Json<InitReport>> {
    let o = srv::init_server(&state, &session.actor(), id).await.map_err(|e| match e {
        srv::InitError::NotFound => not_found(),
        srv::InitError::Aborted(why) => {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "init_failed", format!("Init failed: {why}"))
        }
    })?;
    Ok(Json(InitReport {
        bootstrap_sql: (o.status == "needs_bootstrap")
            .then(|| crate::edge::bootstrap_sql(o.panel_role.as_deref().unwrap_or("cryptarch_admin"))),
        status: o.status,
        steps: o
            .steps
            .into_iter()
            .map(|s| {
                let (ok, detail) = match s.outcome {
                    Ok(m) => (true, m),
                    Err(m) => (false, m),
                };
                InitStep { step: s.step, ok, detail }
            })
            .collect(),
        userlist_line: o.manual_userlist_line,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialsBody {
    /// Empty or absent keeps what is stored.
    #[serde(default)]
    admin_dsn: Option<String>,
    #[serde(default)]
    bouncer_dsn: Option<String>,
}

#[derive(Serialize)]
pub struct Rotated {
    admin: bool,
    bouncer: bool,
    /// After a new admin login: null when the server is disabled, else
    /// whether Cryptarch is connected with it.
    reconnected: Option<bool>,
}

/// `POST /api/v1/admin/servers/{id}/credentials` — replace the stored admin
/// and/or bouncer console DSN; a new admin login is vetted as when adding.
pub async fn credentials(
    State(state): State<AppState>,
    ApiAdmin(session): ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
    ApiJson(body): ApiJson<CredentialsBody>,
) -> ApiResult<Json<Rotated>> {
    let r = srv::rotate_credentials(&state, &session.actor(), id, body.admin_dsn.as_deref(), body.bouncer_dsn.as_deref())
        .await
        .map_err(add_error)?;
    if !r.admin && !r.bouncer {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "nothing_to_rotate",
            "Nothing to rotate — both fields were left empty.",
        ));
    }
    Ok(Json(Rotated { admin: r.admin, bouncer: r.bouncer, reconnected: r.reconnected }))
}

// ---- S8c: settings, sources, listeners, pool overrides, sync ---------------

fn config_error(e: srv::ConfigError) -> ApiError {
    use srv::ConfigError;
    let message = e.to_string();
    match e {
        ConfigError::Invalid(_) => ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid", message),
        ConfigError::Duplicate(_) => ApiError::new(StatusCode::CONFLICT, "duplicate", message),
        ConfigError::NotFound => not_found(),
        ConfigError::NoSuchItem => ApiError::new(StatusCode::NOT_FOUND, "no_such_item", message),
        ConfigError::Internal => ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", message),
    }
}

/// What pushing a change to the edge did.
#[derive(Serialize)]
pub struct EdgeOut {
    /// "applied", "manual" (no conf dir: the rendered files are below, for
    /// the operator to place) or "failed" (saved, but the edge did not take
    /// it).
    state: &'static str,
    rules: Option<usize>,
    hba: Option<String>,
    knobs: Option<String>,
    error: Option<String>,
}

fn edge_out(s: srv::EdgeSync) -> EdgeOut {
    match s {
        srv::EdgeSync::Applied(n) => EdgeOut { state: "applied", rules: Some(n), hba: None, knobs: None, error: None },
        srv::EdgeSync::Manual { hba, knobs } => {
            EdgeOut { state: "manual", rules: None, hba: Some(hba), knobs: Some(knobs), error: None }
        }
        srv::EdgeSync::Failed(e) => EdgeOut { state: "failed", rules: None, hba: None, knobs: None, error: Some(e) },
    }
}

#[derive(Serialize)]
pub struct Synced {
    edge: EdgeOut,
}

#[derive(Serialize)]
pub struct Config {
    /// Each database's pool override; null fields inherit the server's.
    databases: Vec<srv::DbKnobRow>,
    sources: Vec<Source>,
    listeners: Vec<Listener>,
}

#[derive(Serialize)]
pub struct Source {
    id: Uuid,
    label: String,
    cidr: String,
    /// Pre-ticked on the provision form.
    is_default: bool,
}

#[derive(Serialize)]
pub struct Listener {
    id: Uuid,
    label: String,
    host: String,
    port: i32,
}

/// `GET /api/v1/admin/servers/{id}/config` — what the server page lists
/// besides the row: pool overrides, named sources, listeners.
pub async fn config(
    State(state): State<AppState>,
    ApiAdmin(_): ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
) -> ApiResult<Json<Config>> {
    load(&state, id).await?;
    let c = srv::server_config(&state, id).await.map_err(config_error)?;
    Ok(Json(Config {
        databases: c.databases,
        sources: c.sources.into_iter().map(|s| Source { id: s.id, label: s.label, cidr: s.cidr, is_default: s.is_default }).collect(),
        listeners: c.listeners.into_iter().map(|l| Listener { id: l.id, label: l.label, host: l.host, port: l.port }).collect(),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressBody {
    host: String,
    port: u32,
}

#[derive(Serialize)]
pub struct AddressSaved {
    /// Null when the server is disabled; else whether Cryptarch reconnected.
    reconnected: Option<bool>,
}

/// `POST /api/v1/admin/servers/{id}/settings/address`
pub async fn set_address(
    State(state): State<AppState>,
    ApiAdmin(session): ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
    ApiJson(body): ApiJson<AddressBody>,
) -> ApiResult<Json<AddressSaved>> {
    let input = srv::AddressInput { host: body.host, port: body.port.to_string() };
    let reconnected = srv::update_address_for(&state, &session.actor(), id, &input).await.map_err(config_error)?;
    Ok(Json(AddressSaved { reconnected }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolingBody {
    pool_mode: String,
    default_pool_size: u32,
    max_client_conn: u32,
    max_db_connections: u32,
    max_user_connections: u32,
}

/// `POST /api/v1/admin/servers/{id}/settings/pooling` — saved, then pushed
/// to the edge; the answer says whether it got there.
pub async fn set_pooling(
    State(state): State<AppState>,
    ApiAdmin(session): ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
    ApiJson(body): ApiJson<PoolingBody>,
) -> ApiResult<Json<Synced>> {
    let input = srv::PoolingInput {
        pool_mode: body.pool_mode,
        default_pool_size: body.default_pool_size.to_string(),
        max_client_conn: body.max_client_conn.to_string(),
        max_db_connections: body.max_db_connections.to_string(),
        max_user_connections: body.max_user_connections.to_string(),
    };
    let sync = srv::update_pooling_for(&state, &session.actor(), id, &input).await.map_err(config_error)?;
    Ok(Json(Synced { edge: edge_out(sync) }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeBody {
    tls_mode: String,
    backend_kind: String,
    /// Required, though it may be null: leaving it out must not clear it.
    #[serde(deserialize_with = "present")]
    default_consumer_cidr: Option<String>,
    /// Required; empty or null means no conf dir — edge config is rendered
    /// for manual placement.
    #[serde(deserialize_with = "present")]
    bouncer_conf_dir: Option<String>,
}

/// A field that must be sent, but may be null. Without this serde reads a
/// missing `Option` as `None`, and for these fields `None` means "clear it".
fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(d)
}

/// `POST /api/v1/admin/servers/{id}/settings/edge`
pub async fn set_edge(
    State(state): State<AppState>,
    ApiAdmin(session): ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
    ApiJson(body): ApiJson<EdgeBody>,
) -> ApiResult<Json<Synced>> {
    let input = srv::EdgeInput {
        tls_mode: body.tls_mode,
        backend_kind: body.backend_kind,
        default_consumer_cidr: body.default_consumer_cidr,
        bouncer_conf_dir: body.bouncer_conf_dir,
    };
    let sync = srv::update_edge_for(&state, &session.actor(), id, &input).await.map_err(config_error)?;
    Ok(Json(Synced { edge: edge_out(sync) }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBody {
    label: String,
    cidr: String,
    #[serde(default)]
    is_default: bool,
}

/// `POST /api/v1/admin/servers/{id}/sources` — 201.
pub async fn add_source(
    State(state): State<AppState>,
    ApiAdmin(session): ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
    ApiJson(body): ApiJson<SourceBody>,
) -> ApiResult<(StatusCode, Json<Done>)> {
    srv::add_source_for(&state, &session.actor(), id, &body.label, &body.cidr, body.is_default)
        .await
        .map_err(config_error)?;
    Ok((StatusCode::CREATED, Json(Done { ok: true })))
}

/// `DELETE /api/v1/admin/servers/{id}/sources/{source_id}` — it stops being
/// offered; access rules already made from it stay.
pub async fn remove_source(
    State(state): State<AppState>,
    ApiAdmin(session): ApiAdmin,
    ApiPath((id, source_id)): ApiPath<(Uuid, Uuid)>,
) -> ApiResult<Json<Done>> {
    srv::remove_source_for(&state, &session.actor(), id, source_id).await.map_err(config_error)?;
    Ok(Json(Done { ok: true }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerBody {
    label: String,
    host: String,
    port: u32,
}

/// `POST /api/v1/admin/servers/{id}/listeners` — 201.
pub async fn add_listener(
    State(state): State<AppState>,
    ApiAdmin(session): ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
    ApiJson(body): ApiJson<ListenerBody>,
) -> ApiResult<(StatusCode, Json<Done>)> {
    let input = srv::ListenerAddInput { host: body.host, port: body.port.to_string(), label: body.label };
    srv::add_listener_for(&state, &session.actor(), id, &input).await.map_err(config_error)?;
    Ok((StatusCode::CREATED, Json(Done { ok: true })))
}

/// `DELETE /api/v1/admin/servers/{id}/listeners/{listener_id}`
pub async fn remove_listener(
    State(state): State<AppState>,
    ApiAdmin(session): ApiAdmin,
    ApiPath((id, listener_id)): ApiPath<(Uuid, Uuid)>,
) -> ApiResult<Json<Done>> {
    srv::remove_listener_for(&state, &session.actor(), id, listener_id).await.map_err(config_error)?;
    Ok(Json(Done { ok: true }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolBody {
    /// "inherit", "session" or "transaction".
    pool_mode: String,
    /// Null inherits the server's limit.
    #[serde(default)]
    max_connections: Option<u32>,
}

#[derive(Serialize)]
pub struct PoolSaved {
    name: String,
    edge: EdgeOut,
}

/// `POST /api/v1/admin/servers/{id}/databases/{db_id}/pool` — one database's
/// pool override. The database must be on this server.
pub async fn set_db_pool(
    State(state): State<AppState>,
    ApiAdmin(session): ApiAdmin,
    ApiPath((id, db_id)): ApiPath<(Uuid, Uuid)>,
    ApiJson(body): ApiJson<PoolBody>,
) -> ApiResult<Json<PoolSaved>> {
    let input = srv::DbKnobsInput { pool_mode: body.pool_mode, max_connections: body.max_connections.map(|n| n.to_string()) };
    let (name, sync) = srv::set_db_pool_for(&state, &session.actor(), id, db_id, &input).await.map_err(config_error)?;
    Ok(Json(PoolSaved { name, edge: edge_out(sync) }))
}

/// `POST /api/v1/admin/servers/{id}/sync` — push the current ACL and pool
/// settings to the edge now.
pub async fn sync(
    State(state): State<AppState>,
    ApiAdmin(session): ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
) -> ApiResult<Json<Synced>> {
    let sync = srv::sync_for(&state, &session.actor(), id).await.map_err(config_error)?;
    Ok(Json(Synced { edge: edge_out(sync) }))
}

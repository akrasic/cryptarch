//! The tenant's own databases: the dashboard list, the provision form's data,
//! and provisioning (CRYPTARCH-131).
//!
//! Thin on purpose. Each handler calls a domain function —
//! `web::dashboard_data`, `web::provision_options`, `web::provision_request` —
//! so the quota, the ACL assembly and the server-scoped source resolution
//! exist once.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{ApiError, ApiJson, ApiPath, ApiResult, ApiUser};
use crate::provision::ProvisionError;
use crate::web::{self, AppState, OwnedDbRow, ProvisionResult, ServerOption};

#[derive(Serialize)]
pub struct Quota {
    /// Slots held, by the enforcer's own count.
    used: usize,
    /// `null` is unlimited.
    limit: Option<i32>,
    /// Whether the "New database" action should be offered.
    at_cap: bool,
    /// False when the quota or the slot count could not be read: `limit` and
    /// `used` are then not the account's, and must not be shown as such.
    known: bool,
}

#[derive(Serialize)]
pub struct DatabaseList {
    databases: Vec<OwnedDbRow>,
    /// False when the list could not be read: `databases` is then empty
    /// because nothing was seen, not because there is nothing.
    listed: bool,
    quota: Quota,
}

/// `GET /api/v1/databases` — the caller's databases and quota.
pub async fn list(State(state): State<AppState>, ApiUser(session): ApiUser) -> Json<DatabaseList> {
    let d = web::dashboard_data(&state, session.user_id).await;
    Json(DatabaseList {
        databases: d.dbs,
        listed: d.list_known,
        quota: Quota { used: d.used, limit: d.quota, at_cap: d.at_cap, known: d.quota_known },
    })
}

#[derive(Serialize)]
pub struct ServerList {
    servers: Vec<ServerOption>,
}

/// `GET /api/v1/servers` — where the caller may provision, and the named
/// sources each server offers. Signed-in users only; nothing an address or a
/// credential could be read from.
pub async fn servers(State(state): State<AppState>, ApiUser(_): ApiUser) -> Json<ServerList> {
    Json(ServerList { servers: web::provision_options(&state).await })
}

#[derive(Deserialize)]
pub struct ProvisionBody {
    server_id: Uuid,
    name: String,
    #[serde(default)]
    allowed_from: Option<String>,
    #[serde(default)]
    sources: Vec<Uuid>,
}

#[derive(Serialize)]
pub struct ViaListener {
    label: String,
    conn: String,
}

/// The show-once credential. Sent no-store (every API response is) and held by
/// the SPA in component state only (dec D8).
#[derive(Serialize)]
pub struct Provisioned {
    name: String,
    username: String,
    password: String,
    conn: String,
    via: Vec<ViaListener>,
    warnings: Vec<String>,
}

/// `POST /api/v1/databases` — provision one.
pub async fn create(
    State(state): State<AppState>,
    ApiUser(session): ApiUser,
    ApiJson(body): ApiJson<ProvisionBody>,
) -> ApiResult<(StatusCode, Json<Provisioned>)> {
    let ProvisionResult { done, via, warnings } = web::provision_request(
        &state,
        &session,
        body.server_id,
        &body.name,
        body.allowed_from.as_deref(),
        &body.sources,
    )
    .await
    .map_err(provision_error)?;
    Ok((
        StatusCode::CREATED,
        Json(Provisioned {
            name: done.name,
            username: done.username,
            password: done.password,
            conn: done.conn.0,
            via: via.into_iter().map(|(label, conn)| ViaListener { label, conn }).collect(),
            warnings,
        }),
    ))
}

/// A refused provision, as the form should show it: a stable code to branch on
/// and the domain error's own wording to display.
fn provision_error(e: ProvisionError) -> ApiError {
    let message = e.to_string();
    match e {
        ProvisionError::BadName => ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "bad_name", message),
        ProvisionError::BadCidr(_) => ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "bad_cidr", message),
        ProvisionError::NotActive(_) => ApiError::new(StatusCode::CONFLICT, "not_active", message),
        ProvisionError::RangeTooBroad(_) => ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "range_too_broad", message),
        ProvisionError::NoServer => ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "no_server", message),
        ProvisionError::QuotaReached { .. } => ApiError::new(StatusCode::CONFLICT, "quota_reached", message),
        ProvisionError::NameTaken(_) => ApiError::new(StatusCode::CONFLICT, "name_taken", message),
        ProvisionError::Internal => ApiError::internal(),
    }
}

#[derive(Serialize)]
pub struct Connection {
    label: String,
    /// Always masked; see `web::masked_connections`.
    conn: String,
}

#[derive(Serialize)]
pub struct DatabaseView {
    name: String,
    status: String,
    server_name: String,
    engine: String,
    created_at: chrono::DateTime<chrono::Utc>,
    owner: String,
    /// False when an admin is looking at someone else's database: the page
    /// hides what only the owner may do (reset, backup, restore).
    is_owner: bool,
    edge_dirty: bool,
    connections: Vec<Connection>,
    backups_enabled: bool,
}

/// One answer for "not yours" and "does not exist", so this endpoint does not
/// ADD a way to learn which names are taken. (Names are portal-wide unique, so
/// provisioning's 409 name_taken already says a name exists; what it never
/// says is whose, or what is in it.)
pub(super) fn no_such_database() -> ApiError {
    ApiError::not_found("There is no database by that name.")
}

/// `GET /api/v1/databases/{name}` — the database page's header and Connect
/// tab. Owner or admin (CRYPTARCH-140, 117).
pub async fn detail(
    State(state): State<AppState>,
    ApiUser(session): ApiUser,
    ApiPath(name): ApiPath<String>,
) -> ApiResult<Json<DatabaseView>> {
    let crate::provision::ViewableDb { detail: d, owner, is_owner } =
        crate::provision::viewable_db_detail(&state.db, session.user_id, session.is_admin, &name)
            .await
            .map_err(|_| ApiError::internal())?
            .ok_or_else(no_such_database)?;
    let connections = web::masked_connections(&state, &d)
        .await
        .into_iter()
        .map(|(label, conn)| Connection { label, conn })
        .collect();
    Ok(Json(DatabaseView {
        edge_dirty: web::edge_dirty(&state, d.server_id).await,
        is_owner,
        owner,
        connections,
        backups_enabled: state.backup_dir.is_some(),
        name: d.name,
        status: d.status,
        server_name: d.server_name,
        engine: d.engine,
        created_at: d.created_at,
    }))
}

#[derive(Serialize)]
pub struct Table {
    name: String,
    /// Planner estimate; -1 when never analyzed.
    approx_rows: i64,
    total_bytes: i64,
}

/// What the Contents tab shows. `available: false` (everything else absent)
/// when the managed server did not answer in time — a degraded answer, not an
/// error.
#[derive(Serialize)]
pub struct Contents {
    available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    size_bytes: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    active: Option<bool>,
    /// `null` when the size was readable but the table list was not; `[]` is
    /// a genuinely empty database. Absent when unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    tables: Option<Option<Vec<Table>>>,
}

/// `GET /api/v1/databases/{name}/contents` — the one call that asks the
/// managed server what is in a database. Same posture as the view.
pub async fn contents(
    State(state): State<AppState>,
    ApiUser(session): ApiUser,
    ApiPath(name): ApiPath<String>,
) -> ApiResult<Json<Contents>> {
    let v = crate::provision::viewable_db_detail(&state.db, session.user_id, session.is_admin, &name)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or_else(no_such_database)?;
    Ok(Json(match web::db_contents(&state, &v.detail).await {
        None => Contents { available: false, size_bytes: None, active: None, tables: None },
        Some(s) => Contents {
            available: true,
            size_bytes: Some(s.size_bytes),
            active: Some(s.active),
            tables: Some(s.tables.map(|ts| {
                ts.into_iter()
                    .map(|t| Table { name: t.name, approx_rows: t.approx_rows, total_bytes: t.total_bytes })
                    .collect()
            })),
        },
    }))
}

/// `POST /api/v1/databases/{name}/reset` — a new password, shown once. The
/// OWNER's alone (`web::reset_request`): anyone else, admin included, gets the
/// uniform 404 and the server is never asked.
pub async fn reset(
    State(state): State<AppState>,
    ApiUser(session): ApiUser,
    ApiPath(name): ApiPath<String>,
) -> ApiResult<Json<Reset>> {
    let (done, via) = web::reset_request(&state, &session, &name)
        .await
        .map_err(|e| match e {
            ProvisionError::NotActive(_) => ApiError::new(StatusCode::CONFLICT, "not_active", e.to_string()),
            e => {
                tracing::error!("reset failed for {}/{name}: {e}", session.username);
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "reset_failed", format!("Password reset failed: {e}"))
            }
        })?
        .ok_or_else(no_such_database)?;
    Ok(Json(Reset {
        name: done.name,
        username: done.username,
        password: done.password,
        conn: done.conn.0,
        via: via.into_iter().map(|(label, conn)| ViaListener { label, conn }).collect(),
        unrecorded: done.unrecorded,
    }))
}

/// A reset's show-once credential. Like [`Provisioned`], held by the SPA in
/// component state only.
#[derive(Serialize)]
pub struct Reset {
    name: String,
    username: String,
    password: String,
    conn: String,
    via: Vec<ViaListener>,
    /// Live on the server, but Cryptarch could not record its hash
    /// (CRYPTARCH-101): the page says so above the credential.
    unrecorded: bool,
}

#[derive(Deserialize)]
pub struct DeleteBody {
    /// Absent is a mismatch like any other, not a malformed request.
    #[serde(default)]
    confirm: String,
}

#[derive(Serialize)]
pub struct Deleted {
    deleted: String,
    /// Set when the edge did not take the change.
    warning: Option<String>,
}

/// `POST /api/v1/databases/{name}/delete` with `{"confirm": "<name>"}`. Owner
/// or admin (`web::authz_lookup`); anyone else gets the uniform 404, like the
/// view and the ACL. A POST, not a DELETE with a body: a DELETE body has no
/// defined meaning (RFC 9110) and some proxies drop it, which would turn every
/// delete into a confusing refusal.
pub async fn delete(
    State(state): State<AppState>,
    ApiUser(session): ApiUser,
    ApiPath(name): ApiPath<String>,
    ApiJson(body): ApiJson<DeleteBody>,
) -> ApiResult<Json<Deleted>> {
    let lookup = web::authz_lookup(&state, &session, &name).await.map_err(|d| match d {
        web::DbDenied::Forbidden | web::DbDenied::Missing => no_such_database(),
        web::DbDenied::Internal => ApiError::internal(),
    })?;
    let warning = web::delete_request(&state, &session, &lookup, &name, &body.confirm)
        .await
        .map_err(|e| match e {
            web::DeleteError::ConfirmMismatch => ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "confirm_mismatch",
                format!("Confirmation didn't match — type {name} exactly to delete."),
            ),
            web::DeleteError::JobRunning => ApiError::new(
                StatusCode::CONFLICT,
                "job_running",
                "A backup or restore of this database is running — wait for it to finish, then delete.",
            ),
            web::DeleteError::Failed(e) => {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "delete_failed", format!("Delete failed: {e}"))
            }
        })?;
    Ok(Json(Deleted { deleted: name, warning }))
}

//! The Access tab: who may reach a database at the edge (CRYPTARCH-142).
//!
//! The owner or an admin may read and change the list (`web::authz_lookup`).
//! Anyone else gets the same 404 as a name that does not exist — never a 403:
//! the database view already answers a non-owner 404 (CRYPTARCH-140), and two
//! endpoints of one page disagreeing would tell a tenant which names exist.
//! The changes themselves are `web::acl_add_entry` / `acl_remove_entry`.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{ApiError, ApiJson, ApiPath, ApiResult, ApiUser};
use crate::auth::Session;
use crate::provision::DbLookup;
use crate::web::{self, AclEntryRow, AclError, AppState, DbDenied};

async fn authz(state: &AppState, session: &Session, name: &str) -> ApiResult<DbLookup> {
    web::authz_lookup(state, session, name).await.map_err(|d| match d {
        DbDenied::Forbidden | DbDenied::Missing => super::databases::no_such_database(),
        DbDenied::Internal => ApiError::internal(),
    })
}

fn acl_error(e: AclError) -> ApiError {
    let message = e.to_string();
    match e {
        AclError::BadCidr(_) => ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "bad_cidr", message),
        AclError::RangeTooBroad(_) => ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "range_too_broad", message),
        AclError::BadNote => ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "bad_note", message),
        AclError::NoSuchEntry => ApiError::new(StatusCode::NOT_FOUND, "no_such_source", message),
        AclError::Internal => ApiError::internal(),
    }
}

/// A server's named source the database does not allow yet: a quick-add.
#[derive(Serialize)]
pub struct Source {
    id: Uuid,
    label: String,
    cidr: String,
}

#[derive(Serialize)]
pub struct Acl {
    entries: Vec<AclEntryRow>,
    unallowed_sources: Vec<Source>,
}

/// `GET /api/v1/databases/{name}/acl`
pub async fn list(
    State(state): State<AppState>,
    ApiUser(session): ApiUser,
    ApiPath(name): ApiPath<String>,
) -> ApiResult<Json<Acl>> {
    let lookup = authz(&state, &session, &name).await?;
    let entries = web::acl_list(&state.db, lookup.id).await.map_err(|e| {
        tracing::error!("acl list {name}: {e:#}");
        ApiError::internal()
    })?;
    // Only what this caller could actually add: a tenant is not offered a
    // named source that reaches 0.0.0.0 (CRYPTARCH-142).
    let approved = crate::servers::approved_ranges(&state.db, lookup.server_id).await;
    let unallowed_sources = crate::servers::sources_for(&state.db, lookup.server_id)
        .await
        .into_iter()
        .filter(|s| !entries.iter().any(|a| a.cidr == s.cidr))
        .filter(|s| session.is_admin || crate::servers::tenant_may_allow(&s.cidr, &approved))
        .map(|s| Source { id: s.id, label: s.label, cidr: s.cidr })
        .collect();
    Ok(Json(Acl { entries, unallowed_sources }))
}

#[derive(Deserialize)]
pub struct AddBody {
    cidr: String,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Serialize)]
pub struct Added {
    entry: AclEntryRow,
    /// False when the cidr was already allowed: `entry` is the existing row,
    /// and the note sent with this request was not kept.
    created: bool,
    /// Set when the edge did not take the change — it must not look applied.
    warning: Option<String>,
}

/// `POST /api/v1/databases/{name}/acl` — 201 when added, 200 with the existing
/// entry when the cidr was already allowed.
pub async fn add(
    State(state): State<AppState>,
    ApiUser(session): ApiUser,
    ApiPath(name): ApiPath<String>,
    ApiJson(body): ApiJson<AddBody>,
) -> ApiResult<(StatusCode, Json<Added>)> {
    let lookup = authz(&state, &session, &name).await?;
    let done = web::acl_add_entry(&state, &session, &lookup, &name, &body.cidr, body.note.as_deref())
        .await
        .map_err(acl_error)?;
    let status = if done.created { StatusCode::CREATED } else { StatusCode::OK };
    Ok((status, Json(Added { entry: done.entry, created: done.created, warning: done.warning })))
}

#[derive(Serialize)]
pub struct Removed {
    removed: String,
    warning: Option<String>,
}

/// `DELETE /api/v1/databases/{name}/acl/{entry_id}` — 404 when the entry is
/// not on this database (CRYPTARCH-116).
pub async fn remove(
    State(state): State<AppState>,
    ApiUser(session): ApiUser,
    ApiPath((name, entry_id)): ApiPath<(String, Uuid)>,
) -> ApiResult<Json<Removed>> {
    let lookup = authz(&state, &session, &name).await?;
    let done = web::acl_remove_entry(&state, &session, &lookup, &name, entry_id)
        .await
        .map_err(acl_error)?;
    Ok(Json(Removed { removed: done.cidr, warning: done.warning }))
}

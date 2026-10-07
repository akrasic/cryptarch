//! The Backups tab: a database's backup history, and starting one
//! (CRYPTARCH-144).
//!
//! Two postures. READING the history follows the database view —
//! owner or admin (CRYPTARCH-117), since it is metadata about jobs, not their
//! contents. STARTING one is the owner's alone (`owned_db_detail`): an admin
//! has the fleet tools for that. Anyone else gets the uniform 404 either way.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;
use uuid::Uuid;

use super::{ApiError, ApiPath, ApiResult, ApiUser};
use crate::backup::EnqueueError;
use crate::web::{self, AppState, ContentsSummary};

#[derive(Serialize)]
pub struct Backup {
    id: Uuid,
    created_at: chrono::DateTime<chrono::Utc>,
    finished_at: Option<chrono::DateTime<chrono::Utc>>,
    size_bytes: Option<i64>,
    /// How long it took, or has taken so far, in words ("4.2s").
    took: String,
    status: String,
    error: Option<String>,
    log: String,
    /// Read back after writing and proven readable. False says only that this
    /// never happened, not that it failed.
    verified: bool,
    contents: ContentsSummary,
}

#[derive(Serialize)]
pub struct Backups {
    /// False when this deployment has no backup directory: nothing can be
    /// started, and the list is empty.
    enabled: bool,
    backups: Vec<Backup>,
}

/// `GET /api/v1/databases/{name}/backups` — newest first.
pub async fn list(
    State(state): State<AppState>,
    ApiUser(session): ApiUser,
    ApiPath(name): ApiPath<String>,
) -> ApiResult<Json<Backups>> {
    let v = crate::provision::viewable_db_detail(&state.db, session.user_id, session.is_admin, &name)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or_else(super::databases::no_such_database)?;
    if state.backup_dir.is_none() {
        return Ok(Json(Backups { enabled: false, backups: Vec::new() }));
    }
    let backups = crate::backup::history(&state.db, v.detail.id)
        .await
        .into_iter()
        .map(|b| Backup {
            took: b.duration(),
            verified: b.verified_at.is_some(),
            contents: web::contents_summary(&b),
            id: b.id,
            created_at: b.created_at,
            finished_at: b.finished_at,
            size_bytes: b.size_bytes,
            status: b.status,
            error: b.error,
            log: b.log,
        })
        .collect();
    Ok(Json(Backups { enabled: true, backups }))
}

#[derive(Serialize)]
pub struct Started {
    id: Uuid,
}

/// `POST /api/v1/databases/{name}/backups` — start one; 202 with its id. The
/// history follows it.
pub async fn start(
    State(state): State<AppState>,
    ApiUser(session): ApiUser,
    ApiPath(name): ApiPath<String>,
) -> ApiResult<(StatusCode, Json<Started>)> {
    let d = crate::provision::owned_db_detail(&state.db, session.user_id, &name)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or_else(super::databases::no_such_database)?;
    // Mid-delete or mid-restore: said as such, as a reset does, not left to
    // the enqueue's "not found" about a database the page is showing.
    if d.status != "active" {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "not_active",
            format!("Backup not started: this database is {} — try again once it is active.", d.status),
        ));
    }
    let id = crate::backup::enqueue(&state, &session.actor(), &d.name).await.map_err(|e| {
        let message = format!("Backup not started: {e}");
        match e {
            EnqueueError::Disabled => ApiError::new(StatusCode::CONFLICT, "backups_disabled", message),
            EnqueueError::AlreadyRunning => ApiError::new(StatusCode::CONFLICT, "already_running", message),
            EnqueueError::RestoreRunning => ApiError::new(StatusCode::CONFLICT, "restore_running", message),
            EnqueueError::ShuttingDown => ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "shutting_down", message),
            EnqueueError::NotFound => super::databases::no_such_database(),
            EnqueueError::Internal => ApiError::internal(),
        }
    })?;
    Ok((StatusCode::ACCEPTED, Json(Started { id })))
}

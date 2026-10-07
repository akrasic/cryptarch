//! Restores: starting one, a database's restore history, and one job as its
//! five-step pipeline (CRYPTARCH-145).
//!
//! STARTING is the owner's alone (`owned_db_detail`): it rewrites their data,
//! and the backup is resolved against the database's IDENTITY inside
//! `restore::enqueue` (CRYPTARCH-86), so owning the target is not owning the
//! backup. READING follows the database view — owner or admin — and is keyed
//! on identity too (CRYPTARCH-100): the next holder of a freed name sees none
//! of it. Anyone else gets the uniform 404.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{ApiError, ApiJson, ApiPath, ApiResult, ApiUser};
use crate::restore::{EnqueueError, RestoreRow, Stage, StepState};
use crate::web::AppState;

#[derive(Deserialize)]
pub struct StartBody {
    backup_id: Uuid,
    /// The database's name, typed. Absent is a mismatch like any other.
    #[serde(default)]
    confirm: String,
}

#[derive(Serialize)]
pub struct Started {
    id: Uuid,
}

/// `POST /api/v1/databases/{name}/restores` — 202 with the job's id; the SPA
/// goes to the job's page.
pub async fn start(
    State(state): State<AppState>,
    ApiUser(session): ApiUser,
    ApiPath(name): ApiPath<String>,
    ApiJson(body): ApiJson<StartBody>,
) -> ApiResult<(StatusCode, Json<Started>)> {
    let d = crate::provision::owned_db_detail(&state.db, session.user_id, &name)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or_else(super::databases::no_such_database)?;
    if body.confirm.trim() != d.name {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "confirm_mismatch",
            "Type the database name exactly to confirm the restore.",
        ));
    }
    if d.status != "active" {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "not_active",
            format!("Restore not started: this database is {} — try again once it is active.", d.status),
        ));
    }
    let id = crate::restore::enqueue(&state, &session.actor(), d.id, &d.name, body.backup_id)
        .await
        .map_err(|e| {
            let message = format!("Restore not started: {e}");
            match e {
                EnqueueError::Disabled => ApiError::new(StatusCode::CONFLICT, "backups_disabled", message),
                EnqueueError::NotFound => ApiError::new(StatusCode::NOT_FOUND, "no_such_backup", message),
                EnqueueError::AlreadyRunning => ApiError::new(StatusCode::CONFLICT, "already_running", message),
                EnqueueError::NotActive => ApiError::new(StatusCode::CONFLICT, "not_active", message),
                EnqueueError::BackupRunning => ApiError::new(StatusCode::CONFLICT, "backup_running", message),
                EnqueueError::WrongKey { .. } => ApiError::new(StatusCode::CONFLICT, "wrong_key", message),
                EnqueueError::ShuttingDown => {
                    ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "shutting_down", message)
                }
                EnqueueError::Internal => ApiError::internal(),
            }
        })?;
    Ok((StatusCode::ACCEPTED, Json(Started { id })))
}

async fn viewable(state: &AppState, session: &crate::auth::Session, name: &str) -> ApiResult<Uuid> {
    Ok(crate::provision::viewable_db_detail(&state.db, session.user_id, session.is_admin, name)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or_else(super::databases::no_such_database)?
        .detail
        .id)
}

#[derive(Serialize)]
pub struct Summary {
    id: Uuid,
    created_at: chrono::DateTime<chrono::Utc>,
    finished_at: Option<chrono::DateTime<chrono::Utc>>,
    status: String,
    requested_by: String,
    /// The step the stored stage names: in flight while running, where it
    /// stopped on failure. `null` for a stage this build does not know.
    stage_title: Option<&'static str>,
}

#[derive(Serialize)]
pub struct History {
    restores: Vec<Summary>,
}

/// `GET /api/v1/databases/{name}/restores` — newest first.
pub async fn list(
    State(state): State<AppState>,
    ApiUser(session): ApiUser,
    ApiPath(name): ApiPath<String>,
) -> ApiResult<Json<History>> {
    let database_id = viewable(&state, &session, &name).await?;
    let restores = crate::restore::history(&state.db, database_id)
        .await
        .into_iter()
        .map(|r| Summary {
            stage_title: Stage::from_key(&r.stage).map(Stage::title),
            id: r.id,
            created_at: r.created_at,
            finished_at: r.finished_at,
            status: r.status,
            requested_by: r.requested_by,
        })
        .collect();
    Ok(Json(History { restores }))
}

#[derive(Serialize)]
pub struct Step {
    key: &'static str,
    title: &'static str,
    blurb: &'static str,
    /// done | running | failed | skipped | pending — `RestoreRow::step_state`,
    /// one derivation for every caller.
    state: &'static str,
    time: Option<String>,
    detail: Option<String>,
    /// The restore's error, on the step that failed and nowhere else.
    error: Option<String>,
}

#[derive(Serialize)]
pub struct Job {
    id: Uuid,
    created_at: chrono::DateTime<chrono::Utc>,
    finished_at: Option<chrono::DateTime<chrono::Utc>>,
    status: String,
    requested_by: String,
    /// The restore's error, whole (redacted of row data when stored). Also on
    /// the failed step; here too, so a stage this build does not know cannot
    /// hide it.
    error: Option<String>,
    steps: Vec<Step>,
}

fn steps(r: &RestoreRow) -> Vec<Step> {
    Stage::ALL
        .into_iter()
        .map(|stage| {
            let st = r.step_state(stage);
            let (time, detail) = match r.detail(stage) {
                Some((t, d)) => (Some(t), Some(d).filter(|d| !d.is_empty())),
                None => (None, None),
            };
            Step {
                key: stage.key(),
                title: stage.title(),
                blurb: stage.blurb(),
                state: match st {
                    StepState::Done => "done",
                    StepState::Running => "running",
                    StepState::Failed => "failed",
                    StepState::Skipped => "skipped",
                    StepState::Pending => "pending",
                },
                time,
                detail,
                error: (st == StepState::Failed).then(|| r.error.clone()).flatten(),
            }
        })
        .collect()
}

/// `GET /api/v1/databases/{name}/restores/{id}` — one job. A restore id is
/// not a capability: it is found only through a database the caller may view.
pub async fn job(
    State(state): State<AppState>,
    ApiUser(session): ApiUser,
    ApiPath((name, id)): ApiPath<(String, Uuid)>,
) -> ApiResult<Json<Job>> {
    let database_id = viewable(&state, &session, &name).await?;
    let r = crate::restore::get(&state.db, database_id, id)
        .await
        .ok_or_else(|| ApiError::not_found("There is no restore by that id for this database."))?;
    Ok(Json(Job {
        steps: steps(&r),
        id: r.id,
        created_at: r.created_at,
        finished_at: r.finished_at,
        status: r.status,
        requested_by: r.requested_by,
        error: r.error,
    }))
}

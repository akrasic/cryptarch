//! The admin API, backups (CRYPTARCH-135, S7): every backup job across the
//! fleet, the backups deleted databases left behind, and files on the backup
//! disk that no row points at.
//!
//! Three reads, not one, on purpose. The jobs list is what the page polls
//! while a job runs; the other two walk the backup mount and stat every file
//! left behind. The maud page used to re-run both on every 3s poll and throw
//! them away (CRYPTARCH-124), so the poll gets an endpoint that does neither.
//!
//! Purging keeps its re-validation in `crate::backup`: a purge is scoped
//! through the `operator_backups` view, so a live tenant's backup is a 404
//! whatever id is sent, and a file is deleted only if its name identifies a
//! backup that still has no row.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{ApiAdmin, ApiError, ApiJson, ApiPath, ApiResult};
use crate::backup::{FilePurgeError, PurgeError, Purged};
use crate::web::{self, AppState, ContentsSummary};

/// The newest jobs listed.
const JOBS_LISTED: i64 = 100;

#[derive(Serialize)]
pub struct Job {
    id: Uuid,
    db_name: String,
    /// Cryptarch's own metadata database: no page to link to.
    metadata: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    size_bytes: Option<i64>,
    took: String,
    status: String,
    error: Option<String>,
    log: String,
    verified: bool,
    contents: ContentsSummary,
}

#[derive(Serialize)]
pub struct Jobs {
    /// False when this deployment has no backup directory.
    configured: bool,
    /// Whether any job is still running: the page polls while it is.
    running: bool,
    jobs: Vec<Job>,
}

/// `GET /api/v1/admin/backups` — the newest jobs, every database's, newest
/// first. What the page polls; it reads nothing else.
pub async fn jobs(State(state): State<AppState>, ApiAdmin(_): ApiAdmin) -> ApiResult<Json<Jobs>> {
    let rows = crate::backup::recent(&state.db, JOBS_LISTED).await.map_err(|e| {
        tracing::error!("reading recent backups: {e}");
        ApiError::internal()
    })?;
    let jobs: Vec<Job> = rows
        .into_iter()
        .map(|b| Job {
            took: b.duration(),
            verified: b.verified_at.is_some(),
            contents: web::contents_summary(&b),
            metadata: b.db_name == crate::backup::METADATA_DB,
            id: b.id,
            db_name: b.db_name,
            created_at: b.created_at,
            size_bytes: b.size_bytes,
            status: b.status,
            error: b.error,
            log: b.log,
        })
        .collect();
    Ok(Json(Jobs {
        configured: state.backup_dir.is_some(),
        running: jobs.iter().any(|j| j.status == "running"),
        jobs,
    }))
}

#[derive(Serialize)]
pub struct LeftBehindRow {
    id: Uuid,
    db_name: String,
    created_at: chrono::DateTime<chrono::Utc>,
    status: String,
    /// What the row says the blob weighs.
    size_bytes: Option<i64>,
    /// Whether the blob is on disk. False beside a recorded size is how an
    /// operator finds out a backup lost its file (CRYPTARCH-87). Null: it
    /// could not be looked for, which is neither.
    file_present: Option<bool>,
}

#[derive(Serialize)]
pub struct LeftBehind {
    configured: bool,
    backups: Vec<LeftBehindRow>,
    /// The sum of the recorded sizes, which over-reports by whatever is missing.
    recorded_bytes: i64,
    missing: usize,
    /// How many could not be looked for.
    unchecked: usize,
}

/// `GET /api/v1/admin/backups/left-behind` — the backups of deleted databases,
/// newest first. Never the metadata database's (the view excludes it).
pub async fn left_behind(State(state): State<AppState>, ApiAdmin(_): ApiAdmin) -> ApiResult<Json<LeftBehind>> {
    let view = crate::backup::operator_backups_view(&state).await.map_err(|e| {
        tracing::error!("reading operator-owned backups: {e}");
        ApiError::internal()
    })?;
    Ok(Json(LeftBehind {
        configured: state.backup_dir.is_some(),
        recorded_bytes: view.recorded_bytes,
        missing: view.missing,
        unchecked: view.unchecked,
        backups: view
            .rows
            .into_iter()
            .map(|(b, file_present)| LeftBehindRow {
                id: b.id,
                db_name: b.db_name,
                created_at: b.created_at,
                status: b.status,
                size_bytes: b.size_bytes,
                file_present,
            })
            .collect(),
    }))
}

#[derive(Serialize)]
pub struct FileOut {
    /// Relative to the backup root; the handle `purge-file` takes.
    rel: String,
    size_bytes: u64,
    /// Named as Cryptarch names a blob, so it can be matched to (the absence
    /// of) a row and deleted. An unrecognised file is listed, never deletable.
    recognised: bool,
}

#[derive(Serialize)]
pub struct Unreferenced {
    configured: bool,
    files: Vec<FileOut>,
    total_bytes: u64,
}

/// `GET /api/v1/admin/backups/unreferenced` — files on the backup disk that
/// no backup row points at. A scan that could not read the disk is an error,
/// never an empty list.
pub async fn unreferenced(State(state): State<AppState>, ApiAdmin(_): ApiAdmin) -> ApiResult<Json<Unreferenced>> {
    let files = crate::backup::unreferenced_files(&state).await.map_err(|e| {
        tracing::warn!("could not scan the backup directory for unreferenced files: {e:#}");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "scan_failed",
            "The backup disk could not be fully read, so this list is unknown, not empty. See the server log.",
        )
    })?;
    Ok(Json(Unreferenced {
        configured: state.backup_dir.is_some(),
        total_bytes: files.iter().map(|f| f.size_bytes).sum(),
        files: files
            .into_iter()
            .map(|f| FileOut { recognised: f.id.is_some(), rel: f.rel, size_bytes: f.size_bytes })
            .collect(),
    }))
}

fn disabled() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        "backups_disabled",
        "Backups are not configured on this deployment, so there is nothing to purge.",
    )
}

#[derive(Serialize)]
pub struct PurgedOut {
    /// `with_file`, or `row_only`: the row was purged and no file was found —
    /// no space reclaimed, and the backup had already lost its file.
    outcome: &'static str,
}

/// `POST /api/v1/admin/backups/{id}/purge` — delete one backup a deleted
/// database left behind, row and file. Irreversible: it is the last copy.
pub async fn purge(
    State(state): State<AppState>,
    ApiAdmin(session): ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
) -> ApiResult<Json<PurgedOut>> {
    let outcome = crate::backup::purge_operator_backup(&state, &session.actor(), id).await.map_err(|e| match e {
        PurgeError::Disabled => disabled(),
        PurgeError::NotFound => ApiError::new(
            StatusCode::NOT_FOUND,
            "no_such_backup",
            "No backup left behind by a deleted database has that id — it may already be purged.",
        ),
        PurgeError::RestoreRunning => ApiError::new(
            StatusCode::CONFLICT,
            "restore_running",
            "A restore is reading this backup right now. Purge it once that restore has finished.",
        ),
        PurgeError::Failed(e) => {
            tracing::warn!("purging backup {id}: {e:#}");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "purge_failed",
                "The backup could not be purged and is still there — see the server log.",
            )
        }
    })?;
    Ok(Json(PurgedOut {
        outcome: match outcome {
            Purged::WithBlob => "with_file",
            Purged::RowOnlyNoBlobFound => "row_only",
        },
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PurgeFileBody {
    rel: String,
}

#[derive(Serialize)]
pub struct FilePurged {
    size_bytes: u64,
}

/// `POST /api/v1/admin/backups/purge-file` — delete one file no row points at.
/// Takes the path, since no row exists to name it.
pub async fn purge_file(
    State(state): State<AppState>,
    ApiAdmin(session): ApiAdmin,
    ApiJson(body): ApiJson<PurgeFileBody>,
) -> ApiResult<Json<FilePurged>> {
    let size_bytes =
        crate::backup::purge_unreferenced_file(&state, &session.actor(), &body.rel).await.map_err(|e| {
            let message = e.to_string();
            match e {
                FilePurgeError::Disabled => disabled(),
                FilePurgeError::BadPath(_) => ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "bad_path",
                    "That is not a path inside the backup directory.",
                ),
                FilePurgeError::Unrecognised => {
                    ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "unrecognised_file", message)
                }
                FilePurgeError::NowReferenced => ApiError::new(
                    StatusCode::CONFLICT,
                    "now_referenced",
                    "That file belongs to a backup now, so it was not deleted. Reload the page.",
                ),
                FilePurgeError::NotFound => ApiError::new(
                    StatusCode::NOT_FOUND,
                    "no_such_file",
                    "That file is not on the backup disk any more — it may already be deleted.",
                ),
                FilePurgeError::Failed(e) => {
                    tracing::warn!("purging unreferenced file {}: {e:#}", body.rel);
                    ApiError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "purge_failed",
                        "The file could not be deleted — see the server log.",
                    )
                }
            }
        })?;
    Ok(Json(FilePurged { size_bytes }))
}

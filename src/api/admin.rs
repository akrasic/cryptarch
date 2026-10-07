//! The admin API, part one: the overview and users (CRYPTARCH-134, S6a).
//!
//! Every route takes `ApiAdmin`: 401 signed out, 403 for a tenant, and 403
//! `password_change_required` for an admin whose own password an admin set
//! (CRYPTARCH-146). The changes are `crate::admin`'s `*_for` functions, shared
//! domain functions: a reset and a suspension are each one transaction, so
//! neither can leave live sessions behind a change reported as done.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{ApiAdmin, ApiError, ApiJson, ApiPath, ApiResult};
use crate::admin::{self, AdminError, AdminUserRow, UserDbRow};
use crate::web::AppState;

fn admin_error(e: AdminError) -> ApiError {
    let message = e.to_string();
    match e {
        AdminError::NotFound => ApiError::not_found(message),
        AdminError::OwnAccount => ApiError::new(StatusCode::CONFLICT, "own_account", message),
        AdminError::BadUsername => ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "bad_username", message),
        AdminError::BadQuota => ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "bad_quota", message),
        AdminError::TooShort => ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "too_short", message),
        AdminError::TooLong => ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "too_long", message),
        AdminError::UsernameTaken => ApiError::new(StatusCode::CONFLICT, "username_taken", message),
        AdminError::NotAnActiveAdmin => ApiError::new(StatusCode::FORBIDDEN, "not_an_active_admin", message),
        AdminError::Internal => ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", message),
    }
}

/// A quota as JSON: a whole number 0-999, or null for unlimited. Anything
/// else — a string, a fraction — is refused rather than coerced.
fn quota_from(v: &serde_json::Value) -> Result<Option<i32>, ApiError> {
    match v {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Number(n) => admin::check_quota(n.as_i64().or(Some(-1))).map_err(admin_error),
        _ => Err(admin_error(AdminError::BadQuota)),
    }
}

#[derive(Serialize)]
pub struct Overview {
    users: i64,
    databases: i64,
    servers: i64,
    /// Whether to show the encryption-key warning (no key material here).
    backups_enabled: bool,
}

/// `GET /api/v1/admin/overview`
pub async fn overview(State(state): State<AppState>, ApiAdmin(_): ApiAdmin) -> Json<Overview> {
    let (users, databases, servers) = admin::overview_counts(&state.db).await;
    Json(Overview { users, databases, servers, backups_enabled: state.backup_dir.is_some() })
}

#[derive(Serialize)]
pub struct Users {
    users: Vec<AdminUserRow>,
}

/// `GET /api/v1/admin/users` — by name.
pub async fn users(State(state): State<AppState>, ApiAdmin(_): ApiAdmin) -> ApiResult<Json<Users>> {
    let users = admin::list_users(&state.db).await.map_err(|e| {
        tracing::error!("listing users: {e}");
        ApiError::internal()
    })?;
    Ok(Json(Users { users }))
}

#[derive(Serialize)]
pub struct UserDetail {
    user: AdminUserRow,
    /// The admin's own account: the page offers its profile instead.
    is_self: bool,
    databases: Vec<UserDbRow>,
}

/// `GET /api/v1/admin/users/{id}`
pub async fn user(
    State(state): State<AppState>,
    ApiAdmin(session): ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
) -> ApiResult<Json<UserDetail>> {
    let failed = |e: sqlx::Error| {
        tracing::error!("reading user {id}: {e}");
        ApiError::internal()
    };
    let user = admin::find_user(&state.db, id).await.map_err(failed)?.ok_or_else(|| admin_error(AdminError::NotFound))?;
    let databases = admin::user_databases(&state.db, id).await.map_err(failed)?;
    Ok(Json(UserDetail { is_self: user.id == session.user_id, user, databases }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewUser {
    username: String,
    /// Absent or empty: one is generated.
    #[serde(default)]
    password: Option<String>,
    /// Required, even when unlimited (`null`): a quota is said, never assumed
    /// (S6a audit P2 — a missing one used to mean unlimited).
    quota: serde_json::Value,
    #[serde(default)]
    is_admin: bool,
}

/// The new account's password, shown ONCE (no-store, like every API answer).
#[derive(Serialize)]
pub struct Created {
    username: String,
    password: String,
    is_admin: bool,
}

/// `POST /api/v1/admin/users` — 201.
pub async fn create_user(
    State(state): State<AppState>,
    ApiAdmin(session): ApiAdmin,
    ApiJson(body): ApiJson<NewUser>,
) -> ApiResult<(StatusCode, Json<Created>)> {
    let quota = quota_from(&body.quota)?;
    let password = admin::create_user_for(&state, &session, &body.username, body.password.as_deref(), quota, body.is_admin)
        .await
        .map_err(admin_error)?;
    Ok((
        StatusCode::CREATED,
        Json(Created { username: body.username.trim().to_string(), password, is_admin: body.is_admin }),
    ))
}

#[derive(Serialize)]
pub struct Reset {
    username: String,
    password: String,
}

/// `POST /api/v1/admin/users/{id}/reset-password` — the new password, ONCE.
pub async fn reset_password(
    State(state): State<AppState>,
    ApiAdmin(session): ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
) -> ApiResult<Json<Reset>> {
    let (username, password) = admin::reset_user_password_for(&state, &session, id).await.map_err(admin_error)?;
    Ok(Json(Reset { username, password }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaBody {
    /// Required: `null` is unlimited, absent is a mistake.
    quota: serde_json::Value,
}

#[derive(Serialize)]
pub struct Done {
    pub(super) ok: bool,
}

/// `POST /api/v1/admin/users/{id}/quota` — `{"quota": n | null}`.
pub async fn set_quota(
    State(state): State<AppState>,
    ApiAdmin(session): ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
    ApiJson(body): ApiJson<QuotaBody>,
) -> ApiResult<Json<Done>> {
    let quota = quota_from(&body.quota)?;
    admin::set_quota_for(&state, &session, id, quota).await.map_err(admin_error)?;
    Ok(Json(Done { ok: true }))
}

#[derive(Deserialize)]
pub struct ActiveBody {
    active: bool,
}

/// `POST /api/v1/admin/users/{id}/active` — suspend (signing out every
/// session, in the same transaction) or enable.
pub async fn set_active(
    State(state): State<AppState>,
    ApiAdmin(session): ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
    ApiJson(body): ApiJson<ActiveBody>,
) -> ApiResult<Json<Done>> {
    admin::set_active_for(&state, &session, id, body.active).await.map_err(admin_error)?;
    Ok(Json(Done { ok: true }))
}

#[derive(Serialize)]
pub struct LastBackup {
    at: chrono::DateTime<chrono::Utc>,
    status: String,
    /// Read back after writing. False on an ok backup is "unverified".
    verified: bool,
}

#[derive(Serialize)]
pub struct FleetDb {
    name: String,
    status: String,
    owner: String,
    server_name: String,
    /// `null`: never backed up — the finding, not a blank cell.
    last_backup: Option<LastBackup>,
}

#[derive(Serialize)]
pub struct Fleet {
    databases: Vec<FleetDb>,
}

/// `GET /api/v1/admin/databases` — every database, newest first.
pub async fn databases(State(state): State<AppState>, ApiAdmin(_): ApiAdmin) -> ApiResult<Json<Fleet>> {
    let rows = admin::all_databases(&state.db).await.map_err(|e| {
        tracing::error!("listing databases: {e}");
        ApiError::internal()
    })?;
    let databases = rows
        .into_iter()
        .map(|d| FleetDb {
            last_backup: d.last_backup_at.zip(d.last_backup_status).map(|(at, status)| LastBackup {
                at,
                status,
                verified: d.last_backup_verified.is_some(),
            }),
            name: d.name,
            status: d.status,
            owner: d.owner,
            server_name: d.server_name,
        })
        .collect();
    Ok(Json(Fleet { databases }))
}

#[derive(Deserialize)]
pub struct AuditParams {
    #[serde(default)]
    before: Option<String>,
}

#[derive(Serialize)]
pub struct AuditPage {
    entries: Vec<admin::AuditRow>,
    /// The cursor for the next older page (`?before=`), or null at the start.
    older: Option<i64>,
}

/// `GET /api/v1/admin/audit?before=<id>` — newest first, a page at a time.
pub async fn audit(
    State(state): State<AppState>,
    ApiAdmin(_): ApiAdmin,
    axum::extract::Query(p): axum::extract::Query<AuditParams>,
) -> ApiResult<Json<AuditPage>> {
    let before = match p.before.as_deref() {
        None | Some("") => None,
        Some(raw) => Some(raw.parse::<i64>().map_err(|_| {
            ApiError::new(StatusCode::BAD_REQUEST, "bad_cursor", "That is not a page of the audit log.")
        })?),
    };
    let (entries, older) = admin::audit_page(&state.db, before).await.map_err(|e| {
        tracing::error!("reading the audit log: {e}");
        ApiError::internal()
    })?;
    Ok(Json(AuditPage { entries, older }))
}

#[derive(Serialize)]
pub struct DisabledRoleOut {
    role_name: String,
    /// `null`: the role exists on the server, but no database row names it.
    db_name: Option<String>,
    /// failed_delete | disabled_outside_cryptarch | unknown
    cause: &'static str,
}

/// One server's report, as `ServerReport::verdict` decides it — the same
/// decision, made once (`repair::ServerReport::verdict`).
#[derive(Serialize)]
pub struct ServerLogins {
    server_name: String,
    /// not_checked | partial | not_surveyed | inconclusive | sources_disagree
    /// | clean | findings
    verdict: &'static str,
    /// Why it was not checked or not surveyed.
    detail: Option<String>,
    roles_checked: Option<usize>,
    roles_failed: Option<usize>,
    known_databases: Option<i64>,
    disabled: Vec<DisabledRoleOut>,
    unknown_to_metadata: Vec<String>,
}

#[derive(Serialize)]
pub struct StrandedOut {
    name: String,
    /// `null`: the server could not be asked.
    can_log_in: Option<bool>,
    db_exists: Option<bool>,
    /// False when the delete never changed anything: not offered.
    retryable: bool,
}

#[derive(Serialize)]
pub struct UnreachableAtUpgrade {
    server_name: String,
    detail: String,
}

#[derive(Serialize)]
pub struct Logins {
    summary: crate::repair::ReportSummary,
    /// Inconclusive first.
    servers: Vec<ServerLogins>,
    stranded: Vec<StrandedOut>,
    unreachable_at_upgrade: Vec<UnreachableAtUpgrade>,
}

/// `GET /api/v1/admin/logins` — surveyed live, every server.
pub async fn logins(State(state): State<AppState>, ApiAdmin(_): ApiAdmin) -> Json<Logins> {
    use crate::repair::{DisabledCause, Verdict};
    let report = admin::login_report(&state).await;
    let servers = crate::repair::ordered(&report.reports)
        .into_iter()
        .map(|r| {
            let mut out = ServerLogins {
                server_name: r.server_name.clone(),
                verdict: "",
                detail: None,
                roles_checked: None,
                roles_failed: None,
                known_databases: r.known_databases,
                disabled: r
                    .survey
                    .disabled
                    .iter()
                    .map(|d| DisabledRoleOut {
                        role_name: d.role_name.clone(),
                        db_name: d.db_name.clone(),
                        cause: match d.cause {
                            DisabledCause::FailedDelete => "failed_delete",
                            DisabledCause::DisabledOutsideCryptarch => "disabled_outside_cryptarch",
                            DisabledCause::Unknown => "unknown",
                        },
                    })
                    .collect(),
                unknown_to_metadata: r.survey.unknown_to_metadata.clone(),
            };
            match r.verdict() {
                Verdict::NotChecked { detail } => (out.verdict, out.detail) = ("not_checked", Some(detail.into())),
                Verdict::Partial { roles_checked, roles_failed } => {
                    (out.verdict, out.roles_checked, out.roles_failed) = ("partial", Some(roles_checked), Some(roles_failed))
                }
                Verdict::NotSurveyed { reason } => (out.verdict, out.detail) = ("not_surveyed", Some(reason.into())),
                Verdict::Inconclusive => out.verdict = "inconclusive",
                Verdict::SourcesDisagree { .. } => out.verdict = "sources_disagree",
                Verdict::Clean { roles_checked } => (out.verdict, out.roles_checked) = ("clean", Some(roles_checked)),
                Verdict::Findings { roles_checked } => (out.verdict, out.roles_checked) = ("findings", Some(roles_checked)),
            }
            out
        })
        .collect();
    Json(Logins {
        summary: crate::repair::summarize(&report.reports),
        servers,
        stranded: report
            .stranded
            .iter()
            .map(|s| StrandedOut { name: s.name.clone(), can_log_in: s.can_log_in, db_exists: s.db_exists, retryable: s.retryable() })
            .collect(),
        unreachable_at_upgrade: report
            .unreachable_at_upgrade
            .into_iter()
            .map(|(server_name, detail)| UnreachableAtUpgrade { server_name, detail })
            .collect(),
    })
}

#[derive(Deserialize)]
pub struct RetryBody {
    /// The database's name, typed. Absent is a mismatch like any other.
    #[serde(default)]
    confirm: String,
}

/// `POST /api/v1/admin/logins/{name}/retry-delete` — finish a delete that
/// stopped partway; each refusal says which it is.
pub async fn retry_delete(
    State(state): State<AppState>,
    ApiAdmin(session): ApiAdmin,
    ApiPath(name): ApiPath<String>,
    ApiJson(body): ApiJson<RetryBody>,
) -> ApiResult<Json<Done>> {
    use crate::provision::RetryRefusal;
    admin::retry_delete_for(&state, &session, &name, &body.confirm).await.map_err(|e| match e {
        admin::RetryError::ConfirmMismatch => ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "confirm_mismatch",
            format!("Type {name} exactly to finish the delete."),
        ),
        admin::RetryError::Gone => ApiError::not_found("There is no database by that name any more."),
        admin::RetryError::Refused(RetryRefusal::NoLongerDeleting) => ApiError::new(
            StatusCode::CONFLICT,
            "no_longer_deleting",
            "Nothing to finish — that database is not mid-delete any more: returned to service, or the \
             name now belongs to a new database.",
        ),
        admin::RetryError::Refused(RetryRefusal::AlreadyBeingFinished) => ApiError::new(
            StatusCode::CONFLICT,
            "being_finished",
            "That delete is already being finished. Reload in a moment.",
        ),
        admin::RetryError::Refused(RetryRefusal::NothingWasStarted) => ApiError::new(
            StatusCode::CONFLICT,
            "nothing_started",
            "This delete never changed anything — the database is intact and serving. Not finished.",
        ),
        admin::RetryError::Refused(RetryRefusal::CouldNotCheck(why)) => ApiError::new(
            StatusCode::CONFLICT,
            "uncheckable",
            format!("The server could not be checked, so the delete was not finished: {why}"),
        ),
        admin::RetryError::Failed => ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "retry_failed",
            "Finishing the delete failed — see the server log.",
        ),
    })?;
    Ok(Json(Done { ok: true }))
}

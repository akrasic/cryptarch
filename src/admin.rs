//! Admin surface — the elevated view, gated by the [`AdminUser`] extractor.
//!
//! Where a normal user sees only their own databases (owner-scoped), an admin
//! sees everything: all users (with editable quotas + suspend), all databases
//! across all users, and the global append-only audit log. Managed-server
//! management (the encrypted multi-server registry) is a later task; this slice
//! covers users, databases, and audit.

use uuid::Uuid;

use sqlx::AssertSqlSafe;

use crate::auth::Session;
use crate::web::AppState;

// ---- queries ----------------------------------------------------------------

/// A user as the admin pages see them.
#[derive(sqlx::FromRow, serde::Serialize)]
pub struct AdminUserRow {
    pub id: Uuid,
    pub username: String,
    pub is_admin: bool,
    pub is_active: bool,
    /// NULL = unlimited.
    #[serde(rename = "quota")]
    pub db_quota: Option<i32>,
    /// By the quota enforcer's own predicate (CRYPTARCH-111).
    pub used: i64,
    /// Their password is one an admin set (CRYPTARCH-146).
    pub must_change_password: bool,
}

/// The users query, both pages: `{where}` narrows it (to one id, say).
fn users_sql(filter: &str) -> String {
    format!(
        // The QUOTA predicate, not the admin-totals one (CRYPTARCH-111): this
        // reads "used / quota", so it counts exactly what provision_db counts
        // against the cap — otherwise an admin sees 1/2 for a user whose next
        // provision will be refused at 2/2.
        "SELECT u.id, u.username, u.is_admin, u.is_active, u.db_quota, \
                COUNT(d.id) FILTER (WHERE {}) AS used, \
                u.password_set_by IS NOT NULL AS must_change_password \
         FROM users u LEFT JOIN databases d ON d.owner_id = u.id \
         {filter} GROUP BY u.id ORDER BY u.username",
        crate::status::DbStatus::quota_exclusion_sql()
    )
}

pub async fn list_users(db: &sqlx::PgPool) -> Result<Vec<AdminUserRow>, sqlx::Error> {
    sqlx::query_as::<_, AdminUserRow>(AssertSqlSafe(users_sql(""))).fetch_all(db).await
}

pub async fn find_user(db: &sqlx::PgPool, id: Uuid) -> Result<Option<AdminUserRow>, sqlx::Error> {
    sqlx::query_as::<_, AdminUserRow>(AssertSqlSafe(users_sql("WHERE u.id = $1")))
        .bind(id)
        .fetch_optional(db)
        .await
}

/// One user's databases, newest first.
pub async fn user_databases(db: &sqlx::PgPool, id: Uuid) -> Result<Vec<UserDbRow>, sqlx::Error> {
    sqlx::query_as::<_, UserDbRow>(
        "SELECT d.name, d.status, s.name AS server_name \
         FROM databases d JOIN managed_servers s ON s.id = d.server_id \
         WHERE d.owner_id = $1 ORDER BY d.created_at DESC",
    )
    .bind(id)
    .fetch_all(db)
    .await
}

/// The overview's three counts: users, databases (anything still on a disk,
/// CRYPTARCH-111), servers.
pub async fn overview_counts(db: &sqlx::PgPool) -> (i64, i64, i64) {
    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users").fetch_one(db).await.unwrap_or(0);
    let dbs: i64 = sqlx::query_scalar(AssertSqlSafe(format!(
        "SELECT COUNT(*) FROM databases WHERE {}",
        crate::status::DbStatus::counts_in_admin_totals_sql()
    )))
    .fetch_one(db)
    .await
    .unwrap_or(0);
    let servers: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM managed_servers").fetch_one(db).await.unwrap_or(0);
    (users, dbs, servers)
}

/// Why an admin's change to a user was refused. Nothing changed in any.
#[derive(Debug)]
pub enum AdminError {
    NotFound,
    /// Not on yourself through the admin path: a suspended admin cannot sign
    /// back in to lift it, and your own password lives in the profile.
    OwnAccount,
    BadUsername,
    BadQuota,
    TooShort,
    TooLong,
    UsernameTaken,
    /// The acting admin is no longer an active admin — suspended, say, by
    /// another admin a moment ago (S6a audit P2: two admins could suspend
    /// each other into an empty building).
    NotAnActiveAdmin,
    Internal,
}

impl std::fmt::Display for AdminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            AdminError::NotFound => "That user doesn't exist — they may have been removed since this page loaded.",
            AdminError::OwnAccount => {
                "Not on your own account. Change your password in Profile; and a suspended admin \
                 cannot sign back in to lift it — ask another admin."
            }
            AdminError::BadUsername => "Username: lowercase letter first; lowercase, digits, _ and -; 3-32 chars.",
            AdminError::BadQuota => "Quota must be 0-999 or unlimited.",
            AdminError::TooShort => "Password must be at least 8 characters.",
            AdminError::TooLong => "Password is too long.",
            AdminError::UsernameTaken => "A user by that name already exists.",
            AdminError::NotAnActiveAdmin => "Your account is no longer an active admin — nothing was changed.",
            AdminError::Internal => "Cryptarch could not write the change, so nothing was altered.",
        })
    }
}

fn internal(what: &str) -> impl FnOnce(sqlx::Error) -> AdminError + '_ {
    move |e| {
        tracing::error!("{what}: {e}");
        AdminError::Internal
    }
}

/// Lock the acting admin's row and the target's, in id order (so two admins
/// acting on each other cannot deadlock), and require the actor to still be
/// an active admin. Under these locks, two admins suspending each other
/// serialise: the second finds itself suspended and is refused.
async fn lock_actor_and_target(
    tx: &mut sqlx::PgConnection,
    actor: Uuid,
    target: Uuid,
) -> Result<(), AdminError> {
    let rows: Vec<(Uuid, bool, bool)> = sqlx::query_as(
        "SELECT id, is_active, is_admin FROM users WHERE id = ANY($1) ORDER BY id FOR UPDATE",
    )
    .bind(vec![actor, target])
    .fetch_all(&mut *tx)
    .await
    .map_err(internal("locking the users an admin change touches"))?;
    match rows.iter().find(|(id, ..)| *id == actor) {
        Some((_, true, true)) => {}
        _ => return Err(AdminError::NotAnActiveAdmin),
    }
    if !rows.iter().any(|(id, ..)| *id == target) {
        return Err(AdminError::NotFound);
    }
    Ok(())
}

/// A quota in range, or None for unlimited.
pub fn check_quota(q: Option<i64>) -> Result<Option<i32>, AdminError> {
    match q {
        None => Ok(None),
        Some(n) if (0..=999).contains(&n) => Ok(Some(n as i32)),
        Some(_) => Err(AdminError::BadQuota),
    }
}

/// Create a user; returns the password to show ONCE (generated when none is
/// given). The admin chose or saw it, so it is theirs until the user replaces
/// it (CRYPTARCH-146).
pub async fn create_user_for(
    state: &AppState,
    session: &Session,
    username: &str,
    password: Option<&str>,
    quota: Option<i32>,
    is_admin: bool,
) -> Result<String, AdminError> {
    let username = username.trim();
    if !crate::auth::valid_username(username) {
        return Err(AdminError::BadUsername);
    }
    let supplied = password.map(str::trim).filter(|p| !p.is_empty());
    if supplied.is_some_and(|p| p.len() < 8) {
        return Err(AdminError::TooShort);
    }
    if supplied.is_some_and(|p| p.len() > crate::auth::MAX_PASSWORD_LEN) {
        return Err(AdminError::TooLong);
    }
    let password = supplied.map(String::from).unwrap_or_else(crate::names::generate_password);
    let hash = crate::auth::hash_password_capped(password.clone()).await.map_err(|e| {
        tracing::error!("hashing password for new user: {e}");
        AdminError::Internal
    })?;
    let mut tx = state.db.begin().await.map_err(internal("creating a user"))?;
    let res = sqlx::query(
        "INSERT INTO users (username, password_hash, is_admin, db_quota, password_set_by) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(username)
    .bind(&hash)
    .bind(is_admin)
    .bind(quota)
    // The whole lineage: an admin acting on a password someone else set
    // passes that on (CRYPTARCH-146).
    .bind(session.actor())
    .execute(&mut *tx)
    .await;
    if let Err(e) = res {
        if e.as_database_error().is_some_and(|d| d.is_unique_violation()) {
            return Err(AdminError::UsernameTaken);
        }
        tracing::error!("creating user {username}: {e:#}");
        return Err(AdminError::Internal);
    }
    // In the same transaction: the change and its record, together or not.
    crate::provision::audit_in(&mut tx, &session.actor(), "create_user", Some(username),
        Some(&format!("admin={is_admin} quota={}", quota.map_or("unlimited".into(), |q| q.to_string()))))
        .await
        .map_err(internal("auditing a new user"))?;
    tx.commit().await.map_err(internal("creating a user"))?;
    Ok(password)
}

/// Reset another user's password: a new one (returned to show ONCE), every
/// session of theirs gone, the account gated (CRYPTARCH-146) — in one
/// transaction. A reset is a revocation; if the sessions cannot go, nothing
/// happens and there is no password to show (CRYPTARCH-102 used to hand one
/// over with live sessions behind it).
pub async fn reset_user_password_for(
    state: &AppState,
    session: &Session,
    id: Uuid,
) -> Result<(String, String), AdminError> {
    if id == session.user_id {
        return Err(AdminError::OwnAccount);
    }
    let password = crate::names::generate_password();
    let hash = crate::auth::hash_password_capped(password.clone()).await.map_err(|e| {
        tracing::error!("hashing reset password: {e}");
        AdminError::Internal
    })?;
    let mut tx = state.db.begin().await.map_err(internal("resetting a password"))?;
    lock_actor_and_target(&mut tx, session.user_id, id).await?;
    let target: String = sqlx::query_scalar(
        "UPDATE users SET password_hash = $1, password_set_by = $3 WHERE id = $2 RETURNING username",
    )
    .bind(&hash)
    .bind(id)
    .bind(session.actor())
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal("resetting a password"))?
    .ok_or(AdminError::NotFound)?;
    sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(internal("signing out a reset user"))?;
    crate::provision::audit_in(&mut tx, &session.actor(), "reset_user_password", Some(&target),
        Some("all sessions revoked"))
        .await
        .map_err(internal("auditing a reset"))?;
    tx.commit().await.map_err(internal("resetting a password"))?;
    Ok((target, password))
}

/// Set a user's quota (None = unlimited). A quota for nobody is not a success.
pub async fn set_quota_for(state: &AppState, session: &Session, id: Uuid, quota: Option<i32>) -> Result<(), AdminError> {
    let mut tx = state.db.begin().await.map_err(internal("setting a quota"))?;
    let changed = sqlx::query("UPDATE users SET db_quota = $1 WHERE id = $2")
        .bind(quota)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(internal("setting a quota"))?
        .rows_affected();
    if changed != 1 {
        return Err(AdminError::NotFound);
    }
    crate::provision::audit_in(&mut tx, &session.actor(), "set_quota", Some(&id.to_string()),
        Some(&quota.map_or("unlimited".into(), |q| q.to_string())))
        .await
        .map_err(internal("auditing a quota"))?;
    tx.commit().await.map_err(internal("setting a quota"))?;
    Ok(())
}

/// Suspend (signing out every session, in the same transaction — a
/// suspension that leaves live sessions is not one) or enable a user. Never
/// yourself.
pub async fn set_active_for(state: &AppState, session: &Session, id: Uuid, active: bool) -> Result<(), AdminError> {
    if id == session.user_id {
        return Err(AdminError::OwnAccount);
    }
    let mut tx = state.db.begin().await.map_err(internal("changing account status"))?;
    lock_actor_and_target(&mut tx, session.user_id, id).await?;
    let changed = sqlx::query("UPDATE users SET is_active = $1 WHERE id = $2")
        .bind(active)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(internal("changing account status"))?
        .rows_affected();
    if changed != 1 {
        return Err(AdminError::NotFound);
    }
    if !active {
        // Revokes, not pauses: re-enabling must not resurrect old cookies.
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(internal("signing out a suspended user"))?;
    }
    crate::provision::audit_in(&mut tx, &session.actor(),
        if active { "enable_user" } else { "suspend_user" }, Some(&id.to_string()), None)
        .await
        .map_err(internal("auditing an account status change"))?;
    tx.commit().await.map_err(internal("changing account status"))?;
    Ok(())
}

#[derive(sqlx::FromRow)]
pub struct AdminDbRow {
    pub name: String,
    pub status: String,
    pub owner: String,
    pub server_name: String,
    /// Newest backup of any outcome, so a database whose backups have started
    /// failing does not read as "covered" (CRYPTARCH-65).
    pub last_backup_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_backup_status: Option<String>,
    /// Whether that backup was read back. Carried so this column cannot show a
    /// plain green "ok" for a backup the database's own page calls unverified.
    pub last_backup_verified: Option<chrono::DateTime<chrono::Utc>>,
}

/// Every database, newest first, with its newest backup — THIS database's,
/// by identity (CRYPTARCH-86). Joining on the name, as this once did, showed
/// a database that took a freed name wearing the previous owner's backup.
/// (Backups of deleted databases have their own view: /admin/backups.)
pub async fn all_databases(db: &sqlx::PgPool) -> Result<Vec<AdminDbRow>, sqlx::Error> {
    sqlx::query_as::<_, AdminDbRow>(
        "SELECT d.name, d.status, u.username AS owner, s.name AS server_name, \
                b.created_at AS last_backup_at, b.status AS last_backup_status, \
                b.verified_at AS last_backup_verified \
         FROM databases d \
         JOIN users u ON u.id = d.owner_id \
         JOIN managed_servers s ON s.id = d.server_id \
         LEFT JOIN LATERAL ( \
             SELECT created_at, status, verified_at FROM backups \
             WHERE database_id = d.id ORDER BY created_at DESC LIMIT 1 \
         ) b ON TRUE \
         ORDER BY d.created_at DESC",
    )
    .fetch_all(db)
    .await
}

#[derive(sqlx::FromRow, serde::Serialize)]
pub struct AuditRow {
    pub id: i64,
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub detail: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// One page of the audit log, newest first, older than `before` when given;
/// with the cursor for the next older page, or None at the start of the log.
pub async fn audit_page(db: &sqlx::PgPool, before: Option<i64>) -> Result<(Vec<AuditRow>, Option<i64>), sqlx::Error> {
    // Fetch one extra row: a full page proves nothing about whether older
    // entries exist; the peek row does.
    let mut rows = sqlx::query_as::<_, AuditRow>(
        "SELECT id, actor, action, target, detail, created_at \
         FROM audit_log WHERE ($1::bigint IS NULL OR id < $1) \
         ORDER BY id DESC LIMIT $2",
    )
    .bind(before)
    .bind(AUDIT_PAGE + 1)
    .fetch_all(db)
    .await?;
    let has_older = rows.len() as i64 > AUDIT_PAGE;
    rows.truncate(AUDIT_PAGE as usize);
    let older = has_older.then(|| rows.last().map(|r| r.id)).flatten();
    Ok((rows, older))
}

// ---- overview ---------------------------------------------------------------

// ---- users ------------------------------------------------------------------

// ---- per-user manage page (CRYPTARCH-36) ------------------------------------

#[derive(sqlx::FromRow, serde::Serialize)]
pub struct UserDbRow {
    pub name: String,
    pub status: String,
    pub server_name: String,
}

// ---- create user / reset password (CRYPTARCH-16) ------------------------------

// ---- databases (all) --------------------------------------------------------

// ---- audit ------------------------------------------------------------------

pub const AUDIT_PAGE: i64 = 200;

// ---- rendering helpers ------------------------------------------------------

/// One stranded delete: a database left mid-delete, with the two facts that
/// decide whether finishing it is safe (render-time only; the destructive
/// path re-reads them at action time).
pub struct Stranded {
    pub name: String,
    /// `None`: the server could not be asked (or is not in service). Unknown
    /// is never read as "no" — that rendered "no data left to lose" about a
    /// database nobody had looked at (S6b/c audit P2).
    pub can_log_in: Option<bool>,
    pub db_exists: Option<bool>,
}

impl Stranded {
    /// Offered only when destruction demonstrably began: both facts known,
    /// and the login off (a delete turns it off first). Login on means the
    /// delete never started — or, with the database absent, someone else's
    /// provision in flight under this name. Unknown is not offered.
    pub fn retryable(&self) -> bool {
        self.can_log_in == Some(false) && self.db_exists.is_some()
    }
}

/// Everything the login report shows.
pub struct LoginReport {
    pub reports: Vec<crate::repair::ServerReport>,
    pub stranded: Vec<Stranded>,
    /// (server name, detail): servers the one-time CRYPTARCH-78 repair could
    /// not reach. DISPLAY ONLY (see migration 0016).
    pub unreachable_at_upgrade: Vec<(String, String)>,
}

/// The CRYPTARCH-78 login report, surveyed live, every server concurrently.
pub async fn login_report(state: &AppState) -> LoginReport {
    // Enumerated from METADATA, not from the live registry. A server an admin
    // has disabled is removed from the registry entirely (`unregister` drops
    // it from both maps) while its metadata row, its databases and its roles
    // all remain. Enumerating from the registry would give it no report row at
    // all — and Tier A skips it too, so each tier's silence would be justified
    // by the other's responsibility while a disabled login stayed disabled.
    let servers: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT id, name FROM managed_servers ORDER BY name")
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();

    // Concurrent, not serial. Each survey is bounded by TimeoutEngine, but a
    // serial loop makes the worst case N × that bound — one hanging box would
    // slow the page down on every other server's behalf. They are independent
    // by construction.
    let mut tasks = tokio::task::JoinSet::new();
    for (id, name) in servers {
        let state = state.clone();
        tasks.spawn(async move {
                let known_databases: Option<i64> = sqlx::query_scalar(
                    "SELECT count(*) FROM databases WHERE server_id = $1",
                )
                .bind(id)
                .fetch_one(&state.db)
                .await
                .ok();

                let survey = if state.servers.get(id).is_none() {
                    // Registered, but not in live service. Not a failure, and
                    // therefore nothing else would ever be loud about it.
                    crate::repair::Survey {
                        server_id: id,
                        coverage: crate::repair::SurveyCoverage::NotSurveyed {
                            reason: "This server is disabled, so it was not surveyed.".into(),
                        },
                        disabled: Vec::new(),
                        unknown_to_metadata: Vec::new(),
                    }
                } else {
                    // A survey that fails outright still produces a row, as
                    // Unreachable — a server missing from the list would be
                    // indistinguishable from one with nothing to say.
                    crate::repair::survey_disabled_logins(&state.db, &state.servers, id)
                        .await
                        .unwrap_or_else(|e| crate::repair::Survey {
                            server_id: id,
                            coverage: crate::repair::SurveyCoverage::Unreachable {
                                detail: format!("{e:#}"),
                            },
                            disabled: Vec::new(),
                            unknown_to_metadata: Vec::new(),
                        })
                };
            crate::repair::ServerReport { server_name: name, survey, known_databases }
        });
    }
    let mut reports: Vec<crate::repair::ServerReport> = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        // A panicked survey task must not silently remove a server from the
        // report; it is logged and the server is simply absent from THIS
        // collection, which the count check below would then notice.
        match joined {
            Ok(r) => reports.push(r),
            Err(e) => tracing::error!("login report: a server survey task failed: {e}"),
        }
    }
    // Concurrency reorders; the renderer sorts by coverage, so give it a
    // stable base ordering rather than whatever finished first.
    reports.sort_by(|a, b| a.server_name.cmp(&b.server_name));

    // Servers whose one repair attempt was never spent because they could not
    // be reached at upgrade. Nothing will ever retry them — an admin has to
    // finish the job by hand — so the obligation must outlive the single
    // `warn!` emitted during that boot.
    //
    // DISPLAY ONLY. `0016_repair_78.sql` forbids BRANCHING on these rows;
    // rendering them is the use they exist for.
    // Rows mid-delete, with the two facts that decide whether finishing is
    // safe. Render-time only: the destructive path re-reads them from the
    // server at action time, because this page is read slowly and the
    // maintenance sweep can change the answer while it is on screen.
    let mut stranded: Vec<Stranded> = Vec::new();
    let deleting: Vec<(String, Uuid)> =
        sqlx::query_as("SELECT name, server_id FROM databases WHERE status = 'deleting'")
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();
    for (name, server_id) in deleting {
        // A server out of service still has the row listed — as unknown,
        // never skipped (the report would otherwise not show it at all).
        let Some(engine) = state.servers.get(server_id) else {
            stranded.push(Stranded { name, can_log_in: None, db_exists: None });
            continue;
        };
        let can_log_in = engine
            .login_states(crate::repair::PANEL_OWNED_ROLES)
            .await
            .ok()
            .map(|rs| rs.iter().any(|r| r.role_name == name && r.can_login));
        let db_exists = engine.database_exists(&name).await.ok();
        stranded.push(Stranded { name, can_log_in, db_exists });
    }

    let unreachable_at_upgrade: Vec<(String, String)> = sqlx::query_as(
        "SELECT s.name, r.detail FROM repair_unreachable_78 r \
         JOIN managed_servers s ON s.id = r.server_id ORDER BY s.name",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    LoginReport { reports, stranded, unreachable_at_upgrade }
}

/// Why finishing a stranded delete was refused.
#[derive(Debug)]
pub enum RetryError {
    /// The typed name did not match.
    ConfirmMismatch,
    /// No database by that name any more.
    Gone,
    /// Re-checked at action time and found unsafe or moot.
    Refused(crate::provision::RetryRefusal),
    Failed,
}

/// Finish a delete that stopped partway. Typed confirmation, like delete; the
/// server is re-checked inside `provision::retry_delete`, because the report
/// is read slowly and the maintenance sweep can change the answer meanwhile.
pub async fn retry_delete_for(state: &AppState, session: &Session, name: &str, confirm: &str) -> Result<(), RetryError> {
    // Trimmed, as delete's is: the dialog arms on the trimmed name, so a
    // stray space must not arm the button and then be refused here.
    if confirm.trim() != name {
        return Err(RetryError::ConfirmMismatch);
    }
    let lookup = match crate::provision::find_db(&state.db, name).await {
        Ok(Some(l)) => l,
        Ok(None) => return Err(RetryError::Gone),
        Err(_) => return Err(RetryError::Failed),
    };
    match crate::provision::retry_delete(&state.db, &state.servers, &lookup, name, &session.actor()).await {
        Ok(Ok(())) => {
            // Ends the way a delete does (web::delete_request): the edge stops
            // admitting it, and anything still connected is evicted.
            if let Err(e) = crate::acl::sync_edge(&state.db, &state.crypto, lookup.server_id).await {
                tracing::warn!("finished deleting '{name}', but the edge sync failed: {e:#}");
            }
            crate::acl::kill_db_sessions(&state.db, &state.crypto, lookup.server_id, name).await;
            Ok(())
        }
        Ok(Err(why)) => Err(RetryError::Refused(why)),
        Err(e) => {
            tracing::error!("retry delete of '{name}' failed: {e}");
            Err(RetryError::Failed)
        }
    }
}


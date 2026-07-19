//! Admin surface — the elevated view, gated by the [`AdminUser`] extractor.
//!
//! Where a normal user sees only their own databases (owner-scoped), an admin
//! sees everything: all users (with editable quotas + suspend), all databases
//! across all users, and the global append-only audit log. Managed-server
//! management (the encrypted multi-server registry) is a later task; this slice
//! covers users, databases, and audit.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::{AdminUser, Session};
use crate::web::{shell, status_badge, AppState};

// ---- queries ----------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct AdminUserRow {
    id: Uuid,
    username: String,
    is_admin: bool,
    is_active: bool,
    /// NULL = unlimited.
    db_quota: Option<i32>,
    used: i64,
}

/// The quota dropdown, shared by the users table and the add-user form.
/// `current`: Some(n) or None (unlimited) marks the selected option.
/// `for_whom` labels the control for AT — in a table there are N of these.
fn quota_select(current: Option<Option<i32>>, for_whom: &str) -> Markup {
    let is = |v: Option<i32>| current == Some(v);
    html! {
        select name="quota" aria-label={ "Quota for " (for_whom) } {
            option value="2" selected[is(Some(2))] { "2" }
            option value="5" selected[is(Some(5)) || current.is_none()] { "5" }
            option value="10" selected[is(Some(10))] { "10" }
            option value="unlimited" selected[is(None)] { "unlimited" }
            // Preserve a legacy/custom value so an admin opening the form
            // doesn't silently reassign it to a preset.
            @if let Some(Some(q)) = current {
                @if ![2, 5, 10].contains(&q) {
                    option value=(q) selected { (q) " (current)" }
                }
            }
        }
    }
}

/// Parse the dropdown value: "unlimited" → None, else a bounded integer.
fn parse_quota(raw: &str) -> Result<Option<i32>, ()> {
    if raw == "unlimited" {
        return Ok(None);
    }
    match raw.trim().parse::<i32>() {
        Ok(q) if (0..=999).contains(&q) => Ok(Some(q)),
        _ => Err(()),
    }
}

#[derive(sqlx::FromRow)]
struct AdminDbRow {
    name: String,
    status: String,
    owner: String,
    server_name: String,
}

#[derive(sqlx::FromRow)]
struct AuditRow {
    id: i64,
    actor: String,
    action: String,
    target: Option<String>,
    detail: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

// ---- overview ---------------------------------------------------------------

pub async fn overview(State(state): State<AppState>, AdminUser(session): AdminUser) -> Response {
    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);
    let db_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM databases")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);
    let server_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM managed_servers")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    shell(
        "Admin",
        &session,
        html! {
            (admin_nav("overview"))
            h1 { "Admin" }
            div.cards {
                a.card href="/admin/users" { span.n { (user_count) } span.l { "users" } }
                a.card href="/admin/databases" { span.n { (db_count) } span.l { "databases" } }
                a.card href="/admin/servers" { span.n { (server_count) } span.l { "servers" } }
            }
            p { a.link href="/dashboard" { "← Back to your dashboard" } }
        },
    )
    .into_response()
}

// ---- users ------------------------------------------------------------------

pub async fn users(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    axum::extract::Query(flash): axum::extract::Query<crate::web::FlashQuery>,
) -> Response {
    let rows = sqlx::query_as::<_, AdminUserRow>(
        "SELECT u.id, u.username, u.is_admin, u.is_active, u.db_quota, \
                COUNT(d.id) FILTER (WHERE d.status = 'active') AS used \
         FROM users u LEFT JOIN databases d ON d.owner_id = u.id \
         GROUP BY u.id ORDER BY u.username",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    shell(
        "Users · Admin",
        &session,
        html! {
            (admin_nav("users"))
            h1 { "Users" }
            (crate::web::flash_banner(flash.msg()))
            div.table-scroll {
                table.dbs {
                    thead { tr {
                        th { "User" } th { "Role" } th { "Databases" } th { "Status" } th { "" }
                    } }
                    tbody {
                        @for u in &rows {
                            tr {
                                td {
                                    a href={ "/admin/users/" (u.id) } { code { (u.username) } }
                                    @if u.username == session.username { " " span.muted { "(you)" } }
                                }
                                td { @if u.is_admin { "admin" } @else { "user" } }
                                td.tnum {
                                    (u.used) " / "
                                    @match u.db_quota { Some(q) => { (q) }, None => { "∞" } }
                                }
                                td { (status_badge(if u.is_active { "active" } else { "suspended" })) }
                                td {
                                    a.link href={ "/admin/users/" (u.id) }
                                        aria-label={ "Manage user " (u.username) } { "manage" }
                                }
                            }
                        }
                    }
                }
            }
            p { a.button href="/admin/users/new" { "+ Add user" } }
        },
    )
    .into_response()
}

// ---- per-user manage page (CRYPTARCH-36) ------------------------------------

#[derive(sqlx::FromRow)]
struct UserDbRow {
    name: String,
    status: String,
    server_name: String,
}

pub async fn user_detail(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    Path(id): Path<Uuid>,
    axum::extract::Query(flash): axum::extract::Query<crate::web::FlashQuery>,
) -> Response {
    let user = sqlx::query_as::<_, AdminUserRow>(
        "SELECT u.id, u.username, u.is_admin, u.is_active, u.db_quota, \
                COUNT(d.id) FILTER (WHERE d.status = 'active') AS used \
         FROM users u LEFT JOIN databases d ON d.owner_id = u.id \
         WHERE u.id = $1 GROUP BY u.id",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();
    let Some(u) = user else {
        return crate::web::error_page(&session, axum::http::StatusCode::NOT_FOUND,
            "No such user", "That user doesn't exist (maybe deleted in another tab).");
    };
    let dbs = sqlx::query_as::<_, UserDbRow>(
        "SELECT d.name, d.status, s.name AS server_name \
         FROM databases d JOIN managed_servers s ON s.id = d.server_id \
         WHERE d.owner_id = $1 ORDER BY d.created_at DESC",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    let is_self = u.id == session.user_id;

    shell(
        &format!("{} · Admin", u.username),
        &session,
        html! {
            (admin_nav("users"))
            p { a.link href="/admin/users" { "← Users" } }
            h1 { code { (u.username) } @if is_self { " " span.muted { "· you" } } }
            (crate::web::flash_banner(flash.msg()))
            dl.creds {
                dt { "Role" } dd { @if u.is_admin { "admin" } @else { "user" } }
                dt { "Status" } dd { (status_badge(if u.is_active { "active" } else { "suspended" })) }
                dt { "Databases" } dd {
                    (u.used) " of "
                    @match u.db_quota { Some(q) => { (q) }, None => { "unlimited" } }
                    " in use"
                }
            }

            h2 { "Quota" }
            form method="post" action={ "/admin/users/" (u.id) "/quota" } .scard {
                (crate::web::srow("Database quota",
                    "How many databases this user may hold at once. Lowering it never \
                     deletes anything — it only blocks new provisioning past the cap.",
                    quota_select(Some(u.db_quota), &u.username)))
                (crate::web::sfoot(Some("Takes effect on their next provision attempt."), "Save"))
            }

            h2 { "Access" }
            @if is_self {
                p.muted { "That's you. Your own password and sessions live in "
                          a.link href="/profile" { "Profile" } " — the admin path is for others, \
                          so you can't suspend yourself out of the building." }
            } @else {
                div.scard {
                    (crate::web::srow(
                        if u.is_active { "Suspend account" } else { "Enable account" },
                        if u.is_active {
                            "Blocks login and signs out every session immediately. Their \
                             databases keep running — suspend those separately if needed."
                        } else {
                            "Restores login. Their databases are untouched by this."
                        },
                        html! {
                            form method="post" action={ "/admin/users/" (u.id) "/active" } .inline
                                hx-confirm=[u.is_active.then(|| format!(
                                    "Suspend {}? Their sessions are signed out immediately.", u.username))] {
                                input type="hidden" name="active" value=(!u.is_active);
                                @if u.is_active { button.danger type="submit" { "Suspend" } }
                                @else { button type="submit" { "Enable" } }
                            }
                        }))
                    (crate::web::srow("Reset password",
                        "Generates a new password, shown once. Every session they have \
                         is signed out.",
                        html! {
                            form method="post" action={ "/admin/users/" (u.id) "/reset-password" } .inline
                                hx-confirm={ "Reset " (u.username) "'s password? All their sessions are signed out." } {
                                button type="submit" { "Reset password" }
                            }
                        }))
                }
            }

            h2 { "Databases" }
            @if dbs.is_empty() {
                p.muted { "None provisioned." }
            } @else {
                div.table-scroll {
                    table.dbs {
                        thead { tr { th { "Database" } th { "Server" } th { "Status" } } }
                        tbody {
                            @for d in &dbs {
                                tr {
                                    td { a href={ "/db/" (d.name) } { code { (d.name) } } }
                                    td { (d.server_name) }
                                    td { (status_badge(&d.status)) }
                                }
                            }
                        }
                    }
                }
            }
        },
    )
    .into_response()
}

// ---- create user / reset password (CRYPTARCH-16) ------------------------------

#[derive(Deserialize)]
pub struct NewUserInput {
    username: String,
    /// Empty = generate one (shown once, same show-once contract as db creds).
    password: Option<String>,
    quota: String,
    is_admin: Option<String>,
}

pub async fn new_user_form(State(_): State<AppState>, AdminUser(session): AdminUser) -> Markup {
    new_user_page(&session, None)
}

fn new_user_page(session: &Session, error: Option<&str>) -> Markup {
    shell(
        "Add user · Admin",
        session,
        html! {
            (admin_nav("users"))
            p { a.link href="/admin/users" { "← Users" } }
            h1 { "Add user" }
            @if let Some(msg) = error { p.error role="alert" { (msg) } }
            form method="post" action="/admin/users" .scard {
                (crate::web::srow("Username",
                    "Lowercase letter first; lowercase, digits, _ and -; 3-32 characters.",
                    html! { input type="text" name="username" placeholder="alice" autocomplete="off" required; }))
                (crate::web::srow("Password",
                    "Leave empty to generate a strong one — shown once on the next screen.",
                    html! { input type="text" name="password" autocomplete="off" placeholder="generated if empty"; }))
                (crate::web::srow("Database quota",
                    "How many databases this user may hold at once.",
                    quota_select(None, "the new user")))
                (crate::web::srow("Admin",
                    "Admins manage users, quotas, and servers — grant sparingly.",
                    html! {
                        select name="is_admin" {
                            option value="" selected { "no" }
                            option value="1" { "yes" }
                        }
                    }))
                div.sfoot {
                    a.link href="/admin/users" { "Cancel" }
                    button.primary type="submit" { "Create user" }
                }
            }
        },
    )
}

pub async fn create_user(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    Form(input): Form<NewUserInput>,
) -> Response {
    let username = input.username.trim();
    if !crate::auth::valid_username(username) {
        return new_user_page(&session,
            Some("Username: lowercase letter first; lowercase, digits, _ and -; 3-32 chars."))
            .into_response();
    }
    let Ok(quota) = parse_quota(&input.quota) else {
        return new_user_page(&session, Some("Quota must be 0-999 or unlimited.")).into_response();
    };
    let supplied = input.password.as_deref().map(str::trim).filter(|p| !p.is_empty());
    if let Some(p) = supplied {
        if p.len() < 8 {
            return new_user_page(&session, Some("Password must be at least 8 characters.")).into_response();
        }
    }
    let password = supplied.map(String::from).unwrap_or_else(crate::names::generate_password);
    let hash = match crate::auth::hash_password(&password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("hashing password for new user: {e}");
            return new_user_page(&session, Some("Internal error.")).into_response();
        }
    };
    let is_admin = input.is_admin.as_deref() == Some("1");
    let res = sqlx::query(
        "INSERT INTO users (username, password_hash, is_admin, db_quota) VALUES ($1, $2, $3, $4)",
    )
    .bind(username)
    .bind(&hash)
    .bind(is_admin)
    .bind(quota)
    .execute(&state.db)
    .await;
    if let Err(e) = res {
        let msg = if e.as_database_error().is_some_and(|d| d.is_unique_violation()) {
            format!("User '{username}' already exists.")
        } else {
            tracing::error!("creating user {username}: {e:#}");
            "Saving failed.".into()
        };
        return new_user_page(&session, Some(&msg)).into_response();
    }
    crate::provision::audit(&state.db, &session.username, "create_user", Some(username),
                            Some(&format!("admin={is_admin} quota={}",
                                          quota.map_or("unlimited".into(), |q: i32| q.to_string()))))
        .await;
    crate::web::no_store(shell(
        "User created · Admin",
        &session,
        html! {
            (admin_nav("users"))
            h1 { "User created" }
            p { strong { "Save this now" } " — the password is shown once and stored only as a hash." }
            dl.creds {
                dt { "Username" } dd { code { (username) }
                    button.copy type="button" data-copy=(username) aria-label="Copy username" { "copy" } }
                dt { "Password" } dd { code { (password) }
                    button.copy type="button" data-copy=(password) aria-label="Copy password" { "copy" } }
                dt { "Role" } dd { @if is_admin { "admin" } @else { "user" } }
            }
            p { a.button href="/admin/users" { "Back to users" } }
        },
    ))
}

pub async fn reset_user_password(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    Path(id): Path<Uuid>,
) -> Response {
    // Same self-guard as set_active: resetting your own password via this
    // admin path would kill your own session mid-flight. Use /profile.
    if id == session.user_id {
        return Redirect::to("/admin/users").into_response();
    }
    let target: Option<String> = sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
    let Some(target) = target else {
        return crate::web::error_page(&session, axum::http::StatusCode::NOT_FOUND,
            "No such user", "That user doesn't exist (maybe deleted in another tab).");
    };
    let password = crate::names::generate_password();
    let hash = match crate::auth::hash_password(&password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("hashing reset password: {e}");
            return crate::web::error_page(&session, axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong", "Generating the new password failed — nothing was changed.");
        }
    };
    if let Err(e) = sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
        .bind(&hash)
        .bind(id)
        .execute(&state.db)
        .await
    {
        tracing::error!("resetting password for {target}: {e}");
        return crate::web::error_page(&session, axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Something went wrong", "Saving the new password failed — the old one still works.");
    }
    // Every session of that user dies — a reset is a revocation.
    state.sessions.remove_all_for_user(id).await;
    crate::provision::audit(&state.db, &session.username, "reset_user_password", Some(&target),
                            Some("all sessions revoked"))
        .await;
    crate::web::no_store(shell(
        "Password reset · Admin",
        &session,
        html! {
            (admin_nav("users"))
            h1 { "Password reset" }
            p { "New password for " code { (target) } " — " strong { "shown once" }
                ". All their sessions were signed out." }
            dl.creds {
                dt { "Username" } dd { code { (target) } }
                dt { "Password" } dd { code { (password) }
                    button.copy type="button" data-copy=(password) aria-label="Copy password" { "copy" } }
            }
            p { a.button href={ "/admin/users/" (id) } { "Back to " (target) } }
        },
    ))
}

#[derive(Deserialize)]
pub struct QuotaInput {
    quota: String,
}

pub async fn set_quota(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    Path(id): Path<Uuid>,
    Form(input): Form<QuotaInput>,
) -> Response {
    let Ok(quota) = parse_quota(&input.quota) else {
        // Only reachable by bypassing the dropdown — a terse styled page is enough.
        return crate::web::error_page(&session, axum::http::StatusCode::BAD_REQUEST,
            "Invalid quota", "Quota must be 0-999 or unlimited.");
    };
    let _ = sqlx::query("UPDATE users SET db_quota = $1 WHERE id = $2")
        .bind(quota)
        .bind(id)
        .execute(&state.db)
        .await;
    crate::provision::audit(
        &state.db,
        &session.username,
        "set_quota",
        Some(&id.to_string()),
        Some(&quota.map_or("unlimited".into(), |q| q.to_string())),
    )
    .await;
    Redirect::to(&format!("/admin/users/{id}?ok=quota_set")).into_response()
}

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
    // Guard: never let an admin suspend themselves out of access.
    if id == session.user_id {
        return Redirect::to("/admin/users").into_response();
    }
    let _ = sqlx::query("UPDATE users SET is_active = $1 WHERE id = $2")
        .bind(input.active)
        .bind(id)
        .execute(&state.db)
        .await;
    if !input.active {
        // Suspension revokes, not just pauses: without this, re-enabling the
        // user would resurrect every pre-suspension cookie.
        let _ = sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(id)
            .execute(&state.db)
            .await;
    }
    crate::provision::audit(
        &state.db,
        &session.username,
        if input.active { "enable_user" } else { "suspend_user" },
        Some(&id.to_string()),
        None,
    )
    .await;
    let ok = if input.active { "user_enabled" } else { "user_suspended" };
    Redirect::to(&format!("/admin/users/{id}?ok={ok}")).into_response()
}

// ---- databases (all) --------------------------------------------------------

pub async fn databases(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    axum::extract::Query(flash): axum::extract::Query<crate::web::FlashQuery>,
) -> Response {
    let rows = sqlx::query_as::<_, AdminDbRow>(
        "SELECT d.name, d.status, u.username AS owner, s.name AS server_name \
         FROM databases d \
         JOIN users u ON u.id = d.owner_id \
         JOIN managed_servers s ON s.id = d.server_id \
         ORDER BY d.created_at DESC",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    shell(
        "All databases · Admin",
        &session,
        html! {
            (admin_nav("databases"))
            h1 { "All databases" }
            (crate::web::flash_banner(flash.msg()))
            @if rows.is_empty() {
                p.muted { "No databases provisioned yet." }
            } @else {
                div.table-scroll {
                    table.dbs {
                        thead { tr { th { "Name" } th { "Owner" } th { "Server" } th { "Status" } th { "" } } }
                        tbody {
                            @for d in &rows {
                                tr {
                                    td { a href={ "/db/" (d.name) } { code { (d.name) } } }
                                    td { (d.owner) }
                                    td { (d.server_name) }
                                    td { (status_badge(&d.status)) }
                                    td {
                                        @if d.status == "active" {
                                            (action_button(&d.name, "suspend", "suspend",
                                                Some(format!("Suspend {}? Live connections will be evicted.", d.name))))
                                        } @else {
                                            (action_button(&d.name, "resume", "resume", None))
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    )
    .into_response()
}

// ---- audit ------------------------------------------------------------------

/// Keyset pagination: `?before=<id>` walks toward older entries. Kept as a
/// String and parsed leniently — a mangled link must not fall through to
/// axum's bare text 400, it should just show the newest page.
#[derive(Deserialize, Default)]
pub struct AuditQuery {
    before: Option<String>,
}

const AUDIT_PAGE: i64 = 200;

pub async fn audit_log(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    axum::extract::Query(q): axum::extract::Query<AuditQuery>,
) -> Response {
    let before: Option<i64> = q.before.as_deref().and_then(|s| s.parse().ok());
    // Fetch one extra row: a full page proves nothing about whether older
    // entries exist; the peek row does.
    let mut rows = sqlx::query_as::<_, AuditRow>(
        "SELECT id, actor, action, target, detail, created_at \
         FROM audit_log WHERE ($1::bigint IS NULL OR id < $1) \
         ORDER BY id DESC LIMIT $2",
    )
    .bind(before)
    .bind(AUDIT_PAGE + 1)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    let has_older = rows.len() as i64 > AUDIT_PAGE;
    rows.truncate(AUDIT_PAGE as usize);
    let older_cursor = has_older.then(|| rows.last().map(|r| r.id)).flatten();

    shell(
        "Audit · Admin",
        &session,
        html! {
            (admin_nav("audit"))
            h1 { "Audit log" }
            p.muted {
                "Append-only, newest first, " (AUDIT_PAGE) " per page."
                @if before.is_some() { " Showing older entries." }
            }
            @if rows.is_empty() {
                p.muted { "Nothing older than this point — you've reached the start of the log." }
            }
            div.table-scroll {
                table.dbs {
                    thead { tr { th { "When (UTC)" } th { "Actor" } th { "Action" } th { "Target" } th { "Detail" } } }
                    tbody {
                        @for a in &rows {
                            tr {
                                td.tnum { (a.created_at.format("%Y-%m-%d %H:%M:%S").to_string()) }
                                td { (a.actor) }
                                td { code { (a.action) } }
                                td { @if let Some(t) = &a.target { (t) } }
                                td.muted { @if let Some(d) = &a.detail { (d) } }
                            }
                        }
                    }
                }
            }
            div.actions {
                @if before.is_some() {
                    a.link href="/admin/audit" { "← Newest" }
                }
                @if let Some(cursor) = older_cursor {
                    a.link href={ "/admin/audit?before=" (cursor) } { "Older →" }
                }
            }
        },
    )
    .into_response()
}

// ---- rendering helpers ------------------------------------------------------

/// Server context for the sidebar: when set, the sidebar grows a group for
/// that server (section anchors + settings link) — CRYPTARCH-35.
pub(crate) struct ServerNavCtx {
    pub id: uuid::Uuid,
    pub name: String,
    /// "detail" | "settings" — which server page is showing.
    pub here: &'static str,
}

/// Admin sidebar; `here` highlights the current section. Rendered as a
/// direct child of `main.wrap`, which the CSS turns into a two-column
/// console layout (`main.wrap:has(> nav.sidenav)`).
pub(crate) fn admin_nav(here: &str) -> Markup {
    admin_sidebar(here, None)
}

pub(crate) fn admin_sidebar(here: &str, server: Option<&ServerNavCtx>) -> Markup {
    html! {
        nav.sidenav aria-label="Admin sections" {
            div.navgroup {
                span.navlabel { "Portal" }
                a href="/admin" .active[here == "overview"] { "Overview" }
            }
            div.navgroup {
                span.navlabel { "Access" }
                a href="/admin/users" .active[here == "users"] { "Users" }
                a href="/admin/audit" .active[here == "audit"] { "Audit" }
            }
            div.navgroup {
                span.navlabel { "Fleet" }
                a href="/admin/databases" .active[here == "databases"] { "Databases" }
                a href="/admin/servers" .active[here == "servers"] { "Servers" }
            }
            @if let Some(srv) = server {
                div.navgroup {
                    span.navlabel { code { (srv.name) } }
                    a href={ "/admin/servers/" (srv.id) "#dashboard" } .active[srv.here == "detail"] { "Dashboard" }
                    a href={ "/admin/servers/" (srv.id) "#edge" } { "Edge health" }
                    a href={ "/admin/servers/" (srv.id) "#pools" } { "Pool overrides" }
                    a href={ "/admin/servers/" (srv.id) "#sources" } { "Named sources" }
                    a href={ "/admin/servers/" (srv.id) "#listeners" } { "Listeners" }
                    a href={ "/admin/servers/" (srv.id) "/settings" } .active[srv.here == "settings"] { "Settings" }
                }
            }
        }
    }
}

/// A small POST-form button for a db lifecycle action (admin acts on any db).
/// `confirm`: optional hx-confirm prompt for destructive verbs.
fn action_button(name: &str, verb: &str, label: &str, confirm: Option<String>) -> Markup {
    html! {
        form method="post" action={ "/db/" (name) "/" (verb) } .inline hx-confirm=[confirm] {
            button.link type="submit" aria-label={ (label) " database " (name) } { (label) }
        }
    }
}

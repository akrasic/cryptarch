//! HTTP surface. v0.1: login, logout, a protected dashboard, health. The
//! provisioning flow (CRYPTARCH-3) hangs off the dashboard next.

use axum::extract::State;
use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Router};
use tower_http::set_header::SetResponseHeaderLayer;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use maud::{html, Markup, DOCTYPE};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::admin;
use crate::auth::{self, CurrentUser, Session, SessionStore, SESSION_COOKIE};
use crate::provision::{self, ProvisionError};
use crate::servers::ServerRegistry;

/// In-memory per-username login backoff. 5 failures in a 5-minute window
/// throttle further attempts (even with the correct password) until the
/// window expires. Memory-only by design: a restart clears it, which is
/// fine — Argon2 already rate-limits online guessing; this exists to make
/// sustained credential-stuffing loud (audited) and slow.
#[derive(Clone, Default)]
pub struct LoginThrottle(
    std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, (u32, std::time::Instant)>>>,
);

const THROTTLE_MAX_FAILURES: u32 = 5;
const THROTTLE_WINDOW: std::time::Duration = std::time::Duration::from_secs(300);

impl LoginThrottle {
    pub fn is_throttled(&self, user: &str) -> bool {
        let mut map = self.0.lock().unwrap();
        match map.get(user) {
            Some((n, since)) if *n >= THROTTLE_MAX_FAILURES => {
                if since.elapsed() > THROTTLE_WINDOW {
                    map.remove(user);
                    false
                } else {
                    true
                }
            }
            _ => false,
        }
    }

    /// Record one failure; returns the count now on record.
    pub fn record_failure(&self, user: &str) -> u32 {
        let mut map = self.0.lock().unwrap();
        let entry = map.entry(user.to_string()).or_insert((0, std::time::Instant::now()));
        if entry.1.elapsed() > THROTTLE_WINDOW {
            *entry = (0, std::time::Instant::now());
        }
        entry.0 += 1;
        entry.0
    }

    pub fn clear(&self, user: &str) {
        self.0.lock().unwrap().remove(user);
    }
}

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub sessions: SessionStore,
    pub servers: ServerRegistry,
    pub crypto: crate::crypto::Crypto,
    pub secure_cookies: bool,
    pub login_throttle: LoginThrottle,
    /// Mirrors CRYPTARCH_ALLOW_SUPERUSER_ADMIN. Runtime re-registration
    /// (settings save, enable) must apply the same role gate as startup —
    /// hardcoding `false` there meant a dev settings-save silently
    /// unregistered the seed server until the next restart.
    pub allow_superuser: bool,
    /// Latest background health per server (CRYPTARCH-43); the loop writes,
    /// pages read. Default (empty) simply renders as "no data yet".
    pub health: crate::health::HealthRegistry,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/login", get(login_form).post(login_submit))
        .route("/logout", post(logout))
        .route("/dashboard", get(dashboard))
        .route("/provision", get(provision_form).post(provision_submit))
        .route("/db/:name", get(db_detail))
        .route("/db/:name/acl", post(acl_add))
        .route("/db/:name/acl/:entry_id/remove", post(acl_remove))
        .route("/db/:name/reset", post(db_reset))
        .route("/db/:name/suspend", post(db_suspend))
        .route("/db/:name/resume", post(db_resume))
        .route("/db/:name/delete", post(db_delete))
        .route("/profile", get(crate::profile::page))
        .route("/profile/password", post(crate::profile::change_password))
        .route("/profile/sessions/revoke-others", post(crate::profile::revoke_others))
        .route("/admin", get(admin::overview))
        .route("/admin/users", get(admin::users).post(admin::create_user))
        .route("/admin/users/new", get(admin::new_user_form))
        .route("/admin/users/:id", get(admin::user_detail))
        .route("/admin/users/:id/reset-password", post(admin::reset_user_password))
        .route("/admin/users/:id/quota", post(admin::set_quota))
        .route("/admin/users/:id/active", post(admin::set_active))
        .route("/admin/databases", get(admin::databases))
        .route("/admin/servers", get(crate::admin_servers::list).post(crate::admin_servers::create))
        .route("/admin/servers/new", get(crate::admin_servers::new_form))
        .route("/admin/servers/:id", get(crate::admin_servers::detail))
        .route("/admin/servers/:id/active", post(crate::admin_servers::set_active))
        .route("/admin/servers/:id/test", post(crate::admin_servers::test))
        .route("/admin/servers/:id/init", post(crate::admin_servers::init))
        .route("/admin/servers/:id/sync", post(crate::admin_servers::sync))
        .route("/admin/servers/:id/settings", get(crate::admin_servers::settings))
        .route("/admin/servers/:id/settings/address", post(crate::admin_servers::update_address))
        .route("/admin/servers/:id/settings/pooling", post(crate::admin_servers::update_pooling))
        .route("/admin/servers/:id/settings/edge", post(crate::admin_servers::update_edge))
        .route("/admin/servers/:id/settings/credentials", post(crate::admin_servers::update_credentials))
        .route("/admin/servers/:id/db/:db_id/knobs", post(crate::admin_servers::db_knobs))
        .route("/admin/servers/:id/sources", post(crate::admin_servers::source_add))
        .route("/admin/servers/:id/sources/:source_id/remove", post(crate::admin_servers::source_remove))
        .route("/admin/servers/:id/listeners", post(crate::admin_servers::listener_add))
        .route("/admin/servers/:id/listeners/:listener_id/remove", post(crate::admin_servers::listener_remove))
        .route("/admin/audit", get(admin::audit_log))
        .route("/static/app.css", get(asset_css))
        .route("/static/app.js", get(asset_js))
        .route("/static/htmx.min.js", get(asset_htmx))
        .route("/static/favicon.svg", get(asset_favicon))
        .route("/static/fonts/fraunces-var.woff2", get(asset_font_fraunces))
        .route("/static/fonts/manrope-var.woff2", get(asset_font_manrope))
        .route("/healthz", get(health))
        .fallback(not_found)
        // CSRF: cross-site POSTs are refused by Origin/Referer validation.
        // Browsers always attach Origin to cross-site form posts; a mismatch
        // with Host is an attack, full stop. Requests with NEITHER header
        // (curl, monitors) pass — they aren't riding a victim's cookies.
        .layer(axum::middleware::from_fn(origin_guard))
        // Strict CSP: everything is same-origin static files — no inline
        // styles or scripts anywhere, so no unsafe-inline needed.
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self'; style-src 'self'; \
                 img-src 'self'; frame-ancestors 'none'; form-action 'self'; \
                 base-uri 'none'",
            ),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .with_state(state)
}

// Assets are compiled into the binary — the deploy stays a single file.
async fn asset_css() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "max-age=300"),
        ],
        include_str!("../../assets/app.css"),
    )
}

async fn asset_js() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "max-age=300"),
        ],
        include_str!("../../assets/app.js"),
    )
}

// Vendored htmx 2.0.6 — CSP is 'self'-only, so no CDN. Immutable-ish: bump
// the cache when the vendored file is upgraded.
async fn asset_htmx() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "max-age=86400"),
        ],
        include_str!("../../assets/htmx.min.js"),
    )
}

// Vendored variable webfonts (latin subsets), compiled in like every other
// asset. Fraunces carries the brand voice, Manrope the UI.
async fn asset_font_fraunces() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "font/woff2"),
            (header::CACHE_CONTROL, "max-age=604800"),
        ],
        include_bytes!("../../assets/fonts/fraunces-var.woff2").as_slice(),
    )
}

async fn asset_font_manrope() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "font/woff2"),
            (header::CACHE_CONTROL, "max-age=604800"),
        ],
        include_bytes!("../../assets/fonts/manrope-var.woff2").as_slice(),
    )
}

async fn asset_favicon() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/svg+xml"),
            (header::CACHE_CONTROL, "max-age=86400"),
        ],
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><rect x="4.6" y="4.6" width="6.8" height="6.8" fill="#c2924f" transform="rotate(45 8 8)"/></svg>"##,
    )
}

/// Human byte size: "18.5 MB", "3.2 GB", "412 kB", "97 B". One decimal from
/// kB up, none for raw bytes.
pub fn human_bytes(bytes: i64) -> String {
    let b = bytes.max(0) as f64;
    const UNITS: [&str; 5] = ["kB", "MB", "GB", "TB", "PB"];
    if b < 1024.0 {
        return format!("{bytes} B");
    }
    let mut v = b / 1024.0;
    for unit in UNITS {
        if v < 1024.0 {
            return format!("{v:.1} {unit}");
        }
        v /= 1024.0;
    }
    format!("{v:.1} EB")
}

/// Human duration for uptimes: "3d 4h", "5h 12m", "42m", "30s".
pub fn human_duration(secs: i64) -> String {
    let s = secs.max(0);
    let (d, h, m) = (s / 86400, (s % 86400) / 3600, (s % 3600) / 60);
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m")
    } else {
        format!("{s}s")
    }
}

/// The host part ("host[:port]") of an Origin/Referer value like
/// `https://host:port/path`. `None` for unparseable values (including the
/// literal "null" Origin) — which callers treat as a mismatch.
fn url_host(value: &str) -> Option<&str> {
    let rest = value.split_once("://")?.1;
    let host = rest.split(['/', '?', '#']).next()?;
    if host.is_empty() { None } else { Some(host) }
}

/// Reject state-changing cross-site requests: on POST, when Origin (or,
/// failing that, Referer) is present, its host must equal the Host header.
async fn origin_guard(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    if req.method() == axum::http::Method::POST {
        let headers = req.headers();
        let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
        let claimed = headers
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .or_else(|| headers.get(header::REFERER).and_then(|v| v.to_str().ok()));
        if let Some(claimed) = claimed {
            let matches = match (host, url_host(claimed)) {
                (Some(h), Some(c)) => h.eq_ignore_ascii_case(c),
                // Present but unparseable (e.g. Origin: null) → hostile.
                _ => false,
            };
            if !matches {
                tracing::warn!("cross-origin POST blocked: origin/referer '{claimed}'");
                return (
                    axum::http::StatusCode::FORBIDDEN,
                    page(
                        "Blocked — Cryptarch",
                        html! {
                            div.vault {
                                div.plate {
                                    h1 { "Blocked" }
                                    p.motto { "Cross-site request refused." }
                                    p.muted { "This request came from another site and was not executed. \
                                               If that was you, use Cryptarch directly." }
                                    p { a.button href="/dashboard" { "Go to dashboard" } }
                                }
                            }
                        },
                    ),
                )
                    .into_response();
            }
        }
    }
    next.run(req).await
}

/// Styled 404 for unknown routes — a bare empty body reads as a broken app.
async fn not_found() -> Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        page(
            "Not found — Cryptarch",
            html! {
                div.vault {
                    div.plate {
                        h1 { "Not found" }
                        p.motto { "No such engram in the archive." }
                        p { a.button href="/dashboard" { "Go to dashboard" } }
                    }
                }
            },
        ),
    )
        .into_response()
}

async fn health() -> &'static str {
    "ok"
}

/// Root redirects into the app (which will bounce to /login if unauthenticated).
async fn index() -> Redirect {
    Redirect::to("/dashboard")
}

// ---- login -----------------------------------------------------------------

async fn login_form() -> Markup {
    login_page(None)
}

#[derive(Deserialize)]
struct LoginInput {
    username: String,
    password: String,
}

/// A row we need to authenticate a user. Role/identity aren't kept here —
/// the session lookup reads them fresh from users on every request.
#[derive(sqlx::FromRow)]
struct UserAuthRow {
    id: uuid::Uuid,
    username: String,
    password_hash: String,
    is_active: bool,
}

async fn login_submit(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(input): Form<LoginInput>,
) -> Response {
    let username = input.username.trim();
    // Checked before password verification on purpose: while throttled,
    // even the correct password is refused — otherwise the throttle only
    // slows wrong guesses, which is no throttle at all.
    if state.login_throttle.is_throttled(username) {
        return login_page(Some(
            "Too many failed attempts — wait a few minutes and try again.",
        ))
        .into_response();
    }
    let row = sqlx::query_as::<_, UserAuthRow>(
        "SELECT id, username, password_hash, is_active \
         FROM users WHERE username = $1",
    )
    .bind(username)
    .fetch_optional(&state.db)
    .await;

    let user = match row {
        Ok(Some(u)) if u.is_active && auth::verify_password(&input.password, &u.password_hash) => u,
        Ok(_) => {
            let n = state.login_throttle.record_failure(username);
            if n == THROTTLE_MAX_FAILURES {
                // The trip itself is the audit-worthy event; per-attempt
                // rows would just be noise an attacker controls.
                provision::audit(&state.db, username, "login_throttled", Some(username), None)
                    .await;
            }
            return login_page(Some("Invalid credentials.")).into_response();
        }
        Err(e) => {
            tracing::error!("login query failed: {e}");
            return login_page(Some("Internal error.")).into_response();
        }
    };
    state.login_throttle.clear(username);

    let token = match state.sessions.insert(user.id).await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("creating session for {}: {e:#}", user.username);
            return login_page(Some("Internal error.")).into_response();
        }
    };

    let cookie = Cookie::build((SESSION_COOKIE, token))
        .path("/")
        .http_only(true)
        .secure(state.secure_cookies)
        .same_site(SameSite::Lax)
        .build();

    (jar.add(cookie), Redirect::to("/dashboard")).into_response()
}

async fn logout(State(state): State<AppState>, jar: CookieJar) -> Response {
    if let Some(c) = jar.get(SESSION_COOKIE) {
        state.sessions.remove(c.value()).await;
    }
    (jar.remove(Cookie::from(SESSION_COOKIE)), Redirect::to("/login")).into_response()
}

// ---- dashboard (protected) --------------------------------------------------

/// One of the caller's databases, for the dashboard table.
#[derive(sqlx::FromRow)]
struct OwnedDbRow {
    name: String,
    status: String,
    server_name: String,
}

async fn dashboard(
    State(state): State<AppState>,
    CurrentUser(session): CurrentUser,
    axum::extract::Query(flash): axum::extract::Query<FlashQuery>,
) -> Response {
    let dbs = sqlx::query_as::<_, OwnedDbRow>(
        "SELECT d.name, d.status, s.name AS server_name \
         FROM databases d JOIN managed_servers s ON s.id = d.server_id \
         WHERE d.owner_id = $1 ORDER BY d.created_at DESC",
    )
    .bind(session.user_id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let quota: Option<i32> = sqlx::query_scalar("SELECT db_quota FROM users WHERE id = $1")
        .bind(session.user_id)
        .fetch_one(&state.db)
        .await
        .unwrap_or(Some(0));
    let used = dbs.iter().filter(|d| d.status == "active").count();
    let at_cap = quota.is_some_and(|q| used >= q.max(0) as usize);

    shell(
        "Your databases",
        &session,
        html! {
            (flash_banner(flash.msg()))
            h1 { "Your databases" }
            div.cards {
                div.card {
                    span.n { (used) }
                    span.l { "in use" }
                }
                div.card {
                    span.n { @match quota { Some(q) => { (q) }, None => { "∞" } } }
                    span.l { "quota" }
                }
            }
            @if dbs.is_empty() {
                p.muted { "None yet. Provision your first below." }
            } @else {
                div.table-scroll {
                    table.dbs {
                        thead { tr { th { "Name" } th { "Server" } th { "Status" } } }
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
            @if at_cap {
                p.error { "Quota reached — delete a database to provision another." }
            } @else {
                p { a.button href="/provision" { "+ New database" } }
            }
        },
    )
    .into_response()
}

// ---- provisioning (protected) -----------------------------------------------

async fn provision_form(State(state): State<AppState>, CurrentUser(session): CurrentUser) -> Markup {
    provision_page(&state, &session, None, None, None, None).await
}

#[derive(Deserialize)]
struct ProvisionInput {
    server_id: Uuid,
    name: String,
    allowed_from: Option<String>,
    /// Named-source ids ticked on the form (repeated `sources` keys —
    /// needs axum_extra's Form, serde_urlencoded can't do Vec).
    #[serde(default)]
    sources: Vec<Uuid>,
}

/// Parse a comma/whitespace/newline-separated "Allowed from" input.
fn parse_allowed_from(raw: Option<&str>) -> Vec<String> {
    raw.unwrap_or("")
        .split([',', ' ', '\t', '\n', '\r'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{flash_msg, parse_allowed_from};

    #[test]
    fn allowed_from_parsing() {
        assert_eq!(
            parse_allowed_from(Some("10.0.0.0/24, 10.1.2.3\n192.168.0.0/16")),
            vec!["10.0.0.0/24", "10.1.2.3", "192.168.0.0/16"]
        );
        assert!(parse_allowed_from(None).is_empty());
        assert!(parse_allowed_from(Some("  ,, \n ")).is_empty());
    }

    #[test]
    fn human_duration_formatting() {
        use super::human_duration;
        assert_eq!(human_duration(30), "30s");
        assert_eq!(human_duration(42 * 60), "42m");
        assert_eq!(human_duration(5 * 3600 + 12 * 60), "5h 12m");
        assert_eq!(human_duration(3 * 86400 + 4 * 3600 + 120), "3d 4h");
        assert_eq!(human_duration(-5), "0s");
    }

    #[test]
    fn human_bytes_formatting() {
        use super::human_bytes;
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(97), "97 B");
        assert_eq!(human_bytes(1024), "1.0 kB");
        assert_eq!(human_bytes(421_888), "412.0 kB");
        assert_eq!(human_bytes(19 * 1024 * 1024), "19.0 MB");
        assert_eq!(human_bytes(7_500_000), "7.2 MB");
        assert_eq!(human_bytes(3_435_973_836), "3.2 GB");
        assert_eq!(human_bytes(-5), "-5 B");
    }

    #[test]
    fn flash_codes_are_closed_set() {
        // Known codes map to fixed strings; anything else renders nothing —
        // a crafted ?ok= link must never put attacker words in a banner.
        assert!(flash_msg("db_deleted").is_some());
        assert!(flash_msg("quota_set").is_some());
        assert!(flash_msg("").is_none());
        assert!(flash_msg("evil<script>").is_none());
        assert!(flash_msg("DB_DELETED").is_none());
    }
}

async fn provision_submit(
    State(state): State<AppState>,
    CurrentUser(session): CurrentUser,
    axum_extra::extract::Form(input): axum_extra::extract::Form<ProvisionInput>,
) -> Response {
    // Named sources first (labels ride along as notes), then free-text
    // extras. Resolution is server-scoped: ids from another server's list
    // resolve to nothing rather than smuggling a foreign range in.
    let named = crate::servers::resolve_sources(&state.db, input.server_id, &input.sources).await;
    let mut acl: Vec<(String, Option<String>)> =
        named.into_iter().map(|(cidr, label)| (cidr, Some(label))).collect();
    for c in parse_allowed_from(input.allowed_from.as_deref()) {
        if !acl.iter().any(|(existing, _)| *existing == c) {
            acl.push((c, None));
        }
    }
    match provision::provision_db(
        &state.db,
        &state.servers,
        session.user_id,
        &session.username,
        input.server_id,
        input.name.trim(),
        &acl,
    )
    .await
    {
        Ok(done) => {
            let sync_note = sync_edge_note(&state, input.server_id).await;
            let alt = listener_conn_strings(&state, input.server_id, &done).await;
            no_store(shell(
                "Database ready",
                &session,
                html! {
                    @if let Some(warn) = &sync_note { p.error role="alert" { (warn) } }
                    @if acl.is_empty() {
                        p.error { "No \"Allowed from\" sources were given — this database is \
                                   unreachable at the edge until you add one on its page." }
                    }
                    (credentials_once("Database ready", &done, &alt))
                },
            ))
        }
        Err(e) => {
            let msg = e.to_string();
            if matches!(e, ProvisionError::Internal) {
                tracing::error!("provision failed for {}: {msg}", session.username);
            }
            provision_page(&state, &session, Some(&msg), Some(&input.name),
                           input.allowed_from.as_deref(), Some(input.server_id))
                .await
                .into_response()
        }
    }
}

/// Run an edge sync and turn failure into a user-visible warning string.
/// An ACL change that didn't reach the edge must never look like it did.
async fn sync_edge_note(state: &AppState, server_id: Uuid) -> Option<String> {
    match crate::acl::sync_edge(&state.db, &state.crypto, server_id).await {
        Ok(crate::acl::SyncOutcome::Applied(_)) => None,
        Ok(crate::acl::SyncOutcome::ManualPlacement { .. }) => Some(
            "Edge config not applied automatically (no conf dir on this server) — \
             an admin must sync the bouncer hba manually."
                .into(),
        ),
        Err(e) => {
            tracing::error!("edge sync for server {server_id}: {e:#}");
            Some(format!("Edge sync FAILED — access rules not applied: {e}"))
        }
    }
}

/// Per-listener connection strings for the show-once screen: (label, string).
/// The primary (engine-built) string is rendered separately by the caller.
async fn listener_conn_strings(
    state: &AppState,
    server_id: Uuid,
    done: &provision::Provisioned,
) -> Vec<(String, String)> {
    crate::servers::listeners_for(&state.db, server_id)
        .await
        .into_iter()
        .map(|l| {
            // IPv6 literals need brackets in URLs or libpq misparses them.
            let host = if l.host.parse::<std::net::Ipv6Addr>().is_ok() {
                format!("[{}]", l.host)
            } else {
                l.host
            };
            (
                l.label,
                format!(
                    "postgresql://{}:{}@{}:{}/{}",
                    done.username, done.password, host, l.port, done.name
                ),
            )
        })
        .collect()
}

/// The show-once credentials screen — shared by provisioning and password reset.
/// Username, password, and one connection string per listener address.
fn credentials_once(
    heading: &str,
    done: &provision::Provisioned,
    listener_strings: &[(String, String)],
) -> Markup {
    html! {
        h1 { (heading) }
        p { "Database " code { (done.name) } " is live. "
            strong { "Save these now" } " — the password is shown "
            strong { "once" } " and is not stored anywhere." }
        dl.creds {
            dt { "Username" } dd { code { (done.username) }
                button.copy type="button" data-copy=(done.username) aria-label="Copy username" { "copy" } }
            dt { "Password" } dd { code { (done.password) }
                button.copy type="button" data-copy=(done.password) aria-label="Copy password" { "copy" } }
            dt { "Connection string" } dd { pre.conn { (done.conn.0) }
                button.copy type="button" data-copy=(done.conn.0) aria-label="Copy connection string" { "copy" } }
            @for (label, conn) in listener_strings {
                dt { "via " (label) } dd { pre.conn { (conn) }
                    button.copy type="button" data-copy=(conn) aria-label={ "Copy connection string via " (label) } { "copy" } }
            }
        }
        @if !listener_strings.is_empty() {
            p.muted { "Same credentials on every address — use whichever network the \
                       consumer lives on." }
        }
        p.muted { "Lost it later? Use " strong { "Reset password" }
            " on the database's page to get a new one — the old one stops working." }
        p { a.button href={ "/db/" (done.name) } { "View database" } " "
            a.link href="/dashboard" { "Back to dashboard" } }
    }
}

// ---- database detail + password reset (protected, owner-scoped) -------------

/// One ACL entry for the detail page.
#[derive(sqlx::FromRow)]
struct AclEntryRow {
    id: Uuid,
    cidr: String,
    created_by: String,
    /// A named source's label when the entry was born from one.
    note: Option<String>,
}

async fn db_detail(
    State(state): State<AppState>,
    CurrentUser(session): CurrentUser,
    axum::extract::Path(name): axum::extract::Path<String>,
    axum::extract::Query(flash): axum::extract::Query<FlashQuery>,
) -> Response {
    db_page(&state, &session, &name, axum::http::StatusCode::OK, None, flash.msg()).await
}

/// Error re-render for owner-OR-admin db actions: the owner gets the db page
/// with the error inline; an admin acting on a foreign database can't see
/// that owner-scoped page (it would 404 misleadingly), so they get the
/// styled error page carrying the same message.
async fn db_action_error(
    state: &AppState,
    session: &Session,
    owner_id: Uuid,
    name: &str,
    msg: &str,
) -> Response {
    let status = axum::http::StatusCode::BAD_REQUEST;
    if owner_id == session.user_id {
        db_page(state, session, name, status, Some(msg), None).await
    } else {
        error_page(session, status, "Action failed", msg)
    }
}

/// Render the owner-scoped database page. `error` re-renders it after a
/// failed action (bad CIDR, wrong delete confirmation, failed reset) — a
/// failure must keep the page, never dead-end on a bare text response.
/// `status` keeps HTTP semantics honest: error re-renders are 4xx even
/// though they carry a full page (htmx is configured to swap those too).
async fn db_page(
    state: &AppState,
    session: &Session,
    name: &str,
    status: axum::http::StatusCode,
    error: Option<&str>,
    notice: Option<&str>,
) -> Response {
    let acl = sqlx::query_as::<_, AclEntryRow>(
        "SELECT a.id, a.cidr::text AS cidr, a.created_by, a.note \
         FROM acl_entries a JOIN databases d ON d.id = a.database_id \
         WHERE d.name = $1 AND d.owner_id = $2 ORDER BY a.cidr",
    )
    .bind(name)
    .bind(session.user_id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    match provision::owned_db_detail(&state.db, session.user_id, name).await {
        Ok(Some(d)) => {
            let edge_dirty: bool = sqlx::query_scalar(
                "SELECT edge_dirty FROM managed_servers WHERE id = $1",
            )
            .bind(d.server_id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .unwrap_or(false);
            // Contents (size + table list) come from the managed server.
            // The engine is already timeout-bounded, but a VIEW must not
            // wait out the full op budget — 3s, then a degraded note.
            let stats = match state.servers.get(d.server_id) {
                Some(engine) => tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    engine.stats(&d.name),
                )
                .await
                .ok()
                .and_then(Result::ok),
                None => None,
            };
            let markup = shell(
            &d.name,
            session,
            html! {
                p { a.link href="/dashboard" { "← Dashboard" } }
                h1 { code { (d.name) } }
                @if let Some(msg) = error { p.error role="alert" { (msg) } }
                (flash_banner(notice))
                @if edge_dirty {
                    p.error { "Edge out of sync — the access rules shown here may not match \
                               what the bouncer is enforcing. An admin needs to re-sync \
                               (any successful ACL change clears this)." }
                }
                dl.creds {
                    dt { "Server" } dd { (d.server_name) " (" (d.engine) ")" }
                    dt { "Status" } dd { (status_badge(&d.status)) }
                    dt { "Created" } dd { (d.created_at.format("%Y-%m-%d %H:%M UTC").to_string()) }
                }

                h2 { "Connect" }
                p.sdesc { "One address per place you might be connecting from — inside the \
                           stack, this machine, another box on the network. Same database, \
                           same credentials; only the dial address differs. Passwords are \
                           redacted (only a hash is stored) — reset under Lifecycle if lost." }
                @let listeners = crate::servers::listeners_for(&state.db, d.server_id).await;
                div.scard {
                    div.conn-row {
                        span.conn-label { "primary" }
                        pre.conn { (d.masked_conn()) }
                        button.copy type="button" data-copy=(d.masked_conn())
                            aria-label="Copy primary connection string" { "copy" }
                    }
                    @for l in &listeners {
                        @let cs = d.masked_conn_at(&l.host, l.port);
                        div.conn-row {
                            span.conn-label { (l.label) }
                            pre.conn { (cs) }
                            button.copy type="button" data-copy=(cs)
                                aria-label={ "Copy " (l.label) " connection string" } { "copy" }
                        }
                    }
                    (srow("Database / username",
                        "Same name for both, by design.",
                        html! { code { (d.name) } }))
                }

                h2 { "Contents" }
                @match &stats {
                    None => {
                        p.muted { "Contents unavailable — the managed server didn't respond. \
                                   Refresh to try again." }
                    }
                    Some(s) => {
                        p.muted {
                            "Size on disk " strong { (human_bytes(s.size_bytes)) }
                            @if let Some(ts) = &s.tables {
                                " · " (ts.len()) " table" @if ts.len() != 1 { "s" }
                            }
                            " · " @if s.active { "in use now" } @else { "idle" }
                        }
                        @match &s.tables {
                            None => {
                                p.muted { "The table list isn't readable for this database." }
                            }
                            Some(ts) if ts.is_empty() => {
                                p.muted { "No tables yet — connect with your credentials \
                                           and create your first." }
                            }
                            Some(ts) => {
                                div.table-scroll {
                                    table.dbs {
                                        thead { tr { th { "Table" } th { "~ Rows" } th { "Size" } } }
                                        tbody {
                                            @for t in ts {
                                                tr {
                                                    td { code { (t.name) } }
                                                    td.tnum {
                                                        @if t.approx_rows < 0 { "—" }
                                                        @else { (t.approx_rows) }
                                                    }
                                                    td.tnum { (human_bytes(t.total_bytes)) }
                                                }
                                            }
                                        }
                                    }
                                }
                                p.muted { "Row counts are planner estimates; sizes include indexes." }
                            }
                        }
                    }
                }
                h2 { "Allowed from" }
                p.sdesc { "Sources admitted at the edge. No entries means unreachable — \
                           default-deny is the resting state." }
                @if acl.is_empty() {
                    p.error { "No sources — this database cannot be reached through the bouncer." }
                } @else {
                    div.table-scroll {
                        table.dbs {
                            thead { tr { th { "Source" } th { "Added by" } th { "" } } }
                            tbody {
                                @for a in &acl {
                                    tr {
                                        td {
                                            code { (a.cidr) }
                                            @if let Some(n) = &a.note { " " span.muted { (n) } }
                                        }
                                        td { (a.created_by) }
                                        td {
                                            form method="post" action={ "/db/" (d.name) "/acl/" (a.id) "/remove" } .inline
                                                hx-confirm={ "Remove " (a.cidr) "? Clients there lose access at the edge." } {
                                                button.link type="submit"
                                                    aria-label={ "Remove source " (a.cidr) } { "remove" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                @let unallowed: Vec<_> = crate::servers::sources_for(&state.db, d.server_id)
                    .await.into_iter().filter(|src| !acl.iter().any(|a| a.cidr == src.cidr)).collect();
                form method="post" action={ "/db/" (d.name) "/acl" } .scard {
                    // The quick-add buttons live INSIDE this card but submit
                    // their own hidden forms (form attribute) — a form can't
                    // nest in the card's own form.
                    @if !unallowed.is_empty() {
                        (srow("Quick add",
                            "Ranges your admin has named on this server, one click to allow.",
                            html! {
                                div.quick-btns {
                                    @for src in &unallowed {
                                        button.small type="submit" form={ "qa-" (src.id) }
                                            aria-label={ "Allow " (src.label) " (" (src.cidr) ")" } {
                                            "+ " (src.label) " " code { (src.cidr) }
                                        }
                                    }
                                }
                            }))
                    }
                    (srow("Allow a source",
                        "An IP or CIDR to admit at the edge — 10.10.100.0/24, or a single \
                         address.",
                        html! { input type="text" name="cidr" placeholder="10.10.100.0/24" autocomplete="off" required; }))
                    (sfoot(Some("Applied to the edge immediately."), "Allow source"))
                }
                @for src in &unallowed {
                    form id={ "qa-" (src.id) } method="post" action={ "/db/" (d.name) "/acl" } {
                        input type="hidden" name="cidr" value=(src.cidr);
                        input type="hidden" name="note" value=(src.label);
                    }
                }

                h2 { "Lifecycle" }
                div.scard {
                    (srow("Reset password",
                        "Generates a new password, shown once. The current one stops \
                         working immediately.",
                        html! {
                            form method="post" action={ "/db/" (d.name) "/reset" } .inline
                                hx-confirm={ "Reset the password for " (d.name)
                                             "? The current password stops working immediately." } {
                                button type="submit" { "Reset password" }
                            }
                        }))
                    @if d.status == "active" {
                        (srow("Suspend",
                            "Blocks logins and evicts live connections. The data stays; \
                             resume any time.",
                            html! {
                                form method="post" action={ "/db/" (d.name) "/suspend" } .inline
                                    hx-confirm={ "Suspend " (d.name) "? Live connections will be evicted." } {
                                    button type="submit" { "Suspend" }
                                }
                            }))
                    } @else {
                        (srow("Resume",
                            "Restores logins and edge access.",
                            html! {
                                form method="post" action={ "/db/" (d.name) "/resume" } .inline {
                                    button type="submit" { "Resume" }
                                }
                            }))
                    }
                }

                h2 { "Danger zone" }
                form method="post" action={ "/db/" (d.name) "/delete" } .scard {
                    (srow("Delete this database",
                        "Permanent — drops the database and its role on the server. There \
                         is no undo and no backup taken.",
                        html! {
                            input type="text" name="confirm" placeholder={ "type " (d.name) " to confirm" }
                                autocomplete="off" required;
                        }))
                    div.sfoot {
                        p.muted { "Type the database name above to arm the button." }
                        button.danger type="submit" { "Delete database" }
                    }
                }
            },
        );
        (status, markup).into_response()
        }
        Ok(None) => error_page(
            session,
            axum::http::StatusCode::NOT_FOUND,
            "No such database",
            "There is no database by that name in your account.",
        ),
        Err(_) => error_page(
            session,
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Something went wrong",
            "Loading the database failed — try again, and tell an admin if it persists.",
        ),
    }
}

async fn db_reset(
    State(state): State<AppState>,
    CurrentUser(session): CurrentUser,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Response {
    match provision::reset_password(
        &state.db,
        &state.servers,
        session.user_id,
        &session.username,
        &name,
    )
    .await
    {
        Ok(done) => {
            // Owner-scoped lookup: find_db is name-only and names are unique
            // per server, not globally — it could return another tenant's
            // same-named row and leak their listener topology into our
            // credential strings.
            let alt = match provision::owned_db_detail(&state.db, session.user_id, &name).await {
                Ok(Some(d)) => listener_conn_strings(&state, d.server_id, &done).await,
                _ => Vec::new(),
            };
            no_store(shell("New password", &session, credentials_once("New password", &done, &alt)))
        }
        Err(e) => {
            tracing::error!("reset failed for {}/{name}: {e}", session.username);
            db_page(&state, &session, &name, axum::http::StatusCode::BAD_REQUEST,
                    Some(&format!("Password reset failed: {e}")), None).await
        }
    }
}

// ---- ACL management (owner OR admin) -----------------------------------------

#[derive(Deserialize)]
struct AclAddInput {
    cidr: String,
    /// Label carried by named-source quick-adds; free-text adds send none.
    note: Option<String>,
}

async fn acl_add(
    State(state): State<AppState>,
    CurrentUser(session): CurrentUser,
    axum::extract::Path(name): axum::extract::Path<String>,
    Form(input): Form<AclAddInput>,
) -> Response {
    let lookup = match authz_db(&state, &session, &name).await {
        Ok(l) => l,
        Err(r) => return r,
    };
    let cidr = input.cidr.trim();
    if !crate::servers::valid_cidr(cidr) {
        return db_action_error(&state, &session, lookup.owner_id, &name,
            &format!("'{cidr}' is not a valid IP or CIDR (no hostnames; prefixes need zero host bits)."))
            .await;
    }
    let note = input.note.as_deref().map(str::trim).filter(|n| !n.is_empty() && n.len() <= 32);
    if let Err(e) = sqlx::query(
        "INSERT INTO acl_entries (database_id, cidr, created_by, note) \
         VALUES ($1, $2::cidr, $3, $4) ON CONFLICT (database_id, cidr) DO NOTHING",
    )
    .bind(lookup.id)
    .bind(cidr)
    .bind(&session.username)
    .bind(note)
    .execute(&state.db)
    .await
    {
        tracing::error!("acl add {name}/{cidr}: {e:#}");
        return db_action_error(&state, &session, lookup.owner_id, &name,
            "Saving the source failed.").await;
    }
    provision::audit(&state.db, &session.username, "acl_add", Some(&name), Some(cidr)).await;
    if let Some(warn) = sync_edge_note(&state, lookup.server_id).await {
        tracing::warn!("acl add {name}: {warn}");
    }
    Redirect::to(&format!("/db/{name}?ok=source_added")).into_response()
}

async fn acl_remove(
    State(state): State<AppState>,
    CurrentUser(session): CurrentUser,
    axum::extract::Path((name, entry_id)): axum::extract::Path<(String, Uuid)>,
) -> Response {
    let lookup = match authz_db(&state, &session, &name).await {
        Ok(l) => l,
        Err(r) => return r,
    };
    let removed: Option<String> = match sqlx::query_scalar(
        "DELETE FROM acl_entries WHERE id = $1 AND database_id = $2 RETURNING cidr::text",
    )
    .bind(entry_id)
    .bind(lookup.id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            // A failed revocation must never render as success.
            tracing::error!("acl remove {name}/{entry_id}: {e:#}");
            return db_action_error(&state, &session, lookup.owner_id, &name,
                "Removing the source failed — it is still allowed at the edge.").await;
        }
    };
    if let Some(cidr) = removed {
        provision::audit(&state.db, &session.username, "acl_remove", Some(&name), Some(&cidr)).await;
        if let Some(warn) = sync_edge_note(&state, lookup.server_id).await {
            // sync_edge has marked the server edge_dirty; the detail page
            // the user lands on banners it. Log for the operator trail too.
            tracing::warn!("acl remove {name}: {warn}");
        }
    }
    Redirect::to(&format!("/db/{name}?ok=source_removed")).into_response()
}

// ---- database lifecycle (owner OR admin) ------------------------------------

/// Authorise a lifecycle action on `name`: allowed if the caller owns it or is
/// an admin. Returns the row, or an error Response (404/403/500).
async fn authz_db(
    state: &AppState,
    session: &Session,
    name: &str,
) -> Result<provision::DbLookup, Response> {
    match provision::find_db(&state.db, name).await {
        Ok(Some(row)) if row.owner_id == session.user_id || session.is_admin => Ok(row),
        Ok(Some(_)) => Err(error_page(
            session,
            axum::http::StatusCode::FORBIDDEN,
            "Not your database",
            "That database belongs to another user.",
        )),
        Ok(None) => Err(error_page(
            session,
            axum::http::StatusCode::NOT_FOUND,
            "No such database",
            "There is no database by that name.",
        )),
        Err(_) => Err(error_page(
            session,
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Something went wrong",
            "Looking up the database failed — try again.",
        )),
    }
}

/// Where to send the user after a db action — admins back to the admin table,
/// owners back to their dashboard. `ok` is the flash code for the banner.
fn after_db_action(session: &Session, ok: &str) -> Redirect {
    if session.is_admin {
        Redirect::to(&format!("/admin/databases?ok={ok}"))
    } else {
        Redirect::to(&format!("/dashboard?ok={ok}"))
    }
}

async fn db_suspend(
    State(state): State<AppState>,
    CurrentUser(session): CurrentUser,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Response {
    let lookup = match authz_db(&state, &session, &name).await {
        Ok(l) => l,
        Err(r) => return r,
    };
    match provision::set_db_active(&state.db, &state.servers, &lookup, &name, false, &session.username)
        .await
    {
        Ok(_) => {
            // Suspension is an edge event too: drop the db's hba lines and
            // evict live sessions — not just NOLOGIN on the role.
            if let Some(warn) = sync_edge_note(&state, lookup.server_id).await {
                tracing::warn!("suspend {name}: {warn}");
            }
            crate::acl::kill_db_sessions(&state.db, &state.crypto, lookup.server_id, &name).await;
            after_db_action(&session, "db_suspended").into_response()
        }
        Err(e) => db_action_error(&state, &session, lookup.owner_id, &name,
                                  &format!("Suspending failed: {e}")).await,
    }
}

async fn db_resume(
    State(state): State<AppState>,
    CurrentUser(session): CurrentUser,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Response {
    let lookup = match authz_db(&state, &session, &name).await {
        Ok(l) => l,
        Err(r) => return r,
    };
    match provision::set_db_active(&state.db, &state.servers, &lookup, &name, true, &session.username)
        .await
    {
        Ok(_) => {
            if let Some(warn) = sync_edge_note(&state, lookup.server_id).await {
                tracing::warn!("resume {name}: {warn}");
            }
            after_db_action(&session, "db_resumed").into_response()
        }
        Err(e) => db_action_error(&state, &session, lookup.owner_id, &name,
                                  &format!("Resuming failed: {e}")).await,
    }
}

#[derive(Deserialize)]
struct DeleteInput {
    confirm: String,
}

async fn db_delete(
    State(state): State<AppState>,
    CurrentUser(session): CurrentUser,
    axum::extract::Path(name): axum::extract::Path<String>,
    Form(input): Form<DeleteInput>,
) -> Response {
    let lookup = match authz_db(&state, &session, &name).await {
        Ok(l) => l,
        Err(r) => return r,
    };
    // Typed-name confirmation — the one irreversible action. Checked after
    // authz so the error re-render can be owner-aware.
    if input.confirm.trim() != name {
        return db_action_error(&state, &session, lookup.owner_id, &name,
            &format!("Confirmation didn't match — type {name} exactly to delete.")).await;
    }
    match provision::delete_db(&state.db, &state.servers, &lookup, &name, &session.username).await {
        Ok(_) => {
            // acl_entries cascade with the databases row; re-render drops
            // the lines, KILL evicts anything still connected at the edge.
            if let Some(warn) = sync_edge_note(&state, lookup.server_id).await {
                tracing::warn!("delete {name}: {warn}");
            }
            crate::acl::kill_db_sessions(&state.db, &state.crypto, lookup.server_id, &name).await;
            after_db_action(&session, "db_deleted").into_response()
        }
        Err(e) => db_action_error(&state, &session, lookup.owner_id, &name,
                                  &format!("Delete failed: {e}")).await,
    }
}

async fn provision_page(
    state: &AppState,
    session: &Session,
    error: Option<&str>,
    prefill: Option<&str>,
    prefill_allowed: Option<&str>,
    selected_server: Option<Uuid>,
) -> Markup {
    let servers = state.servers.list();
    // Each server's default consumer CIDR rides on its <option> as data-cidr;
    // app.js swaps the (untouched) "Allowed from" value when the selection
    // changes. The first server's default is the initial value.
    let cidr_rows: Vec<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT id, default_consumer_cidr::text FROM managed_servers",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    let cidr_of = |id: Uuid| -> String {
        cidr_rows
            .iter()
            .find(|(rid, _)| *rid == id)
            .and_then(|(_, c)| c.clone())
            .unwrap_or_default()
    };
    // Named sources per active server (CRYPTARCH-39): rendered as opt-in
    // checkboxes. The free-text default-CIDR prefill only applies to servers
    // with NO named sources — with sources, the default is a ticked box.
    let server_ids: Vec<Uuid> = servers.iter().map(|s| s.id).collect();
    let sources: Vec<(Uuid, Uuid, String, String, bool)> = sqlx::query_as(
        "SELECT id, server_id, label, cidr::text, is_default FROM server_sources \
         WHERE server_id = ANY($1) ORDER BY is_default DESC, label",
    )
    .bind(&server_ids)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    let sources_of = |sid: Uuid| -> Vec<&(Uuid, Uuid, String, String, bool)> {
        sources.iter().filter(|(_, s, ..)| *s == sid).collect()
    };
    let first_selected = selected_server.or_else(|| servers.first().map(|s| s.id));
    let default_cidr: String = first_selected
        .filter(|sid| sources_of(*sid).is_empty())
        .map(&cidr_of)
        .unwrap_or_default();
    let allowed_value = prefill_allowed.map(str::to_string).unwrap_or(default_cidr);
    let has_any_sources = !sources.is_empty();
    shell(
        "New database",
        session,
        html! {
            h1 { "New database" }
            @if servers.is_empty() {
                p.error { "No managed server is configured. Provisioning is unavailable." }
                p { a.button href="/dashboard" { "Back" } }
            } @else {
                @if let Some(msg) = error {
                    p.error role="alert" { (msg) }
                }
                form method="post" action="/provision" .scard {
                    (srow("Server",
                        "Where the database lives. Your connection string points at its edge.",
                        html! {
                            select name="server_id" required {
                                @for s in &servers {
                                    option value=(s.id) data-cidr=(cidr_of(s.id))
                                        selected[selected_server == Some(s.id)] {
                                        (s.name) " (" (s.engine) ")"
                                    }
                                }
                            }
                        }))
                    (srow("Database name",
                        "Also your username on it. Lowercase letter first, then letters, \
                         digits, underscores; 3–63 characters.",
                        html! {
                            input type="text" name="name" value=(prefill.unwrap_or(""))
                                placeholder="e.g. alice_app" pattern="[a-z][a-z0-9_]{2,62}"
                                autocomplete="off" required;
                        }))
                    @if has_any_sources {
                        (srow("Allowed sources",
                            "Where connections may come from — tick what applies. Your \
                             admin named these ranges so you don't have to know them.",
                            html! {
                                @for s in &servers {
                                    div.src-group data-server=(s.id) {
                                        @if servers.len() > 1 { span.src-server.muted { (s.name) } }
                                        @let list = sources_of(s.id);
                                        @if list.is_empty() {
                                            span.muted { "No named ranges on this server — use the field below." }
                                        }
                                        @for (id, _, label, cidr, is_default) in list {
                                            label.check {
                                                input type="checkbox" name="sources" value=(id) checked[*is_default];
                                                span { (label) " " code { (cidr) } }
                                            }
                                        }
                                    }
                                }
                            }))
                    }
                    (srow(
                        if has_any_sources { "Additional sources" } else { "Allowed from" },
                        "Extra IPs or CIDRs, comma-separated, for anything not listed. \
                         Empty is fine: the database is still created, it just stays \
                         unreachable until some source is allowed.",
                        html! {
                            input type="text" name="allowed_from" value=(allowed_value)
                                placeholder="10.10.100.0/24, 10.10.12.33" autocomplete="off";
                        }))
                    div.sfoot {
                        p.muted { "The password is shown exactly once on the next screen." }
                        a.link href="/dashboard" { "Cancel" }
                        button.primary type="submit" { "Provision" }
                    }
                }
            }
        },
    )
}

// ---- rendering --------------------------------------------------------------

fn login_page(error: Option<&str>) -> Markup {
    page(
        "Sign in — Cryptarch",
        html! {
            div.vault {
                div.plate {
                    h1 { "Cryptarch" }
                    p.motto { "Decode an engram, receive a database." }
                    @if let Some(msg) = error {
                        p.error role="alert" { (msg) }
                    }
                    form method="post" action="/login" .stack {
                        label { "Username"
                            input type="text" name="username" autocomplete="username" autofocus required;
                        }
                        label { "Password"
                            input type="password" name="password" autocomplete="current-password" required;
                        }
                        button.primary type="submit" { "Sign in" }
                    }
                }
            }
        },
    )
}

fn page(title: &str, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                // historyCacheSize 0: show-once credentials must never be
                // snapshotted into sessionStorage ("htmx-history-cache") by
                // boosted navigation. responseHandling overrides the htmx
                // default of NOT swapping 4xx/5xx — our error responses are
                // full styled pages and must render, not vanish silently.
                meta name="htmx-config"
                    content=r#"{"historyCacheSize":0,"responseHandling":[{"code":"204","swap":false},{"code":"...","swap":true}]}"#;
                title { (title) }
                link rel="icon" type="image/svg+xml" href="/static/favicon.svg";
                // Fonts preload with crossorigin — required for font
                // preloads even same-origin, or browsers double-fetch.
                link rel="preload" href="/static/fonts/manrope-var.woff2"
                    as="font" type="font/woff2" crossorigin;
                link rel="preload" href="/static/fonts/fraunces-var.woff2"
                    as="font" type="font/woff2" crossorigin;
                link rel="stylesheet" href="/static/app.css";
                script src="/static/htmx.min.js" defer {}
                script src="/static/app.js" defer {}
            }
            // hx-boost: links and forms go over XHR with a body swap — same
            // server-rendered pages, no full-document reload flash. Everything
            // still works with JS disabled.
            body hx-boost="true" {
                main.wrap { (body) }
            }
        }
    }
}

/// Map a `?ok=` flash code (set by redirect-after-POST) to its banner text.
/// Codes, not free text — a query parameter must never become an arbitrary
/// banner an attacker can put words in via a crafted link.
pub fn flash_msg(code: &str) -> Option<&'static str> {
    Some(match code {
        "db_suspended" => "Database suspended — live connections were evicted.",
        "db_resumed" => "Database resumed.",
        "db_deleted" => "Database deleted.",
        "source_added" => "Source allowed.",
        "source_removed" => "Source removed.",
        "quota_set" => "Quota updated.",
        "user_suspended" => "User suspended — their sessions were signed out.",
        "user_enabled" => "User re-enabled.",
        "listener_removed" => "Listener removed.",
        "server_enabled" => "Server enabled.",
        "server_disabled" => "Server disabled.",
        _ => return None,
    })
}

/// Query shape for pages that show a post-action flash banner.
#[derive(Deserialize, Default)]
pub struct FlashQuery {
    pub ok: Option<String>,
}

impl FlashQuery {
    pub fn msg(&self) -> Option<&'static str> {
        self.ok.as_deref().and_then(flash_msg)
    }
}

/// The success banner, if a flash code resolved. Renders nothing otherwise.
pub fn flash_banner(msg: Option<&str>) -> Markup {
    html! {
        @if let Some(m) = msg { p.notice role="status" { (m) } }
    }
}

/// A styled, in-chrome error page — every failure a signed-in user can hit
/// must keep the topbar and a way back. Bare text/plain dead-ends are bugs.
pub fn error_page(
    session: &Session,
    status: axum::http::StatusCode,
    title: &str,
    msg: &str,
) -> Response {
    let markup = shell(
        title,
        session,
        html! {
            h1 { (title) }
            p.error { (msg) }
            p { a.button href="/dashboard" { "Back to dashboard" } }
        },
    );
    (status, markup).into_response()
}

/// Wrap a show-once page (fresh credentials) so browsers never cache it —
/// without this, bfcache can re-show a password on back-navigation.
pub fn no_store(markup: Markup) -> Response {
    ([(header::CACHE_CONTROL, "no-store")], markup).into_response()
}

/// Status rendered as an indicator dot + label. Shared with the admin views.
/// One settings-card row (CRYPTARCH-34): label + plain-language description
/// on the left, the control on the right. Pair with a `.scard` container and
/// close the card with [`sfoot`].
pub fn srow(label: &str, desc: &str, control: Markup) -> Markup {
    html! {
        div.srow {
            span.s-label { (label) }
            p.s-desc { (desc) }
            div.s-control { (control) }
        }
    }
}

/// A settings card's submit footer: optional consequence hint + the button.
pub fn sfoot(hint: Option<&str>, label: &str) -> Markup {
    html! {
        div.sfoot {
            @if let Some(h) = hint { p.muted { (h) } }
            button.primary type="submit" { (label) }
        }
    }
}

pub fn status_badge(status: &str) -> Markup {
    let class = match status {
        "active" => "st st-active",
        "suspended" => "st st-suspended",
        _ => "st st-bad",
    };
    html! {
        span class=(class) { span.dot {} (status) }
    }
}

/// Page chrome for authenticated views: a topbar with identity + sign-out.
/// Public so the admin module can reuse the same chrome. `title` is the
/// page-specific part; " — Cryptarch" is appended for the tab/history.
pub fn shell(title: &str, session: &Session, body: Markup) -> Markup {
    page(
        &format!("{title} — Cryptarch"),
        html! {
            div.topbar {
                div.topnav {
                    a.brand href="/dashboard" { "Cryptarch" }
                    nav.primary aria-label="Primary" {
                        a href="/dashboard" { "Dashboard" }
                        @if session.is_admin {
                            a href="/admin" { "Admin" }
                        }
                    }
                }
                nav.session aria-label="Session" {
                    a.userchip href="/profile"
                        aria-label={ "Your profile — signed in as " (session.username) } {
                        strong { (session.username) }
                        @if session.is_admin { span.rolepill { "admin" } }
                    }
                    form method="post" action="/logout" .inline {
                        button.small type="submit" { "Sign out" }
                    }
                }
            }
            (body)
        },
    )
}


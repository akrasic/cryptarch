//! The HTTP surface: the router, the session and login plumbing, and the
//! domain functions behind the tenant's side of the API (dashboard,
//! provisioning, the database page's tabs). The pages are the SPA's
//! (CRYPTARCH-137, `spa`); the API (`crate::api`) is the only door.
//!
//! # Two scopes for a database, one answer for a stranger
//!
//! A per-database action resolves its target one of two ways:
//!
//! * **Owner-scoped** (reset, backup, restore, via `owned_db_detail` /
//!   `reset_password`): the query is keyed on `owner_id` *and* name.
//! * **Owner or admin** (`authz_lookup`: the view, the ACL, delete): looks the
//!   database up by name, then checks ownership or admin.
//!
//! Either way the API answers someone who may not see the database exactly as
//! it answers a name that does not exist — a 404 that does not confirm the
//! name is taken (CRYPTARCH-140). If you add a database action, choose the
//! scope deliberately, and keep that answer uniform.

pub mod spa;

use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::Router;
use tower_http::set_header::SetResponseHeaderLayer;
use axum_extra::extract::cookie::{Cookie, SameSite};
use sqlx::{AssertSqlSafe, PgPool};
use uuid::Uuid;

use crate::auth::{self, Session, SessionStore};
use crate::provision::{self, ProvisionError};
use crate::servers::ServerRegistry;

/// In-memory per-username login backoff. 5 failures in a 5-minute window
/// throttle further attempts (even with the correct password) until the
/// window expires. Memory-only by design: a restart clears it, which is
/// fine — Argon2 already rate-limits online guessing; this exists to make
/// sustained credential-stuffing loud (audited) and slow.
#[derive(Clone, Default)]
pub struct LoginThrottle(
    std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Attempts>>>,
);

/// One username's standing in the throttle.
#[derive(Clone, Copy)]
struct Attempts {
    failures: u32,
    since: std::time::Instant,
    /// Attempts that have passed the check and not yet finished (CRYPTARCH-128).
    /// Counted against the limit, because a failure is only RECORDED after the
    /// Argon2 verify — so without this, any number of concurrent guesses all
    /// passed the check before the first of them could fail. Behind the verify
    /// queue, that window is as long as the queue.
    in_flight: u32,
}

const THROTTLE_MAX_FAILURES: u32 = 5;
const THROTTLE_WINDOW: std::time::Duration = std::time::Duration::from_secs(300);
/// Hard ceiling on tracked usernames. Failed logins carry an attacker-chosen
/// username, so without a cap a spray of distinct names would grow the map
/// without bound (memory DoS). At the ceiling we evict a NOT-currently-tripped,
/// not-in-flight entry (oldest first) — a spray of single-failure usernames
/// must never knock a genuinely-throttled victim off the list and reset their
/// guess budget.
const THROTTLE_MAX_TRACKED: usize = 4096;

/// A login attempt that has been admitted by the throttle. Releases its
/// in-flight slot on drop, however the attempt ends.
pub struct LoginAttempt {
    throttle: LoginThrottle,
    user: String,
}

impl Drop for LoginAttempt {
    fn drop(&mut self) {
        let mut map = self.throttle.0.lock().unwrap();
        if let Some(e) = map.get_mut(&self.user) {
            e.in_flight = e.in_flight.saturating_sub(1);
            if e.failures == 0 && e.in_flight == 0 {
                map.remove(&self.user);
            }
        }
    }
}

impl LoginThrottle {
    /// Make room for `user` if the map is at its ceiling. Caller holds the lock.
    fn make_room(map: &mut std::collections::HashMap<String, Attempts>, user: &str) {
        let now = std::time::Instant::now();
        // Drop fully-expired, idle entries first — bounds the map to usernames
        // that failed within the window, and is cheap at realistic sizes.
        map.retain(|_, a| a.in_flight > 0 || now.duration_since(a.since) <= THROTTLE_WINDOW);
        // Still at the ceiling with a new username? Evict to stay bounded —
        // but prefer an entry that ISN'T currently throttled (oldest first), so
        // a spray of single-failure usernames is what gets dropped, not a
        // genuinely-tripped victim. Only if every slot is already tripped (a
        // far larger, ~MAX×MAX_FAILURES attack) do we fall back to oldest overall.
        // An entry with attempts in flight is never evicted: its guard would
        // then decrement nothing, and its count would silently vanish.
        if map.len() >= THROTTLE_MAX_TRACKED && !map.contains_key(user) {
            let idle = |a: &Attempts| a.in_flight == 0;
            let evict = map
                .iter()
                .filter(|(_, a)| idle(a) && a.failures < THROTTLE_MAX_FAILURES)
                .min_by_key(|(_, a)| a.since)
                .or_else(|| map.iter().filter(|(_, a)| idle(a)).min_by_key(|(_, a)| a.since))
                .map(|(k, _)| k.clone());
            if let Some(k) = evict {
                map.remove(&k);
            }
        }
    }

    /// Admit one attempt for `user`, or refuse it. Refused when recorded
    /// failures PLUS attempts already in flight reach the limit, checked and
    /// counted under one lock, so concurrent guesses cannot all slip through
    /// the check before any of them has failed.
    ///
    /// While throttled even the correct password is refused — otherwise the
    /// throttle only slows wrong guesses, which is no throttle at all.
    pub fn begin(&self, user: &str) -> Option<LoginAttempt> {
        let mut map = self.0.lock().unwrap();
        let now = std::time::Instant::now();
        if let Some(a) = map.get_mut(user)
            && a.in_flight == 0
            && now.duration_since(a.since) > THROTTLE_WINDOW
        {
            a.failures = 0;
            a.since = now;
        }
        if map.get(user).is_some_and(|a| a.failures + a.in_flight >= THROTTLE_MAX_FAILURES) {
            return None;
        }
        Self::make_room(&mut map, user);
        let a = map
            .entry(user.to_string())
            .or_insert(Attempts { failures: 0, since: now, in_flight: 0 });
        a.in_flight += 1;
        Some(LoginAttempt { throttle: self.clone(), user: user.to_string() })
    }

    pub fn is_throttled(&self, user: &str) -> bool {
        let mut map = self.0.lock().unwrap();
        match map.get(user) {
            Some(a) if a.failures >= THROTTLE_MAX_FAILURES => {
                if a.since.elapsed() > THROTTLE_WINDOW && a.in_flight == 0 {
                    map.remove(user);
                    false
                } else {
                    a.since.elapsed() <= THROTTLE_WINDOW
                }
            }
            _ => false,
        }
    }

    /// Record one failure; returns the count now on record.
    pub fn record_failure(&self, user: &str) -> u32 {
        let mut map = self.0.lock().unwrap();
        let now = std::time::Instant::now();
        Self::make_room(&mut map, user);
        let entry = map
            .entry(user.to_string())
            .or_insert(Attempts { failures: 0, since: now, in_flight: 0 });
        if now.duration_since(entry.since) > THROTTLE_WINDOW {
            entry.failures = 0;
            entry.since = now;
        }
        entry.failures += 1;
        entry.failures
    }

    /// Forget `user`'s failures after a successful login. In-flight attempts
    /// keep their slots until they finish.
    pub fn clear(&self, user: &str) {
        let mut map = self.0.lock().unwrap();
        if let Some(a) = map.get_mut(user) {
            if a.in_flight == 0 {
                map.remove(user);
            } else {
                a.failures = 0;
            }
        }
    }
}

/// Counts backup and restore jobs that are in flight, so shutdown can wait for
/// them instead of dropping the runtime out from under them (CRYPTARCH-113).
///
/// `axum::serve(..).with_graceful_shutdown(..)` drains HTTP CONNECTIONS. The
/// jobs are `tokio::spawn`ed and have no relationship to it, so `main`
/// returning killed them mid-write — and the partial `.enc` cleanup lives on
/// `run_job`'s error path, which a dropped future never reaches. Every redeploy
/// during a backup window therefore cost one dump-sized orphan file.
///
/// A counter rather than a `JoinSet`: the jobs are spawned from request
/// handlers that have already returned, so there is nowhere to keep a handle,
/// and the only thing shutdown needs to know is "is anything still running".
#[derive(Clone, Default)]
pub struct JobTracker {
    inflight: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    idle: std::sync::Arc<tokio::sync::Notify>,
    /// Raised by [`drain`](Self::drain). Waiting for running jobs is only half
    /// of shutdown; the scheduler also has to stop STARTING them, or it claims
    /// the next database the moment the drained job finishes (CRYPTARCH-123).
    closing: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl JobTracker {
    /// Register a job. The returned guard decrements on drop — including on a
    /// panic, which is the case that matters, since a panicking job is exactly
    /// the one nobody else is tracking.
    #[must_use]
    pub fn start(&self) -> JobGuard {
        self.inflight.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        JobGuard { tracker: self.clone() }
    }

    pub fn inflight(&self) -> usize {
        self.inflight.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Whether shutdown has begun. Long-running loops check this between units
    /// of work rather than starting one the process will not live to finish.
    pub fn is_closing(&self) -> bool {
        self.closing.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Stop admitting new jobs. Called the moment the shutdown signal arrives,
    /// not when HTTP has finished draining (CRYPTARCH-128) — the scheduler
    /// otherwise keeps starting backups for as long as HTTP takes.
    pub fn close(&self) {
        self.closing.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Register a job unless shutdown has begun. Every job start goes through
    /// this, BEFORE it claims its row (CRYPTARCH-128).
    ///
    /// The order is the guarantee. `drain` raises `closing` and then reads the
    /// count; this raises the count and then reads `closing`. With both SeqCst,
    /// at least one side sees the other: either drain counts this job and waits
    /// for it, or this sees `closing` and backs out. Checking `closing` first
    /// and registering after — what `run_now` used to do, by registering after
    /// `claim` — leaves a window where drain reads zero and returns while a
    /// dump is starting.
    pub fn begin(&self) -> Option<JobGuard> {
        let guard = self.start();
        if self.is_closing() {
            return None; // `guard` drops here and gives the count back
        }
        Some(guard)
    }

    /// Wait for every in-flight job, or `deadline`, whichever comes first.
    ///
    /// Bounded on purpose. A 20 GB dump can outlast any shutdown anyone is
    /// willing to wait through, and an orchestrator that gave up would SIGKILL
    /// us anyway — which is strictly worse, because it skips this path
    /// entirely. So: give short jobs the seconds they need to settle their row
    /// and clean up, and tell the operator plainly about anything still
    /// running when the deadline passes.
    ///
    /// Returns whether every job finished inside the deadline.
    pub async fn drain(&self, deadline: std::time::Duration) -> bool {
        // First, and unconditionally: even with nothing running, the scheduler
        // must not start something now. Usually already raised at the signal.
        self.close();
        if self.inflight() == 0 {
            return true;
        }
        tracing::info!("waiting up to {deadline:?} for {} background job(s)", self.inflight());
        let waited = tokio::time::timeout(deadline, async {
            loop {
                // Registered BEFORE the count is read. `notify_waiters` wakes
                // only futures already enabled, so checking first and then
                // creating `notified()` loses a wakeup whenever the last job
                // ends between the two — and the drain then sits out the full
                // deadline with nothing left to wait for.
                let notified = self.idle.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.inflight() == 0 {
                    return;
                }
                notified.await;
            }
        })
        .await;
        match waited {
            Ok(()) => {
                tracing::info!("background jobs finished");
                true
            }
            Err(_) => {
                tracing::warn!(
                    "{} background job(s) still running at shutdown — their rows stay `running` \
                     until the boot sweep marks them interrupted on the next start",
                    self.inflight()
                );
                false
            }
        }
    }
}

/// Decrements the tracker when the job ends, however it ends.
pub struct JobGuard {
    tracker: JobTracker,
}

impl Drop for JobGuard {
    fn drop(&mut self) {
        if self.tracker.inflight.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) == 1 {
            self.tracker.idle.notify_waiters();
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    /// In-flight background jobs, for shutdown draining (CRYPTARCH-113).
    pub jobs: JobTracker,
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
    /// Root for backup blobs (CRYPTARCH-57), from `CRYPTARCH_BACKUP_DIR`.
    /// `None` = backups not configured; the UI says so rather than offering a
    /// button that always fails.
    pub backup_dir: Option<std::path::PathBuf>,
    /// Scrape token for `/metrics`. `None` disables the endpoint entirely.
    pub metrics_token: Option<String>,
    /// Cryptarch's own DSN, kept so the metadata database can ride the backup
    /// pipeline (CRYPTARCH-62). It carries a password — same handling as the
    /// server DSNs the registry holds decrypted in memory.
    pub metadata_dsn: Option<String>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        // Unauthenticated by session on purpose: Prometheus presents a bearer
        // token, not a cookie. The handler is the gate.
        .route("/metrics", get(crate::metrics::metrics))
        .route("/healthz", get(health))
        // The SvelteKit SPA (CRYPTARCH-129) is the whole UI (CRYPTARCH-137):
        // the fallback below hands it every GET not routed here. It sets its
        // own CSP — the layer below is if_not_present — because its shell
        // needs its inline bootstrap script admitted by hash.
        .merge(spa::router())
        // The JSON API (CRYPTARCH-130). Inside the origin guard and the global
        // headers below, like every other route.
        .nest("/api/v1", crate::api::router())
        .route("/api", any(crate::api::unknown_endpoint))
        .route("/api/", any(crate::api::unknown_endpoint))
        .route("/api/{*rest}", any(crate::api::unknown_endpoint))
        .fallback(spa::fallback)
        // CSRF: cross-site POSTs are refused by Origin/Referer validation.
        // Browsers always attach Origin to cross-site form posts; a mismatch
        // with Host is an attack, full stop. Requests with NEITHER header
        // (curl, monitors) pass — they aren't riding a victim's cookies.
        .layer(axum::middleware::from_fn(origin_guard))
        // Strict CSP: everything is same-origin static files — no inline
        // styles or scripts anywhere, so no unsafe-inline needed.
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(spa::PLAIN_CSP),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .with_state(state)
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
    // Every method that can change state, not just POST (CRYPTARCH-130): the
    // forms only ever POSTed, but the JSON API also uses PUT, PATCH and DELETE.
    let unsafe_method = !matches!(
        *req.method(),
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    );
    if unsafe_method {
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
                tracing::warn!("cross-origin {} blocked: origin/referer '{claimed}'", req.method());
                // Every state-changing route is the API's now (CRYPTARCH-137),
                // so the refusal is in its shape, whatever the path.
                return crate::api::ApiError::new(
                    axum::http::StatusCode::FORBIDDEN,
                    "cross_site",
                    "Cross-site request refused.",
                )
                .into_response();
            }
        }
    }
    next.run(req).await
}

async fn health() -> &'static str {
    "ok"
}

// ---- login -----------------------------------------------------------------

/// A row we need to authenticate a user. Role/identity aren't kept here —
/// the session lookup reads them fresh from users on every request.
#[derive(sqlx::FromRow, Clone)]
struct UserAuthRow {
    id: uuid::Uuid,
    username: String,
    password_hash: String,
    is_active: bool,
}

/// Longer than any username can be (`auth::valid_username` caps at 32), with
/// room for a bootstrap admin named in config.
const MAX_LOGIN_USERNAME: usize = 128;

/// Why a login did not produce a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginFailure {
    /// Too many recent failures for this username — even a correct password is
    /// refused (see `LoginThrottle::begin`).
    Throttled,
    /// Wrong password, unknown user, or suspended account: deliberately one
    /// answer, so none of the three can be told apart.
    Invalid,
    Internal,
}

/// Check a username and password and open a session, returning its token.
///
/// The one implementation of login, shared by the form and the JSON API
/// (CRYPTARCH-130) — the throttle, the timing equalisation and the audit row
/// are security properties, and two copies of them would drift.
pub async fn authenticate(
    state: &AppState,
    username: &str,
    password: String,
) -> Result<String, LoginFailure> {
    let username = username.trim();
    // No account can have a name this long (valid_username caps at 32), so it
    // is refused before the throttle — which would otherwise keep every such
    // attacker-chosen name in memory for its whole window (CRYPTARCH-138). The
    // dummy verify is still spent, so the answer looks like any other failure.
    if username.len() > MAX_LOGIN_USERNAME {
        let _ = auth::verify_login_password(password, auth::DUMMY_HASH.clone()).await;
        return Err(LoginFailure::Invalid);
    }
    // Admitted before password verification on purpose, and held until the
    // attempt is over — including the session insert below: see
    // `LoginThrottle::begin`.
    let Some(_attempt) = state.login_throttle.begin(username) else {
        return Err(LoginFailure::Throttled);
    };
    let row = sqlx::query_as::<_, UserAuthRow>(
        "SELECT id, username, password_hash, is_active \
         FROM users WHERE username = $1",
    )
    .bind(username)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("login query failed: {e}");
        LoginFailure::Internal
    })?;

    // Always spend exactly one Argon2 verify — against the real hash for an
    // existing active user, else a fixed dummy — so a missing or suspended
    // account is indistinguishable from a wrong password by response latency.
    //
    // On the blocking pool, not a runtime worker (CRYPTARCH-115). Argon2's
    // default profile is ~19 MiB and two passes — tens of milliseconds of pure
    // CPU — and this is the one unauthenticated path in the product that spends
    // it. The throttle above is keyed per username, and the equalisation the
    // comment describes means an UNKNOWN username still costs a full verify, so
    // a spray of distinct usernames is never throttled and never cheap. Held on
    // a worker thread that starves everything else sharing the runtime:
    // /healthz, the backup runner draining its pg_dump pipe, an in-flight
    // provision. spawn_blocking keeps the timing property exactly and moves the
    // cost somewhere it only competes with other blocking work — behind a
    // concurrency cap (CRYPTARCH-124), or the spray simply moves from starving
    // the workers to exhausting memory.
    let candidate = row.as_ref().filter(|u| u.is_active);
    let hash = candidate
        .map(|u| u.password_hash.to_string())
        .unwrap_or_else(|| auth::DUMMY_HASH.clone());
    // A panic in the hasher must not authenticate anybody; the helper maps it
    // to false.
    let password_ok = auth::verify_login_password(password, hash).await;

    let user = match candidate {
        Some(u) if password_ok => u.clone(),
        _ => {
            let n = state.login_throttle.record_failure(username);
            if n == THROTTLE_MAX_FAILURES {
                // The trip itself is the audit-worthy event; per-attempt
                // rows would just be noise an attacker controls.
                // No actor: nobody is signed in. The attempted name is the
                // target; as the actor, a crafted one could forge any actor,
                // a CRYPTARCH-146 tag included.
                provision::audit(&state.db, "(unauthenticated)", "login_throttled", Some(username), None)
                    .await;
            }
            return Err(LoginFailure::Invalid);
        }
    };
    state.login_throttle.clear(username);

    match state.sessions.insert_for_login(user.id, &user.password_hash).await {
        Ok(Some(token)) => Ok(token),
        // The password changed while this one was being checked.
        Ok(None) => Err(LoginFailure::Invalid),
        Err(e) => {
            tracing::error!("creating session for {}: {e:#}", user.username);
            Err(LoginFailure::Internal)
        }
    }
}

/// The session cookie for `token`, with the one set of flags every login path
/// uses. Secure deployments name it `__Host-…` (CRYPTARCH-150), which the
/// browser only accepts with exactly these: Secure, `Path=/`, no Domain.
pub fn session_cookie(state: &AppState, token: String) -> Cookie<'static> {
    Cookie::build((auth::session_cookie_name(state.secure_cookies), token))
        .path("/")
        .http_only(true)
        .secure(state.secure_cookies)
        .same_site(SameSite::Lax)
        .build()
}

/// The session token a request carries, read under this deployment's cookie
/// name only.
pub fn session_token(state: &AppState, jar: &axum_extra::extract::cookie::CookieJar) -> Option<String> {
    jar.get(auth::session_cookie_name(state.secure_cookies)).map(|c| c.value().to_owned())
}

/// A removal of the session cookie, matching how it was set (a `__Host-`
/// cookie is only replaced by one with the same Secure and Path=/).
pub fn session_cookie_removal(state: &AppState) -> Cookie<'static> {
    Cookie::build(auth::session_cookie_name(state.secure_cookies))
        .path("/")
        .secure(state.secure_cookies)
        .build()
}

// ---- dashboard (protected) --------------------------------------------------

/// One of the caller's databases, for the dashboard table.
#[derive(sqlx::FromRow, serde::Serialize)]
pub struct OwnedDbRow {
    pub name: String,
    pub status: String,
    pub server_name: String,
}

/// Everything the dashboard shows. One assembly
/// (CRYPTARCH-131), so the two cannot disagree about a quota.
pub struct DashboardData {
    pub dbs: Vec<OwnedDbRow>,
    /// Slots held, by the enforcer's own count.
    pub used: usize,
    /// `None` is unlimited.
    pub quota: Option<i32>,
    /// Whether to gate the "New database" action. False whenever either read
    /// failed: the authoritative check runs in `provision_db` regardless.
    pub at_cap: bool,
    /// Whether the list was read. False shows as "could not load", never as
    /// an empty list (CRYPTARCH-153).
    pub list_known: bool,
    /// Whether the quota and the slot count were both read. False shows as
    /// "unavailable", never as an unlimited account (CRYPTARCH-153).
    pub quota_known: bool,
}

pub async fn dashboard_data(state: &AppState, user_id: Uuid) -> DashboardData {
    let dbs = sqlx::query_as::<_, OwnedDbRow>(AssertSqlSafe(format!(
        // The predicate comes from `DbStatus`, not a literal (CRYPTARCH-111).
        // The row carries its status and the table badges it, so a database
        // being restored or deleted stays visible and says so — a database
        // that vanishes mid-restore is the opposite of the named-stages
        // promise the restore UI makes.
        "SELECT d.name, d.status, s.name AS server_name \
         FROM databases d JOIN managed_servers s ON s.id = d.server_id \
         WHERE d.owner_id = $1 AND {} ORDER BY d.created_at DESC",
        crate::status::DbStatus::visible_to_owner_sql()
    )))
    .bind(user_id)
    .fetch_all(&state.db)
    .await;
    let list_known = dbs.is_ok();
    let dbs = dbs.unwrap_or_default();

    // A transient read error must not masquerade as quota 0 and false-block
    // the "New database" button — the authoritative check runs transactionally
    // in provision_db regardless. On error, show the count and don't gate.
    let quota_read = sqlx::query_scalar::<_, Option<i32>>("SELECT db_quota FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&state.db)
        .await;
    let quota_known = quota_read.is_ok();
    let quota: Option<i32> = quota_read.unwrap_or(None);
    // Counted with the ENFORCER's rule, not the list's (CRYPTARCH-111).
    //
    // These are two different questions and it is easy to miss that they are:
    // the rows above answer "what do I show you", which includes a database
    // being restored or deleted, while this answers "how many slots are you
    // holding", which `provision_db` decides. Deriving `used` from the rendered
    // list conflated them, so a user with quota 2 and one `deleting` row saw
    // "1 in use / 2" with the button enabled, clicked it, and got "database
    // quota reached (2/2)". The display and the enforcer disagreed by
    // construction — the exact drift `provision.rs` warns about.
    //
    // And counted by the enforcer's own query, not by filtering the rows above
    // (CRYPTARCH-122): that agreed only while every visible status also held a
    // slot. On a read error, show the list's count and don't gate, for the
    // same reason as the quota read.
    let used_read = crate::provision::slots_used(&state.db, user_id).await;
    let used_known = used_read.is_ok();
    let used = used_read.map(|n| n.max(0) as usize).unwrap_or(dbs.len());
    let at_cap = quota_known && used_known && quota.is_some_and(|q| used >= q.max(0) as usize);
    DashboardData { dbs, used, quota, at_cap, list_known, quota_known: quota_known && used_known }
}

/// Every way to dial `d`, masked: the primary edge address first, then each
/// additional listener with its label (CRYPTARCH-40). Never a password — this
/// is the persistent view; the real credential is shown once and never again.
pub async fn masked_connections(state: &AppState, d: &provision::DbDetail) -> Vec<(String, String)> {
    let mut out = vec![("primary".to_string(), d.masked_conn())];
    for l in crate::servers::listeners_for(&state.db, d.server_id).await {
        out.push((l.label.clone(), d.masked_conn_at(&l.host, l.port)));
    }
    out
}

/// A database's contents from its managed server, or `None` when the server
/// did not answer within 3s. A VIEW must not wait out the whole engine budget;
/// the page says "unavailable" and the user refreshes. The Contents tab's
/// (CRYPTARCH-141), and called by nothing else — it is
/// a fresh TCP + SCRAM handshake per call (CRYPTARCH-115).
pub async fn db_contents(state: &AppState, d: &provision::DbDetail) -> Option<crate::engine::DbStats> {
    let engine = state.servers.get(d.server_id)?;
    tokio::time::timeout(std::time::Duration::from_secs(3), engine.stats(&d.name))
        .await
        .ok()
        .and_then(Result::ok)
}

/// Whether the server's rendered edge may not match what the bouncer is
/// enforcing. Unknown reads as in sync.
pub async fn edge_dirty(state: &AppState, server_id: Uuid) -> bool {
    sqlx::query_scalar("SELECT edge_dirty FROM managed_servers WHERE id = $1")
        .bind(server_id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .unwrap_or(false)
}

/// A named range an admin defined for a server (CRYPTARCH-39), offered on the
/// provision form as an opt-in checkbox.
#[derive(serde::Serialize, Clone)]
pub struct SourceOption {
    pub id: Uuid,
    pub label: String,
    pub cidr: String,
    pub is_default: bool,
}

/// A server a user may provision onto, with what the form needs about it.
/// Deliberately no address or credential of any kind: this goes to tenants.
#[derive(serde::Serialize, Clone)]
pub struct ServerOption {
    pub id: Uuid,
    pub name: String,
    pub engine: String,
    /// Pre-filled into "Allowed from" when the server has no named sources.
    pub default_cidr: Option<String>,
    /// Defaults first, then by label — the form's order.
    pub sources: Vec<SourceOption>,
}

/// The provision form's data.
pub async fn provision_options(state: &AppState) -> Vec<ServerOption> {
    let servers = state.servers.list();
    let cidr_rows: Vec<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT id, default_consumer_cidr::text FROM managed_servers",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    let server_ids: Vec<Uuid> = servers.iter().map(|s| s.id).collect();
    let sources: Vec<(Uuid, Uuid, String, String, bool)> = sqlx::query_as(
        "SELECT id, server_id, label, cidr::text, is_default FROM server_sources \
         WHERE server_id = ANY($1) ORDER BY is_default DESC, label",
    )
    .bind(&server_ids)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    servers
        .into_iter()
        .map(|s| ServerOption {
            default_cidr: cidr_rows
                .iter()
                .find(|(rid, _)| *rid == s.id)
                .and_then(|(_, c)| c.clone())
                .filter(|c| !c.is_empty()),
            sources: sources
                .iter()
                .filter(|(_, sid, ..)| *sid == s.id)
                .map(|(id, _, label, cidr, is_default)| SourceOption {
                    id: *id,
                    label: label.clone(),
                    cidr: cidr.clone(),
                    is_default: *is_default,
                })
                .collect(),
            id: s.id,
            name: s.name,
            engine: s.engine,
        })
        .collect()
}

/// A successful provision, with what the show-once screen says beside it.
pub struct ProvisionResult {
    pub done: provision::Provisioned,
    /// The same credential on every additional listener: (label, conn string).
    pub via: Vec<(String, String)>,
    /// Problems that did not stop the database being created, worded for the
    /// person who just created it.
    pub warnings: Vec<String>,
}

/// Provision on behalf of `session` — the one implementation behind the form
/// and `POST /api/v1/databases` (CRYPTARCH-131). Named sources are resolved
/// server-scoped: ids from another server's list resolve to nothing rather
/// than smuggling a foreign range in.
pub async fn provision_request(
    state: &AppState,
    session: &Session,
    server_id: Uuid,
    name: &str,
    allowed_from: Option<&str>,
    source_ids: &[Uuid],
) -> Result<ProvisionResult, ProvisionError> {
    // Named sources first (labels ride along as notes), then free-text extras.
    let named = crate::servers::resolve_sources(&state.db, server_id, source_ids).await;
    let mut acl: Vec<(String, Option<String>)> =
        named.into_iter().map(|(cidr, label)| (cidr, Some(label))).collect();
    for c in parse_allowed_from(allowed_from) {
        if !acl.iter().any(|(existing, _)| *existing == c) {
            acl.push((c, None));
        }
    }
    // Named sources included: one reaching 0.0.0.0 is still not a tenant's.
    // Invalid entries are left for provision_db to refuse as BadCidr.
    if !session.is_admin {
        let approved = crate::servers::approved_ranges(&state.db, server_id).await;
        if let Some((c, _)) = acl.iter().find(|(c, _)| {
            crate::servers::valid_cidr(c) && !crate::servers::tenant_may_allow(c, &approved)
        }) {
            return Err(ProvisionError::RangeTooBroad(c.clone()));
        }
    }
    let done = provision::provision_db(
        &state.db,
        &state.servers,
        session.user_id,
        &session.actor(),
        server_id,
        name.trim(),
        &acl,
    )
    .await
    .inspect_err(|e| {
        if matches!(e, ProvisionError::Internal) {
            tracing::error!("provision failed for {}: {e}", session.username);
        }
    })?;
    let mut warnings = Vec::new();
    if let Some(w) = sync_edge_note(state, server_id).await {
        warnings.push(w);
    }
    if acl.is_empty() {
        warnings.push(
            "No \"Allowed from\" sources were given — this database is unreachable at the \
             edge until you add one on its page."
                .into(),
        );
    }
    let via = listener_conn_strings(state, server_id, &done).await;
    Ok(ProvisionResult { done, via, warnings })
}

// ---- provisioning (protected) -----------------------------------------------

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
    use super::{parse_allowed_from, LoginThrottle, THROTTLE_MAX_TRACKED};

    /// Shutdown must stop the scheduler from STARTING work, not only wait for
    /// work already running (CRYPTARCH-123). The flag is how the scheduler
    /// learns that; this pins that drain is what raises it.
    #[tokio::test]
    async fn drain_marks_the_tracker_closing() {
        let jobs = super::JobTracker::default();
        assert!(!jobs.is_closing(), "premise: a fresh tracker is open for work");
        jobs.drain(std::time::Duration::from_millis(10)).await;
        assert!(jobs.is_closing(), "after drain the scheduler must see it is closing");
    }

    /// The positive half of drain: it returns as soon as the last job ends,
    /// not at the deadline. Measured against a deadline long enough that
    /// waiting it out would fail the test by a wide margin.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drain_returns_when_the_last_job_ends() {
        let jobs = super::JobTracker::default();
        let guard = jobs.start();
        assert_eq!(jobs.inflight(), 1, "premise: one job registered");
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            drop(guard);
        });
        let began = std::time::Instant::now();
        let finished = jobs.drain(std::time::Duration::from_secs(30)).await;
        assert!(finished, "drain must report that every job finished");
        assert!(
            began.elapsed() < std::time::Duration::from_secs(5),
            "drain waited {:?} — it should return when the job ends, not at the deadline",
            began.elapsed()
        );
    }

    #[test]
    fn throttle_map_is_bounded_under_username_spray() {
        let t = LoginThrottle::default();
        // A spray of distinct attacker-chosen usernames must not grow the map
        // past the ceiling.
        for i in 0..(THROTTLE_MAX_TRACKED + 500) {
            t.record_failure(&format!("sprayed_user_{i}"));
        }
        let len = t.0.lock().unwrap().len();
        assert!(len <= THROTTLE_MAX_TRACKED, "throttle map stayed bounded (was {len})");
    }

    #[test]
    fn throttle_trips_a_targeted_account_after_max_failures() {
        let t = LoginThrottle::default();
        assert!(!t.is_throttled("victim"));
        for _ in 0..super::THROTTLE_MAX_FAILURES {
            t.record_failure("victim");
        }
        assert!(t.is_throttled("victim"), "the targeted account trips at the cap");
        t.clear("victim");
        assert!(!t.is_throttled("victim"), "a successful login clears the trip");
    }

    /// The lost wakeup, made deterministic (CRYPTARCH-128). On a current-thread
    /// runtime the job can only end at drain's first await — so if drain reads
    /// the count and only registers for the wakeup after awaiting anything, the
    /// job's `notify_waiters` finds nobody listening and drain sits out its
    /// whole deadline. Registering first makes the same interleaving harmless.
    #[tokio::test(flavor = "current_thread")]
    async fn drain_hears_a_job_that_ends_at_its_first_await() {
        let jobs = super::JobTracker::default();
        let guard = jobs.start();
        tokio::spawn(async move {
            drop(guard);
        });
        let began = std::time::Instant::now();
        let finished = jobs.drain(std::time::Duration::from_secs(5)).await;
        assert!(finished, "drain missed the job ending and waited out its deadline");
        assert!(began.elapsed() < std::time::Duration::from_secs(1), "took {:?}", began.elapsed());
    }

    /// Pinned, with the SAME vector in frontend/src/lib/format.spec.ts, so the
    /// two UIs show one size during the migration. Exact .x5 ties round to
    /// even here (Rust's formatter) — 1280 B is 1.25 kB, shown as 1.2 — which
    /// JS's toFixed does not do (CRYPTARCH-141 audit).
    #[test]
    fn human_bytes_rounds_ties_to_even() {
        for (bytes, want) in [
            (0, "0 B"), (1023, "1023 B"), (1024, "1.0 kB"), (1280, "1.2 kB"), (1536, "1.5 kB"),
            (3328, "3.2 kB"), (3840, "3.8 kB"), (1_310_720, "1.2 MB"), (1_200_000, "1.1 MB"),
            (19 * 1024 * 1024, "19.0 MB"), (5 * 1024_i64.pow(4), "5.0 TB"),
            (1024 * 1024 - 1, "1024.0 kB"),
        ] {
            assert_eq!(super::human_bytes(bytes), want, "{bytes}");
        }
    }

    #[test]
    fn begin_refuses_new_jobs_once_closing() {
        let jobs = super::JobTracker::default();
        let first = jobs.begin();
        assert!(first.is_some(), "premise: an open tracker admits jobs");
        jobs.close();
        assert!(jobs.begin().is_none(), "a closing tracker must refuse new jobs");
        assert_eq!(jobs.inflight(), 1, "and a refused begin must not leak a count");
        drop(first);
        assert_eq!(jobs.inflight(), 0);
    }

    /// Concurrent guesses count against the limit while they are still being
    /// verified (CRYPTARCH-128). The positive half matters as much: slots come
    /// back when attempts finish without failing, or one burst of correct
    /// logins would lock an account out.
    #[test]
    fn in_flight_attempts_count_against_the_limit() {
        let t = LoginThrottle::default();
        let held: Vec<_> = (0..super::THROTTLE_MAX_FAILURES)
            .map(|i| t.begin("victim").unwrap_or_else(|| panic!("attempt {i} must be admitted")))
            .collect();
        assert!(t.begin("victim").is_none(), "the next concurrent attempt must be refused");
        assert!(t.begin("someone_else").is_some(), "the limit is per username");
        drop(held);
        assert!(t.begin("victim").is_some(), "finished attempts that did not fail free their slots");
    }

    #[test]
    fn recorded_failures_and_in_flight_attempts_add_up() {
        let t = LoginThrottle::default();
        for _ in 0..(super::THROTTLE_MAX_FAILURES - 1) {
            t.record_failure("victim");
        }
        let one = t.begin("victim").expect("one attempt left in the budget");
        assert!(t.begin("victim").is_none(), "four failures plus one in flight is the limit");
        drop(one);
        assert!(t.begin("victim").is_some(), "and the slot returns when it finishes");
    }

    #[test]
    fn throttle_spray_cannot_evict_a_tripped_victim() {
        let t = LoginThrottle::default();
        // Trip the victim, then flood far past the cap with fresh usernames.
        for _ in 0..super::THROTTLE_MAX_FAILURES {
            t.record_failure("victim");
        }
        assert!(t.is_throttled("victim"));
        for i in 0..(THROTTLE_MAX_TRACKED * 2) {
            t.record_failure(&format!("sprayed_{i}"));
        }
        // The spray evicts its own single-failure entries, never the victim —
        // otherwise the throttle would reset a real attacker's guess budget.
        assert!(t.is_throttled("victim"), "a tripped account survives a username spray");
        let len = t.0.lock().unwrap().len();
        assert!(len <= THROTTLE_MAX_TRACKED, "still bounded (was {len})");
    }

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

    /// The contents badge's three states, as data for both doors. No manifest
    /// is "unknown", never a clean bill of health; hazards are "needs care"
    /// with what they are; a manifest with none is "recorded".
    #[test]
    fn contents_summary_keeps_its_three_states_apart() {
        let row = |manifest: Option<serde_json::Value>| crate::backup::BackupRow {
            id: uuid::Uuid::nil(),
            created_at: chrono::Utc::now(),
            finished_at: None,
            size_bytes: None,
            status: "ok".into(),
            error: None,
            log: String::new(),
            verified_at: None,
            db_name: "x".into(),
            manifest,
        };
        let none = super::contents_summary(&row(None));
        assert_eq!(none.state, "unknown");
        assert!(none.detail.is_some(), "and says why");

        let hazardous = crate::manifest::tests::sample();
        assert!(hazardous.hazards.any(), "PRECONDITION: the sample has a hazard");
        let care = super::contents_summary(&row(Some(serde_json::to_value(&hazardous).unwrap())));
        assert_eq!(care.state, "needs_care");
        assert!(care.detail.as_deref().is_some_and(|d| d.contains("policy")), "{:?}", care.detail);

        let mut clean = hazardous;
        clean.hazards.policies.clear();
        assert!(!clean.hazards.any());
        let recorded = super::contents_summary(&row(Some(serde_json::to_value(&clean).unwrap())));
        assert_eq!((recorded.state, recorded.detail), ("recorded", None));
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

// ---- database detail + password reset (protected, owner-scoped) -------------

/// One ACL entry, for the Access tab.
#[derive(sqlx::FromRow, serde::Serialize)]
pub struct AclEntryRow {
    pub id: Uuid,
    pub cidr: String,
    pub created_by: String,
    /// A named source's label when the entry was born from one.
    pub note: Option<String>,
}

/// Rotate the password of the caller's OWN database: owner-scoped, admin
/// included — whoever holds the new password can read the data, so an admin
/// does not get to mint one for a tenant's database. `None` when the caller
/// does not own `name`; nothing has been asked of the server then.
pub async fn reset_request(
    state: &AppState,
    session: &Session,
    name: &str,
) -> Result<Option<(provision::Provisioned, Vec<(String, String)>)>, ProvisionError> {
    let Some(d) = provision::owned_db_detail(&state.db, session.user_id, name).await? else {
        return Ok(None);
    };
    if d.status != "active" {
        return Err(ProvisionError::NotActive(d.status));
    }
    let done =
        provision::reset_password(&state.db, &state.servers, session.user_id, &session.actor(), name)
            .await?;
    // The listener topology comes from the row resolved through owner_id +
    // name, so the strings can only ever be this caller's own database's.
    let via = listener_conn_strings(state, d.server_id, &done).await;
    Ok(Some((done, via)))
}

// ---- ACL management (owner OR admin) -----------------------------------------
//
// The domain half (`acl_*_entry`, `acl_list`); `api::acl` only renders the
// outcome (CRYPTARCH-142).

/// The longest note an entry may carry — a named source's label, whose own cap
/// this matches (admin_servers::source_add).
const ACL_NOTE_MAX: usize = 32;

/// Why an ACL change was refused.
#[derive(Debug)]
pub enum AclError {
    BadCidr(String),
    /// Wider than a non-admin may allow (CRYPTARCH-142).
    RangeTooBroad(String),
    BadNote,
    /// The entry is not on THIS database — gone already, never existed, or
    /// another database's (CRYPTARCH-116). Never reported as removed.
    NoSuchEntry,
    Internal,
}

impl std::fmt::Display for AclError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AclError::BadCidr(c) => write!(
                f,
                "'{c}' is not a valid IP or CIDR (no hostnames; prefixes need zero host bits)."
            ),
            AclError::RangeTooBroad(c) => f.write_str(&crate::servers::range_too_broad_message(c)),
            AclError::BadNote => write!(f, "A note is one line of at most {ACL_NOTE_MAX} characters."),
            AclError::NoSuchEntry => {
                write!(f, "That source is no longer allowed on this database — nothing was removed.")
            }
            AclError::Internal => write!(f, "Saving the change failed — the access rules are unchanged."),
        }
    }
}

/// The ACL of one database, by cidr.
pub async fn acl_list(db: &PgPool, database_id: Uuid) -> Result<Vec<AclEntryRow>, sqlx::Error> {
    sqlx::query_as::<_, AclEntryRow>(
        "SELECT id, cidr::text AS cidr, created_by, note FROM acl_entries \
         WHERE database_id = $1 ORDER BY cidr",
    )
    .bind(database_id)
    .fetch_all(db)
    .await
}

pub struct AclAdded {
    pub entry: AclEntryRow,
    /// False when the cidr was already allowed: `entry` is the existing row,
    /// nothing was written or audited (the edge is still re-synced).
    pub created: bool,
    /// The edge did not take the change; see [`sync_edge_note`].
    pub warning: Option<String>,
}

/// Allow `cidr` on an `authz_lookup`-resolved database.
pub async fn acl_add_entry(
    state: &AppState,
    session: &Session,
    lookup: &provision::DbLookup,
    name: &str,
    cidr: &str,
    note: Option<&str>,
) -> Result<AclAdded, AclError> {
    let cidr = cidr.trim();
    if !crate::servers::valid_cidr(cidr) {
        return Err(AclError::BadCidr(cidr.to_string()));
    }
    if !session.is_admin
        && !crate::servers::tenant_may_allow(cidr, &crate::servers::approved_ranges(&state.db, lookup.server_id).await)
    {
        return Err(AclError::RangeTooBroad(cidr.to_string()));
    }
    let note = note.map(str::trim).filter(|n| !n.is_empty());
    // A label, so one line of plain text: nothing that could break a config
    // line if a note is ever rendered into one.
    if note.is_some_and(|n| n.chars().count() > ACL_NOTE_MAX || n.chars().any(char::is_control)) {
        return Err(AclError::BadNote);
    }
    let internal = |e: sqlx::Error| {
        tracing::error!("acl add {name}/{cidr}: {e:#}");
        AclError::Internal
    };
    // Twice at most: an entry that conflicts on insert can be removed before
    // it is read back, and that is a reason to insert again, not a failure.
    let mut found = None;
    for _ in 0..2 {
        let mut tx = state.db.begin().await.map_err(internal)?;
        let inserted = sqlx::query_as::<_, AclEntryRow>(
            "INSERT INTO acl_entries (database_id, cidr, created_by, note) \
             VALUES ($1, $2::cidr, $3, $4) ON CONFLICT (database_id, cidr) DO NOTHING \
             RETURNING id, cidr::text AS cidr, created_by, note",
        )
        .bind(lookup.id)
        .bind(cidr)
        .bind(session.actor())
        .bind(note)
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?;
        if let Some(entry) = inserted {
            // The change and its audit row commit together (Security Spine 5).
            provision::audit_in(&mut tx, &session.actor(), "acl_add", Some(name), Some(cidr))
                .await
                .map_err(internal)?;
            tx.commit().await.map_err(internal)?;
            found = Some((entry, true));
            break;
        }
        drop(tx);
        let existing = sqlx::query_as::<_, AclEntryRow>(
            "SELECT id, cidr::text AS cidr, created_by, note FROM acl_entries \
             WHERE database_id = $1 AND cidr = $2::cidr",
        )
        .bind(lookup.id)
        .bind(cidr)
        .fetch_optional(&state.db)
        .await
        .map_err(internal)?;
        if let Some(entry) = existing {
            found = Some((entry, false));
            break;
        }
    }
    let Some((entry, created)) = found else {
        tracing::error!("acl add {name}/{cidr}: the entry kept vanishing between insert and read");
        return Err(AclError::Internal);
    };
    // Synced even when nothing changed: re-adding a source is how a tenant can
    // retry an edge that did not take (the out-of-sync banner says any
    // successful ACL change clears it). Not audited — nothing changed.
    let warning = sync_edge_note(state, lookup.server_id).await;
    if let Some(w) = &warning {
        tracing::warn!("acl add {name}: {w}");
    }
    Ok(AclAdded { entry, created, warning })
}

pub struct AclRemoved {
    pub cidr: String,
    pub warning: Option<String>,
}

/// Revoke one entry. Keyed on the database AND the entry, so an id from
/// another database removes nothing, and removing nothing is an error.
pub async fn acl_remove_entry(
    state: &AppState,
    session: &Session,
    lookup: &provision::DbLookup,
    name: &str,
    entry_id: Uuid,
) -> Result<AclRemoved, AclError> {
    // A failed revocation must never render as success.
    let internal = |e: sqlx::Error| {
        tracing::error!("acl remove {name}/{entry_id}: {e:#}");
        AclError::Internal
    };
    let mut tx = state.db.begin().await.map_err(internal)?;
    let cidr: String = sqlx::query_scalar(
        "DELETE FROM acl_entries WHERE id = $1 AND database_id = $2 RETURNING cidr::text",
    )
    .bind(entry_id)
    .bind(lookup.id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal)?
    .ok_or(AclError::NoSuchEntry)?;
    provision::audit_in(&mut tx, &session.actor(), "acl_remove", Some(name), Some(&cidr))
        .await
        .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    let warning = sync_edge_note(state, lookup.server_id).await;
    if let Some(w) = &warning {
        // sync_edge has marked the server edge_dirty; the page banners it.
        tracing::warn!("acl remove {name}: {w}");
    }
    Ok(AclRemoved { cidr, warning })
}

// ---- database lifecycle (owner OR admin) ------------------------------------

/// Why [`authz_lookup`] refused.
pub enum DbDenied {
    /// Exists, and is someone else's (403 — see the module docs).
    Forbidden,
    Missing,
    Internal,
}

/// The owner-or-admin scope: allowed if the caller owns `name` or is an admin.
pub async fn authz_lookup(
    state: &AppState,
    session: &Session,
    name: &str,
) -> Result<provision::DbLookup, DbDenied> {
    match provision::find_db(&state.db, name).await {
        Ok(Some(row)) if row.owner_id == session.user_id || session.is_admin => Ok(row),
        Ok(Some(_)) => Err(DbDenied::Forbidden),
        Ok(None) => Err(DbDenied::Missing),
        Err(_) => Err(DbDenied::Internal),
    }
}

/// Why a delete was refused.
#[derive(Debug)]
pub enum DeleteError {
    /// The typed name did not match — the one irreversible action is armed by
    /// typing it, and that is checked here, not by the page.
    ConfirmMismatch,
    /// A backup or restore of this database is running. A restore reaches its
    /// target by name; deleting under it and letting the name be taken loaded
    /// the old owner's data into the new tenant's database (S4f audit P1).
    JobRunning,
    Failed(ProvisionError),
}

/// Delete an `authz_lookup`-resolved database once `confirm` names it. Returns the
/// edge warning, if the edge did not take the change.
pub async fn delete_request(
    state: &AppState,
    session: &Session,
    lookup: &provision::DbLookup,
    name: &str,
    confirm: &str,
) -> Result<Option<String>, DeleteError> {
    if confirm.trim() != name {
        return Err(DeleteError::ConfirmMismatch);
    }
    // Under the job lock both claimers take: either a job's claim sees the
    // database no longer active and refuses, or this sees the job and refuses.
    let failed = |e: sqlx::Error| {
        tracing::error!("delete {name}: checking for running jobs: {e}");
        DeleteError::Failed(ProvisionError::Internal)
    };
    let mut tx = state.db.begin().await.map_err(failed)?;
    crate::backup::lock_db_jobs(&mut tx, name).await.map_err(failed)?;
    let busy: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM restores WHERE database_id = $1 AND status = 'running') \
             OR EXISTS (SELECT 1 FROM backups WHERE database_id = $1 AND status = 'running')",
    )
    .bind(lookup.id)
    .fetch_one(&mut *tx)
    .await
    .map_err(failed)?;
    if busy {
        return Err(DeleteError::JobRunning);
    }
    sqlx::query("UPDATE databases SET status = 'deleting', status_changed_at = now() WHERE id = $1")
        .bind(lookup.id)
        .execute(&mut *tx)
        .await
        .map_err(failed)?;
    tx.commit().await.map_err(failed)?;
    provision::delete_db(&state.db, &state.servers, lookup, name, &session.actor())
        .await
        .map_err(DeleteError::Failed)?;
    // acl_entries cascade with the databases row; re-render drops the lines,
    // KILL evicts anything still connected at the edge.
    let warning = sync_edge_note(state, lookup.server_id).await;
    if let Some(w) = &warning {
        tracing::warn!("delete {name}: {w}");
    }
    crate::acl::kill_db_sessions(&state.db, &state.crypto, lookup.server_id, name).await;
    Ok(warning)
}

// ---- rendering --------------------------------------------------------------

/// The contents badge as data, for both doors: `unknown` (with why),
/// `needs_care` (with what), or `recorded`. Three states, never two.
#[derive(serde::Serialize)]
pub struct ContentsSummary {
    pub state: &'static str,
    pub detail: Option<String>,
}

pub fn contents_summary(b: &crate::backup::BackupRow) -> ContentsSummary {
    match b.contents().hazards() {
        crate::manifest::Known::Unknown(why) => ContentsSummary { state: "unknown", detail: Some(why.to_string()) },
        crate::manifest::Known::Known(h) if h.any() => {
            ContentsSummary { state: "needs_care", detail: Some(hazard_summary(h)) }
        }
        crate::manifest::Known::Known(_) => ContentsSummary { state: "recorded", detail: None },
    }
}

/// Plain-language summary of why a backup needs care on restore.
fn hazard_summary(h: &crate::manifest::Hazards) -> String {
    let mut parts = Vec::new();
    let count = |n: usize, one: &str, many: &str| {
        (n > 0).then(|| format!("{n} {}", if n == 1 { one } else { many }))
    };
    parts.extend(count(h.force_rls_tables.len(), "table forces row-level security",
                       "tables force row-level security"));
    parts.extend(count(h.policies.len(), "row-level security policy",
                       "row-level security policies"));
    parts.extend(count(h.non_owner_grants.len(), "grant to another role",
                       "grants to other roles"));
    parts.extend(count(h.security_definer_functions.len(), "SECURITY DEFINER function",
                       "SECURITY DEFINER functions"));
    parts.extend(count(h.foreign_servers.len(), "foreign server", "foreign servers"));
    parts.extend(count(h.event_triggers.len(), "event trigger", "event triggers"));
    if parts.is_empty() {
        return "nothing that complicates a restore".into();
    }
    format!(
        "Restoring under a different role changes what these mean: {}.",
        parts.join(", ")
    )
}


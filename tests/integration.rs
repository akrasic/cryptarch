//! Integration tests: real HTTP through the real router against a throwaway
//! Postgres database (CRYPTARCH-23).
//!
//! Requires `CRYPTARCH_TEST_DSN` pointing at a Postgres superuser that can
//! CREATE DATABASE (the dev stack's works:
//! `postgres://postgres:devpass@localhost:55432/postgres`). When the variable
//! is unset every test skips with a note, so a bare `cargo test` stays green.
//!
//! Each test gets its own freshly-migrated database named
//! `cryptarch_test_<uuid>`; setup opportunistically drops leftovers from
//! crashed runs (plain DROP — in-use databases from parallel tests survive).

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use cryptarch::auth::{self, SessionStore};
use cryptarch::crypto::Crypto;
use cryptarch::engine::{ConnString, DbEngine, DbStats, DbUsage, ServerOverview, TableInfo};
use cryptarch::servers::ServerRegistry;
use cryptarch::web::{self, AppState};

const TEST_DSN_VAR: &str = "CRYPTARCH_TEST_DSN";

/// Test double for a managed server: no network, records every call.
struct TestEngine {
    calls: Mutex<Vec<String>>,
}

impl TestEngine {
    fn new() -> Arc<Self> {
        Arc::new(Self { calls: Mutex::new(Vec::new()) })
    }
    fn log(&self, s: String) {
        self.calls.lock().unwrap().push(s);
    }
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl DbEngine for TestEngine {
    fn kind(&self) -> &'static str {
        "postgres"
    }
    async fn ping(&self) -> anyhow::Result<()> {
        self.log("ping".into());
        Ok(())
    }
    async fn create_user_db(&self, name: &str, password: &str) -> anyhow::Result<ConnString> {
        self.log(format!("create:{name}"));
        Ok(ConnString(format!("postgresql://{name}:{password}@test-host:5432/{name}")))
    }
    async fn drop_user_db(&self, name: &str) -> anyhow::Result<()> {
        self.log(format!("drop:{name}"));
        Ok(())
    }
    async fn set_login(&self, name: &str, enabled: bool) -> anyhow::Result<()> {
        self.log(format!("set_login:{name}:{enabled}"));
        Ok(())
    }
    async fn rotate_password(&self, name: &str, password: &str) -> anyhow::Result<ConnString> {
        self.log(format!("rotate:{name}"));
        Ok(ConnString(format!("postgresql://{name}:{password}@test-host:5432/{name}")))
    }
    async fn stats(&self, name: &str) -> anyhow::Result<DbStats> {
        self.log(format!("stats:{name}"));
        Ok(DbStats {
            size_bytes: 19 * 1024 * 1024,
            active: true,
            tables: Some(vec![
                TableInfo { name: "app_events".into(), approx_rows: 15000, total_bytes: 7_500_000 },
                TableInfo { name: "shop_orders".into(), approx_rows: 8000, total_bytes: 1_200_000 },
                TableInfo { name: "never_analyzed".into(), approx_rows: -1, total_bytes: 8192 },
            ]),
        })
    }
    async fn server_overview(&self) -> anyhow::Result<ServerOverview> {
        self.log("server_overview".into());
        Ok(ServerOverview {
            version: "17.5 (Debian 17.5-1.pgdg120+1)".into(),
            uptime_secs: 3 * 86400 + 4 * 3600 + 120,
            total_connections: 12,
            max_connections: 100,
            databases: vec![
                DbUsage { name: "alice_dash".into(), size_bytes: 19 * 1024 * 1024, connections: 2 },
                DbUsage { name: "postgres".into(), size_bytes: 8 * 1024 * 1024, connections: 1 },
            ],
        })
    }
}

struct TestApp {
    router: Router,
    db: PgPool,
    engine: Arc<TestEngine>,
    servers: ServerRegistry,
    server_id: Uuid,
}

/// Build a full app against a fresh throwaway database, or None (skip) when
/// no test DSN is configured.
async fn test_app() -> Option<TestApp> {
    let Ok(admin_dsn) = std::env::var(TEST_DSN_VAR) else {
        eprintln!("skipping: {TEST_DSN_VAR} not set");
        return None;
    };
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_dsn)
        .await
        .expect("connecting to test admin DSN");

    // Best-effort cleanup of leftovers from prior crashed runs — exactly once
    // per process, and every test awaits it BEFORE creating its own database,
    // so the sweep can never race a sibling test's fresh db in this run.
    static CLEANUP: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
    CLEANUP
        .get_or_init(|| async {
            let leftovers: Vec<String> = sqlx::query_scalar(
                "SELECT datname FROM pg_database WHERE datname LIKE 'cryptarch_test_%'",
            )
            .fetch_all(&admin)
            .await
            .unwrap_or_default();
            for l in leftovers {
                let _ = sqlx::query(&format!("DROP DATABASE \"{l}\"")).execute(&admin).await;
            }
        })
        .await;

    let dbname = format!("cryptarch_test_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE \"{dbname}\""))
        .execute(&admin)
        .await
        .expect("creating throwaway database");
    let (base, _) = admin_dsn.rsplit_once('/').expect("DSN has a path");
    let dsn = format!("{base}/{dbname}");

    let db = PgPoolOptions::new()
        .max_connections(5)
        .connect(&dsn)
        .await
        .expect("connecting to throwaway database");
    cryptarch::MIGRATOR.run(&db).await.expect("running migrations");

    // Users: admin (quota 3) via the real bootstrap path, alice (2), bob (1).
    auth::bootstrap_admin(&db, "admin", "adminpw123", 3)
        .await
        .expect("bootstrapping admin");
    for (user, pw, quota) in [("alice", "alicepw123", 2), ("bob", "bobpw123", 1)] {
        let hash = auth::hash_password(pw).unwrap();
        sqlx::query("INSERT INTO users (username, password_hash, db_quota) VALUES ($1, $2, $3)")
            .bind(user)
            .bind(hash)
            .bind(quota)
            .execute(&db)
            .await
            .expect("inserting test user");
    }

    // One managed server backed by the recording TestEngine.
    let crypto = Crypto::from_hex_key(&"ab".repeat(32)).unwrap();
    let sealed = crypto.seal("postgres://unused").unwrap();
    let server_id: Uuid = sqlx::query_scalar(
        "INSERT INTO managed_servers (name, engine, host, port, admin_dsn_enc) \
         VALUES ('test-srv', 'postgres', 'test-host', 5432, $1) RETURNING id",
    )
    .bind(&sealed)
    .fetch_one(&db)
    .await
    .expect("inserting managed server");
    let engine = TestEngine::new();
    let servers = ServerRegistry::default();
    servers.register(server_id, "test-srv".into(), "postgres".into(), engine.clone());

    let state = AppState {
        sessions: SessionStore::new(db.clone()),
        db: db.clone(),
        servers: servers.clone(),
        crypto,
        secure_cookies: false,
        login_throttle: web::LoginThrottle::default(),
        allow_superuser: true,
        health: cryptarch::health::HealthRegistry::default(),
    };
    Some(TestApp { router: web::router(state), db, engine, servers, server_id })
}

/// Drive one request; returns (status, location-or-empty, body).
async fn send(
    router: &Router,
    method: &str,
    path: &str,
    cookie: Option<&str>,
    form: Option<String>,
) -> (StatusCode, String, String) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(c) = cookie {
        req = req.header(header::COOKIE, c);
    }
    let req = match form {
        Some(f) => req
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(f))
            .unwrap(),
        None => req.body(Body::empty()).unwrap(),
    };
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let location = resp
        .headers()
        .get(header::LOCATION)
        .map(|v| v.to_str().unwrap_or("").to_string())
        .unwrap_or_default();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024).await.unwrap();
    (status, location, String::from_utf8_lossy(&bytes).into_owned())
}

/// Log in and return the session Cookie header value.
async fn login(app: &TestApp, user: &str, pw: &str) -> String {
    let req = Request::builder()
        .method("POST")
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("username={user}&password={pw}")))
        .unwrap();
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "login for {user} should redirect");
    let set = resp
        .headers()
        .get(header::SET_COOKIE)
        .expect("login sets a session cookie")
        .to_str()
        .unwrap();
    set.split(';').next().unwrap().to_string()
}

fn provision_form(server_id: Uuid, name: &str, allowed: &str) -> String {
    format!("server_id={server_id}&name={name}&allowed_from={allowed}")
}

// ---- auth & gating ----------------------------------------------------------

#[tokio::test]
async fn login_rejects_bad_credentials_and_inactive_users() {
    let Some(app) = test_app().await else { return };
    let (st, _, body) =
        send(&app.router, "POST", "/login", None, Some("username=alice&password=wrong".into()))
            .await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.contains("Invalid credentials."), "wrong password is rejected");

    sqlx::query("UPDATE users SET is_active = FALSE WHERE username = 'alice'")
        .execute(&app.db)
        .await
        .unwrap();
    let (st, _, body) =
        send(&app.router, "POST", "/login", None, Some("username=alice&password=alicepw123".into()))
            .await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.contains("Invalid credentials."), "suspended user cannot log in");
}

#[tokio::test]
async fn unauthenticated_requests_redirect_to_login() {
    let Some(app) = test_app().await else { return };
    let (st, loc, _) = send(&app.router, "GET", "/dashboard", None, None).await;
    assert_eq!(st, StatusCode::SEE_OTHER);
    assert_eq!(loc, "/login");
}

#[tokio::test]
async fn admin_pages_are_gated_with_styled_403() {
    let Some(app) = test_app().await else { return };
    let alice = login(&app, "alice", "alicepw123").await;
    let (st, _, body) = send(&app.router, "GET", "/admin", Some(&alice), None).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert!(body.contains("Admins only"), "403 is a styled page, not bare text");
    assert!(body.contains("<html"), "styled page has full chrome");

    let admin = login(&app, "admin", "adminpw123").await;
    let (st, _, _) = send(&app.router, "GET", "/admin", Some(&admin), None).await;
    assert_eq!(st, StatusCode::OK);
}

// ---- provisioning lifecycle -------------------------------------------------

#[tokio::test]
async fn provision_lifecycle_create_reset_suspend_delete() {
    let Some(app) = test_app().await else { return };
    let alice = login(&app, "alice", "alicepw123").await;

    // Create: show-once page with the password, engine called, row present.
    let (st, _, body) = send(&app.router, "POST", "/provision", Some(&alice),
        Some(provision_form(app.server_id, "alice_app", "10.0.0.0/24"))).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.contains("Database ready"), "show-once page renders");
    assert!(body.contains("postgresql://alice_app:"), "conn string with real password shown");
    assert!(app.engine.calls().contains(&"create:alice_app".to_string()));
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM databases WHERE name = 'alice_app'")
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert_eq!(count, 1);

    // Detail page is owner-visible and masks the password.
    let (st, _, body) = send(&app.router, "GET", "/db/alice_app", Some(&alice), None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.contains("••••••••"), "detail page masks the password");

    // Reset: new show-once page, rotate recorded.
    let (st, _, body) =
        send(&app.router, "POST", "/db/alice_app/reset", Some(&alice), Some(String::new())).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.contains("New password"));
    assert!(app.engine.calls().contains(&"rotate:alice_app".to_string()));

    // Suspend: redirect with flash; engine set_login(false).
    let (st, loc, _) =
        send(&app.router, "POST", "/db/alice_app/suspend", Some(&alice), Some(String::new())).await;
    assert_eq!(st, StatusCode::SEE_OTHER);
    assert_eq!(loc, "/dashboard?ok=db_suspended");
    assert!(app.engine.calls().contains(&"set_login:alice_app:false".to_string()));

    // Delete with wrong confirmation: 400, styled re-render, row survives.
    let (st, _, body) = send(&app.router, "POST", "/db/alice_app/delete", Some(&alice),
        Some("confirm=nope".into())).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(body.contains("didn"), "confirm mismatch explains itself");
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM databases WHERE name = 'alice_app'")
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert_eq!(count, 1, "wrong confirmation must not delete");

    // Delete with the right confirmation: gone, engine drop recorded.
    let (st, loc, _) = send(&app.router, "POST", "/db/alice_app/delete", Some(&alice),
        Some("confirm=alice_app".into())).await;
    assert_eq!(st, StatusCode::SEE_OTHER);
    assert_eq!(loc, "/dashboard?ok=db_deleted");
    assert!(app.engine.calls().contains(&"drop:alice_app".to_string()));
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM databases WHERE name = 'alice_app'")
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert_eq!(count, 0);

    // Audit trail covered the whole arc.
    let actions: Vec<String> =
        sqlx::query_scalar("SELECT action FROM audit_log ORDER BY id")
            .fetch_all(&app.db)
            .await
            .unwrap();
    for needed in ["create_db", "reset_password", "suspend_db", "delete_db"] {
        assert!(
            actions.iter().any(|a| a.contains(needed)),
            "audit log records '{needed}' (has: {actions:?})"
        );
    }
}

#[tokio::test]
async fn provision_rejects_bad_names_and_keeps_form_state() {
    let Some(app) = test_app().await else { return };
    let alice = login(&app, "alice", "alicepw123").await;
    let (st, _, body) = send(&app.router, "POST", "/provision", Some(&alice),
        Some(provision_form(app.server_id, "BAD", "10.0.0.0/24"))).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.contains("database name must be"), "validation error shown");
    assert!(body.contains("value=\"BAD\""), "typed name survives the re-render");
    assert!(app.engine.calls().is_empty(), "engine untouched on validation failure");
}

// ---- quota ------------------------------------------------------------------

#[tokio::test]
async fn quota_is_enforced_at_cap() {
    let Some(app) = test_app().await else { return };
    let bob = login(&app, "bob", "bobpw123").await; // quota 1
    let (st, _, body) = send(&app.router, "POST", "/provision", Some(&bob),
        Some(provision_form(app.server_id, "bob_one", "10.0.0.0/24"))).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.contains("Database ready"));

    let (st, _, body) = send(&app.router, "POST", "/provision", Some(&bob),
        Some(provision_form(app.server_id, "bob_two", "10.0.0.0/24"))).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.contains("quota reached"), "second provision at quota 1 is refused");
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM databases d JOIN users u ON u.id = d.owner_id \
         WHERE u.username = 'bob'",
    )
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn quota_race_two_fast_clicks_cannot_exceed_cap() {
    let Some(app) = test_app().await else { return };
    let bob = login(&app, "bob", "bobpw123").await; // quota 1

    let a = send(&app.router, "POST", "/provision", Some(&bob),
        Some(provision_form(app.server_id, "bob_race_a", "10.0.0.0/24")));
    let b = send(&app.router, "POST", "/provision", Some(&bob),
        Some(provision_form(app.server_id, "bob_race_b", "10.0.0.0/24")));
    let ((sa, _, ba), (sb, _, bb)) = tokio::join!(a, b);
    assert_eq!(sa, StatusCode::OK);
    assert_eq!(sb, StatusCode::OK);

    let created: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM databases d JOIN users u ON u.id = d.owner_id \
         WHERE u.username = 'bob'",
    )
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(created, 1, "the same-transaction quota check must not race past the cap");
    let wins = [&ba, &bb].iter().filter(|b| b.contains("Database ready")).count();
    assert_eq!(wins, 1, "exactly one of the two clicks wins");
}

// ---- ownership & admin boundary ---------------------------------------------

#[tokio::test]
async fn ownership_scopes_pages_and_actions() {
    let Some(app) = test_app().await else { return };
    let alice = login(&app, "alice", "alicepw123").await;
    let bob = login(&app, "bob", "bobpw123").await;
    let admin = login(&app, "admin", "adminpw123").await;

    let (st, _, _) = send(&app.router, "POST", "/provision", Some(&alice),
        Some(provision_form(app.server_id, "alice_priv", "10.0.0.0/24"))).await;
    assert_eq!(st, StatusCode::OK);

    // Bob can't see alice's db page (owner-scoped 404, styled).
    let (st, _, body) = send(&app.router, "GET", "/db/alice_priv", Some(&bob), None).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert!(body.contains("No such database"));

    // Bob can't act on it either: styled 403.
    let (st, _, body) =
        send(&app.router, "POST", "/db/alice_priv/suspend", Some(&bob), Some(String::new())).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert!(body.contains("Not your database"));

    // Bob's dashboard doesn't list it.
    let (_, _, body) = send(&app.router, "GET", "/dashboard", Some(&bob), None).await;
    assert!(!body.contains("alice_priv"));

    // Admin CAN act on it, and is routed back to the admin table.
    let (st, loc, _) =
        send(&app.router, "POST", "/db/alice_priv/suspend", Some(&admin), Some(String::new()))
            .await;
    assert_eq!(st, StatusCode::SEE_OTHER);
    assert_eq!(loc, "/admin/databases?ok=db_suspended");
}

// ---- ACL validation ---------------------------------------------------------

#[tokio::test]
async fn acl_rejects_invalid_cidr_with_styled_400() {
    let Some(app) = test_app().await else { return };
    let alice = login(&app, "alice", "alicepw123").await;
    let (st, _, _) = send(&app.router, "POST", "/provision", Some(&alice),
        Some(provision_form(app.server_id, "alice_acl", "10.0.0.0/24"))).await;
    assert_eq!(st, StatusCode::OK);

    let (st, _, body) = send(&app.router, "POST", "/db/alice_acl/acl", Some(&alice),
        Some("cidr=not-an-ip".into())).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(body.contains("not a valid IP or CIDR"));
    assert!(body.contains("Allowed from"), "error re-renders the db page, not a dead end");

    let (st, loc, _) = send(&app.router, "POST", "/db/alice_acl/acl", Some(&alice),
        Some("cidr=10.9.8.0/24".into())).await;
    assert_eq!(st, StatusCode::SEE_OTHER);
    assert_eq!(loc, "/db/alice_acl?ok=source_added");
}

// ---- CSRF (cross-origin POST rejection) -------------------------------------

/// Like send(), but with explicit Host/Origin headers to simulate browsers.
async fn send_with_origin(
    router: &Router,
    path: &str,
    cookie: &str,
    form: &str,
    host: &str,
    origin: Option<&str>,
) -> (StatusCode, String) {
    let mut req = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::HOST, host)
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(o) = origin {
        req = req.header(header::ORIGIN, o);
    }
    let resp = router.clone().oneshot(req.body(Body::from(form.to_string())).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn cross_origin_posts_are_rejected() {
    let Some(app) = test_app().await else { return };
    let alice = login(&app, "alice", "alicepw123").await;
    let (st, _, _) = send(&app.router, "POST", "/provision", Some(&alice),
        Some(provision_form(app.server_id, "alice_csrf", "10.0.0.0/24"))).await;
    assert_eq!(st, StatusCode::OK);

    // A cross-site form post carries the attacker's Origin: blocked, no action.
    let (st, body) = send_with_origin(&app.router, "/db/alice_csrf/suspend", &alice,
        "", "cryptarch.test", Some("https://evil.example")).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert!(body.contains("Cross-site"), "styled cross-site rejection page");
    let status: String =
        sqlx::query_scalar("SELECT status FROM databases WHERE name = 'alice_csrf'")
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert_eq!(status, "active", "cross-origin POST must not suspend");

    // Same-origin browser post: allowed.
    let (st, _) = send_with_origin(&app.router, "/db/alice_csrf/suspend", &alice,
        "", "cryptarch.test", Some("http://cryptarch.test")).await;
    assert_eq!(st, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn headerless_scripted_posts_still_work() {
    let Some(app) = test_app().await else { return };
    let alice = login(&app, "alice", "alicepw123").await;
    // send() sets no Origin/Referer at all — the curl/monitoring case.
    let (st, _, body) = send(&app.router, "POST", "/provision", Some(&alice),
        Some(provision_form(app.server_id, "alice_curl", "10.0.0.0/24"))).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.contains("Database ready"));
}

// ---- login throttling -------------------------------------------------------

#[tokio::test]
async fn login_throttles_after_repeated_failures() {
    let Some(app) = test_app().await else { return };
    for _ in 0..5 {
        let (st, _, _) = send(&app.router, "POST", "/login", None,
            Some("username=bob&password=wrong".into())).await;
        assert_eq!(st, StatusCode::OK);
    }
    // Even the CORRECT password is refused while throttled.
    let (st, _, body) = send(&app.router, "POST", "/login", None,
        Some("username=bob&password=bobpw123".into())).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.contains("Too many failed attempts"), "throttle message shown (got: no match)");

    // Other users are unaffected (per-username, not global).
    let (st, _, _) = send(&app.router, "POST", "/login", None,
        Some("username=alice&password=alicepw123".into())).await;
    assert_eq!(st, StatusCode::SEE_OTHER);

    // The trip landed in the audit log.
    let throttled: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'login_throttled'",
    )
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert!(throttled >= 1);
}

// ---- user-side db view (v0.3 contents section) ------------------------------

#[tokio::test]
async fn db_page_shows_size_and_table_list() {
    let Some(app) = test_app().await else { return };
    let alice = login(&app, "alice", "alicepw123").await;
    let (st, _, _) = send(&app.router, "POST", "/provision", Some(&alice),
        Some(provision_form(app.server_id, "alice_view", "10.0.0.0/24"))).await;
    assert_eq!(st, StatusCode::OK);

    let (st, _, body) = send(&app.router, "GET", "/db/alice_view", Some(&alice), None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.contains("Contents"), "contents section renders");
    assert!(body.contains("19.0 MB"), "database size shown human-readable");
    assert!(body.contains("in use now"), "activity indicator shown");
    assert!(body.contains("app_events") && body.contains("shop_orders"), "tables listed");
    assert!(body.contains("15000"), "approximate row counts shown");
    assert!(body.contains("7.2 MB"), "table sizes humanized");
    // reltuples = -1 (never analyzed) renders as a dash, not -1.
    assert!(body.contains("never_analyzed"));
    assert!(!body.contains(">-1<"), "unanalyzed tables must not show -1");
    assert!(app.engine.calls().contains(&"stats:alice_view".to_string()));
}

#[tokio::test]
async fn db_page_degrades_when_server_is_wedged() {
    let Some(app) = test_app().await else { return };
    let alice = login(&app, "alice", "alicepw123").await;
    let (st, _, _) = send(&app.router, "POST", "/provision", Some(&alice),
        Some(provision_form(app.server_id, "alice_deg", "10.0.0.0/24"))).await;
    assert_eq!(st, StatusCode::OK);

    // Swap in a wedged engine AFTER provisioning succeeded.
    app_registry_register(&app, cryptarch::engine::TimeoutEngine::wrap(
        Arc::new(HangingEngine),
        std::time::Duration::from_millis(300),
    ));

    let started = std::time::Instant::now();
    let (st, _, body) = send(&app.router, "GET", "/db/alice_deg", Some(&alice), None).await;
    assert!(started.elapsed() < std::time::Duration::from_secs(5),
        "page must render fast with a wedged server");
    assert_eq!(st, StatusCode::OK, "the page itself still renders");
    assert!(body.contains("Contents unavailable"), "degraded note instead of broken section");
    assert!(body.contains("Allowed from"), "rest of the page is intact");
}

// ---- server dashboard (v0.3) ------------------------------------------------

#[tokio::test]
async fn server_detail_shows_dashboard() {
    let Some(app) = test_app().await else { return };
    let alice = login(&app, "alice", "alicepw123").await;
    // Provision so 'alice_dash' is cryptarch-managed on this server.
    let (st, _, _) = send(&app.router, "POST", "/provision", Some(&alice),
        Some(provision_form(app.server_id, "alice_dash", "10.0.0.0/24"))).await;
    assert_eq!(st, StatusCode::OK);

    let admin = login(&app, "admin", "adminpw123").await;
    let (st, _, body) = send(&app.router, "GET",
        &format!("/admin/servers/{}", app.server_id), Some(&admin), None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.contains("17.5"), "postgres version shown");
    assert!(body.contains("3d 4h"), "uptime humanized");
    assert!(body.contains("12 / 100"), "connection usage shown");
    assert!(body.contains("alice_dash") && body.contains("19.0 MB"), "per-db usage listed");
    assert!(body.contains("managed"), "cryptarch-managed databases are badged");
    assert!(app.engine.calls().contains(&"server_overview".to_string()));
}

#[tokio::test]
async fn server_detail_degrades_when_engine_is_wedged() {
    let Some(app) = test_app().await else { return };
    app_registry_register(&app, cryptarch::engine::TimeoutEngine::wrap(
        Arc::new(HangingEngine),
        std::time::Duration::from_millis(300),
    ));
    let admin = login(&app, "admin", "adminpw123").await;
    let started = std::time::Instant::now();
    let (st, _, body) = send(&app.router, "GET",
        &format!("/admin/servers/{}", app.server_id), Some(&admin), None).await;
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert_eq!(st, StatusCode::OK);
    assert!(body.contains("dashboard unavailable") || body.contains("Dashboard unavailable"),
        "degraded note instead of a broken page");
    assert!(body.contains("Listeners"), "rest of the page intact");
}

// ---- failure modes ----------------------------------------------------------

/// An engine whose every operation hangs forever — the unreachable/wedged
/// managed server.
struct HangingEngine;

#[async_trait::async_trait]
impl DbEngine for HangingEngine {
    fn kind(&self) -> &'static str {
        "postgres"
    }
    async fn create_user_db(&self, _: &str, _: &str) -> anyhow::Result<ConnString> {
        std::future::pending().await
    }
    async fn drop_user_db(&self, _: &str) -> anyhow::Result<()> {
        std::future::pending().await
    }
    async fn set_login(&self, _: &str, _: bool) -> anyhow::Result<()> {
        std::future::pending().await
    }
    async fn rotate_password(&self, _: &str, _: &str) -> anyhow::Result<ConnString> {
        std::future::pending().await
    }
    async fn stats(&self, _: &str) -> anyhow::Result<DbStats> {
        std::future::pending().await
    }
    async fn server_overview(&self) -> anyhow::Result<ServerOverview> {
        std::future::pending().await
    }
    async fn ping(&self) -> anyhow::Result<()> {
        std::future::pending().await
    }
}

#[tokio::test]
async fn hung_managed_server_fails_requests_fast_instead_of_hanging() {
    let Some(app) = test_app().await else { return };
    // Re-register the server with a hanging engine bounded at 300ms.
    app.engine.calls(); // keep the recording engine alive for other asserts
    let hanging = cryptarch::engine::TimeoutEngine::wrap(
        Arc::new(HangingEngine),
        std::time::Duration::from_millis(300),
    );
    // Fresh registry entry replaces the recording engine.
    let alice = login(&app, "alice", "alicepw123").await;
    // Reach into the same registry the router holds.
    // (register() on the same id replaces the engine.)
    app_registry_register(&app, hanging);

    let started = std::time::Instant::now();
    let (st, _, body) = send(&app.router, "POST", "/provision", Some(&alice),
        Some(provision_form(app.server_id, "alice_hang", "10.0.0.0/24"))).await;
    let elapsed = started.elapsed();

    assert!(elapsed < std::time::Duration::from_secs(5),
        "a wedged server must not hang the request (took {elapsed:?})");
    assert_eq!(st, StatusCode::OK, "failure re-renders the form, no dead end");
    assert!(body.contains("error") || body.contains("failed") || body.contains("respond"),
        "user sees an error, not silence");
    // Nothing half-provisioned survives.
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM databases WHERE name = 'alice_hang'")
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert_eq!(count, 0, "timed-out provisioning must not leave a metadata row");
}

fn app_registry_register(app: &TestApp, engine: Arc<dyn DbEngine>) {
    app.servers.register(app.server_id, "test-srv".into(), "postgres".into(), engine);
}

// ---- sessions ---------------------------------------------------------------

#[tokio::test]
async fn logout_revokes_the_session() {
    let Some(app) = test_app().await else { return };
    let alice = login(&app, "alice", "alicepw123").await;
    let (st, _, _) = send(&app.router, "GET", "/dashboard", Some(&alice), None).await;
    assert_eq!(st, StatusCode::OK);

    let (st, _, _) =
        send(&app.router, "POST", "/logout", Some(&alice), Some(String::new())).await;
    assert_eq!(st, StatusCode::SEE_OTHER);

    let (st, loc, _) = send(&app.router, "GET", "/dashboard", Some(&alice), None).await;
    assert_eq!(st, StatusCode::SEE_OTHER, "revoked cookie no longer authenticates");
    assert_eq!(loc, "/login");
}

// ---- bouncer knobs (CRYPTARCH-32) -------------------------------------------

/// Throwaway conf dir shaped like a bouncer's: pgbouncer.ini present (init's
/// guard requires it) with an auth_hba_file line for %include path derivation.
fn temp_conf_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("cryptarch_knobs_{}", Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("pgbouncer.ini"),
        "[databases]\n* = host=db port=5432\n\n[pgbouncer]\n\
         auth_hba_file = /etc/pgbouncer/pgbouncer_hba.conf\npool_mode = session\n",
    )
    .unwrap();
    dir
}

/// Edge-card save: points the server at a conf dir (CRYPTARCH-34 per-card).
fn edge_form(conf_dir: &std::path::Path) -> String {
    format!("tls_mode=off&backend_kind=docker&bouncer_conf_dir={}", conf_dir.display())
}

/// Pooling-card save with the four numeric knobs.
fn pooling_form(pool_mode: &str, pool_size: u32, user_conns: u32) -> String {
    format!(
        "pool_mode={pool_mode}&default_pool_size={pool_size}&max_client_conn=150\
         &max_db_connections=0&max_user_connections={user_conns}"
    )
}

#[tokio::test]
async fn settings_save_renders_knobs_file_next_to_hba() {
    let Some(app) = test_app().await else { return };
    let admin = login(&app, "admin", "adminpw123").await;
    let dir = temp_conf_dir();

    let (st, _, _) = send(&app.router, "POST",
        &format!("/admin/servers/{}/settings/edge", app.server_id),
        Some(&admin), Some(edge_form(&dir))).await;
    assert_eq!(st, StatusCode::OK);
    let (st, _, body) = send(&app.router, "POST",
        &format!("/admin/servers/{}/settings/pooling", app.server_id),
        Some(&admin), Some(pooling_form("transaction", 7, 9))).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.contains("edge synced"), "save must run an edge sync: {body}");

    let knobs = std::fs::read_to_string(dir.join("cryptarch_bouncer.ini"))
        .expect("knobs file rendered into conf dir");
    assert!(knobs.contains("pool_mode = transaction"));
    assert!(knobs.contains("default_pool_size = 7"));
    assert!(knobs.contains("max_client_conn = 150"));
    assert!(knobs.contains("max_user_connections = 9"));
    assert!(knobs.starts_with("; managed by cryptarch"), "checksum header present");
    assert!(dir.join("pgbouncer_hba.conf").is_file(), "hba rides the same sync");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn per_db_override_lands_in_users_section_and_audits() {
    let Some(app) = test_app().await else { return };
    let admin = login(&app, "admin", "adminpw123").await;
    let alice = login(&app, "alice", "alicepw123").await;
    let dir = temp_conf_dir();

    // Point the server at the conf dir. The edge card doesn't touch the DSN,
    // so the registered TestEngine survives the save.
    let (st, _, _) = send(&app.router, "POST",
        &format!("/admin/servers/{}/settings/edge", app.server_id),
        Some(&admin), Some(edge_form(&dir))).await;
    assert_eq!(st, StatusCode::OK);

    // A tenant to override.
    let (st, _, _) = send(&app.router, "POST", "/provision", Some(&alice),
        Some(provision_form(app.server_id, "alice_pool", "10.0.0.0/24"))).await;
    assert_eq!(st, StatusCode::OK);
    let db_id: Uuid = sqlx::query_scalar("SELECT id FROM databases WHERE name = 'alice_pool'")
        .fetch_one(&app.db)
        .await
        .unwrap();

    // Override: transaction mode, 5 connections.
    let (st, _, body) = send(&app.router, "POST",
        &format!("/admin/servers/{}/db/{}/knobs", app.server_id, db_id),
        Some(&admin), Some("pool_mode=transaction&max_connections=5".into())).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.contains("Override for alice_pool saved"), "notice names the db: {body}");

    let knobs = std::fs::read_to_string(dir.join("cryptarch_bouncer.ini")).unwrap();
    assert!(knobs.contains("[users]"));
    assert!(knobs.contains("alice_pool = pool_mode=transaction max_user_connections=5"));

    let audited: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'db_pool_override' AND target = 'alice_pool'",
    )
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(audited, 1, "override must audit");

    // Clearing back to inherit drops the [users] line entirely.
    let (st, _, _) = send(&app.router, "POST",
        &format!("/admin/servers/{}/db/{}/knobs", app.server_id, db_id),
        Some(&admin), Some("pool_mode=inherit&max_connections=".into())).await;
    assert_eq!(st, StatusCode::OK);
    let knobs = std::fs::read_to_string(dir.join("cryptarch_bouncer.ini")).unwrap();
    assert!(!knobs.contains("[users]"), "cleared override leaves no [users] section");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn db_knob_overrides_validate_and_scope_to_server() {
    let Some(app) = test_app().await else { return };
    let admin = login(&app, "admin", "adminpw123").await;
    let alice = login(&app, "alice", "alicepw123").await;
    let (st, _, _) = send(&app.router, "POST", "/provision", Some(&alice),
        Some(provision_form(app.server_id, "alice_val", "10.0.0.0/24"))).await;
    assert_eq!(st, StatusCode::OK);
    let db_id: Uuid = sqlx::query_scalar("SELECT id FROM databases WHERE name = 'alice_val'")
        .fetch_one(&app.db)
        .await
        .unwrap();

    // Out-of-range limit: friendly error, nothing stored.
    let (st, _, body) = send(&app.router, "POST",
        &format!("/admin/servers/{}/db/{}/knobs", app.server_id, db_id),
        Some(&admin), Some("pool_mode=inherit&max_connections=0".into())).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.contains("must be 1-10000"), "range error explains itself: {body}");
    let stored: Option<i32> =
        sqlx::query_scalar("SELECT max_connections FROM databases WHERE id = $1")
            .bind(db_id)
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert_eq!(stored, None);

    // A db id that isn't on this server: 404, not someone else's edit.
    let (st, _, _) = send(&app.router, "POST",
        &format!("/admin/servers/{}/db/{}/knobs", app.server_id, Uuid::new_v4()),
        Some(&admin), Some("pool_mode=session&max_connections=".into())).await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    // Non-admin: gated.
    let (st, _, _) = send(&app.router, "POST",
        &format!("/admin/servers/{}/db/{}/knobs", app.server_id, db_id),
        Some(&alice), Some("pool_mode=session&max_connections=".into())).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

// ---- per-user manage page (CRYPTARCH-36) ------------------------------------

#[tokio::test]
async fn user_manage_page_renders_and_quota_saves_land_back_on_it() {
    let Some(app) = test_app().await else { return };
    let admin = login(&app, "admin", "adminpw123").await;
    let alice_id: Uuid = sqlx::query_scalar("SELECT id FROM users WHERE username = 'alice'")
        .fetch_one(&app.db)
        .await
        .unwrap();

    let (st, _, body) = send(&app.router, "GET",
        &format!("/admin/users/{alice_id}"), Some(&admin), None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.contains("alice"), "page names the user");
    assert!(body.contains("Suspend account"), "access card present for others");
    assert!(body.contains("Database quota"), "quota card present");

    // Quota save redirects back to the manage page, not the list.
    let (st, loc, _) = send(&app.router, "POST",
        &format!("/admin/users/{alice_id}/quota"), Some(&admin),
        Some("quota=10".into())).await;
    assert_eq!(st, StatusCode::SEE_OTHER);
    assert_eq!(loc, format!("/admin/users/{alice_id}?ok=quota_set"));
    let stored: Option<i32> = sqlx::query_scalar("SELECT db_quota FROM users WHERE id = $1")
        .bind(alice_id)
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(stored, Some(10));

    // Own page: no suspend/reset controls, pointer to /profile instead.
    let admin_id: Uuid = sqlx::query_scalar("SELECT id FROM users WHERE username = 'admin'")
        .fetch_one(&app.db)
        .await
        .unwrap();
    let (st, _, body) = send(&app.router, "GET",
        &format!("/admin/users/{admin_id}"), Some(&admin), None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(!body.contains("Suspend account"), "no self-suspend");
    assert!(body.contains("/profile"), "points at profile for self");
}

// ---- named sources (CRYPTARCH-39) -------------------------------------------

#[tokio::test]
async fn named_sources_flow_admin_defines_user_opts_in() {
    let Some(app) = test_app().await else { return };
    let admin = login(&app, "admin", "adminpw123").await;
    let alice = login(&app, "alice", "alicepw123").await;

    // Admin defines two named sources; one default.
    let (st, _, body) = send(&app.router, "POST",
        &format!("/admin/servers/{}/sources", app.server_id), Some(&admin),
        Some("label=db+network&cidr=172.18.0.0/16&is_default=1".into())).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.contains("Named source added"), "{body}");
    let (st, _, _) = send(&app.router, "POST",
        &format!("/admin/servers/{}/sources", app.server_id), Some(&admin),
        Some("label=LAN&cidr=192.168.8.0/24".into())).await;
    assert_eq!(st, StatusCode::OK);

    // Provision form offers them, default pre-ticked.
    let (st, _, body) = send(&app.router, "GET", "/provision", Some(&alice), None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.contains("db network"), "sources rendered");
    assert!(body.contains("checked"), "default pre-ticked");

    // Alice provisions ticking both sources, no free text.
    let ids: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, label FROM server_sources WHERE server_id = $1")
        .bind(app.server_id)
        .fetch_all(&app.db)
        .await
        .unwrap();
    let form = format!(
        "server_id={}&name=alice_srcs&allowed_from=&{}",
        app.server_id,
        ids.iter().map(|(id, _)| format!("sources={id}")).collect::<Vec<_>>().join("&"),
    );
    let (st, _, body) = send(&app.router, "POST", "/provision", Some(&alice), Some(form)).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.contains("Database ready"), "{body}");

    // Both entries exist, labels carried into notes.
    let notes: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT a.note FROM acl_entries a JOIN databases d ON d.id = a.database_id \
         WHERE d.name = 'alice_srcs' ORDER BY a.cidr")
        .fetch_all(&app.db)
        .await
        .unwrap();
    assert_eq!(notes, vec![Some("db network".into()), Some("LAN".into())]);

    // A foreign source id resolves to nothing (server-scoped).
    let (st, _, body) = send(&app.router, "POST", "/provision", Some(&alice),
        Some(format!("server_id={}&name=alice_forgn&allowed_from=&sources={}",
                     app.server_id, Uuid::new_v4()))).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.contains("unreachable at the edge"),
        "unknown source id must yield zero entries, not a foreign range: {body}");
}

#[tokio::test]
async fn db_page_quick_add_allows_named_source_with_label() {
    let Some(app) = test_app().await else { return };
    let admin = login(&app, "admin", "adminpw123").await;
    let alice = login(&app, "alice", "alicepw123").await;
    let (st, _, _) = send(&app.router, "POST",
        &format!("/admin/servers/{}/sources", app.server_id), Some(&admin),
        Some("label=tailnet&cidr=100.64.0.0/10".into())).await;
    assert_eq!(st, StatusCode::OK);

    let (st, _, _) = send(&app.router, "POST", "/provision", Some(&alice),
        Some(provision_form(app.server_id, "alice_qa", "10.0.0.0/24"))).await;
    assert_eq!(st, StatusCode::OK);

    // Page offers the unallowed named range as a quick-add.
    let (st, _, body) = send(&app.router, "GET", "/db/alice_qa", Some(&alice), None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.contains("tailnet"), "quick-add offered: {body}");

    // Quick-add posts cidr+note; entry lands with the label.
    let (st, loc, _) = send(&app.router, "POST", "/db/alice_qa/acl", Some(&alice),
        Some("cidr=100.64.0.0/10&note=tailnet".into())).await;
    assert_eq!(st, StatusCode::SEE_OTHER);
    assert_eq!(loc, "/db/alice_qa?ok=source_added");
    let note: Option<String> = sqlx::query_scalar(
        "SELECT a.note FROM acl_entries a JOIN databases d ON d.id = a.database_id \
         WHERE d.name = 'alice_qa' AND a.cidr = '100.64.0.0/10'")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(note.as_deref(), Some("tailnet"));

    // Once allowed, it's no longer offered as a quick-add button.
    let (st, _, body) = send(&app.router, "GET", "/db/alice_qa", Some(&alice), None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(!body.contains("+ tailnet"), "allowed source drops out of quick-adds");
}

// ---- per-path connection strings (CRYPTARCH-40) ------------------------------

#[tokio::test]
async fn db_page_lists_one_connection_string_per_dial_path() {
    let Some(app) = test_app().await else { return };
    let admin = login(&app, "admin", "adminpw123").await;
    let alice = login(&app, "alice", "alicepw123").await;
    // Two extra dial paths beside the primary.
    for form in ["label=db+network&host=bouncer&port=6432", "label=LAN&host=192.168.8.14&port=6432"] {
        let (st, _, _) = send(&app.router, "POST",
            &format!("/admin/servers/{}/listeners", app.server_id),
            Some(&admin), Some(form.into())).await;
        assert_eq!(st, StatusCode::OK);
    }
    let (st, _, _) = send(&app.router, "POST", "/provision", Some(&alice),
        Some(provision_form(app.server_id, "alice_paths", "10.0.0.0/24"))).await;
    assert_eq!(st, StatusCode::OK);

    let (st, _, body) = send(&app.router, "GET", "/db/alice_paths", Some(&alice), None).await;
    assert_eq!(st, StatusCode::OK);
    for expected in [
        "postgresql://alice_paths:••••••••@test-host:5432/alice_paths",   // primary
        "postgresql://alice_paths:••••••••@bouncer:6432/alice_paths",     // in-stack
        "postgresql://alice_paths:••••••••@192.168.8.14:6432/alice_paths", // LAN
    ] {
        assert!(body.contains(expected), "missing dial path {expected}");
    }
    assert!(body.contains("db network") && body.contains("LAN"), "labels shown");
}

// ---- health + notifications (CRYPTARCH-43) -----------------------------------

/// Minimal one-shot HTTP sink: accepts one request, returns 200, hands back
/// the raw request text.
async fn http_sink() -> (String, tokio::task::JoinHandle<String>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 16384];
        let n = sock.read(&mut buf).await.unwrap();
        sock.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n").await.unwrap();
        String::from_utf8_lossy(&buf[..n]).into_owned()
    });
    (format!("http://{addr}/notify"), handle)
}

#[tokio::test]
async fn health_sweep_detects_edge_failure_and_notifies_webhook_once() {
    let Some(app) = test_app().await else { return };
    let state = test_state(&app);

    let (url, sink) = http_sink().await;
    let notifier = cryptarch::health::Notifier::from_config(Some(&url), "json");
    let registry = cryptarch::health::HealthRegistry::default();

    // test-srv advertises test-host:5432 — unresolvable, so the edge check
    // fails; the TestEngine ping succeeds; no conf dir → drift unknown.
    cryptarch::health::sweep(&state, &registry, &notifier).await;

    let h = registry.get(app.server_id).expect("swept");
    assert!(h.edge.is_err(), "unresolvable advertised address must fail");
    assert!(h.postgres.is_ok(), "test engine ping succeeds");
    assert!(h.drift.is_none(), "no conf dir → drift not checkable");

    // The webhook got exactly one JSON transition for the edge.
    let req = sink.await.unwrap();
    assert!(req.starts_with("POST /notify"), "{req}");
    assert!(req.contains("\"check\":\"edge\"") && req.contains("\"status\":\"failed\""), "{req}");

    // Audited as system.
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE actor = 'system' AND action = 'health_failed'")
        .fetch_one(&app.db).await.unwrap();
    assert_eq!(n, 1);

    // Second sweep: still red, still silent — no second notification, no
    // second audit row (transition-based alerting).
    cryptarch::health::sweep(&state, &registry, &cryptarch::health::Notifier::Disabled).await;
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE actor = 'system' AND action = 'health_failed'")
        .fetch_one(&app.db).await.unwrap();
    assert_eq!(n, 1, "steady red state must not re-audit");
}

/// Rebuild an AppState sharing the TestApp's internals (router holds its own
/// clone; sweep needs the state directly).
fn test_state(app: &TestApp) -> AppState {
    AppState {
        sessions: SessionStore::new(app.db.clone()),
        db: app.db.clone(),
        servers: app.servers.clone(),
        crypto: Crypto::from_hex_key(&"ab".repeat(32)).unwrap(),
        secure_cookies: false,
        login_throttle: web::LoginThrottle::default(),
        allow_superuser: true,
        health: cryptarch::health::HealthRegistry::default(),
    }
}

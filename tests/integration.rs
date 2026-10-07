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
//!
//! # `AssertSqlSafe` here means something weaker than it does in `src/`
//!
//! Fixtures build SQL by interpolation and so carry `AssertSqlSafe`, the same
//! marker the engine uses. It is not the same claim, and the difference is
//! worth keeping legible. In `src/` the wrapper is a security assertion resting
//! on `quote_ident` and the name allowlist (see the `engine::postgres` module
//! docs). Here the interpolands are hardcoded literals, UUID-derived suffixes,
//! or catalog reads filtered to this suite's own `cryptarch_test_%` prefix —
//! the test author *is* the attacker, so the wrapper is bookkeeping.
//!
//! The reason to say so out loud: if the two tiers look identical, the wrapper
//! starts reading as a rubber stamp, and that habit is harmless in a fixture
//! and dangerous in the engine. The two sites that read a value *out of* the
//! database rather than constructing it (the leftover-database sweep and the
//! role-preserve list) are the ones worth a second glance; both filter before
//! interpolating, and both quote the result.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use sqlx::postgres::PgPoolOptions;
use sqlx::AssertSqlSafe;
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
    /// What `login_states` reports. Empty by default.
    roles: Mutex<Vec<cryptarch::engine::RoleLogin>>,
    /// Databases the server claims to have. `None` = "everything exists",
    /// which is the default most tests want.
    existing: Mutex<Option<Vec<String>>>,
    /// What `claim_repair_attempt` returns: Some(true) won, Some(false)
    /// already spent, None = could not ask. Three states, kept apart on
    /// purpose — collapsing "could not ask" into "already spent" is the bug
    /// the caller is being tested for.
    claim: Mutex<Option<bool>>,
    /// How `stats` answers (CRYPTARCH-141).
    stats_mode: Mutex<StatsMode>,
    /// When set, `restore_stream` runs a stand-in tool that swallows the dump
    /// and exits 1 with this on stderr; unset, restores are unsupported.
    restore_stderr: Mutex<Option<String>>,
    /// When set, `login_states` and `database_exists` fail: a server that
    /// cannot be asked.
    checks_fail: Mutex<bool>,
    /// What `maintenance` reports; empty (the trait default) unless set.
    findings: Mutex<Vec<cryptarch::engine::MaintenanceFinding>>,
}

#[derive(Clone, Copy)]
enum StatsMode {
    /// Size, activity and a three-table list.
    Normal,
    /// The size was readable but the table list was not.
    NoTables,
    /// The server answered with an error.
    Fails,
}

impl TestEngine {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            roles: Mutex::new(Vec::new()),
            existing: Mutex::new(None),
            claim: Mutex::new(Some(true)),
            stats_mode: Mutex::new(StatsMode::Normal),
            restore_stderr: Mutex::new(None),
            checks_fail: Mutex::new(false),
            findings: Mutex::new(Vec::new()),
        })
    }
    fn set_findings(&self, findings: Vec<cryptarch::engine::MaintenanceFinding>) {
        *self.findings.lock().unwrap() = findings;
    }
    fn set_checks_fail(&self, fail: bool) {
        *self.checks_fail.lock().unwrap() = fail;
    }
    fn set_restore_failure(&self, stderr: &str) {
        *self.restore_stderr.lock().unwrap() = Some(stderr.to_string());
    }
    fn set_stats(&self, mode: StatsMode) {
        *self.stats_mode.lock().unwrap() = mode;
    }
    fn set_roles(&self, roles: Vec<(&str, bool)>) {
        *self.roles.lock().unwrap() = roles
            .into_iter()
            .map(|(role_name, can_login)| cryptarch::engine::RoleLogin {
                role_name: role_name.to_string(),
                can_login,
            })
            .collect();
    }
    fn set_existing(&self, names: Vec<&str>) {
        *self.existing.lock().unwrap() = Some(names.into_iter().map(String::from).collect());
    }
    fn set_claim(&self, outcome: Option<bool>) {
        *self.claim.lock().unwrap() = outcome;
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
    async fn maintenance(&self) -> anyhow::Result<cryptarch::engine::MaintenanceReport> {
        Ok(cryptarch::engine::MaintenanceReport { findings: self.findings.lock().unwrap().clone() })
    }
    async fn create_user_db(&self, name: &str, password: &str) -> anyhow::Result<ConnString> {
        self.log(format!("create:{name}"));
        Ok(ConnString(format!("postgresql://{name}:{password}@test-host:5432/{name}")))
    }
    async fn drop_user_db(&self, name: &str) -> anyhow::Result<()> {
        // Records the NOLOGIN as a separate call, so a test can assert the
        // fail-safe step happened and happened FIRST.
        self.log(format!("nologin:{name}"));
        self.log(format!("drop:{name}"));
        Ok(())
    }
    async fn enable_login(&self, name: &str) -> anyhow::Result<()> {
        self.log(format!("enable_login:{name}"));
        Ok(())
    }
    async fn login_states(&self, exclude: &[&str]) -> anyhow::Result<Vec<cryptarch::engine::RoleLogin>> {
        self.log(format!("login_states:exclude={}", exclude.join(",")));
        if *self.checks_fail.lock().unwrap() {
            anyhow::bail!("could not reach the server");
        }
        let all = self.roles.lock().unwrap().clone();
        // The real engine excludes in SQL; the double must too, or a test can
        // pass while the exclusion is broken.
        Ok(all.into_iter().filter(|r| !exclude.contains(&r.role_name.as_str())).collect())
    }
    async fn database_exists(&self, name: &str) -> anyhow::Result<bool> {
        self.log(format!("database_exists:{name}"));
        if *self.checks_fail.lock().unwrap() {
            anyhow::bail!("could not reach the server");
        }
        Ok(match self.existing.lock().unwrap().as_ref() {
            None => true,
            Some(list) => list.iter().any(|n| n == name),
        })
    }
    async fn claim_repair_attempt(&self, marker: &str, _comment: &str) -> anyhow::Result<bool> {
        self.log(format!("claim_repair_attempt:{marker}"));
        match *self.claim.lock().unwrap() {
            Some(won) => Ok(won),
            None => anyhow::bail!("could not reach the server"),
        }
    }
    async fn rotate_password(&self, name: &str, password: &str) -> anyhow::Result<ConnString> {
        self.log(format!("rotate:{name}"));
        Ok(ConnString(format!("postgresql://{name}:{password}@test-host:5432/{name}")))
    }
    async fn restore_stream(&self, name: &str) -> anyhow::Result<cryptarch::engine::RestoreSink> {
        self.log(format!("restore_stream:{name}"));
        let Some(stderr) = self.restore_stderr.lock().unwrap().clone() else {
            anyhow::bail!("this engine does not support restores yet");
        };
        let child = tokio::process::Command::new("sh")
            .args(["-c", "cat >/dev/null; printf '%s' \"$TEST_STDERR\" >&2; exit 1"])
            .env("TEST_STDERR", stderr)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()?;
        cryptarch::engine::RestoreSink::new(child, "test-restore".into())
    }
    async fn stats(&self, name: &str) -> anyhow::Result<DbStats> {
        self.log(format!("stats:{name}"));
        match *self.stats_mode.lock().unwrap() {
            StatsMode::Fails => anyhow::bail!("permission denied for database {name}"),
            StatsMode::NoTables => {
                return Ok(DbStats { size_bytes: 8192, active: false, tables: None });
            }
            StatsMode::Normal => {}
        }
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
    /// Throwaway backup root, so backup tests exercise the configured-and-
    /// enabled path rather than the "backups off" branch.
    backup_dir: std::path::PathBuf,
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
                let _ = sqlx::query(AssertSqlSafe(format!("DROP DATABASE \"{l}\""))).execute(&admin).await;
            }
        })
        .await;

    let dbname = format!("cryptarch_test_{}", Uuid::new_v4().simple());
    sqlx::query(AssertSqlSafe(format!("CREATE DATABASE \"{dbname}\"")))
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

    let backup_dir =
        std::env::temp_dir().join(format!("cryptarch-test-backups-{}", Uuid::new_v4()));
    let state = AppState {
        jobs: cryptarch::web::JobTracker::default(),
        sessions: SessionStore::new(db.clone()),
        db: db.clone(),
        servers: servers.clone(),
        crypto,
        secure_cookies: false,
        login_throttle: web::LoginThrottle::default(),
        allow_superuser: true,
        health: cryptarch::health::HealthRegistry::default(),
        backup_dir: Some(backup_dir.clone()),
        metrics_token: Some("test-scrape-token".into()),
        metadata_dsn: None,
    };
    Some(TestApp { router: web::router(state), db, engine, servers, server_id, backup_dir })
}

/// Cluster-scoped test objects, reset on construction.
///
/// # Why this exists rather than a convention
///
/// Three separate fixtures in this file were written non-idempotent, and all
/// three were found the same way: by deliberately breaking a fix to check the
/// test could fail, and then watching the *reverted* run fail too. The
/// failures were mutually indistinguishable and each pointed at the wrong
/// module.
///
/// The three modes, all of which this makes impossible:
///
/// 1. **Cleanup only on success.** A panicking run never reaches its trailing
///    cleanup, so the next run fails on leftovers — reporting the previous
///    failure forever, with a message about whatever the leftover breaks
///    rather than about the leftover. Here, cleanup runs *in the
///    constructor*: you cannot hold a fixture without having reset it.
/// 2. **One bad statement aborting the rest.** `DROP DATABASE` cannot run in a
///    transaction, and dropping something absent errors. Statements are run
///    one at a time and failures ignored — this is teardown, not a migration.
/// 3. **Cluster-scoped collateral.** Roles and databases are cluster-scoped,
///    not per-test-database, so a fixture using a *real* production constant
///    (as the repair-marker test must, to prove the real name is excluded)
///    can destroy real state. `preserve` records whether such an object
///    existed beforehand and puts it back.
struct ClusterFixture {
    admin: PgPool,
    statements: Vec<String>,
    /// (role name, existed before this fixture ran)
    preserve: Vec<(String, bool)>,
}

impl ClusterFixture {
    /// Reset `statements`, then hand back the guard. Cleanup has already run
    /// by the time you have one.
    async fn reset(admin: &PgPool, statements: &[&str], preserve_roles: &[&str]) -> Self {
        let mut preserve = Vec::new();
        for name in preserve_roles {
            let existed: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)",
            )
            .bind(*name)
            .fetch_one(admin)
            .await
            .unwrap_or(false);
            preserve.push((name.to_string(), existed));
        }
        let me = Self {
            admin: admin.clone(),
            statements: statements.iter().map(|s| s.to_string()).collect(),
            preserve,
        };
        me.wipe().await;
        me
    }

    async fn wipe(&self) {
        for stmt in &self.statements {
            // One at a time, failures ignored: absent objects are the normal
            // case, and DROP DATABASE refuses to run inside a transaction.
            let _ = sqlx::raw_sql(AssertSqlSafe(stmt.as_str())).execute(&self.admin).await;
        }
    }

    /// Wipe again and restore anything that pre-existed. Call at the end of a
    /// test; skipping it costs the next run nothing, because that run wipes
    /// first.
    async fn finish(&self) {
        self.wipe().await;
        for (name, existed) in &self.preserve {
            if *existed {
                let _ = sqlx::raw_sql(AssertSqlSafe(format!("CREATE ROLE \"{name}\" NOLOGIN;")))
                    .execute(&self.admin)
                    .await;
            }
        }
    }
}

/// A JSON API request (CRYPTARCH-130). Sends `Content-Type: application/json`
/// whenever there is a body, like the SPA's fetch wrapper does, and returns the
/// headers too — the API's no-store and cookie behaviour are part of what is
/// under test. A non-JSON body decodes to `Value::Null`.
async fn send_json(
    router: &Router,
    method: &str,
    path: &str,
    cookie: Option<&str>,
    body: Option<serde_json::Value>,
) -> (StatusCode, axum::http::HeaderMap, serde_json::Value) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(c) = cookie {
        req = req.header(header::COOKIE, c);
    }
    let req = match body {
        Some(b) => req
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(b.to_string()))
            .unwrap(),
        None => req.body(Body::empty()).unwrap(),
    };
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024).await.unwrap();
    (status, headers, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
}

/// Log in through the API and return the session cookie, as `login` does for
/// the maud form.
async fn api_login(app: &TestApp, user: &str, password: &str) -> String {
    let (st, h, body) = send_json(&app.router, "POST", "/api/v1/session", None,
        Some(serde_json::json!({"username": user, "password": password}))).await;
    assert_eq!(st, StatusCode::OK, "api login as {user}: {body}");
    let set = h.get(header::SET_COOKIE).expect("login sets the session cookie").to_str().unwrap();
    set.split(';').next().unwrap().to_string()
}

/// Log in and return the session Cookie header value. There is one door now
/// (CRYPTARCH-137): this is `api_login` under the name the older tests use.
async fn login(app: &TestApp, user: &str, pw: &str) -> String {
    api_login(app, user, pw).await
}

// ---- provisioning lifecycle -------------------------------------------------

/// The arc a database lives through, through the one door there is now.
/// The parts each have their own focused API test; this one keeps the
/// CRYPTARCH-78 tripwire: database suspend/resume is gone, and nothing in the
/// normal request path touches role login.
#[tokio::test]
async fn provision_lifecycle_create_reset_suspend_delete() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_app").await;
    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/databases/alice_app/reset", Some(&alice), Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::OK);
    assert!(app.engine.calls().contains(&"rotate:alice_app".to_string()), "premise: the arc ran");

    // Asserted rather than simply deleted: the routes were user-reachable, and
    // a quota bypass lived behind them (suspend dropped a db out of the active
    // count), so a re-introduction should fail a test rather than pass silently.
    for verb in ["suspend", "resume"] {
        let (st, _, _) = send_json(&app.router, "POST", &format!("/api/v1/databases/alice_app/{verb}"),
            Some(&alice), Some(serde_json::json!({}))).await;
        assert!(!st.is_success(), "/databases/{{name}}/{verb} must not exist ({st})");
    }
    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/databases/alice_app/delete", Some(&alice),
        Some(serde_json::json!({"confirm": "alice_app"}))).await;
    assert_eq!(st, StatusCode::OK);
    assert!(app.engine.calls().contains(&"drop:alice_app".to_string()));
    assert!(!app.engine.calls().iter().any(|c| c.starts_with("enable_login")),
            "nothing in the normal request path touches role login any more");
}

// ---- quota ------------------------------------------------------------------

/// The quota bypass that CRYPTARCH-78 *dissolved* rather than fixed: a user
/// cannot end up with more databases than their quota by any route, and no
/// row is parked outside the count — in ANY status, not only the active one
/// the enforcer's own predicate reads. Worth keeping because the restore work
/// reopens exactly this question: `restoring` must occupy a slot, or
/// drop-and-recreate becomes the same bypass with a new name.
#[tokio::test]
async fn no_route_lets_a_user_exceed_their_quota() {
    let Some(app) = test_app().await else { return };
    let bob = api_login(&app, "bob", "bobpw123").await; // quota 1
    api_provision(&app, &bob, "bob_first").await;
    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/databases", Some(&bob),
        Some(provision_body(app.server_id, "bob_second", "10.0.0.0/24"))).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("quota_reached")), "{body}");

    let counts: (i64, i64) = sqlx::query_as(
        "SELECT count(*), count(*) FILTER (WHERE d.status = 'active') FROM databases d \
         JOIN users u ON u.id = d.owner_id WHERE u.username = 'bob'",
    ).fetch_one(&app.db).await.unwrap();
    assert_eq!(counts, (1, 1), "no row parked in a non-active status either");
}

/// A name is unique across ALL servers (migration 0010), and the refusal
/// lands before any DDL on the second server.
#[tokio::test]
async fn db_name_is_unique_across_servers() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await; // quota 2
    api_provision(&app, &alice, "shared_name").await;

    let crypto = Crypto::from_hex_key(&"ab".repeat(32)).unwrap();
    let server2: Uuid = sqlx::query_scalar(
        "INSERT INTO managed_servers (name, engine, host, port, admin_dsn_enc) \
         VALUES ('test-srv-2', 'postgres', 'test-host-2', 5432, $1) RETURNING id",
    ).bind(crypto.seal("postgres://unused").unwrap()).fetch_one(&app.db).await.unwrap();
    let engine2 = TestEngine::new();
    app.servers.register(server2, "test-srv-2".into(), "postgres".into(), engine2.clone());

    // Alice still has quota to spare, so this is a name clash, not a quota block.
    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/databases", Some(&alice),
        Some(provision_body(server2, "shared_name", "10.0.0.0/24"))).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("name_taken")), "{body}");
    assert!(engine2.calls().is_empty(), "engine2 untouched — the insert failed before DDL");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM databases WHERE name = 'shared_name'")
        .fetch_one(&app.db).await.unwrap();
    assert_eq!(count, 1, "only the first database keeps the name");
}

// ---- CSRF (cross-origin rejection) ------------------------------------------

/// A JSON mutation with explicit Host/Origin headers, as a browser sends one.
async fn send_with_origin(router: &Router, path: &str, cookie: &str, host: &str, origin: Option<&str>) -> StatusCode {
    let mut req = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::HOST, host)
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(o) = origin {
        req = req.header(header::ORIGIN, o);
    }
    router.clone().oneshot(req.body(Body::from("{}")).unwrap()).await.unwrap().status()
}

/// The origin guard refuses another site's Origin AND lets this site's own
/// through. The second half is the one no other test can see: every
/// `send_json` sends no Origin at all, so a guard that refused even a
/// matching Origin would break the real SPA and pass every other test.
#[tokio::test]
async fn cross_origin_posts_are_rejected() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_csrf").await;

    // Password rotation is a real CSRF prize: it breaks every live client.
    let st = send_with_origin(&app.router, "/api/v1/databases/alice_csrf/reset", &alice,
        "cryptarch.test", Some("https://evil.example")).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert!(!app.engine.calls().contains(&"rotate:alice_csrf".to_string()),
            "a cross-origin request must not reach the engine");

    let st = send_with_origin(&app.router, "/api/v1/databases/alice_csrf/reset", &alice,
        "cryptarch.test", Some("http://cryptarch.test")).await;
    assert_eq!(st, StatusCode::OK, "this site's own request is let through");
    assert!(app.engine.calls().contains(&"rotate:alice_csrf".to_string()));
}

// ---- login throttling -------------------------------------------------------

/// Concurrent guesses are counted while they are still being verified
/// (CRYPTARCH-128). The throttle used to be checked before the Argon2 verify
/// and recorded after it, so any number of simultaneous guesses all passed the
/// check — the audit sent 40 at once and none were throttled. This drives the
/// real handler, so it also pins that the handler HOLDS its admission for the
/// whole attempt: binding it to `_` instead would drop it on the spot, and the
/// unit tests of the throttle itself would never notice.
#[tokio::test]
async fn concurrent_wrong_passwords_are_throttled_while_in_flight() {
    let Some(app) = test_app().await else { return };
    let attempts: Vec<_> = (0..12)
        .map(|_| {
            let router = app.router.clone();
            tokio::spawn(async move {
                send_json(&router, "POST", "/api/v1/session", None,
                    Some(serde_json::json!({"username": "carol_burst", "password": "wrong-guess"}))).await
            })
        })
        .collect();
    let (mut throttled, mut verified) = (0, 0);
    for a in attempts {
        let (st, _, body) = a.await.unwrap();
        match (st, body["error"]["code"].as_str()) {
            (StatusCode::TOO_MANY_REQUESTS, Some("throttled")) => throttled += 1,
            (StatusCode::UNAUTHORIZED, Some("invalid_credentials")) => verified += 1,
            other => panic!("unexpected answer {other:?}: {body}"),
        }
    }
    assert!(verified >= 1, "premise: some attempts really reached the verify ({verified})");
    assert!(verified <= 5, "at most the limit may be verified at once, {verified} were");
    assert_eq!(throttled + verified, 12, "every attempt is one or the other");
}

/// Mounted into the real router, the SPA shell keeps the CSP it computed — the
/// global CSP layer is if_not_present and must not overwrite it — while
/// everything else (the API, the probes) keeps the plain policy with no
/// script hashes (CRYPTARCH-129). The SPA is the whole UI at the root
/// (CRYPTARCH-137): any page path is the shell; old /app links redirect to the
/// same page, never off this host.
#[tokio::test]
async fn the_spa_shell_keeps_its_own_csp_inside_the_full_router() {
    let Some(app) = test_app().await else { return };
    let get = |path: &'static str| {
        let router = app.router.clone();
        async move { router.oneshot(Request::builder().uri(path).body(Body::empty()).unwrap()).await.unwrap() }
    };
    let csp = |r: &axum::response::Response| {
        r.headers().get(header::CONTENT_SECURITY_POLICY).map(|v| v.to_str().unwrap().to_string()).unwrap_or_default()
    };
    for page in ["/", "/login", "/dashboard", "/db/alice_db?tab=access", "/admin/servers"] {
        let r = get(page).await;
        assert_eq!(r.status(), StatusCode::OK, "{page}");
        assert!(csp(&r).contains("'sha256-"), "{page}: the shell's hashes were overwritten: {}", csp(&r));
    }
    let r = get("/healthz").await;
    assert!(csp(&r).contains("script-src 'self'") && !csp(&r).contains("sha256-"), "the rest keeps the plain policy: {}", csp(&r));

    for (old, new) in [("/app", "/"), ("/app/db/x?tab=backups", "/db/x?tab=backups"),
                       ("/app//evil.example/x", "/evil.example/x")] {
        let r = get(old).await;
        assert_eq!(r.status(), StatusCode::PERMANENT_REDIRECT, "{old}");
        assert_eq!(r.headers().get(header::LOCATION).unwrap(), new, "{old}");
    }
    // A form post to a page path is nobody's: the SPA only answers GET.
    let r = app.router.clone().oneshot(Request::builder().method("POST").uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from("username=admin&password=adminpw123")).unwrap()).await.unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    assert!(r.headers().get(header::SET_COOKIE).is_none(), "no session from the old form door");
}

// ---- the JSON API foundation (CRYPTARCH-130) -------------------------------

/// Unauthenticated API requests get 401 JSON — never the login-page redirect
/// the maud extractors answer with, which a fetch would silently follow and
/// then try to parse as data.
#[tokio::test]
async fn the_api_answers_401_json_not_a_redirect() {
    let Some(app) = test_app().await else { return };
    let (st, h, body) = send_json(&app.router, "GET", "/api/v1/session", None, None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert!(h.get(header::LOCATION).is_none(), "an API must not redirect to a login page");
    assert_eq!(body["error"]["code"], "unauthenticated", "{body}");
    // A cookie that names no session is no better than none.
    let (st, _, _) = send_json(&app.router, "GET", "/api/v1/session",
        Some("cryptarch_session=not-a-real-token"), None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

/// Log in, see who you are, log out — and the cookie the API sets carries the
/// same flags as the form login's.
#[tokio::test]
async fn an_api_session_logs_in_reports_itself_and_logs_out() {
    let Some(app) = test_app().await else { return };
    let (st, h, body) = send_json(&app.router, "POST", "/api/v1/session", None,
        Some(serde_json::json!({"username": "alice", "password": "alicepw123"}))).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["username"], "alice");
    assert_eq!(body["is_admin"], false);
    let set = h.get(header::SET_COOKIE).unwrap().to_str().unwrap().to_string();
    assert!(set.contains("HttpOnly") && set.contains("SameSite=Lax") && set.contains("Path=/"),
        "the API cookie must match the form login's flags: {set}");
    let cookie = set.split(';').next().unwrap().to_string();

    let (st, _, me) = send_json(&app.router, "GET", "/api/v1/session", Some(&cookie), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(me["username"], "alice");

    let (st, _, _) = send_json(&app.router, "DELETE", "/api/v1/session", Some(&cookie),
        Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (st, _, _) = send_json(&app.router, "GET", "/api/v1/session", Some(&cookie), None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "logout must kill the session server-side");
}

/// A wrong password and an unknown user are the same answer, and the API
/// login is held to the same throttle as the form: shared code, not a copy.
#[tokio::test]
async fn api_login_failures_are_uniform_and_throttled() {
    let Some(app) = test_app().await else { return };
    let try_login = |user: &'static str, pw: &'static str| {
        let router = app.router.clone();
        async move {
            send_json(&router, "POST", "/api/v1/session", None,
                Some(serde_json::json!({"username": user, "password": pw}))).await
        }
    };
    let (st_wrong, _, wrong) = try_login("bob", "wrong").await;
    let (st_ghost, _, ghost) = try_login("nobody_at_all", "wrong").await;
    assert_eq!(st_wrong, StatusCode::UNAUTHORIZED);
    assert_eq!((st_wrong, &wrong), (st_ghost, &ghost), "unknown user must look like a wrong password");
    for _ in 0..4 {
        try_login("bob", "wrong").await;
    }
    // The correct password, refused while throttled.
    let (st, _, body) = try_login("bob", "bobpw123").await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["error"]["code"], "throttled");
}

/// Every API response is no-store — successes, errors and refusals alike. The
/// API carries account data and, later, show-once credentials; none of it may
/// ever sit in a cache.
#[tokio::test]
async fn every_api_response_is_no_store() {
    let Some(app) = test_app().await else { return };
    let cookie = api_login(&app, "alice", "alicepw123").await;
    for (method, path, cookie, body) in [
        ("GET", "/api/v1/session", Some(cookie.as_str()), None),
        ("GET", "/api/v1/session", None, None),
        ("GET", "/api/v1/does-not-exist", Some(cookie.as_str()), None),
        ("POST", "/api/v1/session", None, Some(serde_json::json!({"username": "x", "password": "y"}))),
    ] {
        let (_, h, _) = send_json(&app.router, method, path, cookie, body).await;
        assert_eq!(h.get(header::CACHE_CONTROL).map(|v| v.to_str().unwrap()), Some("no-store"),
            "{method} {path}");
    }
}

/// CSRF for the API, two independent locks (dec D6). A cross-site Origin is
/// refused on every unsafe method, not just POST; and a mutating API request
/// must be JSON, which a cross-site form or "simple" fetch cannot send without
/// a CORS preflight that is never granted.
#[tokio::test]
async fn the_api_refuses_cross_site_and_non_json_mutations() {
    let Some(app) = test_app().await else { return };
    let cookie = api_login(&app, "alice", "alicepw123").await;
    for method in ["POST", "PUT", "PATCH", "DELETE"] {
        let req = Request::builder().method(method).uri("/api/v1/session")
            .header(header::HOST, "cryptarch.test")
            .header(header::ORIGIN, "https://evil.example")
            .header(header::COOKIE, &cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{}")).unwrap();
        let st = app.router.clone().oneshot(req).await.unwrap().status();
        assert_eq!(st, StatusCode::FORBIDDEN, "cross-site {method} must be refused");
    }
    // The cross-site refusal is the API's own JSON, not the maud HTML page —
    // on every method, and on the bare /api path too.
    for (method, path) in [("POST", "/api/v1/session"), ("PUT", "/api/v1/session"),
                           ("PATCH", "/api/v1/session"), ("DELETE", "/api/v1/session"),
                           ("POST", "/api")] {
        let req = Request::builder().method(method).uri(path)
            .header(header::HOST, "cryptarch.test")
            .header(header::ORIGIN, "https://evil.example")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{}")).unwrap();
        let resp = app.router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.headers().get(header::CACHE_CONTROL).unwrap(), "no-store", "{method} {path}");
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap())
            .unwrap_or_else(|_| panic!("{method} {path}: the refusal must be JSON"));
        assert_eq!(body["error"]["code"], "cross_site", "{method} {path}: {body}");
    }
    // Same-site but form-encoded: refused before any handler runs, on every
    // mutating method.
    for method in ["POST", "PUT", "PATCH", "DELETE"] {
        let req = Request::builder().method(method).uri("/api/v1/session")
            .header(header::COOKIE, &cookie)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from("")).unwrap();
        let st = app.router.clone().oneshot(req).await.unwrap().status();
        assert_eq!(st, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{method}");
    }
    // And with no content type at all — the shape of a "simple" cross-site POST.
    let req = Request::builder().method("POST").uri("/api/v1/session")
        .body(Body::from("username=alice&password=alicepw123")).unwrap();
    let st = app.router.clone().oneshot(req).await.unwrap().status();
    assert_eq!(st, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    // Premise: the session survived all of the above, so the refusals were
    // refusals rather than a logout that happened to return an error.
    let (st, _, _) = send_json(&app.router, "GET", "/api/v1/session", Some(&cookie), None).await;
    assert_eq!(st, StatusCode::OK);
}

/// A third CSRF lock (CRYPTARCH-138): the browser's own `Sec-Fetch-Site`.
/// SameSite cookies are no lock on a homelab — another port on the same host
/// is "same-site", and the audit had a page on :9911 get the Lax cookie
/// attached to POSTs to :8080. Only same-origin requests (and direct
/// navigation, "none") may reach the API; non-browser clients send nothing.
#[tokio::test]
async fn the_api_refuses_requests_a_browser_marks_as_from_another_site() {
    let Some(app) = test_app().await else { return };
    let cookie = api_login(&app, "alice", "alicepw123").await;
    let with_site = |site: Option<&'static str>| {
        let router = app.router.clone();
        let cookie = cookie.clone();
        async move {
            let mut req = Request::builder().uri("/api/v1/session").header(header::COOKIE, cookie);
            if let Some(s) = site {
                req = req.header("sec-fetch-site", s);
            }
            router.oneshot(req.body(Body::empty()).unwrap()).await.unwrap().status()
        }
    };
    assert_eq!(with_site(Some("same-origin")).await, StatusCode::OK, "premise: the app itself is let in");
    assert_eq!(with_site(Some("none")).await, StatusCode::OK);
    assert_eq!(with_site(None).await, StatusCode::OK, "non-browser clients send no such header");
    assert_eq!(with_site(Some("same-site")).await, StatusCode::FORBIDDEN);
    assert_eq!(with_site(Some("cross-site")).await, StatusCode::FORBIDDEN);
    // An allowlist, over every value: a combined header is foreign if any part is.
    assert_eq!(with_site(Some("cross-site, same-origin")).await, StatusCode::FORBIDDEN);
    assert_eq!(with_site(Some("something-new")).await, StatusCode::FORBIDDEN);
    // And on the methods that change things, not only on reads.
    let req = Request::builder().method("DELETE").uri("/api/v1/session")
        .header(header::COOKIE, &cookie)
        .header(header::CONTENT_TYPE, "application/json")
        .header("sec-fetch-site", "same-site")
        .body(Body::from("{}")).unwrap();
    assert_eq!(app.router.clone().oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);
    assert_eq!(with_site(Some("same-origin")).await, StatusCode::OK, "and the refused DELETE did not sign out");
}

/// Every way a request can go wrong still answers in the API's own shape,
/// uncacheable (CRYPTARCH-138): a malformed body, an oversized one, a wrong
/// method, and paths under /api the API does not know.
#[tokio::test]
async fn api_errors_are_always_json_and_no_store() {
    let Some(app) = test_app().await else { return };
    let raw = |method: &'static str, path: &'static str, body: String| {
        let router = app.router.clone();
        async move {
            let req = Request::builder().method(method).uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body)).unwrap();
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();
            let cache = resp.headers().get(header::CACHE_CONTROL).map(|v| v.to_str().unwrap().to_string());
            let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| panic!("{method} {path} → {status}: not JSON: {}", String::from_utf8_lossy(&bytes)));
            assert!(json["error"]["code"].is_string(), "{method} {path}: {json}");
            assert_eq!(cache.as_deref(), Some("no-store"), "{method} {path}");
            status
        }
    };
    assert_eq!(raw("POST", "/api/v1/session", "{not json".into()).await, StatusCode::BAD_REQUEST);
    assert_eq!(raw("POST", "/api/v1/session", r#"{"username": 1}"#.into()).await.as_u16() / 100, 4);
    let huge = format!(r#"{{"username":"{}","password":"x"}}"#, "a".repeat(200 * 1024));
    assert_eq!(raw("POST", "/api/v1/session", huge).await, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(raw("PUT", "/api/v1/session", "{}".into()).await, StatusCode::METHOD_NOT_ALLOWED);
    for path in ["/api/v1/", "/api/v1/nope", "/api", "/api/", "/api/v2/session"] {
        assert_eq!(raw("GET", path, String::new()).await, StatusCode::NOT_FOUND, "{path}");
    }
}

/// A username no account can have is refused before it reaches the throttle
/// (CRYPTARCH-138). The audit parked a 1.9 MB username in the throttle map for
/// five minutes per request — with a 4096-entry cap, gigabytes. Refused, it
/// also never accumulates: no amount of retrying gets it "throttled".
#[tokio::test]
async fn an_oversized_username_is_refused_without_being_tracked() {
    let Some(app) = test_app().await else { return };
    let long = "a".repeat(200);
    for _ in 0..7 {
        let (st, _, body) = send_json(&app.router, "POST", "/api/v1/session", None,
            Some(serde_json::json!({"username": long, "password": "x"}))).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body["error"]["code"], "invalid_credentials");
    }
}

/// Signing out through the API clears the cookie for the whole site, not just
/// for /api/v1 — the path the browser scopes a removal to when none is given.
#[tokio::test]
async fn api_sign_out_clears_the_cookie_at_the_site_root() {
    let Some(app) = test_app().await else { return };
    let cookie = api_login(&app, "alice", "alicepw123").await;
    let (st, h, _) = send_json(&app.router, "DELETE", "/api/v1/session", Some(&cookie),
        Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let set = h.get(header::SET_COOKIE).expect("sign-out clears the cookie").to_str().unwrap();
    assert!(set.starts_with("cryptarch_session=") && set.contains("Path=/;") || set.ends_with("Path=/"),
        "the removal must be scoped to Path=/: {set}");
}

/// CRYPTARCH-150: with secure cookies (the default) the session cookie is
/// `__Host-`-prefixed, and ONLY that name is read. A browser accepts a
/// `__Host-` cookie only from a secure origin, only host-only and only with
/// `Path=/` — so a plain-http service on the same host, or a sibling
/// subdomain, cannot plant a session the portal will honour. An unprefixed
/// cookie carrying a perfectly valid token is ignored: that is the planted
/// shape, and honouring it would undo the prefix.
#[tokio::test]
async fn a_secure_session_cookie_is_host_prefixed_and_only_that_name_is_read() {
    let Some(app) = test_app().await else { return };
    let mut st = test_state(&app);
    st.secure_cookies = true;
    let router = web::router(st);

    let (status, h, body) = send_json(&router, "POST", "/api/v1/session", None,
        Some(serde_json::json!({"username": "alice", "password": "alicepw123"}))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let set = h.get(header::SET_COOKIE).expect("login sets the cookie").to_str().unwrap().to_string();
    let attrs: Vec<&str> = set.split(';').map(str::trim).collect();
    assert!(attrs[0].starts_with("__Host-cryptarch_session="), "{set}");
    for needed in ["Secure", "HttpOnly", "Path=/", "SameSite=Lax"] {
        assert!(attrs.contains(&needed), "{needed} missing: {set}");
    }
    assert!(!attrs.iter().any(|a| a.to_ascii_lowercase().starts_with("domain=")), "a __Host- cookie has no Domain: {set}");
    let token = attrs[0].split_once('=').unwrap().1.to_string();

    let (status, _, _) = send_json(&router, "GET", "/api/v1/session", Some(&format!("__Host-cryptarch_session={token}")), None).await;
    assert_eq!(status, StatusCode::OK, "PRECONDITION: the prefixed cookie is a session");
    let (status, _, _) = send_json(&router, "GET", "/api/v1/session", Some(&format!("cryptarch_session={token}")), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "an unprefixed cookie is not read when cookies are secure");

    // Signing out clears the name in use, at the site root.
    let (status, h, _) = send_json(&router, "DELETE", "/api/v1/session",
        Some(&format!("__Host-cryptarch_session={token}")), Some(serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let cleared: Vec<String> = h.get_all(header::SET_COOKIE).iter().map(|v| v.to_str().unwrap().to_string()).collect();
    assert!(cleared.iter().any(|c| c.starts_with("__Host-cryptarch_session=") && c.contains("Path=/") && c.contains("Secure")),
        "the prefixed cookie is cleared (a __Host- removal must itself be Secure, Path=/): {cleared:?}");
    let (status, _, _) = send_json(&router, "GET", "/api/v1/session", Some(&format!("__Host-cryptarch_session={token}")), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "and the session is gone");

    // The rotated cookie a password change issues is prefixed too.
    let cookie = {
        let (_, h, _) = send_json(&router, "POST", "/api/v1/session", None,
            Some(serde_json::json!({"username": "alice", "password": "alicepw123"}))).await;
        h.get(header::SET_COOKIE).unwrap().to_str().unwrap().split(';').next().unwrap().to_string()
    };
    let (status, h, body) = send_json(&router, "POST", "/api/v1/me/password", Some(&cookie),
        Some(serde_json::json!({"current_password": "alicepw123", "new_password": "alicesnew123", "confirm_password": "alicesnew123"}))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(h.get(header::SET_COOKIE).unwrap().to_str().unwrap().starts_with("__Host-cryptarch_session="));
}

/// The dev mode (CRYPTARCH_INSECURE_COOKIES, plain http): a browser refuses a
/// `__Host-` cookie from a non-secure origin, so the name stays unprefixed —
/// and the prefixed one is not read there.
#[tokio::test]
async fn an_insecure_session_cookie_keeps_its_plain_name() {
    let Some(app) = test_app().await else { return };
    let (status, h, _) = send_json(&app.router, "POST", "/api/v1/session", None,
        Some(serde_json::json!({"username": "alice", "password": "alicepw123"}))).await;
    assert_eq!(status, StatusCode::OK);
    let set = h.get(header::SET_COOKIE).unwrap().to_str().unwrap().to_string();
    assert!(set.starts_with("cryptarch_session=") && !set.contains("Secure"), "{set}");
    let token = set.split(';').next().unwrap().split_once('=').unwrap().1;
    let (status, _, _) = send_json(&app.router, "GET", "/api/v1/session", Some(&format!("__Host-cryptarch_session={token}")), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---- S3: dashboard + provision through the API (CRYPTARCH-131) ------------

fn provision_body(server_id: Uuid, name: &str, allowed: &str) -> serde_json::Value {
    serde_json::json!({"server_id": server_id, "name": name, "allowed_from": allowed})
}

/// Provisioning returns the show-once credentials — and only here, only once:
/// the response is no-store and the password appears nowhere else afterwards.
#[tokio::test]
async fn api_provision_returns_the_credential_once() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    let (st, h, body) = send_json(&app.router, "POST", "/api/v1/databases", Some(&alice),
        Some(provision_body(app.server_id, "alice_api", "10.0.0.0/24"))).await;
    assert_eq!(st, StatusCode::CREATED, "{body}");
    assert_eq!(h.get(header::CACHE_CONTROL).unwrap(), "no-store");
    let password = body["password"].as_str().expect("the password is in the response").to_string();
    assert_eq!(password.len(), 32, "a generated 32-char password");
    assert_eq!(body["name"], "alice_api");
    assert_eq!(body["username"], "alice_api");
    assert!(body["conn"].as_str().unwrap().starts_with("postgresql://alice_api:"), "{body}");
    assert!(app.engine.calls().contains(&"create:alice_api".to_string()));

    // The list afterwards shows the database — and never its password.
    let (st, _, list) = send_json(&app.router, "GET", "/api/v1/databases", Some(&alice), None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(list["databases"].as_array().unwrap().iter().any(|d| d["name"] == "alice_api"), "{list}");
    assert!(!list.to_string().contains(&password), "the list must never carry a password");

    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE action = 'create_db' AND target = 'alice_api'")
        .fetch_one(&app.db).await.unwrap();
    assert_eq!(audited, 1, "provisioning is audited");
}

/// Names are validated before anything touches a server, and the refusal is a
/// 422 the form can show, not a 500.
#[tokio::test]
async fn api_provision_rejects_bad_names_before_the_engine() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    for name in ["BAD", "a", "x\"; DROP DATABASE postgres; --", "alice app", "1abc"] {
        let (st, _, body) = send_json(&app.router, "POST", "/api/v1/databases", Some(&alice),
            Some(provision_body(app.server_id, name, "10.0.0.0/24"))).await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{name}: {body}");
        assert_eq!(body["error"]["code"], "bad_name", "{name}");
    }
    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/databases", Some(&alice),
        Some(provision_body(app.server_id, "alice_cidr", "not-a-cidr"))).await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"]["code"], "bad_cidr");
    assert!(app.engine.calls().is_empty(), "the engine is untouched by refused requests");
}

/// The cap holds through the API, the dashboard says so, and two simultaneous
/// requests cannot both get past it.
#[tokio::test]
async fn api_quota_is_enforced_shown_and_race_free() {
    let Some(app) = test_app().await else { return };
    let bob = api_login(&app, "bob", "bobpw123").await; // quota 1
    let (_, _, before) = send_json(&app.router, "GET", "/api/v1/databases", Some(&bob), None).await;
    assert_eq!(before["quota"]["at_cap"], false, "premise: bob starts under his cap: {before}");

    let a = send_json(&app.router, "POST", "/api/v1/databases", Some(&bob),
        Some(provision_body(app.server_id, "bob_race_a", "10.0.0.0/24")));
    let b = send_json(&app.router, "POST", "/api/v1/databases", Some(&bob),
        Some(provision_body(app.server_id, "bob_race_b", "10.0.0.0/24")));
    let ((sa, _, ba), (sb, _, bb)) = tokio::join!(a, b);
    let statuses = [sa, sb];
    assert_eq!(statuses.iter().filter(|s| **s == StatusCode::CREATED).count(), 1,
        "exactly one wins: {ba} / {bb}");
    let (loser, loser_status) = if sa == StatusCode::CREATED { (&bb, sb) } else { (&ba, sa) };
    assert_eq!(loser_status, StatusCode::CONFLICT, "a quota refusal is a 409: {loser}");
    assert_eq!(loser["error"]["code"], "quota_reached", "the loser is refused for quota: {loser}");

    let (_, _, after) = send_json(&app.router, "GET", "/api/v1/databases", Some(&bob), None).await;
    assert_eq!(after["quota"]["used"], 1);
    assert_eq!(after["quota"]["limit"], 1);
    assert_eq!(after["quota"]["at_cap"], true, "{after}");
}

/// The quota lock, staged deterministically (CRYPTARCH-139). The race test
/// above cannot fail: password hashing and the unlocked pre-check spread two
/// requests apart, so it passed with `FOR UPDATE` deleted. Here a transaction
/// holds bob's user row and reserves his only slot inside it — the exact state
/// of a provision caught between its lock and its commit. Another provision
/// must WAIT on that lock, then count the committed slot and refuse.
#[tokio::test]
async fn a_provision_waits_for_an_in_flight_reservation_and_then_counts_it() {
    let Some(app) = test_app().await else { return };
    let bob = api_login(&app, "bob", "bobpw123").await; // quota 1
    let bob_id: Uuid = sqlx::query_scalar("SELECT id FROM users WHERE username = 'bob'")
        .fetch_one(&app.db).await.unwrap();

    let mut tx = app.db.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM users WHERE id = $1 FOR UPDATE")
        .bind(bob_id).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO databases (owner_id, server_id, name, password_hash, status) \
                 VALUES ($1, $2, 'bob_reserved', 'x', 'active')")
        .bind(bob_id).bind(app.server_id).execute(&mut *tx).await.unwrap();

    let claim = tokio::spawn({
        let router = app.router.clone();
        let server = app.server_id;
        async move {
            send_json(&router, "POST", "/api/v1/databases", Some(&bob),
                Some(provision_body(server, "bob_second", "10.0.0.0/24"))).await
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    assert!(!claim.is_finished(), "the provision must block on the user lock, not race past it");

    tx.commit().await.unwrap();
    let (st, _, body) = tokio::time::timeout(std::time::Duration::from_secs(15), claim)
        .await.expect("the provision proceeds once the lock is released").unwrap();
    assert_eq!(st, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"]["code"], "quota_reached", "having waited, it must count the slot: {body}");
    assert!(!app.engine.calls().contains(&"create:bob_second".to_string()));
}

/// Name collisions and an unknown server are answered with their own codes —
/// the form branches on them.
#[tokio::test]
async fn api_provision_names_its_other_refusals() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/databases", Some(&alice),
        Some(provision_body(app.server_id, "alice_dupe", "10.0.0.0/24"))).await;
    assert_eq!(st, StatusCode::CREATED, "premise: the first one is created");
    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/databases", Some(&alice),
        Some(provision_body(app.server_id, "alice_dupe", "10.0.0.0/24"))).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("name_taken")), "{body}");
    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/databases", Some(&alice),
        Some(provision_body(Uuid::new_v4(), "alice_nosrv", "10.0.0.0/24"))).await;
    assert_eq!((st, body["error"]["code"].as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, Some("no_server")), "{body}");
}

/// The dashboard lists the caller's databases only, and counts held slots the
/// way the enforcer does — a database being deleted still occupies one.
#[tokio::test]
async fn api_dashboard_is_owner_scoped_and_counts_like_the_enforcer() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    let bob = api_login(&app, "bob", "bobpw123").await;
    for (who, name) in [(&alice, "alice_one"), (&alice, "alice_two"), (&bob, "bob_only")] {
        let (st, _, body) = send_json(&app.router, "POST", "/api/v1/databases", Some(who),
            Some(provision_body(app.server_id, name, "10.0.0.0/24"))).await;
        assert_eq!(st, StatusCode::CREATED, "{name}: {body}");
    }
    sqlx::query("UPDATE databases SET status = 'deleting' WHERE name = 'alice_two'")
        .execute(&app.db).await.unwrap();

    let (_, _, list) = send_json(&app.router, "GET", "/api/v1/databases", Some(&alice), None).await;
    let names: Vec<&str> = list["databases"].as_array().unwrap().iter()
        .map(|d| d["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"alice_one") && names.contains(&"alice_two"), "{list}");
    assert!(!names.contains(&"bob_only"), "another user's database must not be listed: {list}");
    let deleting = list["databases"].as_array().unwrap().iter()
        .find(|d| d["name"] == "alice_two").unwrap();
    assert_eq!(deleting["status"], "deleting", "a database being deleted says so");
    assert_eq!(list["quota"]["used"], 2, "a deleting database still holds its slot: {list}");
    // Both reads were made, and the answer says so.
    assert_eq!(list["listed"], true, "{list}");
    assert_eq!(list["quota"]["known"], true, "{list}");
}

/// CRYPTARCH-153: a dashboard read that failed is reported as failed. It used
/// to come back as an empty list and an unlimited quota, which the page then
/// stated as fact ("No databases yet", "your account has no limit"): could not
/// look, shown as nothing there.
#[tokio::test]
async fn the_dashboard_says_when_it_could_not_read_rather_than_nothing_or_no_limit() {
    let Some(app) = test_app().await else { return };
    let alice: Uuid = sqlx::query_scalar("SELECT id FROM users WHERE username = 'alice'")
        .fetch_one(&app.db).await.unwrap();
    // Premise: with the metadata database there, both reads are made.
    let seen = web::dashboard_data(&test_state(&app), alice).await;
    assert!(seen.list_known && seen.quota_known, "PRECONDITION: a healthy read is known");

    let mut blind = test_state(&app);
    blind.db = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_secs(1))
        .connect_lazy("postgres://nobody:nothing@127.0.0.1:1/none")
        .unwrap();
    let d = web::dashboard_data(&blind, alice).await;
    assert!(!d.list_known, "an unread list must not pass for an empty one");
    assert!(!d.quota_known, "an unread quota must not pass for no limit");
    assert!(!d.at_cap, "and it gates nothing: provision_db enforces regardless");
}

/// The provision form's data: the servers, their named sources and default
/// range — and nothing an admin's DSN or a secret could be read from.
#[tokio::test]
async fn api_provision_options_carry_sources_and_no_secrets() {
    let Some(app) = test_app().await else { return };
    // Labels chosen so alphabetical order is the WRONG order: only the
    // defaults-first rule puts "zeta" ahead of "alpha".
    sqlx::query("INSERT INTO server_sources (server_id, label, cidr, is_default) \
                 VALUES ($1, 'zeta', '172.18.0.0/16', true), ($1, 'alpha', '192.168.8.0/24', false)")
        .bind(app.server_id).execute(&app.db).await.unwrap();
    let alice = api_login(&app, "alice", "alicepw123").await;
    let (st, _, body) = send_json(&app.router, "GET", "/api/v1/servers", Some(&alice), None).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let server = body["servers"].as_array().unwrap().iter()
        .find(|s| s["id"] == app.server_id.to_string()).expect("the test server is offered");
    let sources = server["sources"].as_array().unwrap();
    assert_eq!(sources.len(), 2, "{server}");
    assert_eq!(sources[0]["label"], "zeta", "defaults first, as on the form, not alphabetical");
    assert_eq!(sources[0]["is_default"], true);
    let text = body.to_string().to_lowercase();
    for leak in ["dsn", "password", "postgres://", "admin_", "\"host\"", "\"port\"", "test-host"] {
        assert!(!text.contains(leak), "provision options must not carry `{leak}`: {body}");
    }
    let keys: Vec<&String> = server.as_object().unwrap().keys().collect();
    assert_eq!(keys.len(), 5, "only id, name, engine, default_cidr, sources: {keys:?}");
}

/// Named sources are opted into by id, carry their label as the note, and an
/// id from anywhere else resolves to nothing rather than to a foreign range.
#[tokio::test]
async fn api_provision_resolves_named_sources_server_scoped() {
    let Some(app) = test_app().await else { return };
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "INSERT INTO server_sources (server_id, label, cidr, is_default) \
         VALUES ($1, 'db network', '172.18.0.0/16', true), ($1, 'LAN', '192.168.8.0/24', false) \
         RETURNING id")
        .bind(app.server_id).fetch_all(&app.db).await.unwrap();
    let alice = api_login(&app, "alice", "alicepw123").await;
    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/databases", Some(&alice),
        Some(serde_json::json!({"server_id": app.server_id, "name": "alice_srcs", "sources": ids}))).await;
    assert_eq!(st, StatusCode::CREATED, "{body}");
    let notes: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT a.note FROM acl_entries a JOIN databases d ON d.id = a.database_id \
         WHERE d.name = 'alice_srcs' ORDER BY a.cidr")
        .fetch_all(&app.db).await.unwrap();
    assert_eq!(notes, vec![Some("db network".into()), Some("LAN".into())]);

    // A REAL source id, from a second server: the only id that tests the
    // scoping — an unknown one resolves to nothing with or without it.
    let crypto = Crypto::from_hex_key(&"ab".repeat(32)).unwrap();
    let other_server: Uuid = sqlx::query_scalar(
        "INSERT INTO managed_servers (name, engine, host, port, admin_dsn_enc) \
         VALUES ('test-srv-foreign', 'postgres', 'foreign.invalid', 5432, $1) RETURNING id")
        .bind(crypto.seal("postgres://unused").unwrap()).fetch_one(&app.db).await.unwrap();
    let foreign: Uuid = sqlx::query_scalar(
        "INSERT INTO server_sources (server_id, label, cidr, is_default) \
         VALUES ($1, 'elsewhere', '10.99.0.0/16', true) RETURNING id")
        .bind(other_server).fetch_one(&app.db).await.unwrap();
    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/databases", Some(&alice),
        Some(serde_json::json!({"server_id": app.server_id, "name": "alice_forgn",
                                "sources": [foreign, Uuid::new_v4()]}))).await;
    assert_eq!(st, StatusCode::CREATED, "{body}");
    let entries: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM acl_entries a JOIN databases d ON d.id = a.database_id \
         WHERE d.name = 'alice_forgn'").fetch_one(&app.db).await.unwrap();
    assert_eq!(entries, 0, "another server's source, or an unknown id, must yield no entry");
    assert!(body["warnings"].as_array().unwrap().iter()
        .any(|w| w.as_str().unwrap().contains("unreachable at the edge")),
        "and the response says the database is unreachable: {body}");
}

// ---- S4a: the database view (CRYPTARCH-140) ---------------------------------

/// Provision `name` for `who` through the API and return the show-once password.
async fn api_provision(app: &TestApp, who: &str, name: &str) -> String {
    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/databases", Some(who),
        Some(provision_body(app.server_id, name, "10.0.0.0/24"))).await;
    assert_eq!(st, StatusCode::CREATED, "provisioning {name}: {body}");
    body["password"].as_str().unwrap().to_string()
}

/// The status, and body, each of three viewers gets for `path`: the owner,
/// another tenant, an admin. The start of the ownership table the later S4
/// slices extend with their own routes.
async fn as_owner_tenant_admin(
    app: &TestApp,
    owner: &str,
    tenant: &str,
    admin: &str,
    path: &str,
) -> [(StatusCode, serde_json::Value); 3] {
    let mut out = Vec::new();
    for who in [owner, tenant, admin] {
        let (st, _, body) = send_json(&app.router, "GET", path, Some(who), None).await;
        out.push((st, body));
    }
    out.try_into().unwrap()
}

/// The owner sees their database; another tenant gets exactly the answer a
/// name that does not exist gets, so the API cannot be used to learn which
/// names are taken; an admin sees anyone's (117: the maud page 404'd them).
#[tokio::test]
async fn the_database_view_is_owner_or_admin_and_never_confirms_a_name_to_others() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    let bob = api_login(&app, "bob", "bobpw123").await;
    let admin = api_login(&app, "admin", "adminpw123").await;
    let password = api_provision(&app, &alice, "alice_view").await;

    let [(own_st, own), (ten_st, ten), (adm_st, adm)] =
        as_owner_tenant_admin(&app, &alice, &bob, &admin, "/api/v1/databases/alice_view").await;
    assert_eq!(own_st, StatusCode::OK, "{own}");
    assert_eq!(own["name"], "alice_view");
    assert_eq!(own["is_owner"], true);
    assert_eq!(own["status"], "active");

    let (ghost_st, _, ghost) = send_json(&app.router, "GET",
        "/api/v1/databases/no_such_database", Some(&bob), None).await;
    assert_eq!(ten_st, StatusCode::NOT_FOUND, "{ten}");
    assert_eq!((ten_st, &ten), (ghost_st, &ghost),
        "another tenant must get the same answer as for a name that does not exist");

    assert_eq!(adm_st, StatusCode::OK, "an admin can open any database: {adm}");
    assert_eq!(adm["is_owner"], false, "and is told it is not theirs");
    assert_eq!(adm["owner"], "alice");

    // The plaintext is stored nowhere after it is shown, so its absence alone
    // proves little (the audit leaked the Argon2 hash past exactly that check).
    // The view is pinned instead: exactly these fields, and nothing hash-shaped.
    for body in [&own, &adm] {
        assert!(!body.to_string().contains(&password), "the view must never carry the password");
        assert!(!body.to_string().contains("$argon2"), "nor the stored hash: {body}");
        let mut keys: Vec<&str> = body.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(keys, ["backups_enabled", "connections", "created_at", "edge_dirty", "engine",
                          "is_owner", "name", "owner", "server_name", "status"], "{body}");
    }
}

/// Malformed names are answered like any other name that cannot exist, in the
/// API's own shape — never a plain-text 400 or an unlogged 500.
#[tokio::test]
async fn odd_database_names_get_the_api_error_shape() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    for path in ["/api/v1/databases/%FF", "/api/v1/databases/%00", "/api/v1/databases/x%00y"] {
        let (st, h, body) = send_json(&app.router, "GET", path, Some(&alice), None).await;
        assert!(st == StatusCode::NOT_FOUND || st == StatusCode::BAD_REQUEST, "{path}: {st}");
        assert!(body["error"]["code"].is_string(), "{path}: not the API error shape: {body}");
        assert_eq!(h.get(header::CACHE_CONTROL).unwrap(), "no-store", "{path}");
    }
}

/// Connection strings: one per dial path, labelled, always masked.
#[tokio::test]
async fn the_database_view_lists_masked_connection_strings_per_listener() {
    let Some(app) = test_app().await else { return };
    sqlx::query("INSERT INTO server_listeners (server_id, host, port, label) \
                 VALUES ($1, '10.1.2.3', 6432, 'lan'), ($1, 'fd00::7', 6432, 'tailnet')")
        .bind(app.server_id).execute(&app.db).await.unwrap();
    let alice = api_login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_conns").await;
    let (st, _, body) = send_json(&app.router, "GET", "/api/v1/databases/alice_conns", Some(&alice), None).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let conns = body["connections"].as_array().unwrap();
    let labels: Vec<&str> = conns.iter().map(|c| c["label"].as_str().unwrap()).collect();
    assert_eq!(labels, vec!["primary", "lan", "tailnet"], "{body}");
    // Exactly the masked form, nothing appended (CRYPTARCH-140 audit).
    let got: Vec<&str> = conns.iter().map(|c| c["conn"].as_str().unwrap()).collect();
    assert_eq!(got, [
        "postgresql://alice_conns:••••••••@test-host:5432/alice_conns",
        "postgresql://alice_conns:••••••••@10.1.2.3:6432/alice_conns",
        "postgresql://alice_conns:••••••••@[fd00::7]:6432/alice_conns",
    ]);
}

/// An edge the panel could not bring in sync is said, not hidden.
#[tokio::test]
async fn the_database_view_reports_an_out_of_sync_edge() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_edge").await;
    let (_, _, before) = send_json(&app.router, "GET", "/api/v1/databases/alice_edge", Some(&alice), None).await;
    assert_eq!(before["edge_dirty"], false, "premise: in sync to begin with");
    sqlx::query("UPDATE managed_servers SET edge_dirty = true WHERE id = $1")
        .bind(app.server_id).execute(&app.db).await.unwrap();
    let (_, _, after) = send_json(&app.router, "GET", "/api/v1/databases/alice_edge", Some(&alice), None).await;
    assert_eq!(after["edge_dirty"], true);
}

// ---- S4b: the Contents tab (CRYPTARCH-141) ---------------------------------

fn stats_calls(app: &TestApp, name: &str) -> usize {
    let want = format!("stats:{name}");
    app.engine.calls().iter().filter(|c| **c == want).count()
}

/// Contents are a round trip to the managed server, so they have an endpoint
/// of their own and nothing else pays for them (the CRYPTARCH-115 rule). The
/// precondition is that this endpoint DOES ask, or "the view does not ask"
/// would be satisfied by contents being broken.
#[tokio::test]
async fn contents_are_fetched_only_by_their_own_endpoint() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_contents").await;

    let before = stats_calls(&app, "alice_contents");
    let (st, _, _) = send_json(&app.router, "GET", "/api/v1/databases/alice_contents", Some(&alice), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(stats_calls(&app, "alice_contents"), before, "the view must not ask the server for contents");

    let (st, _, body) = send_json(&app.router, "GET", "/api/v1/databases/alice_contents/contents",
        Some(&alice), None).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(stats_calls(&app, "alice_contents"), before + 1, "PRECONDITION: contents does ask");
    assert_eq!(body["available"], true, "{body}");
    assert_eq!(body["size_bytes"], 19 * 1024 * 1024);
    assert_eq!(body["active"], true);
    let tables = body["tables"].as_array().expect("the table list was readable");
    assert_eq!(tables.len(), 3);
    assert_eq!(tables[0]["name"], "app_events");
    assert_eq!(tables[2]["approx_rows"], -1, "never-analyzed is passed through for the page to show as —");
}

/// Contents follow the view's posture: owner or admin; another tenant gets the
/// uniform 404 — and the server is never asked on their behalf.
#[tokio::test]
async fn contents_are_owner_or_admin_and_never_fetched_for_others() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    let bob = api_login(&app, "bob", "bobpw123").await;
    let admin = api_login(&app, "admin", "adminpw123").await;
    api_provision(&app, &alice, "alice_private").await;

    let before = stats_calls(&app, "alice_private");
    let (st, _, body) = send_json(&app.router, "GET", "/api/v1/databases/alice_private/contents",
        Some(&bob), None).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(stats_calls(&app, "alice_private"), before, "no round trip on another tenant's behalf");

    let (st, _, body) = send_json(&app.router, "GET", "/api/v1/databases/alice_private/contents",
        Some(&admin), None).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["available"], true);
}

/// The three shapes `tables` can take are kept apart (CRYPTARCH-141 audit):
/// absent when the server was unavailable, null when the size was readable but
/// the list was not, and a list otherwise. Collapsing "unreadable" into `[]`
/// would have the page invite the user to "create your first table".
#[tokio::test]
async fn contents_keep_unreadable_unavailable_and_empty_apart() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_shapes").await;
    let fetch = || send_json(&app.router, "GET", "/api/v1/databases/alice_shapes/contents", Some(&alice), None);

    app.engine.set_stats(StatsMode::NoTables);
    let (st, _, body) = fetch().await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["available"], true, "{body}");
    assert!(body.as_object().unwrap().contains_key("tables") && body["tables"].is_null(),
        "an unreadable list is null, not []: {body}");

    app.engine.set_stats(StatsMode::Fails);
    let (st, _, body) = fetch().await;
    assert_eq!(st, StatusCode::OK, "a server error is a degraded answer, not a 500: {body}");
    assert_eq!(body["available"], false);
    assert!(!body.as_object().unwrap().contains_key("tables"), "nothing to say when unavailable: {body}");
    assert_eq!(body.as_object().unwrap().len(), 1, "only `available`: {body}");
}

/// A managed server that does not answer gives a page that says so, quickly —
/// not an error, and not a request that waits out the whole engine budget.
/// The engine here is NOT timeout-wrapped, so the endpoint's own bound is what
/// is being tested.
#[tokio::test]
async fn contents_degrade_when_the_server_does_not_answer() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_slow").await;
    app_registry_register(&app, Arc::new(HangingEngine));

    let started = std::time::Instant::now();
    // Bounded from outside too, so a missing bound FAILS this test rather than
    // hanging it forever.
    let (st, _, body) = tokio::time::timeout(std::time::Duration::from_secs(10),
        send_json(&app.router, "GET", "/api/v1/databases/alice_slow/contents", Some(&alice), None))
        .await
        .expect("the contents request must be bounded — it hung");
    let took = started.elapsed();
    assert_eq!(st, StatusCode::OK, "an unanswered server is a degraded answer, not an error: {body}");
    assert_eq!(body["available"], false, "{body}");
    assert!(took < std::time::Duration::from_secs(6), "bounded, took {took:?}");
}

// ---- S4c: the Access tab (CRYPTARCH-142) -----------------------------------

/// The ACL rows on `name`, by cidr, straight from the table — what the edge is
/// rendered from, whatever any endpoint says.
async fn acl_rows(app: &TestApp, name: &str) -> Vec<(Uuid, String)> {
    sqlx::query_as("SELECT a.id, a.cidr::text FROM acl_entries a JOIN databases d ON d.id = a.database_id \
                    WHERE d.name = $1 ORDER BY a.cidr")
        .bind(name).fetch_all(&app.db).await.unwrap()
}

async fn audit_count(app: &TestApp, action: &str, target: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = $1 AND target = $2")
        .bind(action).bind(target).fetch_one(&app.db).await.unwrap()
}

/// The list carries the entries, and the server's named sources that are not
/// yet among them — the quick-add buttons. Exactly those fields.
#[tokio::test]
async fn acl_lists_entries_and_the_named_sources_not_yet_allowed() {
    let Some(app) = test_app().await else { return };
    sqlx::query("INSERT INTO server_sources (server_id, label, cidr, is_default) \
                 VALUES ($1, 'lan', '10.0.0.0/24', false), ($1, 'office', '192.168.5.0/24', false)")
        .bind(app.server_id).execute(&app.db).await.unwrap();
    let alice = api_login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_list").await;

    let (st, _, body) = send_json(&app.router, "GET", "/api/v1/databases/alice_list/acl", Some(&alice), None).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let entries = body["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "{body}");
    assert_eq!(entries[0]["cidr"], "10.0.0.0/24");
    assert_eq!(entries[0]["created_by"], "alice");
    let mut keys: Vec<&str> = entries[0].as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(keys, ["cidr", "created_by", "id", "note"]);
    // 'lan' is already allowed, so only 'office' is offered.
    let offered: Vec<&str> = body["unallowed_sources"].as_array().unwrap().iter()
        .map(|s| s["label"].as_str().unwrap()).collect();
    assert_eq!(offered, ["office"], "{body}");
    assert_eq!(body["unallowed_sources"][0]["cidr"], "192.168.5.0/24");
}

/// The owner or an admin may read and change the list. Another tenant gets the
/// database view's uniform 404 through the API (maud keeps its 403), and
/// nothing is written on their behalf — through either door. The precondition
/// for "bob changed nothing" is that the same request from admin DOES change
/// something.
#[tokio::test]
async fn acl_is_owner_or_admin_and_a_refused_change_writes_nothing() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    let bob = api_login(&app, "bob", "bobpw123").await;
    let admin = api_login(&app, "admin", "adminpw123").await;
    api_provision(&app, &alice, "alice_acl_authz").await;
    let path = "/api/v1/databases/alice_acl_authz/acl";

    let [(own, _), (ten, ten_body), (adm, _)] = as_owner_tenant_admin(&app, &alice, &bob, &admin, path).await;
    assert_eq!((own, ten, adm), (StatusCode::OK, StatusCode::NOT_FOUND, StatusCode::OK), "{ten_body}");
    let (ghost_st, _, ghost) = send_json(&app.router, "GET", "/api/v1/databases/no_such_db/acl", Some(&bob), None).await;
    assert_eq!((ten, &ten_body), (ghost_st, &ghost), "the same answer as a name that does not exist");

    let before = acl_rows(&app, "alice_acl_authz").await;
    let (st, _, body) = send_json(&app.router, "POST", path, Some(&bob),
        Some(serde_json::json!({"cidr": "10.9.9.0/24"}))).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "{body}");
    let (id, _) = before[0].clone();
    let (st, _, body) = send_json(&app.router, "DELETE", &format!("{path}/{id}"), Some(&bob),
        Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(acl_rows(&app, "alice_acl_authz").await, before, "a refused tenant changed the ACL");
    assert_eq!(audit_count(&app, "acl_add", "alice_acl_authz").await, 0);
    assert_eq!(audit_count(&app, "acl_remove", "alice_acl_authz").await, 0);

    // An admin acts on someone else's database, and is recorded as the actor.
    let (st, _, body) = send_json(&app.router, "POST", path, Some(&admin),
        Some(serde_json::json!({"cidr": "10.9.9.0/24"}))).await;
    assert_eq!(st, StatusCode::CREATED, "{body}");
    assert_eq!(body["entry"]["created_by"], "admin");
    assert_eq!(acl_rows(&app, "alice_acl_authz").await.len(), 2, "PRECONDITION: the request can change it");

    for path in ["/api/v1/databases/no_such_db/acl", "/api/v1/databases/%00/acl", "/api/v1/databases/x%00y/acl"] {
        let (st, _, body) = send_json(&app.router, "GET", path, Some(&alice), None).await;
        assert_eq!(st, StatusCode::NOT_FOUND, "{path}: {body}");
        let (st, _, body) = send_json(&app.router, "POST", path, Some(&alice),
            Some(serde_json::json!({"cidr": "10.9.9.0/24"}))).await;
        assert_eq!(st, StatusCode::NOT_FOUND, "{path}: {body}");
    }
}

/// Adding: the CIDR and the note are checked before anything is written, a
/// change is audited and its edge outcome reported, and adding what is already
/// there is answered as such — not audited as a change that never happened.
#[tokio::test]
async fn acl_add_validates_audits_and_reports_the_edge() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_add").await;
    let path = "/api/v1/databases/alice_add/acl";
    let before = acl_rows(&app, "alice_add").await;

    for (body, code) in [
        (serde_json::json!({"cidr": "not-an-ip"}), "bad_cidr"),
        (serde_json::json!({"cidr": "10.0.0.1/24"}), "bad_cidr"),
        (serde_json::json!({"cidr": "db.example.com"}), "bad_cidr"),
        (serde_json::json!({"cidr": "10.7.0.0/16", "note": "x".repeat(33)}), "bad_note"),
        (serde_json::json!({"cidr": "10.7.0.0/16", "note": "é".repeat(33)}), "bad_note"),
        (serde_json::json!({"cidr": "10.7.0.0/16", "note": "a\nhost all all 0.0.0.0/0 trust"}), "bad_note"),
        (serde_json::json!({"cidr": "10.7.0.0/16", "note": "tab\there"}), "bad_note"),
    ] {
        let (st, _, resp) = send_json(&app.router, "POST", path, Some(&alice), Some(body.clone())).await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{body}: {resp}");
        assert_eq!(resp["error"]["code"], code, "{body}: {resp}");
    }
    assert_eq!(acl_rows(&app, "alice_add").await, before, "a refused add wrote a row");

    let (st, _, resp) = send_json(&app.router, "POST", path, Some(&alice),
        Some(serde_json::json!({"cidr": " 10.7.0.0/16 ", "note": "  vpn  "}))).await;
    assert_eq!(st, StatusCode::CREATED, "{resp}");
    assert_eq!(resp["created"], true);
    assert_eq!(resp["entry"]["cidr"], "10.7.0.0/16");
    assert_eq!(resp["entry"]["note"], "vpn", "trimmed");
    assert!(resp["entry"]["id"].is_string());
    // The test server has no conf dir: the edge is not written, and saying
    // nothing would let the change look applied.
    assert!(resp["warning"].as_str().is_some_and(|w| w.contains("manually")), "{resp}");
    assert_eq!(audit_count(&app, "acl_add", "alice_add").await, 1);
    let detail: String = sqlx::query_scalar(
        "SELECT detail FROM audit_log WHERE action = 'acl_add' AND target = 'alice_add'")
        .fetch_one(&app.db).await.unwrap();
    assert_eq!(detail, "10.7.0.0/16");

    // The cap is characters, inclusive: 32 of them fit, however many bytes.
    for (cidr, note) in [("10.5.0.0/16", "x".repeat(32)), ("10.6.0.0/16", "é".repeat(32))] {
        let (st, _, resp) = send_json(&app.router, "POST", path, Some(&alice),
            Some(serde_json::json!({"cidr": cidr, "note": note}))).await;
        assert_eq!(st, StatusCode::CREATED, "{note}: {resp}");
        assert_eq!(resp["entry"]["note"], note.as_str());
    }

    // A blank note is no note.
    let (st, _, resp) = send_json(&app.router, "POST", path, Some(&alice),
        Some(serde_json::json!({"cidr": "10.8.0.0/16", "note": "   "}))).await;
    assert_eq!(st, StatusCode::CREATED, "{resp}");
    assert!(resp["entry"]["note"].is_null(), "{resp}");

    let (st, _, resp) = send_json(&app.router, "POST", path, Some(&alice),
        Some(serde_json::json!({"cidr": "10.7.0.0/16"}))).await;
    assert_eq!(st, StatusCode::OK, "already allowed is not a new entry: {resp}");
    assert_eq!(resp["created"], false, "{resp}");
    assert_eq!(resp["entry"]["note"], "vpn", "the existing entry, unchanged: {resp}");
    assert_eq!(audit_count(&app, "acl_add", "alice_add").await, 4, "the no-op add was audited");
    // Still synced: re-adding is how a tenant retries an edge that did not take.
    assert!(resp["warning"].as_str().is_some_and(|w| w.contains("manually")), "no-op add skipped the sync: {resp}");
}

/// Removal is keyed on the database AND the entry (CRYPTARCH-116): an entry id
/// from another database — even another of the caller's own — is not removed
/// through this one. The foreign row exists before and after, and removing it
/// through its own database works, so the refusal is not an id that could never
/// have matched.
#[tokio::test]
async fn acl_remove_is_scoped_to_its_own_database() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_one").await;
    api_provision(&app, &alice, "alice_two").await;
    let (foreign, cidr) = acl_rows(&app, "alice_two").await[0].clone();
    assert_eq!(cidr, "10.0.0.0/24", "PRECONDITION: alice_two has its entry");
    let (own, own_cidr) = acl_rows(&app, "alice_one").await[0].clone();
    assert_eq!(own_cidr, cidr, "PRECONDITION: both databases allow the same cidr");

    // Re-adding it to alice_one answers with alice_one's entry, never the
    // other database's row for the same cidr.
    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/databases/alice_one/acl", Some(&alice),
        Some(serde_json::json!({"cidr": cidr}))).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["entry"]["id"], own.to_string(), "answered with another database's entry: {body}");

    let (st, _, body) = send_json(&app.router, "DELETE",
        &format!("/api/v1/databases/alice_one/acl/{foreign}"), Some(&alice), Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(acl_rows(&app, "alice_two").await, vec![(foreign, cidr.clone())], "removed through the wrong database");
    assert_eq!(acl_rows(&app, "alice_one").await.len(), 1, "and nothing of alice_one's went instead");
    assert_eq!(audit_count(&app, "acl_remove", "alice_one").await, 0);

    let (st, _, body) = send_json(&app.router, "DELETE",
        &format!("/api/v1/databases/alice_two/acl/{foreign}"), Some(&alice), Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::OK, "PRECONDITION: the id is removable through its own database: {body}");
    assert_eq!(body["removed"], cidr);
    assert!(body["warning"].as_str().is_some_and(|w| w.contains("manually")), "{body}");
    assert!(acl_rows(&app, "alice_two").await.is_empty());
    assert_eq!(audit_count(&app, "acl_remove", "alice_two").await, 1);
    let detail: String = sqlx::query_scalar(
        "SELECT detail FROM audit_log WHERE action = 'acl_remove' AND target = 'alice_two'")
        .fetch_one(&app.db).await.unwrap();
    assert_eq!(detail, cidr, "the audit row names what was revoked");
}

/// Opening a database widely is an admin's call (Antun, 2026-10-06): a tenant
/// may allow /16 (IPv6 /48) or narrower, or exactly a range an admin configured
/// for the server (a named source, the default); anything reaching 0.0.0.0
/// never. The precondition for each refusal is that an admin's identical
/// request succeeds.
#[tokio::test]
async fn wide_ranges_are_an_admins_to_allow() {
    let Some(app) = test_app().await else { return };
    sqlx::query("INSERT INTO server_sources (server_id, label, cidr, is_default) \
                 VALUES ($1, 'corp', '10.0.0.0/8', false), ($1, 'anywhere', '0.0.0.0/0', false)")
        .bind(app.server_id).execute(&app.db).await.unwrap();
    sqlx::query("UPDATE managed_servers SET default_consumer_cidr = '172.16.0.0/12' WHERE id = $1")
        .bind(app.server_id).execute(&app.db).await.unwrap();
    let alice = api_login(&app, "alice", "alicepw123").await;
    let admin = api_login(&app, "admin", "adminpw123").await;
    api_provision(&app, &alice, "alice_wide").await;
    let path = "/api/v1/databases/alice_wide/acl";
    let add = |who: &str, cidr: &str| {
        let (who, body) = (who.to_string(), serde_json::json!({"cidr": cidr}));
        let router = app.router.clone();
        async move { send_json(&router, "POST", path, Some(&who), Some(body)).await }
    };

    let before = acl_rows(&app, "alice_wide").await;
    for cidr in ["0.0.0.0/0", "10.0.0.0/15", "128.0.0.0/1", "0.0.0.0/16", "::/0", "2001:db8::/32",
                 "::ffff:0.0.0.0/96"] {
        let (st, _, body) = add(&alice, cidr).await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{cidr}: {body}");
        assert_eq!(body["error"]["code"], "range_too_broad", "{cidr}: {body}");
    }
    assert_eq!(acl_rows(&app, "alice_wide").await, before, "a refused range was written");
    assert_eq!(audit_count(&app, "acl_add", "alice_wide").await, 0);

    // What a tenant may do alone: /16, /48, and exactly what an admin configured.
    for cidr in ["10.20.0.0/16", "2001:db8:7::/48", "10.0.0.0/8", "172.16.0.0/12"] {
        let (st, _, body) = add(&alice, cidr).await;
        assert_eq!(st, StatusCode::CREATED, "{cidr}: {body}");
    }

    // Quick-adds a tenant cannot use are not offered to them; the admin sees it.
    let (_, _, list) = send_json(&app.router, "GET", path, Some(&alice), None).await;
    let offered: Vec<&str> = list["unallowed_sources"].as_array().unwrap().iter()
        .map(|s| s["label"].as_str().unwrap()).collect();
    assert_eq!(offered, Vec::<&str>::new(), "{list}");
    let (_, _, list) = send_json(&app.router, "GET", path, Some(&admin), None).await;
    let offered: Vec<&str> = list["unallowed_sources"].as_array().unwrap().iter()
        .map(|s| s["label"].as_str().unwrap()).collect();
    assert_eq!(offered, ["anywhere"], "PRECONDITION: the source exists: {list}");

    // An admin may open it to everything.
    for cidr in ["0.0.0.0/0", "::/0"] {
        let (st, _, body) = add(&admin, cidr).await;
        assert_eq!(st, StatusCode::CREATED, "PRECONDITION: an admin may allow {cidr}: {body}");
    }
}

/// Provisioning is the other place a tenant picks ranges.
/// A refused range provisions nothing — no row, no engine call.
#[tokio::test]
async fn provisioning_applies_the_same_range_limit() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    let admin = api_login(&app, "admin", "adminpw123").await;
    let calls = app.engine.calls().len();

    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/databases", Some(&alice),
        Some(provision_body(app.server_id, "alice_open", "10.1.0.0/24, 0.0.0.0/0"))).await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"]["code"], "range_too_broad", "{body}");
    // Not only 0.0.0.0: anything wider than /16 is the admin's to allow.
    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/databases", Some(&alice),
        Some(provision_body(app.server_id, "alice_open", "10.0.0.0/8"))).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("range_too_broad")), "{body}");
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM databases WHERE name = 'alice_open'")
        .fetch_one(&app.db).await.unwrap();
    assert_eq!(rows, 0, "a refused provision left a row");
    assert_eq!(app.engine.calls().len(), calls, "a refused provision reached the engine");

    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/databases", Some(&admin),
        Some(provision_body(app.server_id, "admin_open", "0.0.0.0/0"))).await;
    assert_eq!(st, StatusCode::CREATED, "PRECONDITION: an admin may: {body}");
}

/// A change and its audit row commit together (Security Spine 5): when the
/// audit write fails, the change is refused and nothing is left behind. The
/// audit table is made to refuse ACL rows with a trigger; the precondition is
/// that the same requests succeed once it is gone.
#[tokio::test]
async fn an_acl_change_that_cannot_be_audited_does_not_happen() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_audited").await;
    let path = "/api/v1/databases/alice_audited/acl";
    let before = acl_rows(&app, "alice_audited").await;
    let (id, _) = before[0].clone();
    for sql in [
        "CREATE FUNCTION refuse_acl_audit() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN IF NEW.action LIKE 'acl_%' THEN RAISE EXCEPTION 'audit refused'; END IF; RETURN NEW; END $$",
        "CREATE TRIGGER refuse_acl_audit BEFORE INSERT ON audit_log \
         FOR EACH ROW EXECUTE FUNCTION refuse_acl_audit()",
    ] {
        sqlx::query(AssertSqlSafe(sql)).execute(&app.db).await.unwrap();
    }

    let (st, _, body) = send_json(&app.router, "POST", path, Some(&alice),
        Some(serde_json::json!({"cidr": "10.4.0.0/16"}))).await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    let (st, _, body) = send_json(&app.router, "DELETE", &format!("{path}/{id}"), Some(&alice),
        Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(acl_rows(&app, "alice_audited").await, before, "an unaudited change was kept");

    sqlx::query("DROP TRIGGER refuse_acl_audit ON audit_log").execute(&app.db).await.unwrap();
    let (st, _, _) = send_json(&app.router, "POST", path, Some(&alice),
        Some(serde_json::json!({"cidr": "10.4.0.0/16"}))).await;
    assert_eq!(st, StatusCode::CREATED, "PRECONDITION: the add works with auditing restored");
    let (st, _, _) = send_json(&app.router, "DELETE", &format!("{path}/{id}"), Some(&alice),
        Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::OK, "PRECONDITION: the remove works with auditing restored");
}

/// Removing nothing is not success (CRYPTARCH-116): the second removal of the
/// same entry, and an id that never existed, are 404s and audit nothing. The
/// first removal succeeding is the precondition.
#[tokio::test]
async fn removing_an_absent_source_is_not_reported_as_done() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_gone").await;
    let (id, _) = acl_rows(&app, "alice_gone").await[0].clone();
    let path = format!("/api/v1/databases/alice_gone/acl/{id}");

    let (st, _, body) = send_json(&app.router, "DELETE", &path, Some(&alice), Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::OK, "PRECONDITION: the first removal works: {body}");
    let (st, _, body) = send_json(&app.router, "DELETE", &path, Some(&alice), Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"]["code"], "no_such_source", "{body}");
    let ghost = Uuid::new_v4();
    let (st, _, _) = send_json(&app.router, "DELETE", &format!("/api/v1/databases/alice_gone/acl/{ghost}"),
        Some(&alice), Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_eq!(audit_count(&app, "acl_remove", "alice_gone").await, 1, "only the real removal is audited");
}

// ---- S4d: the Manage tab (CRYPTARCH-143) -----------------------------------

async fn stored_hash(app: &TestApp, name: &str) -> String {
    sqlx::query_scalar("SELECT password_hash FROM databases WHERE name = $1")
        .bind(name).fetch_one(&app.db).await.unwrap()
}

fn engine_calls(app: &TestApp, call: &str) -> usize {
    app.engine.calls().iter().filter(|c| *c == call).count()
}

/// A reset is the owner's alone: the new password is for whoever uses the
/// database, and an admin who could reset a tenant's database could read its
/// data. Everyone else — admin included — gets the uniform 404, the server is
/// never asked, and the stored hash is untouched. The precondition is that the
/// owner's identical request does rotate it.
#[tokio::test]
async fn a_reset_is_the_owners_alone_and_shown_once() {
    let Some(app) = test_app().await else { return };
    sqlx::query("INSERT INTO server_listeners (server_id, host, port, label) VALUES ($1, '10.1.2.3', 6432, 'lan')")
        .bind(app.server_id).execute(&app.db).await.unwrap();
    let alice = api_login(&app, "alice", "alicepw123").await;
    let bob = api_login(&app, "bob", "bobpw123").await;
    let admin = api_login(&app, "admin", "adminpw123").await;
    let first = api_provision(&app, &alice, "alice_reset").await;
    let path = "/api/v1/databases/alice_reset/reset";
    let hash = stored_hash(&app, "alice_reset").await;

    let (ghost_st, _, ghost) = send_json(&app.router, "POST", "/api/v1/databases/no_such_db/reset",
        Some(&bob), Some(serde_json::json!({}))).await;
    assert_eq!(ghost_st, StatusCode::NOT_FOUND);
    for who in [&bob, &admin] {
        let (st, _, body) = send_json(&app.router, "POST", path, Some(who), Some(serde_json::json!({}))).await;
        assert_eq!((st, &body), (ghost_st, &ghost), "a non-owner's reset must look like no database");
    }
    for odd in ["/api/v1/databases/%00/reset", "/api/v1/databases/x%00y/reset"] {
        let (st, _, body) = send_json(&app.router, "POST", odd, Some(&alice), Some(serde_json::json!({}))).await;
        assert_eq!(st, StatusCode::NOT_FOUND, "{odd}: {body}");
    }
    assert_eq!(engine_calls(&app, "rotate:alice_reset"), 0, "the server was asked on a non-owner's behalf");
    assert_eq!(stored_hash(&app, "alice_reset").await, hash);
    assert_eq!(audit_count(&app, "reset_password", "alice_reset").await, 0);

    let (st, h, body) = send_json(&app.router, "POST", path, Some(&alice), Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(h.get(header::CACHE_CONTROL).unwrap(), "no-store");
    let password = body["password"].as_str().unwrap();
    assert_eq!(password.len(), 32);
    assert_ne!(password, first, "a new password");
    assert_eq!(body["username"], "alice_reset");
    assert_eq!(body["unrecorded"], false);
    assert!(body["conn"].as_str().unwrap().contains(password), "{body}");
    assert_eq!(body["via"][0]["label"], "lan");
    assert!(body["via"][0]["conn"].as_str().unwrap().contains(&format!("{password}@10.1.2.3:6432")), "{body}");
    let mut keys: Vec<&str> = body.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(keys, ["conn", "name", "password", "unrecorded", "username", "via"]);
    assert_eq!(engine_calls(&app, "rotate:alice_reset"), 1, "PRECONDITION: the owner's reset rotates");
    assert_ne!(stored_hash(&app, "alice_reset").await, hash);
    assert_eq!(audit_count(&app, "reset_password", "alice_reset").await, 1);
}

/// A database that is being deleted or restored has no password to reset: a
/// delete has already disabled the role's login, so a "new password" would be
/// one that cannot log in, shown under "is live". Refused before the server is
/// asked; the precondition is that the same database resets once active.
#[tokio::test]
async fn a_reset_is_refused_unless_the_database_is_active() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_busy").await;
    let path = "/api/v1/databases/alice_busy/reset";
    let hash = stored_hash(&app, "alice_busy").await;
    for status in ["deleting", "restoring"] {
        sqlx::query("UPDATE databases SET status = $1 WHERE name = 'alice_busy'")
            .bind(status).execute(&app.db).await.unwrap();
        let (st, _, body) = send_json(&app.router, "POST", path, Some(&alice), Some(serde_json::json!({}))).await;
        assert_eq!(st, StatusCode::CONFLICT, "{status}: {body}");
        assert_eq!(body["error"]["code"], "not_active", "{body}");
        assert!(body.get("password").is_none(), "a credential was shown for a {status} database");
    }
    assert_eq!(engine_calls(&app, "rotate:alice_busy"), 0);
    assert_eq!(stored_hash(&app, "alice_busy").await, hash);
    sqlx::query("UPDATE databases SET status = 'active' WHERE name = 'alice_busy'").execute(&app.db).await.unwrap();
    let (st, _, body) = send_json(&app.router, "POST", path, Some(&alice), Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::OK, "PRECONDITION: an active database resets: {body}");
}

/// A rotation whose new hash cannot be recorded still hands over the password
/// — the old one is already dead on the server (CRYPTARCH-101) — and says so.
#[tokio::test]
async fn a_reset_that_cannot_be_recorded_still_hands_over_the_password() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_unrec").await;
    let hash = stored_hash(&app, "alice_unrec").await;
    for sql in [
        "CREATE FUNCTION refuse_hash() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN RAISE EXCEPTION 'hash refused'; END $$",
        "CREATE TRIGGER refuse_hash BEFORE UPDATE OF password_hash ON databases \
         FOR EACH ROW EXECUTE FUNCTION refuse_hash()",
    ] {
        sqlx::query(AssertSqlSafe(sql)).execute(&app.db).await.unwrap();
    }
    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/databases/alice_unrec/reset",
        Some(&alice), Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["unrecorded"], true);
    assert_eq!(body["password"].as_str().unwrap().len(), 32, "the only copy is still handed over");
    assert_eq!(audit_count(&app, "reset_password_unrecorded", "alice_unrec").await, 1);
    assert_eq!(engine_calls(&app, "rotate:alice_unrec"), 1, "the server really rotated");
    assert_eq!(stored_hash(&app, "alice_unrec").await, hash, "and the record really did not change");
}

/// Delete is the one irreversible action: the typed name is checked on the
/// server, before anything happens. Owner or admin; another tenant gets the
/// uniform 404. Each refusal leaves the row and the server untouched; the
/// precondition is that the same database IS deletable.
#[tokio::test]
async fn delete_needs_the_typed_name_and_is_owner_or_admin() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    let bob = api_login(&app, "bob", "bobpw123").await;
    let admin = api_login(&app, "admin", "adminpw123").await;
    api_provision(&app, &alice, "alice_del").await;
    api_provision(&app, &alice, "alice_del2").await;
    let path = "/api/v1/databases/alice_del/delete";
    let rows = |name: &'static str| {
        let db = app.db.clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM databases WHERE name = $1")
                .bind(name).fetch_one(&db).await.unwrap()
        }
    };

    for confirm in ["nope", "alice_del2", "ALICE_DEL", ""] {
        let (st, _, body) = send_json(&app.router, "POST", path, Some(&alice),
            Some(serde_json::json!({"confirm": confirm}))).await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{confirm:?}: {body}");
        assert_eq!(body["error"]["code"], "confirm_mismatch", "{body}");
    }
    let (st, _, body) = send_json(&app.router, "POST", path, Some(&alice), Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "no confirmation at all: {body}");
    assert_eq!(body["error"]["code"], "confirm_mismatch", "a missing confirmation is a mismatch: {body}");
    let (ghost_st, _, ghost) = send_json(&app.router, "POST", "/api/v1/databases/no_such_db/delete",
        Some(&bob), Some(serde_json::json!({"confirm": "no_such_db"}))).await;
    let (st, _, body) = send_json(&app.router, "POST", path, Some(&bob),
        Some(serde_json::json!({"confirm": "alice_del"}))).await;
    assert_eq!((st, &body), (ghost_st, &ghost), "a tenant's delete must look like no database");
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_eq!(rows("alice_del").await, 1, "a refused delete removed the row");
    assert!(!app.engine.calls().iter().any(|c| c.ends_with(":alice_del")
        && !c.starts_with("create:")), "a refused delete reached the server: {:?}", app.engine.calls());
    assert_eq!(audit_count(&app, "delete_db", "alice_del").await, 0);

    // The owner, with the name typed (surrounding space forgiven, as maud).
    let (st, h, body) = send_json(&app.router, "POST", path, Some(&alice),
        Some(serde_json::json!({"confirm": " alice_del "}))).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(h.get(header::CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(body["deleted"], "alice_del");
    // No conf dir on the test server: the edge was not rewritten, and the
    // tenant is told rather than left to assume.
    assert!(body["warning"].as_str().is_some_and(|w| w.contains("manually")), "{body}");
    assert_eq!(engine_calls(&app, "drop:alice_del"), 1);
    assert_eq!(rows("alice_del").await, 0);
    assert_eq!(audit_count(&app, "delete_db", "alice_del").await, 1);
    let (st, _, _) = send_json(&app.router, "GET", "/api/v1/databases/alice_del", Some(&alice), None).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "gone from the view");

    // An admin may delete someone else's.
    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/databases/alice_del2/delete", Some(&admin),
        Some(serde_json::json!({"confirm": "alice_del2"}))).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(engine_calls(&app, "drop:alice_del2"), 1);
    assert_eq!(audit_count(&app, "delete_db", "alice_del2").await, 1);
    let actor: String = sqlx::query_scalar(
        "SELECT actor FROM audit_log WHERE action = 'delete_db' AND target = 'alice_del2'")
        .fetch_one(&app.db).await.unwrap();
    assert_eq!(actor, "admin");
}

/// An edge that did not take a delete is said where the deleter lands — for
/// an admin too, who is the one who has to act on it. The maud door picks the
/// flash code; the test server has no conf dir, so the edge is never applied.
#[tokio::test]
async fn a_delete_the_edge_did_not_take_says_so_where_you_land() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    let admin = api_login(&app, "admin", "adminpw123").await;
    api_provision(&app, &alice, "alice_edge_del").await;
    api_provision(&app, &alice, "alice_edge_del2").await;
    // No conf dir: the edge never took the delete, and whoever deleted is told
    // — an admin as much as the owner.
    for (who, name) in [(&admin, "alice_edge_del"), (&alice, "alice_edge_del2")] {
        let (st, _, body) = send_json(&app.router, "POST", &format!("/api/v1/databases/{name}/delete"),
            Some(who), Some(serde_json::json!({"confirm": name}))).await;
        assert_eq!(st, StatusCode::OK, "{body}");
        assert!(body["warning"].as_str().unwrap_or("").contains("manually"), "{name}: {body}");
    }

    // Where the edge IS applied (a conf dir, no console to reload), nothing
    // extra is said.
    let dir = temp_conf_dir();
    sqlx::query("UPDATE managed_servers SET bouncer_conf_dir = $1 WHERE id = $2")
        .bind(dir.display().to_string()).bind(app.server_id).execute(&app.db).await.unwrap();
    api_provision(&app, &alice, "alice_clean_del").await;
    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/databases/alice_clean_del/delete",
        Some(&alice), Some(serde_json::json!({"confirm": "alice_clean_del"}))).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert!(body["warning"].is_null(), "an applied edge carries no warning: {body}");
    std::fs::remove_dir_all(&dir).ok();
}

// ---- S4e: the Backups tab (CRYPTARCH-144) ---------------------------------

/// The history reads like the maud tab: newest first, each with its status,
/// whether it was read back, what is known of its contents, and its log —
/// owner or admin, like the view; anyone else the uniform 404. The shape is
/// pinned, so nothing the blob holds (a path, a checksum) rides along.
#[tokio::test]
async fn backup_history_is_the_views_posture_and_says_what_each_backup_is() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    let bob = api_login(&app, "bob", "bobpw123").await;
    let admin = api_login(&app, "admin", "adminpw123").await;
    api_provision(&app, &alice, "alice_bk").await;
    let (old, _) = seed_backup(&app, "alice_bk", chrono::Duration::hours(2), "ok").await;
    sqlx::query("UPDATE backups SET verified_at = now(), log = 'pg_dump: done' WHERE id = $1")
        .bind(old).execute(&app.db).await.unwrap();
    let (running, _) = seed_backup(&app, "alice_bk", chrono::Duration::minutes(1), "running").await;
    sqlx::query("UPDATE backups SET finished_at = NULL, size_bytes = NULL WHERE id = $1")
        .bind(running).execute(&app.db).await.unwrap();
    let path = "/api/v1/databases/alice_bk/backups";

    let [(own_st, own), (ten_st, ten), (adm_st, _)] = as_owner_tenant_admin(&app, &alice, &bob, &admin, path).await;
    assert_eq!((own_st, ten_st, adm_st), (StatusCode::OK, StatusCode::NOT_FOUND, StatusCode::OK), "{own} {ten}");
    let (_, _, ghost) = send_json(&app.router, "GET", "/api/v1/databases/no_such_db/backups", Some(&bob), None).await;
    assert_eq!(ten, ghost, "the same answer as a name that does not exist");

    assert_eq!(own["enabled"], true);
    let list = own["backups"].as_array().unwrap();
    assert_eq!(list.len(), 2, "{own}");
    assert_eq!(list[0]["id"], running.to_string(), "newest first");
    assert_eq!(list[0]["status"], "running");
    assert_eq!(list[0]["verified"], false, "never read back is not verified");
    assert!(list[0]["finished_at"].is_null() && list[0]["size_bytes"].is_null(), "{own}");
    assert_eq!(list[1]["status"], "ok");
    assert_eq!(list[1]["verified"], true);
    assert_eq!(list[1]["size_bytes"], 12);
    assert_eq!(list[1]["log"], "pg_dump: done");
    // No manifest on a seeded row: "unknown", never a clean bill of health.
    assert_eq!(list[1]["contents"]["state"], "unknown", "{own}");
    assert!(list[1]["contents"]["detail"].is_string());
    let mut keys: Vec<&str> = list[1].as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(keys, ["contents", "created_at", "error", "finished_at", "id", "log", "size_bytes", "status",
                      "took", "verified"]);
    // No `path`/`checksum` FIELD rides along (the key set above). The job LOG
    // does name the blob and the dump command, exactly as the maud tab and
    // the admin fleet view already show it to the same readers.
}

/// Starting a backup of a database that is mid-delete or mid-restore says so,
/// rather than "there is no database by that name" about one the page shows.
#[tokio::test]
async fn a_backup_of_a_database_that_is_not_active_says_so() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_dying").await;
    sqlx::query("UPDATE databases SET status = 'deleting' WHERE name = 'alice_dying'").execute(&app.db).await.unwrap();
    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/databases/alice_dying/backups", Some(&alice),
        Some(serde_json::json!({}))).await;
    assert_eq!((st, &body["error"]["code"]), (StatusCode::CONFLICT, &serde_json::json!("not_active")), "{body}");
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM backups WHERE db_name = 'alice_dying'")
        .fetch_one(&app.db).await.unwrap();
    assert_eq!(rows, 0);
    sqlx::query("UPDATE databases SET status = 'active' WHERE name = 'alice_dying'").execute(&app.db).await.unwrap();
    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/databases/alice_dying/backups", Some(&alice),
        Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::ACCEPTED, "PRECONDITION: an active one starts: {body}");
}

/// Starting one is the owner's alone, as on maud — not an admin's, whose
/// fleet tools are elsewhere — and every refusal says which it is.
#[tokio::test]
async fn starting_a_backup_is_the_owners_and_each_refusal_says_why() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    let bob = api_login(&app, "bob", "bobpw123").await;
    let admin = api_login(&app, "admin", "adminpw123").await;
    api_provision(&app, &alice, "alice_go").await;
    let path = "/api/v1/databases/alice_go/backups";
    let rows = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM backups WHERE db_name = 'alice_go'")
            .fetch_one(&app.db).await.unwrap()
    };

    let (ghost_st, _, ghost) = send_json(&app.router, "POST", "/api/v1/databases/no_such_db/backups",
        Some(&bob), Some(serde_json::json!({}))).await;
    for who in [&bob, &admin] {
        let (st, _, body) = send_json(&app.router, "POST", path, Some(who), Some(serde_json::json!({}))).await;
        assert_eq!((st, &body), (ghost_st, &ghost), "a non-owner's backup must look like no database");
    }
    assert_eq!(rows().await, 0, "a refused backup was started");

    // A restore holds the database: a dump now would capture it mid-rebuild.
    let (bk, _) = seed_backup(&app, "alice_go", chrono::Duration::hours(1), "ok").await;
    let restore: Uuid = sqlx::query_scalar(
        "INSERT INTO restores (backup_id, source_name, target_name, mode, requested_by) \
         VALUES ($1, 'alice_go', 'alice_go', 'replace', 'alice') RETURNING id")
        .bind(bk).fetch_one(&app.db).await.unwrap();
    let (st, _, body) = send_json(&app.router, "POST", path, Some(&alice), Some(serde_json::json!({}))).await;
    assert_eq!((st, &body["error"]["code"]), (StatusCode::CONFLICT, &serde_json::json!("restore_running")), "{body}");
    sqlx::query("UPDATE restores SET status = 'ok' WHERE id = $1").bind(restore).execute(&app.db).await.unwrap();
    assert_eq!(rows().await, 1, "only the seeded one");

    let (st, h, body) = send_json(&app.router, "POST", path, Some(&alice), Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::ACCEPTED, "PRECONDITION: the owner starts one: {body}");
    assert_eq!(h.get(header::CACHE_CONTROL).unwrap(), "no-store");
    let id: Uuid = body["id"].as_str().unwrap().parse().unwrap();
    assert!(sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM backups WHERE id = $1)")
        .bind(id).fetch_one(&app.db).await.unwrap(), "the id names the job");

    // Let the job it started finish (the test engine cannot dump, so it
    // fails), or its last write races the rows set up below.
    let settled = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            let st: String = sqlx::query_scalar("SELECT status FROM backups WHERE id = $1")
                .bind(id).fetch_one(&app.db).await.unwrap();
            if st != "running" { break st; }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }).await.expect("the started job settles");
    assert_ne!(settled, "running");

    // A second while one runs.
    let (held, _) = seed_backup(&app, "alice_go", chrono::Duration::seconds(5), "running").await;
    let (st, _, body) = send_json(&app.router, "POST", path, Some(&alice), Some(serde_json::json!({}))).await;
    assert_eq!((st, &body["error"]["code"]), (StatusCode::CONFLICT, &serde_json::json!("already_running")), "{body}");
    sqlx::query("UPDATE backups SET status = 'failed' WHERE id = $1").bind(held).execute(&app.db).await.unwrap();

    // Not configured on this deployment.
    let mut off = test_state(&app);
    off.backup_dir = None;
    let off = web::router(off);
    let (st, _, body) = send_json(&off, "POST", path, Some(&alice), Some(serde_json::json!({}))).await;
    assert_eq!((st, &body["error"]["code"]), (StatusCode::CONFLICT, &serde_json::json!("backups_disabled")), "{body}");
    let (st, _, body) = send_json(&off, "GET", path, Some(&alice), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["enabled"], false, "{body}");

    // Shutting down.
    let closing = test_state(&app);
    closing.jobs.drain(std::time::Duration::from_millis(10)).await;
    let closing = web::router(closing);
    let (st, _, body) = send_json(&closing, "POST", path, Some(&alice), Some(serde_json::json!({}))).await;
    assert_eq!((st, &body["error"]["code"]), (StatusCode::SERVICE_UNAVAILABLE, &serde_json::json!("shutting_down")), "{body}");
}

// ---- S4f: restores (CRYPTARCH-145) -----------------------------------------

/// A finished backup of `name` that `restore::enqueue` will accept: seeded ok,
/// and naming the fixture's server (the seed leaves it NULL).
async fn restorable_backup(app: &TestApp, name: &str) -> Uuid {
    let (id, _) = seed_backup(app, name, chrono::Duration::days(1), "ok").await;
    sqlx::query("UPDATE backups SET server_id = $2 WHERE id = $1")
        .bind(id).bind(app.server_id).execute(&app.db).await.unwrap();
    id
}

async fn restores_of_backup(app: &TestApp, backup: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM restores WHERE backup_id = $1")
        .bind(backup).fetch_one(&app.db).await.unwrap()
}

/// Starting a restore is the owner's alone — it rewrites their data — and is
/// armed by the typed name, checked on the server. The job it starts is
/// readable by the owner and an admin (the view's posture), and by nobody else.
#[tokio::test]
async fn a_restore_is_the_owners_and_needs_the_typed_name() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    let bob = api_login(&app, "bob", "bobpw123").await;
    let admin = api_login(&app, "admin", "adminpw123").await;
    api_provision(&app, &alice, "alice_rs").await;
    let backup = restorable_backup(&app, "alice_rs").await;
    let path = "/api/v1/databases/alice_rs/restores";
    let body = |confirm: &str| serde_json::json!({"backup_id": backup, "confirm": confirm});

    let (ghost_st, _, ghost) = send_json(&app.router, "POST", "/api/v1/databases/no_such_db/restores",
        Some(&bob), Some(body("no_such_db"))).await;
    for who in [&bob, &admin] {
        let (st, _, resp) = send_json(&app.router, "POST", path, Some(who), Some(body("alice_rs"))).await;
        assert_eq!((st, &resp), (ghost_st, &ghost), "a non-owner's restore must look like no database");
    }
    for wrong in ["", "alice", "ALICE_RS", "alice_rs2"] {
        let (st, _, resp) = send_json(&app.router, "POST", path, Some(&alice), Some(body(wrong))).await;
        assert_eq!((st, &resp["error"]["code"]), (StatusCode::UNPROCESSABLE_ENTITY, &serde_json::json!("confirm_mismatch")),
            "{wrong:?}: {resp}");
    }
    let (st, _, resp) = send_json(&app.router, "POST", path, Some(&alice),
        Some(serde_json::json!({"backup_id": backup}))).await;
    assert_eq!((st, &resp["error"]["code"]), (StatusCode::UNPROCESSABLE_ENTITY, &serde_json::json!("confirm_mismatch")));
    assert_eq!(restores_of_backup(&app, backup).await, 0, "a refused restore claimed a job");

    let (st, h, resp) = send_json(&app.router, "POST", path, Some(&alice), Some(body(" alice_rs "))).await;
    assert_eq!(st, StatusCode::ACCEPTED, "PRECONDITION: the owner starts one: {resp}");
    assert_eq!(h.get(header::CACHE_CONTROL).unwrap(), "no-store");
    let id: Uuid = resp["id"].as_str().unwrap().parse().unwrap();
    let (settled, _) = await_restore(&app, id).await;
    assert_ne!(settled, "running");

    let job = format!("{path}/{id}");
    let [(own, own_body), (ten, ten_body), (adm, _)] = as_owner_tenant_admin(&app, &alice, &bob, &admin, &job).await;
    assert_eq!((own, ten, adm), (StatusCode::OK, StatusCode::NOT_FOUND, StatusCode::OK), "{ten_body}");
    assert_eq!(own_body["id"], id.to_string());
    assert_eq!(own_body["requested_by"], "alice");
    let [(own, list), (ten, _), (adm, _)] = as_owner_tenant_admin(&app, &alice, &bob, &admin, path).await;
    assert_eq!((own, ten, adm), (StatusCode::OK, StatusCode::NOT_FOUND, StatusCode::OK));
    assert_eq!(list["restores"][0]["id"], id.to_string(), "{list}");
}

/// Owning the target is not owning the backup (CRYPTARCH-86): a backup of
/// someone else's database cannot be loaded into yours by passing its id.
#[tokio::test]
async fn a_restore_cannot_load_another_databases_backup() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    let bob = api_login(&app, "bob", "bobpw123").await;
    api_provision(&app, &alice, "alice_src2").await;
    api_provision(&app, &bob, "bob_dst2").await;
    let alices = restorable_backup(&app, "alice_src2").await;
    let bobs = restorable_backup(&app, "bob_dst2").await;
    let path = "/api/v1/databases/bob_dst2/restores";

    let (st, _, resp) = send_json(&app.router, "POST", path, Some(&bob),
        Some(serde_json::json!({"backup_id": bobs, "confirm": "bob_dst2"}))).await;
    assert_eq!(st, StatusCode::ACCEPTED, "PRECONDITION: bob restores his own: {resp}");
    let (settled, _) = await_restore(&app, resp["id"].as_str().unwrap().parse().unwrap()).await;
    assert_ne!(settled, "running");

    let (st, _, resp) = send_json(&app.router, "POST", path, Some(&bob),
        Some(serde_json::json!({"backup_id": alices, "confirm": "bob_dst2"}))).await;
    assert_eq!((st, &resp["error"]["code"]), (StatusCode::NOT_FOUND, &serde_json::json!("no_such_backup")), "{resp}");
    assert_eq!(restores_of_backup(&app, alices).await, 0);
}

/// Each refusal says which it is, and none of them claims a job.
#[tokio::test]
async fn a_restore_refusal_says_why() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_rx").await;
    let backup = restorable_backup(&app, "alice_rx").await;
    let path = "/api/v1/databases/alice_rx/restores";
    let go = |router: Router| {
        let alice = alice.clone();
        async move {
            send_json(&router, "POST", path, Some(&alice),
                Some(serde_json::json!({"backup_id": backup, "confirm": "alice_rx"}))).await
        }
    };
    let code = |r: &(StatusCode, axum::http::HeaderMap, serde_json::Value)| (r.0, r.2["error"]["code"].clone());

    // A backup in flight holds the database.
    let (running, _) = seed_backup(&app, "alice_rx", chrono::Duration::seconds(5), "running").await;
    assert_eq!(code(&go(app.router.clone()).await), (StatusCode::CONFLICT, serde_json::json!("backup_running")));
    sqlx::query("UPDATE backups SET status = 'failed' WHERE id = $1").bind(running).execute(&app.db).await.unwrap();

    // Sealed under a key this deployment does not hold (CRYPTARCH-107).
    sqlx::query("UPDATE backups SET key_fingerprint = 'ffffffffffffffff' WHERE id = $1").bind(backup).execute(&app.db).await.unwrap();
    let r = go(app.router.clone()).await;
    assert_eq!(code(&r), (StatusCode::CONFLICT, serde_json::json!("wrong_key")), "{}", r.2);
    assert!(r.2["error"]["message"].as_str().unwrap().contains("different encryption key"));
    sqlx::query("UPDATE backups SET key_fingerprint = NULL WHERE id = $1").bind(backup).execute(&app.db).await.unwrap();

    // Not while the database is mid-delete.
    sqlx::query("UPDATE databases SET status = 'deleting' WHERE name = 'alice_rx'").execute(&app.db).await.unwrap();
    assert_eq!(code(&go(app.router.clone()).await), (StatusCode::CONFLICT, serde_json::json!("not_active")));
    sqlx::query("UPDATE databases SET status = 'active' WHERE name = 'alice_rx'").execute(&app.db).await.unwrap();

    // Not configured; shutting down.
    let mut off = test_state(&app);
    off.backup_dir = None;
    assert_eq!(code(&go(web::router(off)).await), (StatusCode::CONFLICT, serde_json::json!("backups_disabled")));
    let closing = test_state(&app);
    closing.jobs.drain(std::time::Duration::from_millis(10)).await;
    assert_eq!(code(&go(web::router(closing)).await), (StatusCode::SERVICE_UNAVAILABLE, serde_json::json!("shutting_down")));
    assert_eq!(restores_of_backup(&app, backup).await, 0, "a refusal claimed a job");

    // One already running.
    let r = go(app.router.clone()).await;
    assert_eq!(r.0, StatusCode::ACCEPTED, "PRECONDITION: it starts once nothing is in the way: {}", r.2);
    let id: Uuid = r.2["id"].as_str().unwrap().parse().unwrap();
    let _ = await_restore(&app, id).await;
    sqlx::query("UPDATE restores SET status = 'running' WHERE id = $1").bind(id).execute(&app.db).await.unwrap();
    assert_eq!(code(&go(app.router.clone()).await), (StatusCode::CONFLICT, serde_json::json!("already_running")));
    sqlx::query("UPDATE restores SET status = 'failed' WHERE id = $1").bind(id).execute(&app.db).await.unwrap();
}

/// The job reads as the maud page draws it: five steps in order, each with
/// its state — derived from the stored stage and the outcome, never from
/// either alone — and what it recorded. A step after a failure was skipped,
/// not pending: "will never start" and "not yet" mean opposite things.
#[tokio::test]
async fn a_restore_job_reads_as_its_five_steps() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_job2").await;
    let backup = restorable_backup(&app, "alice_job2").await;
    let db: Uuid = sqlx::query_scalar("SELECT id FROM databases WHERE name = 'alice_job2'").fetch_one(&app.db).await.unwrap();
    let seed = |status: &'static str, stage: &'static str, error: Option<&'static str>, log: &'static str| {
        let db_pool = app.db.clone();
        async move {
            sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO restores (backup_id, source_name, target_name, mode, requested_by, database_id, \
                                       status, stage, error, log, finished_at) \
                 VALUES ($1, 'alice_job2', 'alice_job2', 'replace', 'alice', $2, $3, $4, $5, $6, \
                         CASE WHEN $3 = 'running' THEN NULL ELSE now() END) RETURNING id")
                .bind(backup).bind(db).bind(status).bind(stage).bind(error).bind(log)
                .fetch_one(&db_pool).await.unwrap()
        }
    };
    let failed = seed("failed", "loading", Some("pg_restore: error: relation exists"),
        "10:00:01Z  locating  found alice_job2/x.enc\n10:00:02Z  checking  read back 2.0 kB\n10:00:03Z  connecting\n").await;
    let job = |id: Uuid| {
        let (router, alice) = (app.router.clone(), alice.clone());
        async move {
            send_json(&router, "GET", &format!("/api/v1/databases/alice_job2/restores/{id}"), Some(&alice), None).await
        }
    };

    let (st, _, body) = job(failed).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let steps = body["steps"].as_array().unwrap();
    let keys: Vec<&str> = steps.iter().map(|s| s["key"].as_str().unwrap()).collect();
    assert_eq!(keys, ["locating", "checking", "connecting", "loading", "finishing"]);
    let states: Vec<&str> = steps.iter().map(|s| s["state"].as_str().unwrap()).collect();
    assert_eq!(states, ["done", "done", "done", "failed", "skipped"]);
    assert_eq!(steps[0]["title"], "Find the backup");
    assert!(steps[0]["blurb"].as_str().unwrap().contains("sealed file"));
    assert_eq!((&steps[0]["time"], &steps[0]["detail"]), (&serde_json::json!("10:00:01Z"), &serde_json::json!("found alice_job2/x.enc")));
    assert_eq!(steps[2]["time"], "10:00:03Z", "PRECONDITION: the step did log a line");
    assert!(steps[2]["detail"].is_null(), "a line with nothing to say is no detail, not an empty one");
    assert!(steps[4]["time"].is_null() && steps[4]["detail"].is_null(), "a step that logged nothing has neither");
    assert_eq!(steps[3]["error"], "pg_restore: error: relation exists", "the error rides on the failed step");
    for (i, step) in steps.iter().enumerate() {
        if i != 3 {
            assert!(step["error"].is_null(), "the error rides only on the failed step, not step {i}: {step}");
        }
    }
    assert_eq!(body["error"], "pg_restore: error: relation exists", "and whole, on the job");
    assert_eq!(body["status"], "failed");

    sqlx::query("UPDATE restores SET status = 'failed' WHERE status = 'running'").execute(&app.db).await.unwrap();
    let running = seed("running", "connecting", None, "").await;
    let (_, _, body) = job(running).await;
    let states: Vec<&str> = body["steps"].as_array().unwrap().iter().map(|s| s["state"].as_str().unwrap()).collect();
    assert_eq!(states, ["done", "done", "running", "pending", "pending"]);
    assert!(body["finished_at"].is_null());

    sqlx::query("UPDATE restores SET status = 'failed' WHERE status = 'running'").execute(&app.db).await.unwrap();
    let ok = seed("ok", "loading", None, "").await;
    let (_, _, body) = job(ok).await;
    let states: Vec<&str> = body["steps"].as_array().unwrap().iter().map(|s| s["state"].as_str().unwrap()).collect();
    assert_eq!(states, ["done"; 5], "a committed restore did every step, whatever the column says");

    // History: newest first, with the stage in flight for a running one.
    let (_, _, list) = send_json(&app.router, "GET", "/api/v1/databases/alice_job2/restores", Some(&alice), None).await;
    let ids: Vec<&str> = list["restores"].as_array().unwrap().iter().map(|r| r["id"].as_str().unwrap()).collect();
    assert_eq!(ids, [ok.to_string(), running.to_string(), failed.to_string()]);
    assert_eq!(list["restores"][1]["stage_title"], "Connect as the owner");
    let ghost = Uuid::new_v4();
    let (st, _, _) = job(ghost).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

/// A restore's history belongs to the database's identity, not its name
/// (CRYPTARCH-100): the next holder of a freed name inherits none of it. The
/// preconditions are that the job showed for its owner first, and that its
/// row outlives the delete.
#[tokio::test]
async fn a_recycled_name_reaches_none_of_the_previous_owners_restores() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    let bob = api_login(&app, "bob", "bobpw123").await;
    api_provision(&app, &alice, "recycled2").await;
    let backup = restorable_backup(&app, "recycled2").await;
    let (st, _, resp) = send_json(&app.router, "POST", "/api/v1/databases/recycled2/restores", Some(&alice),
        Some(serde_json::json!({"backup_id": backup, "confirm": "recycled2"}))).await;
    assert_eq!(st, StatusCode::ACCEPTED, "{resp}");
    let id: Uuid = resp["id"].as_str().unwrap().parse().unwrap();
    let _ = await_restore(&app, id).await;
    let (_, _, list) = send_json(&app.router, "GET", "/api/v1/databases/recycled2/restores", Some(&alice), None).await;
    assert_eq!(list["restores"][0]["id"], id.to_string(), "PRECONDITION: alice sees her job");

    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/databases/recycled2/delete", Some(&alice),
        Some(serde_json::json!({"confirm": "recycled2"}))).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(restores_of_backup(&app, backup).await, 1, "PRECONDITION: the row outlived the delete");
    api_provision(&app, &bob, "recycled2").await;

    let (st, _, list) = send_json(&app.router, "GET", "/api/v1/databases/recycled2/restores", Some(&bob), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(list["restores"], serde_json::json!([]), "bob inherited alice's restores: {list}");
    let (st, _, _) = send_json(&app.router, "GET", &format!("/api/v1/databases/recycled2/restores/{id}"), Some(&bob), None).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "bob read alice's job through a name he merely took");
}

/// A database cannot be deleted out from under a running restore or backup
/// (S4f audit P1). The restore re-resolves its target by NAME when it
/// connects; deleting mid-restore and letting someone else take the name
/// loaded the old owner's data into the new tenant's database. So: refused,
/// through both doors, until the job settles — and then it goes through.
#[tokio::test]
async fn a_database_with_a_job_running_cannot_be_deleted() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_busy_del").await;
    let backup = restorable_backup(&app, "alice_busy_del").await;
    let db: Uuid = sqlx::query_scalar("SELECT id FROM databases WHERE name = 'alice_busy_del'").fetch_one(&app.db).await.unwrap();
    let restore: Uuid = sqlx::query_scalar(
        "INSERT INTO restores (backup_id, source_name, target_name, mode, requested_by, database_id) \
         VALUES ($1, 'alice_busy_del', 'alice_busy_del', 'replace', 'alice', $2) RETURNING id")
        .bind(backup).bind(db).fetch_one(&app.db).await.unwrap();
    let del = || send_json(&app.router, "POST", "/api/v1/databases/alice_busy_del/delete", Some(&alice),
        Some(serde_json::json!({"confirm": "alice_busy_del"})));

    let (st, _, body) = del().await;
    assert_eq!((st, &body["error"]["code"]), (StatusCode::CONFLICT, &serde_json::json!("job_running")), "{body}");
    let status: String = sqlx::query_scalar("SELECT status FROM databases WHERE id = $1").bind(db).fetch_one(&app.db).await.unwrap();
    assert_eq!(status, "active", "a refused delete left the database {status}");
    assert_eq!(engine_calls(&app, "drop:alice_busy_del"), 0);

    sqlx::query("UPDATE restores SET status = 'ok' WHERE id = $1").bind(restore).execute(&app.db).await.unwrap();
    let (running, _) = seed_backup(&app, "alice_busy_del", chrono::Duration::seconds(5), "running").await;
    let (st, _, body) = del().await;
    assert_eq!((st, &body["error"]["code"]), (StatusCode::CONFLICT, &serde_json::json!("job_running")), "a backup holds it too: {body}");
    sqlx::query("UPDATE backups SET status = 'failed' WHERE id = $1").bind(running).execute(&app.db).await.unwrap();

    let (st, _, body) = del().await;
    assert_eq!(st, StatusCode::OK, "PRECONDITION: with nothing running it deletes: {body}");
}

/// The other half: a restore cannot be claimed against a database that is not
/// active — mid-delete, say — checked under the same lock the delete takes.
#[tokio::test]
async fn a_restore_cannot_be_claimed_for_a_database_being_deleted() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_claim").await;
    let backup = restorable_backup(&app, "alice_claim").await;
    let db: Uuid = sqlx::query_scalar("SELECT id FROM databases WHERE name = 'alice_claim'").fetch_one(&app.db).await.unwrap();
    let state = test_state(&app);
    sqlx::query("UPDATE databases SET status = 'deleting' WHERE id = $1").bind(db).execute(&app.db).await.unwrap();
    let refused = cryptarch::restore::enqueue(&state, "alice", db, "alice_claim", backup).await;
    assert!(matches!(refused, Err(cryptarch::restore::EnqueueError::NotActive)), "{refused:?}");
    assert_eq!(restores_of_backup(&app, backup).await, 0);
    sqlx::query("UPDATE databases SET status = 'active' WHERE id = $1").bind(db).execute(&app.db).await.unwrap();
    let id = cryptarch::restore::enqueue(&state, "alice", db, "alice_claim", backup).await
        .expect("PRECONDITION: an active database's restore is claimed");
    let _ = await_restore(&app, id).await;
}

/// pg_restore's stderr quotes the rows it failed on; none of that is kept —
/// not in the job row (which an admin can read through the API), not in the
/// audit log — while what went wrong is (S4f audit P2). Driven through the
/// real runner: a blob that really decrypts, a tool that really fails.
#[tokio::test]
async fn a_failed_restore_keeps_no_row_data() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_redact").await;
    let (backup, blob) = seed_backup(&app, "alice_redact", chrono::Duration::days(1), "ok").await;
    sqlx::query("UPDATE backups SET server_id = $2 WHERE id = $1").bind(backup).bind(app.server_id).execute(&app.db).await.unwrap();
    // A real archive, so the "check it opens" step passes and the runner gets
    // as far as the tool: a schema-only dump of the test cluster's own db.
    let dsn = std::env::var("CRYPTARCH_TEST_DSN").unwrap();
    let dump = std::process::Command::new("pg_dump").args(["-Fc", "-s", &dsn]).output().unwrap();
    assert!(dump.status.success(), "PRECONDITION: pg_dump made an archive");
    let crypto = cryptarch::crypto::Crypto::from_hex_key(&"ab".repeat(32)).unwrap();
    cryptarch::backup::seal_stream(&crypto, backup, &dump.stdout[..], &blob).await.unwrap();
    app.engine.set_restore_failure(
        "pg_restore: error: COPY failed for table \"ledger\": ERROR:  new row violates check constraint \"c\"\n\
         CONTEXT:  COPY ledger, line 1: \"1\tSSN 123-45-6789\"\n\
         DETAIL:  Failing row contains (1, SSN 123-45-6789).\n");

    let (st, _, resp) = send_json(&app.router, "POST", "/api/v1/databases/alice_redact/restores", Some(&alice),
        Some(serde_json::json!({"backup_id": backup, "confirm": "alice_redact"}))).await;
    assert_eq!(st, StatusCode::ACCEPTED, "{resp}");
    let id: Uuid = resp["id"].as_str().unwrap().parse().unwrap();
    let (status, error) = await_restore(&app, id).await;
    assert_eq!(status, "failed");
    assert!(app.engine.calls().contains(&"restore_stream:alice_redact".to_string()),
        "PRECONDITION: the runner reached the tool; it failed with {error:?}");
    let error = error.unwrap();
    assert!(error.contains("violates check constraint"), "what went wrong is kept: {error}");
    // Written just after the row settles: wait for it rather than race it.
    let mut audit = None;
    for _ in 0..100 {
        audit = sqlx::query_scalar::<_, String>(
            "SELECT detail FROM audit_log WHERE action = 'restore_failed' AND target = 'alice_redact'")
            .fetch_optional(&app.db).await.unwrap();
        if audit.is_some() { break; }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let audit = audit.expect("the failure was audited");
    for kept in [&error, &audit] {
        assert!(!kept.contains("123-45-6789"), "row data kept: {kept}");
    }
}

/// The runner's last look before it connects: the target must still be the
/// database that was claimed — same identity, same name, active. A name now
/// held by someone else is not it.
#[tokio::test]
async fn a_restore_target_is_rechecked_by_identity_before_connecting() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    let bob = api_login(&app, "bob", "bobpw123").await;
    api_provision(&app, &alice, "taken_over").await;
    let alices: Uuid = sqlx::query_scalar("SELECT id FROM databases WHERE name = 'taken_over'").fetch_one(&app.db).await.unwrap();
    assert!(cryptarch::restore::target_still_matches(&app.db, alices, "taken_over").await,
        "PRECONDITION: the live database matches");
    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/databases/taken_over/delete", Some(&alice),
        Some(serde_json::json!({"confirm": "taken_over"}))).await;
    assert_eq!(st, StatusCode::OK);
    api_provision(&app, &bob, "taken_over").await;
    assert!(!cryptarch::restore::target_still_matches(&app.db, alices, "taken_over").await,
        "bob's database under the same name passed for alice's");
}

// ---- S5: the profile (CRYPTARCH-133) ----------------------------------------

/// The sessions a user sees are their own, the current one marked; no token,
/// no hash, nothing that names another user's session.
#[tokio::test]
async fn my_sessions_are_mine_and_say_which_is_this_one() {
    let Some(app) = test_app().await else { return };
    let a1 = api_login(&app, "alice", "alicepw123").await;
    let _a2 = api_login(&app, "alice", "alicepw123").await;
    let _b = api_login(&app, "bob", "bobpw123").await;
    let (st, _, body) = send_json(&app.router, "GET", "/api/v1/me/sessions", Some(&a1), None).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let list = body["sessions"].as_array().unwrap();
    assert_eq!(list.len(), 2, "alice's two, not bob's: {body}");
    assert_eq!(list.iter().filter(|s| s["current"] == true).count(), 1);
    assert_eq!(list[0]["current"], true, "this one first");
    let mut keys: Vec<&str> = list[0].as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(keys, ["created_at", "current", "last_seen"]);
    let raw = a1.split_once('=').unwrap().1;
    assert!(!body.to_string().contains(raw), "the token never comes back");
}

/// A password change needs the current password — a stolen cookie must not
/// rotate it quietly — and a wrong one is refused and audited. The rotation
/// test: two sessions; change with one; the other is dead, the acting one
/// lives on under a NEW cookie, and the old cookie value is dead too.
#[tokio::test]
async fn a_password_change_needs_the_current_one_and_rotates_every_session() {
    let Some(app) = test_app().await else { return };
    let acting = api_login(&app, "alice", "alicepw123").await;
    let other = api_login(&app, "alice", "alicepw123").await;
    let change = |current: &str, new: &str, confirm: &str| serde_json::json!({
        "current_password": current, "new_password": new, "confirm_password": confirm });

    for (body, code) in [
        (change("wrong-one", "newpassword1", "newpassword1"), "wrong_password"),
        (change("alicepw123", "newpassword1", "different12"), "mismatch"),
        (change("alicepw123", "short", "short"), "too_short"),
        (change("alicepw123", &"x".repeat(1025), &"x".repeat(1025)), "too_long"),
    ] {
        let (st, _, resp) = send_json(&app.router, "POST", "/api/v1/me/password", Some(&acting), Some(body)).await;
        assert_eq!(resp["error"]["code"], code, "{resp}");
        assert!(st == StatusCode::UNPROCESSABLE_ENTITY || st == StatusCode::FORBIDDEN, "{code}: {st}");
    }
    assert_eq!(audit_count(&app, "change_password_failed", "alice").await, 1, "the wrong password was audited");
    for s in [&acting, &other] {
        let (st, _, _) = send_json(&app.router, "GET", "/api/v1/databases", Some(s), None).await;
        assert_eq!(st, StatusCode::OK, "PRECONDITION: refusals changed nothing");
    }

    let (st, h, resp) = send_json(&app.router, "POST", "/api/v1/me/password", Some(&acting),
        Some(change("alicepw123", "newpassword1", "newpassword1"))).await;
    assert_eq!(st, StatusCode::OK, "{resp}");
    let rotated = h.get(header::SET_COOKIE).expect("the acting session is rotated")
        .to_str().unwrap().split(';').next().unwrap().to_string();
    assert_ne!(rotated, acting);
    assert_eq!(resp["other_sessions_signed_out"], 1);
    for (s, want) in [(&other, StatusCode::UNAUTHORIZED), (&acting, StatusCode::UNAUTHORIZED), (&rotated, StatusCode::OK)] {
        let (st, _, _) = send_json(&app.router, "GET", "/api/v1/databases", Some(s), None).await;
        assert_eq!(st, want);
    }
    let _ = api_login(&app, "alice", "newpassword1").await;
}

/// Sign out everywhere else kills only the others.
#[tokio::test]
async fn revoking_other_sessions_keeps_this_one() {
    let Some(app) = test_app().await else { return };
    let mine = api_login(&app, "alice", "alicepw123").await;
    let others = [api_login(&app, "alice", "alicepw123").await, api_login(&app, "alice", "alicepw123").await];
    let bob = api_login(&app, "bob", "bobpw123").await;
    let (st, _, resp) = send_json(&app.router, "POST", "/api/v1/me/sessions/revoke-others", Some(&mine),
        Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::OK, "{resp}");
    assert_eq!(resp["signed_out"], 2);
    for o in &others {
        let (st, _, _) = send_json(&app.router, "GET", "/api/v1/databases", Some(o), None).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }
    for s in [&mine, &bob] {
        let (st, _, _) = send_json(&app.router, "GET", "/api/v1/databases", Some(s), None).await;
        assert_eq!(st, StatusCode::OK, "only alice's others go");
    }
}

/// A password change is one transaction: the new hash, every old session
/// gone, the acting one re-issued. If any part fails, none of it happened —
/// so the old password still works and the response says nothing changed
/// (the handover's carry-over: a stolen pre-change cookie must not survive a
/// change reported as done). The trigger refuses the LAST step, issuing the
/// new session — after the old ones were deleted — so only one transaction
/// around all of it brings them back. The precondition is the same change
/// succeeding without it.
#[tokio::test]
async fn a_password_change_happens_whole_or_not_at_all() {
    let Some(app) = test_app().await else { return };
    let acting = api_login(&app, "alice", "alicepw123").await;
    let other = api_login(&app, "alice", "alicepw123").await;
    let change = serde_json::json!({"current_password": "alicepw123", "new_password": "newpassword1",
                                    "confirm_password": "newpassword1"});
    for sql in [
        "CREATE FUNCTION refuse_session_insert() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN RAISE EXCEPTION 'sessions refused'; END $$",
        "CREATE TRIGGER refuse_session_insert BEFORE INSERT ON sessions \
         FOR EACH ROW EXECUTE FUNCTION refuse_session_insert()",
    ] {
        sqlx::query(AssertSqlSafe(sql)).execute(&app.db).await.unwrap();
    }
    let (st, h, body) = send_json(&app.router, "POST", "/api/v1/me/password", Some(&acting), Some(change.clone())).await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert!(h.get(header::SET_COOKIE).is_none(), "no new cookie for a change that did not happen");
    assert!(body["error"]["message"].as_str().unwrap().contains("not changed"), "{body}");
    for s in [&acting, &other] {
        let (st, _, _) = send_json(&app.router, "GET", "/api/v1/databases", Some(s), None).await;
        assert_eq!(st, StatusCode::OK, "a session died in a change that did not happen");
    }
    sqlx::query("DROP TRIGGER refuse_session_insert ON sessions").execute(&app.db).await.unwrap();
    let _ = api_login(&app, "alice", "alicepw123").await; // the old password still works
    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/me/password", Some(&acting), Some(change)).await;
    assert_eq!(st, StatusCode::OK, "PRECONDITION: the same change goes through: {body}");
}

/// The profile is what a session with an admin-set password is FOR
/// (CRYPTARCH-146): it reaches all three endpoints, and after the change the
/// gate is lifted for its rotated session.
#[tokio::test]
async fn a_gated_session_can_reach_the_profile_and_lift_its_gate() {
    let Some(app) = test_app().await else { return };
    let admin = login(&app, "admin", "adminpw123").await;
    let issued = admin_resets_account(&app, &admin, "alice").await;
    let gated = api_login(&app, "alice", &issued).await;
    let (st, _, _) = send_json(&app.router, "GET", "/api/v1/databases", Some(&gated), None).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "PRECONDITION: gated");
    let (st, _, _) = send_json(&app.router, "GET", "/api/v1/me/sessions", Some(&gated), None).await;
    assert_eq!(st, StatusCode::OK);
    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/me/sessions/revoke-others", Some(&gated),
        Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::OK);
    let (st, h, body) = send_json(&app.router, "POST", "/api/v1/me/password", Some(&gated),
        Some(serde_json::json!({"current_password": issued, "new_password": "alicesown12",
                                "confirm_password": "alicesown12"}))).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let rotated = h.get(header::SET_COOKIE).unwrap().to_str().unwrap().split(';').next().unwrap().to_string();
    let (st, _, me) = send_json(&app.router, "GET", "/api/v1/session", Some(&rotated), None).await;
    assert_eq!((st, &me["must_change_password"]), (StatusCode::OK, &serde_json::json!(false)));
    let (st, _, _) = send_json(&app.router, "GET", "/api/v1/databases", Some(&rotated), None).await;
    assert_eq!(st, StatusCode::OK, "the gate lifted");
    // And the ROTATED session keeps its lineage (CRYPTARCH-146): something it
    // does after the change is still recorded with the tag.
    api_provision(&app, &rotated, "alice_after").await;
    assert_eq!(actors_of(&app, "create_db", "alice_after").await, ["alice [on a password set by admin]"]);
}

/// Start `alice`'s password change while `concurrent` holds her rows in an
/// open transaction, commit it once the change is blocked on them, and return
/// what the change answered.
async fn change_racing(app: &TestApp, alice: &str, concurrent: &[&str]) -> (StatusCode, axum::http::HeaderMap, serde_json::Value) {
    let mut other = app.db.begin().await.unwrap();
    for sql in concurrent {
        sqlx::query(AssertSqlSafe(*sql)).execute(&mut *other).await.unwrap();
    }
    let router = app.router.clone();
    let cookie = alice.to_string();
    let change = tokio::spawn(async move {
        send_json(&router, "POST", "/api/v1/me/password", Some(&cookie),
            Some(serde_json::json!({"current_password": "alicepw123", "new_password": "attacker123",
                                    "confirm_password": "attacker123"}))).await
    });
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    other.commit().await.unwrap();
    change.await.unwrap()
}

/// An admin reset that lands while a user's change is being verified wins,
/// and the change is refused (S5 audit P1): the change re-checks, in its own
/// transaction, that the hash it verified is still the account's and that the
/// acting session still exists — each on its own, since either moving alone
/// means the verify no longer speaks for now. Deterministic: the concurrent
/// write holds the rows while the change runs into them, and commits after.
#[tokio::test]
async fn a_change_racing_an_admin_reset_loses_to_it() {
    let Some(app) = test_app().await else { return };
    let issued = cryptarch::auth::hash_password("adminissued1").unwrap();
    let alice_id = "(SELECT id FROM users WHERE username = 'alice')";

    // 1. A full admin reset: new hash, every session out.
    let alice = api_login(&app, "alice", "alicepw123").await;
    let reset_hash = format!("UPDATE users SET password_hash = '{issued}', password_set_by = 'admin' WHERE username = 'alice'");
    let sign_out_all = format!("DELETE FROM sessions WHERE user_id = {alice_id}");
    let (st, h, body) = change_racing(&app, &alice, &[&reset_hash, &sign_out_all]).await;
    assert_eq!((st, &body["error"]["code"]), (StatusCode::CONFLICT, &serde_json::json!("changed_elsewhere")), "{body}");
    assert!(h.get(header::SET_COOKIE).is_none(), "no session for a change that lost");
    let set_by: Option<String> = sqlx::query_scalar("SELECT password_set_by FROM users WHERE username = 'alice'")
        .fetch_one(&app.db).await.unwrap();
    assert_eq!(set_by.as_deref(), Some("admin"), "the reset stands");
    let live: i64 = sqlx::query_scalar(AssertSqlSafe(format!("SELECT count(*) FROM sessions WHERE user_id = {alice_id}")))
        .fetch_one(&app.db).await.unwrap();
    assert_eq!(live, 0, "the reset's sign-out stands");
    let _ = api_login(&app, "alice", "adminissued1").await; // the admin's password works

    // 2. Only the hash moves (a reset whose sign-out failed, CRYPTARCH-102).
    sqlx::query("UPDATE users SET password_hash = $1, password_set_by = NULL WHERE username = 'alice'")
        .bind(cryptarch::auth::hash_password("alicepw123").unwrap()).execute(&app.db).await.unwrap();
    let alice = api_login(&app, "alice", "alicepw123").await;
    let (st, _, body) = change_racing(&app, &alice, &[&reset_hash]).await;
    assert_eq!((st, &body["error"]["code"]), (StatusCode::CONFLICT, &serde_json::json!("changed_elsewhere")),
        "a moved hash alone refuses it: {body}");

    // 3. Only this session goes (signed out from another device mid-change).
    sqlx::query("UPDATE users SET password_hash = $1, password_set_by = NULL WHERE username = 'alice'")
        .bind(cryptarch::auth::hash_password("alicepw123").unwrap()).execute(&app.db).await.unwrap();
    let alice = api_login(&app, "alice", "alicepw123").await;
    let token = alice.split_once('=').unwrap().1;
    use sha2::Digest;
    let digest: String = sha2::Sha256::digest(token.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
    let this_session = format!("DELETE FROM sessions WHERE token_hash = '{digest}'");
    let (st, _, body) = change_racing(&app, &alice, &[&this_session]).await;
    assert_eq!((st, &body["error"]["code"]), (StatusCode::CONFLICT, &serde_json::json!("changed_elsewhere")),
        "a signed-out session alone refuses it: {body}");
    let _ = api_login(&app, "alice", "alicepw123").await; // nothing changed

    // PRECONDITION: unraced, the same change goes through.
    let alice = api_login(&app, "alice", "alicepw123").await;
    let (st, _, body) = change_racing(&app, &alice, &[]).await;
    assert_eq!(st, StatusCode::OK, "{body}");
}

/// Guessing the current password through a stolen session is throttled like
/// guessing it at login (S5 audit P2) — the same counter, so neither door is a
/// way around the other. The precondition is that the guesses were refused as
/// wrong first, not throttled from the start.
#[tokio::test]
async fn guessing_the_current_password_is_throttled_like_login() {
    let Some(app) = test_app().await else { return };
    let stolen = api_login(&app, "alice", "alicepw123").await;
    let guess = |current: &str| serde_json::json!({"current_password": current, "new_password": "attacker123",
                                                   "confirm_password": "attacker123"});
    for i in 0..5 {
        let (st, _, body) = send_json(&app.router, "POST", "/api/v1/me/password", Some(&stolen), Some(guess(&format!("guess{i}")))).await;
        assert_eq!((st, &body["error"]["code"]), (StatusCode::FORBIDDEN, &serde_json::json!("wrong_password")), "{body}");
    }
    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/me/password", Some(&stolen), Some(guess("alicepw123"))).await;
    assert_eq!((st, &body["error"]["code"]), (StatusCode::TOO_MANY_REQUESTS, &serde_json::json!("throttled")),
        "even the right one, while throttled: {body}");
    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/session", None,
        Some(serde_json::json!({"username": "alice", "password": "alicepw123"}))).await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS, "and login shares the count");
    let _ = api_login(&app, "bob", "bobpw123").await; // per user, not global
}

/// The re-issued cookie carries a login cookie's flags; a sign-out-everywhere
/// that fails says so, through both doors, instead of a count of none.
#[tokio::test]
async fn the_rotated_cookie_is_a_login_cookie_and_a_failed_revoke_says_so() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    let (st, h, _) = send_json(&app.router, "POST", "/api/v1/me/password", Some(&alice),
        Some(serde_json::json!({"current_password": "alicepw123", "new_password": "newpassword1",
                                "confirm_password": "newpassword1"}))).await;
    assert_eq!(st, StatusCode::OK);
    let set = h.get(header::SET_COOKIE).unwrap().to_str().unwrap().to_string();
    for flag in ["HttpOnly", "SameSite=Lax", "Path=/"] {
        assert!(set.contains(flag), "rotated cookie lacks {flag}: {set}");
    }
    let rotated = set.split(';').next().unwrap().to_string();
    let _second = api_login(&app, "alice", "newpassword1").await;

    for sql in [
        "CREATE FUNCTION refuse_revoke() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN RAISE EXCEPTION 'revoke refused'; END $$",
        "CREATE TRIGGER refuse_revoke BEFORE DELETE ON sessions FOR EACH ROW EXECUTE FUNCTION refuse_revoke()",
    ] {
        sqlx::query(AssertSqlSafe(sql)).execute(&app.db).await.unwrap();
    }
    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/me/sessions/revoke-others", Some(&rotated),
        Some(serde_json::json!({}))).await;
    assert_eq!((st, &body["error"]["code"]), (StatusCode::INTERNAL_SERVER_ERROR, &serde_json::json!("revoke_failed")), "{body}");
    sqlx::query("DROP TRIGGER refuse_revoke ON sessions").execute(&app.db).await.unwrap();
    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/me/sessions/revoke-others", Some(&rotated),
        Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::OK, "PRECONDITION: it works without the trigger: {body}");
}

// ---- S6a: admin users (CRYPTARCH-134) ---------------------------------------

async fn user_id(app: &TestApp, name: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM users WHERE username = $1").bind(name).fetch_one(&app.db).await.unwrap()
}

/// Every admin endpoint is an admin's: a tenant is refused (403), a stranger
/// is asked to sign in (401), and an admin whose own password an admin set
/// is gated like anyone else (CRYPTARCH-146). The precondition for each is the
/// real admin's 2xx through the same path.
#[tokio::test]
async fn the_admin_api_is_for_admins() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;
    let alice = api_login(&app, "alice", "alicepw123").await;
    let bob = user_id(&app, "bob").await;
    let reads = ["/api/v1/admin/overview".to_string(), "/api/v1/admin/users".into(), format!("/api/v1/admin/users/{bob}")];
    let writes: [(String, serde_json::Value); 4] = [
        ("/api/v1/admin/users".into(), serde_json::json!({"username": "zed", "quota": 1, "is_admin": false})),
        (format!("/api/v1/admin/users/{bob}/reset-password"), serde_json::json!({})),
        (format!("/api/v1/admin/users/{bob}/quota"), serde_json::json!({"quota": 3})),
        (format!("/api/v1/admin/users/{bob}/active"), serde_json::json!({"active": true})),
    ];
    for path in &reads {
        let (st, _, body) = send_json(&app.router, "GET", path, Some(&alice), None).await;
        assert_eq!((st, &body["error"]["code"]), (StatusCode::FORBIDDEN, &serde_json::json!("forbidden")), "{path}");
        let (st, _, _) = send_json(&app.router, "GET", path, None, None).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{path}");
        let (st, _, body) = send_json(&app.router, "GET", path, Some(&admin), None).await;
        assert_eq!(st, StatusCode::OK, "PRECONDITION: {path}: {body}");
    }
    for (path, body) in &writes {
        let (st, _, resp) = send_json(&app.router, "POST", path, Some(&alice), Some(body.clone())).await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{path}: {resp}");
    }
    assert!(sqlx::query_scalar::<_, Option<Uuid>>("SELECT id FROM users WHERE username = 'zed'")
        .fetch_optional(&app.db).await.unwrap().is_none(), "a tenant created a user");
    for (path, body) in &writes {
        let (st, _, resp) = send_json(&app.router, "POST", path, Some(&admin), Some(body.clone())).await;
        assert!(st.is_success(), "PRECONDITION: the admin's {path}: {st} {resp}");
    }

    // An admin account an admin created is gated until its password is its own.
    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/admin/users", Some(&admin),
        Some(serde_json::json!({"username": "dana", "password": "danastart1", "quota": 1, "is_admin": true}))).await;
    assert_eq!(st, StatusCode::CREATED);
    let dana = api_login(&app, "dana", "danastart1").await;
    let (st, _, body) = send_json(&app.router, "GET", "/api/v1/admin/users", Some(&dana), None).await;
    assert_eq!((st, &body["error"]["code"]), (StatusCode::FORBIDDEN, &serde_json::json!("password_change_required")));
}

/// The overview's counts, and the users table's "used / quota" by the
/// enforcer's own predicate (CRYPTARCH-111). Nothing hash-shaped rides along.
#[tokio::test]
async fn the_admin_overview_and_users_say_what_is_there() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;
    let alice = api_login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_counted").await;
    api_provision(&app, &alice, "alice_dying2").await;
    sqlx::query("UPDATE databases SET status = 'deleting' WHERE name = 'alice_dying2'").execute(&app.db).await.unwrap();

    let (_, _, ov) = send_json(&app.router, "GET", "/api/v1/admin/overview", Some(&admin), None).await;
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM users").fetch_one(&app.db).await.unwrap();
    assert_eq!(ov["users"], users);
    assert_eq!(ov["servers"], 1);
    assert_eq!(ov["databases"], 2, "a database mid-delete is still on the disk: {ov}");
    assert_eq!(ov["backups_enabled"], true);

    let (_, _, list) = send_json(&app.router, "GET", "/api/v1/admin/users", Some(&admin), None).await;
    let users = list["users"].as_array().unwrap();
    let names: Vec<&str> = users.iter().map(|u| u["username"].as_str().unwrap()).collect();
    assert_eq!(names, ["admin", "alice", "bob"], "by name");
    let a = &users[1];
    assert_eq!((a["quota"].clone(), a["is_admin"].clone(), a["is_active"].clone()),
               (serde_json::json!(2), serde_json::json!(false), serde_json::json!(true)));
    let enforced: i64 = sqlx::query_scalar(AssertSqlSafe(format!(
        "SELECT count(*) FROM databases d JOIN users u ON u.id = d.owner_id WHERE u.username = 'alice' AND {}",
        cryptarch::status::DbStatus::quota_exclusion_sql()))).fetch_one(&app.db).await.unwrap();
    assert_eq!(a["used"], enforced, "the column counts what the cap counts: {a}");
    let mut keys: Vec<&str> = a.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(keys, ["id", "is_active", "is_admin", "must_change_password", "quota", "used", "username"]);
    assert!(!list.to_string().contains("$argon2"));

    let alice_id = user_id(&app, "alice").await;
    let (st, _, detail) = send_json(&app.router, "GET", &format!("/api/v1/admin/users/{alice_id}"), Some(&admin), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(detail["user"]["username"], "alice");
    assert_eq!(detail["is_self"], false);
    let dbs: Vec<&str> = detail["databases"].as_array().unwrap().iter().map(|d| d["name"].as_str().unwrap()).collect();
    assert_eq!(dbs, ["alice_dying2", "alice_counted"], "newest first");
    let admin_id = user_id(&app, "admin").await;
    let (_, _, me) = send_json(&app.router, "GET", &format!("/api/v1/admin/users/{admin_id}"), Some(&admin), None).await;
    assert_eq!(me["is_self"], true);
    let (st, _, _) = send_json(&app.router, "GET", &format!("/api/v1/admin/users/{}", Uuid::new_v4()), Some(&admin), None).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

/// Creating a user shows its password once (no-store), generated if none was
/// given, and the account starts gated (CRYPTARCH-146). Every refusal writes
/// nothing.
#[tokio::test]
async fn an_admin_creates_a_user_whose_password_is_shown_once() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;
    let create = |body: serde_json::Value| send_json(&app.router, "POST", "/api/v1/admin/users", Some(&admin), Some(body));

    for (body, code) in [
        (serde_json::json!({"username": "Bad Name", "quota": 1, "is_admin": false}), "bad_username"),
        (serde_json::json!({"username": "carl", "quota": 1000, "is_admin": false}), "bad_quota"),
        (serde_json::json!({"username": "carl", "quota": -1, "is_admin": false}), "bad_quota"),
        (serde_json::json!({"username": "carl", "password": "short", "quota": 1, "is_admin": false}), "too_short"),
        (serde_json::json!({"username": "alice", "quota": 1, "is_admin": false}), "username_taken"),
    ] {
        let (st, _, resp) = create(body.clone()).await;
        assert_eq!(resp["error"]["code"], code, "{body}: {resp}");
        assert!(st == StatusCode::UNPROCESSABLE_ENTITY || st == StatusCode::CONFLICT, "{st}");
    }
    assert!(sqlx::query_scalar::<_, Uuid>("SELECT id FROM users WHERE username = 'carl'")
        .fetch_optional(&app.db).await.unwrap().is_none());

    let (st, h, made) = create(serde_json::json!({"username": "carl", "quota": null, "is_admin": false})).await;
    assert_eq!(st, StatusCode::CREATED, "{made}");
    assert_eq!(h.get(header::CACHE_CONTROL).unwrap(), "no-store");
    let password = made["password"].as_str().unwrap();
    assert_eq!(password.len(), 32, "generated when none is given");
    let (quota, set_by): (Option<i32>, Option<String>) =
        sqlx::query_as("SELECT db_quota, password_set_by FROM users WHERE username = 'carl'").fetch_one(&app.db).await.unwrap();
    assert_eq!((quota, set_by.as_deref()), (None, Some("admin")), "unlimited, and an admin's password");
    let carl = api_login(&app, "carl", password).await;
    let (st, _, _) = send_json(&app.router, "GET", "/api/v1/databases", Some(&carl), None).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "gated until it is carl's own");
    assert_eq!(audit_count(&app, "create_user", "carl").await, 1);

    let (st, _, made) = create(serde_json::json!({"username": "cora", "password": "corastart1", "quota": 3, "is_admin": true})).await;
    assert_eq!(st, StatusCode::CREATED);
    assert_eq!(made["password"], "corastart1", "a supplied one is used as given");
    assert_eq!(made["is_admin"], true);
}

/// Reset: a new password shown once, every session of theirs gone, the
/// account gated — in one transaction, so a failure changes nothing (the old
/// password still works and nothing is shown). Never your own account here.
#[tokio::test]
async fn an_admin_reset_is_shown_once_and_whole_or_not_at_all() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;
    let alice_session = api_login(&app, "alice", "alicepw123").await;
    let alice_id = user_id(&app, "alice").await;
    let reset = format!("/api/v1/admin/users/{alice_id}/reset-password");

    for sql in [
        "CREATE FUNCTION refuse_reset() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN RAISE EXCEPTION 'reset refused'; END $$",
        "CREATE TRIGGER refuse_reset BEFORE DELETE ON sessions FOR EACH ROW EXECUTE FUNCTION refuse_reset()",
    ] {
        sqlx::query(AssertSqlSafe(sql)).execute(&app.db).await.unwrap();
    }
    let (st, _, body) = send_json(&app.router, "POST", &reset, Some(&admin), Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(body["error"]["code"], "internal", "an error, not a password, for a reset that did not happen: {body}");
    sqlx::query("DROP TRIGGER refuse_reset ON sessions").execute(&app.db).await.unwrap();
    let (st, _, _) = send_json(&app.router, "GET", "/api/v1/databases", Some(&alice_session), None).await;
    assert_eq!(st, StatusCode::OK, "her session survived the failed reset");
    let _ = api_login(&app, "alice", "alicepw123").await; // and her password

    let (st, h, body) = send_json(&app.router, "POST", &reset, Some(&admin), Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(h.get(header::CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(body["username"], "alice");
    let issued = body["password"].as_str().unwrap();
    let (st, _, _) = send_json(&app.router, "GET", "/api/v1/databases", Some(&alice_session), None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "every session of hers is gone");
    let gated = api_login(&app, "alice", issued).await;
    let (_, _, me) = send_json(&app.router, "GET", "/api/v1/session", Some(&gated), None).await;
    assert_eq!(me["must_change_password"], true);
    assert_eq!(audit_count(&app, "reset_user_password", "alice").await, 1);

    let admin_id = user_id(&app, "admin").await;
    let (st, _, body) = send_json(&app.router, "POST", &format!("/api/v1/admin/users/{admin_id}/reset-password"),
        Some(&admin), Some(serde_json::json!({}))).await;
    assert_eq!((st, &body["error"]["code"]), (StatusCode::CONFLICT, &serde_json::json!("own_account")), "{body}");
    let _ = api_login(&app, "admin", "adminpw123").await; // unchanged
    let (st, _, _) = send_json(&app.router, "POST", &format!("/api/v1/admin/users/{}/reset-password", Uuid::new_v4()),
        Some(&admin), Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

/// Quota: a number 0-999 or unlimited (null); audited; nothing else accepted.
#[tokio::test]
async fn an_admin_sets_a_quota() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;
    let bob = user_id(&app, "bob").await;
    let path = format!("/api/v1/admin/users/{bob}/quota");
    let quota = || async { sqlx::query_scalar::<_, Option<i32>>("SELECT db_quota FROM users WHERE username = 'bob'").fetch_one(&app.db).await.unwrap() };
    for bad in [serde_json::json!(1000), serde_json::json!(-1), serde_json::json!("lots")] {
        let (st, _, body) = send_json(&app.router, "POST", &path, Some(&admin), Some(serde_json::json!({"quota": bad}))).await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{bad}: {body}");
    }
    assert_eq!(quota().await, Some(1), "unchanged by refusals");
    let (st, _, _) = send_json(&app.router, "POST", &path, Some(&admin), Some(serde_json::json!({"quota": 7}))).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(quota().await, Some(7));
    let (st, _, _) = send_json(&app.router, "POST", &path, Some(&admin), Some(serde_json::json!({"quota": null}))).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(quota().await, None, "unlimited");
    assert_eq!(audit_count(&app, "set_quota", &bob.to_string()).await, 2);
    let (st, _, _) = send_json(&app.router, "POST", &format!("/api/v1/admin/users/{}/quota", Uuid::new_v4()),
        Some(&admin), Some(serde_json::json!({"quota": 3}))).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "a quota for nobody is not a success");
}

/// Suspension signs out every session, in the same transaction as the flag:
/// if the sign-out cannot happen, neither does the suspension. Enabling
/// restores login. Never your own account.
#[tokio::test]
async fn a_suspension_is_whole_or_not_at_all_and_never_your_own() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;
    let alice_session = api_login(&app, "alice", "alicepw123").await;
    let alice_id = user_id(&app, "alice").await;
    let active = format!("/api/v1/admin/users/{alice_id}/active");
    let is_active = || async { sqlx::query_scalar::<_, bool>("SELECT is_active FROM users WHERE username = 'alice'").fetch_one(&app.db).await.unwrap() };

    for sql in [
        "CREATE FUNCTION refuse_suspend() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN RAISE EXCEPTION 'suspend refused'; END $$",
        "CREATE TRIGGER refuse_suspend BEFORE DELETE ON sessions FOR EACH ROW EXECUTE FUNCTION refuse_suspend()",
    ] {
        sqlx::query(AssertSqlSafe(sql)).execute(&app.db).await.unwrap();
    }
    let (st, _, body) = send_json(&app.router, "POST", &active, Some(&admin), Some(serde_json::json!({"active": false}))).await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert!(is_active().await, "a suspension whose sign-out failed did not happen");
    assert_eq!(audit_count(&app, "suspend_user", &alice_id.to_string()).await, 0);
    sqlx::query("DROP TRIGGER refuse_suspend ON sessions").execute(&app.db).await.unwrap();

    let (st, _, _) = send_json(&app.router, "GET", "/api/v1/databases", Some(&alice_session), None).await;
    assert_eq!(st, StatusCode::OK, "PRECONDITION: her session works before the suspension");
    let (st, _, _) = send_json(&app.router, "POST", &active, Some(&admin), Some(serde_json::json!({"active": false}))).await;
    assert_eq!(st, StatusCode::OK);
    assert!(!is_active().await);
    let (st, _, _) = send_json(&app.router, "GET", "/api/v1/databases", Some(&alice_session), None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "her session is gone");
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions WHERE user_id = $1").bind(alice_id).fetch_one(&app.db).await.unwrap();
    assert_eq!(left, 0, "and so are its rows");
    let (st, _, _) = send_json(&app.router, "POST", &active, Some(&admin), Some(serde_json::json!({"active": true}))).await;
    assert_eq!(st, StatusCode::OK);
    let _ = api_login(&app, "alice", "alicepw123").await;
    assert_eq!(audit_count(&app, "suspend_user", &alice_id.to_string()).await, 1);
    assert_eq!(audit_count(&app, "enable_user", &alice_id.to_string()).await, 1);

    let admin_id = user_id(&app, "admin").await;
    let (st, _, body) = send_json(&app.router, "POST", &format!("/api/v1/admin/users/{admin_id}/active"),
        Some(&admin), Some(serde_json::json!({"active": false}))).await;
    assert_eq!((st, &body["error"]["code"]), (StatusCode::CONFLICT, &serde_json::json!("own_account")));
    let (st, _, _) = send_json(&app.router, "GET", "/api/v1/admin/users", Some(&admin), None).await;
    assert_eq!(st, StatusCode::OK, "still in");
}

/// A login that lands while an admin's reset or suspension is in flight must
/// wait for it and lose (S6a audit P2): otherwise it reads the account as it
/// was, inserts a session after the sign-out, and that session survives — a
/// suspended user's cookie working again once they are re-enabled.
/// Deterministic: the admin's transaction is held open, signed out, while the
/// login runs into it; then it commits.
#[tokio::test]
async fn a_login_cannot_slip_a_session_into_a_suspension_or_reset() {
    let Some(app) = test_app().await else { return };
    let alice = user_id(&app, "alice").await;
    for change in [
        "UPDATE users SET is_active = false WHERE username = 'alice'",
        "UPDATE users SET password_hash = 'x', password_set_by = 'admin' WHERE username = 'alice'",
    ] {
        let mut admin_tx = app.db.begin().await.unwrap();
        sqlx::query(AssertSqlSafe(change)).execute(&mut *admin_tx).await.unwrap();
        sqlx::query("DELETE FROM sessions WHERE user_id = $1").bind(alice).execute(&mut *admin_tx).await.unwrap();
        let router = app.router.clone();
        let login = tokio::spawn(async move {
            send_json(&router, "POST", "/api/v1/session", None,
                Some(serde_json::json!({"username": "alice", "password": "alicepw123"}))).await.0
        });
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        admin_tx.commit().await.unwrap();
        let st = login.await.unwrap();
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{change}: the login won");
        let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions WHERE user_id = $1")
            .bind(alice).fetch_one(&app.db).await.unwrap();
        assert_eq!(sessions, 0, "{change}: a session survived the sign-out");
        // Put alice back for the next round.
        sqlx::query("UPDATE users SET is_active = true, password_set_by = NULL, password_hash = $1 WHERE id = $2")
            .bind(cryptarch::auth::hash_password("alicepw123").unwrap()).bind(alice).execute(&app.db).await.unwrap();
    }
    let _ = api_login(&app, "alice", "alicepw123").await; // PRECONDITION: unraced, she signs in
}

/// Two admins cannot suspend each other into an empty building (S6a audit
/// P2): the actor must still be an active admin when the change commits —
/// checked under a lock on both rows. dana's request runs into admin's
/// suspension of her, waits, and is refused; admin is still active.
#[tokio::test]
async fn two_admins_cannot_suspend_each_other_out() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;
    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/admin/users", Some(&admin),
        Some(serde_json::json!({"username": "dana", "password": "danastart1", "quota": 1, "is_admin": true}))).await;
    assert_eq!(st, StatusCode::CREATED);
    let dana_id = user_id(&app, "dana").await;
    let admin_id = user_id(&app, "admin").await;
    sqlx::query("UPDATE users SET password_set_by = NULL WHERE id = $1").bind(dana_id).execute(&app.db).await.unwrap();
    let dana = api_login(&app, "dana", "danastart1").await;

    // admin's suspension of dana, held open.
    let mut admin_tx = app.db.begin().await.unwrap();
    sqlx::query("UPDATE users SET is_active = false WHERE id = $1").bind(dana_id).execute(&mut *admin_tx).await.unwrap();
    let router = app.router.clone();
    let dana_req = tokio::spawn(async move {
        send_json(&router, "POST", &format!("/api/v1/admin/users/{admin_id}/active"), Some(&dana),
            Some(serde_json::json!({"active": false}))).await
    });
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    admin_tx.commit().await.unwrap();
    let (st, _, body) = dana_req.await.unwrap();
    assert!(!st.is_success(), "a suspended admin's suspension went through: {body}");
    let active: bool = sqlx::query_scalar("SELECT is_active FROM users WHERE id = $1").bind(admin_id).fetch_one(&app.db).await.unwrap();
    assert!(active, "no active admin is left");
    let (st, _, _) = send_json(&app.router, "GET", "/api/v1/admin/users", Some(&admin), None).await;
    assert_eq!(st, StatusCode::OK, "PRECONDITION: admin is still in");
}

/// A quota is said, never assumed: a body without one (or with a typo) is
/// refused, not read as "unlimited"; a fraction is not a quota.
#[tokio::test]
async fn a_quota_must_be_given_and_whole() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;
    let bob = user_id(&app, "bob").await;
    let path = format!("/api/v1/admin/users/{bob}/quota");
    for body in [serde_json::json!({}), serde_json::json!({"qouta": 3}), serde_json::json!({"quota": 2.5})] {
        let (st, _, resp) = send_json(&app.router, "POST", &path, Some(&admin), Some(body.clone())).await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{body}: {resp}");
    }
    let quota: Option<i32> = sqlx::query_scalar("SELECT db_quota FROM users WHERE id = $1").bind(bob).fetch_one(&app.db).await.unwrap();
    assert_eq!(quota, Some(1), "a refused quota changed it");
    let (st, _, resp) = send_json(&app.router, "POST", "/api/v1/admin/users", Some(&admin),
        Some(serde_json::json!({"username": "noquota", "is_admin": false}))).await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "a user with no quota said: {resp}");
    let (st, _, resp) = send_json(&app.router, "POST", "/api/v1/admin/users", Some(&admin),
        Some(serde_json::json!({"username": "longpw", "password": "x".repeat(1025), "quota": 1, "is_admin": false}))).await;
    assert_eq!((st, &resp["error"]["code"]), (StatusCode::UNPROCESSABLE_ENTITY, &serde_json::json!("too_long")));
}

/// The acting admin is recorded by `Session::actor()`: an admin whose session
/// began on a password another admin set is tagged on every change they
/// make (CRYPTARCH-146). A plain admin's actor equals their username, so only
/// a tagged one tells the two apart.
#[tokio::test]
async fn a_tagged_admin_is_recorded_as_tagged() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;
    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/admin/users", Some(&admin),
        Some(serde_json::json!({"username": "dana", "password": "danastart1", "quota": 1, "is_admin": true}))).await;
    assert_eq!(st, StatusCode::CREATED);
    let gated = api_login(&app, "dana", "danastart1").await;
    let (st, h, _) = send_json(&app.router, "POST", "/api/v1/me/password", Some(&gated),
        Some(serde_json::json!({"current_password": "danastart1", "new_password": "danasown123", "confirm_password": "danasown123"}))).await;
    assert_eq!(st, StatusCode::OK);
    let dana = h.get(header::SET_COOKIE).unwrap().to_str().unwrap().split(';').next().unwrap().to_string();
    let bob = user_id(&app, "bob").await;
    for (path, body) in [
        ("/api/v1/admin/users".to_string(), serde_json::json!({"username": "fay", "quota": 1, "is_admin": false})),
        (format!("/api/v1/admin/users/{bob}/quota"), serde_json::json!({"quota": 4})),
        (format!("/api/v1/admin/users/{bob}/reset-password"), serde_json::json!({})),
        (format!("/api/v1/admin/users/{bob}/active"), serde_json::json!({"active": false})),
    ] {
        let (st, _, resp) = send_json(&app.router, "POST", &path, Some(&dana), Some(body)).await;
        assert!(st.is_success(), "{path}: {resp}");
    }
    let tagged = "dana [on a password set by admin]";
    assert_eq!(actors_of(&app, "create_user", "fay").await, [tagged]);
    assert_eq!(actors_of(&app, "reset_user_password", "bob").await, [tagged]);
    assert_eq!(actors_of(&app, "set_quota", &bob.to_string()).await, [tagged]);
    assert_eq!(actors_of(&app, "suspend_user", &bob.to_string()).await, [tagged]);
}

/// Every admin change is recorded with the acting admin, in the same
/// transaction as the change; the list says which accounts still hold an
/// admin-set password; the overview knows when backups are off.
#[tokio::test]
async fn admin_changes_are_audited_as_their_admin() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;
    let bob = user_id(&app, "bob").await;
    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/admin/users", Some(&admin),
        Some(serde_json::json!({"username": "evan", "quota": 2, "is_admin": false}))).await;
    assert_eq!(st, StatusCode::CREATED);
    for (path, body) in [
        (format!("/api/v1/admin/users/{bob}/quota"), serde_json::json!({"quota": 4})),
        (format!("/api/v1/admin/users/{bob}/reset-password"), serde_json::json!({})),
        (format!("/api/v1/admin/users/{bob}/active"), serde_json::json!({"active": false})),
        (format!("/api/v1/admin/users/{bob}/active"), serde_json::json!({"active": true})),
    ] {
        let (st, _, resp) = send_json(&app.router, "POST", &path, Some(&admin), Some(body)).await;
        assert!(st.is_success(), "{path}: {resp}");
    }
    assert_eq!(actors_of(&app, "create_user", "evan").await, ["admin"]);
    assert_eq!(actors_of(&app, "reset_user_password", "bob").await, ["admin"]);
    for action in ["set_quota", "suspend_user", "enable_user"] {
        assert_eq!(actors_of(&app, action, &bob.to_string()).await, ["admin"], "{action}");
    }
    let (_, _, list) = send_json(&app.router, "GET", "/api/v1/admin/users", Some(&admin), None).await;
    let flag = |name: &str| list["users"].as_array().unwrap().iter().find(|u| u["username"] == name).unwrap()["must_change_password"].clone();
    assert_eq!((flag("bob"), flag("evan"), flag("alice")), (serde_json::json!(true), serde_json::json!(true), serde_json::json!(false)));

    let mut off = test_state(&app);
    off.backup_dir = None;
    let (_, _, ov) = send_json(&web::router(off), "GET", "/api/v1/admin/overview", Some(&admin), None).await;
    assert_eq!(ov["backups_enabled"], false);
}

// ---- S6b: admin databases and audit (CRYPTARCH-134) ---------------------------

/// Every database, newest first, with its owner, server and LAST BACKUP —
/// "never" when there is none, and the read-back mark beside an ok one.
/// Admin only.
#[tokio::test]
async fn the_admin_sees_every_database_and_its_last_backup() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;
    let alice = api_login(&app, "alice", "alicepw123").await;
    let bob = api_login(&app, "bob", "bobpw123").await;
    api_provision(&app, &alice, "alice_fleet").await;
    api_provision(&app, &bob, "bob_fleet").await;
    let (b, _) = seed_backup(&app, "alice_fleet", chrono::Duration::hours(1), "ok").await;
    let _ = b;

    let (st, _, body) = send_json(&app.router, "GET", "/api/v1/admin/databases", Some(&alice), None).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{body}");
    let (st, _, body) = send_json(&app.router, "GET", "/api/v1/admin/databases", Some(&admin), None).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let rows = body["databases"].as_array().unwrap();
    let names: Vec<&str> = rows.iter().map(|d| d["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["bob_fleet", "alice_fleet"], "newest first");
    assert_eq!(rows[1]["owner"], "alice");
    assert_eq!(rows[1]["server_name"], "test-srv");
    assert_eq!(rows[1]["last_backup"]["status"], "ok");
    assert_eq!(rows[1]["last_backup"]["verified"], false);
    assert!(rows[0]["last_backup"].is_null(), "never is said as nothing, not a blank date: {}", rows[0]);
}

/// The last backup is THIS database's (CRYPTARCH-86): one that took a freed
/// name does not show the previous owner's backup as its own. The
/// precondition is that the old database showed it.
#[tokio::test]
async fn a_recycled_name_shows_no_backup_it_never_had() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;
    let alice = api_login(&app, "alice", "alicepw123").await;
    let bob = api_login(&app, "bob", "bobpw123").await;
    api_provision(&app, &alice, "reused").await;
    seed_backup(&app, "reused", chrono::Duration::hours(1), "ok").await;
    let last = || async {
        let (_, _, body) = send_json(&app.router, "GET", "/api/v1/admin/databases", Some(&admin), None).await;
        body["databases"].as_array().unwrap().iter().find(|d| d["name"] == "reused").unwrap()["last_backup"].clone()
    };
    assert_eq!(last().await["status"], "ok", "PRECONDITION: alice's database shows its backup");
    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/databases/reused/delete", Some(&alice),
        Some(serde_json::json!({"confirm": "reused"}))).await;
    assert_eq!(st, StatusCode::OK);
    api_provision(&app, &bob, "reused").await;
    assert!(last().await.is_null(), "bob's new database wears alice's backup");
}

/// The audit log pages newest first; each page names the cursor for the next
/// older one, and the last page names none. Admin only.
#[tokio::test]
async fn the_audit_log_pages_newest_first() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;
    let alice = api_login(&app, "alice", "alicepw123").await;
    // Exactly three full pages: a page that is precisely full must still say
    // whether anything older exists (the peek row), not guess from fullness.
    let existing: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log").fetch_one(&app.db).await.unwrap();
    sqlx::query("INSERT INTO audit_log (actor, action, target, detail) \
                 SELECT 'seed', 'seed_' || g, 't' || g, NULL FROM generate_series(1, $1) g")
        .bind((600 - existing) as i32).execute(&app.db).await.unwrap();
    let (st, _, _) = send_json(&app.router, "GET", "/api/v1/admin/audit", Some(&alice), None).await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    let mut seen = Vec::new();
    let mut before: Option<i64> = None;
    let mut pages = 0;
    loop {
        let path = match before { Some(b) => format!("/api/v1/admin/audit?before={b}"), None => "/api/v1/admin/audit".into() };
        let (st, _, body) = send_json(&app.router, "GET", &path, Some(&admin), None).await;
        assert_eq!(st, StatusCode::OK, "{body}");
        let entries = body["entries"].as_array().unwrap();
        assert!(entries.len() <= 200);
        seen.extend(entries.iter().map(|e| e["id"].as_i64().unwrap()));
        pages += 1;
        match body["older"].as_i64() {
            Some(c) => before = Some(c),
            None => break,
        }
        assert!(pages < 10, "the cursor never ran out");
    }
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log").fetch_one(&app.db).await.unwrap();
    assert_eq!(seen.len() as i64, total, "every entry, exactly once");
    assert!(seen.windows(2).all(|w| w[0] > w[1]), "newest first, no repeats");
    assert_eq!(total, 600, "PRECONDITION: exactly three full pages");
    assert_eq!(pages, 3, "no empty fourth page after a precisely full third");
    let (st, _, _) = send_json(&app.router, "GET", "/api/v1/admin/audit?before=notanumber", Some(&admin), None).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

// ---- S6c: the login report and finishing a delete (CRYPTARCH-134) -----------

/// The report says, per server, what the maud renderer says — one verdict,
/// decided once — and its headline always carries both numbers. Admin only.
#[tokio::test]
async fn the_login_report_says_what_each_server_is() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;
    let alice = api_login(&app, "alice", "alicepw123").await;
    let (st, _, _) = send_json(&app.router, "GET", "/api/v1/admin/logins", Some(&alice), None).await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    api_provision(&app, &alice, "alice_lr").await;
    // The panel administers no roles here, while metadata lists a database.
    let (st, _, body) = send_json(&app.router, "GET", "/api/v1/admin/logins", Some(&admin), None).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let server = &body["servers"][0];
    assert_eq!(server["server_name"], "test-srv");
    assert_eq!(server["verdict"], "sources_disagree", "{body}");
    assert_eq!(server["known_databases"], 1);
    // A disagreement is a finding: the headline must not read clean over it.
    assert_eq!(body["summary"], serde_json::json!({"findings": 1, "checked": 1, "unchecked": 0}));

    // Now the role exists with its login disabled: a finding, with its cause.
    app.engine.set_roles(vec![("alice_lr", false)]);
    let (_, _, body) = send_json(&app.router, "GET", "/api/v1/admin/logins", Some(&admin), None).await;
    let server = &body["servers"][0];
    assert_eq!(server["verdict"], "findings", "{body}");
    assert_eq!(server["roles_checked"], 1);
    assert_eq!(server["disabled"][0]["role_name"], "alice_lr");
    assert_eq!(server["disabled"][0]["db_name"], "alice_lr");
    assert_eq!(server["disabled"][0]["cause"], "disabled_outside_cryptarch");
    assert_eq!(body["summary"]["findings"], 1);
    // Gated admins and strangers are refused too.
    let (st, _, _) = send_json(&app.router, "GET", "/api/v1/admin/logins", None, None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

/// A stranded delete is listed with the two facts that decide whether
/// finishing it is safe; one that never changed anything is not offered.
/// Finishing needs the typed name, re-checks the server at action time, and
/// says which refusal it hit.
#[tokio::test]
async fn finishing_a_stranded_delete_is_typed_rechecked_and_explained() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;
    let alice = api_login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_stuck").await;
    sqlx::query("UPDATE databases SET status = 'deleting' WHERE name = 'alice_stuck'").execute(&app.db).await.unwrap();
    let retry = |confirm: &str| {
        let (router, admin, body) = (app.router.clone(), admin.clone(), serde_json::json!({"confirm": confirm}));
        async move { send_json(&router, "POST", "/api/v1/admin/logins/alice_stuck/retry-delete", Some(&admin), Some(body)).await }
    };
    let stranded = || async {
        let (_, _, body) = send_json(&app.router, "GET", "/api/v1/admin/logins", Some(&admin), None).await;
        body["stranded"].as_array().unwrap().iter().find(|s| s["name"] == "alice_stuck").cloned().unwrap()
    };

    // Nothing happened yet: login enabled, database present. Not offered, and
    // refused if forced.
    app.engine.set_roles(vec![("alice_stuck", true)]);
    app.engine.set_existing(vec!["alice_stuck"]);
    let s = stranded().await;
    assert_eq!((s["can_log_in"].clone(), s["db_exists"].clone(), s["retryable"].clone()),
               (serde_json::json!(true), serde_json::json!(true), serde_json::json!(false)));
    let (st, _, body) = retry("alice_stuck").await;
    assert_eq!((st, &body["error"]["code"]), (StatusCode::CONFLICT, &serde_json::json!("nothing_started")), "{body}");

    // Half done: the login is off. Offered; a wrong name refused first.
    app.engine.set_roles(vec![("alice_stuck", false)]);
    assert_eq!(stranded().await["retryable"], true);
    let (st, _, body) = retry("alice_stuc").await;
    assert_eq!((st, &body["error"]["code"]), (StatusCode::UNPROCESSABLE_ENTITY, &serde_json::json!("confirm_mismatch")));
    assert_eq!(engine_calls(&app, "drop:alice_stuck"), 0, "nothing dropped on a refusal");
    let (st, _, body) = retry(" alice_stuck ").await;
    assert_eq!(st, StatusCode::OK, "surrounding space forgiven, as delete's: {body}");
    assert_eq!(engine_calls(&app, "drop:alice_stuck"), 1);
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM databases WHERE name = 'alice_stuck'").fetch_one(&app.db).await.unwrap();
    assert_eq!(rows, 0);
    let (st, _, body) = retry("alice_stuck").await;
    assert_eq!((st, &body["error"]["code"]), (StatusCode::NOT_FOUND, &serde_json::json!("not_found")), "gone: {body}");

    // A row the sweep returned to service is not finished off.
    api_provision(&app, &alice, "alice_back").await;
    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/admin/logins/alice_back/retry-delete", Some(&admin),
        Some(serde_json::json!({"confirm": "alice_back"}))).await;
    assert_eq!((st, &body["error"]["code"]), (StatusCode::CONFLICT, &serde_json::json!("no_longer_deleting")), "{body}");
    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/admin/logins/alice_back/retry-delete", Some(&alice),
        Some(serde_json::json!({"confirm": "alice_back"}))).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "an admin's alone");
}

/// Finishing a delete acts on THE database that was stranded, by identity, and
/// on nothing else (S6b/c audit P1). A lookup taken before the name was freed
/// and re-provisioned must not drop the new tenant's database — even when the
/// server's state, read by name, looks finishable. Each guard on its own:
/// the row re-read by id; login still on (delete turns it off first, so on
/// means a provision in flight or a delete that never started); and one
/// finisher at a time.
#[tokio::test]
async fn finishing_a_delete_acts_only_on_the_database_that_was_stranded() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    let bob = api_login(&app, "bob", "bobpw123").await;
    api_provision(&app, &alice, "victim").await;
    sqlx::query("UPDATE databases SET status = 'deleting' WHERE name = 'victim'").execute(&app.db).await.unwrap();
    let stale = cryptarch::provision::find_db(&app.db, "victim").await.unwrap().unwrap();

    // Someone finishes it; bob takes the name.
    sqlx::query("DELETE FROM databases WHERE id = $1").bind(stale.id).execute(&app.db).await.unwrap();
    api_provision(&app, &bob, "victim").await;
    let drops = || engine_calls(&app, "drop:victim");
    let before = drops();

    // 1. The stale lookup, with the server looking finishable by name.
    app.engine.set_roles(vec![("victim", false)]);
    app.engine.set_existing(vec!["victim"]);
    let out = cryptarch::provision::retry_delete(&app.db, &app.servers, &stale, "victim", "admin").await.unwrap();
    assert!(matches!(out, Err(cryptarch::provision::RetryRefusal::NoLongerDeleting)), "{out:?}");
    assert_eq!(drops(), before, "the new tenant's database was dropped through a stale lookup");

    // 2. A current stranded row, but login on and no database: a provision in
    //    flight, never a half-finished delete.
    sqlx::query("UPDATE databases SET status = 'deleting' WHERE name = 'victim'").execute(&app.db).await.unwrap();
    let current = cryptarch::provision::find_db(&app.db, "victim").await.unwrap().unwrap();
    app.engine.set_roles(vec![("victim", true)]);
    app.engine.set_existing(vec![]);
    let out = cryptarch::provision::retry_delete(&app.db, &app.servers, &current, "victim", "admin").await.unwrap();
    assert!(matches!(out, Err(cryptarch::provision::RetryRefusal::NothingWasStarted)), "{out:?}");
    assert_eq!(drops(), before);

    // 3. One finisher at a time: another holds this database's finish lock.
    app.engine.set_roles(vec![("victim", false)]);
    app.engine.set_existing(vec!["victim"]);
    let mut other = app.db.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock(hashtext($1))").bind(format!("cryptarch-finish:{}", current.id))
        .execute(&mut *other).await.unwrap();
    let out = cryptarch::provision::retry_delete(&app.db, &app.servers, &current, "victim", "admin").await.unwrap();
    assert!(matches!(out, Err(cryptarch::provision::RetryRefusal::AlreadyBeingFinished)), "{out:?}");
    assert_eq!(drops(), before);
    sqlx::query("SELECT pg_advisory_unlock(hashtext($1))").bind(format!("cryptarch-finish:{}", current.id))
        .execute(&mut *other).await.unwrap();
    drop(other);

    // PRECONDITION: the same database, genuinely half-deleted, finishes.
    let out = cryptarch::provision::retry_delete(&app.db, &app.servers, &current, "victim", "admin").await.unwrap();
    assert!(out.is_ok(), "{out:?}");
    assert_eq!(drops(), before + 1);
}

/// A server that cannot be asked is neither offered nor acted on: the report
/// says it could not check (not "no data left to lose"), and finishing
/// refuses as uncheckable, dropping nothing.
#[tokio::test]
async fn an_unanswered_server_is_not_finished_or_offered() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;
    let alice = api_login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_dark").await;
    sqlx::query("UPDATE databases SET status = 'deleting' WHERE name = 'alice_dark'").execute(&app.db).await.unwrap();
    app.engine.set_checks_fail(true);
    let (_, _, body) = send_json(&app.router, "GET", "/api/v1/admin/logins", Some(&admin), None).await;
    let st = body["stranded"].as_array().unwrap().iter().find(|s| s["name"] == "alice_dark").cloned().unwrap();
    assert!(st["can_log_in"].is_null() && st["db_exists"].is_null(), "unknown is said as unknown: {st}");
    assert_eq!(st["retryable"], false);
    let (status, _, resp) = send_json(&app.router, "POST", "/api/v1/admin/logins/alice_dark/retry-delete", Some(&admin),
        Some(serde_json::json!({"confirm": "alice_dark"}))).await;
    assert_eq!((status, &resp["error"]["code"]), (StatusCode::CONFLICT, &serde_json::json!("uncheckable")), "{resp}");
    assert_eq!(engine_calls(&app, "drop:alice_dark"), 0);
}

/// Finishing a delete ends the way a delete does: the edge stops admitting
/// the database (its hba lines re-rendered without it). The precondition is
/// that the hba named it before.
#[tokio::test]
async fn finishing_a_delete_resyncs_the_edge() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;
    let alice = api_login(&app, "alice", "alicepw123").await;
    let dir = temp_conf_dir();
    sqlx::query("UPDATE managed_servers SET bouncer_conf_dir = $1 WHERE id = $2")
        .bind(dir.display().to_string()).bind(app.server_id).execute(&app.db).await.unwrap();
    api_provision(&app, &alice, "alice_edge_fin").await;
    let hba = || std::fs::read_to_string(dir.join("pgbouncer_hba.conf")).unwrap_or_default();
    assert!(hba().contains("alice_edge_fin"), "PRECONDITION: the edge admits it: {}", hba());
    sqlx::query("UPDATE databases SET status = 'deleting' WHERE name = 'alice_edge_fin'").execute(&app.db).await.unwrap();
    app.engine.set_roles(vec![("alice_edge_fin", false)]);
    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/admin/logins/alice_edge_fin/retry-delete", Some(&admin),
        Some(serde_json::json!({"confirm": "alice_edge_fin"}))).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert!(!hba().contains("alice_edge_fin"), "the edge still admits a finished delete: {}", hba());
    std::fs::remove_dir_all(&dir).ok();
}

// ---- CRYPTARCH-146: an admin-set password, and the trail it leaves ----------

/// Reset `user`'s account password through the admin page, as `admin_cookie`,
/// and return the password the page shows once.
async fn admin_resets_account(app: &TestApp, admin_cookie: &str, user: &str) -> String {
    let id: Uuid = sqlx::query_scalar("SELECT id FROM users WHERE username = $1")
        .bind(user).fetch_one(&app.db).await.unwrap();
    let (st, _, body) = send_json(&app.router, "POST", &format!("/api/v1/admin/users/{id}/reset-password"),
        Some(admin_cookie), Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::OK, "admin reset of {user}: {body}");
    body["password"].as_str().expect("the reset shows the new password").to_string()
}

/// Change the signed-in user's password through the profile form; returns the
/// status, the ROTATED session cookie, and the page.
async fn change_own_password(app: &TestApp, cookie: &str, current: &str, new: &str) -> (StatusCode, Option<String>, String) {
    let body = serde_json::json!({"current_password": current, "new_password": new, "confirm_password": new});
    let req = Request::builder().method("POST").uri("/api/v1/me/password")
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let rotated = resp.headers().get(header::SET_COOKIE)
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string());
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024).await.unwrap();
    (status, rotated, String::from_utf8_lossy(&bytes).into_owned())
}

async fn actors_of(app: &TestApp, action: &str, target: &str) -> Vec<String> {
    sqlx::query_scalar("SELECT actor FROM audit_log WHERE action = $1 AND target = $2 ORDER BY id")
        .bind(action).bind(target).fetch_all(&app.db).await.unwrap()
}

/// An account whose password an admin set can do nothing but replace it: no
/// database, no credential, through either door. It can still sign in, see
/// who it is and reach the form. Once the user has set their own password,
/// the very same requests work — the precondition that each refusal was the
/// gate and not something else.
#[tokio::test]
async fn an_admin_set_password_must_be_replaced_before_anything_else() {
    let Some(app) = test_app().await else { return };
    let alice_before = api_login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice_before, "alice_gated").await;
    let admin = login(&app, "admin", "adminpw123").await;
    let issued = admin_resets_account(&app, &admin, "alice").await;

    let alice = api_login(&app, "alice", &issued).await;
    let (st, _, me) = send_json(&app.router, "GET", "/api/v1/session", Some(&alice), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(me["must_change_password"], true, "{me}");

    let gated: [(&str, &str, Option<serde_json::Value>); 6] = [
        ("GET", "/api/v1/databases", None),
        ("GET", "/api/v1/databases/alice_gated", None),
        ("GET", "/api/v1/databases/alice_gated/acl", None),
        ("POST", "/api/v1/databases/alice_gated/reset", Some(serde_json::json!({}))),
        ("POST", "/api/v1/databases", Some(provision_body(app.server_id, "alice_gated2", "10.0.0.0/24"))),
        ("GET", "/api/v1/servers", None),
    ];
    for (method, path, body) in gated.clone() {
        let (st, _, resp) = send_json(&app.router, method, path, Some(&alice), body).await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{method} {path}: {resp}");
        assert_eq!(resp["error"]["code"], "password_change_required", "{method} {path}: {resp}");
    }
    assert_eq!(engine_calls(&app, "rotate:alice_gated"), 0, "a gated session reached the server");
    assert_eq!(engine_calls(&app, "create:alice_gated2"), 0);

    // The user sets their own; the same requests now go through.
    let (st, rotated, _) = change_own_password(&app, &alice, &issued, "alicesown123").await;
    assert_eq!(st, StatusCode::OK);
    let alice_own = api_login(&app, "alice", "alicesown123").await;
    let (_, _, me) = send_json(&app.router, "GET", "/api/v1/session", Some(&alice_own), None).await;
    assert_eq!(me["must_change_password"], false, "{me}");
    for (method, path, body) in gated {
        let (st, _, resp) = send_json(&app.router, method, path, Some(&alice_own), body).await;
        assert!(st.is_success(), "PRECONDITION: {method} {path} works once changed: {st} {resp}");
    }
    let rotated = rotated.expect("the change rotated the session");
    let (st, _, _) = send_json(&app.router, "GET", "/api/v1/databases", Some(&rotated), None).await;
    assert_eq!(st, StatusCode::OK, "and the rotated session is ungated");
}

/// The trail says who could have been acting. A session that began on a
/// password an admin set is recorded as such on everything it does — the
/// forced change included, and after it, since the admin who set it may be
/// the one who changed it. A session begun on the user's own password is not.
#[tokio::test]
async fn the_audit_trail_names_a_session_begun_on_an_admin_set_password() {
    let Some(app) = test_app().await else { return };
    let alice_first = api_login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice_first, "alice_trail").await;
    let admin = login(&app, "admin", "adminpw123").await;
    let issued = admin_resets_account(&app, &admin, "alice").await;

    // Whoever holds the issued password — the admin, say — signs in as alice,
    // replaces the password, and resets her database in the same session.
    let session = login(&app, "alice", &issued).await;
    let (_, rotated, _) = change_own_password(&app, &session, &issued, "chosen12345").await;
    let rotated = rotated.unwrap();
    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/databases/alice_trail/reset", Some(&rotated), Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::OK, "PRECONDITION: the reset happened");
    let tagged = "alice [on a password set by admin]";
    assert_eq!(actors_of(&app, "change_password", "alice").await, [tagged]);
    assert_eq!(actors_of(&app, "reset_password", "alice_trail").await, [tagged],
        "the lineage survives the rotation the password change does");
    // An ACL entry's "added by" is a record of who acted, too.
    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/databases/alice_trail/acl", Some(&rotated),
        Some(serde_json::json!({"cidr": "10.44.0.0/16"}))).await;
    assert_eq!(st, StatusCode::CREATED, "PRECONDITION: the source was added");
    let by: String = sqlx::query_scalar("SELECT created_by FROM acl_entries WHERE cidr = '10.44.0.0/16'")
        .fetch_one(&app.db).await.unwrap();
    assert_eq!(by, tagged);

    // A session begun on the password alice now holds is plainly hers.
    let fresh = api_login(&app, "alice", "chosen12345").await;
    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/databases/alice_trail/reset", Some(&fresh),
        Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(actors_of(&app, "reset_password", "alice_trail").await, [tagged, "alice"]);
}

/// A login whose verify straddles a password change must not produce a session
/// (CRYPTARCH-146 audit P1): the session is created only if the hash it was
/// verified against is still the account's, read in the same statement as the
/// lineage. Otherwise a login checked against an admin-issued password could
/// land after the user replaced it — ungated, untagged, and surviving the
/// change's revocation.
#[tokio::test]
async fn a_login_verified_against_a_replaced_password_gets_no_session() {
    let Some(app) = test_app().await else { return };
    let (id, hash): (Uuid, String) = sqlx::query_as("SELECT id, password_hash FROM users WHERE username = 'alice'")
        .fetch_one(&app.db).await.unwrap();
    let store = SessionStore::new(app.db.clone());
    let count = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM sessions WHERE user_id = $1")
            .bind(id).fetch_one(&app.db).await.unwrap()
    };
    let before = count().await;
    assert!(store.insert_for_login(id, "$argon2id$v=19$m=1,t=1,p=1$c3RhbGU$c3RhbGU").await.unwrap().is_none(),
        "a session for a hash the account no longer has");
    assert_eq!(count().await, before);
    let token = store.insert_for_login(id, &hash).await.unwrap();
    assert!(token.is_some(), "PRECONDITION: the current hash gets a session");
    assert_eq!(count().await, before + 1);
}

/// Every action a tagged session takes is recorded with the tag — not only the
/// three the first test samples. After the admin reset, no audit row may name
/// plain `alice`: each recording site has to use the session's actor. And an
/// admin whose own session is tagged passes the tag on to the accounts they
/// reset, so the chain stays readable.
#[tokio::test]
async fn nothing_a_tagged_session_does_is_recorded_untagged() {
    let Some(app) = test_app().await else { return };
    let admin = login(&app, "admin", "adminpw123").await;
    let issued = admin_resets_account(&app, &admin, "alice").await;
    let mark: i64 = sqlx::query_scalar("SELECT coalesce(max(id), 0) FROM audit_log").fetch_one(&app.db).await.unwrap();

    let gated = login(&app, "alice", &issued).await;
    // Refused while gated, and recorded tagged when it is attempted.
    let (st, _, _) = change_own_password(&app, &gated, "wrong-current", "whatever123").await;
    assert_eq!(st, StatusCode::FORBIDDEN, "PRECONDITION: the wrong current password is refused");
    let (_, rotated, _) = change_own_password(&app, &gated, &issued, "chosen12345").await;
    let s = rotated.unwrap();
    // One of each tenant action, through the session the change rotated.
    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/databases", Some(&s), Some(provision_body(app.server_id, "alice_sweep", "10.0.0.0/24"))).await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/databases/alice_sweep/acl", Some(&s), Some(serde_json::json!({"cidr": "10.45.0.0/16"}))).await;
    assert_eq!(st, StatusCode::CREATED);
    let entry: Uuid = sqlx::query_scalar("SELECT id FROM acl_entries WHERE cidr = '10.45.0.0/16'").fetch_one(&app.db).await.unwrap();
    let (st, _, _) = send_json(&app.router, "DELETE", &format!("/api/v1/databases/alice_sweep/acl/{entry}"), Some(&s), Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::OK);
    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/databases/alice_sweep/reset", Some(&s), Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::OK);
    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/me/sessions/revoke-others", Some(&s), Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::OK);
    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/databases/alice_sweep/delete", Some(&s), Some(serde_json::json!({"confirm": "alice_sweep"}))).await;
    assert_eq!(st, StatusCode::OK);

    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT action, actor FROM audit_log WHERE id > $1 AND actor LIKE 'alice%' ORDER BY id")
        .bind(mark).fetch_all(&app.db).await.unwrap();
    let actions: Vec<&str> = rows.iter().map(|(a, _)| a.as_str()).collect();
    for needed in ["change_password_failed", "change_password", "create_db", "acl_add", "acl_remove",
                   "reset_password", "revoke_sessions", "delete_db"] {
        assert!(actions.contains(&needed), "PRECONDITION: {needed} was recorded: {actions:?}");
    }
    let untagged: Vec<&(String, String)> = rows.iter().filter(|(_, actor)| actor == "alice").collect();
    assert!(untagged.is_empty(), "recorded as plain alice: {untagged:?}");

    // Chains: an admin whose session is tagged resets someone; the account
    // records the whole lineage.
    let erin = tagged_admin(&app, "erin").await;
    let _ = admin_resets_account(&app, &erin, "bob").await;
    let set_by: String = sqlx::query_scalar("SELECT password_set_by FROM users WHERE username = 'bob'")
        .fetch_one(&app.db).await.unwrap();
    assert_eq!(set_by, "erin [on a password set by admin]");
}

/// A tag is something only a signed-in session can earn. Throttled logins are
/// unauthenticated, so their row names no actor — or a crafted username could
/// write any actor it likes, a tag included.
#[tokio::test]
async fn an_unauthenticated_event_names_no_actor() {
    let Some(app) = test_app().await else { return };
    let forged = "alice [on a password set by admin]";
    for _ in 0..5 {
        let _ = send_json(&app.router, "POST", "/api/v1/session", None,
            Some(serde_json::json!({"username": forged, "password": "x"}))).await;
    }
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT actor, target FROM audit_log WHERE action = 'login_throttled'")
        .fetch_all(&app.db).await.unwrap();
    assert_eq!(rows.len(), 1, "PRECONDITION: the throttle tripped and was recorded");
    assert_eq!(rows[0].0, "(unauthenticated)");
    assert_eq!(rows[0].1.as_deref(), Some(forged), "the attempted name is kept, as the target");
}

// ---- user-side db view (v0.3 contents section) ------------------------------

/// CRYPTARCH-113: a wedged restore is reclaimed by the scheduler, not only by
/// a restart.
///
/// `enqueue` spawns the job and drops the handle, so a panic inside it is
/// swallowed; and `settle` deliberately leaves the row `running` when its
/// finishing UPDATE fails, "for a human to notice". Nothing was doing the
/// noticing — the only recovery was a boot-time sweep. Since the `running` row
/// IS the per-target lock, either path meant that database could never be
/// restored again until someone restarted the process, which on a homelab box
/// is months.
#[tokio::test]
async fn an_abandoned_restore_is_reclaimed_without_a_restart() {
    let Some(app) = test_app().await else { return };
    let alice = login(&app, "alice", "alicepw123").await;
    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/databases", Some(&alice), Some(provision_body(app.server_id, "alice_wedged", "10.0.0.0/24"))).await;
    assert_eq!(st, StatusCode::CREATED);
    let (backup_id, _) = seed_backup(&app, "alice_wedged", chrono::Duration::days(1), "ok").await;
    let db_id = database_for(&app, "alice_wedged").await;

    let insert_running = |id: Uuid, age_hours: i64| {
        let db = app.db.clone();
        async move {
            sqlx::query(
                "INSERT INTO restores (id, backup_id, source_name, target_name, database_id, \
                                       mode, requested_by, status, created_at) \
                 VALUES ($1, $2, 'alice_wedged', 'alice_wedged', $3, 'replace', 'alice', \
                         'running', now() - make_interval(hours => $4))",
            ).bind(id).bind(backup_id).bind(db_id).bind(age_hours as i32)
             .execute(&db).await.unwrap();
        }
    };

    // PRECONDITION — a YOUNG running job is left alone. Without this, "the old
    // one was reclaimed" is satisfied by a sweep that fails every restore it
    // sees, which would kill live jobs mid-flight.
    let young = Uuid::new_v4();
    insert_running(young, 1).await;
    let swept = cryptarch::restore::sweep_abandoned(&app.db).await.unwrap();
    assert_eq!(swept, 0, "a restore running for an hour is not abandoned");
    let status: String = sqlx::query_scalar("SELECT status FROM restores WHERE id = $1")
        .bind(young).fetch_one(&app.db).await.unwrap();
    assert_eq!(status, "running", "PRECONDITION: the young job must survive the sweep");

    // The claim: one past the threshold is reclaimed.
    sqlx::query("DELETE FROM restores WHERE id = $1").bind(young).execute(&app.db).await.unwrap();
    let old = Uuid::new_v4();
    insert_running(old, 9).await;
    let swept = cryptarch::restore::sweep_abandoned(&app.db).await.unwrap();
    assert_eq!(swept, 1, "a restore stuck for 9h must be reclaimed");
    let (status, error): (String, Option<String>) =
        sqlx::query_as("SELECT status, error FROM restores WHERE id = $1")
            .bind(old).fetch_one(&app.db).await.unwrap();
    assert_eq!(status, "failed");
    assert!(error.unwrap_or_default().contains("abandoned"),
            "and must say why, since nobody watched it happen");

    // And the point of reclaiming it: that database can be restored again. This
    // is the actual harm the wedged row caused, so it is the actual fix.
    let state = test_state(&app);
    let after = cryptarch::restore::enqueue(&state, "alice", db_id, "alice_wedged", backup_id).await;
    assert!(!matches!(after, Err(cryptarch::restore::EnqueueError::AlreadyRunning)),
            "the lock must be released, not just the row relabelled — got {after:?}");
}

/// CRYPTARCH-114: a backup and a restore of the same database exclude each
/// other, in BOTH directions.
///
/// They had separate locks — `idx_backups_one_running_per_db` and
/// `idx_restores_one_running_per_database` — so each table prevented a
/// duplicate of itself and neither knew about the other. But the two jobs are
/// not independent: `pg_dump` holds ACCESS SHARE on every table for its whole
/// run, and `pg_restore --clean` wants ACCESS EXCLUSIVE to drop them. Overlap
/// either blocks the tenant's live application on its own tables for the
/// duration of the dump, or kills the dump with "relation does not exist" after
/// a full-size partial blob has been written.
///
/// Both directions are asserted because a one-way guard is worse than none: it
/// reads as protected while the ordering that actually happens is unguarded.
/// The advisory lock is what makes the cross-check above race-free
/// (CRYPTARCH-128): without it both claimers can read "nothing running" before
/// either commits. The sequential test beside this one passes with the lock
/// deleted, so this one stages the race deterministically — a restore claim
/// caught mid-transaction, holding the lock with its row not yet committed.
///
/// A backup claim must WAIT for that transaction, then see the restore and
/// refuse. With the lock gone it would neither wait nor see the uncommitted
/// row, and would start a dump against a database about to be rebuilt.
#[tokio::test]
async fn a_backup_claim_waits_for_an_in_flight_restore_claim() {
    let Some(app) = test_app().await else { return };
    let alice = login(&app, "alice", "alicepw123").await;
    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/databases", Some(&alice), Some(provision_body(app.server_id, "alice_race", "10.0.0.0/24"))).await;
    assert_eq!(st, StatusCode::CREATED);
    let (backup_id, _) = seed_backup(&app, "alice_race", chrono::Duration::days(1), "ok").await;
    let db_id = database_for(&app, "alice_race").await;
    let state = test_state(&app);

    // The restore side, frozen between taking the lock and committing its row.
    let mut tx = app.db.begin().await.unwrap();
    cryptarch::backup::lock_db_jobs(&mut tx, "alice_race").await.unwrap();
    sqlx::query(
        "INSERT INTO restores (id, backup_id, source_name, target_name, database_id, mode, \
                               requested_by, status) \
         VALUES ($1, $2, 'alice_race', 'alice_race', $3, 'replace', 'alice', 'running')",
    ).bind(Uuid::new_v4()).bind(backup_id).bind(db_id).execute(&mut *tx).await.unwrap();

    let claim = tokio::spawn({
        let state = state.clone();
        async move { cryptarch::backup::run_now(&state, "alice", "alice_race").await }
    });
    tokio::time::sleep(std::time::Duration::from_millis(750)).await;
    assert!(!claim.is_finished(),
        "the backup claim must block on the in-flight restore claim's lock, not race past it");

    tx.commit().await.unwrap();
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(10), claim)
        .await.expect("the claim must proceed once the lock is released").unwrap();
    assert!(matches!(outcome, Err(cryptarch::backup::EnqueueError::RestoreRunning)),
        "having waited, it must see the restore and refuse, got {:?}", outcome.as_ref().map(|_| ()));
}

#[tokio::test]
async fn a_backup_and_a_restore_of_one_database_exclude_each_other() {
    let Some(app) = test_app().await else { return };
    let alice = login(&app, "alice", "alicepw123").await;
    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/databases", Some(&alice), Some(provision_body(app.server_id, "alice_excl", "10.0.0.0/24"))).await;
    assert_eq!(st, StatusCode::CREATED);

    let (backup_id, _) = seed_backup(&app, "alice_excl", chrono::Duration::days(1), "ok").await;
    sqlx::query("UPDATE backups SET server_id = $2 WHERE id = $1")
        .bind(backup_id).bind(app.server_id).execute(&app.db).await.unwrap();
    let db_id = database_for(&app, "alice_excl").await;
    let state = test_state(&app);

    // ---- direction 1: a running RESTORE blocks a backup --------------------
    // The running row is what the lock is made of, so seeding one IS the state
    // a live restore produces — not a fabrication of it.
    let restore_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO restores (id, backup_id, source_name, target_name, database_id, mode, \
                               requested_by, status) \
         VALUES ($1, $2, 'alice_excl', 'alice_excl', $3, 'replace', 'alice', 'running')",
    ).bind(restore_id).bind(backup_id).bind(db_id).execute(&app.db).await.unwrap();

    let blocked = cryptarch::backup::run_now(&state, "alice", "alice_excl").await;
    assert!(
        matches!(blocked, Err(cryptarch::backup::EnqueueError::RestoreRunning)),
        "a backup started during a restore would dump a half-rebuilt database, got {blocked:?}"
    );

    // PRECONDITION for direction 1 — with the restore finished, the SAME call
    // succeeds. Without this, "it was refused" is satisfied by backups being
    // broken for this database entirely.
    sqlx::query("UPDATE restores SET status = 'failed', finished_at = now() WHERE id = $1")
        .bind(restore_id).execute(&app.db).await.unwrap();
    let allowed = cryptarch::backup::run_now(&state, "alice", "alice_excl").await;
    assert!(!matches!(allowed, Err(cryptarch::backup::EnqueueError::RestoreRunning)),
            "PRECONDITION: once the restore is done a backup must be allowed, got {allowed:?}");

    // ---- direction 2: a running BACKUP blocks a restore --------------------
    // Clear the backup the call above just started, but leave the SEEDED one
    // `ok` — it is the blob the restore below restores FROM, and failing it
    // would make enqueue answer NotFound for a reason unrelated to this test.
    sqlx::query("UPDATE backups SET status = 'failed' WHERE db_name = 'alice_excl' AND id <> $1")
        .bind(backup_id).execute(&app.db).await.unwrap();
    let running_backup = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO backups (id, database_id, db_name, server_id, status) \
         VALUES ($1, $2, 'alice_excl', $3, 'running')",
    ).bind(running_backup).bind(db_id).bind(app.server_id).execute(&app.db).await.unwrap();

    let blocked = cryptarch::restore::enqueue(&state, "alice", db_id, "alice_excl", backup_id).await;
    assert!(
        matches!(blocked, Err(cryptarch::restore::EnqueueError::BackupRunning)),
        "a restore started during a backup would fight it for table locks, got {blocked:?}"
    );

    // PRECONDITION for direction 2, same reasoning as above.
    sqlx::query("UPDATE backups SET status = 'ok' WHERE id = $1")
        .bind(running_backup).execute(&app.db).await.unwrap();
    let allowed = cryptarch::restore::enqueue(&state, "alice", db_id, "alice_excl", backup_id).await;
    assert!(!matches!(allowed, Err(cryptarch::restore::EnqueueError::BackupRunning)),
            "PRECONDITION: once the backup is done a restore must be allowed, got {allowed:?}");
}

/// CRYPTARCH-111: what the dashboard says you have used is what the enforcer
/// will count.
///
/// They were two different rules. The dashboard counted `status = 'active'`;
/// `provision_db` counts everything that occupies a slot, which is every status
/// including ones this build has never heard of. So a user holding one non-
/// active row saw "1 in use / 2 quota" with "+ New database" enabled, clicked
/// it, and was told "database quota reached (2/2)".
#[tokio::test]
async fn the_dashboard_counts_a_slot_the_same_way_the_enforcer_does() {
    let Some(app) = test_app().await else { return };
    let alice = login(&app, "alice", "alicepw123").await;
    // Quota 2, so one held slot plus one live database is exactly at the cap.
    sqlx::query("UPDATE users SET db_quota = 2 WHERE username = 'alice'")
        .execute(&app.db).await.unwrap();

    for n in ["alice_one", "alice_two"] {
        let (st, _, _) = send_json(&app.router, "POST", "/api/v1/databases", Some(&alice), Some(provision_body(app.server_id, n, "10.0.0.0/24"))).await;
        assert_eq!(st, StatusCode::CREATED, "provisioning {n}");
    }

    // Put one into a non-active status the way a stalled delete does. Not a
    // fabricated value: `delete_db` writes exactly this before calling the
    // engine, and a delete that fails partway leaves it.
    sqlx::query("UPDATE databases SET status = 'deleting' WHERE name = 'alice_two'")
        .execute(&app.db).await.unwrap();

    let (st, _, body) = send_json(&app.router, "GET", "/api/v1/databases", Some(&alice), None).await;
    assert_eq!(st, StatusCode::OK);

    // PRECONDITION — the row is still SHOWN. This is not "hide it and the
    // numbers work out": visibility and quota are deliberately different
    // questions, and a database that vanishes mid-delete is the failure the
    // visible_to_owner rule exists to prevent.
    let names: Vec<&str> = body["databases"].as_array().unwrap().iter().map(|d| d["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"alice_two"), "PRECONDITION: a deleting database stays on its owner's dashboard: {body}");

    // The claim: the dashboard counts the held slot, and gates the button on
    // it (the page reads at_cap), since the enforcer will refuse.
    assert_eq!((body["quota"]["used"].as_i64(), body["quota"]["at_cap"].as_bool()), (Some(2), Some(true)), "{body}");

    // And the enforcer really is at the cap, which is what makes the number
    // above the RIGHT one rather than merely a different one.
    let (st, _, refused) = send_json(&app.router, "POST", "/api/v1/databases", Some(&alice),
        Some(provision_body(app.server_id, "alice_three", "10.0.0.0/24"))).await;
    assert_eq!((st, refused["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("quota_reached")),
        "premise: the enforcer must actually refuse at this point: {refused}");
    let made: i64 = sqlx::query_scalar("SELECT count(*) FROM databases WHERE name = 'alice_three'")
        .fetch_one(&app.db).await.unwrap();
    assert_eq!(made, 0, "and the refusal must not have reserved a row");
}

/// CRYPTARCH-107: the wrong at-rest key stops the process instead of quietly
/// producing a backup history full of noise.
///
/// Loading a key always succeeds — any 32 valid hex bytes is a valid AES key —
/// so nothing downstream could tell a wrong key from the right one. Worse, the
/// downstream signals were actively reassuring: the seed server keeps working
/// (its DSN is re-encrypted with whatever key is loaded), backups keep
/// succeeding (sealed and then verified with the SAME wrong key), and the
/// staleness check reads the `backups` table rather than the blobs.
#[tokio::test]
async fn the_key_canary_refuses_a_key_that_did_not_seal_this_deployment() {
    let Some(app) = test_app().await else { return };
    // Key A is the fixture's OWN key — the one that sealed the managed-server
    // DSN test_app() already stored. That matters: establishing now has to get
    // past the "existing sealed data" check, so using an arbitrary key here
    // would test the wrong refusal.
    const KEY_A: &str = "abababababababababababababababababababababababababababababababab";
    const KEY_B: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    let a = cryptarch::crypto::Crypto::from_hex_key(KEY_A).unwrap();
    let b = cryptarch::crypto::Crypto::from_hex_key(KEY_B).unwrap();

    // PRECONDITION — both keys load. The refusal below must come from the
    // canary, not from key B being malformed; if `from_hex_key` rejected it
    // this test would pass while proving nothing about the canary at all.
    assert_ne!(a.key_fingerprint(), b.key_fingerprint(), "PRECONDITION: two distinct keys");

    // First boot on a fresh database: establishes, does not refuse.
    let none_yet: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM key_canary")
        .fetch_one(&app.db).await.unwrap();
    assert_eq!(none_yet, 0, "PRECONDITION: nothing established yet");
    cryptarch::crypto::verify_or_establish_canary(&app.db, &a).await
        .expect("first boot must establish the canary, not fail");

    let stored: (String,) = sqlx::query_as("SELECT fingerprint FROM key_canary WHERE id")
        .fetch_one(&app.db).await.unwrap();
    assert_eq!(stored.0, a.key_fingerprint(), "it records which key it was");

    // Same key again: still fine. Without this, "the wrong key is refused"
    // would also be satisfied by a check that refuses everything.
    cryptarch::crypto::verify_or_establish_canary(&app.db, &a).await
        .expect("the SAME key must keep booting");

    // The claim.
    let err = cryptarch::crypto::verify_or_establish_canary(&app.db, &b).await
        .expect_err("a different key must refuse to boot");
    let msg = format!("{err}");
    assert!(msg.contains(a.key_fingerprint()),
            "the error must name the key this deployment was sealed with:\n{msg}");
    assert!(msg.contains(b.key_fingerprint()),
            "and the key that was actually loaded:\n{msg}");

    // The canary must not have been overwritten by the failed attempt — that
    // would let a second boot on the wrong key succeed and adopt it.
    let after: (String,) = sqlx::query_as("SELECT fingerprint FROM key_canary WHERE id")
        .fetch_one(&app.db).await.unwrap();
    assert_eq!(after.0, a.key_fingerprint(), "a refused boot must not claim the deployment");
}

/// CRYPTARCH-107, the hole the first version of the canary had: an EMPTY
/// canary table is not evidence of an empty deployment.
///
/// `key_canary` is created by a migration, so it is empty on the first boot of
/// every EXISTING deployment — exactly the boot where an operator who has just
/// restored a metadata dump might be holding the wrong key. Establishing
/// blindly there would seal the canary with the WRONG key, log "future boots
/// will refuse a different key", and make the mistake permanent and invisible:
/// every later boot verifies clean against a key that opens none of the real
/// data. The check would manufacture the all-clear it exists to prevent.
#[tokio::test]
async fn the_canary_will_not_adopt_a_key_that_opens_none_of_the_existing_data() {
    let Some(app) = test_app().await else { return };
    const WRONG: &str = "3333333333333333333333333333333333333333333333333333333333333333";
    let wrong = cryptarch::crypto::Crypto::from_hex_key(WRONG).unwrap();

    // PRECONDITION 1 — no canary yet. This is the upgrade-boot shape, and it
    // is the only state in which establishment is reachable at all.
    let none_yet: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM key_canary")
        .fetch_one(&app.db).await.unwrap();
    assert_eq!(none_yet, 0, "PRECONDITION: the upgrade-boot state is an empty canary table");

    // PRECONDITION 2 — but sealed data DOES exist, and this key does not open
    // it. Without this the refusal below would be indistinguishable from a
    // check that simply refuses every fresh deployment.
    let sealed: Vec<Vec<u8>> = sqlx::query_scalar("SELECT admin_dsn_enc FROM managed_servers")
        .fetch_all(&app.db).await.unwrap();
    assert!(!sealed.is_empty(), "PRECONDITION: the fixture stored a sealed DSN");
    assert!(sealed.iter().all(|b| wrong.open(b).is_err()),
            "PRECONDITION: the wrong key must genuinely not open it");

    let err = cryptarch::crypto::verify_or_establish_canary(&app.db, &wrong).await
        .expect_err("a key that opens none of the existing data must not claim the deployment");
    assert!(format!("{err}").contains("already holds encrypted data"),
            "the error must explain WHY it refused:\n{err}");

    // The claim that matters: it did not adopt. A canary row here would mean
    // every future boot on the wrong key verifies clean.
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM key_canary")
        .fetch_one(&app.db).await.unwrap();
    assert_eq!(after, 0, "the refused key must NOT have been recorded as this deployment's");

    // And the right key still establishes normally — otherwise this guard would
    // brick every legitimate upgrade.
    let right = cryptarch::crypto::Crypto::from_hex_key(&"ab".repeat(32)).unwrap();
    cryptarch::crypto::verify_or_establish_canary(&app.db, &right).await
        .expect("the key that DID seal the data must establish the canary");
}

/// CRYPTARCH-102: `is_active` is enforced on every request, not only at login.
///
/// Deliberately separate from the suspend-handler test above, and the split is
/// the point. That test drives the real handler, which BOTH flips the flag and
/// deletes the session rows — so it stays green with `SessionStore::get`'s
/// `AND u.is_active` removed, because the rows are gone either way. It pins the
/// revocation, not the join.
///
/// This one isolates the join by flipping the flag in SQL and leaving the
/// session rows alone. That is not a fabricated state: it is what an operator
/// does with psql, what a future LDAP or admin path might do, and what any
/// code that forgets to revoke would leave behind. The guarantee is that a
/// deactivated user is refused on the NEXT REQUEST regardless of who cleaned up.
#[tokio::test]
async fn a_deactivated_user_is_refused_even_with_their_session_row_intact() {
    let Some(app) = test_app().await else { return };
    let alice_cookie = login(&app, "alice", "alicepw123").await;
    let alice_id: Uuid = sqlx::query_scalar("SELECT id FROM users WHERE username = 'alice'")
        .fetch_one(&app.db).await.unwrap();

    let (st, _, _) = send_json(&app.router, "GET", "/api/v1/databases", Some(&alice_cookie), None).await;
    assert_eq!(st, StatusCode::OK, "PRECONDITION: the session works while she is active");

    // The flag only. No revocation — that is what this test is for.
    sqlx::query("UPDATE users SET is_active = false WHERE id = $1")
        .bind(alice_id).execute(&app.db).await.unwrap();

    // PRECONDITION — the row is STILL THERE. Without this the assertion below
    // is satisfied by the session having been deleted, which is the other
    // mechanism and is already covered above.
    let rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND expires_at > now()",
    ).bind(alice_id).fetch_one(&app.db).await.unwrap();
    assert_eq!(rows, 1, "PRECONDITION: the session row must survive, or this tests nothing new");

    let (st, _, _) = send_json(&app.router, "GET", "/api/v1/databases", Some(&alice_cookie), None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "a deactivated user must be refused on every request");
}

/// CRYPTARCH-98: /metrics is gated, and says something once you are through.
///
/// The gate matters more than the numbers. The compose stack publishes the app
/// port on every interface and this endpoint carries tenant DATABASE NAMES, so
/// an open scrape hands the tenant inventory to anyone who can reach the panel.
#[tokio::test]
async fn metrics_needs_its_token_and_then_reports() {
    let Some(app) = test_app().await else { return };
    let alice = login(&app, "alice", "alicepw123").await;
    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/databases", Some(&alice), Some(provision_body(app.server_id, "alice_metrics", "10.0.0.0/24"))).await;
    assert_eq!(st, StatusCode::CREATED);

    // No token, wrong token, and a session cookie must all be refused — the
    // last one because a signed-in user is not a scraper, and it would be easy
    // to accidentally gate this on the ordinary auth layer instead.
    for (label, cookie, auth) in [
        ("no credentials", None, None),
        ("wrong token", None, Some("Bearer nope")),
        ("prefix of the real token", None, Some("Bearer test-scrape")),
        ("a logged-in session", Some(alice.as_str()), None),
    ] {
        let mut req = axum::http::Request::builder().method("GET").uri("/metrics");
        if let Some(c) = cookie {
            req = req.header(axum::http::header::COOKIE, c);
        }
        if let Some(a) = auth {
            req = req.header(axum::http::header::AUTHORIZATION, a);
        }
        let resp = app.router.clone().oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "{label} was allowed to scrape /metrics"
        );
    }

    // With the token: real content. Asserting the body is non-empty would pass
    // for a handler that returned a comment, so this looks for the series it
    // must publish and for this database by name.
    let resp = app
        .router
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/metrics")
                .header(axum::http::header::AUTHORIZATION, "Bearer test-scrape-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024).await.unwrap();
    let body = String::from_utf8_lossy(&bytes).into_owned();

    for expected in ["# TYPE cryptarch_databases gauge", "cryptarch_users ", "cryptarch_server_up"]
    {
        assert!(body.contains(expected), "missing {expected:?} in:\n{body}");
    }
    assert!(
        body.contains("alice_metrics") || body.contains("cryptarch_databases{"),
        "the inventory series carries no databases:\n{body}"
    );

    // Exposition format is line-oriented, so a malformed sample corrupts every
    // sample after it rather than just its own.
    for l in body.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()) {
        let value = l.rsplit(' ').next().unwrap_or("");
        assert!(
            value.parse::<f64>().is_ok(),
            "sample does not end in a number, so the scrape would be rejected: {l:?}"
        );
    }
}

/// With no token configured the endpoint does not exist.
///
/// 404 rather than 403 on purpose: a 403 confirms there is something here
/// worth coming back for.
#[tokio::test]
async fn metrics_is_absent_when_no_token_is_configured() {
    let Some(app) = test_app().await else { return };
    let router = cryptarch::web::router(AppState { metrics_token: None, ..test_state(&app) });
    let resp = router
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/metrics")
                .header(axum::http::header::AUTHORIZATION, "Bearer test-scrape-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "an unconfigured /metrics answered something other than 404"
    );
}

// ---- server dashboard (v0.3) ------------------------------------------------

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
    async fn enable_login(&self, _: &str) -> anyhow::Result<()> {
        std::future::pending().await
    }
    async fn login_states(&self, _: &[&str]) -> anyhow::Result<Vec<cryptarch::engine::RoleLogin>> {
        std::future::pending().await
    }
    async fn database_exists(&self, _: &str) -> anyhow::Result<bool> {
        std::future::pending().await
    }
    async fn claim_repair_attempt(&self, _: &str, _: &str) -> anyhow::Result<bool> {
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
    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/databases", Some(&alice), Some(provision_body(app.server_id, "alice_hang", "10.0.0.0/24"))).await;
    let elapsed = started.elapsed();

    assert!(elapsed < std::time::Duration::from_secs(5),
        "a wedged server must not hang the request (took {elapsed:?})");
    assert!(st.is_server_error(), "the request fails, rather than reporting a database ({st})");
    assert!(body["error"]["message"].as_str().is_some_and(|m| !m.is_empty()), "and says so: {body}");
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

#[tokio::test]
async fn per_db_override_lands_in_users_section_and_audits() {
    let Some(app) = test_app().await else { return };
    let admin = login(&app, "admin", "adminpw123").await;
    let alice = login(&app, "alice", "alicepw123").await;
    let dir = temp_conf_dir();

    // Point the server at the conf dir. The edge card doesn't touch the DSN,
    // so the registered TestEngine survives the save.
    let (st, _, body) = send_json(&app.router, "POST",
        &format!("/api/v1/admin/servers/{}/settings/edge", app.server_id), Some(&admin),
        Some(serde_json::json!({"tls_mode": "off", "backend_kind": "docker", "default_consumer_cidr": null,
                                "bouncer_conf_dir": dir.display().to_string()}))).await;
    assert_eq!((st, body["edge"]["state"].as_str()), (StatusCode::OK, Some("applied")), "{body}");

    // A tenant to override.
    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/databases", Some(&alice), Some(provision_body(app.server_id, "alice_pool", "10.0.0.0/24"))).await;
    assert_eq!(st, StatusCode::CREATED);
    let db_id: Uuid = sqlx::query_scalar("SELECT id FROM databases WHERE name = 'alice_pool'")
        .fetch_one(&app.db)
        .await
        .unwrap();

    // Override: transaction mode, 5 connections.
    let pool = format!("/api/v1/admin/servers/{}/databases/{}/pool", app.server_id, db_id);
    let (st, _, body) = send_json(&app.router, "POST", &pool, Some(&admin),
        Some(serde_json::json!({"pool_mode": "transaction", "max_connections": 5}))).await;
    assert_eq!((st, body["name"].as_str(), body["edge"]["state"].as_str()), (StatusCode::OK, Some("alice_pool"), Some("applied")), "{body}");

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
    let (st, _, _) = send_json(&app.router, "POST", &pool, Some(&admin),
        Some(serde_json::json!({"pool_mode": "inherit", "max_connections": null}))).await;
    assert_eq!(st, StatusCode::OK);
    let knobs = std::fs::read_to_string(dir.join("cryptarch_bouncer.ini")).unwrap();
    assert!(!knobs.contains("[users]"), "cleared override leaves no [users] section");
    std::fs::remove_dir_all(&dir).ok();
}

// ---- per-user manage page (CRYPTARCH-36) ------------------------------------

// ---- named sources (CRYPTARCH-39) -------------------------------------------

// ---- per-path connection strings (CRYPTARCH-40) ------------------------------

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
        jobs: cryptarch::web::JobTracker::default(),
        sessions: SessionStore::new(app.db.clone()),
        db: app.db.clone(),
        servers: app.servers.clone(),
        crypto: Crypto::from_hex_key(&"ab".repeat(32)).unwrap(),
        secure_cookies: false,
        login_throttle: web::LoginThrottle::default(),
        allow_superuser: true,
        health: cryptarch::health::HealthRegistry::default(),
        backup_dir: Some(app.backup_dir.clone()),
        metrics_token: Some("test-scrape-token".into()),
        metadata_dsn: None,
    }
}

// ---- backups (CRYPTARCH-61) --------------------------------------------------

/// The live database `db_name` refers to, creating it if this is the first
/// backup seeded for that name. Owned by alice, on the fixture's server.
async fn database_for(app: &TestApp, db_name: &str) -> Uuid {
    if let Some(id) = sqlx::query_scalar::<_, Uuid>("SELECT id FROM databases WHERE name = $1")
        .bind(db_name)
        .fetch_optional(&app.db)
        .await
        .expect("looking up the database")
    {
        return id;
    }
    let owner: Uuid = sqlx::query_scalar("SELECT id FROM users WHERE username = 'alice'")
        .fetch_one(&app.db)
        .await
        .expect("alice must exist in the fixture");
    sqlx::query_scalar(
        "INSERT INTO databases (owner_id, server_id, name, password_hash, status) \
         VALUES ($1, $2, $3, 'not-a-real-hash', 'active') RETURNING id",
    )
    .bind(owner)
    .bind(app.server_id)
    .bind(db_name)
    .fetch_one(&app.db)
    .await
    .expect("seeding the database row")
}

/// Insert a finished backup row with a blob on disk, as the runner would.
///
/// LINKED BY DEFAULT, and that is load-bearing (CRYPTARCH-86). This fixture
/// used to leave `database_id` NULL while `claim()` always sets it, so any
/// assertion about provenance, orphans, or the NULL case passed VACUOUSLY — it
/// was asserting something about rows that had never been linked at all. A
/// fixture that cannot express the unfaithful shape is the only reliable fix.
async fn seed_backup(
    app: &TestApp,
    db_name: &str,
    age: chrono::Duration,
    status: &str,
) -> (Uuid, std::path::PathBuf) {
    let database_id = database_for(app, db_name).await;
    seed_backup_inner(app, db_name, Some(database_id), age, status).await
}

// No `seed_orphan_backup` helper: the orphan case is produced by DELETEing the
// database and letting the foreign key NULL the column, which is what actually
// happens. A fixture that fabricated the NULL directly would assert against a
// state it had invented rather than one the system produces.
async fn seed_backup_inner(
    app: &TestApp,
    db_name: &str,
    database_id: Option<Uuid>,
    age: chrono::Duration,
    status: &str,
) -> (Uuid, std::path::PathBuf) {
    let id = Uuid::new_v4();
    let created = chrono::Utc::now() - age;
    let rel = cryptarch::backup::blob_path(db_name, id, created);
    let abs = app.backup_dir.join(&rel);
    std::fs::create_dir_all(abs.parent().unwrap()).unwrap();
    std::fs::write(&abs, b"sealed bytes").unwrap();
    sqlx::query(
        "INSERT INTO backups (id, db_name, database_id, created_at, finished_at, size_bytes, checksum, path, status) \
         VALUES ($1, $2, $3, $4, $4, 12, 'deadbeef', $5, $6)",
    )
    .bind(id)
    .bind(db_name)
    .bind(database_id)
    .bind(created)
    .bind(rel.to_string_lossy().as_ref())
    .bind(status)
    .execute(&app.db)
    .await
    .expect("seeding backup row");
    (id, abs)
}

#[tokio::test]
async fn retention_keeps_the_newest_successful_backups_and_deletes_their_blobs() {
    let Some(app) = test_app().await else { return };
    let state = test_state(&app);

    let mut seeded = Vec::new();
    for days in 1..=5 {
        seeded.push(seed_backup(&app, "keeper", chrono::Duration::days(days), "ok").await);
    }

    let pruned = cryptarch::backup::prune(&state, 2).await.expect("prune");
    assert_eq!(pruned, 3, "five backups, keep two");

    let remaining: Vec<String> = sqlx::query_scalar(
        "SELECT path FROM backups WHERE db_name = 'keeper' ORDER BY created_at DESC",
    )
    .fetch_all(&app.db)
    .await
    .unwrap();
    assert_eq!(remaining.len(), 2, "two rows survive");

    // The blobs of pruned rows must be gone, and the kept ones still there —
    // a retention pass that deleted rows but left files would silently fill
    // the disk with orphans.
    for (i, (_, abs)) in seeded.iter().enumerate() {
        let kept = i < 2; // seeded oldest-last: index 0,1 are the newest
        assert_eq!(abs.exists(), kept, "blob {i} existence (kept={kept})");
    }
}

/// The pool's session-state scrub must actually run (CRYPTARCH-83).
///
/// It is two statements, so it cannot be prepared — `query()` fails on it, and
/// the pool SWALLOWS that failure by retiring the connection. Safe, silent, and
/// it throws away every pooled connection to every managed server after a
/// single use. Exactly that happened when sqlx 0.9 landed: 0.8 took an
/// unprepared path for queries with no binds, 0.9 always prepares.
///
/// Nothing else in the suite can see this. The pool reports success either way,
/// so it only ever surfaced as a WARN on a real boot. Hence a direct assertion
/// on the real statement.
#[tokio::test]
async fn the_pool_reset_statement_executes_against_a_real_server() {
    use sqlx::Connection;
    let Ok(dsn) = std::env::var(TEST_DSN_VAR) else {
        eprintln!("skipping: {TEST_DSN_VAR} not set");
        return;
    };
    let mut conn = sqlx::PgConnection::connect(&dsn).await.expect("connecting");

    // Positive precondition: put state on the connection and observe it. A
    // reset that silently did nothing would otherwise "pass" — the assertion
    // below needs something that was actually there to clear.
    sqlx::query("SET statement_timeout = '1234ms'").execute(&mut conn).await.unwrap();
    let before: String =
        sqlx::query_scalar("SHOW statement_timeout").fetch_one(&mut conn).await.unwrap();
    assert_eq!(before, "1234ms", "could not set session state to scrub");

    sqlx::raw_sql(cryptarch::engine::postgres::POOL_RESET_SQL)
        .execute(&mut conn)
        .await
        .expect(
            "the pool's reset statement failed to execute — the pool is retiring every \
             connection instead of reusing it, and the failure is swallowed in production",
        );

    let after: String =
        sqlx::query_scalar("SHOW statement_timeout").fetch_one(&mut conn).await.unwrap();
    assert_ne!(after, "1234ms", "the reset executed but cleared nothing");

    // And the same claim through the REAL pool, which is what regresses if
    // someone puts `query()` back at the call site. A connection whose reset
    // fails is RETIRED, so the difference is visible two ways: the pool holds
    // nothing idle afterwards, and the next acquire lands on a new backend.
    //
    // The release is asynchronous, so this acquires and drops explicitly and
    // then waits. An earlier version of this test issued two queries straight
    // at `&pool` and raced the release — it failed against correct code, which
    // is worth recording: the assertion was right and its mechanism was not.
    let pool = cryptarch::engine::postgres::PostgresEngine::pool_options()
        .connect(&dsn)
        .await
        .expect("connecting with the real pool configuration");

    let first: i32 = {
        let mut c = pool.acquire().await.expect("acquiring");
        sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *c).await.unwrap()
    };
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    assert_eq!(
        pool.num_idle(),
        1,
        "the pool kept no idle connection after release, so the one just used was retired \
         — after_release is failing and the failure is swallowed in production"
    );

    let second: i32 = {
        let mut c = pool.acquire().await.expect("re-acquiring");
        sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *c).await.unwrap()
    };
    assert_eq!(first, second, "the pool opened a new backend instead of reusing the scrubbed one");
}

/// CRYPTARCH-93: the mount is reconciled against the table, in both directions.
///
/// Every assertion here is "X is/is not in a list", and both halves pass for
/// free against a degenerate implementation — a lister that returns everything
/// satisfies "the orphan is listed", and one that returns nothing satisfies
/// "the live backup is not listed". So the two are asserted together, over the
/// same directory, and neither is meaningful without the other.
#[tokio::test]
async fn unreferenced_files_are_found_without_sweeping_up_live_backups() {
    let Some(app) = test_app().await else { return };
    let state = test_state(&app);

    // A real backup: row plus file, in the directory the orphans go in too.
    let (_, live_blob) = seed_backup(&app, "recon", chrono::Duration::days(1), "ok").await;
    assert!(live_blob.exists(), "the referenced blob was not created");

    let dir = app.backup_dir.join("recon");

    // An orphan: correctly named, so its id parses, but no row was ever
    // inserted for it. This is what a crash between unlink and DELETE leaves.
    let orphan_id = Uuid::new_v4();
    let orphan = dir.join(format!("20260101T000000Z-{orphan_id}.dump.zst.enc"));
    std::fs::write(&orphan, b"orphaned bytes").unwrap();

    // A file whose name Cryptarch would never write. Must be reported, not
    // quietly skipped — and must not be deletable, because we cannot say what
    // it is.
    let junk = dir.join("restored-by-hand.dump");
    std::fs::write(&junk, b"someone put this here").unwrap();

    let found = cryptarch::backup::unreferenced_files(&state).await.expect("scanning the mount");
    let names: Vec<&str> = found.iter().map(|f| f.rel.as_str()).collect();

    // Direction 1: the orphan and the junk are seen.
    assert!(
        names.iter().any(|n| n.ends_with(&format!("{orphan_id}.dump.zst.enc"))),
        "the orphaned blob was not reported; found {names:?}"
    );
    assert!(
        names.iter().any(|n| n.ends_with("restored-by-hand.dump")),
        "an unrecognised file was skipped instead of reported; found {names:?}"
    );

    // Direction 2 — the half that stops "list everything" from passing: a blob
    // with a row is NOT reported, even though it sits in the same directory.
    let live_name = live_blob.file_name().unwrap().to_string_lossy().to_string();
    assert!(
        !names.iter().any(|n| n.ends_with(live_name.as_str())),
        "a live backup's blob was reported as unreferenced; found {names:?}"
    );

    // The unrecognised file is listed without an id, which is what suppresses
    // its delete action.
    let junk_row = found.iter().find(|f| f.rel.ends_with("restored-by-hand.dump")).unwrap();
    assert!(junk_row.id.is_none(), "an unparseable name yielded an id");

    // === PURGE ===
    let orphan_rel = format!("recon/20260101T000000Z-{orphan_id}.dump.zst.enc");
    cryptarch::backup::purge_unreferenced_file(&state, "admin", &orphan_rel)
        .await
        .expect("purging the orphan");
    assert!(!orphan.exists(), "the orphan survived its purge");
    assert!(live_blob.exists(), "purging the orphan destroyed a live backup's blob");

    // Unidentifiable files are listed, never deleted.
    assert!(
        cryptarch::backup::purge_unreferenced_file(&state, "admin", "recon/restored-by-hand.dump")
            .await
            .is_err(),
        "a file whose name identifies nothing was deleted anyway"
    );
    assert!(junk.exists(), "the unrecognised file was removed despite the refusal");

    // The path comes from a form field, so it is attacker-shaped input on the
    // one endpoint whose job is deletion.
    assert!(
        cryptarch::backup::purge_unreferenced_file(&state, "admin", "../../../etc/passwd")
            .await
            .is_err(),
        "a traversal path was accepted by the purge endpoint"
    );
}

/// A file whose id HAS a row must not be purgeable, even if the listing that
/// offered it was rendered before the row appeared.
#[tokio::test]
async fn a_file_that_regained_its_row_is_no_longer_purgeable() {
    let Some(app) = test_app().await else { return };
    let state = test_state(&app);

    // Seeded through the normal path, so this file is referenced by a real row.
    let (id, blob) = seed_backup(&app, "recheck", chrono::Duration::days(1), "ok").await;
    let rel = blob.strip_prefix(&app.backup_dir).unwrap().to_string_lossy().to_string();

    // Positive precondition: the row really is there, so the refusal below is
    // about the re-check and not about the file being missing.
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM backups WHERE id = $1")
        .bind(id).fetch_one(&app.db).await.unwrap();
    assert_eq!(rows, 1, "the seeded backup has no row; nothing to re-check against");

    let err = cryptarch::backup::purge_unreferenced_file(&state, "admin", &rel)
        .await
        .expect_err("purged a blob that still has a backup row");
    assert!(
        format!("{err:#}").contains("no longer unreferenced"),
        "refused for an unrelated reason: {err:#}"
    );
    assert!(blob.exists(), "the live blob was deleted despite the refusal");
}

#[tokio::test]
async fn retention_never_ages_out_good_backups_behind_a_run_of_failures() {
    let Some(app) = test_app().await else { return };
    let state = test_state(&app);

    // Two good backups, then three failures on top. Counting rows would drop
    // the good ones; counting successes must not.
    let (_, old_good) = seed_backup(&app, "flaky", chrono::Duration::days(9), "ok").await;
    let (_, new_good) = seed_backup(&app, "flaky", chrono::Duration::days(8), "ok").await;
    for days in 1..=3 {
        seed_backup(&app, "flaky", chrono::Duration::days(days), "failed").await;
    }

    cryptarch::backup::prune(&state, 2).await.expect("prune");

    assert!(new_good.exists(), "newest good backup survives");
    assert!(old_good.exists(), "second-newest good backup survives");
    let good: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM backups WHERE db_name = 'flaky' AND status = 'ok'",
    )
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(good, 2, "both successful backups kept despite newer failures");
}

#[tokio::test]
async fn retention_leaves_a_running_job_alone() {
    let Some(app) = test_app().await else { return };
    let state = test_state(&app);

    for days in 1..=3 {
        seed_backup(&app, "busy", chrono::Duration::days(days), "ok").await;
    }
    // A job still writing its file, older than the cutoff: deleting its row
    // would strand the writer and free its lock.
    sqlx::query(
        "INSERT INTO backups (db_name, created_at, status) VALUES ('busy', now() - interval '10 days', 'running')",
    )
    .execute(&app.db)
    .await
    .unwrap();

    cryptarch::backup::prune(&state, 1).await.expect("prune");

    let running: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM backups WHERE db_name = 'busy' AND status = 'running'",
    )
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(running, 1, "an in-flight job must survive retention");
}

#[tokio::test]
async fn retention_prunes_a_database_that_has_never_succeeded() {
    let Some(app) = test_app().await else { return };
    let state = test_state(&app);

    // A database whose backups have only ever failed has no success to anchor
    // the cutoff on. An inner join against the success cutoff dropped it
    // entirely, so its failure rows — each carrying a full error string —
    // accumulated forever. That is exactly the database you least want
    // quietly filling a table.
    for days in 1..=6 {
        seed_backup(&app, "doomed", chrono::Duration::days(days), "failed").await;
    }

    let pruned = cryptarch::backup::prune(&state, 2).await.expect("prune");
    assert_eq!(pruned, 4, "six failures, keep the newest two");

    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM backups WHERE db_name = 'doomed'")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(left, 2);
}

#[tokio::test]
async fn abandoned_jobs_release_their_lock_without_waiting_for_a_restart() {
    let Some(app) = test_app().await else { return };

    // enqueue() spawns the job and drops the handle, so a panic inside it is
    // swallowed and the row stays 'running'. Because the per-database lock IS
    // that row, the database could never be backed up again until a restart.
    sqlx::query(
        "INSERT INTO backups (db_name, created_at, status) \
         VALUES ('wedged', now() - interval '9 hours', 'running')",
    )
    .execute(&app.db)
    .await
    .unwrap();
    // A job that started recently is still legitimately working.
    sqlx::query(
        "INSERT INTO backups (db_name, created_at, status) \
         VALUES ('working', now() - interval '10 minutes', 'running')",
    )
    .execute(&app.db)
    .await
    .unwrap();

    let swept = cryptarch::backup::sweep_abandoned(&app.db).await.expect("sweep");
    assert_eq!(swept, 1, "only the long-dead job is swept");

    let status: String =
        sqlx::query_scalar("SELECT status FROM backups WHERE db_name = 'working'")
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert_eq!(status, "running", "a job still within its runtime budget is left alone");
}

#[tokio::test]
async fn a_kept_blob_after_failed_verification_is_still_findable_and_prunable() {
    let Some(app) = test_app().await else { return };
    let state = test_state(&app);

    // A verification failure keeps the file deliberately. If the row does not
    // point at it, "kept for a human to look at" is hollow: retention reclaims
    // through `path`, so the blob would accumulate forever, and nothing would
    // tell anyone WHICH file in a directory of timestamped blobs to examine.
    let (_, abs) = seed_backup(&app, "kept", chrono::Duration::days(10), "failed").await;
    let path: Option<String> = sqlx::query_scalar(
        "SELECT path FROM backups WHERE db_name = 'kept'",
    )
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert!(path.is_some(), "a kept blob must be reachable from its row");

    // And retention can therefore reclaim it once newer successful backups
    // have aged it out.
    for days in 1..=3 {
        seed_backup(&app, "kept", chrono::Duration::days(days), "ok").await;
    }
    cryptarch::backup::prune(&state, 1).await.expect("prune");
    assert!(!abs.exists(), "retention must be able to reclaim a kept blob");
}

/// CRYPTARCH-82: a partition down to ONE restorable backup is not pruned at
/// all this pass.
///
/// Protecting that row by id would leave a window — its blob can vanish
/// between the check and the deletes, and no transaction covers the
/// filesystem — so the whole partition is skipped instead. The cost is that
/// failure rows linger while a database has only one good backup, which is the
/// right trade: they are evidence that backups are failing.
#[tokio::test]
async fn retention_freezes_a_database_down_to_its_last_restorable_backup() {
    let Some(app) = test_app().await else { return };
    let state = test_state(&app);

    // One good backup, with OLDER failures behind it. The count rule alone
    // anchors the cutoff on the good one and deletes everything older.
    seed_backup(&app, "onlyone", chrono::Duration::days(5), "ok").await;
    for days in 10..=12 {
        seed_backup(&app, "onlyone", chrono::Duration::days(days), "failed").await;
    }

    let pruned = cryptarch::backup::prune(&state, 1).await.expect("prune");

    assert_eq!(pruned, 0, "nothing may be pruned while one restorable backup is all there is");
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM backups WHERE db_name = 'onlyone'")
        .fetch_one(&app.db).await.expect("counting");
    assert_eq!(left, 4, "every row stays, including the failures that explain why");
}

/// A row that CLAIMS to be a good backup but whose file is gone is not
/// restorable, and must not be mistaken for the copy worth protecting — that
/// would let retention delete the real one while guarding a ghost.
#[tokio::test]
async fn a_backup_whose_file_is_missing_does_not_count_as_the_last_restorable() {
    let Some(app) = test_app().await else { return };
    let state = test_state(&app);

    let (real_id, real_blob) =
        seed_backup(&app, "ghosted", chrono::Duration::days(9), "ok").await;
    let (ghost_id, ghost_blob) =
        seed_backup(&app, "ghosted", chrono::Duration::days(1), "ok").await;
    // Newer, ok, and its file is gone — the CRYPTARCH-87 shape.
    std::fs::remove_file(&ghost_blob).expect("removing the ghost's file");

    cryptarch::backup::prune(&state, 1).await.expect("prune");

    let real: i64 = sqlx::query_scalar("SELECT count(*) FROM backups WHERE id = $1")
        .bind(real_id).fetch_one(&app.db).await.expect("counting");
    assert_eq!(
        real, 1,
        "the older backup that actually exists is the last restorable one, not the newer ghost"
    );
    assert!(real_blob.exists(), "and its blob must survive");
    let _ = ghost_id;
}

/// CRYPTARCH-86 step 2: once a database is deleted its backups are the
/// operator's, and the ONLY thing that removes them is an explicit purge.
///
/// Partitioning retention on the name put them in the same partition as
/// whoever took the name next, so the new tenant's ordinary schedule aged them
/// out and unlinked their blobs — the operator's copies destroyed by a stranger,
/// at a time nobody chose.
#[tokio::test]
async fn retention_does_not_let_a_new_tenant_age_out_a_deleted_databases_backups() {
    let Some(app) = test_app().await else { return };
    let state = test_state(&app);

    let alice_db = database_for(&app, "recycled").await;
    let (_, orphan_blob) =
        seed_backup(&app, "recycled", chrono::Duration::days(30), "ok").await;

    sqlx::query("DELETE FROM databases WHERE id = $1")
        .bind(alice_db).execute(&app.db).await.expect("deleting alice's database");

    // The next holder of the name backs up busily. Every one of these is
    // newer than the orphan, so under name-partitioning the orphan is the
    // oldest row in the partition and the first to be pruned.
    let bob_db = database_for(&app, "recycled").await;
    assert_ne!(bob_db, alice_db, "premise: a genuinely different database");
    for hours in 1..=4 {
        seed_backup(&app, "recycled", chrono::Duration::hours(hours), "ok").await;
    }

    cryptarch::backup::prune(&state, 2).await.expect("prune");

    let orphans: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM backups WHERE db_name = 'recycled' AND database_id IS NULL",
    ).fetch_one(&app.db).await.expect("counting orphans");
    assert_eq!(orphans, 1, "the operator's copy must survive another tenant's retention");
    assert!(orphan_blob.exists(), "and so must its blob");

    // Premise: retention did still run on the live tenant, or this proves nothing.
    let bobs: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM backups WHERE database_id = $1",
    ).bind(bob_db).fetch_one(&app.db).await.expect("counting bob's rows");
    assert_eq!(bobs, 2, "premise: the live database was pruned to `keep`");
}

/// `_cryptarch_meta` also has a NULL `database_id` — it has no `databases` row
/// at all — so a naive "skip the NULLs" would exempt the metadata backups from
/// retention forever. NULL means two different things and the predicate has to
/// tell them apart.
#[tokio::test]
async fn retention_still_prunes_the_metadata_database() {
    let Some(app) = test_app().await else { return };
    let state = test_state(&app);
    let meta = cryptarch::backup::METADATA_DB;

    for days in 1..=5 {
        seed_backup_inner(&app, meta, None, chrono::Duration::days(days), "ok").await;
    }
    let pruned = cryptarch::backup::prune(&state, 2).await.expect("prune");

    assert_eq!(pruned, 3, "the metadata database is not an orphan and is not exempt");
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM backups WHERE db_name = $1")
        .bind(meta).fetch_one(&app.db).await.expect("counting");
    assert_eq!(left, 2);
}

/// The dangerous half. Freshness grouped on the name let a live database
/// inherit a DEAD one's verdict: take a recycled name, have every backup fail,
/// and the previous owner's recent row kept the alert from ever firing.
///
/// Worse than the retention hole beside it — that destroys data visibly, this
/// silences the alarm.
#[tokio::test]
async fn a_recycled_name_is_judged_on_its_own_backups_not_a_deleted_databases() {
    let Some(app) = test_app().await else { return };

    // alice's database has a BRAND NEW successful backup, then is deleted.
    let alice_db = database_for(&app, "inherited").await;
    seed_backup(&app, "inherited", chrono::Duration::minutes(1), "ok").await;
    sqlx::query("DELETE FROM databases WHERE id = $1")
        .bind(alice_db).execute(&app.db).await.expect("deleting alice's database");

    // bob takes the name and has never had a successful backup.
    let bob_db = database_for(&app, "inherited").await;
    seed_backup_inner(&app, "inherited", Some(bob_db), chrono::Duration::days(3), "failed").await;

    // Driven through the real pass rather than a test-only entry point.
    // `backups_enabled` must be true because the freshness half of `sweep`
    // sits below that gate — the pass will also attempt a backup through the
    // test engine, which fails and therefore cannot give bob the successful
    // row that would make this pass for the wrong reason.
    let schedule = cryptarch::backup::Schedule {
        interval_secs: cryptarch::backup::MAINTENANCE_INTERVAL_SECS,
        keep: 0,
        stale_after_secs: 3600,
        backups_enabled: true,
    };
    let notifier = cryptarch::health::Notifier::from_config(None, "json");
    let mut alerted = std::collections::HashSet::new();
    cryptarch::backup::run_one_pass(&test_state(&app), schedule, &notifier, &mut alerted).await;

    // Premise: bob still has no successful backup, or "stale" is trivially true
    // for a reason unrelated to the grouping under test.
    let bob_ok: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM backups WHERE database_id = $1 AND status = 'ok'",
    ).bind(bob_db).fetch_one(&app.db).await.expect("counting bob's successes");
    assert_eq!(bob_ok, 0, "premise: the live database has no successful backup");

    assert!(
        alerted.contains("inherited"),
        "a database whose own backups all failed must be reported stale, even when a \
         deleted database of the same name has a fresh one — alerted: {alerted:?}"
    );
}

/// Once shutdown begins, the scheduler must not START another backup
/// (CRYPTARCH-123). The drain waits for the job in hand; without this, the
/// sweep would claim the next database the moment that job finished, and the
/// runtime would then be dropped out from under it mid-dump.
///
/// Positive precondition second, on the same database: an open tracker DOES
/// back it up, so the closing case's zero is the flag's doing and not a target
/// the sweep was never going to touch.
#[tokio::test]
async fn a_closing_tracker_stops_the_scheduler_starting_backups() {
    let Some(app) = test_app().await else { return };
    let db = database_for(&app, "closing_sched").await;
    let schedule = cryptarch::backup::Schedule {
        interval_secs: cryptarch::backup::MAINTENANCE_INTERVAL_SECS,
        keep: 0,
        stale_after_secs: 0,
        backups_enabled: true,
    };
    let notifier = cryptarch::health::Notifier::from_config(None, "json");
    let attempts = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM backups WHERE database_id = $1")
            .bind(db).fetch_one(&app.db).await.expect("counting backups")
    };

    let closing = test_state(&app);
    closing.jobs.drain(std::time::Duration::from_millis(10)).await;
    cryptarch::backup::run_one_pass(&closing, schedule, &notifier, &mut Default::default()).await;
    assert_eq!(attempts().await, 0, "a closing tracker must stop the sweep starting a backup");

    // And each job start refuses on its own, before claiming anything
    // (CRYPTARCH-128) — the sweep's check above is only the first line. This is
    // the path that matters when shutdown begins between that check and the
    // claim.
    let refused = cryptarch::backup::run_now(&closing, "system", "closing_sched").await;
    assert!(matches!(refused, Err(cryptarch::backup::EnqueueError::ShuttingDown)),
        "run_now must refuse once closing, got {:?}", refused.as_ref().map(|_| ()));
    let refused = cryptarch::backup::enqueue(&closing, "alice", "closing_sched").await;
    assert!(matches!(refused, Err(cryptarch::backup::EnqueueError::ShuttingDown)));
    assert_eq!(attempts().await, 0, "a refused start must not have claimed a row");
    assert_eq!(closing.jobs.inflight(), 0, "nor leaked a tracker count");

    let open = test_state(&app);
    cryptarch::backup::run_one_pass(&open, schedule, &notifier, &mut Default::default()).await;
    assert!(attempts().await > 0, "premise: an open tracker does attempt this database");
}

// ---- the operator's backups (CRYPTARCH-86 step 3) ---------------------------

/// Seed a backup, then delete its database so the foreign key unlinks it —
/// producing an orphan the way the system actually produces one.
async fn orphaned_backup(
    app: &TestApp,
    db_name: &str,
    age: chrono::Duration,
) -> (Uuid, std::path::PathBuf) {
    let db = database_for(app, db_name).await;
    let seeded = seed_backup(app, db_name, age, "ok").await;
    sqlx::query("DELETE FROM databases WHERE id = $1")
        .bind(db).execute(&app.db).await.expect("deleting the database");
    seeded
}

/// `database_id IS NULL` means "orphaned by deletion" OR "is the metadata
/// database", which has no `databases` row at all. The operator's list is the
/// list with a purge button on it, so the metadata backups — the index to every
/// other backup — must not be in it.
///
/// This pins the view's hardcoded sentinel to the Rust constant so the two
/// cannot drift apart silently.
#[tokio::test]
async fn the_operator_list_excludes_the_metadata_database() {
    let Some(app) = test_app().await else { return };

    orphaned_backup(&app, "gone_db", chrono::Duration::hours(1)).await;
    seed_backup_inner(
        &app, cryptarch::backup::METADATA_DB, None, chrono::Duration::hours(1), "ok",
    ).await;

    let listed = cryptarch::backup::operator_backups(&app.db).await.expect("listing");
    let names: Vec<_> = listed.iter().map(|b| b.db_name.as_str()).collect();

    assert!(names.contains(&"gone_db"), "premise: a real orphan IS listed");
    assert!(
        !names.contains(&cryptarch::backup::METADATA_DB),
        "the metadata database has a NULL database_id for an unrelated reason and \
         must never be offered for purging — listed: {names:?}"
    );
}

/// A backup that sealed but never recorded itself has a NULL `path`
/// (CRYPTARCH-87), and is still findable because its filename carries the row's
/// id.
///
/// The blob here is written with a timestamp that DIFFERS from the row's
/// `created_at`, exactly as production does — `run_job` stamps the name in the
/// worker while `created_at` was set earlier at claim time. An implementation
/// that rebuilt the path from `created_at` would look correct and fail here.
#[tokio::test]
async fn a_backup_that_never_recorded_its_path_is_still_found_by_its_id() {
    let Some(app) = test_app().await else { return };
    let state = test_state(&app);

    let db = database_for(&app, "unrecorded_db").await;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO backups (db_name, database_id, created_at, status, path) \
         VALUES ('unrecorded_db', $1, now() - interval '2 hours', 'failed', NULL) RETURNING id",
    ).bind(db).fetch_one(&app.db).await.expect("seeding the unrecorded row");

    // Written under a stamp unrelated to created_at — the claim-to-run gap.
    let stamped = chrono::Utc::now();
    let rel = cryptarch::backup::blob_path("unrecorded_db", id, stamped);
    let abs = app.backup_dir.join(&rel);
    std::fs::create_dir_all(abs.parent().unwrap()).unwrap();
    std::fs::write(&abs, b"sealed bytes").unwrap();

    sqlx::query("DELETE FROM databases WHERE id = $1")
        .bind(db).execute(&app.db).await.expect("deleting the database");

    let found = cryptarch::backup::locate_blob(&app.backup_dir, "unrecorded_db", id, None)
        .await
        .expect("locating the blob");
    assert_eq!(
        found.as_deref(), Some(abs.as_path()),
        "a NULL-path backup must be resolvable by the id in its filename"
    );

    assert_eq!(
        cryptarch::backup::purge_operator_backup(&state, "admin", id).await.expect("purge"),
        cryptarch::backup::Purged::WithBlob,
        "and purging it must reclaim the file, not just the row"
    );
    assert!(!abs.exists(), "the blob must be gone");
}

/// Purging must never be directory-scoped. Until backups are keyed by id on
/// disk, a deleted database's blobs share a directory with the LIVE database
/// that reused its name — so `remove_dir_all` on that directory is the cheapest
/// implementation and destroys the current tenant's backups.
#[tokio::test]
async fn purging_an_orphan_leaves_the_live_tenants_blob_in_the_same_directory() {
    let Some(app) = test_app().await else { return };
    let state = test_state(&app);

    let (orphan_id, orphan_blob) =
        orphaned_backup(&app, "shared_dir", chrono::Duration::days(1)).await;

    // The name is free; the next holder's blobs land in the same directory.
    let live_db = database_for(&app, "shared_dir").await;
    let (_, live_blob) = seed_backup(&app, "shared_dir", chrono::Duration::hours(1), "ok").await;
    assert_eq!(
        orphan_blob.parent(), live_blob.parent(),
        "premise: both tenants' blobs really do share one directory"
    );

    cryptarch::backup::purge_operator_backup(&state, "admin", orphan_id).await.expect("purge");

    assert!(!orphan_blob.exists(), "the purged blob is gone");
    assert!(live_blob.exists(), "the LIVE tenant's blob must survive a purge next to it");
    let live_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM backups WHERE database_id = $1")
        .bind(live_db).fetch_one(&app.db).await.expect("counting");
    assert_eq!(live_rows, 1, "and so must its row");
}

/// Purge is scoped through the view, so a live tenant's backup cannot be
/// purged even by passing its id directly — the narrowing is in the statement,
/// not in the caller's care.
#[tokio::test]
async fn a_live_tenants_backup_cannot_be_purged_as_if_it_were_an_orphan() {
    let Some(app) = test_app().await else { return };
    let state = test_state(&app);

    let live_db = database_for(&app, "still_here").await;
    let (live_id, live_blob) =
        seed_backup(&app, "still_here", chrono::Duration::hours(1), "ok").await;

    let refused = cryptarch::backup::purge_operator_backup(&state, "admin", live_id).await;
    assert!(refused.is_err(), "purging a live database's backup must be refused");
    assert!(live_blob.exists(), "and must not have touched its blob");
    let still: i64 = sqlx::query_scalar("SELECT count(*) FROM backups WHERE database_id = $1")
        .bind(live_db).fetch_one(&app.db).await.expect("counting");
    assert_eq!(still, 1, "nor its row");
}

/// "Purged the row and its blob" and "purged the row, and there was no blob"
/// are different facts. The second is the operator's only signal that a backup
/// lost its file, so it must not be reported as a clean reclaim.
#[tokio::test]
async fn purging_a_backup_whose_file_is_missing_says_so() {
    let Some(app) = test_app().await else { return };
    let state = test_state(&app);

    let (id, blob) = orphaned_backup(&app, "vanished", chrono::Duration::days(2)).await;
    std::fs::remove_file(&blob).expect("simulating a blob that went missing");

    assert_eq!(
        cryptarch::backup::purge_operator_backup(&state, "admin", id).await.expect("purge"),
        cryptarch::backup::Purged::RowOnlyNoBlobFound,
        "a purge that found no file must not report a clean reclaim"
    );
}

// ---- S7: admin backups (CRYPTARCH-135, CRYPTARCH-147) -----------------------

/// A finished restore that read `backup_id`, as `restore::enqueue` records one.
async fn restore_from(app: &TestApp, backup_id: Uuid, name: &str, status: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO restores (backup_id, source_name, target_name, mode, requested_by, status) \
         VALUES ($1, $2, $2, 'replace', 'alice', $3) RETURNING id",
    )
    .bind(backup_id).bind(name).bind(status)
    .fetch_one(&app.db).await.expect("seeding a restore")
}

async fn backup_rows(app: &TestApp, id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM backups WHERE id = $1")
        .bind(id).fetch_one(&app.db).await.unwrap()
}

/// CRYPTARCH-147. A backup that was restored from is referenced by its restore
/// record. The purge used to unlink the file and then fail on the foreign key,
/// leaving a row for a file that no longer existed. The row and the file share
/// one fate, and the restore's own record survives the backup it came from.
#[tokio::test]
async fn purging_a_restored_from_backup_removes_the_row_and_the_file_together() {
    let Some(app) = test_app().await else { return };
    let state = test_state(&app);

    let (id, blob) = orphaned_backup(&app, "was_restored", chrono::Duration::days(1)).await;
    let restore = restore_from(&app, id, "was_restored", "ok").await;

    assert_eq!(
        cryptarch::backup::purge_operator_backup(&state, "admin", id).await.expect("purge"),
        cryptarch::backup::Purged::WithBlob,
    );
    assert!(!blob.exists(), "the blob is reclaimed");
    assert_eq!(backup_rows(&app, id).await, 0, "and the row goes with it");

    let (backup_id, source): (Option<Uuid>, String) =
        sqlx::query_as("SELECT backup_id, source_name FROM restores WHERE id = $1")
            .bind(restore).fetch_one(&app.db).await.expect("the restore record survives");
    assert_eq!(backup_id, None, "it no longer points at a backup that is gone");
    assert_eq!(source, "was_restored", "and still says what it restored");
    assert_eq!(audit_count(&app, "backup_purged", "was_restored").await, 1);
}

/// Retention has the same shape: a live database's old backup that was once
/// restored from must be prunable, row and file, like any other.
#[tokio::test]
async fn retention_prunes_a_backup_that_was_restored_from() {
    let Some(app) = test_app().await else { return };
    let state = test_state(&app);

    let (old, old_blob) = seed_backup(&app, "pruned_restored", chrono::Duration::days(3), "ok").await;
    let (_, new_blob) = seed_backup(&app, "pruned_restored", chrono::Duration::days(1), "ok").await;
    restore_from(&app, old, "pruned_restored", "ok").await;

    cryptarch::backup::prune(&state, 1).await.expect("prune");
    assert!(new_blob.exists(), "premise: the newest backup is kept");
    assert!(!old_blob.exists(), "the older blob is pruned");
    assert_eq!(backup_rows(&app, old).await, 0, "and so is its row, restore or no restore");
}

/// If the file cannot be removed, nothing is: the row stays, so the backup is
/// still listed and the purge can be tried again. The reverse — file gone, row
/// kept — is the state CRYPTARCH-147 left behind.
#[tokio::test]
async fn a_purge_that_cannot_remove_the_file_keeps_the_row() {
    use std::os::unix::fs::PermissionsExt;
    let Some(app) = test_app().await else { return };
    let state = test_state(&app);

    let (id, blob) = orphaned_backup(&app, "stuck_file", chrono::Duration::days(1)).await;
    let dir = blob.parent().unwrap().to_path_buf();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    let result = cryptarch::backup::purge_operator_backup(&state, "admin", id).await;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert!(
        matches!(result, Err(cryptarch::backup::PurgeError::Failed(_))),
        "a file that could not be removed is a failed purge: {result:?}"
    );
    assert!(blob.exists(), "premise: the file really could not be removed");
    assert_eq!(backup_rows(&app, id).await, 1, "so the row must still be there");
    assert_eq!(audit_count(&app, "backup_purged", "stuck_file").await, 0, "and nothing is audited as purged");
}

/// A restore that is still reading a backup keeps it.
#[tokio::test]
async fn a_backup_a_running_restore_reads_is_not_purged() {
    let Some(app) = test_app().await else { return };
    let state = test_state(&app);

    let (id, blob) = orphaned_backup(&app, "being_read", chrono::Duration::days(1)).await;
    let restore = restore_from(&app, id, "being_read", "running").await;

    let result = cryptarch::backup::purge_operator_backup(&state, "admin", id).await;
    assert!(matches!(result, Err(cryptarch::backup::PurgeError::RestoreRunning)), "{result:?}");
    assert!(blob.exists() && backup_rows(&app, id).await == 1, "nothing was removed");

    // Positive control: the same backup purges once that restore has finished.
    sqlx::query("UPDATE restores SET status = 'ok' WHERE id = $1").bind(restore).execute(&app.db).await.unwrap();
    cryptarch::backup::purge_operator_backup(&state, "admin", id).await.expect("purge after it finished");
    assert!(!blob.exists());
}

/// A directory the scan cannot read is a scan that failed, not a clean one.
#[tokio::test]
async fn an_unreadable_backup_directory_is_not_reported_as_clean() {
    use std::os::unix::fs::PermissionsExt;
    let Some(app) = test_app().await else { return };
    let state = test_state(&app);

    let dir = app.backup_dir.join("unreadable");
    std::fs::create_dir_all(&dir).unwrap();
    let orphan = dir.join(format!("20260101T000000Z-{}.dump.zst.enc", Uuid::new_v4()));
    std::fs::write(&orphan, b"x").unwrap();
    let found = cryptarch::backup::unreferenced_files(&state).await.expect("premise: readable scan");
    assert_eq!(found.len(), 1, "premise: the file is found while it can be read");

    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    let result = cryptarch::backup::unreferenced_files(&state).await;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(result.is_err(), "an unreadable directory was skipped and the scan reported success");
}

/// Every endpoint is admin-only: signed out 401, a tenant 403, and a tenant's
/// purge touches nothing.
#[tokio::test]
async fn api_admin_backups_are_admin_only() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    let (orphan_id, orphan_blob) = orphaned_backup(&app, "api_gated", chrono::Duration::days(1)).await;
    let rel = orphan_blob.strip_prefix(&app.backup_dir).unwrap().to_string_lossy().to_string();

    for path in ["/api/v1/admin/backups", "/api/v1/admin/backups/left-behind", "/api/v1/admin/backups/unreferenced"] {
        let (st, _, _) = send_json(&app.router, "GET", path, None, None).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{path} signed out");
        let (st, _, body) = send_json(&app.router, "GET", path, Some(&alice), None).await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{path} as a tenant");
        assert!(!body.to_string().contains("api_gated"), "{path} leaked to a tenant: {body}");
    }
    let purge = format!("/api/v1/admin/backups/{orphan_id}/purge");
    let (st, _, _) = send_json(&app.router, "POST", &purge, Some(&alice), Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/admin/backups/purge-file", Some(&alice),
        Some(serde_json::json!({"rel": rel}))).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert!(orphan_blob.exists() && backup_rows(&app, orphan_id).await == 1, "a tenant removed something");
}

/// The jobs list is what the page polls, so it is its own endpoint and carries
/// nothing else (CRYPTARCH-124).
#[tokio::test]
async fn api_admin_backup_jobs_list_every_database_and_say_when_one_runs() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;

    let (st, _, body) = send_json(&app.router, "GET", "/api/v1/admin/backups", Some(&admin), None).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!((body["configured"].clone(), body["running"].clone()), (serde_json::json!(true), serde_json::json!(false)), "{body}");

    let (done, _) = seed_backup(&app, "jobs_done", chrono::Duration::hours(2), "ok").await;
    let (running, _) = seed_backup(&app, "jobs_running", chrono::Duration::minutes(1), "running").await;
    seed_backup_inner(&app, cryptarch::backup::METADATA_DB, None, chrono::Duration::hours(1), "ok").await;

    let (st, _, body) = send_json(&app.router, "GET", "/api/v1/admin/backups", Some(&admin), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["running"], true, "{body}");
    let jobs = body["jobs"].as_array().expect("jobs");
    let names: Vec<&str> = jobs.iter().map(|j| j["db_name"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["jobs_running", cryptarch::backup::METADATA_DB, "jobs_done"], "newest first: {body}");
    let first = &jobs[0];
    assert_eq!((first["id"].as_str(), first["status"].as_str()), (Some(running.to_string().as_str()), Some("running")));
    assert_eq!(jobs[1]["metadata"], true, "Cryptarch's own database is marked: {body}");
    assert_eq!(jobs[2]["metadata"], false);
    assert_eq!(jobs[2]["id"], done.to_string());
    for key in ["created_at", "size_bytes", "took", "error", "log", "verified", "contents"] {
        assert!(first.get(key).is_some(), "a job carries {key}: {first}");
    }
    assert!(body.get("left_behind").is_none() && body.get("files").is_none(), "the polled list carries only jobs: {body}");

    // Not configured: said, and the list is empty.
    let mut off = test_state(&app);
    off.backup_dir = None;
    let off = web::router(off);
    let (st, _, body) = send_json(&off, "GET", "/api/v1/admin/backups", Some(&admin), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["configured"], false, "{body}");
}

/// The backups deleted databases left behind: listed with whether each file is
/// there, with both totals, never the metadata database's; purged one at a time,
/// and never a live tenant's.
#[tokio::test]
async fn api_admin_left_behind_lists_and_purges() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;

    let (kept, _) = orphaned_backup(&app, "lb_present", chrono::Duration::days(2)).await;
    let (lost, lost_blob) = orphaned_backup(&app, "lb_missing", chrono::Duration::days(1)).await;
    std::fs::remove_file(&lost_blob).unwrap();
    seed_backup_inner(&app, cryptarch::backup::METADATA_DB, None, chrono::Duration::hours(1), "ok").await;
    let (live, live_blob) = seed_backup(&app, "lb_live", chrono::Duration::hours(1), "ok").await;

    let (st, _, body) = send_json(&app.router, "GET", "/api/v1/admin/backups/left-behind", Some(&admin), None).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let rows = body["backups"].as_array().expect("backups");
    let names: Vec<&str> = rows.iter().map(|r| r["db_name"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["lb_missing", "lb_present"], "newest first, no live or metadata backups: {body}");
    assert_eq!((rows[0]["file_present"].clone(), rows[1]["file_present"].clone()),
        (serde_json::json!(false), serde_json::json!(true)), "{body}");
    assert_eq!(rows[0]["id"], lost.to_string());
    assert_eq!((body["recorded_bytes"].clone(), body["missing"].clone()), (serde_json::json!(24), serde_json::json!(1)), "{body}");

    // A live tenant's backup is not the operator's to purge, whatever id is sent.
    let (st, _, body) = send_json(&app.router, "POST", &format!("/api/v1/admin/backups/{live}/purge"),
        Some(&admin), Some(serde_json::json!({}))).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::NOT_FOUND, Some("no_such_backup")), "{body}");
    assert!(live_blob.exists() && backup_rows(&app, live).await == 1);

    let (st, _, body) = send_json(&app.router, "POST", &format!("/api/v1/admin/backups/{kept}/purge"),
        Some(&admin), Some(serde_json::json!({}))).await;
    assert_eq!((st, body["outcome"].as_str()), (StatusCode::OK, Some("with_file")), "{body}");
    let (st, _, body) = send_json(&app.router, "POST", &format!("/api/v1/admin/backups/{lost}/purge"),
        Some(&admin), Some(serde_json::json!({}))).await;
    assert_eq!((st, body["outcome"].as_str()), (StatusCode::OK, Some("row_only")), "no file found is said: {body}");
    assert_eq!(audit_count(&app, "backup_purged", "lb_present").await, 1);

    // Gone now: the second click is a 404, not a second audit row.
    let (st, _, body) = send_json(&app.router, "POST", &format!("/api/v1/admin/backups/{kept}/purge"),
        Some(&admin), Some(serde_json::json!({}))).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::NOT_FOUND, Some("no_such_backup")), "{body}");
    assert_eq!(audit_count(&app, "backup_purged", "lb_present").await, 1);

    // The audit names the admin's session, tagged or not (CRYPTARCH-146).
    let actor: String = sqlx::query_scalar(
        "SELECT actor FROM audit_log WHERE action = 'backup_purged' AND target = 'lb_present'",
    ).fetch_one(&app.db).await.unwrap();
    assert_eq!(actor, "admin");

    // A running restore holds it.
    let (held, _) = orphaned_backup(&app, "lb_held", chrono::Duration::hours(3)).await;
    restore_from(&app, held, "lb_held", "running").await;
    let (st, _, body) = send_json(&app.router, "POST", &format!("/api/v1/admin/backups/{held}/purge"),
        Some(&admin), Some(serde_json::json!({}))).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("restore_running")), "{body}");

    // Not configured: nothing can be purged, and the list says why it is empty.
    let mut off = test_state(&app);
    off.backup_dir = None;
    let off = web::router(off);
    let (st, _, body) = send_json(&off, "POST", &format!("/api/v1/admin/backups/{held}/purge"),
        Some(&admin), Some(serde_json::json!({}))).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("backups_disabled")), "{body}");
    assert_eq!(backup_rows(&app, held).await, 1);
}

/// Files with no row: listed, recognised or not; only a recognised one can be
/// deleted, and only while it is still unreferenced.
#[tokio::test]
async fn api_admin_unreferenced_files_list_and_purge() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;

    let (live, live_blob) = seed_backup(&app, "uf_dir", chrono::Duration::days(1), "ok").await;
    let dir = app.backup_dir.join("uf_dir");
    let orphan_id = Uuid::new_v4();
    let orphan_rel = format!("uf_dir/20260101T000000Z-{orphan_id}.dump.zst.enc");
    std::fs::write(app.backup_dir.join(&orphan_rel), b"twelve bytes").unwrap();
    std::fs::write(dir.join("by-hand.dump"), b"mine").unwrap();
    let live_rel = live_blob.strip_prefix(&app.backup_dir).unwrap().to_string_lossy().to_string();

    let (st, _, body) = send_json(&app.router, "GET", "/api/v1/admin/backups/unreferenced", Some(&admin), None).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let files = body["files"].as_array().expect("files");
    let listed: Vec<(&str, bool)> =
        files.iter().map(|f| (f["rel"].as_str().unwrap(), f["recognised"].as_bool().unwrap())).collect();
    assert_eq!(listed, vec![(orphan_rel.as_str(), true), ("uf_dir/by-hand.dump", false)], "{body}");
    assert_eq!(files[0]["size_bytes"], 12);
    assert_eq!(body["total_bytes"], 16, "{body}");

    let purge = |rel: String| {
        let router = app.router.clone();
        let admin = admin.clone();
        async move {
            send_json(&router, "POST", "/api/v1/admin/backups/purge-file", Some(&admin),
                Some(serde_json::json!({"rel": rel}))).await
        }
    };
    let (st, _, body) = purge("uf_dir/by-hand.dump".into()).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("unrecognised_file")), "{body}");
    assert!(dir.join("by-hand.dump").exists());
    let (st, _, body) = purge(format!("../{orphan_id}.dump.zst.enc")).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("bad_path")), "{body}");
    let (st, _, body) = purge(live_rel).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("now_referenced")), "{body}");
    assert!(live_blob.exists() && backup_rows(&app, live).await == 1);

    let (st, _, body) = purge(orphan_rel.clone()).await;
    assert_eq!((st, body["size_bytes"].as_u64()), (StatusCode::OK, Some(12)), "{body}");
    assert!(!app.backup_dir.join(&orphan_rel).exists());
    assert_eq!(audit_count(&app, "backup_file_purged", &orphan_rel).await, 1);
    let (st, _, body) = purge(orphan_rel.clone()).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::NOT_FOUND, Some("no_such_file")), "{body}");
    assert_eq!(audit_count(&app, "backup_file_purged", &orphan_rel).await, 1, "a second click audits nothing");

    // A scan that cannot see says so rather than listing nothing.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    let (st, _, body) = send_json(&app.router, "GET", "/api/v1/admin/backups/unreferenced", Some(&admin), None).await;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::INTERNAL_SERVER_ERROR, Some("scan_failed")), "{body}");

    // Not configured: nothing to scan, and said.
    let mut off = test_state(&app);
    off.backup_dir = None;
    let off = web::router(off);
    let (st, _, body) = send_json(&off, "GET", "/api/v1/admin/backups/unreferenced", Some(&admin), None).await;
    assert_eq!((st, body["configured"].clone()), (StatusCode::OK, serde_json::json!(false)), "{body}");
    let (st, _, body) = send_json(&off, "POST", "/api/v1/admin/backups/purge-file", Some(&admin),
        Some(serde_json::json!({"rel": "uf_dir/by-hand.dump"}))).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("backups_disabled")), "{body}");
}

/// `safe_join` checks the text of a path; a directory symlink inside the root
/// still leads out of it. The listing never descends into one, so no path
/// through one was ever offered — and none may be deleted (S7 audit).
#[tokio::test]
async fn a_file_purge_never_follows_a_symlink_out_of_the_backup_root() {
    let Some(app) = test_app().await else { return };
    let state = test_state(&app);

    let outside = std::env::temp_dir().join(format!("cryptarch-outside-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&outside).unwrap();
    let name = format!("20260101T000000Z-{}.dump.zst.enc", Uuid::new_v4());
    let victim = outside.join(&name);
    std::fs::write(&victim, b"another disk's backup").unwrap();
    std::fs::create_dir_all(&app.backup_dir).unwrap();
    std::os::unix::fs::symlink(&outside, app.backup_dir.join("elsewhere")).unwrap();

    let result = cryptarch::backup::purge_unreferenced_file(&state, "admin", &format!("elsewhere/{name}")).await;
    let survived = victim.exists();
    std::fs::remove_dir_all(&outside).unwrap();
    assert!(matches!(result, Err(cryptarch::backup::FilePurgeError::BadPath(_))), "{result:?}");
    assert!(survived, "a file outside the backup directory was deleted through a symlink");

    // Positive control: the same name directly under a real directory in the
    // root is deletable, so the refusal above was about the symlink.
    let real = app.backup_dir.join("real_dir");
    std::fs::create_dir_all(&real).unwrap();
    std::fs::write(real.join(&name), b"x").unwrap();
    cryptarch::backup::purge_unreferenced_file(&state, "admin", &format!("real_dir/{name}"))
        .await
        .expect("a file really under the root is purged");
    assert!(!real.join(&name).exists());

    for odd in ["", "a\0b", &"a/".repeat(3000)] {
        let r = cryptarch::backup::purge_unreferenced_file(&state, "admin", odd).await;
        assert!(matches!(r, Err(cryptarch::backup::FilePurgeError::BadPath(_))), "{odd:.20?}: {r:?}");
    }
}

/// Two purges of one backup: one purges it and audits once, the other finds
/// nothing. A purge that waits on another must re-read the row, not act on
/// what it read before (S7 audit: the FOR UPDATE had no test).
#[tokio::test]
async fn a_purge_racing_another_audits_once() {
    let Some(app) = test_app().await else { return };
    let state = test_state(&app);
    let (id, blob) = orphaned_backup(&app, "raced", chrono::Duration::days(1)).await;

    // Hold the row as the first purge would, then let the second run into it.
    let mut first = app.db.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM backups WHERE id = $1 FOR UPDATE").bind(id).execute(&mut *first).await.unwrap();
    let second = tokio::spawn({
        let state = state.clone();
        async move { cryptarch::backup::purge_operator_backup(&state, "admin", id).await }
    });
    let waiting = async {
        loop {
            let n: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'",
            ).fetch_one(&app.db).await.unwrap();
            if n > 0 { break; }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), waiting).await.expect("the second purge never waited on the row");
    sqlx::query("DELETE FROM backups WHERE id = $1").bind(id).execute(&mut *first).await.unwrap();
    first.commit().await.unwrap();

    let result = second.await.unwrap();
    assert!(matches!(result, Err(cryptarch::backup::PurgeError::NotFound)), "{result:?}");
    assert_eq!(audit_count(&app, "backup_purged", "raced").await, 0, "a purge that removed nothing audited one");
    assert!(blob.exists(), "nor did it touch the file");
}

/// Retention leaves alone a backup a restore is reading, like the purge does.
#[tokio::test]
async fn retention_keeps_a_backup_a_running_restore_reads() {
    let Some(app) = test_app().await else { return };
    let state = test_state(&app);

    let (old, old_blob) = seed_backup(&app, "pruned_reading", chrono::Duration::days(3), "ok").await;
    seed_backup(&app, "pruned_reading", chrono::Duration::days(1), "ok").await;
    let restore = restore_from(&app, old, "pruned_reading", "running").await;

    cryptarch::backup::prune(&state, 1).await.expect("prune");
    assert!(old_blob.exists() && backup_rows(&app, old).await == 1, "a backup being restored from was pruned");

    // Positive control: once that restore is over, the same pass prunes it.
    sqlx::query("UPDATE restores SET status = 'ok' WHERE id = $1").bind(restore).execute(&app.db).await.unwrap();
    cryptarch::backup::prune(&state, 1).await.expect("prune");
    assert!(!old_blob.exists() && backup_rows(&app, old).await == 0);
}

/// A file that could not be looked for is neither present nor missing.
#[tokio::test]
async fn api_left_behind_says_when_a_file_could_not_be_checked() {
    use std::os::unix::fs::PermissionsExt;
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;
    let (_, blob) = orphaned_backup(&app, "lb_dark", chrono::Duration::days(1)).await;
    let dir = blob.parent().unwrap().to_path_buf();

    let (_, _, body) = send_json(&app.router, "GET", "/api/v1/admin/backups/left-behind", Some(&admin), None).await;
    assert_eq!(body["backups"][0]["file_present"], true, "premise: found while readable: {body}");

    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    let (st, _, body) = send_json(&app.router, "GET", "/api/v1/admin/backups/left-behind", Some(&admin), None).await;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["backups"][0]["file_present"], serde_json::Value::Null, "{body}");
    assert_eq!((body["missing"].clone(), body["unchecked"].clone()), (serde_json::json!(0), serde_json::json!(1)), "{body}");

    // And a purge that cannot look must not record "no file found" and drop
    // the row: the file is still there.
    let id = body["backups"][0]["id"].as_str().unwrap().to_string();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    let (st, _, body) = send_json(&app.router, "POST", &format!("/api/v1/admin/backups/{id}/purge"),
        Some(&admin), Some(serde_json::json!({}))).await;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::INTERNAL_SERVER_ERROR, Some("purge_failed")), "{body}");
    assert!(blob.exists() && backup_rows(&app, id.parse().unwrap()).await == 1, "the row was dropped for a file it could not see");
}

// ---- S8a: managed servers, list and detail (CRYPTARCH-136) -------------------

/// A server row the registry holds no engine for: enabled but unreachable, or
/// disabled.
async fn extra_server(app: &TestApp, name: &str, active: bool) -> Uuid {
    let crypto = Crypto::from_hex_key(&"ab".repeat(32)).unwrap();
    sqlx::query_scalar(
        "INSERT INTO managed_servers (name, engine, host, port, admin_dsn_enc, is_active) \
         VALUES ($1, 'postgres', 'other-host', 5433, $2, $3) RETURNING id",
    )
    .bind(name).bind(crypto.seal("postgres://u:secret-pw@other-host/postgres").unwrap()).bind(active)
    .fetch_one(&app.db).await.expect("inserting a server")
}

#[tokio::test]
async fn api_admin_servers_are_admin_only() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    let id = app.server_id;
    for path in [
        "/api/v1/admin/servers".to_string(),
        format!("/api/v1/admin/servers/{id}"),
        format!("/api/v1/admin/servers/{id}/overview"),
        format!("/api/v1/admin/servers/{id}/edge"),
    ] {
        let (st, _, _) = send_json(&app.router, "GET", &path, None, None).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{path} signed out");
        let (st, _, body) = send_json(&app.router, "GET", &path, Some(&alice), None).await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{path} as a tenant");
        assert!(!body.to_string().contains("test-host"), "{path} leaked to a tenant: {body}");
    }
    for (path, body) in [
        (format!("/api/v1/admin/servers/{id}/active"), serde_json::json!({"active": false})),
        (format!("/api/v1/admin/servers/{id}/test"), serde_json::json!({})),
    ] {
        let (st, _, _) = send_json(&app.router, "POST", &path, Some(&alice), Some(body)).await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{path} as a tenant");
    }
    let active: bool = sqlx::query_scalar("SELECT is_active FROM managed_servers WHERE id = $1")
        .bind(id).fetch_one(&app.db).await.unwrap();
    assert!(active && app.servers.get(id).is_some(), "a tenant's request changed the server");
    assert_eq!(audit_count(&app, "test_server", "test-srv").await, 0, "a tenant's request ran the test");
}

#[tokio::test]
async fn api_admin_server_list_and_detail_carry_no_credentials() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;
    let alice = api_login(&app, "alice", "alicepw123").await;
    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/databases", Some(&alice),
        Some(provision_body(app.server_id, "alice_srv", "10.0.0.0/24"))).await;
    assert_eq!(st, StatusCode::CREATED, "{body}");
    let dark = extra_server(&app, "dark-srv", true).await;
    let off = extra_server(&app, "off-srv", false).await;

    let (st, h, body) = send_json(&app.router, "GET", "/api/v1/admin/servers", Some(&admin), None).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(h.get(header::CACHE_CONTROL).unwrap(), "no-store");
    let rows = body["servers"].as_array().expect("servers");
    let by_name = |n: &str| rows.iter().find(|r| r["name"] == n).unwrap_or_else(|| panic!("{n} missing: {body}")).clone();
    let live = by_name("test-srv");
    assert_eq!((live["status"].as_str(), live["db_count"].as_i64(), live["host"].as_str(), live["port"].as_i64()),
        (Some("active"), Some(1), Some("test-host"), Some(5432)), "{live}");
    assert_eq!(live["health"], serde_json::Value::Null, "no sweep has run, and that is not 'healthy': {live}");
    assert_eq!(by_name("dark-srv")["status"], "unreachable");
    assert_eq!(by_name("off-srv")["status"], "disabled");
    assert_eq!(rows.iter().map(|r| r["name"].as_str().unwrap()).collect::<Vec<_>>(),
        vec!["dark-srv", "off-srv", "test-srv"], "ordered by name");
    let text = body.to_string();
    assert!(!text.contains("secret-pw") && !text.contains("postgres://") && !text.contains("dsn_enc"),
        "the list carries credential material: {text}");

    let (st, _, body) = send_json(&app.router, "GET", &format!("/api/v1/admin/servers/{dark}"), Some(&admin), None).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    for (k, v) in [("name", serde_json::json!("dark-srv")), ("status", serde_json::json!("unreachable")),
                   ("has_admin_dsn", serde_json::json!(true)), ("has_bouncer_dsn", serde_json::json!(false)),
                   ("init_status", serde_json::json!("pending")), ("bouncer_conf_dir", serde_json::Value::Null),
                   ("db_count", serde_json::json!(0)), ("health", serde_json::Value::Null)] {
        assert_eq!(body[k], v, "{k}: {body}");
    }
    assert!(!body.to_string().contains("secret-pw"), "{body}");
    let _ = off;

    let (st, _, body) = send_json(&app.router, "GET", &format!("/api/v1/admin/servers/{}", Uuid::new_v4()), Some(&admin), None).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::NOT_FOUND, Some("server_not_found")), "{body}");
}

#[tokio::test]
async fn api_admin_server_overview_reports_what_the_server_said() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;
    let alice = api_login(&app, "alice", "alicepw123").await;
    send_json(&app.router, "POST", "/api/v1/databases", Some(&alice),
        Some(provision_body(app.server_id, "alice_dash", "10.0.0.0/24"))).await;
    let path = format!("/api/v1/admin/servers/{}/overview", app.server_id);

    // Silent: the engine reports no checks, which is not "all clear".
    let (st, _, body) = send_json(&app.router, "GET", &path, Some(&admin), None).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["maintenance"]["findings"], serde_json::json!([]), "{body}");
    let d = &body["dashboard"];
    assert_eq!((d["version"].as_str(), d["uptime"].as_str(), d["total_connections"].as_i64(), d["max_connections"].as_i64()),
        (Some("17.5 (Debian 17.5-1.pgdg120+1)"), Some("3d 4h"), Some(12), Some(100)), "{body}");
    let dbs = d["databases"].as_array().unwrap();
    let dash = dbs.iter().find(|x| x["name"] == "alice_dash").expect("alice_dash listed");
    assert_eq!((dash["size_bytes"].as_i64(), dash["managed"].as_bool()), (Some(19 * 1024 * 1024), Some(true)), "{dash}");
    assert!(dbs.iter().any(|x| x["managed"] == false), "an external database is marked as such: {body}");

    app.engine.set_findings(vec![cryptarch::engine::MaintenanceFinding {
        severity: cryptarch::engine::Severity::Urgent,
        title: "Transaction ID headroom".into(),
        summary: "40% used".into(),
        advice: "Vacuum".into(),
        metrics: vec![],
    }]);
    let (_, _, body) = send_json(&app.router, "GET", &path, Some(&admin), None).await;
    assert_eq!(body["maintenance"]["findings"],
        serde_json::json!([{"severity": "urgent", "title": "Transaction ID headroom", "summary": "40% used", "advice": "Vacuum"}]),
        "{body}");

    // No engine: neither part answered, and both say so.
    let dark = extra_server(&app, "dark-srv", true).await;
    let (st, _, body) = send_json(&app.router, "GET", &format!("/api/v1/admin/servers/{dark}/overview"), Some(&admin), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!((body["dashboard"].clone(), body["maintenance"].clone()), (serde_json::Value::Null, serde_json::Value::Null), "{body}");

    // A wedged server costs the page a note, not a hang.
    app_registry_register(&app, cryptarch::engine::TimeoutEngine::wrap(
        Arc::new(HangingEngine), std::time::Duration::from_millis(300)));
    let started = std::time::Instant::now();
    let (st, _, body) = send_json(&app.router, "GET", &path, Some(&admin), None).await;
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert_eq!((st, body["dashboard"].clone()), (StatusCode::OK, serde_json::Value::Null), "{body}");

    let (st, _, body) = send_json(&app.router, "GET", &format!("/api/v1/admin/servers/{}/overview", Uuid::new_v4()), Some(&admin), None).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::NOT_FOUND, Some("server_not_found")));
}

#[tokio::test]
async fn api_admin_server_edge_health() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;
    let path = format!("/api/v1/admin/servers/{}/edge", app.server_id);

    let (st, _, body) = send_json(&app.router, "GET", &path, Some(&admin), None).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert!(body["hba"]["verdict"].as_str().unwrap().contains("manual placement"), "{body}");
    // Nothing to compare against is unknown, not fine.
    assert_eq!((body["hba"]["state"].as_str(), body["knobs"]["state"].as_str()), (Some("unknown"), Some("unknown")), "{body}");
    assert_eq!(body["pools"], serde_json::Value::Null, "no console configured: {body}");
    assert_eq!(body["dirty"], false);

    let dir = std::env::temp_dir().join(format!("cryptarch-edge-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    sqlx::query("UPDATE managed_servers SET bouncer_conf_dir = $1, edge_dirty = true WHERE id = $2")
        .bind(dir.to_string_lossy().as_ref()).bind(app.server_id).execute(&app.db).await.unwrap();
    let (_, _, body) = send_json(&app.router, "GET", &path, Some(&admin), None).await;
    assert_eq!((body["hba"]["state"].as_str(), body["knobs"]["state"].as_str(), body["dirty"].clone()),
        (Some("bad"), Some("bad"), serde_json::json!(true)), "{body}");
    assert!(body["hba"]["verdict"].as_str().unwrap().contains("hba file missing"), "{body}");

    // The knobs file exactly as it should be, but pgbouncer.ini unreadable:
    // whether it is in effect is unknown.
    let knobs = cryptarch::bouncer::render_knobs(
        &cryptarch::bouncer::load_server_knobs(&app.db, app.server_id).await.unwrap(),
        &cryptarch::bouncer::load_overrides(&app.db, app.server_id).await.unwrap(),
    );
    std::fs::write(dir.join(cryptarch::bouncer::KNOBS_FILE), &knobs).unwrap();
    let (_, _, body) = send_json(&app.router, "GET", &path, Some(&admin), None).await;
    assert_eq!(body["knobs"]["state"], "unknown", "{body}");
    // And with pgbouncer.ini including it, it is fine.
    std::fs::write(dir.join("pgbouncer.ini"), format!("[pgbouncer]\n%include {}\n", dir.join(cryptarch::bouncer::KNOBS_FILE).display())).unwrap();
    let (_, _, body) = send_json(&app.router, "GET", &path, Some(&admin), None).await;
    assert_eq!(body["knobs"]["state"], "ok", "{body}");
    std::fs::write(dir.join("pgbouncer.ini"), "[pgbouncer]\n").unwrap();
    let (_, _, body) = send_json(&app.router, "GET", &path, Some(&admin), None).await;
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(body["knobs"]["state"], "bad", "{body}");
}

#[tokio::test]
async fn api_admin_server_enable_and_disable() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;
    let path = format!("/api/v1/admin/servers/{}/active", app.server_id);
    let is_active = || async {
        sqlx::query_scalar::<_, bool>("SELECT is_active FROM managed_servers WHERE id = $1")
            .bind(app.server_id).fetch_one(&app.db).await.unwrap()
    };

    let (st, _, body) = send_json(&app.router, "POST", &path, Some(&admin), Some(serde_json::json!({"active": "no"}))).await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(is_active().await, "a malformed request changed nothing");

    let (st, _, body) = send_json(&app.router, "POST", &path, Some(&admin), Some(serde_json::json!({"active": false}))).await;
    assert_eq!((st, body.clone()), (StatusCode::OK, serde_json::json!({"active": false, "connected": null})), "{body}");
    assert!(!is_active().await && app.servers.get(app.server_id).is_none(), "disabled, and its engine dropped");
    let actor: String = sqlx::query_scalar("SELECT actor FROM audit_log WHERE action = 'disable_server' AND target = $1")
        .bind(app.server_id.to_string()).fetch_one(&app.db).await.expect("audited");
    assert_eq!(actor, "admin");

    // Enabled again; its stored DSN points nowhere, so it is enabled and says
    // it could not connect rather than reporting a live server.
    let (st, _, body) = send_json(&app.router, "POST", &path, Some(&admin), Some(serde_json::json!({"active": true}))).await;
    assert_eq!((st, body.clone()), (StatusCode::OK, serde_json::json!({"active": true, "connected": false})), "{body}");
    assert!(is_active().await);
    assert_eq!(audit_count(&app, "enable_server", &app.server_id.to_string()).await, 1);
    let (_, _, body) = send_json(&app.router, "GET", &format!("/api/v1/admin/servers/{}", app.server_id), Some(&admin), None).await;
    assert_eq!(body["status"], "unreachable", "{body}");

    let ghost = Uuid::new_v4();
    let (st, _, body) = send_json(&app.router, "POST", &format!("/api/v1/admin/servers/{ghost}/active"),
        Some(&admin), Some(serde_json::json!({"active": false}))).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::NOT_FOUND, Some("server_not_found")), "{body}");
    assert_eq!(audit_count(&app, "disable_server", &ghost.to_string()).await, 0, "nothing changed, nothing audited");
}

#[tokio::test]
async fn api_admin_server_connect_test_reports_each_check() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;
    let (st, h, body) = send_json(&app.router, "POST", &format!("/api/v1/admin/servers/{}/test", app.server_id),
        Some(&admin), Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(h.get(header::CACHE_CONTROL).unwrap(), "no-store");
    let checks = body["checks"].as_array().expect("checks");
    assert_eq!(checks.iter().map(|c| c["check"].as_str().unwrap()).collect::<Vec<_>>(),
        vec!["Admin connection", "Advertised address test-host:5432"], "{body}");
    // The test server's DSN and address point nowhere: both fail, each with why.
    for c in checks {
        assert_eq!(c["ok"], false, "{c}");
        assert!(!c["detail"].as_str().unwrap().is_empty(), "{c}");
    }
    assert_eq!(audit_count(&app, "test_server", "test-srv").await, 1);

    let (st, _, body) = send_json(&app.router, "POST", &format!("/api/v1/admin/servers/{}/test", Uuid::new_v4()),
        Some(&admin), Some(serde_json::json!({}))).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::NOT_FOUND, Some("server_not_found")), "{body}");
}

/// An admin session that began on a password another admin set, then
/// replaced it: ungated, but tagged — the only way to tell `actor()` from
/// `username` in an audit row.
async fn tagged_admin(app: &TestApp, name: &str) -> String {
    let admin = api_login(app, "admin", "adminpw123").await;
    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/admin/users", Some(&admin),
        Some(serde_json::json!({"username": name, "password": format!("{name}start1"), "quota": 1, "is_admin": true}))).await;
    assert_eq!(st, StatusCode::CREATED, "{body}");
    let first = api_login(app, name, &format!("{name}start1")).await;
    let (_, rotated, _) = change_own_password(app, &first, &format!("{name}start1"), &format!("{name}sown123")).await;
    rotated.expect("a rotated session")
}

/// The page's own bound, not just the engine's: a server whose engine has no
/// bound of its own still costs the overview about 3s, never more.
#[tokio::test]
async fn api_admin_server_overview_is_bounded_by_itself() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;
    app_registry_register(&app, Arc::new(HangingEngine));
    let started = std::time::Instant::now();
    let (st, _, body) = send_json(&app.router, "GET", &format!("/api/v1/admin/servers/{}/overview", app.server_id),
        Some(&admin), None).await;
    assert!(started.elapsed() < std::time::Duration::from_secs(5), "took {:?}", started.elapsed());
    assert_eq!((st, body["dashboard"].clone()), (StatusCode::OK, serde_json::Value::Null), "{body}");
}

/// A change that cannot be audited does not happen.
#[tokio::test]
async fn api_admin_server_disable_that_cannot_be_audited_does_not_happen() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;
    sqlx::raw_sql(
        "CREATE FUNCTION refuse_audit() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN RAISE EXCEPTION 'audit unavailable'; END $$; \
         CREATE TRIGGER refuse_disable_audit BEFORE INSERT ON audit_log FOR EACH ROW \
         WHEN (NEW.action = 'disable_server') EXECUTE FUNCTION refuse_audit();",
    ).execute(&app.db).await.unwrap();
    let (st, _, body) = send_json(&app.router, "POST", &format!("/api/v1/admin/servers/{}/active", app.server_id),
        Some(&admin), Some(serde_json::json!({"active": false}))).await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    let active: bool = sqlx::query_scalar("SELECT is_active FROM managed_servers WHERE id = $1")
        .bind(app.server_id).fetch_one(&app.db).await.unwrap();
    assert!(active, "the server was disabled with no audit row");
    assert!(app.servers.get(app.server_id).is_some(), "and its engine is still live");
}

/// Enabling a server whose stored login works connects it, and the audit names
/// the session as it is (CRYPTARCH-146).
#[tokio::test]
async fn api_admin_server_enable_connects_a_reachable_server() {
    let Some(app) = test_app().await else { return };
    let dsn = std::env::var(TEST_DSN_VAR).unwrap();
    let crypto = Crypto::from_hex_key(&"ab".repeat(32)).unwrap();
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO managed_servers (name, engine, host, port, admin_dsn_enc, is_active) \
         VALUES ('real-srv', 'postgres', 'localhost', 5432, $1, false) RETURNING id",
    ).bind(crypto.seal(&dsn).unwrap()).fetch_one(&app.db).await.unwrap();
    let erin = tagged_admin(&app, "erin").await;

    let (st, _, body) = send_json(&app.router, "POST", &format!("/api/v1/admin/servers/{id}/active"),
        Some(&erin), Some(serde_json::json!({"active": true}))).await;
    assert_eq!((st, body.clone()), (StatusCode::OK, serde_json::json!({"active": true, "connected": true})), "{body}");
    assert!(app.servers.get(id).is_some(), "an engine is registered");
    let (_, _, body) = send_json(&app.router, "GET", &format!("/api/v1/admin/servers/{id}"), Some(&erin), None).await;
    assert_eq!(body["status"], "active", "{body}");
    assert_eq!(actors_of(&app, "enable_server", &id.to_string()).await, ["erin [on a password set by admin]"]);

    let (st, _, _) = send_json(&app.router, "POST", &format!("/api/v1/admin/servers/{id}/test"),
        Some(&erin), Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(actors_of(&app, "test_server", "real-srv").await, ["erin [on a password set by admin]"]);
}

// ---- S8b: adding a server, init, credentials (CRYPTARCH-136) ---------------

/// The test DSN, pointed at this test's own throwaway database: a real login
/// whose writes land nowhere shared.
async fn own_db_dsn(app: &TestApp) -> String {
    let db: String = sqlx::query_scalar("SELECT current_database()").fetch_one(&app.db).await.unwrap();
    let dsn = std::env::var(TEST_DSN_VAR).unwrap();
    let (base, _) = dsn.rsplit_once('/').expect("a DSN with a database");
    format!("{base}/{db}")
}

fn new_server_body(name: &str, admin_dsn: &str) -> serde_json::Value {
    serde_json::json!({
        "name": name, "admin_dsn": admin_dsn, "bouncer_dsn": null, "host": "edge.lan", "port": 6432,
        "pool_mode": "session", "tls_mode": "off", "backend_kind": "docker", "default_consumer_cidr": "10.20.0.0/16"
    })
}

#[tokio::test]
async fn api_admin_server_writes_are_admin_only() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    let id = app.server_id;
    for (path, body) in [
        ("/api/v1/admin/servers".to_string(), new_server_body("tenant-srv", "postgres://x@nowhere/db")),
        (format!("/api/v1/admin/servers/{id}/init"), serde_json::json!({})),
        (format!("/api/v1/admin/servers/{id}/credentials"), serde_json::json!({"bouncer_dsn": "postgres://evil@x/pgbouncer"})),
    ] {
        let (st, _, _) = send_json(&app.router, "POST", &path, None, Some(body.clone())).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{path} signed out");
        let (st, _, _) = send_json(&app.router, "POST", &path, Some(&alice), Some(body)).await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{path} as a tenant");
    }
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM managed_servers").fetch_one(&app.db).await.unwrap();
    let bouncer: i32 = sqlx::query_scalar("SELECT octet_length(bouncer_admin_dsn_enc) FROM managed_servers WHERE id = $1")
        .bind(id).fetch_one(&app.db).await.unwrap();
    assert_eq!((n, bouncer), (1, 0), "a tenant's request changed the registry");
    assert_eq!(audit_count(&app, "server_init", &id.to_string()).await, 0);
}

/// The front door of the security spine: the DSN must connect, and its role
/// must never be a superuser. Every refusal says which, writes nothing, and
/// never echoes the DSN back.
#[tokio::test]
async fn api_admin_add_server_vets_the_login_and_stores_it_sealed() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;
    let count = || async { sqlx::query_scalar::<_, i64>("SELECT count(*) FROM managed_servers").fetch_one(&app.db).await.unwrap() };

    // Malformed fields: refused before anything connects.
    for (field, value) in [("name", serde_json::json!("Bad Name")), ("port", serde_json::json!(70000)),
                           ("pool_mode", serde_json::json!("statement")), ("default_consumer_cidr", serde_json::json!("10.1.2.3/24")),
                           ("host", serde_json::json!(" "))] {
        let mut body = new_server_body("new-srv", "postgres://u:hunter2@127.0.0.1:1/db");
        body[field] = value;
        let (st, _, body) = send_json(&app.router, "POST", "/api/v1/admin/servers", Some(&admin), Some(body)).await;
        assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("invalid")), "{field}: {body}");
    }

    // A DSN the driver rejects, repeating part of it: the password is taken
    // out wherever it appears. Here it is also pasted as the sslmode, which
    // the driver's message quotes back — so the scrub has something to do.
    let (st, h, body) = send_json(&app.router, "POST", "/api/v1/admin/servers", Some(&admin),
        Some(new_server_body("new-srv", "postgres://u:hunter2@127.0.0.1:1/db?sslmode=hunter2"))).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("dsn_check_failed")), "{body}");
    assert_eq!(h.get(header::CACHE_CONTROL).unwrap(), "no-store");
    assert!(body["error"]["message"].as_str().unwrap().contains("****"), "premise: the driver echoed it: {body}");
    assert!(!body.to_string().contains("hunter2"), "the error echoed the password: {body}");

    // A superuser login connects, and is refused: the spine.
    let dsn = own_db_dsn(&app).await;
    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/admin/servers", Some(&admin),
        Some(new_server_body("new-srv", &dsn))).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("role_refused")), "{body}");
    assert!(body["error"]["message"].as_str().unwrap().contains("SUPERUSER"), "{body}");
    assert_eq!(count().await, 1, "nothing was added");
    assert_eq!(audit_count(&app, "add_server", "new-srv").await, 0);
}

/// A role made for one test on the shared cluster, and its DSN into this
/// test's own database. Dropped at the end — loudly, so a leak fails the test.
struct VettedRole {
    admin: PgPool,
    name: String,
}

impl VettedRole {
    /// A login that passes the gate: CREATEDB CREATEROLE, not superuser.
    async fn create(app: &TestApp) -> (Self, String) {
        Self::with(app, "LOGIN CREATEDB CREATEROLE", &[]).await
    }
    async fn with(app: &TestApp, attrs: &str, then: &[&str]) -> (Self, String) {
        let admin = PgPoolOptions::new().max_connections(1)
            .connect(&std::env::var(TEST_DSN_VAR).unwrap()).await.unwrap();
        let name = format!("cryptarch_t_{}", &Uuid::new_v4().simple().to_string()[..12]);
        sqlx::raw_sql(AssertSqlSafe(format!("CREATE ROLE \"{name}\" {attrs} PASSWORD 'vetted-pw-123'")))
            .execute(&admin).await.unwrap();
        for sql in then {
            sqlx::raw_sql(AssertSqlSafe(sql.replace("{role}", &name))).execute(&admin).await.unwrap();
        }
        let db: String = sqlx::query_scalar("SELECT current_database()").fetch_one(&app.db).await.unwrap();
        let dsn = std::env::var(TEST_DSN_VAR).unwrap();
        let (base, _) = dsn.rsplit_once('/').unwrap();
        let (scheme_creds, host) = base.split_once('@').unwrap();
        let (scheme, _) = scheme_creds.split_once("//").unwrap();
        let vetted = format!("{scheme}//{name}:vetted-pw-123@{host}/{db}");
        (Self { admin, name }, vetted)
    }
    async fn drop_role(self) {
        sqlx::raw_sql(AssertSqlSafe(format!("DROP ROLE IF EXISTS \"{}\"", self.name)))
            .execute(&self.admin).await.expect("dropping the test role");
    }
}

/// A stored DSN that switches role after login is refused where an engine is
/// made, too — at boot and on enable — not only at the two doors.
#[tokio::test]
async fn a_stored_dsn_that_switches_role_never_gets_an_engine() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;
    let (target, _) = VettedRole::with(&app, "NOLOGIN CREATEDB CREATEROLE", &[]).await;
    let crypto = Crypto::from_hex_key(&"ab".repeat(32)).unwrap();
    let mut ids = Vec::new();
    for (name, dsn) in [("plain-srv", own_db_dsn(&app).await),
                        ("switched-srv", format!("{}?options=-c%20role%3D{}", own_db_dsn(&app).await, target.name))] {
        ids.push(sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO managed_servers (name, engine, host, port, admin_dsn_enc, is_active) \
             VALUES ($1, 'postgres', 'localhost', 5432, $2, false) RETURNING id",
        ).bind(name).bind(crypto.seal(&dsn).unwrap()).fetch_one(&app.db).await.unwrap());
    }
    let mut answers = Vec::new();
    for id in &ids {
        let (_, _, body) = send_json(&app.router, "POST", &format!("/api/v1/admin/servers/{id}/active"),
            Some(&admin), Some(serde_json::json!({"active": true}))).await;
        answers.push(body["connected"].clone());
    }
    target.drop_role().await;
    // The test state allows a superuser login (as the dev seed does), so the
    // plain one connects: the refusal of the other is about the switch.
    assert_eq!(answers, vec![serde_json::json!(true), serde_json::json!(false)]);
    assert!(app.servers.get(ids[1]).is_none());
}

/// The gate judges the LOGIN, not only the role it ends up acting as (S8b
/// audit P1): a DSN that logs in as a superuser and switches role with
/// `options`, a login that can SET ROLE to a superuser, and a login missing
/// CREATEROLE are each refused, by both doors, storing nothing.
#[tokio::test]
async fn api_admin_server_logins_that_are_or_can_become_superuser_are_refused() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;
    let (target, _) = VettedRole::with(&app, "NOLOGIN CREATEDB CREATEROLE", &[]).await;
    let switched = format!("{}?options=-c%20role%3D{}", own_db_dsn(&app).await, target.name);
    let (member, member_dsn) = VettedRole::with(&app, "LOGIN CREATEDB CREATEROLE", &["GRANT postgres TO \"{role}\""]).await;
    let (no_createrole, weak_dsn) = VettedRole::with(&app, "LOGIN CREATEDB", &[]).await;
    let (vetted, ok_dsn) = VettedRole::create(&app).await;

    let mut refusals = Vec::new();
    for dsn in [&switched, &member_dsn, &weak_dsn] {
        let (st, _, body) = send_json(&app.router, "POST", "/api/v1/admin/servers", Some(&admin),
            Some(new_server_body("sneaky-srv", dsn))).await;
        refusals.push((st, body["error"]["code"].as_str().map(String::from), body["error"]["message"].as_str().unwrap_or("").to_string()));
    }
    let before: Vec<u8> = sqlx::query_scalar("SELECT admin_dsn_enc FROM managed_servers WHERE id = $1")
        .bind(app.server_id).fetch_one(&app.db).await.unwrap();
    let (rot_st, _, rot) = send_json(&app.router, "POST", &format!("/api/v1/admin/servers/{}/credentials", app.server_id),
        Some(&admin), Some(serde_json::json!({"admin_dsn": switched}))).await;
    let after: Vec<u8> = sqlx::query_scalar("SELECT admin_dsn_enc FROM managed_servers WHERE id = $1")
        .bind(app.server_id).fetch_one(&app.db).await.unwrap();
    // Positive control: the same shape of request with a plain vetted login is accepted.
    let (ok_st, _, ok) = send_json(&app.router, "POST", "/api/v1/admin/servers", Some(&admin),
        Some(new_server_body("fine-srv", &ok_dsn))).await;
    let servers: Vec<String> = sqlx::query_scalar("SELECT name FROM managed_servers ORDER BY name").fetch_all(&app.db).await.unwrap();
    for r in [target, member, no_createrole, vetted] { r.drop_role().await; }

    let refused = |i: usize, says: &str| {
        let (st, code, msg) = &refusals[i];
        assert_eq!((*st, code.as_deref()), (StatusCode::UNPROCESSABLE_ENTITY, Some("role_refused")), "case {i}: {msg}");
        assert!(msg.contains(says), "case {i} said: {msg}");
    };
    refused(0, "logs in as 'postgres' and then acts as");
    refused(1, "SUPERUSER");
    refused(2, "needs both CREATEDB and CREATEROLE");
    assert_eq!((rot_st, rot["error"]["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("role_refused")), "{rot}");
    assert_eq!(before, after, "a refused rotation stored the switched DSN");
    assert_eq!(ok_st, StatusCode::CREATED, "premise: a vetted login is accepted: {ok}");
    assert_eq!(servers, vec!["fine-srv", "test-srv"], "only the vetted server was added");
}

#[tokio::test]
async fn api_admin_add_server_adds_a_vetted_login() {
    let Some(app) = test_app().await else { return };
    let admin = tagged_admin(&app, "erin").await;
    let (role, dsn) = VettedRole::create(&app).await;

    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/admin/servers", Some(&admin),
        Some(new_server_body("new-srv", &dsn))).await;
    let id: Uuid = body["id"].as_str().unwrap_or_default().parse().unwrap_or_default();
    let added: Option<(String, i32, Vec<u8>, String, Option<String>)> = sqlx::query_as(
        "SELECT host, port, admin_dsn_enc, pool_mode, default_consumer_cidr::text FROM managed_servers WHERE id = $1",
    ).bind(id).fetch_optional(&app.db).await.unwrap();
    let live = app.servers.get(id).is_some();
    let (st2, _, dup) = send_json(&app.router, "POST", "/api/v1/admin/servers", Some(&admin),
        Some(new_server_body("new-srv", &dsn))).await;
    role.drop_role().await;

    assert_eq!(st, StatusCode::CREATED, "{body}");
    let (host, port, enc, pool, cidr) = added.expect("the row");
    assert_eq!((host.as_str(), port, pool.as_str(), cidr.as_deref()), ("edge.lan", 6432, "session", Some("10.20.0.0/16")));
    assert!(!String::from_utf8_lossy(&enc).contains("vetted-pw-123"), "the DSN was stored in the clear");
    assert!(live, "registered live, so provisioning works without a restart");
    assert_eq!(actors_of(&app, "add_server", "new-srv").await, ["erin [on a password set by admin]"]);
    assert_eq!((st2, dup["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("name_taken")), "{dup}");
    assert_eq!(audit_count(&app, "add_server", "new-srv").await, 1, "the refused duplicate audited nothing");
}

/// Init reports each step. Run against this test's own database, it stops at
/// the bootstrap check — before anything cluster-wide is touched — and hands
/// back the SQL to run, rendered for the role it actually connected as.
#[tokio::test]
async fn api_admin_server_init_reports_steps_and_the_bootstrap_sql() {
    let Some(app) = test_app().await else { return };
    let admin = tagged_admin(&app, "erin").await;

    // The test server's stored DSN points nowhere: the first step fails.
    let (st, h, body) = send_json(&app.router, "POST", &format!("/api/v1/admin/servers/{}/init", app.server_id),
        Some(&admin), Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(h.get(header::CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(body["status"], "failed", "{body}");
    assert_eq!(body["steps"][0]["step"], "Admin connection");
    assert_eq!(body["steps"][0]["ok"], false);
    assert_eq!((body["bootstrap_sql"].clone(), body["userlist_line"].clone()), (serde_json::Value::Null, serde_json::Value::Null));
    assert_eq!(actors_of(&app, "server_init", &app.server_id.to_string()).await, ["erin [on a password set by admin]"]);

    let crypto = Crypto::from_hex_key(&"ab".repeat(32)).unwrap();
    let own: Uuid = sqlx::query_scalar(
        "INSERT INTO managed_servers (name, engine, host, port, admin_dsn_enc) VALUES ('own-db', 'postgres', 'localhost', 5432, $1) RETURNING id",
    ).bind(crypto.seal(&own_db_dsn(&app).await).unwrap()).fetch_one(&app.db).await.unwrap();
    let (st, _, body) = send_json(&app.router, "POST", &format!("/api/v1/admin/servers/{own}/init"),
        Some(&admin), Some(serde_json::json!({}))).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "needs_bootstrap", "{body}");
    let steps: Vec<(&str, bool)> = body["steps"].as_array().unwrap().iter()
        .map(|s| (s["step"].as_str().unwrap(), s["ok"].as_bool().unwrap())).collect();
    assert_eq!(steps, vec![("Admin connection", true), ("Superuser bootstrap", false)], "{body}");
    let sql = body["bootstrap_sql"].as_str().expect("the bootstrap SQL");
    assert!(sql.contains("GRANT SELECT ON pg_shadow TO \"postgres\";"), "rendered for the role it connected as: {sql}");
    assert_eq!(body["userlist_line"], serde_json::Value::Null);
    let status: String = sqlx::query_scalar("SELECT init_status FROM managed_servers WHERE id = $1").bind(own).fetch_one(&app.db).await.unwrap();
    assert_eq!(status, "needs_bootstrap");

    let (st, _, body) = send_json(&app.router, "POST", &format!("/api/v1/admin/servers/{}/init", Uuid::new_v4()),
        Some(&admin), Some(serde_json::json!({}))).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::NOT_FOUND, Some("server_not_found")), "{body}");
}

#[tokio::test]
async fn api_admin_server_credentials_rotate_vetted_and_sealed() {
    let Some(app) = test_app().await else { return };
    let admin = tagged_admin(&app, "erin").await;
    let path = format!("/api/v1/admin/servers/{}/credentials", app.server_id);
    let stored = || async {
        sqlx::query_as::<_, (Vec<u8>, Vec<u8>)>("SELECT admin_dsn_enc, bouncer_admin_dsn_enc FROM managed_servers WHERE id = $1")
            .bind(app.server_id).fetch_one(&app.db).await.unwrap()
    };
    let before = stored().await;

    let (st, _, body) = send_json(&app.router, "POST", &path, Some(&admin), Some(serde_json::json!({"admin_dsn": " ", "bouncer_dsn": ""}))).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("nothing_to_rotate")), "{body}");

    // A superuser login is refused here too, and changes nothing.
    let (st, _, body) = send_json(&app.router, "POST", &path, Some(&admin),
        Some(serde_json::json!({"admin_dsn": own_db_dsn(&app).await, "bouncer_dsn": "postgres://pgb:console-pw@edge/pgbouncer"}))).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("role_refused")), "{body}");
    assert_eq!(stored().await, before, "a refused rotation stored the bouncer DSN anyway");

    // The bouncer console login alone: sealed, audited.
    let (st, h, body) = send_json(&app.router, "POST", &path, Some(&admin),
        Some(serde_json::json!({"bouncer_dsn": "postgres://pgb:console-pw@edge/pgbouncer"}))).await;
    assert_eq!((st, body.clone()), (StatusCode::OK, serde_json::json!({"admin": false, "bouncer": true, "reconnected": null})), "{body}");
    assert_eq!(h.get(header::CACHE_CONTROL).unwrap(), "no-store");
    let after = stored().await;
    assert_eq!(after.0, before.0, "the admin DSN was kept");
    assert!(!after.1.is_empty() && !String::from_utf8_lossy(&after.1).contains("console-pw"), "stored, sealed");
    assert_eq!(actors_of(&app, "update_server_credentials", &app.server_id.to_string()).await, ["erin [on a password set by admin]"]);

    // A vetted admin login rotates and the engine reconnects with it.
    let (role, dsn) = VettedRole::create(&app).await;
    let (st, _, body) = send_json(&app.router, "POST", &path, Some(&admin), Some(serde_json::json!({"admin_dsn": dsn}))).await;
    let live = app.servers.get(app.server_id).is_some();
    role.drop_role().await;
    assert_eq!((st, body.clone()), (StatusCode::OK, serde_json::json!({"admin": true, "bouncer": false, "reconnected": true})), "{body}");
    assert!(live, "reconnected with the new login");
    assert_ne!(stored().await.0, before.0);

    let (st, _, body) = send_json(&app.router, "POST", &format!("/api/v1/admin/servers/{}/credentials", Uuid::new_v4()),
        Some(&admin), Some(serde_json::json!({"bouncer_dsn": "postgres://x@y/z"}))).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::NOT_FOUND, Some("server_not_found")), "{body}");
}

// ---- S8c: server settings, sources, listeners, overrides, sync (CRYPTARCH-136)

fn srv_path(app: &TestApp, rest: &str) -> String {
    format!("/api/v1/admin/servers/{}{rest}", app.server_id)
}

#[tokio::test]
async fn api_admin_server_config_routes_are_admin_only() {
    let Some(app) = test_app().await else { return };
    let alice = api_login(&app, "alice", "alicepw123").await;
    let (st, _, _) = send_json(&app.router, "GET", &srv_path(&app, "/config"), Some(&alice), None).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let x = Uuid::new_v4();
    for (method, rest, body) in [
        ("POST", "/settings/address".to_string(), serde_json::json!({"host": "evil", "port": 1})),
        ("POST", "/settings/pooling".to_string(), serde_json::json!({"pool_mode": "session", "default_pool_size": 1, "max_client_conn": 1, "max_db_connections": 0, "max_user_connections": 0})),
        ("POST", "/settings/edge".to_string(), serde_json::json!({"tls_mode": "off", "backend_kind": "vm", "default_consumer_cidr": null, "bouncer_conf_dir": null})),
        ("POST", "/sources".to_string(), serde_json::json!({"label": "x", "cidr": "10.0.0.0/8", "is_default": false})),
        ("DELETE", format!("/sources/{x}"), serde_json::json!({})),
        ("POST", "/listeners".to_string(), serde_json::json!({"label": "x", "host": "h", "port": 1})),
        ("DELETE", format!("/listeners/{x}"), serde_json::json!({})),
        ("POST", format!("/databases/{x}/pool"), serde_json::json!({"pool_mode": "session", "max_connections": null})),
        ("POST", "/sync".to_string(), serde_json::json!({})),
    ] {
        let (st, _, _) = send_json(&app.router, method, &srv_path(&app, &rest), None, Some(body.clone())).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{method} {rest} signed out");
        let (st, _, _) = send_json(&app.router, method, &srv_path(&app, &rest), Some(&alice), Some(body)).await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{method} {rest} as a tenant");
    }
    let host: String = sqlx::query_scalar("SELECT host FROM managed_servers WHERE id = $1").bind(app.server_id).fetch_one(&app.db).await.unwrap();
    let n: i64 = sqlx::query_scalar("SELECT (SELECT count(*) FROM server_sources) + (SELECT count(*) FROM server_listeners)").fetch_one(&app.db).await.unwrap();
    assert_eq!((host.as_str(), n), ("test-host", 0), "a tenant's request changed the server");
}

#[tokio::test]
async fn api_admin_server_settings_validate_save_and_audit() {
    let Some(app) = test_app().await else { return };
    let admin = tagged_admin(&app, "erin").await;
    let tag = "erin [on a password set by admin]";
    let target = app.server_id.to_string();
    let row = || async {
        sqlx::query_as::<_, (String, i32, String, i32, String, Option<String>, Option<String>)>(
            "SELECT host, port, pool_mode, default_pool_size, tls_mode, default_consumer_cidr::text, bouncer_conf_dir \
             FROM managed_servers WHERE id = $1").bind(app.server_id).fetch_one(&app.db).await.unwrap()
    };
    let before = row().await;

    // Address.
    for bad in [serde_json::json!({"host": " ", "port": 6432}), serde_json::json!({"host": "edge", "port": 70000}),
                serde_json::json!({"host": "evil host?x=1", "port": 6432})] {
        let (st, _, body) = send_json(&app.router, "POST", &srv_path(&app, "/settings/address"), Some(&admin), Some(bad)).await;
        assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("invalid")), "{body}");
    }
    assert_eq!(row().await, before, "a refused change changed nothing");
    let (st, _, body) = send_json(&app.router, "POST", &srv_path(&app, "/settings/address"), Some(&admin),
        Some(serde_json::json!({"host": "edge2.lan", "port": 7432}))).await;
    // Its stored DSN points nowhere, so the engine could not come back: said.
    assert_eq!((st, body.clone()), (StatusCode::OK, serde_json::json!({"reconnected": false})), "{body}");
    assert_eq!((row().await.0, row().await.1), ("edge2.lan".to_string(), 7432));
    assert_eq!(actors_of(&app, "update_server_address", &target).await, [tag]);

    // Pooling: no conf dir, so the change is rendered for manual placement.
    let (st, _, body) = send_json(&app.router, "POST", &srv_path(&app, "/settings/pooling"), Some(&admin),
        Some(serde_json::json!({"pool_mode": "transaction", "default_pool_size": 2000, "max_client_conn": 100, "max_db_connections": 0, "max_user_connections": 0}))).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("invalid")), "{body}");
    let (st, _, body) = send_json(&app.router, "POST", &srv_path(&app, "/settings/pooling"), Some(&admin),
        Some(serde_json::json!({"pool_mode": "transaction", "default_pool_size": 25, "max_client_conn": 100, "max_db_connections": 0, "max_user_connections": 5}))).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["edge"]["state"], "manual", "{body}");
    assert!(body["edge"]["knobs"].as_str().unwrap().contains("default_pool_size = 25"), "{body}");
    assert_eq!((row().await.2, row().await.3), ("transaction".to_string(), 25));
    assert_eq!(actors_of(&app, "update_server_pooling", &target).await, [tag]);

    // Edge: a bad range, a relative conf dir; then a real conf dir is written to.
    for bad in [serde_json::json!({"tls_mode": "off", "backend_kind": "vm", "default_consumer_cidr": "10.1.2.3/24", "bouncer_conf_dir": null}),
                serde_json::json!({"tls_mode": "off", "backend_kind": "vm", "default_consumer_cidr": null, "bouncer_conf_dir": "etc/pgbouncer"}),
                serde_json::json!({"tls_mode": "sometimes", "backend_kind": "vm", "default_consumer_cidr": null, "bouncer_conf_dir": null})] {
        let (st, _, body) = send_json(&app.router, "POST", &srv_path(&app, "/settings/edge"), Some(&admin), Some(bad)).await;
        assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("invalid")), "{body}");
    }
    for dir in ["/", "/srv/../etc", "relative/dir"] {
        let (st, _, body) = send_json(&app.router, "POST", &srv_path(&app, "/settings/edge"), Some(&admin),
            Some(serde_json::json!({"tls_mode": "off", "backend_kind": "vm", "default_consumer_cidr": null, "bouncer_conf_dir": dir}))).await;
        assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("invalid")), "{dir}: {body}");
    }
    // Leaving a field out is not the same as clearing it.
    let (st, _, body) = send_json(&app.router, "POST", &srv_path(&app, "/settings/edge"), Some(&admin),
        Some(serde_json::json!({"tls_mode": "off", "backend_kind": "vm", "bouncer_conf_dir": null}))).await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(row().await.5.as_deref(), before.5.as_deref(), "an omitted field was cleared");

    // A directory that is not a bouncer's: saved, but nothing is written there.
    let bare = std::env::temp_dir().join(format!("cryptarch-conf-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&bare).unwrap();
    let (st, _, body) = send_json(&app.router, "POST", &srv_path(&app, "/settings/edge"), Some(&admin),
        Some(serde_json::json!({"tls_mode": "edge", "backend_kind": "vm", "default_consumer_cidr": "10.20.0.0/16", "bouncer_conf_dir": bare.to_string_lossy()}))).await;
    let stray = std::fs::read_dir(&bare).unwrap().count();
    std::fs::remove_dir_all(&bare).unwrap();
    assert_eq!((st, body["edge"]["state"].as_str()), (StatusCode::OK, Some("failed")), "{body}");
    assert!(body["edge"]["error"].as_str().unwrap().contains("no pgbouncer.ini"), "{body}");
    assert_eq!(stray, 0, "edge files were written into a directory that is not a bouncer's");

    let dir = temp_conf_dir();
    let (st, _, body) = send_json(&app.router, "POST", &srv_path(&app, "/settings/edge"), Some(&admin),
        Some(serde_json::json!({"tls_mode": "edge", "backend_kind": "vm", "default_consumer_cidr": "10.20.0.0/16", "bouncer_conf_dir": dir.to_string_lossy()}))).await;
    let written = dir.join("pgbouncer_hba.conf").exists() && dir.join(cryptarch::bouncer::KNOBS_FILE).exists();
    assert_eq!((st, body["edge"]["state"].as_str()), (StatusCode::OK, Some("applied")), "{body}");
    assert!(written, "the edge files were written to the conf dir");
    let r = row().await;
    assert_eq!((r.4.as_str(), r.5.as_deref()), ("edge", Some("10.20.0.0/16")));
    assert_eq!(actors_of(&app, "update_server_edge", &target).await, [tag, tag]);

    // Another server may not share it.
    let other = extra_server(&app, "other-srv", true).await;
    let (st, _, body) = send_json(&app.router, "POST", &format!("/api/v1/admin/servers/{other}/settings/edge"), Some(&admin),
        Some(serde_json::json!({"tls_mode": "off", "backend_kind": "vm", "default_consumer_cidr": null, "bouncer_conf_dir": dir.to_string_lossy()}))).await;
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("duplicate")), "{body}");

    let ghost = format!("/api/v1/admin/servers/{}/settings/address", Uuid::new_v4());
    let (st, _, body) = send_json(&app.router, "POST", &ghost, Some(&admin), Some(serde_json::json!({"host": "x", "port": 1}))).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::NOT_FOUND, Some("server_not_found")), "{body}");
}

#[tokio::test]
async fn api_admin_server_sources_and_listeners() {
    let Some(app) = test_app().await else { return };
    let admin = tagged_admin(&app, "erin").await;
    let tag = "erin [on a password set by admin]";
    let target = app.server_id.to_string();
    let other = extra_server(&app, "other-srv", true).await;
    let foreign: Uuid = sqlx::query_scalar(
        "INSERT INTO server_sources (server_id, label, cidr) VALUES ($1, 'theirs', '10.9.0.0/16') RETURNING id",
    ).bind(other).fetch_one(&app.db).await.unwrap();
    let foreign_listener: Uuid = sqlx::query_scalar(
        "INSERT INTO server_listeners (server_id, host, port, label, position) VALUES ($1, 'theirs.lan', 6432, 'theirs', 1) RETURNING id",
    ).bind(other).fetch_one(&app.db).await.unwrap();

    // Sources.
    for bad in [serde_json::json!({"label": "", "cidr": "10.0.0.0/8", "is_default": false}),
                serde_json::json!({"label": "bell\u{7}", "cidr": "10.0.0.0/8", "is_default": false}),
                serde_json::json!({"label": "x".repeat(33), "cidr": "10.0.0.0/8", "is_default": false}),
                serde_json::json!({"label": "lan", "cidr": "lan.example", "is_default": false})] {
        let (st, _, body) = send_json(&app.router, "POST", &srv_path(&app, "/sources"), Some(&admin), Some(bad)).await;
        assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("invalid")), "{body}");
    }
    let (st, _, body) = send_json(&app.router, "POST", &srv_path(&app, "/sources"), Some(&admin),
        Some(serde_json::json!({"label": "lan", "cidr": "192.168.8.0/24", "is_default": true}))).await;
    assert_eq!(st, StatusCode::CREATED, "{body}");
    let (st, _, body) = send_json(&app.router, "POST", &srv_path(&app, "/sources"), Some(&admin),
        Some(serde_json::json!({"label": "lan", "cidr": "192.168.9.0/24", "is_default": false}))).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("duplicate")), "{body}");
    assert_eq!(actors_of(&app, "source_add", &target).await, [tag], "the duplicate audited nothing");

    // Listeners.
    for bad in [serde_json::json!({"label": "lan", "host": "bad host!", "port": 6432}),
                serde_json::json!({"label": "lan", "host": "pg.lan", "port": 0})] {
        let (st, _, body) = send_json(&app.router, "POST", &srv_path(&app, "/listeners"), Some(&admin), Some(bad)).await;
        assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("invalid")), "{body}");
    }
    let (st, _, body) = send_json(&app.router, "POST", &srv_path(&app, "/listeners"), Some(&admin),
        Some(serde_json::json!({"label": "tailnet", "host": "pg.tail.example", "port": 6432}))).await;
    assert_eq!(st, StatusCode::CREATED, "{body}");
    let (st, _, body) = send_json(&app.router, "POST", &srv_path(&app, "/listeners"), Some(&admin),
        Some(serde_json::json!({"label": "again", "host": "pg.tail.example", "port": 6432}))).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("duplicate")), "{body}");

    // Both listed.
    let (st, _, cfg) = send_json(&app.router, "GET", &srv_path(&app, "/config"), Some(&admin), None).await;
    assert_eq!(st, StatusCode::OK, "{cfg}");
    assert_eq!(cfg["sources"], serde_json::json!([{"id": cfg["sources"][0]["id"], "label": "lan", "cidr": "192.168.8.0/24", "is_default": true}]), "{cfg}");
    assert_eq!(cfg["listeners"].as_array().unwrap().len(), 1);
    assert_eq!((cfg["listeners"][0]["label"].as_str(), cfg["listeners"][0]["host"].as_str(), cfg["listeners"][0]["port"].as_i64()),
        (Some("tailnet"), Some("pg.tail.example"), Some(6432)));
    let source_id = cfg["sources"][0]["id"].as_str().unwrap().to_string();
    let listener_id = cfg["listeners"][0]["id"].as_str().unwrap().to_string();

    // Removing: another server's source is not this server's to remove.
    let (st, _, body) = send_json(&app.router, "DELETE", &srv_path(&app, &format!("/sources/{foreign}")), Some(&admin), Some(serde_json::json!({}))).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::NOT_FOUND, Some("no_such_item")), "{body}");
    let (st, _, body) = send_json(&app.router, "DELETE", &srv_path(&app, &format!("/listeners/{foreign_listener}")), Some(&admin), Some(serde_json::json!({}))).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::NOT_FOUND, Some("no_such_item")), "{body}");
    let still: i64 = sqlx::query_scalar("SELECT (SELECT count(*) FROM server_sources WHERE id = $1) + (SELECT count(*) FROM server_listeners WHERE id = $2)")
        .bind(foreign).bind(foreign_listener).fetch_one(&app.db).await.unwrap();
    assert_eq!(still, 2, "another server's source or listener was removed");
    for (rest, action) in [(format!("/sources/{source_id}"), "source_remove"), (format!("/listeners/{listener_id}"), "listener_remove")] {
        let (st, _, body) = send_json(&app.router, "DELETE", &srv_path(&app, &rest), Some(&admin), Some(serde_json::json!({}))).await;
        assert_eq!(st, StatusCode::OK, "{rest}: {body}");
        let (st, _, body) = send_json(&app.router, "DELETE", &srv_path(&app, &rest), Some(&admin), Some(serde_json::json!({}))).await;
        assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::NOT_FOUND, Some("no_such_item")), "{rest}: {body}");
        assert_eq!(actors_of(&app, action, &target).await, [tag], "{action}: removed once, audited once");
    }
}

#[tokio::test]
async fn api_admin_server_pool_overrides_and_sync() {
    let Some(app) = test_app().await else { return };
    let admin = tagged_admin(&app, "erin").await;
    let alice = api_login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_pool").await;
    let db: Uuid = sqlx::query_scalar("SELECT id FROM databases WHERE name = 'alice_pool'").fetch_one(&app.db).await.unwrap();
    let other = extra_server(&app, "other-srv", true).await;

    let (_, _, cfg) = send_json(&app.router, "GET", &srv_path(&app, "/config"), Some(&admin), None).await;
    assert_eq!(cfg["databases"], serde_json::json!([{"id": db, "name": "alice_pool", "status": "active", "pool_mode": null, "max_connections": null}]), "{cfg}");

    let pool = |sid: Uuid, body: serde_json::Value| {
        let router = app.router.clone();
        let admin = admin.clone();
        async move { send_json(&router, "POST", &format!("/api/v1/admin/servers/{sid}/databases/{db}/pool"), Some(&admin), Some(body)).await }
    };
    for bad in [serde_json::json!({"pool_mode": "statement", "max_connections": null}), serde_json::json!({"pool_mode": "session", "max_connections": 0})] {
        let (st, _, body) = pool(app.server_id, bad).await;
        assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("invalid")), "{body}");
    }
    // The URL's server must own the database.
    let (st, _, body) = pool(other, serde_json::json!({"pool_mode": "session", "max_connections": 3})).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::NOT_FOUND, Some("no_such_item")), "{body}");
    let (st, _, body) = pool(app.server_id, serde_json::json!({"pool_mode": "transaction", "max_connections": 7})).await;
    assert_eq!((st, body["name"].as_str(), body["edge"]["state"].as_str()), (StatusCode::OK, Some("alice_pool"), Some("manual")), "{body}");
    let (mode, max): (Option<String>, Option<i32>) = sqlx::query_as("SELECT pool_mode, max_connections FROM databases WHERE id = $1").bind(db).fetch_one(&app.db).await.unwrap();
    assert_eq!((mode.as_deref(), max), (Some("transaction"), Some(7)));
    assert_eq!(actors_of(&app, "db_pool_override", "alice_pool").await, ["erin [on a password set by admin]"]);
    let (st, _, _) = pool(app.server_id, serde_json::json!({"pool_mode": "inherit", "max_connections": null})).await;
    assert_eq!(st, StatusCode::OK);
    let (mode, max): (Option<String>, Option<i32>) = sqlx::query_as("SELECT pool_mode, max_connections FROM databases WHERE id = $1").bind(db).fetch_one(&app.db).await.unwrap();
    assert_eq!((mode, max), (None, None), "inherit clears the override");

    // Sync: no conf dir, so both files come back for manual placement.
    let (st, _, body) = send_json(&app.router, "POST", &srv_path(&app, "/sync"), Some(&admin), Some(serde_json::json!({}))).await;
    assert_eq!((st, body["edge"]["state"].as_str()), (StatusCode::OK, Some("manual")), "{body}");
    assert!(body["edge"]["hba"].as_str().unwrap().contains("alice_pool"), "{body}");
    assert!(body["edge"]["knobs"].as_str().is_some(), "{body}");
    assert_eq!(actors_of(&app, "edge_sync", &app.server_id.to_string()).await, ["erin [on a password set by admin]"]);
    let (st, _, body) = send_json(&app.router, "POST", &format!("/api/v1/admin/servers/{}/sync", Uuid::new_v4()), Some(&admin), Some(serde_json::json!({}))).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::NOT_FOUND, Some("server_not_found")), "{body}");
}

/// A configuration change that cannot be audited does not happen.
#[tokio::test]
async fn api_admin_server_config_change_that_cannot_be_audited_does_not_happen() {
    let Some(app) = test_app().await else { return };
    let admin = api_login(&app, "admin", "adminpw123").await;
    sqlx::raw_sql(
        "CREATE FUNCTION refuse_audit() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN RAISE EXCEPTION 'audit unavailable'; END $$; \
         CREATE TRIGGER refuse_config_audit BEFORE INSERT ON audit_log FOR EACH ROW \
         WHEN (NEW.action IN ('source_add', 'update_server_pooling')) EXECUTE FUNCTION refuse_audit();",
    ).execute(&app.db).await.unwrap();
    let (st, _, _) = send_json(&app.router, "POST", &srv_path(&app, "/sources"), Some(&admin),
        Some(serde_json::json!({"label": "lan", "cidr": "192.168.8.0/24", "is_default": false}))).await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);
    let (st, _, _) = send_json(&app.router, "POST", &srv_path(&app, "/settings/pooling"), Some(&admin),
        Some(serde_json::json!({"pool_mode": "transaction", "default_pool_size": 25, "max_client_conn": 100, "max_db_connections": 0, "max_user_connections": 0}))).await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);
    let sources: i64 = sqlx::query_scalar("SELECT count(*) FROM server_sources").fetch_one(&app.db).await.unwrap();
    let mode: String = sqlx::query_scalar("SELECT pool_mode FROM managed_servers WHERE id = $1").bind(app.server_id).fetch_one(&app.db).await.unwrap();
    assert_eq!((sources, mode.as_str()), (0, "session"), "an unaudited change was kept");
}

#[tokio::test]
async fn an_unverified_backup_is_not_recorded_as_a_verified_one() {
    let Some(app) = test_app().await else { return };

    // Rows written with verification off, and every row predating the check,
    // must be distinguishable from one that was actually read back — otherwise
    // a green badge means two different things.
    seed_backup(&app, "unchecked", chrono::Duration::hours(1), "ok").await;
    let verified: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "SELECT verified_at FROM backups WHERE db_name = 'unchecked'",
    )
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert!(
        verified.is_none(),
        "a backup nobody read back must not claim to have been verified"
    );

    let rows = cryptarch::backup::history(&app.db, database_for(&app, "unchecked").await).await;
    assert_eq!(rows.len(), 1);
    assert!(rows[0].verified_at.is_none(), "and the UI must see that too");
}

/// CRYPTARCH-86: database names are freed on delete and re-provisionable by
/// ANYONE, so a backup list keyed on the name hands the next holder the
/// previous owner's history — sizes, timestamps and their pg_dump error text.
///
/// Deleting does not hide the backups, it TRANSFERS them: `database_id` is
/// `ON DELETE SET NULL`, so the orphaned rows stop belonging to any tenant and
/// become the operator's.
#[tokio::test]
async fn backup_history_does_not_follow_a_reused_database_name() {
    let Some(app) = test_app().await else { return };

    // alice's database, with a backup whose error names something of hers.
    let alice_db = database_for(&app, "shared_app").await;
    let (_, alice_blob) = seed_backup(&app, "shared_app", chrono::Duration::hours(2), "ok").await;
    sqlx::query("UPDATE backups SET error = 'pg_dump: table alice_salaries' WHERE database_id = $1")
        .bind(alice_db)
        .execute(&app.db)
        .await
        .expect("marking alice's row");

    // PRECONDITION, so "bob sees nothing" cannot pass because nothing exists:
    // the row must be visible to ALICE first.
    let hers = cryptarch::backup::history(&app.db, alice_db).await;
    assert_eq!(hers.len(), 1, "premise: alice can see her own backup");
    assert!(
        hers[0].error.as_deref().is_some_and(|e| e.contains("alice_salaries")),
        "premise: the marker this test looks for is actually rendered for her"
    );

    // alice deletes the database. The name returns to the global pool; the
    // backup row survives with database_id NULLed by the foreign key.
    sqlx::query("DELETE FROM databases WHERE id = $1")
        .bind(alice_db)
        .execute(&app.db)
        .await
        .expect("deleting alice's database");
    let orphaned: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM backups WHERE db_name = 'shared_app' AND database_id IS NULL",
    )
    .fetch_one(&app.db)
    .await
    .expect("counting orphans");
    assert_eq!(orphaned, 1, "premise: her row survived the delete, unlinked");

    // bob takes the freed name. Same string, different database.
    let bob_db = database_for(&app, "shared_app").await;
    assert_ne!(bob_db, alice_db, "premise: re-provisioning is a NEW database");

    let his = cryptarch::backup::history(&app.db, bob_db).await;
    assert!(
        his.is_empty(),
        "bob must not inherit alice's backup history by taking her name — got {} row(s)",
        his.len()
    );

    // And her blob is untouched: the rows became the operator's, not nobody's.
    assert!(alice_blob.exists(), "the operator's copy must still be on disk");
}

/// The same guarantee through the PAGE, with two real tenants.
///
/// The unit test above guards `history()`. The bug was never in `history()`
/// alone — it was authorisation keyed on the live row's identity while
/// RETRIEVAL was keyed on the name, which is a coupling between the handler and
/// the query. A test that calls `history()` directly cannot see that coupling:
/// drop `d.owner_id = $1` from `owned_db_detail` and it still passes. This one
/// fails, because it renders bob's page with bob's session.
#[tokio::test]
async fn a_reused_name_does_not_show_its_new_owner_the_previous_tenants_backups() {
    let Some(app) = test_app().await else { return };
    let alice = login(&app, "alice", "alicepw123").await;
    let bob = login(&app, "bob", "bobpw123").await;

    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/databases", Some(&alice), Some(provision_body(app.server_id, "shared_name", "10.0.0.0/24"))).await;
    assert_eq!(st, StatusCode::CREATED, "premise: alice provisions the name first");

    let alice_db: Uuid = sqlx::query_scalar("SELECT id FROM databases WHERE name = 'shared_name'")
        .fetch_one(&app.db).await.expect("alice's database");
    seed_backup_inner(&app, "shared_name", Some(alice_db), chrono::Duration::hours(2), "ok").await;
    sqlx::query("UPDATE backups SET error = 'pg_dump: table alice_salaries' WHERE database_id = $1")
        .bind(alice_db).execute(&app.db).await.expect("marking alice's row");

    // PRECONDITION: the marker must be in ALICE's history, or "bob cannot see
    // it" is satisfied by it being nowhere at all.
    let (st, _, body) = send_json(&app.router, "GET", "/api/v1/databases/shared_name/backups", Some(&alice), None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.to_string().contains("alice_salaries"), "premise: alice's own history carries the marker: {body}");

    // She deletes it; the name returns to the pool and the FK unlinks her rows.
    sqlx::query("DELETE FROM databases WHERE id = $1")
        .bind(alice_db).execute(&app.db).await.expect("deleting alice's database");

    // Bob — a DIFFERENT user — takes the freed name.
    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/databases", Some(&bob), Some(provision_body(app.server_id, "shared_name", "10.0.0.0/24"))).await;
    assert_eq!(st, StatusCode::CREATED, "premise: the name really is re-provisionable by someone else");
    let bob_owner: Uuid = sqlx::query_scalar(
        "SELECT owner_id FROM databases WHERE name = 'shared_name'",
    ).fetch_one(&app.db).await.expect("bob's database");
    let alice_id: Uuid = sqlx::query_scalar("SELECT id FROM users WHERE username = 'alice'")
        .fetch_one(&app.db).await.unwrap();
    assert_ne!(bob_owner, alice_id, "premise: the new database belongs to a DIFFERENT tenant");

    let (st, _, body) = send_json(&app.router, "GET", "/api/v1/databases/shared_name/backups", Some(&bob), None).await;
    assert_eq!(st, StatusCode::OK, "bob's own history answers: {body}");
    assert_eq!(body["backups"], serde_json::json!([]),
        "bob must not see the previous owner's backup history by taking her name: {body}");
}

// ---- recording a finished backup (CRYPTARCH-85) ------------------------------

/// Insert a `running` row the way `claim` does, and return its id.
async fn seed_running(app: &TestApp, db_name: &str) -> Uuid {
    sqlx::query_scalar("INSERT INTO backups (db_name, status) VALUES ($1, 'running') RETURNING id")
        .bind(db_name)
        .fetch_one(&app.db)
        .await
        .expect("seeding running row")
}

/// The quiet half of CRYPTARCH-85: an UPDATE that matches NO row is `Ok` at the
/// driver — `rows_affected` is 0 and there is no error to log. Testing only for
/// `Err` therefore reports a backup as recorded when nothing was written, and
/// does not even leave a line behind. The count is the claim, not the absence
/// of an error.
#[tokio::test]
async fn recording_a_finished_backup_reports_a_row_that_was_not_there() {
    let Some(app) = test_app().await else { return };

    let outcome = cryptarch::backup::record_success(
        &app.db,
        Uuid::new_v4(), // no such backup
        12,
        "deadbeef",
        "gone/20260721T000000Z-x.dump.zst.enc",
        None,
        "0011223344556677",
    )
    .await;

    let err = outcome.expect_err("recording against a missing row must not report success");
    assert!(
        err.contains("no backup row"),
        "the failure has to name what went wrong, got: {err}"
    );
}

/// The ordinary path still records everything, including the verification
/// timestamp — the guard above must not have been bought by breaking success.
#[tokio::test]
async fn recording_a_finished_backup_marks_the_row_ok() {
    let Some(app) = test_app().await else { return };
    let id = seed_running(&app, "recorded").await;
    let verified = chrono::Utc::now();

    cryptarch::backup::record_success(
        &app.db,
        id,
        4096,
        "cafebabe",
        "recorded/20260721T000000Z-x.dump.zst.enc",
        Some(verified),
        "0011223344556677",
    )
    .await
    .expect("recording a real running row must succeed");

    let (status, size, checksum, path, verified_at) = sqlx::query_as::<
        _,
        (String, Option<i64>, Option<String>, Option<String>, Option<chrono::DateTime<chrono::Utc>>),
    >("SELECT status, size_bytes, checksum, path, verified_at FROM backups WHERE id = $1")
    .bind(id)
    .fetch_one(&app.db)
    .await
    .expect("reading the recorded row");

    assert_eq!(status, "ok");
    assert_eq!(size, Some(4096));
    assert_eq!(checksum.as_deref(), Some("cafebabe"));
    assert_eq!(path.as_deref(), Some("recorded/20260721T000000Z-x.dump.zst.enc"));
    assert!(verified_at.is_some(), "verified_at must survive the round trip");
}

/// A job that outlived `ABANDONED_AFTER` was marked `failed` by the sweep while
/// its task kept running. When it finishes, recording must NOT resurrect the
/// row: matching by id alone would flip it back to 'ok' and — because recording
/// clears `error` — erase the record that the job was ever declared dead. The
/// success would be real, but the claim that nothing went wrong would not.
#[tokio::test]
async fn recording_does_not_resurrect_a_job_the_sweep_already_gave_up_on() {
    let Some(app) = test_app().await else { return };
    let id = seed_running(&app, "overran").await;

    // Exactly what sweep_abandoned writes.
    sqlx::query(
        "UPDATE backups SET status = 'failed', finished_at = now(), \
         error = 'abandoned — no progress within the maximum runtime' WHERE id = $1",
    )
    .bind(id)
    .execute(&app.db)
    .await
    .expect("marking the row abandoned");

    let outcome = cryptarch::backup::record_success(
        &app.db,
        id,
        4096,
        "cafebabe",
        "overran/20260721T000000Z-x.dump.zst.enc",
        None,
        "0011223344556677",
    )
    .await;

    assert!(
        outcome.is_err(),
        "a job the sweep already failed must not be recorded as a success"
    );

    let (status, error) =
        sqlx::query_as::<_, (String, Option<String>)>("SELECT status, error FROM backups WHERE id = $1")
            .bind(id)
            .fetch_one(&app.db)
            .await
            .expect("re-reading the row");
    assert_eq!(status, "failed", "the sweep's verdict stands");
    assert!(
        error.is_some_and(|e| e.contains("abandoned")),
        "and the reason it was given up on must survive"
    );
}

// NOT TESTED HERE, and deliberately not faked: that the unrecorded path emits
// `backup_unrecorded` rather than `backup_ok`, and returns `Outcome::Unrecorded`.
// Both live in `run_job`, which needs a real dump against a real server, and
// `backup_e2e.rs` drives dump/seal/verify directly rather than through the job
// runner. The guarantee is currently STRUCTURAL — `run_job` returns early,
// above the `backup_ok` call — and structural is weaker than tested, because
// the next person to add a step between them will not be stopped by anything.
// Closing it needs the job runner to be drivable end to end, not a test-only
// seam in production code.

// ---- SQL that no test executes ---------------------------------------------

/// Hand every SQL `const` to PostgreSQL and make it parse.
///
/// A `const &str` full of SQL compiles whatever is in it. Query text that no
/// test ever executes has been checked by nobody: `cargo build` and `cargo
/// clippy` are both perfectly happy with a typo, a missing column, or a
/// comment marker that swallows the rest of the statement. This project has
/// been bitten by that exact class twice — an htmx default trigger, and a Rust
/// comment inside a SQL string literal — both of which passed every static
/// check and failed the moment a real request arrived.
///
/// `PANEL_ADMINISTERED_ROLES_SQL` sat unexecuted through two commits while the
/// repair's I/O was still stubbed, including the commit that fixed a real bug
/// in it. This test is what makes "it compiles" and "PostgreSQL accepts it"
/// stop being the same claim.
///
/// It deliberately checks *parsing and binding only*, not semantics. Whether
/// the query returns the right rows is a behavioural question that needs
/// fixtures — for this one, `repair_survey_counts_each_role_once`.
///
/// Note the consts are not interchangeable about *where* they run:
///
/// * [`cryptarch::repair::PANEL_ADMINISTERED_ROLES_SQL`] reads only system
///   catalogs, so it prepares against any Postgres connection.
/// * `cryptarch::edge::AUTH_QUERY` calls `cryptarch.get_auth`, which lives on
///   a *bootstrapped managed server*, not in the metadata database. It cannot
///   be prepared here, and is covered by the server-bootstrap path instead.
///   Listing it here with that reason is the point — a const missing from this
///   test should be a decision, not an oversight.
#[tokio::test]
async fn every_sql_const_parses_against_a_real_server() {
    let Ok(dsn) = std::env::var(TEST_DSN_VAR) else { return };
    let Ok(pool) = sqlx::PgPool::connect(&dsn).await else { return };

    // Each entry carries its OWN binds, so parameter arity travels with the
    // const. A uniform bind list works only while every const takes the same
    // parameters, and the first one that doesn't would fail with a message
    // pointing at the wrong cause.
    let checked: &[(&str, &str, &[&str])] = &[(
        "repair.rs::PANEL_ADMINISTERED_ROLES_SQL",
        cryptarch::repair::PANEL_ADMINISTERED_ROLES_SQL,
        cryptarch::repair::PANEL_OWNED_ROLES,
    )];

    // Consts that read Cryptarch's OWN tables, so they need the *migrated
    // metadata* database rather than the bare admin connection above — the
    // "where they run" distinction this test's doc comment already draws.
    // PREPARE, not query+bind: it asks the server to parse and resolve the
    // statement without needing a value of the right type for every `$n`,
    // which is what "does this SQL survive contact with Postgres" means here.
    let prepared: &[(&str, &str)] = &[
        ("admin_servers.rs::LIST_SERVERS_SQL", cryptarch::admin_servers::LIST_SERVERS_SQL),
        ("admin_servers.rs::ONE_SERVER_SQL", cryptarch::admin_servers::ONE_SERVER_SQL),
    ];

    // Consts that deliberately cannot be prepared here, with the reason.
    let excluded: &[(&str, &str)] = &[
        (
            "edge.rs::AUTH_QUERY",
            "calls cryptarch.get_auth, which lives on a bootstrapped managed \
             server rather than in the metadata database",
        ),
        (
            "engine/postgres.rs::POOL_RESET_SQL",
            "two statements, so Postgres refuses it in a prepared statement — that \
             is the whole reason it goes through raw_sql. Exercised instead by \
             the_pool_reset_statement_executes_against_a_real_server",
        ),
    ];

    for (name, sql, binds) in checked {
        // Bound as a text ARRAY: these queries take a set of names, and binding
        // the elements one at a time would be a different query shape.
        let params: Vec<String> = binds.iter().map(|b| b.to_string()).collect();
        sqlx::query(AssertSqlSafe(*sql)).bind(params).fetch_all(&pool).await.unwrap_or_else(|e| {
            panic!("{name} failed to parse or bind against this server: {e}")
        });
    }

    if !prepared.is_empty() {
        let Some(app) = test_app().await else { return };
        for (name, sql) in prepared {
            use sqlx::{Executor, SqlSafeStr};
            app.db
                .prepare(AssertSqlSafe(*sql).into_sql_str())
                .await
                .unwrap_or_else(|e| panic!("{name} failed to parse against this server: {e}"));
        }
    }

    // The set of things checked must itself be checked. Without this, a const
    // added next week lands in neither list and a test called `every_…` stays
    // green while not covering it — the same disease as a tripwire counted as
    // coverage, one level up.
    //
    // This makes the `_SQL` / `_QUERY` suffix load-bearing: it is how a const
    // announces itself as query text.
    let mut discovered: Vec<String> = Vec::new();
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stack = vec![src.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            // Path relative to src/, NOT file_stem: every `mod.rs` has the same
            // stem, so `web/mod.rs` and `engine/mod.rs` would both produce
            // `mod::FOO_SQL` — a name matching no real Rust path, ambiguous
            // between two files, and satisfiable by a single list entry that is
            // only about one of them.
            let rel = path.strip_prefix(&src).unwrap().to_string_lossy().replace('\\', "/");
            let text = std::fs::read_to_string(&path).unwrap();
            let lines: Vec<&str> = text.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                let line = line.trim_start();
                let Some(rest) = line.strip_prefix("pub const ").or(line.strip_prefix("const "))
                else {
                    continue;
                };
                let Some((ident, tail)) = rest.split_once(':') else { continue };
                let ident = ident.trim();
                if !tail.trim_start().starts_with("&str") {
                    continue;
                }
                let by_name = (ident.ends_with("_SQL") || ident.ends_with("_QUERY"))
                    && ident.chars().all(|c| c.is_ascii_uppercase() || c == '_');
                // Detection by CONTENT as well as by name. Name-based detection
                // only catches people who already know the convention — and
                // someone who knows it is the least likely to forget the list.
                // `const ROLE_LOOKUP: &str = "SELECT …"` must not be invisible
                // just because it was named by someone learning the codebase.
                //
                // The literal is searched PAST the declaration line, because a
                // const long enough to be worth checking is usually written as
                //     const ROLE_LOOKUP: &str =
                //         "SELECT …";
                // Reading only the declaration-line tail put the two detectors'
                // blind spots on top of each other: a const escaped entirely
                // when it was BOTH named outside the `_SQL`/`_QUERY` convention
                // AND had its literal on a later line. That is the exact
                // population `by_content` exists to catch — it is the fallback
                // for authors who don't know the naming rule — so the fallback
                // failed on the people it was for. `SELECT_SERVER` sat in that
                // gap until it became a macro. Where the author put the newline
                // is not information about whether a const is query text.
                let literal = lines[i..]
                    .iter()
                    .take(3)
                    .find_map(|l| l.split_once('"').map(|(_, r)| r))
                    .unwrap_or("")
                    .trim_start();
                let by_content = ["SELECT", "INSERT", "UPDATE", "DELETE", "WITH ", "CREATE"]
                    .iter()
                    .any(|kw| literal.to_ascii_uppercase().starts_with(kw));
                if by_name || by_content {
                    discovered.push(format!("{rel}::{ident}"));
                }
            }
        }
    }
    discovered.sort();
    discovered.dedup();

    for found in &discovered {
        let known = checked.iter().any(|(n, _, _)| n == found)
            || prepared.iter().any(|(n, _)| n == found)
            || excluded.iter().any(|(n, _)| n == found);
        assert!(
            known,
            "{found} looks like SQL that no test hands to PostgreSQL. Either \
             add it to `checked`, or add it to `excluded` with the reason it \
             cannot be prepared here. If it is not query text, the name should \
             not end in _SQL/_QUERY and the literal should not open with a SQL \
             keyword. A const missing from both lists is an oversight, and this \
             test's name claims otherwise."
        );
    }
    assert!(!discovered.is_empty(), "the scanner found nothing — it has stopped working");
}

/// The duplication guarantee the shape tripwire deliberately does not give.
///
/// Every role Cryptarch provisions ends up in `pg_auth_members` **twice**: once
/// from the explicit `GRANT … WITH INHERIT FALSE, SET TRUE` that
/// `create_user_db` issues, and once from the grant PostgreSQL 16+ makes
/// automatically to a `CREATEROLE` creator. The catalog keys on grantor, so
/// those are separate rows with different `admin_option`.
///
/// A join-based query therefore returns each role once per grant. The bug is
/// invisible against a fixture where each role holds one grant — so this
/// fixture builds a role holding **both**, which is what
/// `create_user_db`'s own sequence produces naturally.
///
/// Runs against a real server as a non-superuser `CREATEDB CREATEROLE` role,
/// because the automatic grant only happens for a non-superuser creator.
#[tokio::test]
async fn repair_survey_counts_each_role_once() {
    let Ok(dsn) = std::env::var(TEST_DSN_VAR) else { return };
    let Ok(admin) = sqlx::PgPool::connect(&dsn).await else { return };

    let panel = "t78_panel";
    let tenant = "t78_tenant";
    // Drops the marker too: a previous FAILED run panics before its own
    // cleanup, leaving the marker behind, and the next run would then see the
    // claim already spent and fail for the wrong reason. A test that only
    // cleans up on success is a test that reports the previous failure forever.
    // Reset happens in the constructor, and the repair marker is PRESERVED:
    // roles are cluster-scoped, this test must use the real marker constant to
    // prove the real name is excluded, and the DSN may point at a cluster that
    // is also a live managed server. Dropping it there would un-spend that
    // server's one repair attempt.
    let fixture = ClusterFixture::reset(
        &admin,
        &[
            &format!("DROP ROLE IF EXISTS {tenant};"),
            &format!("DROP ROLE IF EXISTS {panel};"),
            &format!("DROP ROLE IF EXISTS \"{}\";", cryptarch::repair::REPAIR_MARKER_ROLE),
        ],
        &[cryptarch::repair::REPAIR_MARKER_ROLE],
    )
    .await;

    sqlx::raw_sql(AssertSqlSafe(format!(
        "CREATE ROLE {panel} LOGIN PASSWORD 'panelpw' CREATEDB CREATEROLE;"
    )))
    .execute(&admin)
    .await
    .unwrap();

    let panel_dsn = {
        let base = dsn.rsplit_once('@').map(|(_, h)| h).unwrap_or("localhost/postgres");
        format!("postgres://{panel}:panelpw@{base}")
    };
    let Ok(panel_pool) = sqlx::PgPool::connect(&panel_dsn).await else {
        fixture.finish().await;
        return;
    };

    // Exactly what create_user_db does: create, then grant to self. The second
    // statement is the one that produces the *second* pg_auth_members row.
    sqlx::raw_sql(AssertSqlSafe(format!(
        "CREATE ROLE {tenant} LOGIN PASSWORD 'tenantpw'; \
         GRANT {tenant} TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;"
    )))
    .execute(&panel_pool)
    .await
    .unwrap();

    // Precondition: the fixture really does hold two grants. Without this the
    // test could pass by accident on a server that made only one.
    let grants: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_auth_members \
         WHERE roleid = $1::regrole AND member = $2::regrole",
    )
    .bind(tenant)
    .bind(panel)
    .fetch_one(&admin)
    .await
    .unwrap();
    assert_eq!(grants, 2, "fixture must hold BOTH grants or it cannot detect the bug");

    // The query under test, run as the panel role.
    let rows: Vec<(String, bool)> =
        sqlx::query_as(cryptarch::repair::PANEL_ADMINISTERED_ROLES_SQL)
            .bind(cryptarch::repair::PANEL_OWNED_ROLES.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .fetch_all(&panel_pool)
            .await
            .unwrap();

    let seen = rows.iter().filter(|(n, _)| n == tenant).count();
    assert_eq!(seen, 1, "a role holding two grants must appear once, not twice (got {rows:?})");

    // ...and that the exclusion clause actually excludes. Counting the tenant
    // proves rows are not multiplied; it says nothing about `<> ALL($1)`,
    // which would still pass this test if the clause were deleted.
    //
    // The marker is created through the REAL primitive rather than by hand, so
    // this also exercises claim_repair_attempt against a live server — and so
    // that the assertion below is about a role that genuinely exists. Asserting
    // the absence of something never created would be a decorative pass.
    let engine = cryptarch::engine::postgres::PostgresEngine::connect(
        &panel_dsn,
        "localhost".into(),
        5432,
    )
    .await
    .unwrap();
    let won = engine
        .claim_repair_attempt(cryptarch::repair::REPAIR_MARKER_ROLE, "test marker")
        .await
        .unwrap();
    assert!(won, "the marker did not exist, so the claim must be won");
    // And the claim is genuinely one-shot against a real server.
    let again = engine
        .claim_repair_attempt(cryptarch::repair::REPAIR_MARKER_ROLE, "test marker")
        .await
        .unwrap();
    assert!(!again, "a second claim must report the attempt already spent");

    let rows: Vec<(String, bool)> =
        sqlx::query_as(cryptarch::repair::PANEL_ADMINISTERED_ROLES_SQL)
            .bind(
                cryptarch::repair::PANEL_OWNED_ROLES
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>(),
            )
            .fetch_all(&panel_pool)
            .await
            .unwrap();
    assert!(
        rows.iter().any(|(n, _)| n == tenant),
        "sanity: the tenant is still visible, so absence below means excluded \
         rather than nothing being returned at all"
    );
    for owned in cryptarch::repair::PANEL_OWNED_ROLES {
        assert!(
            !rows.iter().any(|(n, _)| n == owned),
            "panel-owned role {owned} must not appear in the survey (got {rows:?})"
        );
    }

    panel_pool.close().await;
    fixture.finish().await;
}

// ---- CRYPTARCH-78 repair, end to end ---------------------------------------

use cryptarch::repair::{self, AttemptOutcome, DisabledCause, RepairOutcome, SurveyCoverage};

/// Put a database into the frozen worklist, as migration 0016 would have.
async fn freeze(app: &TestApp, name: &str) -> Uuid {
    let id: Uuid = sqlx::query_scalar("SELECT id FROM databases WHERE name = $1")
        .bind(name)
        .fetch_one(&app.db)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO repair_worklist_78 (db_id, db_name, server_id) VALUES ($1, $2, $3)",
    )
    .bind(id)
    .bind(name)
    .bind(app.server_id)
    .execute(&app.db)
    .await
    .unwrap();
    sqlx::query("UPDATE databases SET status = 'suspended' WHERE id = $1")
        .bind(id)
        .execute(&app.db)
        .await
        .unwrap();
    id
}

/// The three claim outcomes must drive three different paths.
///
/// This is the test for the defect the whole design is arranged against:
/// `unwrap_or(false)` at the call site would read "could not ask" as "already
/// done" and skip the repair on a server nobody ever reached.
#[tokio::test]
async fn claim_outcomes_do_not_collapse() {
    let Some(app) = test_app().await else { return };
    let alice = login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_r1").await;
    let id = freeze(&app, "alice_r1").await;

    // Could not ask: nothing claimed, nothing repaired, attempt NOT spent.
    app.engine.set_claim(None);
    let out = repair::repair_stranded_logins(&app.db, &app.servers, app.server_id).await.unwrap();
    assert!(matches!(out, AttemptOutcome::CouldNotAsk(_)), "got {out:?}");
    assert!(!app.engine.calls().iter().any(|c| c.starts_with("enable_login")),
            "an unreachable server must not be repaired");
    let status: String = sqlx::query_scalar("SELECT status FROM databases WHERE id = $1")
        .bind(id).fetch_one(&app.db).await.unwrap();
    assert_eq!(status, "suspended", "and its row must be untouched");
    // Recorded for the operator...
    let noted: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM repair_unreachable_78 WHERE server_id = $1")
        .bind(app.server_id).fetch_one(&app.db).await.unwrap();
    assert_eq!(noted, 1);

    // Already spent: distinct from both the above and from a successful walk.
    app.engine.set_claim(Some(false));
    let out = repair::repair_stranded_logins(&app.db, &app.servers, app.server_id).await.unwrap();
    assert_eq!(out, AttemptOutcome::AlreadySpent);
    assert!(!app.engine.calls().iter().any(|c| c.starts_with("enable_login")));

    // Claim won: the worklist is walked and the row settles.
    app.engine.set_claim(Some(true));
    let out = repair::repair_stranded_logins(&app.db, &app.servers, app.server_id).await.unwrap();
    let AttemptOutcome::Walked(records) = out else { panic!("expected Walked, got {out:?}") };
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].outcome, RepairOutcome::Repaired);
    let status: String = sqlx::query_scalar("SELECT status FROM databases WHERE id = $1")
        .bind(id).fetch_one(&app.db).await.unwrap();
    assert_eq!(status, "active", "engine first, row second — and now both agree");
}

/// A worklist entry whose database is gone must not be re-enabled.
///
/// Granting login to a role whose database no longer exists is not a repair —
/// it hands out a credential for nothing.
#[tokio::test]
async fn repair_refuses_when_the_database_is_gone() {
    let Some(app) = test_app().await else { return };
    let alice = login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_r2").await;
    let id = freeze(&app, "alice_r2").await;
    app.engine.set_existing(vec![]); // the server has no such database

    let out = repair::repair_stranded_logins(&app.db, &app.servers, app.server_id).await.unwrap();
    let AttemptOutcome::Walked(records) = out else { panic!("expected Walked") };
    assert_eq!(records[0].outcome, RepairOutcome::DatabaseMissing);
    assert!(!app.engine.calls().iter().any(|c| c.starts_with("enable_login")),
            "no credential for a database that does not exist");

    // The entry is still SETTLED — never silently consumed, never left to be
    // retried forever.
    let outcome: Option<String> = sqlx::query_scalar(
        "SELECT outcome FROM repair_worklist_78 WHERE db_id = $1")
        .bind(id).fetch_one(&app.db).await.unwrap();
    assert_eq!(outcome.as_deref(), Some("database_missing"));
}

/// Tier B: "could not look" must never render as "looked, found nothing".
#[tokio::test]
async fn survey_separates_empty_from_unchecked() {
    let Some(app) = test_app().await else { return };

    // Reachable, genuinely nothing disabled.
    app.engine.set_roles(vec![("alice_ok", true)]);
    let s = repair::survey_disabled_logins(&app.db, &app.servers, app.server_id).await.unwrap();
    assert!(s.coverage.is_conclusive());
    assert!(s.disabled.is_empty());
    assert_eq!(s.coverage, SurveyCoverage::Complete { roles_checked: 1 });
}

/// Tier B classifies from recorded intent, and never reports Cryptarch's own
/// roles — the failure that would make the report permanently noisy.
#[tokio::test]
async fn survey_classifies_and_excludes_our_own_roles() {
    let Some(app) = test_app().await else { return };
    let alice = login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_r3").await;

    app.engine.set_roles(vec![
        ("alice_r3", false),                              // healthy row, disabled
        (cryptarch::repair::REPAIR_MARKER_ROLE, false),    // ours
        (cryptarch::edge::AUTH_ROLE, true),                // ours
        ("stranger", false),                               // no databases row
    ]);

    let s = repair::survey_disabled_logins(&app.db, &app.servers, app.server_id).await.unwrap();

    let names: Vec<&str> = s.disabled.iter().map(|d| d.role_name.as_str()).collect();
    assert!(!names.contains(&cryptarch::repair::REPAIR_MARKER_ROLE),
            "the marker must not report itself, on any server, ever");
    assert!(!s.unknown_to_metadata.iter().any(|r| r == cryptarch::edge::AUTH_ROLE),
            "nor the edge auth role, which has no databases row by design");

    let r3 = s.disabled.iter().find(|d| d.role_name == "alice_r3").unwrap();
    assert_eq!(r3.cause, DisabledCause::DisabledOutsideCryptarch,
               "a healthy row we never disabled is somebody else's doing");

    // A role the panel administers that metadata does not name: the
    // identity-source-is-behind-the-server case. Reported, and NOT attributed.
    assert!(s.unknown_to_metadata.iter().any(|r| r == "stranger"));
    let stranger = s.disabled.iter().find(|d| d.role_name == "stranger").unwrap();
    assert_eq!(stranger.cause, DisabledCause::Unknown);
}

/// C3: the repair is reachable only from the boot that applies its migration.
///
/// This app has no separate upgrade path — `MIGRATOR.run` executes on every
/// boot — so eligibility is defined by observing migration 0016 go from
/// not-applied to applied within one process. A test database has already been
/// fully migrated by the harness, which is exactly the state of an ordinary
/// boot, and the answer there must be "not eligible".
///
/// The failure this guards against is the plausible-looking alternative: run
/// the repair every boot and let the marker stop it. That is unbounded for a
/// server that was never reached, because it has no marker to stop it.
#[tokio::test]
async fn repair_is_not_reachable_from_an_ordinary_boot() {
    let Some(app) = test_app().await else { return };

    // The harness migrated this database, so 0016 is already applied — the
    // condition of every boot after the upgrade.
    assert!(
        cryptarch::repair::repair_migration_applied(&app.db).await,
        "harness should have applied the repair migration"
    );

    // Re-running the migrator is what a normal boot does. It must not produce
    // a transition, because there is none to observe.
    let before = cryptarch::repair::repair_migration_applied(&app.db).await;
    cryptarch::MIGRATOR.run(&app.db).await.unwrap();
    let after = cryptarch::repair::repair_migration_applied(&app.db).await;
    assert!(
        !(!before && after),
        "an ordinary boot must not look like an upgrade boot"
    );

    // And the fact is not stored anywhere a later reader could consult or
    // rewind — eligibility lives in one process's memory and nowhere else.
    let stored: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.columns \
         WHERE table_name = 'managed_servers' AND column_name LIKE '%repair%'",
    )
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(stored, 0, "eligibility must not become a stored flag");
}

/// CRYPTARCH-81 + CRYPTARCH-80: a status the quota predicate has never heard
/// of must still consume a slot.
///
/// The old predicate was `status = 'active'`, so any status added later was
/// silently exempt — and an exempt status is a way to hold a database outside
/// the cap: provision, move it into that status, provision again. This is the
/// bypass CRYPTARCH-80 documents as one commit away, asserted rather than
/// remembered.
#[tokio::test]
async fn a_database_in_any_status_still_consumes_its_quota_slot() {
    let Some(app) = test_app().await else { return };
    let bob = login(&app, "bob", "bobpw123").await; // quota 1

    let (st, _, _) = send_json(&app.router, "POST", "/api/v1/databases", Some(&bob), Some(provision_body(app.server_id, "bob_q1", "10.0.0.0/24"))).await;
    assert_eq!(st, StatusCode::CREATED);

    // Park it in a status the code has never seen. This stands in for every
    // future status — `deleting`, and whatever comes after it.
    sqlx::query("UPDATE databases SET status = 'some_future_state' WHERE name = 'bob_q1'")
        .execute(&app.db)
        .await
        .unwrap();

    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/databases", Some(&bob), Some(provision_body(app.server_id, "bob_q2", "10.0.0.0/24"))).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("quota_reached")),
        "a database in an unrecognised status must still occupy the slot: {body}");

    // And `restoring` specifically, since that one exists today.
    sqlx::query("UPDATE databases SET status = 'restoring' WHERE name = 'bob_q1'")
        .execute(&app.db)
        .await
        .unwrap();
    let (st, _, body) = send_json(&app.router, "POST", "/api/v1/databases", Some(&bob), Some(provision_body(app.server_id, "bob_q3", "10.0.0.0/24"))).await;
    assert_eq!((st, body["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("quota_reached")),
        "a restore must not transiently free its owner's quota slot: {body}");
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM databases WHERE name IN ('bob_q2', 'bob_q3')")
        .fetch_one(&app.db).await.unwrap();
    assert_eq!(rows, 0, "no row was created by either refusal");
}

/// CRYPTARCH-80: a tenant cannot make their own database undeletable.
///
/// Ownership alone is enough to set the template flag, and `WITH (FORCE)` does
/// not help — it terminates sessions and nothing else. Left unhandled the
/// database can never be deleted by anyone, its quota slot is pinned, and
/// restore-replace is permanently blocked.
///
/// Runs against a real server as a NON-SUPERUSER `CREATEDB CREATEROLE` panel
/// role, because the property under test is that the panel recovers without
/// superuser — it exercises the owner's own privilege via `SET ROLE`.
#[tokio::test]
async fn a_tenant_cannot_make_their_database_undeletable() {
    let Ok(dsn) = std::env::var(TEST_DSN_VAR) else { return };
    let Ok(admin) = sqlx::PgPool::connect(&dsn).await else { return };

    let panel = "t80_panel";
    let tenant = "t80_tenant";
    // The template flag must be cleared BEFORE the drop: a previous failed run
    // leaves the database flagged, and `DROP DATABASE IF EXISTS` then fails
    // with "cannot drop a template database" — this test's own subject matter
    // blocking its own fixture.
    let fixture = ClusterFixture::reset(
        &admin,
        &[
            &format!("ALTER DATABASE {tenant} IS_TEMPLATE false;"),
            &format!("DROP DATABASE IF EXISTS {tenant};"),
            &format!("DROP ROLE IF EXISTS {tenant};"),
            &format!("DROP ROLE IF EXISTS {panel};"),
        ],
        &[],
    )
    .await;

    sqlx::raw_sql(AssertSqlSafe(format!(
        "CREATE ROLE {panel} LOGIN PASSWORD 'panelpw' CREATEDB CREATEROLE;"
    )))
    .execute(&admin)
    .await
    .unwrap();

    let base = dsn.rsplit_once('@').map(|(_, h)| h).unwrap_or("localhost/postgres");
    let panel_dsn = format!("postgres://{panel}:panelpw@{base}");
    let Ok(engine) = cryptarch::engine::postgres::PostgresEngine::connect(
        &panel_dsn, "localhost".into(), 5432,
    )
    .await
    else {
        fixture.finish().await;
        return;
    };

    engine.create_user_db(tenant, "tenantpw").await.unwrap();

    // The exploit: the tenant, with ownership and nothing else, flags their
    // own database as a template.
    let tenant_dsn = format!("postgres://{tenant}:tenantpw@{base}");
    let tpool = sqlx::PgPool::connect(&tenant_dsn).await.unwrap();
    sqlx::raw_sql(AssertSqlSafe(format!("ALTER DATABASE {tenant} WITH IS_TEMPLATE true;")))
        .execute(&tpool)
        .await
        .unwrap();
    tpool.close().await;

    let is_template: bool =
        sqlx::query_scalar("SELECT datistemplate FROM pg_database WHERE datname = $1")
            .bind(tenant)
            .fetch_one(&admin)
            .await
            .unwrap();
    assert!(is_template, "fixture must actually set the flag or it proves nothing");

    // The delete must succeed anyway.
    engine
        .drop_user_db(tenant)
        .await
        .expect("a tenant must not be able to block their own deletion");

    let db_gone: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_database WHERE datname = $1")
        .bind(tenant)
        .fetch_one(&admin)
        .await
        .unwrap();
    assert_eq!(db_gone, 0, "database still present after delete");
    let role_gone: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_roles WHERE rolname = $1")
        .bind(tenant)
        .fetch_one(&admin)
        .await
        .unwrap();
    assert_eq!(role_gone, 0, "role still present after delete");

    fixture.finish().await;
}

/// CRYPTARCH-79: a delete that fails partway must not leave a usable credential.
///
/// The database is dropped WITH (FORCE), so a surviving role protects nothing
/// — the only thing it can still do is authenticate. Login is therefore
/// disabled FIRST, before anything destructive.
#[tokio::test]
async fn a_failed_delete_leaves_no_usable_credential() {
    let Ok(dsn) = std::env::var(TEST_DSN_VAR) else { return };
    let Ok(admin) = sqlx::PgPool::connect(&dsn).await else { return };

    let panel = "t79_panel";
    let tenant = "t79_tenant";
    // Includes the dependent objects the partial-failure case creates below —
    // the fixture must name everything the test can produce, not just what it
    // deliberately creates.
    let fixture = ClusterFixture::reset(
        &admin,
        &[
            &format!("DROP DATABASE IF EXISTS {tenant}_held;"),
            &format!("DROP DATABASE IF EXISTS {tenant};"),
            &format!("DROP ROLE IF EXISTS {tenant}_dep;"),
            &format!("DROP ROLE IF EXISTS {tenant};"),
            &format!("DROP ROLE IF EXISTS {panel};"),
        ],
        &[],
    )
    .await;

    sqlx::raw_sql(AssertSqlSafe(format!(
        "CREATE ROLE {panel} LOGIN PASSWORD 'panelpw' CREATEDB CREATEROLE;"
    )))
    .execute(&admin)
    .await
    .unwrap();

    let base = dsn.rsplit_once('@').map(|(_, h)| h).unwrap_or("localhost/postgres");
    let panel_dsn = format!("postgres://{panel}:panelpw@{base}");
    let Ok(engine) = cryptarch::engine::postgres::PostgresEngine::connect(
        &panel_dsn, "localhost".into(), 5432,
    )
    .await
    else {
        fixture.finish().await;
        return;
    };

    engine.create_user_db(tenant, "tenantpw").await.unwrap();
    // The credential works to begin with — otherwise the assertion below
    // passes for the wrong reason.
    let tenant_dsn = format!("postgres://{tenant}:tenantpw@{base}");
    assert!(
        sqlx::PgPool::connect(&tenant_dsn).await.is_ok(),
        "fixture credential must work before the delete"
    );

    // Force the delete to fail AFTER the NOLOGIN step: a prepared-transaction-
    // free way to break DROP DATABASE is to hold a second database of the same
    // owner open... simpler and deterministic: drop the role's database out
    // from under it, then ask the engine to delete, which fails at DROP ROLE
    // only if the role is gone too. Instead assert the ordering directly: the
    // role must be NOLOGIN the moment the database is gone.
    engine.drop_user_db(tenant).await.unwrap();

    // Full success leaves nothing behind at all.
    let role_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_roles WHERE rolname = $1")
        .bind(tenant)
        .fetch_one(&admin)
        .await
        .unwrap();
    assert_eq!(role_rows, 0);

    // Now the partial case: recreate, then make DROP ROLE fail by having
    // another role depend on it, so the delete aborts after NOLOGIN.
    engine.create_user_db(tenant, "tenantpw").await.unwrap();
    sqlx::raw_sql(AssertSqlSafe(format!("CREATE ROLE {tenant}_dep; GRANT {tenant} TO {tenant}_dep;")))
        .execute(&admin)
        .await
        .unwrap();
    sqlx::raw_sql(AssertSqlSafe(format!("CREATE DATABASE {tenant}_held OWNER {tenant};")))
        .execute(&admin)
        .await
        .unwrap();

    let failed = engine.drop_user_db(tenant).await;
    assert!(failed.is_err(), "delete should have failed on the dependent object");

    // THE POINT: the credential must be dead even though the delete failed.
    let can_still_log_in = sqlx::PgPool::connect(&tenant_dsn).await.is_ok();
    assert!(
        !can_still_log_in,
        "a failed delete left a working credential for a deleted tenant"
    );

    fixture.finish().await;
}

/// CRYPTARCH-83: a connection cannot re-enter the pool still `SET ROLE`'d.
///
/// Uses `max_connections(1)` so release-then-acquire is guaranteed to hand
/// back the SAME connection — with a larger pool the test could draw a fresh
/// one and pass without exercising the hook at all.
///
/// The second assertion is the one that matters as much as the first: it
/// catches `DISCARD ALL`, which would also clear the role but deallocates
/// prepared statements behind sqlx's per-connection cache, so a later query on
/// a REUSED connection fails with "prepared statement does not exist". A
/// fresh-connection test passes cleanly; production does not.
#[tokio::test]
async fn a_released_connection_cannot_keep_a_set_role() {
    let Ok(dsn) = std::env::var(TEST_DSN_VAR) else { return };
    let Ok(admin) = sqlx::PgPool::connect(&dsn).await else { return };
    let role = "t83_role";
    let fixture =
        ClusterFixture::reset(&admin, &[&format!("DROP ROLE IF EXISTS {role};")], &[]).await;
    sqlx::raw_sql(AssertSqlSafe(format!("CREATE ROLE {role};"))).execute(&admin).await.unwrap();

    let Ok(pool) = cryptarch::engine::postgres::PostgresEngine::pool_options()
        .max_connections(1)
        .connect(&dsn)
        .await
    else {
        fixture.finish().await;
        return;
    };

    // Prepare a statement on this connection first, so the cache is populated
    // before the reset runs. Without this the DISCARD ALL failure mode cannot
    // reproduce, and the test would pass either way.
    let session_role: String = sqlx::query_scalar("SELECT current_role::text")
        .fetch_one(&pool)
        .await
        .unwrap();
    let panel_role = session_role.clone();

    let dirtied_pid: i32 = {
        let mut conn = pool.acquire().await.unwrap();
        sqlx::query(AssertSqlSafe(format!("SET ROLE {role}"))).execute(&mut *conn).await.unwrap();
        let now: String = sqlx::query_scalar("SELECT current_role::text")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(now, role, "fixture must actually change the role");
        sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *conn).await.unwrap()
    }; // released here
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // THE PRECONDITION THIS TEST SPENT ITS LIFE WITHOUT.
    //
    // There are two ways the assertion below can come out clean: the connection
    // was scrubbed and handed back, or it was RETIRED and this is a brand new
    // backend that was never dirtied. Only the first is the behaviour under
    // test — and for years only the second was happening, because the reset
    // statement was failing and the handler retires on failure. The test could
    // not tell the difference, so it reported a mechanism that was not running.
    //
    // Pinning the backend pid is what makes "the role was cleared" mean "the
    // role was cleared ON THIS CONNECTION".
    assert_eq!(
        pool.num_idle(),
        1,
        "the pool retired the connection instead of scrubbing it, so the assertion below \
         would pass without the scrub ever running"
    );

    // Same connection, because the pool holds exactly one.
    let mut conn = pool.acquire().await.unwrap();
    let same_pid: i32 =
        sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *conn).await.unwrap();
    assert_eq!(
        same_pid, dirtied_pid,
        "a different backend answered, so this is not the connection that was SET ROLE'd"
    );
    let after: String = sqlx::query_scalar("SELECT current_role::text")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    assert_eq!(
        after, panel_role,
        "a connection returned to the pool while SET ROLE'd would run later admin \
         work as the wrong role, intermittently"
    );

    // ...and it must still WORK. This is the DISCARD ALL detector: the query
    // above was prepared earlier, so a cache invalidated behind sqlx's back
    // fails right here.
    let reused: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_roles WHERE rolname = $1")
        .bind(role)
        .fetch_one(&pool)
        .await
        .expect("the connection must still be usable after the reset");
    assert_eq!(reused, 1);

    pool.close().await;
    fixture.finish().await;
}

/// CRYPTARCH-80: a delete that failed before changing anything must be undone,
/// so the database rejoins the backup schedule without a human.
///
/// The dangerous case is not the one that looks dangerous. A failure at the
/// FIRST step destroys nothing — but the row already reads `deleting`, and the
/// backup scheduler selects by status, so a fully working database has quietly
/// stopped being protected. It is invisible to the login report too, because
/// its role is still enabled.
#[tokio::test]
async fn a_delete_that_changed_nothing_is_reverted_and_backups_resume() {
    let Some(app) = test_app().await else { return };
    let alice = login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_sd").await;

    // Strand it exactly as a first-step failure would: intent recorded, and
    // nothing done on the server.
    sqlx::query("UPDATE databases SET status = 'deleting' WHERE name = 'alice_sd'")
        .execute(&app.db)
        .await
        .unwrap();

    // While stranded it is NOT a backup target — which is the harm.
    let targets = cryptarch::backup::scheduled_target_names(&app.db).await;
    assert!(!targets.contains(&"alice_sd".to_string()),
            "precondition: a deleting row is out of the schedule");

    // The server says: role can log in, database present. Nothing happened.
    app.engine.set_roles(vec![("alice_sd", true)]);
    app.engine.set_existing(vec!["alice_sd"]);

    let reverted = cryptarch::repair::sweep_stranded_deletes(&app.db, &app.servers)
        .await
        .unwrap();
    assert_eq!(reverted, 1);

    let status: String =
        sqlx::query_scalar("SELECT status FROM databases WHERE name = 'alice_sd'")
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert_eq!(status, "active", "a delete that changed nothing must be undone");

    // The point of the revert: it is protected again.
    let targets = cryptarch::backup::scheduled_target_names(&app.db).await;
    assert!(targets.contains(&"alice_sd".to_string()),
            "the database must rejoin the backup schedule");

    // Audited WITH the reason — two bare status flips read as the system
    // arguing with itself.
    let detail: Option<String> = sqlx::query_scalar(
        "SELECT detail FROM audit_log WHERE action = 'delete_reverted' AND target = 'alice_sd'",
    )
    .fetch_optional(&app.db)
    .await
    .unwrap()
    .flatten();
    assert!(detail.is_some(), "the revert must be audited");
    assert!(detail.unwrap().contains("failed before anything was changed"));
}

/// The other half: once destruction has begun, the sweep must NOT undo it.
#[tokio::test]
async fn a_partly_completed_delete_is_left_for_the_operator() {
    let Some(app) = test_app().await else { return };
    let alice = login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_sd2").await;
    sqlx::query("UPDATE databases SET status = 'deleting' WHERE name = 'alice_sd2'")
        .execute(&app.db)
        .await
        .unwrap();

    // Login already disabled: a later step failed, so destruction began.
    app.engine.set_roles(vec![("alice_sd2", false)]);
    app.engine.set_existing(vec!["alice_sd2"]);

    let reverted = cryptarch::repair::sweep_stranded_deletes(&app.db, &app.servers)
        .await
        .unwrap();
    assert_eq!(reverted, 0, "a delete that got past its first step must not be undone");

    let status: String =
        sqlx::query_scalar("SELECT status FROM databases WHERE name = 'alice_sd2'")
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert_eq!(status, "deleting");
}

/// CRYPTARCH-80: the stranded-delete sweep must not be gated on backups.
///
/// It lives on the backup scheduler's pass because a periodic loop already
/// existed there — a good reason to write it there, and a bad reason for its
/// liveness to depend on backups being enabled. Two supported configurations
/// switch backups off (`CRYPTARCH_BACKUP_DIR` unset; `interval_secs = 0` with
/// backups driven by external cron), and in both the sweep must still run, or
/// a delete that failed at its first step strands a live database permanently
/// rather than for one interval.
#[tokio::test]
async fn maintenance_runs_when_backups_are_off() {
    let Some(app) = test_app().await else { return };
    let alice = login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_mt").await;
    sqlx::query("UPDATE databases SET status = 'deleting' WHERE name = 'alice_mt'")
        .execute(&app.db)
        .await
        .unwrap();
    app.engine.set_roles(vec![("alice_mt", true)]);
    app.engine.set_existing(vec!["alice_mt"]);

    // Backups explicitly OFF for this pass — the externally-driven cron case.
    let schedule = cryptarch::backup::Schedule {
        interval_secs: cryptarch::backup::MAINTENANCE_INTERVAL_SECS,
        keep: 0,
        stale_after_secs: 0,
        backups_enabled: false,
    };
    let notifier = cryptarch::health::Notifier::from_config(None, "json");
    let mut alerted = std::collections::HashSet::new();
    cryptarch::backup::run_one_pass(&test_state(&app), schedule, &notifier, &mut alerted).await;

    let status: String =
        sqlx::query_scalar("SELECT status FROM databases WHERE name = 'alice_mt'")
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert_eq!(
        status, "active",
        "the sweep must run even when this pass does no backup work"
    );
}

/// CRYPTARCH-80: the retry re-checks at ACTION time, not render time.
///
/// The report decides what to offer from `can_log_in && db_exists`. That
/// decision goes stale: between an operator loading a page whose purpose is to
/// be read slowly and their click, the maintenance sweep can return the row to
/// service. Acting on what the page saw would destroy a live, healthy,
/// tenant-serving database that the system declared fine seconds earlier.
#[tokio::test]
async fn a_retry_refuses_a_database_that_was_never_actually_deleted() {
    let Some(app) = test_app().await else { return };
    let alice = login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_rt").await;
    sqlx::query("UPDATE databases SET status = 'deleting' WHERE name = 'alice_rt'")
        .execute(&app.db)
        .await
        .unwrap();

    // The server says: nothing happened. Login enabled, database present.
    app.engine.set_roles(vec![("alice_rt", true)]);
    app.engine.set_existing(vec!["alice_rt"]);

    let lookup = cryptarch::provision::find_db(&app.db, "alice_rt").await.unwrap().unwrap();
    let out = cryptarch::provision::retry_delete(
        &app.db, &app.servers, &lookup, "alice_rt", "admin",
    )
    .await
    .unwrap();
    assert!(
        matches!(out, Err(cryptarch::provision::RetryRefusal::NothingWasStarted)),
        "must refuse to complete a delete that never started"
    );
    assert!(!app.engine.calls().iter().any(|c| c.starts_with("drop:")),
            "nothing may be dropped");
    let still_there: i64 =
        sqlx::query_scalar("SELECT count(*) FROM databases WHERE name = 'alice_rt'")
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert_eq!(still_there, 1, "the row must survive");

    // The stale-render race: the row was reverted after the page rendered.
    sqlx::query("UPDATE databases SET status = 'active' WHERE name = 'alice_rt'")
        .execute(&app.db)
        .await
        .unwrap();
    let stale = cryptarch::provision::find_db(&app.db, "alice_rt").await.unwrap().unwrap();
    let out = cryptarch::provision::retry_delete(
        &app.db, &app.servers, &stale, "alice_rt", "admin",
    )
    .await
    .unwrap();
    assert!(
        matches!(out, Err(cryptarch::provision::RetryRefusal::NoLongerDeleting)),
        "a row the sweep already reverted must not be finished off"
    );

    // And the safe case still works: destruction began, so finishing is right.
    sqlx::query("UPDATE databases SET status = 'deleting' WHERE name = 'alice_rt'")
        .execute(&app.db)
        .await
        .unwrap();
    app.engine.set_roles(vec![("alice_rt", false)]);
    let lookup = cryptarch::provision::find_db(&app.db, "alice_rt").await.unwrap().unwrap();
    let out = cryptarch::provision::retry_delete(
        &app.db, &app.servers, &lookup, "alice_rt", "admin",
    )
    .await
    .unwrap();
    assert!(out.is_ok(), "a genuinely half-deleted database must be finishable");
    let gone: i64 = sqlx::query_scalar("SELECT count(*) FROM databases WHERE name = 'alice_rt'")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(gone, 0);
}

/// CRYPTARCH-80: a human obligation that nobody discharges must eventually
/// shout, not merely sit on a page.
///
/// Nothing retries a failed delete automatically, and that is deliberate — but
/// "nothing automatic does it" also means "nothing guarantees anything ever
/// does". A requested deletion waiting on an admin who never opens the report
/// waits forever, and the data someone asked to be destroyed persists.
#[tokio::test]
async fn an_unfinished_delete_eventually_raises_an_alert() {
    let Some(app) = test_app().await else { return };
    let alice = login(&app, "alice", "alicepw123").await;
    api_provision(&app, &alice, "alice_ob").await;

    // Stranded, but only just: nothing should fire yet.
    sqlx::query(
        "UPDATE databases SET status = 'deleting', status_changed_at = now() \
         WHERE name = 'alice_ob'",
    )
    .execute(&app.db)
    .await
    .unwrap();
    let fresh = cryptarch::repair::outstanding_work(&app.db, 3600).await;
    assert!(fresh.is_empty(), "a delete that just failed is not yet an obligation");

    // Now aged past the threshold.
    sqlx::query(
        "UPDATE databases SET status_changed_at = now() - interval '2 days' \
         WHERE name = 'alice_ob'",
    )
    .execute(&app.db)
    .await
    .unwrap();
    let aged = cryptarch::repair::outstanding_work(&app.db, 3600).await;
    assert_eq!(aged.len(), 1, "an aged unfinished delete must surface");
    assert!(aged[0].what.contains("alice_ob"));
    assert!(aged[0].age_secs > 3600);

    // Threshold of 0 disables it, like the staleness check it mirrors.
    assert!(cryptarch::repair::outstanding_work(&app.db, 0).await.is_empty());

    // And it stops once discharged.
    sqlx::query("UPDATE databases SET status = 'active' WHERE name = 'alice_ob'")
        .execute(&app.db)
        .await
        .unwrap();
    assert!(cryptarch::repair::outstanding_work(&app.db, 3600).await.is_empty(),
            "a discharged obligation must stop being reported");
}

// ---- CRYPTARCH-85 / W1: the unrecorded path, driven through run_job ----------

/// The guarantee CRYPTARCH-85 exists for, tested behaviourally rather than left
/// structural: when the recording write fails, the job runner must audit
/// `backup_unrecorded` and must NOT audit `backup_ok`.
///
/// # Why this is reachable after all
///
/// The commit says `run_job` "needs a real dump to drive". True — but the dump
/// rides an engine taken from `state.servers` (`backup.rs:864-874`), NOT from
/// the DSN stored on the `managed_servers` row. So registering a real
/// `PostgresEngine` under the fixture's `server_id` makes the whole runner
/// drivable, with no seam added to production code.
///
/// The fault is injected into the **test's own throwaway metadata database**: a
/// trigger that rejects exactly the UPDATE which sets `status='ok'`. That is
/// surgical — the job log's own appends (`backup.rs:337-359`) and the audit
/// INSERT both still work, which is what makes the audit assertion meaningful
/// rather than vacuous. Nothing in `src/` knows this test exists.
#[tokio::test]
async fn an_unrecorded_backup_is_never_audited_as_a_successful_one() {
    let Ok(admin_dsn) = std::env::var(TEST_DSN_VAR) else {
        eprintln!("skipping: {TEST_DSN_VAR} not set");
        return;
    };
    if tokio::process::Command::new("pg_dump").arg("--version").output().await.is_err() {
        eprintln!("skipping: pg_dump not installed");
        return;
    }
    // Verification is mandatory now, so every real backup shells out to
    // pg_restore too — a machine with only pg_dump would fail here rather than
    // skip, and that would look like a bug in the code under test.
    if tokio::process::Command::new("pg_restore").arg("--version").output().await.is_err() {
        eprintln!("skipping: pg_restore not installed (verification needs it)");
        return;
    }
    let Some(app) = test_app().await else { return };
    let state = test_state(&app);

    // A real engine in place of the double, so `run_job` takes a real dump.
    let engine = cryptarch::engine::postgres::PostgresEngine::connect(
        &admin_dsn,
        "localhost".into(),
        5432,
    )
    .await
    .expect("connecting to the test server");
    app_registry_register(&app, Arc::new(engine));
    let engine = app.servers.get(app.server_id).expect("engine registered");

    // A real database on the cluster, unique per run and dropped on every path
    // below — this cluster is also a managed server (see ClusterFixture).
    let name = format!("unrec_{}", &Uuid::new_v4().simple().to_string()[..12]);
    engine.create_user_db(&name, "e2e_test_password_not_a_secret").await
        .expect("provisioning the source database");

    let outcome = unrecorded_scenario(&app, &state, &name).await;

    let _ = engine.drop_user_db(&name).await;
    outcome.expect("the unrecorded-backup scenario");
}

/// Drive a real backup to `Outcome::Unrecorded` and leave the wreckage in
/// place: a `running` row with NULL `path`, and a sealed blob on disk that
/// nothing names.
///
/// Extracted so the retention test below starts from the state production
/// actually produces. Fabricating the NULL directly would assert against an
/// invented state — the same objection the `seed_orphan_backup` note records.
async fn induce_unrecorded_backup(
    app: &TestApp,
    state: &AppState,
    name: &str,
) -> anyhow::Result<()> {
    let owner: Uuid = sqlx::query_scalar("SELECT id FROM users WHERE username = 'alice'")
        .fetch_one(&app.db).await?;
    sqlx::query(
        "INSERT INTO databases (owner_id, server_id, name, password_hash, status) \
         VALUES ($1, $2, $3, 'not-a-real-hash', 'active')",
    )
    .bind(owner)
    .bind(app.server_id)
    .bind(name)
    .execute(&app.db)
    .await?;

    // The fault. Fires ONLY on the recording UPDATE (`status` -> 'ok'), so the
    // log appends and the audit write are left working.
    sqlx::raw_sql(
        "CREATE FUNCTION reject_recording() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN RAISE EXCEPTION 'injected: the metadata write failed'; END $$; \
         CREATE TRIGGER reject_recording BEFORE UPDATE ON backups FOR EACH ROW \
         WHEN (NEW.status = 'ok') EXECUTE FUNCTION reject_recording();",
    )
    .execute(&app.db)
    .await?;

    let outcome = cryptarch::backup::run_now(state, "system", name).await
        .map_err(|e| anyhow::anyhow!("the backup could not even start: {e}"))?;

    // Precondition, not the claim: if the dump itself failed we are testing the
    // wrong path, and every assertion below would pass for the wrong reason.
    match &outcome {
        cryptarch::backup::Outcome::Unrecorded { .. } => {}
        cryptarch::backup::Outcome::Failed { error } => anyhow::bail!(
            "the dump failed, so the recording path was never reached — this test proves \
             nothing in that state: {error}"
        ),
        cryptarch::backup::Outcome::Ok { .. } => anyhow::bail!(
            "CRYPTARCH-85: the recording write was rejected, yet the runner reported Ok"
        ),
    }
    Ok(())
}

async fn unrecorded_scenario(
    app: &TestApp,
    state: &AppState,
    name: &str,
) -> anyhow::Result<()> {
    induce_unrecorded_backup(app, state, name).await?;

    // THE CLAIM: the audit trail must not contain an invented success.
    let ok_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE action = 'backup_ok' AND target = $1",
    )
    .bind(name).fetch_one(&app.db).await?;
    anyhow::ensure!(
        ok_rows == 0,
        "CRYPTARCH-85: audit_log claims backup_ok for a backup whose row was never recorded"
    );

    let unrecorded_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE action = 'backup_unrecorded' AND target = $1",
    )
    .bind(name).fetch_one(&app.db).await?;
    anyhow::ensure!(
        unrecorded_rows == 1,
        "the incident record must SAY the backup was not recorded, got {unrecorded_rows} rows"
    );

    // C13: the row is left `running` (it is the lock; sweep_abandoned owns it)
    // and the blob is kept.
    let (status, path): (String, Option<String>) =
        sqlx::query_as("SELECT status, path FROM backups WHERE db_name = $1")
            .bind(name).fetch_one(&app.db).await?;
    anyhow::ensure!(status == "running", "the row is left running, got '{status}'");

    let blobs: Vec<_> = std::fs::read_dir(app.backup_dir.join(name))
        .map(|d| d.flatten().collect())
        .unwrap_or_default();
    anyhow::ensure!(blobs.len() == 1, "the sealed blob is kept, found {}", blobs.len());

    // NOTHING NAMES THAT BLOB. `path` is written only by `record_success`,
    // which is the call that just failed, so the surviving row cannot say where
    // its file is. That much is still true and is asserted here.
    //
    // What USED to follow from it was CRYPTARCH-87: once the row was marked
    // `failed`, retention deleted it while `prune` only unlinked a file when
    // the row carried a path — so the blob outlived every record that could
    // locate it. That no longer holds; `prune` now resolves the file through
    // `locate_blob`, and the test below drives exactly that sequence. The two
    // assertions are deliberately separate: this one pins the *cause* (no path
    // is recorded), the other pins that the cause no longer leaks.
    anyhow::ensure!(
        path.is_none(),
        "the surviving row has no path — the precondition CRYPTARCH-87 was about"
    );
    Ok(())
}

/// CRYPTARCH-87: the blob an unrecorded backup leaves behind is reclaimed by
/// retention, rather than outliving the row that was its only trace.
///
/// `path` is NULL on that row, and prune used to read a NULL as "there is no
/// file". It deleted the row and left a full-size encrypted dump on the mount:
/// unreferenced, unlistable, invisible in the portal, and removable only by
/// someone with shell access. Every unrecorded backup leaked exactly one.
///
/// The sequence is the real one end to end — a real dump driven to
/// `Unrecorded` by the injected fault, then `sweep_abandoned`, then `prune` —
/// because the bug lived in how those three steps composed, not in any of them
/// alone. Each was individually correct.
#[tokio::test]
async fn retention_reclaims_the_blob_an_unrecorded_backup_left_behind() {
    let Ok(admin_dsn) = std::env::var(TEST_DSN_VAR) else {
        eprintln!("skipping: {TEST_DSN_VAR} not set");
        return;
    };
    for tool in ["pg_dump", "pg_restore"] {
        if tokio::process::Command::new(tool).arg("--version").output().await.is_err() {
            eprintln!("skipping: {tool} not installed");
            return;
        }
    }
    let Some(app) = test_app().await else { return };
    let state = test_state(&app);

    let engine = cryptarch::engine::postgres::PostgresEngine::connect(
        &admin_dsn,
        "localhost".into(),
        5432,
    )
    .await
    .expect("connecting to the test server");
    app_registry_register(&app, Arc::new(engine));
    let engine = app.servers.get(app.server_id).expect("engine registered");

    let name = format!("leak_{}", &Uuid::new_v4().simple().to_string()[..12]);
    engine.create_user_db(&name, "e2e_test_password_not_a_secret").await
        .expect("provisioning the source database");

    let outcome = reclaim_scenario(&app, &state, &name).await;

    let _ = engine.drop_user_db(&name).await;
    outcome.expect("the leaked-blob reclaim scenario");
}

async fn reclaim_scenario(app: &TestApp, state: &AppState, name: &str) -> anyhow::Result<()> {
    induce_unrecorded_backup(app, state, name).await?;

    // === PRECONDITIONS ===
    // Everything below asserts a file is GONE, which passes for free if the
    // file was never there. So prove it IS there, and that the row really is
    // the pathless kind this test is about, before touching retention.
    let (id, path): (Uuid, Option<String>) =
        sqlx::query_as("SELECT id, path FROM backups WHERE db_name = $1")
            .bind(name).fetch_one(&app.db).await?;
    anyhow::ensure!(
        path.is_none(),
        "the row carries a path, so this is not the CRYPTARCH-87 shape at all"
    );

    let dir = app.backup_dir.join(name);
    let leaked: Vec<_> = std::fs::read_dir(&dir)
        .map(|d| d.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    anyhow::ensure!(
        leaked.len() == 1,
        "expected exactly one sealed blob on disk before retention, found {}",
        leaked.len()
    );
    let leaked = leaked.into_iter().next().unwrap();
    anyhow::ensure!(
        leaked.file_name().unwrap().to_string_lossy().contains(&id.to_string()),
        "the blob on disk does not carry this backup's id, so locate_blob could not \
         match it and the test would be measuring the wrong file"
    );

    // Age the row past the abandoned threshold, and give the database TWO
    // newer good backups.
    //
    // Both numbers are forced by rules this test is not about. Retention ranks
    // within a database, so with no survivor the lone row is rn=1 and never
    // prunable. And CRYPTARCH-82 FREEZES a database sitting on exactly one
    // restorable backup — one survivor would protect the whole partition,
    // including this row, and the test would fail for a reason that is correct
    // behaviour. Two survivors clear the floor and leave the pathless row as
    // the only thing retention should touch.
    sqlx::query("UPDATE backups SET created_at = now() - interval '10 days' WHERE id = $1")
        .bind(id).execute(&app.db).await?;
    let (_, keeper_blob) = seed_backup(app, name, chrono::Duration::days(1), "ok").await;
    let (_, keeper_blob_2) = seed_backup(app, name, chrono::Duration::days(2), "ok").await;

    let swept = cryptarch::backup::sweep_abandoned(&app.db).await?;
    anyhow::ensure!(swept == 1, "expected the stranded row to be swept to failed, got {swept}");

    // === THE CLAIM ===
    let pruned = cryptarch::backup::prune(state, 2).await?;
    anyhow::ensure!(pruned == 1, "expected the pathless row to be pruned, got {pruned}");

    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM backups WHERE id = $1")
        .bind(id).fetch_one(&app.db).await?;
    anyhow::ensure!(rows == 0, "the pruned row is still present");

    anyhow::ensure!(
        !leaked.exists(),
        "CRYPTARCH-87: retention deleted the row but left {} on disk — a full-size dump \
         with nothing left pointing at it",
        leaked.display()
    );

    // The pass must not have been indiscriminate: the good backup it was
    // ranked against is still here. Without this, deleting the whole directory
    // would satisfy every assertion above.
    anyhow::ensure!(
        keeper_blob.exists() && keeper_blob_2.exists(),
        "retention reclaimed the leaked blob but also destroyed a kept backup"
    );
    Ok(())
}

/// D4 probe (crypt-2): the `verified_at IS NULL OR status = 'ok'` constraint,
/// exercised in the ONE direction that matters — a real backup, verification
/// ON, recorded through `record_success`.
///
/// This test exists because of how nearly its evidence was faked. When
/// verification was optional, every test-state constructor turned it OFF, so
/// nothing in the suite wrote `verified_at` through the production path and a
/// green suite with the constraint live proved only that nothing had exercised
/// it. Verification is now mandatory, which makes that trap harder to fall
/// into — but "the flag is gone so it must be covered" is the same reasoning
/// that was wrong the first time, so the direct check stays.
#[tokio::test]
async fn a_verified_backup_satisfies_the_verified_implies_ok_constraint() {
    let Ok(admin_dsn) = std::env::var(TEST_DSN_VAR) else { return };
    if tokio::process::Command::new("pg_dump").arg("--version").output().await.is_err() {
        eprintln!("skipping: pg_dump not installed");
        return;
    }
    if tokio::process::Command::new("pg_restore").arg("--version").output().await.is_err() {
        eprintln!("skipping: pg_restore not installed (verification needs it)");
        return;
    }
    let Some(app) = test_app().await else { return };
    // The whole point of the probe: verification ON, so `verified_at` is
    // actually written by the production path.
    let state = test_state(&app);

    let engine = cryptarch::engine::postgres::PostgresEngine::connect(
        &admin_dsn, "localhost".into(), 5432,
    ).await.expect("connecting to the test server");
    app_registry_register(&app, Arc::new(engine));
    let engine = app.servers.get(app.server_id).expect("engine registered");

    let name = format!("vrfy_{}", &Uuid::new_v4().simple().to_string()[..12]);
    engine.create_user_db(&name, "e2e_test_password_not_a_secret").await
        .expect("provisioning the source database");

    let result = verified_scenario(&app, &state, &name).await;
    let _ = engine.drop_user_db(&name).await;
    result.expect("the verified-backup scenario");
}

async fn verified_scenario(app: &TestApp, state: &AppState, name: &str) -> anyhow::Result<()> {
    let owner: Uuid = sqlx::query_scalar("SELECT id FROM users WHERE username = 'alice'")
        .fetch_one(&app.db).await?;
    sqlx::query(
        "INSERT INTO databases (owner_id, server_id, name, password_hash, status) \
         VALUES ($1, $2, $3, 'not-a-real-hash', 'active')",
    ).bind(owner).bind(app.server_id).bind(name).execute(&app.db).await?;

    let outcome = cryptarch::backup::run_now(state, "system", name).await
        .map_err(|e| anyhow::anyhow!("the backup could not even start: {e}"))?;

    // A CHECK violation would surface HERE as Unrecorded, not as a green row —
    // that is exactly what CRYPTARCH-85 bought, and why D4 is safe to add now
    // and was not before.
    match &outcome {
        cryptarch::backup::Outcome::Ok { .. } => {}
        cryptarch::backup::Outcome::Unrecorded { detail, .. } => anyhow::bail!(
            "recording a VERIFIED backup was rejected — the D4 constraint (or its \
             interaction with record_success) is wrong: {detail}"
        ),
        cryptarch::backup::Outcome::Failed { error } =>
            anyhow::bail!("the dump/verification failed, so nothing was recorded: {error}"),
    }

    let (status, verified_at): (String, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT status, verified_at FROM backups WHERE db_name = $1")
            .bind(name).fetch_one(&app.db).await?;

    // Anti-vacuity: if verification silently did not happen, `verified_at` is
    // NULL, the constraint is trivially satisfied, and this test proves nothing.
    anyhow::ensure!(
        verified_at.is_some(),
        "precondition: verification must actually have run and written verified_at, \
         or this probe does not exercise the constraint at all"
    );
    anyhow::ensure!(status == "ok", "a verified backup must be status ok, got '{status}'");
    Ok(())
}

// ---- restore (CRYPTARCH-69) --------------------------------------------------

fn swap_db(dsn: &str, db: &str) -> String {
    let (base, _) = dsn.rsplit_once('/').expect("DSN has a path");
    format!("{base}/{db}")
}

/// Set up a real database on the cluster with one table of known rows, back it
/// up for real, and hand back everything needed to drive a restore.
async fn restorable_fixture(
    app: &TestApp,
    admin_dsn: &str,
    name: &str,
) -> (AppState, Uuid, Uuid) {
    let state = test_state(app);
    let engine = cryptarch::engine::postgres::PostgresEngine::connect(
        admin_dsn, "localhost".into(), 5432,
    ).await.expect("connecting to the test server");
    app_registry_register(app, Arc::new(engine));
    let engine = app.servers.get(app.server_id).expect("engine registered");
    engine.create_user_db(name, "e2e_test_password_not_a_secret").await
        .expect("provisioning the source database");

    let owner: Uuid = sqlx::query_scalar("SELECT id FROM users WHERE username = 'alice'")
        .fetch_one(&app.db).await.unwrap();
    let database_id: Uuid = sqlx::query_scalar(
        "INSERT INTO databases (owner_id, server_id, name, password_hash, status) \
         VALUES ($1, $2, $3, 'not-a-real-hash', 'active') RETURNING id",
    ).bind(owner).bind(app.server_id).bind(name).fetch_one(&app.db).await.unwrap();

    let tenant = sqlx::PgPool::connect(&swap_db(admin_dsn, name)).await
        .expect("connecting to the new database");
    // Created AS THE TENANT. Seeding as the superuser would leave the table
    // owned by postgres, and the dump — which runs as the owner, deliberately —
    // would then fail with "permission denied", which is the dump doing its job
    // rather than a bug.
    sqlx::raw_sql(AssertSqlSafe(format!(
        "SET ROLE \"{name}\"; \
         CREATE TABLE ledger (id int primary key, note text); \
         INSERT INTO ledger VALUES (1, 'original'), (2, 'also original'); \
         RESET ROLE;"
    ))).execute(&tenant).await.expect("seeding rows");
    tenant.close().await;

    // Cleans up before failing. A panic here used to strand the database it had
    // just created — and this cluster is also a managed server, so a leaked
    // `rest_*` database is litter on something real, not on a scratch box.
    let outcome = cryptarch::backup::run_now(&state, "alice", name).await;
    let ok = matches!(outcome, Ok(cryptarch::backup::Outcome::Ok { .. }));
    if !ok {
        let _ = engine.drop_user_db(name).await;
        panic!("premise: the backup must have succeeded, got {outcome:?}");
    }
    let backup_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM backups WHERE database_id = $1 AND status = 'ok'",
    ).bind(database_id).fetch_one(&app.db).await.unwrap();

    (state, database_id, backup_id)
}

async fn await_restore(app: &TestApp, id: Uuid) -> (String, Option<String>) {
    for _ in 0..100 {
        let row: (String, Option<String>) =
            sqlx::query_as("SELECT status, error FROM restores WHERE id = $1")
                .bind(id).fetch_one(&app.db).await.unwrap();
        if row.0 != "running" {
            return row;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("restore did not finish");
}

/// The whole point of the feature: what the backup held is what comes back.
#[tokio::test]
async fn a_restore_puts_back_what_the_backup_held() {
    let Ok(admin_dsn) = std::env::var(TEST_DSN_VAR) else { return };
    if tokio::process::Command::new("pg_restore").arg("--version").output().await.is_err() {
        eprintln!("skipping: pg_restore not installed");
        return;
    }
    let Some(app) = test_app().await else { return };
    let name = format!("rest_{}", &Uuid::new_v4().simple().to_string()[..12]);
    let (state, database_id, backup_id) = restorable_fixture(&app, &admin_dsn, &name).await;

    let result = async {
        // Lose the data the way a tenant would: wrong DELETE, no WHERE.
        let tenant = sqlx::PgPool::connect(&swap_db(&admin_dsn, &name)).await?;
        sqlx::raw_sql("DELETE FROM ledger;").execute(&tenant).await?;
        let gone: i64 = sqlx::query_scalar("SELECT count(*) FROM ledger")
            .fetch_one(&tenant).await?;
        anyhow::ensure!(gone == 0, "premise: the rows really were lost");
        tenant.close().await;

        let id = cryptarch::restore::enqueue(&state, "alice", database_id, &name, backup_id)
            .await.map_err(|e| anyhow::anyhow!("{e}"))?;
        let (status, error) = await_restore(&app, id).await;
        anyhow::ensure!(status == "ok", "the restore failed: {error:?}");

        let tenant = sqlx::PgPool::connect(&swap_db(&admin_dsn, &name)).await?;
        let back: i64 = sqlx::query_scalar("SELECT count(*) FROM ledger")
            .fetch_one(&tenant).await?;
        let note: String = sqlx::query_scalar("SELECT note FROM ledger WHERE id = 1")
            .fetch_one(&tenant).await?;
        // Objects must belong to the TENANT afterwards, not the panel role —
        // without --role a restore silently transfers the schema to the control
        // plane and the owner can no longer alter their own tables.
        let owner: String = sqlx::query_scalar(
            "SELECT tableowner FROM pg_tables WHERE tablename = 'ledger'",
        ).fetch_one(&tenant).await?;
        tenant.close().await;

        anyhow::ensure!(back == 2, "both rows must be back, got {back}");
        anyhow::ensure!(note == "original", "and hold their original contents");
        anyhow::ensure!(owner == name, "the tenant must still own the table, got '{owner}'");
        Ok::<_, anyhow::Error>(())
    }.await;

    let engine = app.servers.get(app.server_id).unwrap();
    let _ = engine.drop_user_db(&name).await;
    result.expect("the restore round trip");
}

/// CRYPTARCH-107: a REAL backup records the REAL fingerprint of the key that
/// sealed it.
///
/// The read guard (`a_backup_sealed_under_a_different_key_is_refused_by_name`)
/// sets `key_fingerprint` by hand, so it proves the refusal works and nothing
/// about the value it refuses on. That leaves the write path uncovered — and
/// the failure direction is brutal: if `run_job` ever passed the wrong value,
/// or `record_success` bound the wrong parameter, EVERY restore would be
/// refused with "sealed with a different encryption key". A self-inflicted
/// total loss of restore capability, wearing the costume of the disaster the
/// feature exists to detect.
///
/// So this takes a real backup through `run_now` and reads the column back.
#[tokio::test]
async fn a_real_backup_records_the_key_that_sealed_it() {
    let Ok(admin_dsn) = std::env::var(TEST_DSN_VAR) else { return };
    if tokio::process::Command::new("pg_dump").arg("--version").output().await.is_err() {
        eprintln!("skipping: pg_dump not installed");
        return;
    }
    let Some(app) = test_app().await else { return };
    let name = format!("fptest_{}", &Uuid::new_v4().simple().to_string()[..10]);
    // Takes a real backup as part of building the fixture.
    let (state, _database_id, backup_id) = restorable_fixture(&app, &admin_dsn, &name).await;

    let result = async {
        let recorded: Option<String> = sqlx::query_scalar(
            "SELECT key_fingerprint FROM backups WHERE id = $1",
        ).bind(backup_id).fetch_one(&app.db).await?;

        let expected = state.crypto.key_fingerprint();
        // PRECONDITION: the fingerprint is a real value, not an empty string
        // that would trivially match a bug producing empty strings everywhere.
        anyhow::ensure!(expected.len() == 16, "premise: a 16-char fingerprint, got {expected:?}");

        anyhow::ensure!(
            recorded.as_deref() == Some(expected),
            "the backup must record the key that sealed it — recorded {recorded:?}, \
             loaded key is {expected}"
        );

        // And the consequence that matters: this blob is restorable, i.e. the
        // recorded value does not trip the guard it feeds. Without this, a bug
        // that wrote a consistent-but-wrong value would satisfy the assertion
        // above while refusing every restore in production.
        let refused = cryptarch::restore::enqueue(&state, "alice", _database_id, &name, backup_id).await;
        anyhow::ensure!(
            !matches!(refused, Err(cryptarch::restore::EnqueueError::WrongKey { .. })),
            "a backup taken with the CURRENT key must not be refused as foreign-keyed"
        );
        Ok::<_, anyhow::Error>(())
    }.await;

    let engine = app.servers.get(app.server_id).unwrap();
    let _ = engine.drop_user_db(&name).await;
    result.expect("the fingerprint round trip");
}

/// The safety rule, and the only reason this design needs no aside copy: a
/// restore that fails leaves the database exactly as it was.
///
/// The failure is injected with an event trigger on the target database, which
/// aborts the restore's first DDL — a real database-level fault, not a seam in
/// production code.
#[tokio::test]
async fn a_failed_restore_leaves_the_database_exactly_as_it_was() {
    let Ok(admin_dsn) = std::env::var(TEST_DSN_VAR) else { return };
    if tokio::process::Command::new("pg_restore").arg("--version").output().await.is_err() {
        eprintln!("skipping: pg_restore not installed");
        return;
    }
    let Some(app) = test_app().await else { return };
    let name = format!("rest_{}", &Uuid::new_v4().simple().to_string()[..12]);
    let (state, database_id, backup_id) = restorable_fixture(&app, &admin_dsn, &name).await;

    let result = async {
        let tenant = sqlx::PgPool::connect(&swap_db(&admin_dsn, &name)).await?;
        // Change the data AFTER the backup, so "unchanged" is distinguishable
        // from "restored" — if the restore wrongly applied, this row reverts.
        sqlx::raw_sql("UPDATE ledger SET note = 'changed after the backup' WHERE id = 1;")
            .execute(&tenant).await?;
        // Fires on CREATE TABLE, NOT on the first statement — that distinction
        // is the whole test. `--clean` drops the table first, so by the time
        // this aborts, a non-transactional restore has ALREADY destroyed the
        // data and cannot put it back. An earlier version of this trigger fired
        // on the first DDL and passed with --single-transaction removed,
        // because nothing had been applied yet: a negative assertion whose
        // subject could not exist. It has to fail after real damage to prove
        // the transaction is what undoes it.
        sqlx::raw_sql(
            "CREATE FUNCTION boom() RETURNS event_trigger LANGUAGE plpgsql AS \
             $$ BEGIN IF tg_tag = 'CREATE TABLE' THEN \
                  RAISE EXCEPTION 'injected: restore must not apply'; \
                END IF; END $$; \
             CREATE EVENT TRIGGER boom ON ddl_command_start EXECUTE FUNCTION boom();",
        ).execute(&tenant).await?;
        tenant.close().await;

        let id = cryptarch::restore::enqueue(&state, "alice", database_id, &name, backup_id)
            .await.map_err(|e| anyhow::anyhow!("{e}"))?;
        let (status, error) = await_restore(&app, id).await;
        anyhow::ensure!(
            status == "failed",
            "premise: the injected fault must have failed the restore, got '{status}'"
        );
        anyhow::ensure!(
            error.is_some_and(|e| e.contains("injected")),
            "and the reason must be recorded"
        );

        let tenant = sqlx::PgPool::connect(&swap_db(&admin_dsn, &name)).await?;
        sqlx::raw_sql("DROP EVENT TRIGGER boom;").execute(&tenant).await?;
        let note: String = sqlx::query_scalar("SELECT note FROM ledger WHERE id = 1")
            .fetch_one(&tenant).await?;
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM ledger")
            .fetch_one(&tenant).await?;
        tenant.close().await;

        // THE CLAIM: not "the restore failed cleanly" but "the database is what
        // it was a moment ago" — including the change made after the backup,
        // which a half-applied restore would have reverted.
        anyhow::ensure!(
            note == "changed after the backup",
            "a failed restore must not have applied ANY of the dump, got '{note}'"
        );
        anyhow::ensure!(rows == 2, "and must not have dropped rows, got {rows}");
        Ok::<_, anyhow::Error>(())
    }.await;

    let engine = app.servers.get(app.server_id).unwrap();
    let _ = engine.drop_user_db(&name).await;
    result.expect("the failed-restore scenario");
}

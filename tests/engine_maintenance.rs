//! CRYPTARCH-97: the maintenance report runs against a real Postgres.
//!
//! Every check here is a hand-written catalog query, and catalog queries are
//! exactly the kind that compile fine and fail on contact — a column that moved
//! between major versions, a cast that only works on some types, a view that
//! needs a privilege the panel role does not have. None of that is visible
//! until a real server answers.
//!
//! The panel role is deliberately NOT superuser, which matters here: several of
//! these views show reduced or empty results to an unprivileged role. A check
//! that errors for a non-superuser would take the whole report down, on the one
//! page an operator opens when a server is already misbehaving.

use cryptarch::engine::postgres::PostgresEngine;
use cryptarch::engine::{DbEngine, Severity};

const TEST_DSN_VAR: &str = "CRYPTARCH_TEST_DSN";

/// Every check executes, and the report says something about each of them.
#[tokio::test]
async fn the_maintenance_report_answers_against_a_real_server() {
    let Ok(dsn) = std::env::var(TEST_DSN_VAR) else {
        eprintln!("skipping: {TEST_DSN_VAR} not set");
        return;
    };
    let engine = PostgresEngine::connect(&dsn, "localhost".into(), 5432)
        .await
        .expect("connecting to the test server");

    // The call itself is the assertion: any query with a bad column, a bad
    // cast, or a permission problem returns Err here rather than a report.
    let report = engine.maintenance().await.expect(
        "a maintenance check failed against a real server — one of the catalog queries is \
         wrong, and this report is what an operator reads when a server is already unwell",
    );

    // Positive precondition. Every assertion below is about the CONTENT of the
    // report, and all of them pass for free against an empty one — which is
    // also exactly what a new engine returns from the trait default.
    assert!(!report.findings.is_empty(), "the report is empty; nothing below tests anything");

    let titles: Vec<&str> = report.findings.iter().map(|f| f.title.as_str()).collect();
    for expected in
        ["Transaction ID headroom", "Oldest open transaction", "Autovacuum", "Connections"]
    {
        assert!(
            titles.contains(&expected),
            "'{expected}' is missing — it is reported unconditionally, so its absence means \
             its query failed or was skipped. Got {titles:?}"
        );
    }

    // Each finding has to actually say something. A blank summary or advice
    // renders as an empty card, which reads as "checked, fine".
    for f in &report.findings {
        assert!(!f.summary.trim().is_empty(), "{} has no summary", f.title);
        assert!(!f.advice.trim().is_empty(), "{} has no advice", f.title);
    }

    // The connections check must have measured something rather than falling
    // through to a default: this very test holds a connection open, so a report
    // claiming zero is reporting a number it did not read.
    let conns = report.findings.iter().find(|f| f.title == "Connections").unwrap();
    assert!(
        !conns.summary.starts_with("0 of"),
        "connections reported as zero while this test is connected: {}",
        conns.summary
    );
}

/// A healthy idle cluster must not cry wolf.
///
/// The report is only useful if `urgent` means something. The dev cluster is
/// small, idle and freshly vacuumed, so anything urgent on it is a threshold
/// that fires on normal conditions — which would teach an operator to ignore
/// the whole page.
#[tokio::test]
async fn a_healthy_server_reports_nothing_urgent() {
    let Ok(dsn) = std::env::var(TEST_DSN_VAR) else { return };
    let engine = PostgresEngine::connect(&dsn, "localhost".into(), 5432)
        .await
        .expect("connecting to the test server");
    let report = engine.maintenance().await.expect("maintenance report");
    assert!(!report.findings.is_empty(), "empty report would pass this vacuously");

    let noisy: Vec<String> = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Urgent)
        .map(|f| format!("{}: {}", f.title, f.summary))
        .collect();
    assert!(
        noisy.is_empty(),
        "an idle dev cluster tripped an urgent finding, so the threshold is wrong: {noisy:?}"
    );

    // And the other direction: `worst()` is what badges the server, so it has
    // to agree with the findings rather than being computed separately.
    assert!(report.worst() < Severity::Urgent);
}

/// The blindness case: a role that cannot see other sessions must SAY so.
///
/// This is the finding that made the whole feature honest. `pg_stat_activity`
/// shows an unprivileged role only its own backends — and the panel role is
/// deliberately not a superuser. Without `pg_read_all_stats` the transaction
/// check sees nothing except Cryptarch's own connections and would report a
/// confident all-clear while a TENANT holds a transaction open, blocking
/// cleanup for the entire server. That is the exact failure the check exists to
/// catch, so "I cannot see" must never render as "all fine".
#[tokio::test]
async fn a_role_that_cannot_see_other_sessions_says_so_instead_of_all_clear() {
    let Ok(dsn) = std::env::var(TEST_DSN_VAR) else { return };
    let admin = match sqlx::PgPool::connect(&dsn).await {
        Ok(p) => p,
        Err(_) => return,
    };

    // A role shaped like the real thing: CREATEDB CREATEROLE, never superuser.
    let role = format!("maint_{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE ROLE \"{role}\" LOGIN PASSWORD 'probe_pw_not_a_secret' CREATEDB CREATEROLE"
    )))
    .execute(&admin)
    .await
    .expect("creating the probe role");

    let outcome = blind_role_scenario(&dsn, &role).await;

    // Always clean up: this cluster is also a managed server.
    let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP ROLE IF EXISTS \"{role}\"")))
        .execute(&admin)
        .await;
    outcome.expect("the blind-role scenario");
}

async fn blind_role_scenario(dsn: &str, role: &str) -> anyhow::Result<()> {
    let unprivileged = swap_user(dsn, role, "probe_pw_not_a_secret");
    let engine = PostgresEngine::connect(&unprivileged, "localhost".into(), 5432).await?;
    let report = engine.maintenance().await?;

    let f = report
        .findings
        .iter()
        .find(|f| f.title == "Oldest open transaction")
        .ok_or_else(|| anyhow::anyhow!("the transaction check vanished for an unprivileged role"))?;

    // Positive precondition: prove this role really IS blind, so the assertion
    // below is about the reporting and not about a coincidentally quiet server.
    let sees: bool = sqlx::query_scalar(
        "SELECT pg_has_role(current_user, 'pg_read_all_stats', 'USAGE') \
             OR current_setting('is_superuser')::bool",
    )
    .fetch_one(&sqlx::PgPool::connect(&unprivileged).await?)
    .await?;
    anyhow::ensure!(!sees, "the probe role can see all stats, so this tests nothing");

    anyhow::ensure!(
        f.severity != Severity::Ok,
        "a role that cannot see other sessions reported the check as fine: {}",
        f.summary
    );

    // The same blindness reaches the autovacuum check (CRYPTARCH-128): without
    // pg_read_all_stats, another role's backend shows `backend_type` NULL, so
    // the filter for workers finds none — and "no workers running" is then
    // reported as fine, with a published worker count of zero.
    let vac = report
        .findings
        .iter()
        .find(|f| f.title == "Autovacuum")
        .ok_or_else(|| anyhow::anyhow!("the autovacuum check vanished for an unprivileged role"))?;
    anyhow::ensure!(
        vac.severity != Severity::Ok && vac.summary.to_lowercase().contains("cannot check"),
        "a role that cannot see autovacuum workers reported them as fine: {}",
        vac.summary
    );
    anyhow::ensure!(
        !vac.metrics.iter().any(|(k, _)| *k == "autovacuum_workers"),
        "a blind check must not publish a worker count it could not take"
    );
    anyhow::ensure!(
        f.summary.to_lowercase().contains("cannot check"),
        "the finding does not say it could not look: {}",
        f.summary
    );

    // The advice has to be self-contained. The bootstrap SQL is only rendered
    // when init reports `needs_bootstrap`, so a server that already works never
    // shows it — advice that says "see the bootstrap SQL" would be pointing at
    // something this operator cannot reach. It must carry the statement, with
    // THIS server's role name in it.
    anyhow::ensure!(
        f.advice.contains("GRANT pg_read_all_stats TO"),
        "the advice does not contain the statement to run: {}",
        f.advice
    );
    anyhow::ensure!(
        f.advice.contains(role),
        "the advice does not name this server's actual role ({role}): {}",
        f.advice
    );
    Ok(())
}

/// Rewrite a DSN's userinfo, keeping host/port/database.
fn swap_user(dsn: &str, user: &str, pw: &str) -> String {
    let (scheme, rest) = dsn.split_once("://").expect("dsn has a scheme");
    let tail = rest.split_once('@').map(|(_, t)| t).unwrap_or(rest);
    format!("{scheme}://{user}:{pw}@{tail}")
}

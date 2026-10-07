//! CRYPTARCH-92: a hostile database name reaching the engine is defeated by
//! quoting.
//!
//! The security spine makes two claims about database names: `valid_db_name`
//! rejects hostile ones at the portal, AND the engine quotes every identifier
//! so a name that somehow got past the allowlist still cannot inject. The first
//! claim has had a unit test since the beginning (`names::rejects_injection_shapes`).
//! The second — which the sqlx 0.9 audit established is the guard that actually
//! carries injection safety *universally*, since `qpanel` and the repair marker
//! are quoted but never validated — had none.
//!
//! # Why it had none, which is the interesting part
//!
//! It was not an oversight, it was structurally unwritable. The security-path
//! tests in `integration.rs` build their own SQL by interpolating the tenant
//! name **unquoted** (`ALTER DATABASE {tenant}`, `CREATE ROLE {role};`). That is
//! fine for the hardcoded names they use — and it means the scaffold breaks on a
//! hostile name before the code under test ever runs. A harness that cannot
//! express the dangerous input silently guarantees the dangerous input never
//! arrives, so the gap looks covered.
//!
//! That is the vacuous-assertion failure mode one level up: instead of an
//! assertion whose subject can be absent, a fixture whose hostile case cannot
//! occur. So this lives in its own file with no shared scaffolding, and drives
//! the engine directly — going through the portal would only re-test
//! `valid_db_name`, which rejects the name long before quoting matters.

use cryptarch::engine::postgres::PostgresEngine;
use cryptarch::engine::DbEngine;
use uuid::Uuid;

const TEST_DSN_VAR: &str = "CRYPTARCH_TEST_DSN";
const PW: &str = "engine_injection_test_password_not_a_secret";

async fn db_exists(dsn: &str, name: &str) -> bool {
    use sqlx::Connection;
    let mut conn = sqlx::PgConnection::connect(dsn).await.expect("connecting to check pg_database");
    let found: Option<String> =
        sqlx::query_scalar("SELECT datname::text FROM pg_database WHERE datname = $1")
            .bind(name)
            .fetch_optional(&mut conn)
            .await
            .expect("querying pg_database");
    found.is_some()
}

/// A name carrying a statement terminator must create a database with that
/// literal name and execute nothing extra.
///
/// The canary is a real provisioned database that the hostile name names in its
/// payload. If quoting failed anywhere in `create_user_db`, the injected
/// `DROP DATABASE` would run against it.
#[tokio::test]
async fn a_database_name_carrying_a_drop_statement_creates_a_database_and_drops_nothing() {
    let Ok(dsn) = std::env::var(TEST_DSN_VAR) else {
        eprintln!("skipping: {TEST_DSN_VAR} not set");
        return;
    };
    let engine = PostgresEngine::connect(&dsn, "localhost".into(), 5432)
        .await
        .expect("connecting to the test server");

    // Short on purpose: Postgres truncates identifiers at 63 bytes, and a
    // truncated name would make the "created with the literal name" assertion
    // below fail for a reason that has nothing to do with injection.
    let canary = format!("canary_{}", &Uuid::new_v4().simple().to_string()[..8]);
    let hostile = format!("x\"; DROP DATABASE {canary}; --");
    assert!(hostile.len() < 63, "hostile name would be truncated by Postgres");

    engine.create_user_db(&canary, PW).await.expect("provisioning the canary database");

    let outcome = scenario(&engine, &dsn, &canary, &hostile).await;

    // Clean up on every path, including panics upstream of here: this cluster
    // is also a managed server, and a leaked `x"; DROP ...` role would be a
    // genuinely unpleasant thing to find by hand.
    drop_test_db(&engine, &hostile).await;
    drop_test_db(&engine, &canary).await;
    outcome.expect("the hostile-name scenario");
}

async fn scenario(
    engine: &PostgresEngine,
    dsn: &str,
    canary: &str,
    hostile: &str,
) -> anyhow::Result<()> {
    // === PRECONDITIONS ===
    // The claim below is "the canary still exists", which passes for free if
    // the canary was never created or if the hostile DDL never ran at all.
    anyhow::ensure!(
        db_exists(dsn, canary).await,
        "the canary was not created, so nothing could have dropped it and this test \
         would pass without proving anything"
    );

    // The engine deliberately does NOT validate — `valid_db_name` guards the
    // portal, quoting guards here — so this must succeed. If it errored, no
    // injection could have fired and the canary would survive trivially.
    engine.create_user_db(hostile, PW).await.map_err(|e| {
        anyhow::anyhow!(
            "create_user_db refused the hostile name ({e}). That is not this test passing: \
             the injection payload never reached any DDL, so quoting was never exercised."
        )
    })?;

    // The strongest evidence the payload reached the server AS ONE IDENTIFIER:
    // a database exists whose name is the whole hostile string, terminator and
    // all. Had quoting failed, the statement would have split and this name
    // could not exist.
    anyhow::ensure!(
        db_exists(dsn, hostile).await,
        "no database named {hostile:?} exists — the name did not survive as a single \
         identifier, so it is unclear what the server actually executed"
    );

    // === THE CLAIM ===
    anyhow::ensure!(
        db_exists(dsn, canary).await,
        "CRYPTARCH-92: the injected DROP DATABASE executed — identifier quoting in \
         create_user_db does not hold"
    );

    // The drop path quotes too. Same reasoning: it interpolates the same name
    // into DROP DATABASE / DROP ROLE, and a failure there is the same class of
    // bug discovered on the way out instead of the way in.
    engine
        .drop_user_db(hostile)
        .await
        .map_err(|e| anyhow::anyhow!("drop_user_db could not remove the hostile name: {e}"))?;
    anyhow::ensure!(
        !db_exists(dsn, hostile).await,
        "the hostile database survived its own drop"
    );
    anyhow::ensure!(
        db_exists(dsn, canary).await,
        "CRYPTARCH-92: dropping the hostile database took the canary with it"
    );

    Ok(())
}

/// The portal still refuses these names, so the engine's quoting is the second
/// line and not the first.
///
/// Without this, the test above could be read as "hostile names are fine" — they
/// are not; they are simply not the only thing standing between a tenant and the
/// server. Both guards are asserted so neither can be removed as redundant.
#[test]
fn the_allowlist_still_rejects_what_the_engine_survives() {
    let canary = "canary_deadbeef";
    let hostile = format!("x\"; DROP DATABASE {canary}; --");
    assert!(
        !cryptarch::names::valid_db_name(&hostile),
        "the allowlist admits the injection shape the engine test relies on being refused here"
    );
    assert!(
        cryptarch::names::valid_db_name(canary),
        "the canary name is not allowlisted, so the pairing above proves nothing"
    );
}

/// Drop a test database, and SAY SO if it does not work.
///
/// `let _ = drop_user_db(..)` is the natural thing to write and it is how a
/// leaked `bak_rls_*` database and role were found sitting on the dev cluster —
/// which is also a real managed server. The drop failing is not worth failing
/// a passing test over, but it is absolutely worth saying out loud, because
/// the alternative is litter nobody attributes to anything.
async fn drop_test_db(engine: &dyn cryptarch::engine::DbEngine, name: &str) {
    if let Err(e) = engine.drop_user_db(name).await {
        eprintln!("WARNING: leaked test database '{name}' — cleanup failed: {e:#}");
    }
}

//! Backup round-trip against a real Postgres (CRYPTARCH-59).
//!
//! The rest of the suite drives a test double; this one does not, because the
//! things most likely to break here are exactly the things a double cannot
//! model: whether `pg_dump --role` works over the panel's non-inherited
//! membership, whether the sealed blob a real dump produces opens again, and
//! whether the bytes that come back restore into a database with the same rows.
//!
//! Path note (CRYPTARCH-59): the dump connects over the *admin* DSN, straight
//! to Postgres. `managed_servers.host/port` is the address advertised to
//! tenants — the bouncer — and never the one the panel dumps through, so
//! pgbouncer's pool mode is not in this path. That is asserted below rather
//! than left as folklore: if someone ever points the dump at the tenant edge,
//! the assertion is where the change gets noticed.
//!
//! `AssertSqlSafe` on the fixtures below is the weaker, test-tier use of the
//! marker — interpolands are literals and UUID-derived suffixes, not tenant
//! input. See the note in `integration.rs` for why the two tiers are kept
//! visibly distinct from the engine's.
//!
//! Skips (does not fail) when CRYPTARCH_TEST_DSN is unset or pg_dump is absent.

use cryptarch::backup;
use cryptarch::crypto::Crypto;
use cryptarch::engine::{DbEngine, postgres::PostgresEngine};
use sqlx::AssertSqlSafe;
use sqlx::{Connection, PgConnection, Row};

const TEST_DSN_VAR: &str = "CRYPTARCH_TEST_DSN";

fn tenant_dsn(admin_dsn: &str, db: &str, user: &str, password: &str) -> String {
    // Reuse the admin DSN's host/port, swapping in the tenant's identity.
    let after_scheme = admin_dsn.split("://").nth(1).unwrap_or(admin_dsn);
    let hostport = after_scheme
        .rsplit_once('@')
        .map(|(_, hp)| hp)
        .unwrap_or(after_scheme);
    let hostport = hostport.split('/').next().unwrap_or(hostport);
    format!("postgres://{user}:{password}@{hostport}/{db}")
}

async fn skip_reason(admin_dsn: &Option<String>) -> Option<&'static str> {
    if admin_dsn.is_none() {
        return Some("CRYPTARCH_TEST_DSN not set");
    }
    if tokio::process::Command::new("pg_dump")
        .arg("--version")
        .output()
        .await
        .is_err()
    {
        return Some("pg_dump not installed");
    }
    None
}

#[tokio::test]
async fn backup_restore_round_trip_preserves_rows() {
    let admin_dsn = std::env::var(TEST_DSN_VAR).ok();
    if let Some(why) = skip_reason(&admin_dsn).await {
        eprintln!("skipping: {why}");
        return;
    }
    let admin_dsn = admin_dsn.unwrap();

    // Unique per run: these are real databases and roles on a real server.
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let source = format!("bak_src_{}", &suffix[..12]);
    let target = format!("bak_dst_{}", &suffix[..12]);
    let password = "e2e_test_password_not_a_secret";

    let engine = PostgresEngine::connect(&admin_dsn, "localhost".into(), 5432)
        .await
        .expect("connecting to the test server");

    // The dump must ride the admin connection, not the advertised tenant
    // address — note the deliberately wrong host/port passed above. If the
    // dump ever started using them, it would fail to connect here.
    engine.create_user_db(&source, password).await.expect("provisioning source db");
    engine.create_user_db(&target, password).await.expect("provisioning restore target");

    let result = round_trip(&engine, &admin_dsn, &source, &target, password).await;

    // Always clean up, even on failure — a leaked role blocks the next run.
    drop_test_db(&engine, &source).await;
    drop_test_db(&engine, &target).await;

    result.expect("backup round trip");
}

async fn round_trip(
    engine: &PostgresEngine,
    admin_dsn: &str,
    source: &str,
    target: &str,
    password: &str,
) -> anyhow::Result<()> {
    // Seed the source database as its owner.
    let mut conn = PgConnection::connect(&tenant_dsn(admin_dsn, source, source, password)).await?;
    sqlx::query("CREATE TABLE widgets (id INT PRIMARY KEY, label TEXT NOT NULL)")
        .execute(&mut conn)
        .await?;
    sqlx::query("INSERT INTO widgets (id, label) SELECT g, 'row-' || g FROM generate_series(1, 500) g")
        .execute(&mut conn)
        .await?;
    conn.close().await?;

    let dir = std::env::temp_dir().join(format!("cryptarch-e2e-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir)?;
    let blob = dir.join("backup.dump.zst.enc");
    let plain = dir.join("restored.dump");
    let crypto = Crypto::from_hex_key(&"ab".repeat(32))?;

    // --- back up ---------------------------------------------------------
    let mut dump = engine.dump_stream(source).await?;
    let stdout = dump.take_stdout()?;
    let blob_id = uuid::Uuid::new_v4();
    let sealed = backup::seal_stream(&crypto, blob_id, stdout, &blob).await?;
    dump.finish().await?;

    assert!(sealed.size_bytes > 0, "sealed blob is empty");
    assert_eq!(sealed.checksum.len(), 64, "checksum should be hex sha256");
    // Sealed on disk means sealed on disk: the plaintext dump's own magic
    // ("PGDMP") must not be sitting there in the clear.
    let on_disk = std::fs::read(&blob)?;
    assert!(
        !on_disk.windows(5).any(|w| w == b"PGDMP"),
        "blob contains an unencrypted pg_dump header"
    );

    // --- restore ---------------------------------------------------------
    backup::open_stream(&crypto, blob_id, &blob, &mut tokio::fs::File::create(&plain).await?)
        .await?;
    let recovered = std::fs::read(&plain)?;
    assert_eq!(&recovered[..5], b"PGDMP", "decrypted bytes are not a pg_dump archive");

    let out = tokio::process::Command::new("pg_restore")
        .arg("--dbname").arg(tenant_dsn(admin_dsn, target, target, password))
        .arg("--no-owner")
        .arg("--exit-on-error")
        .arg(&plain)
        .output()
        .await?;
    anyhow::ensure!(
        out.status.success(),
        "pg_restore failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // --- verify ----------------------------------------------------------
    let mut conn = PgConnection::connect(&tenant_dsn(admin_dsn, target, target, password)).await?;
    let count: i64 = sqlx::query("SELECT count(*) FROM widgets")
        .fetch_one(&mut conn)
        .await?
        .get(0);
    let sample: String = sqlx::query("SELECT label FROM widgets WHERE id = 42")
        .fetch_one(&mut conn)
        .await?
        .get(0);
    conn.close().await?;

    assert_eq!(count, 500, "restored row count");
    assert_eq!(sample, "row-42", "restored row content");

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// A dump of a database with FORCE ROW LEVEL SECURITY must fail loudly rather
/// than quietly producing a backup of only the rows the owner can see. This is
/// the single most dangerous failure mode a backup tool has, so it gets a test
/// of its own.
#[tokio::test]
async fn force_rls_makes_the_dump_fail_loudly() {
    let admin_dsn = std::env::var(TEST_DSN_VAR).ok();
    if let Some(why) = skip_reason(&admin_dsn).await {
        eprintln!("skipping: {why}");
        return;
    }
    let admin_dsn = admin_dsn.unwrap();

    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let name = format!("bak_rls_{}", &suffix[..12]);
    let password = "e2e_test_password_not_a_secret";

    let engine = PostgresEngine::connect(&admin_dsn, "localhost".into(), 5432)
        .await
        .expect("connecting to the test server");
    engine.create_user_db(&name, password).await.expect("provisioning db");

    let outcome = force_rls_dump(&engine, &admin_dsn, &name, password).await;
    drop_test_db(&engine, &name).await;

    let err = outcome.expect_err("a FORCE RLS table must not dump silently");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("row-level security") || msg.contains("row level security"),
        "expected an RLS complaint from pg_dump, got: {msg}"
    );
}

async fn force_rls_dump(
    engine: &PostgresEngine,
    admin_dsn: &str,
    name: &str,
    password: &str,
) -> anyhow::Result<()> {
    let mut conn = PgConnection::connect(&tenant_dsn(admin_dsn, name, name, password)).await?;
    sqlx::query("CREATE TABLE secrets (id INT PRIMARY KEY, tenant TEXT NOT NULL)")
        .execute(&mut conn)
        .await?;
    sqlx::query("INSERT INTO secrets VALUES (1, 'a'), (2, 'b')")
        .execute(&mut conn)
        .await?;
    sqlx::query("ALTER TABLE secrets ENABLE ROW LEVEL SECURITY")
        .execute(&mut conn)
        .await?;
    // FORCE is the part that matters: without it the owner bypasses its own
    // policies and the dump is complete.
    sqlx::query("ALTER TABLE secrets FORCE ROW LEVEL SECURITY")
        .execute(&mut conn)
        .await?;
    sqlx::query("CREATE POLICY only_a ON secrets USING (tenant = 'a')")
        .execute(&mut conn)
        .await?;
    conn.close().await?;

    let dir = std::env::temp_dir().join(format!("cryptarch-e2e-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir)?;
    let blob = dir.join("backup.enc");
    let crypto = Crypto::from_hex_key(&"ab".repeat(32))?;

    let mut dump = engine.dump_stream(name).await?;
    let stdout = dump.take_stdout()?;
    // The seal succeeds — pg_dump writes a prefix before it hits the table.
    // Only finish() knows the dump failed, which is precisely why the caller
    // must not treat "the stream ended" as success.
    let _ = backup::seal_stream(&crypto, uuid::Uuid::new_v4(), stdout, &blob).await;
    // finish() hands back pg_dump's stderr on success; here only the failure
    // matters, so the warnings are discarded.
    let result = dump.finish().await.map(|_| ());
    let _ = std::fs::remove_dir_all(&dir);
    result
}

/// The metadata database's own backup path (CRYPTARCH-62) differs from the
/// tenant path in two ways — no `--role` to assume, and the database name comes
/// from parsing the DSN rather than from a `databases` row. Both are exercised
/// here against a real database, because "Cryptarch can restore itself" is the
/// claim the whole disaster-recovery story rests on.
#[tokio::test]
async fn metadata_style_dump_restores() {
    let admin_dsn = std::env::var(TEST_DSN_VAR).ok();
    if let Some(why) = skip_reason(&admin_dsn).await {
        eprintln!("skipping: {why}");
        return;
    }
    let admin_dsn = admin_dsn.unwrap();

    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let source = format!("meta_src_{}", &suffix[..12]);
    let target = format!("meta_dst_{}", &suffix[..12]);

    let mut admin = PgConnection::connect(&admin_dsn).await.expect("admin connect");
    for db in [&source, &target] {
        sqlx::query(AssertSqlSafe(format!("CREATE DATABASE \"{db}\""))).execute(&mut admin).await.unwrap();
    }

    let result = metadata_round_trip(&admin_dsn, &source, &target).await;

    for db in [&source, &target] {
        let _ = sqlx::query(AssertSqlSafe(format!("DROP DATABASE IF EXISTS \"{db}\" WITH (FORCE)")))
            .execute(&mut admin)
            .await;
    }
    result.expect("metadata-style round trip");
}

async fn metadata_round_trip(admin_dsn: &str, source: &str, target: &str) -> anyhow::Result<()> {
    let source_dsn = swap_db(admin_dsn, source);
    let target_dsn = swap_db(admin_dsn, target);

    // Stand in for the metadata schema.
    let mut conn = PgConnection::connect(&source_dsn).await?;
    sqlx::query("CREATE TABLE users (id INT PRIMARY KEY, username TEXT NOT NULL)")
        .execute(&mut conn)
        .await?;
    sqlx::query("INSERT INTO users VALUES (1, 'admin'), (2, 'alice')")
        .execute(&mut conn)
        .await?;
    conn.close().await?;

    // The name must come out of the DSN, exactly as the metadata path does it.
    let parsed = cryptarch::engine::postgres::database_in_dsn(&source_dsn)
        .ok_or_else(|| anyhow::anyhow!("database_in_dsn found no database"))?;
    anyhow::ensure!(parsed == source, "parsed '{parsed}', expected '{source}'");

    let dir = std::env::temp_dir().join(format!("cryptarch-meta-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir)?;
    let blob = dir.join("meta.enc");
    let plain = dir.join("meta.dump");
    let crypto = Crypto::from_hex_key(&"ab".repeat(32))?;

    // No --role: the metadata database has no tenant owner to become.
    let child = cryptarch::engine::postgres::dump_command(&source_dsn, &parsed, None)?.spawn()?;
    let mut dump = cryptarch::engine::DumpStream::new(child)?;
    let stdout = dump.take_stdout()?;
    let blob_id = uuid::Uuid::new_v4();
    backup::seal_stream(&crypto, blob_id, stdout, &blob).await?;
    dump.finish().await?;

    backup::open_stream(&crypto, blob_id, &blob, &mut tokio::fs::File::create(&plain).await?)
        .await?;
    let out = tokio::process::Command::new("pg_restore")
        .arg("--dbname").arg(&target_dsn)
        .arg("--exit-on-error")
        .arg(&plain)
        .output()
        .await?;
    anyhow::ensure!(
        out.status.success(),
        "pg_restore failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut conn = PgConnection::connect(&target_dsn).await?;
    let count: i64 = sqlx::query("SELECT count(*) FROM users").fetch_one(&mut conn).await?.get(0);
    conn.close().await?;
    anyhow::ensure!(count == 2, "restored {count} users, expected 2");

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

fn swap_db(dsn: &str, db: &str) -> String {
    let (base, _) = dsn.rsplit_once('/').expect("DSN has a path");
    format!("{base}/{db}")
}

/// The manifest must describe the blob, travel INSIDE it, and survive the round
/// trip — surveyed against a database carrying every hazard class we record.
#[tokio::test]
async fn manifest_is_surveyed_at_dump_time_and_authenticated_in_the_blob() {
    let admin_dsn = std::env::var(TEST_DSN_VAR).ok();
    if let Some(why) = skip_reason(&admin_dsn).await {
        eprintln!("skipping: {why}");
        return;
    }
    let admin_dsn = admin_dsn.unwrap();

    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let name = format!("man_src_{}", &suffix[..12]);
    let reader = format!("man_rdr_{}", &suffix[..12]);
    let password = "e2e_test_password_not_a_secret";

    let engine = PostgresEngine::connect(&admin_dsn, "localhost".into(), 5432)
        .await
        .expect("connecting to the test server");
    engine.create_user_db(&name, password).await.expect("provisioning db");
    engine.create_user_db(&reader, password).await.expect("provisioning reader role");

    let outcome = manifest_round_trip(&engine, &admin_dsn, &name, &reader, password).await;
    drop_test_db(&engine, &name).await;
    drop_test_db(&engine, &reader).await;
    outcome.expect("manifest round trip");
}

async fn manifest_round_trip(
    engine: &PostgresEngine,
    admin_dsn: &str,
    name: &str,
    reader: &str,
    password: &str,
) -> anyhow::Result<()> {
    let mut conn = PgConnection::connect(&tenant_dsn(admin_dsn, name, name, password)).await?;
    sqlx::query("CREATE TABLE events (id int primary key, tenant text)")
        .execute(&mut conn)
        .await?;
    sqlx::query("ALTER TABLE events ENABLE ROW LEVEL SECURITY").execute(&mut conn).await?;
    // The policy expression embeds a literal — the manifest must NOT keep it.
    sqlx::query(AssertSqlSafe(format!(
        "CREATE POLICY tenant_isolation ON events TO \"{reader}\" USING (tenant = 'acme-corp')"
    )))
    .execute(&mut conn)
    .await?;
    sqlx::query(AssertSqlSafe(format!("GRANT SELECT ON events TO \"{reader}\"")))
        .execute(&mut conn)
        .await?;
    sqlx::query("CREATE SEQUENCE counter").execute(&mut conn).await?;
    sqlx::query(AssertSqlSafe(format!("GRANT USAGE ON SEQUENCE counter TO \"{reader}\"")))
        .execute(&mut conn)
        .await?;
    sqlx::query("CREATE POLICY everyone ON events TO PUBLIC USING (true)")
        .execute(&mut conn)
        .await?;
    sqlx::query("CREATE FUNCTION whoami() RETURNS text LANGUAGE sql SECURITY DEFINER AS 'SELECT current_user::text'")
        .execute(&mut conn)
        .await?;
    conn.close().await?;

    let survey = engine.survey(name).await?;
    anyhow::ensure!(survey.owner == name, "owner should be the database's own role");
    anyhow::ensure!(!survey.properties.encoding.is_empty(), "encoding recorded");

    // datcollversion is the glibc-drift canary: a restore onto a box with a
    // different collation library silently produces wrong index ordering on
    // text columns. It was dead on arrival because `daticulocale` was renamed
    // in PG17 and one combined query took the whole row down with it, so this
    // asserts the read SUCCEEDED, not merely that the field exists.
    anyhow::ensure!(
        survey.properties.coll_version.was_read(),
        "collation version must be READ, not silently unrecorded: {:?}",
        survey.properties.coll_version
    );
    anyhow::ensure!(
        survey.properties.locale_provider.was_read(),
        "locale provider must be read: {:?}", survey.properties.locale_provider
    );
    let h = &survey.hazards;
    anyhow::ensure!(h.rls_tables == vec!["events".to_string()], "RLS table found: {:?}", h.rls_tables);
    anyhow::ensure!(h.policies.len() == 2, "both policies found: {:?}", h.policies);
    anyhow::ensure!(
        h.policies.iter().any(|p| p.roles == vec![reader.to_string()]),
        "policy's referenced role recorded: {:?}", h.policies
    );
    anyhow::ensure!(
        h.non_owner_grants.iter().any(|g| g.grantee == reader),
        "grant to another role found: {:?}", h.non_owner_grants
    );
    anyhow::ensure!(
        h.security_definer_functions == vec!["whoami".to_string()],
        "SECURITY DEFINER function found: {:?}", h.security_definer_functions
    );
    anyhow::ensure!(h.any(), "this database plainly needs care on restore");

    // A TO PUBLIC policy is stored as polroles = {0}; filtering that out made an
    // empty role list silently mean "applies to everyone".
    anyhow::ensure!(
        h.policies.iter().any(|p| p.name == "everyone" && p.roles == vec!["PUBLIC".to_string()]),
        "a TO PUBLIC policy must record PUBLIC by name, got {:?}", h.policies
    );

    // The grant below is between two roles the panel does not own, which
    // information_schema.role_table_grants can hide entirely.
    anyhow::ensure!(
        h.non_owner_grants.iter().any(|g| g.grantee == reader && g.object == "events"),
        "a grant to another role must be visible: {:?}", h.non_owner_grants
    );
    // A sequence grant is as capable of aborting a restore as a table grant,
    // and enumerating only tables would let the role behind it pass a
    // pre-flight and then fail the restore inside --single-transaction.
    anyhow::ensure!(
        h.non_owner_grants
            .iter()
            .any(|g| g.kind == "sequence" && g.grantee == reader),
        "a grant on a SEQUENCE must be visible too: {:?}", h.non_owner_grants
    );

    let manifest = cryptarch::manifest::Manifest {
        schema: cryptarch::manifest::SCHEMA,
        db_name: name.to_string(),
        owner: survey.owner.clone(),
        database_id: None,
        server_id: None,
        taken_at: chrono::Utc::now(),
        server_version: survey.server_version.clone(),
        client_version: "test".into(),
        properties: survey.properties.clone(),
        extensions: survey.extensions.clone(),
        hazards: survey.hazards.clone(),
    };
    let aux = serde_json::to_vec(&manifest)?;
    anyhow::ensure!(
        !String::from_utf8_lossy(&aux).contains("acme-corp"),
        "the policy's literal leaked into the manifest"
    );

    let dir = std::env::temp_dir().join(format!("cryptarch-man-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir)?;
    let blob = dir.join("backup.enc");
    let crypto = Crypto::from_hex_key(&"ab".repeat(32))?;
    let id = uuid::Uuid::new_v4();

    let mut dump = engine.dump_stream(name).await?;
    let stdout = dump.take_stdout()?;
    backup::seal_stream_with(&crypto, id, aux.clone(), stdout, &blob).await?;
    dump.finish().await?;

    // The manifest comes back out of the sealed header, byte for byte.
    let recovered = backup::open_stream_aux(&crypto, id, &blob, tokio::io::sink()).await?;
    anyhow::ensure!(recovered == aux, "manifest did not survive the round trip");

    let state = cryptarch::manifest::ManifestState::decode(&recovered);
    let hazards = state.hazards();
    anyhow::ensure!(hazards.is_known(), "a surveyed backup's hazards are knowable");
    anyhow::ensure!(hazards.known_or_none().unwrap().any(), "and they are present");

    // Tampering with the manifest invalidates the frames, because the header is
    // authenticated — this is what makes the in-blob copy the trustworthy one.
    let mut bytes = std::fs::read(&blob)?;
    let pos = bytes
        .windows(13)
        .position(|w| w == b"tenant_isolat")
        .ok_or_else(|| anyhow::anyhow!("manifest not found in the header"))?;
    bytes[pos] = b'X';
    std::fs::write(&blob, &bytes)?;
    anyhow::ensure!(
        backup::open_stream_aux(&crypto, id, &blob, tokio::io::sink()).await.is_err(),
        "editing the manifest must break authentication"
    );

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Verification must make the claim it says it makes: not "the header parsed"
/// but "this blob decrypted in full and pg_restore can read it".
#[tokio::test]
async fn verification_catches_a_blob_that_is_damaged_past_its_table_of_contents() {
    let admin_dsn = std::env::var(TEST_DSN_VAR).ok();
    if let Some(why) = skip_reason(&admin_dsn).await {
        eprintln!("skipping: {why}");
        return;
    }
    let admin_dsn = admin_dsn.unwrap();

    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let name = format!("ver_src_{}", &suffix[..12]);
    let password = "e2e_test_password_not_a_secret";

    let engine = PostgresEngine::connect(&admin_dsn, "localhost".into(), 5432)
        .await
        .expect("connecting to the test server");
    engine.create_user_db(&name, password).await.expect("provisioning db");
    let outcome = verify_scenarios(&engine, &admin_dsn, &name, password).await;
    drop_test_db(&engine, &name).await;
    outcome.expect("verification scenarios");
}

async fn verify_scenarios(
    engine: &PostgresEngine,
    admin_dsn: &str,
    name: &str,
    password: &str,
) -> anyhow::Result<()> {
    // Big enough that the table of contents is nowhere near the end: damage
    // after it is exactly what a TOC-only check would miss.
    let mut conn = PgConnection::connect(&tenant_dsn(admin_dsn, name, name, password)).await?;
    // Incompressible on purpose: zstd would squeeze repetitive filler down to
    // a single frame, and the point is to damage the file well past its TOC.
    sqlx::query(
        "CREATE TABLE bulk AS SELECT g id, \
         md5(g::text) || md5((g * 7)::text) || md5((g * 13)::text) || md5((g * 29)::text) pad \
         FROM generate_series(1, 60000) g",
    )
        .execute(&mut conn)
        .await?;
    conn.close().await?;

    let dir = std::env::temp_dir().join(format!("cryptarch-ver-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir)?;
    let blob = dir.join("backup.enc");
    let crypto = Crypto::from_hex_key(&"ab".repeat(32))?;
    let id = uuid::Uuid::new_v4();

    let mut dump = engine.dump_stream(name).await?;
    let stdout = dump.take_stdout()?;
    let sealed = backup::seal_stream(&crypto, id, stdout, &blob).await?;
    dump.finish().await?;
    anyhow::ensure!(
        sealed.size_bytes > 1024 * 1024,
        "want a blob spanning more than one frame, got {} bytes",
        sealed.size_bytes
    );

    // A good blob verifies, and reports real archive entries — an empty archive
    // also lists successfully, so the count is the only thing distinguishing
    // them.
    let entries = backup::verify_for_tests(&crypto, id, &blob).await?;
    anyhow::ensure!(entries >= 2, "expected real TOC entries, got {entries}");

    // Now damage a byte deep in the file, well past the table of contents. A
    // check that stopped once the listing succeeded would call this fine.
    let mut bytes = std::fs::read(&blob)?;
    let deep = bytes.len() * 3 / 4;
    bytes[deep] ^= 0xff;
    std::fs::write(&blob, &bytes)?;

    let err = backup::verify_for_tests(&crypto, id, &blob)
        .await
        .expect_err("damage past the TOC must fail verification");
    let msg = format!("{err:#}");
    anyhow::ensure!(
        msg.contains("could not be decrypted") || msg.contains("failed to decrypt"),
        "expected a decryption failure, got: {msg}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
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

/// A restore stuck behind a tenant's open transaction must give up, say who it
/// was waiting on, and change nothing — and one whose client dies mid-wait
/// must not leave its server backend queued behind that lock (CRYPTARCH-128).
///
/// Against a REAL held lock, on purpose. The previous bound was a
/// `lock_timeout` passed through PGOPTIONS, pinned by a test that checked the
/// variable was set; pg_restore's own script resets lock_timeout to 0, so the
/// bound did nothing and the test could not notice.
#[tokio::test]
async fn a_restore_behind_a_tenant_lock_gives_up_and_changes_nothing() {
    let admin_dsn = std::env::var(TEST_DSN_VAR).ok();
    if let Some(why) = skip_reason(&admin_dsn).await {
        eprintln!("skipping: {why}");
        return;
    }
    let admin_dsn = admin_dsn.unwrap();
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let name = format!("bak_lock_{}", &suffix[..12]);
    let password = "e2e_test_password_not_a_secret";

    let wait = std::time::Duration::from_secs(2);
    let engine = PostgresEngine::connect(&admin_dsn, "localhost".into(), 5432)
        .await
        .expect("connecting to the test server")
        .with_restore_lock_wait(wait);
    // A second engine whose watchdog will not fire inside the orphan scenario,
    // so what clears that backend is the server's client check, not the cancel.
    let patient = PostgresEngine::connect(&admin_dsn, "localhost".into(), 5432)
        .await
        .expect("connecting to the test server")
        .with_restore_lock_wait(std::time::Duration::from_secs(600));
    engine.create_user_db(&name, password).await.expect("creating the test database");

    let result = lock_scenarios(&engine, &patient, &admin_dsn, &name, password, wait).await;
    drop_test_db(&engine, &name).await;
    result.expect("lock scenarios");
}

async fn restore_bytes(engine: &dyn DbEngine, name: &str, bytes: &[u8]) -> anyhow::Result<String> {
    use tokio::io::AsyncWriteExt;
    let mut sink = engine.restore_stream(name).await?;
    let mut stdin = sink.take_stdin()?;
    stdin.write_all(bytes).await?;
    drop(stdin);
    sink.finish().await
}

async fn lock_scenarios(
    engine: &PostgresEngine,
    patient: &PostgresEngine,
    admin_dsn: &str,
    name: &str,
    password: &str,
    wait: std::time::Duration,
) -> anyhow::Result<()> {
    use anyhow::Context;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let tenant = tenant_dsn(admin_dsn, name, name, password);
    let count = |dsn: String| async move {
        let mut c = PgConnection::connect(&dsn).await?;
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM widgets").fetch_one(&mut c).await?;
        anyhow::Ok(n)
    };

    // Three rows in the dump, four in the live database: a restore that went
    // through is distinguishable from one that did not.
    let mut conn = PgConnection::connect(&tenant).await?;
    sqlx::query("CREATE TABLE widgets (id INT PRIMARY KEY)").execute(&mut conn).await?;
    sqlx::query("INSERT INTO widgets SELECT generate_series(1, 3)").execute(&mut conn).await?;
    let mut dump = engine.dump_stream(name).await?;
    let mut bytes = Vec::new();
    dump.take_stdout()?.read_to_end(&mut bytes).await?;
    dump.finish().await?;
    sqlx::query("INSERT INTO widgets VALUES (4)").execute(&mut conn).await?;

    // --- 1. behind a held lock: gives up, names the holder, changes nothing --
    let mut holder = PgConnection::connect(&tenant).await?;
    sqlx::query("BEGIN").execute(&mut holder).await?;
    sqlx::query("SELECT count(*) FROM widgets").execute(&mut holder).await?;

    let began = std::time::Instant::now();
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), restore_bytes(engine, name, &bytes))
        .await
        .context("the restore hung behind the lock — nothing bounded the wait")?;
    let took = began.elapsed();
    let msg = format!("{:#}", outcome.err().context("a restore behind a held lock must fail")?);
    anyhow::ensure!(msg.contains("gave up after waiting"), "the error must say why: {msg}");
    anyhow::ensure!(msg.contains(&format!("as '{name}'")), "and whose session it was behind: {msg}");
    anyhow::ensure!(took < wait + std::time::Duration::from_secs(8), "gave up after {took:?}, bound {wait:?}");
    sqlx::query("ROLLBACK").execute(&mut holder).await?;
    anyhow::ensure!(count(tenant.clone()).await? == 4, "a cancelled restore must leave the database untouched");

    // --- 2. premise: with nothing holding a lock, the same restore works -----
    restore_bytes(engine, name, &bytes).await.context("premise: an unobstructed restore succeeds")?;
    anyhow::ensure!(count(tenant.clone()).await? == 3, "premise: the restore really replaced the contents");

    // --- 2b. a wait shorter than the bound is not cancelled -----------------
    // Released at half the bound. A watchdog that cancelled at the first
    // instant of any wait would pass everything above and fail every restore
    // that ever briefly queued behind autovacuum.
    let mut brief = PgConnection::connect(&tenant).await?;
    sqlx::query("BEGIN").execute(&mut brief).await?;
    sqlx::query("SELECT count(*) FROM widgets").execute(&mut brief).await?;
    let release = tokio::spawn(async move {
        tokio::time::sleep(wait / 2).await;
        sqlx::query("ROLLBACK").execute(&mut brief).await.map(|_| ())
    });
    restore_bytes(engine, name, &bytes).await
        .context("a lock released inside the bound must not cancel the restore")?;
    release.await??;

    // --- 2c. a tenant cannot aim the watchdog at its own session -------------
    // application_name is visible to and settable by anyone, so the watchdog
    // must only ever select the PANEL's session (CRYPTARCH-128).
    let spoof_tag = "cryptarch-restore-spoofed";
    let mut holder0 = PgConnection::connect(&tenant).await?;
    sqlx::query("BEGIN").execute(&mut holder0).await?;
    sqlx::query("SELECT count(*) FROM widgets").execute(&mut holder0).await?;
    let decoy = tokio::spawn({
        let tenant = tenant.clone();
        async move {
            let mut d = PgConnection::connect(&tenant).await?;
            sqlx::query(AssertSqlSafe(format!("SET application_name = '{spoof_tag}'")))
                .execute(&mut d).await?;
            sqlx::query("BEGIN").execute(&mut d).await?;
            sqlx::query("LOCK TABLE widgets IN ACCESS EXCLUSIVE MODE").execute(&mut d).await?;
            sqlx::query("ROLLBACK").execute(&mut d).await?;
            anyhow::Ok(())
        }
    });
    let pool = sqlx::PgPool::connect(admin_dsn).await?;
    let mut spoof_waiting = false;
    for _ in 0..40 {
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity WHERE application_name = $1 \
             AND datname = $2 AND wait_event_type = 'Lock'",
        ).bind(spoof_tag).bind(name).fetch_one(&pool).await?;
        if n > 0 {
            spoof_waiting = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    // Long enough that waitstart is set and past any sub-second bound.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let picked = cryptarch::engine::postgres::blocked_restore(&pool, spoof_tag, name).await?;
    sqlx::query("ROLLBACK").execute(&mut holder0).await?;
    decoy.await??;
    anyhow::ensure!(spoof_waiting, "premise: the decoy is tagged and waiting on a lock");
    anyhow::ensure!(picked.is_none(), "the watchdog selected a tenant's session by its tag: {picked:?}");

    // --- 3. client dies mid-wait: the server backend must not stay queued ----
    sqlx::query("BEGIN").execute(&mut holder).await?;
    sqlx::query("SELECT count(*) FROM widgets").execute(&mut holder).await?;
    let mut sink = patient.restore_stream(name).await?;
    let mut stdin = sink.take_stdin()?;
    stdin.write_all(&bytes).await?;
    drop(stdin);
    let mut admin = PgConnection::connect(admin_dsn).await?;
    let restore_backends = |want_waiting: bool| {
        if want_waiting {
            "SELECT count(*) FROM pg_stat_activity WHERE datname = $1 \
             AND application_name LIKE 'cryptarch-restore-%' AND wait_event_type = 'Lock'"
        } else {
            "SELECT count(*) FROM pg_stat_activity WHERE datname = $1 \
             AND application_name LIKE 'cryptarch-restore-%'"
        }
    };
    let mut queued = false;
    for _ in 0..40 {
        let n: i64 = sqlx::query_scalar(restore_backends(true)).bind(name).fetch_one(&mut admin).await?;
        if n > 0 {
            queued = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    anyhow::ensure!(queued, "premise: the restore's backend reached the lock queue");
    drop(sink); // kill_on_drop: pg_restore dies with its client
    let mut gone = false;
    for _ in 0..60 {
        let n: i64 = sqlx::query_scalar(restore_backends(false)).bind(name).fetch_one(&mut admin).await?;
        if n == 0 {
            gone = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    sqlx::query("ROLLBACK").execute(&mut holder).await?;
    anyhow::ensure!(gone, "the dead client's backend stayed queued behind the tenant's lock");
    Ok(())
}

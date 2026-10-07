//! Can today's binary still open what yesterday's binary sealed?
//!
//! This is the proof that guards the crypto dependency upgrades
//! (aes-gcm, sha2, rand — CRYPTARCH-89 tier 4). Everything here rests on one
//! point, which is the whole reason the file exists:
//!
//! **A fresh seal-then-open round trip proves nothing.** The same code writes
//! and reads it, so it passes even if the on-disk format changed underneath —
//! the two errors cancel exactly. That is the vacuous-assertion shape in
//! another costume: an assertion that cannot fail for the reason you care
//! about. A backup that no longer opens is unrecoverable data, and it fails
//! silently at seal time and loudly months later at restore time.
//!
//! So the ground truth is a blob **captured once from a binary built against
//! the old crate versions** and committed as bytes. The upgraded code must read
//! *that*. The fixtures are frozen evidence, not test scaffolding.
//!
//! # These fixtures must never be regenerated to make a test pass
//!
//! Regenerating turns the proof into a tautology — a self-healing fixture
//! re-blesses whatever the current code happens to do, which is the exact
//! failure it exists to detect. `regenerate` below is deliberately awkward to
//! invoke and is only correct when the *format itself* is being versioned on
//! purpose, never when a test goes red after a dependency bump. If one of these
//! goes red after an upgrade, the upgrade broke on-disk compatibility and every
//! existing backup and stored DSN is at risk. That is a finding, not a chore.
//!
//! Captured 2026-07-22 against aes-gcm 0.10 / sha2 0.10 / rand 0.8.

use std::path::PathBuf;

use cryptarch::backup;
use cryptarch::crypto::Crypto;

/// Fixed key for the fixtures. Test-only, and obviously so.
const FIXTURE_KEY: &str = "3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c";

/// The backup id sealed into the blob header, and the one a reader must claim.
const FIXTURE_BACKUP_ID: &str = "1f0a5c9e-4d3b-4a71-9c2e-7b6d8e5f0a13";

/// Exact plaintext sealed into `backup_v2.blob`.
const FIXTURE_PLAINTEXT: &[u8] =
    b"-- cryptarch fixture dump\nCREATE TABLE t (id int);\nINSERT INTO t VALUES (1);\n";

/// Exact plaintext sealed into `dsn.blob`.
const FIXTURE_DSN: &str = "postgres://fixture_user:fixture_pw@fixture-host:5432/fixture_db";

/// Hex SHA-256 of `backup_v2.blob` as it was written. Recorded so the sha2
/// upgrade is checked against a digest computed by the OLD sha2, not merely
/// against itself.
const FIXTURE_CHECKSUM: &str = include_str!("fixtures/crypto/backup_v2.checksum");

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/crypto")
}

fn crypto() -> Crypto {
    Crypto::from_hex_key(FIXTURE_KEY).expect("fixture key")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A DSN sealed by the old binary still decrypts to the same string.
///
/// Covers `Crypto::seal`/`open`: AES-256-GCM with a random nonce and no AAD.
/// If aes-gcm ever changes how the tag is placed or the nonce interpreted,
/// this is where it surfaces — every stored admin DSN is in this format, so
/// the failure mode is a panel that cannot connect to any managed server.
#[test]
fn a_dsn_sealed_by_the_old_binary_still_opens() {
    let blob = std::fs::read(fixture_dir().join("dsn.blob")).expect(
        "fixture missing — it is committed evidence, not something a test run creates",
    );

    // Positive precondition: prove the bytes under test are real ciphertext and
    // not, say, an empty file that would make any `open` failure look like a
    // format issue. Nonce (12) + tag (16) + the plaintext length.
    assert_eq!(
        blob.len(),
        12 + 16 + FIXTURE_DSN.len(),
        "fixture is not the sealed DSN it claims to be"
    );

    let opened = crypto().open(&blob).expect(
        "a DSN sealed by the pre-upgrade binary no longer opens — this is an at-rest \
         compatibility break, not a flaky test. Every stored admin DSN is unreadable.",
    );
    assert_eq!(opened, FIXTURE_DSN);
}

/// A backup sealed by the old binary still opens, byte for byte.
///
/// Covers the framed format end to end: the v2 header, `seal_frame`/
/// `open_frame` with associated data, and — importantly — `frame_aad`, which
/// feeds the header through `Sha256::digest`. A sha2 change that altered that
/// digest would not corrupt anything visibly; it would simply make every
/// existing frame fail to authenticate.
#[tokio::test]
async fn a_backup_sealed_by_the_old_binary_still_opens() {
    let path = fixture_dir().join("backup_v2.blob");
    let sealed = std::fs::read(&path).expect(
        "fixture missing — it is committed evidence, not something a test run creates",
    );

    // Positive preconditions: this really is a v2 blob, and it really is
    // longer than its own header. Without these, a truncated or empty fixture
    // could make the assertions below pass for the wrong reason.
    assert_eq!(&sealed[..4], b"CRBK", "fixture is not a cryptarch blob");
    assert_eq!(sealed[4], 2, "fixture is not format v2");
    assert!(sealed.len() > 25, "fixture is shorter than a v2 header");

    let id: uuid::Uuid = FIXTURE_BACKUP_ID.parse().unwrap();
    let mut out: Vec<u8> = Vec::new();
    backup::open_stream(&crypto(), id, &path, &mut out).await.expect(
        "a backup sealed by the pre-upgrade binary no longer opens — this is an at-rest \
         compatibility break, not a flaky test. Every existing backup is unrestorable.",
    );

    assert_eq!(out, FIXTURE_PLAINTEXT, "recovered plaintext differs from what was sealed");
}

/// The recorded checksum of the sealed file still matches.
///
/// The stored `backups.checksum` column is how an operator verifies a blob
/// without the key. It was computed by the OLD sha2 over these exact bytes, so
/// recomputing it now checks the new sha2 against a digest it did not produce
/// — rather than against itself, which would hold no matter what changed.
#[test]
fn the_recorded_checksum_of_the_sealed_file_still_matches() {
    use sha2::{Digest, Sha256};

    let sealed = std::fs::read(fixture_dir().join("backup_v2.blob")).expect("fixture missing");
    assert!(!sealed.is_empty(), "fixture is empty; the digest below would be of nothing");

    let recomputed = hex(&Sha256::digest(&sealed));
    assert_eq!(
        recomputed,
        FIXTURE_CHECKSUM.trim(),
        "SHA-256 of an unchanged file changed — stored checksums no longer match their \
         blobs, and every verified backup would start failing verification"
    );
}

/// The wrong backup id must still be refused.
///
/// Guards against the upgrade turning authentication into a no-op. Without
/// this, all three tests above could pass while `open_stream` had quietly
/// stopped checking anything — "it opened" is only meaningful if something
/// comparable fails to open.
#[tokio::test]
async fn the_fixture_still_refuses_a_reader_claiming_the_wrong_id() {
    let path = fixture_dir().join("backup_v2.blob");
    let wrong: uuid::Uuid = "00000000-0000-4000-8000-000000000000".parse().unwrap();
    let mut out: Vec<u8> = Vec::new();

    let err = backup::open_stream(&crypto(), wrong, &path, &mut out)
        .await
        .expect_err("a blob opened under the wrong backup id — whole-file substitution is live");

    // Prove the refusal is about identity, not an incidental read failure that
    // would reject every id equally — including the right one.
    let msg = format!("{err:#}");
    assert!(
        msg.to_lowercase().contains("id") || msg.to_lowercase().contains("expect"),
        "refused for an unrelated reason ({msg}) — this test would pass even if id \
         checking were removed"
    );
}

/// The wrong key must still be refused, for the same reason.
#[test]
fn the_fixture_still_refuses_the_wrong_key() {
    let blob = std::fs::read(fixture_dir().join("dsn.blob")).expect("fixture missing");
    let other = Crypto::from_hex_key(&"a7".repeat(32)).unwrap();
    assert!(
        other.open(&blob).is_err(),
        "a DSN opened under the wrong key — GCM authentication is not doing anything"
    );
}

/// Write the fixtures. NOT a test — it is the capture step, and running it
/// destroys the evidence the tests above depend on.
///
/// Correct only when the on-disk format is being versioned deliberately, and
/// then only from a binary built against the versions being frozen. It is
/// never the right response to a red test after a dependency bump: that red is
/// the finding.
#[tokio::test]
#[ignore = "capture step; overwrites committed evidence"]
async fn regenerate() {
    let guard = std::env::var("CRYPTARCH_REGENERATE_CRYPTO_FIXTURES").unwrap_or_default();
    assert_eq!(
        guard, "yes-i-am-versioning-the-format",
        "refusing to overwrite committed crypto evidence without an explicit opt-in"
    );

    let dir = fixture_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let c = crypto();

    std::fs::write(dir.join("dsn.blob"), c.seal(FIXTURE_DSN).unwrap()).unwrap();

    let id: uuid::Uuid = FIXTURE_BACKUP_ID.parse().unwrap();
    let blob_path = dir.join("backup_v2.blob");
    let sealed =
        backup::seal_stream(&c, id, std::io::Cursor::new(FIXTURE_PLAINTEXT), &blob_path)
            .await
            .unwrap();
    std::fs::write(dir.join("backup_v2.checksum"), format!("{}\n", sealed.checksum)).unwrap();

    eprintln!("captured fixtures into {}", dir.display());
}

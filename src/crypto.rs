//! At-rest encryption for stored admin DSNs (CRYPTARCH-8).
//!
//! AES-256-GCM with a random 96-bit nonce per value, blob layout
//! `nonce || ciphertext+tag`. The key is 32 bytes, hex-encoded in a file
//! whose path comes from `CRYPTARCH_KEY_FILE` — kept out of the metadata DB
//! so a database dump alone never yields credentials. GCM authenticates as
//! well as encrypts: any tampering with a stored blob fails `open()` rather
//! than decrypting to garbage.
//!
//! Known limitation (accepted for now): no AAD, so an attacker with UPDATE on
//! managed_servers could swap encrypted blobs between rows/columns. That
//! requires DB write access — already game-over-adjacent. Revisit with
//! `Payload { aad }` binding blobs to (column, server id) when CRYPTARCH-10
//! starts writing the bouncer DSN column.

use aes_gcm::aead::{Aead, Generate, KeyInit, Payload};
use aes_gcm::{AeadCore, Aes256Gcm, Key};
use anyhow::{bail, Context};

const NONCE_LEN: usize = 12;

/// The 96-bit nonce this cipher takes. Spelled out because aes-gcm 0.11
/// generates nonces through the `Generate` trait on the nonce *type* rather
/// than through a constructor on the cipher.
type GcmNonce = aes_gcm::Nonce<<Aes256Gcm as AeadCore>::NonceSize>;

/// A fresh 96-bit nonce from the operating system's CSPRNG.
///
/// aes-gcm 0.10's `Aes256Gcm::generate_nonce(&mut OsRng)` was infallible and
/// panicked deep inside the RNG if the system entropy source failed. `Generate`
/// offers both; this deliberately takes the FALLIBLE one and turns the failure
/// into an error the caller already handles.
///
/// The distinction is not cosmetic. GCM's security collapses if a nonce ever
/// repeats under the same key — a repeat leaks the XOR of two plaintexts and
/// the authentication subkey with it. So the only acceptable outcomes when the
/// entropy source misbehaves are "a genuinely random nonce" or "no ciphertext
/// at all". Refusing to seal is the safe failure; anything that could yield a
/// predictable or repeated nonce is not.
fn fresh_nonce() -> anyhow::Result<GcmNonce> {
    GcmNonce::try_generate().context("the system CSPRNG failed to produce a nonce")
}

/// Read a stored nonce back off the front of a blob.
///
/// Replaces `Nonce::from_slice`, which 0.11 deprecates because it panicked on
/// a wrong-length slice. Callers here have already checked the blob is longer
/// than `NONCE_LEN` and split at exactly that, so the conversion cannot fail —
/// but it returns an error rather than asserting, because "cannot fail" is a
/// property of today's callers and a stored blob is attacker-reachable input.
fn nonce_from(bytes: &[u8]) -> anyhow::Result<GcmNonce> {
    GcmNonce::try_from(bytes).map_err(|_| anyhow::anyhow!("stored nonce is not {NONCE_LEN} bytes"))
}


/// Domain separator for the key fingerprint.
///
/// The fingerprint must not be a bare hash of the key: a bare `SHA256(key)` is
/// a value derived from secret material with no context binding, and reusing
/// the same construction elsewhere later is how those turn into oracles. This
/// makes the digest mean "this key's identity, for Cryptarch" and nothing else.
const KEY_ID_DOMAIN: &[u8] = b"cryptarch-key-id-v1:";

#[derive(Clone)]
pub struct Crypto {
    cipher: Aes256Gcm,
    /// Stable, non-secret identifier for the loaded key (CRYPTARCH-107).
    fingerprint: String,
}

impl Crypto {
    /// Load the key from a file containing 64 hex chars (32 bytes).
    /// Surrounding whitespace/newline is tolerated. On unix, refuses a key
    /// file readable by group/other — same posture as SSH.
    pub fn from_key_file(path: &str) -> anyhow::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path)
                .with_context(|| format!("reading key file {path}"))?
                .permissions()
                .mode();
            if mode & 0o077 != 0 {
                bail!(
                    "key file {path} is readable by group/other (mode {:o}) — chmod 600 it",
                    mode & 0o777
                );
            }
        }
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading key file {path}"))?;
        Self::from_hex_key(raw.trim())
    }

    pub fn from_hex_key(hex: &str) -> anyhow::Result<Self> {
        let bytes = decode_hex(hex).context("key file is not valid hex")?;
        if bytes.len() != 32 {
            bail!("key must be 32 bytes (64 hex chars), got {}", bytes.len());
        }
        let key = Key::<Aes256Gcm>::try_from(&bytes[..]).expect("length checked above");
        let fingerprint = fingerprint_of(&bytes);
        Ok(Self { cipher: Aes256Gcm::new(&key), fingerprint })
    }

    /// A short, stable, non-secret identifier for the loaded key
    /// (CRYPTARCH-107).
    ///
    /// Eight bytes of a domain-separated SHA-256 over the key. It leaks nothing
    /// useful — inverting it is a preimage attack on SHA-256 — and it exists so
    /// Cryptarch can answer the one question it previously could not: *is this
    /// the key that sealed the data I am looking at?*
    ///
    /// Without it, loading the wrong key succeeds (any 32 valid hex bytes is a
    /// valid key), backups keep "succeeding" because each is sealed and
    /// verified with the SAME wrong key, and the failure surfaces only when
    /// somebody clicks Restore — at which point the error cannot distinguish a
    /// bad key from a bad disk.
    pub fn key_fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Encrypt a secret for storage. Fresh random nonce per call.
    pub fn seal(&self, plaintext: &str) -> anyhow::Result<Vec<u8>> {
        let nonce = fresh_nonce()?;
        let ct = self
            .cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|_| anyhow::anyhow!("encryption failed"))?;
        let mut blob = Vec::with_capacity(NONCE_LEN + ct.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        Ok(blob)
    }

    /// Seal one frame of a chunked stream (CRYPTARCH-56).
    ///
    /// `seal` above holds the whole plaintext in memory, which is fine for a
    /// DSN and wrong for a multi-gigabyte dump. Chunking brings back problems a
    /// single AEAD blob doesn't have — frames can be reordered, dropped, or
    /// swapped in from another file — so the caller passes associated data that
    /// pins the frame to its position AND to the file it belongs to. What goes
    /// in that AAD is the caller's decision; getting it wrong is exactly how
    /// the first version of this was broken (see `backup::frame_aad`).
    pub fn seal_frame(&self, aad: &[u8], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let nonce = fresh_nonce()?;
        let ct = self
            .cipher
            .encrypt(&nonce, Payload { msg: plaintext, aad })
            .map_err(|_| anyhow::anyhow!("encryption failed"))?;
        let mut blob = Vec::with_capacity(NONCE_LEN + ct.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        Ok(blob)
    }

    /// Open one frame sealed by [`Crypto::seal_frame`]. The caller states the
    /// associated data it expects; a mismatch is a decryption failure, not a
    /// silent reinterpretation.
    pub fn open_frame(&self, aad: &[u8], blob: &[u8]) -> anyhow::Result<Vec<u8>> {
        if blob.len() <= NONCE_LEN {
            bail!("frame too short");
        }
        let (nonce, ct) = blob.split_at(NONCE_LEN);
        self.cipher
            .decrypt(&nonce_from(nonce)?, Payload { msg: ct, aad })
            .map_err(|_| {
                anyhow::anyhow!(
                    "frame failed to decrypt (tampered, reordered, truncated, spliced from \
                     another backup, or wrong key)"
                )
            })
    }

    /// Decrypt a stored blob. Fails on tampering, truncation, or a wrong key.
    pub fn open(&self, blob: &[u8]) -> anyhow::Result<String> {
        if blob.len() <= NONCE_LEN {
            bail!("ciphertext too short");
        }
        let (nonce, ct) = blob.split_at(NONCE_LEN);
        let pt = self
            .cipher
            .decrypt(&nonce_from(nonce)?, ct)
            .map_err(|_| anyhow::anyhow!("decryption failed (tampered blob or wrong key)"))?;
        String::from_utf8(pt).context("decrypted value is not UTF-8")
    }
}

fn fingerprint_of(key_bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(KEY_ID_DOMAIN);
    h.update(key_bytes);
    h.finalize()[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// The canary plaintext.
///
/// Its CONTENT does not matter and is never trusted — what matters is that
/// opening it requires the key that sealed it. It is stored in the metadata
/// database, so a restored metadata dump carries the question "which key was
/// this deployment using?" along with everything else.
pub const CANARY_PLAINTEXT: &str = "cryptarch-key-canary-v1";

/// Prove the loaded key is the one this deployment's data was sealed with, or
/// refuse to continue (CRYPTARCH-107).
///
/// First boot writes the canary; every later boot opens it. The check is
/// deliberately fatal rather than a warning: every downstream symptom of a
/// wrong key is either invisible (skipped servers, one log line) or actively
/// reassuring (backups that seal and verify against the same wrong key). A
/// warning would be one more thing reporting healthy.
///
/// A read failure is NOT fatal — that is a database problem, and refusing to
/// boot because the metadata pool hiccuped would turn a transient fault into an
/// outage. Only a canary that exists and does not open is fatal.
pub async fn verify_or_establish_canary(db: &sqlx::PgPool, crypto: &Crypto) -> anyhow::Result<()> {
    let existing: Option<(Vec<u8>, String)> =
        match sqlx::query_as("SELECT sealed, fingerprint FROM key_canary WHERE id")
            .fetch_optional(db)
            .await
        {
            Ok(row) => row,
            Err(e) => {
                tracing::error!("could not read the key canary: {e}");
                return Ok(());
            }
        };

    let Some((sealed, expected_fp)) = existing else {
        // An EMPTY canary table is not evidence of an empty deployment.
        //
        // This table is created by a migration, so it is empty on the first
        // boot of every EXISTING deployment too — which is precisely the boot
        // where an operator who has just restored a metadata dump might be
        // holding the wrong key. Establishing blindly there would seal the
        // canary with the wrong key, log "future boots will refuse a different
        // key", and make the mistake permanent and invisible: every later boot
        // would verify clean against a key that opens none of the real data.
        // The check would have manufactured the all-clear it exists to prevent.
        //
        // So: before claiming the deployment, ask whether it already has sealed
        // material, and whether this key opens it. `managed_servers` is the
        // right witness — every active server's admin DSN is sealed with the
        // at-rest key, and the registry is about to try decrypting them anyway.
        let sealed_dsns: Vec<Vec<u8>> =
            match sqlx::query_scalar("SELECT admin_dsn_enc FROM managed_servers")
                .fetch_all(db)
                .await
            {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::error!("could not check for existing sealed data: {e}");
                    return Ok(());
                }
            };

        if !sealed_dsns.is_empty() && !sealed_dsns.iter().any(|b| crypto.open(b).is_ok()) {
            bail!(
                "REFUSING TO START: this deployment already holds encrypted data, and the \
                 loaded key ({}) opens none of it.\n\
                 \n\
                 {} stored managed-server credential(s) were sealed with a different key. \
                 No key canary had been recorded yet, so Cryptarch cannot name the key it \
                 wants — but adopting this one would permanently mark the wrong key as \
                 correct and leave every existing backup blob unopenable while reporting \
                 healthy.\n\
                 \n\
                 Point CRYPTARCH_KEY_FILE at the key this deployment was using. If that key \
                 is genuinely lost, the stored credentials and blobs are unrecoverable; \
                 clear `managed_servers` deliberately to start over.",
                crypto.key_fingerprint(),
                sealed_dsns.len(),
            );
        }

        // `rows_affected` matters here (CRYPTARCH-107 review): two processes
        // booting concurrently on a fresh deployment both see None, and the
        // loser's INSERT no-ops on conflict. Treating that as "established"
        // would let it boot having verified nothing — so on a conflict, go back
        // and verify against whatever the winner wrote.
        let inserted = match sqlx::query(
            "INSERT INTO key_canary (id, sealed, fingerprint) VALUES (TRUE, $1, $2) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(crypto.seal(CANARY_PLAINTEXT).context("sealing the key canary")?)
        .bind(crypto.key_fingerprint())
        .execute(db)
        .await
        {
            Ok(r) => r.rows_affected(),
            Err(e) => {
                tracing::error!("could not record the key canary: {e}");
                return Ok(());
            }
        };

        if inserted == 0 {
            tracing::warn!("another process established the key canary first — verifying");
            return Box::pin(verify_or_establish_canary(db, crypto)).await;
        }

        tracing::info!(
            "key canary established for key {} — future boots will refuse a different key",
            crypto.key_fingerprint()
        );
        return Ok(());
    };

    match crypto.open(&sealed) {
        Ok(plain) if plain == CANARY_PLAINTEXT => {
            tracing::info!("at-rest key {} verified against the canary", crypto.key_fingerprint());
            Ok(())
        }
        // Opened, but not to what was sealed. Cannot happen with GCM short of a
        // forgery, so it is worth its own arm rather than being folded into the
        // failure below and reported as a wrong key.
        Ok(_) => bail!(
            "the key canary decrypted to unexpected content — the metadata database's \
             key_canary row has been tampered with"
        ),
        // The fingerprints AGREE and it still will not open. That is not a key
        // mismatch — it is damage to the `sealed` column. Distinguishing them
        // matters: told "wrong key", an operator goes hunting the password
        // manager for a key they are already holding, and cannot boot until
        // they work out that the search was pointless.
        Err(_) if expected_fp == crypto.key_fingerprint() => bail!(
            "REFUSING TO START: the key canary will not open, but the loaded key ({}) is \
             the one this deployment recorded.\n\
             \n\
             That means the canary row itself is damaged, NOT that the key is wrong — do \
             not go looking for a different key. Restore the metadata database, or delete \
             the `key_canary` row deliberately to re-establish it with this same key \
             (safe: the fingerprints already agree).",
            crypto.key_fingerprint()
        ),
        Err(_) => bail!(
            "REFUSING TO START: the at-rest key does not match this deployment's data.\n\
             \n\
             Loaded key fingerprint:   {}\n\
             This deployment was sealed with: {}\n\
             \n\
             Every stored managed-server credential and every backup blob was encrypted \
             with the second key. Booting on the first would leave those servers \
             unreachable and, worse, would keep taking backups that only the wrong key \
             can open — a full, verified-looking backup history containing nothing \
             recoverable.\n\
             \n\
             Point CRYPTARCH_KEY_FILE at the matching key. If it is genuinely lost, the \
             existing blobs and stored DSNs are unrecoverable and the canary row must be \
             deleted deliberately to start over.",
            crypto.key_fingerprint(),
            expected_fp
        ),
    }
}

/// Strict hex decode: ASCII hex digits only. Deliberately not
/// `u8::from_str_radix` per pair — that accepts `+7`, and byte-slicing a
/// non-ASCII string panics at char boundaries.
fn decode_hex(s: &str) -> anyhow::Result<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        bail!("odd-length hex");
    }
    b.chunks(2)
        .map(|pair| {
            let hi = hex_val(pair[0])?;
            let lo = hex_val(pair[1])?;
            Ok(hi << 4 | lo)
        })
        .collect()
}

fn hex_val(c: u8) -> anyhow::Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => bail!("invalid hex character"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: &str = "0101010101010101010101010101010101010101010101010101010101010101";
    const KEY_B: &str = "0202020202020202020202020202020202020202020202020202020202020202";

    #[test]
    fn roundtrip() {
        let c = Crypto::from_hex_key(KEY_A).unwrap();
        let blob = c.seal("postgres://admin:s3cret@10.0.0.5:5432/postgres").unwrap();
        assert_eq!(c.open(&blob).unwrap(), "postgres://admin:s3cret@10.0.0.5:5432/postgres");
    }

    #[test]
    fn roundtrip_empty_string() {
        let c = Crypto::from_hex_key(KEY_A).unwrap();
        let blob = c.seal("").unwrap();
        assert_eq!(c.open(&blob).unwrap(), "");
    }

    #[test]
    fn nonces_differ_per_seal() {
        let c = Crypto::from_hex_key(KEY_A).unwrap();
        let a = c.seal("same input").unwrap();
        let b = c.seal("same input").unwrap();
        assert_ne!(a, b, "two seals of the same plaintext must not produce identical blobs");
    }

    #[test]
    fn tampered_blob_fails() {
        let c = Crypto::from_hex_key(KEY_A).unwrap();
        let mut blob = c.seal("secret").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(c.open(&blob).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let a = Crypto::from_hex_key(KEY_A).unwrap();
        let b = Crypto::from_hex_key(KEY_B).unwrap();
        let blob = a.seal("secret").unwrap();
        assert!(b.open(&blob).is_err());
    }

    #[test]
    fn truncated_blob_fails() {
        let c = Crypto::from_hex_key(KEY_A).unwrap();
        let blob = c.seal("secret").unwrap();
        assert!(c.open(&blob[..NONCE_LEN]).is_err());
        assert!(c.open(&[]).is_err());
    }

    #[test]
    fn bad_keys_rejected() {
        assert!(Crypto::from_hex_key("deadbeef").is_err()); // too short
        assert!(Crypto::from_hex_key("zz").is_err()); // not hex
        assert!(Crypto::from_hex_key(&"ab".repeat(33)).is_err()); // too long
        assert!(Crypto::from_hex_key(&"+1".repeat(32)).is_err()); // radix-parse artifacts are not hex
        assert!(Crypto::from_hex_key(&"aé0".repeat(16)).is_err()); // non-ASCII must error, not panic
    }

    #[test]
    fn short_ciphertext_without_full_tag_fails() {
        let c = Crypto::from_hex_key(KEY_A).unwrap();
        let blob = c.seal("secret").unwrap();
        // nonce present but ciphertext shorter than the 16-byte GCM tag:
        // passes the length guard, must still fail in AEAD open.
        assert!(c.open(&blob[..NONCE_LEN + 8]).is_err());
    }

    #[test]
    fn key_file_roundtrip_with_trailing_newline() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir();
        let path = dir.join(format!("cryptarch-key-test-{}", std::process::id()));
        let mut f = std::fs::File::create(&path).unwrap();
        // openssl rand -hex 32 > file produces exactly this shape
        writeln!(f, "{KEY_A}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let c = Crypto::from_key_file(path.to_str().unwrap()).unwrap();
        let blob = c.seal("x").unwrap();
        assert_eq!(c.open(&blob).unwrap(), "x");

        // world-readable key must be refused
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Crypto::from_key_file(path.to_str().unwrap()).is_err());
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn missing_key_file_fails() {
        assert!(Crypto::from_key_file("/nonexistent/cryptarch.key").is_err());
    }

    // ---- CRYPTARCH-107: key identity ------------------------------------

    #[test]
    fn the_fingerprint_identifies_the_key_and_nothing_else() {
        let a = Crypto::from_hex_key(KEY_A).unwrap();
        let a2 = Crypto::from_hex_key(KEY_A).unwrap();
        let b = Crypto::from_hex_key(KEY_B).unwrap();

        // Stable across loads — otherwise it cannot be compared to a stored
        // value, which is its entire job.
        assert_eq!(a.key_fingerprint(), a2.key_fingerprint());
        // ...and different for a different key, which is the other half. A
        // constant would satisfy the line above on its own.
        assert_ne!(a.key_fingerprint(), b.key_fingerprint());

        assert_eq!(a.key_fingerprint().len(), 16, "8 bytes, hex");
        assert!(a.key_fingerprint().chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// The fingerprint is stored in the clear and shown in error messages, so
    /// it must not be a value the key can be read out of. Domain separation is
    /// what makes it a key *identifier* rather than a bare digest of secret
    /// material — this pins that the construction is not plain SHA-256(key).
    #[test]
    fn the_fingerprint_is_domain_separated() {
        use sha2::{Digest, Sha256};
        let key_bytes = decode_hex(KEY_A).unwrap();
        let bare: String = Sha256::digest(&key_bytes)[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let c = Crypto::from_hex_key(KEY_A).unwrap();
        assert_ne!(c.key_fingerprint(), bare, "must not be a bare hash of the key");
    }

    /// The canary is only worth having if the WRONG key fails to open it. The
    /// right-key case is asserted beside it, because a canary that nothing can
    /// open would satisfy the failure assertion while bricking every boot.
    #[test]
    fn the_canary_opens_only_under_the_key_that_sealed_it() {
        let a = Crypto::from_hex_key(KEY_A).unwrap();
        let b = Crypto::from_hex_key(KEY_B).unwrap();
        let sealed = a.seal(CANARY_PLAINTEXT).unwrap();

        assert_eq!(
            a.open(&sealed).unwrap(),
            CANARY_PLAINTEXT,
            "the sealing key must still open it, or every boot fails"
        );
        assert!(b.open(&sealed).is_err(), "a different key must not open the canary");
    }
}

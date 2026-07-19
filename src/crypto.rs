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

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use anyhow::{bail, Context};

const NONCE_LEN: usize = 12;

#[derive(Clone)]
pub struct Crypto {
    cipher: Aes256Gcm,
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
        let key = Key::<Aes256Gcm>::from_slice(&bytes);
        Ok(Self { cipher: Aes256Gcm::new(key) })
    }

    /// Encrypt a secret for storage. Fresh random nonce per call.
    pub fn seal(&self, plaintext: &str) -> anyhow::Result<Vec<u8>> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ct = self
            .cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|_| anyhow::anyhow!("encryption failed"))?;
        let mut blob = Vec::with_capacity(NONCE_LEN + ct.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        Ok(blob)
    }

    /// Decrypt a stored blob. Fails on tampering, truncation, or a wrong key.
    pub fn open(&self, blob: &[u8]) -> anyhow::Result<String> {
        if blob.len() <= NONCE_LEN {
            bail!("ciphertext too short");
        }
        let (nonce, ct) = blob.split_at(NONCE_LEN);
        let pt = self
            .cipher
            .decrypt(Nonce::from_slice(nonce), ct)
            .map_err(|_| anyhow::anyhow!("decryption failed (tampered blob or wrong key)"))?;
        String::from_utf8(pt).context("decrypted value is not UTF-8")
    }
}

/// Strict hex decode: ASCII hex digits only. Deliberately not
/// `u8::from_str_radix` per pair — that accepts `+7`, and byte-slicing a
/// non-ASCII string panics at char boundaries.
fn decode_hex(s: &str) -> anyhow::Result<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
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
}

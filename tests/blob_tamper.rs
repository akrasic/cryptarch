//! Adversarial tests for the sealed backup format.
//!
//! Provenance: the cross-file splice below was written by a reviewing agent
//! (crypt-2, 2026-07-20) as a probe that BROKE the v1 format. v1 authenticated
//! a frame's `index || last` but not the file it belonged to, and every blob on
//! a deployment is sealed under the same master key — so a terminator frame
//! harvested from any other backup forged a clean-opening truncated blob. The
//! probe is kept, with its assertion inverted, because the property it attacks
//! is the one the whole format exists to provide.
//!
//! Threat model throughout: an attacker with write access to the backup
//! directory and NO access to the key file. If that attacker were out of scope
//! the frame AAD would not need to exist at all.

use cryptarch::backup::{open_stream, seal_stream};
use cryptarch::crypto::Crypto;
use std::path::PathBuf;

const FRAME: usize = 1024 * 1024;

fn crypto() -> Crypto {
    Crypto::from_hex_key(&"ab".repeat(32)).unwrap()
}

fn tempdir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("cryptarch-tamper-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Split a v2 blob into (header, frames-with-their-length-prefixes).
fn frames(bytes: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let aux_len = u32::from_be_bytes(bytes[21..25].try_into().unwrap()) as usize;
    let header_len = 25 + aux_len;
    let header = bytes[..header_len].to_vec();
    let mut out = Vec::new();
    let mut i = header_len;
    while i < bytes.len() {
        let len = u32::from_be_bytes(bytes[i..i + 4].try_into().unwrap()) as usize;
        out.push(bytes[i..i + 4 + len].to_vec());
        i += 4 + len;
    }
    (header, out)
}

/// Truncate a backup and splice in a terminator frame taken from a DIFFERENT
/// backup sealed under the same key. In production the donor is simply an older
/// backup of any database, sitting in the same directory by design — retention
/// keeps seven per database.
///
/// This succeeded against v1. It must not succeed again.
#[tokio::test]
async fn cross_file_splice_cannot_forge_a_truncated_backup() {
    let dir = tempdir();
    let c = crypto();

    // Victim: three frames (0 and 1 full, 2 the terminator).
    let victim_path = dir.join("victim.enc");
    let victim_id = uuid::Uuid::new_v4();
    let victim_data: Vec<u8> = (0..FRAME * 2 + 500).map(|i| (i % 251) as u8).collect();
    seal_stream(&c, victim_id, &victim_data[..], &victim_path).await.unwrap();

    // Donor: a payload between 1 and 2 MiB, so it holds a frame sealed as
    // (index = 1, last = true) — the shape the forgery needs.
    let donor_path = dir.join("donor.enc");
    let donor_data: Vec<u8> = (0..FRAME + 10).map(|i| (i % 97) as u8).collect();
    seal_stream(&c, uuid::Uuid::new_v4(), &donor_data[..], &donor_path).await.unwrap();

    let (header, vframes) = frames(&std::fs::read(&victim_path).unwrap());
    let (_, dframes) = frames(&std::fs::read(&donor_path).unwrap());
    assert_eq!(vframes.len(), 3, "victim should be 3 frames");
    assert_eq!(dframes.len(), 2, "donor should be 2 frames");

    let mut forged = header;
    forged.extend_from_slice(&vframes[0]);
    forged.extend_from_slice(&dframes[1]);
    let forged_path = dir.join("forged.enc");
    std::fs::write(&forged_path, &forged).unwrap();

    let mut out = Vec::new();
    let err = open_stream(&c, victim_id, &forged_path, &mut out)
        .await
        .expect_err("a frame from another backup must not authenticate here");
    assert!(
        format!("{err:#}").contains("failed to decrypt"),
        "expected an authentication failure, got: {err:#}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Swapping one whole, internally valid blob for another is not something the
/// format can detect — the file is genuinely well-formed. What catches it is
/// the caller stating which backup it expects, checked against the id the file
/// carries. The metadata database is a different trust domain from the backup
/// mount, which is what makes that check worth anything.
#[tokio::test]
async fn whole_file_substitution_is_caught_by_the_expected_id() {
    let dir = tempdir();
    let c = crypto();

    let a_id = uuid::Uuid::new_v4();
    let b_id = uuid::Uuid::new_v4();
    let a_path = dir.join("a.enc");
    let b_path = dir.join("b.enc");
    seal_stream(&c, a_id, &b"database A"[..], &a_path).await.unwrap();
    seal_stream(&c, b_id, &b"database B"[..], &b_path).await.unwrap();

    // The attacker drops B's blob at A's path. It is a legitimately sealed
    // file; only the identity disagrees.
    std::fs::copy(&b_path, &a_path).unwrap();

    let mut out = Vec::new();
    let err = open_stream(&c, a_id, &a_path, &mut out)
        .await
        .expect_err("a different backup's blob must not open as this one");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("replaced or moved"),
        "error should name the substitution, got: {msg}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Rewriting the id in the header to match what the caller expects does not
/// help: every frame was sealed against the true header, so all of them fail.
#[tokio::test]
async fn rewriting_the_header_id_invalidates_every_frame() {
    let dir = tempdir();
    let c = crypto();

    let real_id = uuid::Uuid::new_v4();
    let wanted_id = uuid::Uuid::new_v4();
    let path = dir.join("blob.enc");
    seal_stream(&c, real_id, &b"some dump bytes"[..], &path).await.unwrap();

    let mut bytes = std::fs::read(&path).unwrap();
    bytes[5..21].copy_from_slice(wanted_id.as_bytes());
    std::fs::write(&path, &bytes).unwrap();

    let mut out = Vec::new();
    let err = open_stream(&c, wanted_id, &path, &mut out)
        .await
        .expect_err("frames must not authenticate under a rewritten header");
    assert!(
        format!("{err:#}").contains("failed to decrypt"),
        "expected an authentication failure, got: {err:#}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The length prefix is read before any key is involved, so it is attacker-
/// controlled input driving an allocation. Overcommit made this cheap rather
/// than fatal on the reviewer's machine, but a memory-capped container is less
/// forgiving, so it is bounded.
#[tokio::test]
async fn an_implausible_frame_length_is_rejected_before_it_is_allocated() {
    let dir = tempdir();
    let c = crypto();
    let id = uuid::Uuid::new_v4();
    let path = dir.join("blob.enc");
    seal_stream(&c, id, &b"small"[..], &path).await.unwrap();

    let mut bytes = std::fs::read(&path).unwrap();
    let header_len = 25 + u32::from_be_bytes(bytes[21..25].try_into().unwrap()) as usize;
    bytes[header_len..header_len + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    std::fs::write(&path, &bytes).unwrap();

    let mut out = Vec::new();
    let err = open_stream(&c, id, &path, &mut out).await.unwrap_err();
    assert!(
        format!("{err:#}").contains("implausible frame length"),
        "expected the length bound to reject it, got: {err:#}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A v1 blob must not open at all: v1 could not say which backup it was, which
/// is exactly what made the splice possible. Its reader is gone, so the version
/// check is what refuses it now.
#[tokio::test]
async fn v1_blobs_are_refused_rather_than_opened_with_a_warning() {
    let dir = tempdir();
    let c = crypto();
    let path = dir.join("legacy.enc");
    // A v1 header is magic + version byte; the frames after it are irrelevant
    // because the version check comes first.
    let mut bytes = b"CRBK\x01".to_vec();
    bytes.extend_from_slice(&[0u8; 64]);
    std::fs::write(&path, &bytes).unwrap();

    let mut out = Vec::new();
    let err = open_stream(&c, uuid::Uuid::new_v4(), &path, &mut out)
        .await
        .expect_err("v1 must not open through the normal path");
    assert!(
        format!("{err:#}").contains("unsupported backup format version 1"),
        "error should name the unsupported version, got: {err:#}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

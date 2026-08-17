//! The corruption suite.
//!
//! Every case here must fail **closed**, with a *distinguishable* typed error,
//! and must never leave plaintext on disk. This is the file to read first when
//! judging whether the format is trustworthy, and the file to extend first when
//! adding to it.

mod common;

use std::io::Cursor;

use common::*;
use xcrypt_core::header::{MAX_CHUNK_SIZE, MAX_HEADER_LEN, MIN_CHUNK_SIZE, PREAMBLE_LEN};
use xcrypt_core::{decrypt_with_passphrase, Error, Key};

// ---------------------------------------------------------------------------
// Bit flips
// ---------------------------------------------------------------------------

#[test]
fn flipping_any_bit_of_the_magic_is_detected() {
    let (master, c) = container(b"payload", CS);
    for byte in 0..4 {
        for bit in 0..8 {
            let corrupt = flip_bit(&c, byte, bit);
            assert!(
                matches!(decrypt(&corrupt, &master), Err(Error::BadMagic)),
                "magic byte {byte} bit {bit} was accepted"
            );
        }
    }
}

#[test]
fn flipping_any_bit_of_the_header_length_is_detected() {
    let (master, c) = container(b"payload", CS);
    for byte in 4..8 {
        for bit in 0..8 {
            let corrupt = flip_bit(&c, byte, bit);
            let err = decrypt(&corrupt, &master).expect_err("corrupt header length was accepted");
            assert!(
                matches!(
                    err,
                    Error::HeaderTooLarge { .. }
                        | Error::MalformedHeader
                        | Error::NonCanonicalHeader
                        | Error::UnsupportedVersion { .. }
                        | Error::InvalidChunkSize { .. }
                        | Error::InvalidHeaderField { .. }
                        | Error::Truncated { .. }
                        | Error::ChunkAuthFailed { .. }
                ),
                "length byte {byte} bit {bit} gave an unexpected error: {err}"
            );
        }
    }
}

/// Exhaustive over the header blob: every bit of every byte.
///
/// A header bit flip lands in one of two places — the encoding (caught by the
/// parser) or a value the AEAD authenticates (caught by the tag). There is no
/// third outcome, and no flip may yield plaintext.
#[test]
fn flipping_any_bit_of_the_header_body_is_detected() {
    let (master, c) = container(&plaintext(3 * CS as usize), CS);
    let range = header_range(&c);

    for byte in range {
        for bit in 0..8 {
            let corrupt = flip_bit(&c, byte, bit);
            let err = decrypt(&corrupt, &master)
                .expect_err(&format!("header byte {byte} bit {bit} was accepted"));
            assert!(
                !matches!(err, Error::Io { .. } | Error::BareIo(_)),
                "header byte {byte} bit {bit} produced an I/O error: {err}"
            );
        }
    }
}

#[test]
fn flipping_a_bit_in_a_middle_chunk_is_detected_at_that_chunk() {
    let (master, c) = container(&plaintext(3 * CS as usize + 10), CS);
    let start = body_start(&c);
    // Byte 5 of chunk 1 (the second chunk).
    let corrupt = flip_bit(&c, start + CT_CHUNK + 5, 3);
    assert!(matches!(
        decrypt(&corrupt, &master),
        Err(Error::ChunkAuthFailed { index: 1 })
    ));
}

#[test]
fn flipping_a_bit_in_the_final_chunk_is_detected() {
    let (master, c) = container(&plaintext(3 * CS as usize + 10), CS);
    let corrupt = flip_bit(&c, c.len() - 20, 0);
    assert!(matches!(
        decrypt(&corrupt, &master),
        Err(Error::ChunkAuthFailed { index: 3 })
    ));
}

#[test]
fn flipping_a_bit_in_any_authentication_tag_is_detected() {
    let (master, c) = container(&plaintext(2 * CS as usize + 1), CS);
    let start = body_start(&c);
    // Interior chunk tags, then the final chunk's tag (the last 16 bytes).
    let tag_offsets = [
        start + CS as usize,
        start + CT_CHUNK + CS as usize,
        c.len() - 16,
    ];
    for offset in tag_offsets {
        for bit in 0..8 {
            let corrupt = flip_bit(&c, offset, bit);
            assert!(
                matches!(
                    decrypt(&corrupt, &master),
                    Err(Error::ChunkAuthFailed { .. })
                ),
                "tag byte {offset} bit {bit} was accepted"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Truncation
// ---------------------------------------------------------------------------

#[test]
fn truncation_mid_preamble_is_detected() {
    let (master, c) = container(b"payload", CS);
    for len in 0..PREAMBLE_LEN {
        let err = decrypt(&c[..len], &master).expect_err("short preamble was accepted");
        assert!(
            matches!(err, Error::Truncated { .. } | Error::BadMagic),
            "length {len} gave {err}"
        );
    }
}

#[test]
fn truncation_mid_header_is_detected() {
    let (master, c) = container(b"payload", CS);
    let range = header_range(&c);
    for len in range.start..range.end {
        assert!(
            matches!(decrypt(&c[..len], &master), Err(Error::Truncated { .. })),
            "header truncated to {len} bytes was accepted"
        );
    }
}

#[test]
fn truncation_with_no_chunks_at_all_is_detected() {
    let (master, c) = container(b"payload", CS);
    let end = body_start(&c);
    assert!(matches!(
        decrypt(&c[..end], &master),
        Err(Error::Truncated { .. })
    ));
}

#[test]
fn truncation_at_a_chunk_boundary_is_detected() {
    // Four chunks; keep the first two whole and drop the rest. The second chunk
    // then looks like a final chunk, and the flag bit says otherwise.
    let (master, c) = container(&plaintext(4 * CS as usize), CS);
    let end = body_start(&c) + 2 * CT_CHUNK;
    let err = decrypt(&c[..end], &master).expect_err("boundary truncation was accepted");
    assert!(
        matches!(err, Error::ChunkAuthFailed { index: 1 }),
        "got {err}"
    );
}

#[test]
fn truncation_mid_chunk_is_detected() {
    let (master, c) = container(&plaintext(3 * CS as usize), CS);
    let end = body_start(&c) + CT_CHUNK + 100;
    let err = decrypt(&c[..end], &master).expect_err("mid-chunk truncation was accepted");
    assert!(
        matches!(err, Error::ChunkAuthFailed { index: 1 }),
        "got {err}"
    );
}

#[test]
fn dropping_the_final_chunk_entirely_is_detected() {
    let data = plaintext(3 * CS as usize + 77);
    let (master, c) = container(&data, CS);
    // The final chunk is short: strip exactly it.
    let final_len = 77 + 16;
    let err = decrypt(&c[..c.len() - final_len], &master)
        .expect_err("dropping the final chunk was accepted");
    assert!(
        matches!(err, Error::ChunkAuthFailed { index: 2 }),
        "got {err}"
    );
}

#[test]
fn truncating_the_final_tag_is_detected() {
    let (master, c) = container(b"short payload", CS);
    for drop in 1..=16 {
        let err =
            decrypt(&c[..c.len() - drop], &master).expect_err("a truncated final tag was accepted");
        assert!(
            matches!(err, Error::ChunkAuthFailed { .. } | Error::Truncated { .. }),
            "dropping {drop} bytes gave {err}"
        );
    }
}

#[test]
fn appending_garbage_is_detected() {
    let (master, c) = container(b"payload", CS);
    let mut corrupt = c.clone();
    corrupt.extend_from_slice(&[0u8; 32]);
    assert!(decrypt(&corrupt, &master).is_err());

    let mut corrupt = c.clone();
    corrupt.extend_from_slice(&[0u8; 3]);
    assert!(decrypt(&corrupt, &master).is_err());
}

// ---------------------------------------------------------------------------
// Chunk shuffling and splicing
// ---------------------------------------------------------------------------

#[test]
fn reordering_two_chunks_is_detected() {
    let (master, c) = container(&plaintext(4 * CS as usize), CS);
    let start = body_start(&c);
    let mut corrupt = c.clone();
    for i in 0..CT_CHUNK {
        corrupt.swap(start + i, start + CT_CHUNK + i);
    }
    assert!(matches!(
        decrypt(&corrupt, &master),
        Err(Error::ChunkAuthFailed { index: 0 })
    ));
}

#[test]
fn duplicating_a_chunk_is_detected() {
    let (master, c) = container(&plaintext(4 * CS as usize), CS);
    let start = body_start(&c);
    let mut corrupt = c.clone();
    // Overwrite chunk 1 with a copy of chunk 0.
    let chunk0 = c[start..start + CT_CHUNK].to_vec();
    corrupt[start + CT_CHUNK..start + 2 * CT_CHUNK].copy_from_slice(&chunk0);
    assert!(matches!(
        decrypt(&corrupt, &master),
        Err(Error::ChunkAuthFailed { index: 1 })
    ));
}

#[test]
fn inserting_an_extra_copy_of_a_chunk_is_detected() {
    let (master, c) = container(&plaintext(3 * CS as usize), CS);
    let start = body_start(&c);
    let mut corrupt = c[..start + CT_CHUNK].to_vec();
    corrupt.extend_from_slice(&c[start..start + CT_CHUNK]);
    corrupt.extend_from_slice(&c[start + CT_CHUNK..]);
    assert!(matches!(
        decrypt(&corrupt, &master),
        Err(Error::ChunkAuthFailed { index: 1 })
    ));
}

#[test]
fn splicing_a_chunk_from_another_container_is_detected() {
    let data = plaintext(4 * CS as usize);
    let (master, c) = container(&data, CS);
    // A second container under the *same* key: only file_id and nonce prefix
    // differ, which must be enough.
    let mut other = Vec::new();
    xcrypt_core::encrypt_stream(
        &mut Cursor::new(&data),
        &mut other,
        &master,
        xcrypt_core::ContainerKind::File,
        CS,
        None,
    )
    .unwrap();

    let start = body_start(&c);
    let other_start = body_start(&other);
    let mut corrupt = c.clone();
    corrupt[start + CT_CHUNK..start + 2 * CT_CHUNK]
        .copy_from_slice(&other[other_start + CT_CHUNK..other_start + 2 * CT_CHUNK]);

    assert!(matches!(
        decrypt(&corrupt, &master),
        Err(Error::ChunkAuthFailed { index: 1 })
    ));
}

// ---------------------------------------------------------------------------
// Header substitution
// ---------------------------------------------------------------------------

#[test]
fn swapping_headers_between_archives_under_one_passphrase_is_detected() {
    let a = container_with_keyring(&plaintext(2 * CS as usize), "same passphrase", CS);
    let b = container_with_keyring(&plaintext(2 * CS as usize), "same passphrase", CS);

    // Graft a's header onto b's body. The keyring still opens — same passphrase —
    // so the master key is recovered and only the AAD binding stands between the
    // attacker and a decrypt.
    let mut forged = a[..body_start(&a)].to_vec();
    forged.extend_from_slice(&b[body_start(&b)..]);

    let err = decrypt_with_passphrase(
        &mut Cursor::new(&forged),
        &mut Vec::new(),
        &pass("same passphrase"),
        &policy(),
    )
    .expect_err("a grafted header was accepted");
    assert!(
        matches!(err, Error::ChunkAuthFailed { index: 0 }),
        "got {err}"
    );
}

#[test]
fn rewriting_the_file_id_is_detected() {
    let (master, c) = container(&plaintext(2 * CS as usize), CS);
    let forged = replace_header(&c, |h| h.file_id = [0xAB; 16]);
    assert!(matches!(
        decrypt(&forged, &master),
        Err(Error::ChunkAuthFailed { index: 0 })
    ));
}

#[test]
fn rewriting_the_nonce_prefix_is_detected() {
    let (master, c) = container(&plaintext(2 * CS as usize), CS);
    let forged = replace_header(&c, |h| h.nonce_prefix = [0xCD; 19]);
    assert!(matches!(
        decrypt(&forged, &master),
        Err(Error::ChunkAuthFailed { index: 0 })
    ));
}

#[test]
fn rewriting_the_chunk_size_is_detected() {
    let (master, c) = container(&plaintext(4 * CS as usize), CS);
    // In range, so the parser accepts it; the AAD binding must catch it.
    let forged = replace_header(&c, |h| h.chunk_size = MIN_CHUNK_SIZE * 2);
    let err = decrypt(&forged, &master).expect_err("a rewritten chunk size was accepted");
    assert!(matches!(err, Error::ChunkAuthFailed { .. }), "got {err}");
}

// ---------------------------------------------------------------------------
// Resource-exhaustion guards
// ---------------------------------------------------------------------------

#[test]
fn an_absurd_header_length_is_rejected_without_allocating() {
    let (master, c) = container(b"payload", CS);
    let mut corrupt = c.clone();
    corrupt[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        decrypt(&corrupt, &master),
        Err(Error::HeaderTooLarge { .. })
    ));

    corrupt[4..8].copy_from_slice(&(MAX_HEADER_LEN + 1).to_le_bytes());
    assert!(matches!(
        decrypt(&corrupt, &master),
        Err(Error::HeaderTooLarge { .. })
    ));
}

#[test]
fn an_absurd_chunk_size_is_rejected_before_buffering() {
    let (master, c) = container(b"payload", CS);
    for size in [0, 1, MIN_CHUNK_SIZE - 1, MAX_CHUNK_SIZE + 1, u32::MAX] {
        let forged = replace_header(&c, |h| h.chunk_size = size);
        assert!(
            matches!(
                decrypt(&forged, &master),
                Err(Error::InvalidChunkSize { .. })
            ),
            "chunk size {size} was accepted"
        );
    }
}

#[test]
fn an_absurd_kdf_cost_is_rejected_before_hashing() {
    let c = container_with_keyring(b"payload", "pw", CS);
    let forged = replace_header(&c, |h| {
        h.keyring.as_mut().unwrap().kdf.m_cost_kib = u32::MAX;
    });
    let err = decrypt_with_passphrase(
        &mut Cursor::new(&forged),
        &mut Vec::new(),
        &pass("pw"),
        &policy(),
    )
    .expect_err("an absurd memory cost was accepted");
    assert!(matches!(err, Error::KdfParamsRejected { .. }), "got {err}");
}

// ---------------------------------------------------------------------------
// Credential failures
// ---------------------------------------------------------------------------

#[test]
fn a_wrong_passphrase_is_reported_as_such() {
    let c = container_with_keyring(b"payload", "right", CS);
    let err = decrypt_with_passphrase(
        &mut Cursor::new(&c),
        &mut Vec::new(),
        &pass("wrong"),
        &policy(),
    )
    .expect_err("the wrong passphrase was accepted");
    assert!(matches!(err, Error::NoMatchingRecipient), "got {err}");
}

#[test]
fn a_kdf_cost_downgrade_is_rejected_rather_than_honored() {
    // Written at a real cost, then downgraded to something brute-forceable.
    let (keyring, master) =
        xcrypt_core::new_keyring(&pass("pw"), 32 * 1024, 3, 1, &policy()).unwrap();
    let mut c = Vec::new();
    xcrypt_core::encrypt_stream(
        &mut Cursor::new(b"payload"),
        &mut c,
        &master,
        xcrypt_core::ContainerKind::Manifest,
        CS,
        Some(keyring),
    )
    .unwrap();

    let forged = replace_header(&c, |h| {
        let kdf = &mut h.keyring.as_mut().unwrap().kdf;
        kdf.m_cost_kib = 8;
        kdf.t_cost = 1;
    });

    let err = decrypt_with_passphrase(
        &mut Cursor::new(&forged),
        &mut Vec::new(),
        &pass("pw"),
        &xcrypt_core::KdfPolicy::default(),
    )
    .expect_err("a downgraded KDF cost was accepted");
    assert!(matches!(err, Error::KdfParamsRejected { .. }), "got {err}");
}

#[test]
fn tampered_in_policy_kdf_params_break_the_wrap() {
    let (keyring, master) =
        xcrypt_core::new_keyring(&pass("pw"), 32 * 1024, 3, 1, &policy()).unwrap();
    let mut c = Vec::new();
    xcrypt_core::encrypt_stream(
        &mut Cursor::new(b"payload"),
        &mut c,
        &master,
        xcrypt_core::ContainerKind::Manifest,
        CS,
        Some(keyring),
    )
    .unwrap();

    // Still inside the permissive policy, so the failure must come from the AAD
    // binding on the key wrap rather than from a bounds check.
    let forged = replace_header(&c, |h| {
        h.keyring.as_mut().unwrap().kdf.t_cost = 2;
    });

    let err = decrypt_with_passphrase(
        &mut Cursor::new(&forged),
        &mut Vec::new(),
        &pass("pw"),
        &policy(),
    )
    .expect_err("tampered KDF parameters were accepted");
    assert!(matches!(err, Error::NoMatchingRecipient), "got {err}");
}

#[test]
fn a_container_without_a_keyring_cannot_be_opened_by_passphrase() {
    let (_, c) = container(b"payload", CS);
    let err = decrypt_with_passphrase(
        &mut Cursor::new(&c),
        &mut Vec::new(),
        &pass("anything"),
        &policy(),
    )
    .expect_err("a keyring-less container was opened by passphrase");
    assert!(matches!(err, Error::InvalidHeaderField { .. }), "got {err}");
}

// ---------------------------------------------------------------------------
// No partial plaintext on disk
// ---------------------------------------------------------------------------

/// The guarantee users actually care about: a failed decrypt leaves nothing
/// behind, even though the AEAD releases earlier chunks before the corrupt one
/// is reached.
#[test]
fn a_failed_decrypt_writes_no_plaintext_to_disk() {
    let data = plaintext(4 * CS as usize);
    let (master, c) = container(&data, CS);

    // Corrupt the *last* chunk, so three chunks authenticate first.
    let corrupt = flip_bit(&c, c.len() - 1, 0);

    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("recovered");

    let err = xcrypt_core::fsutil::atomic_write(&target, false, |file| {
        xcrypt_core::decrypt_with_master(&mut Cursor::new(&corrupt), file, &master).map(|_| ())
    })
    .expect_err("a corrupt container produced a file");

    assert!(matches!(err, Error::ChunkAuthFailed { .. }), "got {err}");
    assert!(!target.exists(), "partial plaintext was left at the target");
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        0,
        "a temporary file with partial plaintext survived"
    );
}

#[test]
fn a_wrong_key_writes_no_plaintext_to_disk() {
    let (_, c) = container(&plaintext(2 * CS as usize), CS);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("recovered");

    let wrong = Key::random();
    assert!(xcrypt_core::fsutil::atomic_write(&target, false, |file| {
        xcrypt_core::decrypt_with_master(&mut Cursor::new(&c), file, &wrong).map(|_| ())
    })
    .is_err());
    assert!(!target.exists());
}

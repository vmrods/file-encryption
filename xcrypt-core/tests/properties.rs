//! Property tests: round-trip fidelity, and fail-closed behaviour under
//! arbitrary damage.
//!
//! Sizes are kept modest so the suite stays fast; the boundary cases that matter
//! (`0`, `1`, `n-1`, `n`, `n+1`, `3n`) are enumerated explicitly rather than left
//! to chance, and multi-megabyte round trips live in the unit tests.

mod common;

use std::io::Cursor;

use common::*;
use proptest::prelude::*;
use xcrypt_core::{decrypt_with_passphrase, Error, MIN_CHUNK_SIZE};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Whatever the content and whatever the chunk size, plaintext survives.
    #[test]
    fn roundtrip_preserves_content(
        data in prop::collection::vec(any::<u8>(), 0..20_000),
        chunk_size in MIN_CHUNK_SIZE..4096u32,
    ) {
        let (master, c) = container(&data, chunk_size);
        prop_assert_eq!(decrypt(&c, &master).unwrap(), data);
    }

    /// Corrupting any single byte anywhere is always caught. Never a wrong
    /// plaintext, never a panic, never a hang.
    #[test]
    fn any_single_byte_corruption_fails_closed(
        data in prop::collection::vec(any::<u8>(), 0..5_000),
        delta in 1u8..=255,
        position in 0.0f64..1.0,
    ) {
        let (master, c) = container(&data, MIN_CHUNK_SIZE);
        let index = ((c.len() as f64 * position) as usize).min(c.len() - 1);

        let mut corrupt = c.clone();
        corrupt[index] ^= delta;

        match decrypt(&corrupt, &master) {
            // A tolerated mutation is only acceptable if it changed nothing that
            // is authenticated — which cannot happen, since every byte of the
            // container is either the header (AAD) or ciphertext.
            Ok(out) => prop_assert!(false, "corruption at {} was accepted, {} bytes out", index, out.len()),
            Err(Error::Io { .. }) | Err(Error::BareIo(_)) => {
                prop_assert!(false, "corruption at {} produced an I/O error", index)
            }
            Err(_) => {}
        }
    }

    /// Truncating anywhere is always caught.
    #[test]
    fn any_truncation_fails_closed(
        data in prop::collection::vec(any::<u8>(), 0..5_000),
        position in 0.0f64..1.0,
    ) {
        let (master, c) = container(&data, MIN_CHUNK_SIZE);
        let len = ((c.len() as f64 * position) as usize).min(c.len() - 1);
        prop_assert!(decrypt(&c[..len], &master).is_err(), "truncation to {} bytes was accepted", len);
    }

    /// Extending a container is always caught.
    #[test]
    fn any_extension_fails_closed(
        data in prop::collection::vec(any::<u8>(), 0..2_000),
        extra in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        let (master, c) = container(&data, MIN_CHUNK_SIZE);
        let mut extended = c.clone();
        extended.extend_from_slice(&extra);
        prop_assert!(decrypt(&extended, &master).is_err());
    }

    /// Arbitrary passphrases round-trip — empty, very long, non-ASCII, embedded
    /// NULs, whitespace that a naive prompt would trim.
    #[test]
    fn arbitrary_passphrases_roundtrip(
        passphrase in "\\PC{0,64}",
        data in prop::collection::vec(any::<u8>(), 0..3_000),
    ) {
        let c = container_with_keyring(&data, &passphrase, MIN_CHUNK_SIZE);

        let mut out = Vec::new();
        decrypt_with_passphrase(&mut Cursor::new(&c), &mut out, &pass(&passphrase), &policy())
            .map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(out, data);
    }

    /// A different passphrase never opens an archive.
    #[test]
    fn wrong_passphrases_never_open(
        right in "\\PC{0,32}",
        wrong in "\\PC{0,32}",
    ) {
        prop_assume!(right != wrong);
        let c = container_with_keyring(b"payload", &right, MIN_CHUNK_SIZE);
        let err = decrypt_with_passphrase(
            &mut Cursor::new(&c),
            &mut Vec::new(),
            &pass(&wrong),
            &policy(),
        )
        .expect_err("a wrong passphrase opened the archive");
        prop_assert!(matches!(err, Error::NoMatchingRecipient));
    }

    /// Arbitrary bytes handed to the reader must never panic. The fuzz targets
    /// cover this far more thoroughly; this keeps a cheap version in `cargo test`.
    #[test]
    fn arbitrary_input_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..2_000)) {
        let master = xcrypt_core::Key::random();
        let _ = decrypt(&bytes, &master);
    }

    /// Arbitrary bytes with a *valid* preamble — reaches deeper into the parser
    /// than random noise, which almost never gets past the magic check.
    #[test]
    fn arbitrary_header_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..2_000)) {
        let mut input = xcrypt_core::MAGIC.to_vec();
        input.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        input.extend_from_slice(&bytes);

        let master = xcrypt_core::Key::random();
        let _ = decrypt(&input, &master);
    }
}

/// Every documented boundary size, at several chunk sizes, deterministically.
#[test]
fn boundary_sizes_roundtrip_exactly() {
    for chunk_size in [MIN_CHUNK_SIZE, 1500, 4096, xcrypt_core::DEFAULT_CHUNK_SIZE] {
        let cs = chunk_size as usize;
        for len in [0, 1, cs - 1, cs, cs + 1, 2 * cs, 3 * cs, 3 * cs + 1] {
            let data = plaintext(len);
            let (master, c) = container(&data, chunk_size);
            assert_eq!(
                decrypt(&c, &master).unwrap(),
                data,
                "len {len} at chunk size {chunk_size}"
            );
        }
    }
}

/// Two encryptions of identical plaintext under the same key share no
/// ciphertext: `file_id` and the nonce prefix are fresh each time.
#[test]
fn identical_plaintext_produces_unrelated_containers() {
    let data = plaintext(4 * MIN_CHUNK_SIZE as usize);
    let master = xcrypt_core::Key::random();

    let mut a = Vec::new();
    let mut b = Vec::new();
    for out in [&mut a, &mut b] {
        xcrypt_core::encrypt_stream(
            &mut Cursor::new(&data),
            out,
            &master,
            xcrypt_core::ContainerKind::File,
            MIN_CHUNK_SIZE,
            None,
        )
        .unwrap();
    }

    assert_eq!(a.len(), b.len());
    assert_ne!(a[body_start(&a)..], b[body_start(&b)..]);
}

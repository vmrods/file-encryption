//! Shared helpers for the integration suites.
//!
//! Kept deliberately small: the tests are the specification of the failure
//! modes, so they should read as directly as possible.

#![allow(dead_code)]

use std::io::Cursor;

use xcrypt_core::header::PREAMBLE_LEN;
use xcrypt_core::keys::new_keyring;
use xcrypt_core::stream::TAG_LEN;
use xcrypt_core::{
    decrypt_with_master, encrypt_stream, ContainerKind, Error, Header, KdfPolicy, Key, Passphrase,
};

/// Chunk size used by most tests: the smallest legal one, so multi-chunk cases
/// stay small enough to be exhaustive.
pub const CS: u32 = xcrypt_core::MIN_CHUNK_SIZE;

/// Ciphertext bytes per full chunk.
pub const CT_CHUNK: usize = CS as usize + TAG_LEN;

/// Cheap Argon2 costs. Only ever paired with [`policy`].
pub const M: u32 = 8;
/// Cheap Argon2 iteration count.
pub const T: u32 = 1;
/// Cheap Argon2 parallelism.
pub const P: u32 = 1;

/// A policy with no cost floor, so tests do not burn 256 MiB per case.
pub fn policy() -> KdfPolicy {
    KdfPolicy::permissive()
}

/// A passphrase from a string literal.
pub fn pass(s: &str) -> Passphrase {
    Passphrase::new(s.to_owned())
}

/// Deterministic pseudo-random plaintext of a given length.
pub fn plaintext(len: usize) -> Vec<u8> {
    // A simple LCG: reproducible, and not compressible enough to hide a bug.
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u8
        })
        .collect()
}

/// Encrypt `data` into a container keyed directly by a fresh master key.
pub fn container(data: &[u8], chunk_size: u32) -> (Key, Vec<u8>) {
    let master = Key::random();
    let mut out = Vec::new();
    encrypt_stream(
        &mut Cursor::new(data),
        &mut out,
        &master,
        ContainerKind::File,
        chunk_size,
        None,
    )
    .expect("encryption of well-formed input must succeed");
    (master, out)
}

/// Encrypt `data` into a root container carrying a passphrase keyring.
pub fn container_with_keyring(data: &[u8], passphrase: &str, chunk_size: u32) -> Vec<u8> {
    let (keyring, master) =
        new_keyring(&pass(passphrase), M, T, P, &policy()).expect("keyring creation must succeed");
    let mut out = Vec::new();
    encrypt_stream(
        &mut Cursor::new(data),
        &mut out,
        &master,
        ContainerKind::Manifest,
        chunk_size,
        Some(keyring),
    )
    .expect("encryption of well-formed input must succeed");
    out
}

/// Decrypt a container into memory.
pub fn decrypt(container: &[u8], master: &Key) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    decrypt_with_master(&mut Cursor::new(container), &mut out, master)?;
    Ok(out)
}

/// Byte range of the header blob (the AAD) inside a container.
pub fn header_range(container: &[u8]) -> std::ops::Range<usize> {
    let len = u32::from_le_bytes(container[4..8].try_into().unwrap()) as usize;
    PREAMBLE_LEN..PREAMBLE_LEN + len
}

/// Offset of the first chunk byte.
pub fn body_start(container: &[u8]) -> usize {
    header_range(container).end
}

/// Flip a single bit, returning the mutated copy.
pub fn flip_bit(container: &[u8], byte: usize, bit: u8) -> Vec<u8> {
    let mut out = container.to_vec();
    out[byte] ^= 1 << bit;
    out
}

/// Re-encode `container` with a mutated header, keeping the body untouched.
///
/// Used for cases that must produce a *structurally valid but wrong* header —
/// bit flips cannot reliably do that.
pub fn replace_header(container: &[u8], mutate: impl FnOnce(&mut Header)) -> Vec<u8> {
    let parsed = Header::read_from(&mut Cursor::new(container)).expect("header must parse");
    let mut header = parsed.header.clone();
    mutate(&mut header);
    let aad = header.encode().expect("mutated header must encode");

    let mut out = Vec::new();
    out.extend_from_slice(&xcrypt_core::MAGIC);
    out.extend_from_slice(&(aad.len() as u32).to_le_bytes());
    out.extend_from_slice(&aad);
    out.extend_from_slice(&container[body_start(container)..]);
    out
}

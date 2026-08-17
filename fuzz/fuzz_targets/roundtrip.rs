//! Fuzz the *happy* path: whatever the plaintext and chunk size, a container
//! must decrypt back to exactly what went in.
//!
//! This is the target that catches chunk-boundary bugs, which are the kind of
//! defect a corruption-only fuzzer will never find.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use xcrypt_core::header::{MAX_CHUNK_SIZE, MIN_CHUNK_SIZE};
use xcrypt_core::{decrypt_with_master, encrypt_stream, ContainerKind, Key};

#[derive(Arbitrary, Debug)]
struct Input {
    chunk_size: u32,
    plaintext: Vec<u8>,
}

fuzz_target!(|input: Input| {
    // Keep the chunk size legal and small enough to stay fast.
    let chunk_size =
        MIN_CHUNK_SIZE + (input.chunk_size % (MAX_CHUNK_SIZE.min(64 * 1024) - MIN_CHUNK_SIZE + 1));

    let key = Key::new([7u8; 32]);
    let mut container = Vec::new();
    let stats = encrypt_stream(
        &mut &input.plaintext[..],
        &mut container,
        &key,
        ContainerKind::File,
        chunk_size,
        None,
    )
    .expect("encrypting in-memory bytes cannot fail");

    assert_eq!(stats.plaintext_len, input.plaintext.len() as u64);
    assert!(stats.chunks >= 1, "every container has a final chunk");

    let mut recovered = Vec::new();
    decrypt_with_master(&mut &container[..], &mut recovered, &key)
        .expect("a container this build wrote must decrypt");
    assert_eq!(recovered, input.plaintext, "round trip lost data");
});

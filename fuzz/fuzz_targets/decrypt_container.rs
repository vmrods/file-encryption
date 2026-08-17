//! Fuzz the full decrypt path with a fixed key.
//!
//! Arbitrary input must never panic, never index out of bounds, never allocate
//! more than the declared (and bounded) chunk size, and never report success:
//! producing a valid container by chance is cryptographically impossible, so any
//! `Ok` here is a bug in the authentication path.

#![no_main]

use libfuzzer_sys::fuzz_target;
use xcrypt_core::{decrypt_with_master, Key};

fuzz_target!(|data: &[u8]| {
    // A fixed key: the fuzzer cannot guess it, so success is not a legal outcome.
    let key = Key::new([0x42; 32]);

    let mut out = Vec::new();
    if decrypt_with_master(&mut &data[..], &mut out, &key).is_ok() {
        panic!("arbitrary input authenticated as a valid container");
    }
});

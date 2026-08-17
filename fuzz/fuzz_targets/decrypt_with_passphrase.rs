//! Fuzz the keyring path: header parsing, KDF policy checks, and key unwrapping.
//!
//! The KDF cost is bounded by the policy, which is what keeps this target fast
//! enough to be useful — and a target that hangs is a finding in itself, because
//! it means a hostile header can make a real decrypt hang too.

#![no_main]

use libfuzzer_sys::fuzz_target;
use xcrypt_core::{decrypt_with_passphrase, KdfPolicy, Passphrase};

fuzz_target!(|data: &[u8]| {
    let passphrase = Passphrase::new("fuzz".to_owned());
    // Permissive bounds so the fuzzer can reach the unwrap logic, but still
    // bounded: an unbounded m_cost would be a memory-exhaustion oracle.
    let policy = KdfPolicy::permissive();

    let mut out = Vec::new();
    if decrypt_with_passphrase(&mut &data[..], &mut out, &passphrase, &policy).is_ok() {
        panic!("arbitrary input opened under a fixed passphrase");
    }
});

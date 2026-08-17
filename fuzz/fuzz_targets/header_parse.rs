//! Fuzz the header parser against arbitrary bytes.
//!
//! Invariants: never panic, never allocate unboundedly, and never accept a
//! header whose re-encoding differs from its input (the canonicality rule the
//! AAD binding depends on).

#![no_main]

use libfuzzer_sys::fuzz_target;
use xcrypt_core::header::{Header, MAX_HEADER_LEN};

fuzz_target!(|data: &[u8]| {
    // The whole-container entry point: magic and length field included.
    let _ = Header::read_from(&mut &data[..]);

    // The header blob on its own, which reaches the postcard decoder directly.
    if data.len() <= MAX_HEADER_LEN as usize {
        if let Ok(parsed) = Header::parse(data) {
            // Accepted input must be exactly canonical, or the AAD could be
            // mutated without changing the header's meaning.
            assert_eq!(parsed.aad, data, "a non-canonical header was accepted");
            let reencoded = parsed
                .header
                .encode()
                .expect("a parsed header must re-encode");
            assert_eq!(reencoded, parsed.aad, "encode/parse are not inverses");
        }
    }
});

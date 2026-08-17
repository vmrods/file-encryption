//! Fuzz manifest decoding and, critically, path validation.
//!
//! Any path a decoded manifest yields must be strictly relative: no `..`, no
//! absolute root, no embedded separators. A manifest that decodes but produces
//! an escaping path would let a malicious archive write anywhere on disk.

#![no_main]

use std::path::Component;

use libfuzzer_sys::fuzz_target;
use xcrypt_core::Manifest;

fuzz_target!(|data: &[u8]| {
    if let Ok(manifest) = Manifest::decode(data) {
        for entry in &manifest.entries {
            let path = entry
                .to_relative_path()
                .expect("decode validated every path already");
            assert!(path.is_relative(), "decoded an absolute path: {path:?}");
            for component in path.components() {
                assert!(
                    matches!(component, Component::Normal(_)),
                    "decoded a traversal component: {path:?}"
                );
            }
        }
        // Re-encoding must round-trip, or the validation ran on different bytes
        // than the ones that will be stored.
        let reencoded = manifest
            .encode()
            .expect("a decoded manifest must re-encode");
        assert_eq!(
            Manifest::decode(&reencoded).ok().as_ref(),
            Some(&manifest),
            "manifest encode/decode are not inverses"
        );
    }
});

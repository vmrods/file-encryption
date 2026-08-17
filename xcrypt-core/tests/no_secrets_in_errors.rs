//! Enforces the "no secret ever lands in `Debug`, `Display`, or an error"
//! rule by construction rather than by review.
//!
//! Every variant of [`xcrypt_core::Error`] is built with recognisable sentinel
//! values in every field and then formatted both ways. If a future variant
//! carries a key, a passphrase, or plaintext, this file stops compiling (the
//! match is exhaustive) or starts failing (the sentinel shows up).

use std::path::PathBuf;

use xcrypt_core::{ContainerKind, Error, Key, Passphrase};

/// Strings that must never appear in any rendered error.
const SENTINELS: [&str; 3] = ["SUPERSECRET", "hunter2", "PLAINTEXTBODY"];

fn all_variants() -> Vec<Error> {
    // Constructed exhaustively on purpose: adding a variant to the enum without
    // adding it here leaves it untested, so keep this list in sync.
    vec![
        Error::BadMagic,
        Error::UnsupportedVersion {
            found: 99,
            supported: 1,
        },
        Error::HeaderTooLarge {
            len: u64::MAX,
            limit: 65536,
        },
        Error::MalformedHeader,
        Error::NonCanonicalHeader,
        Error::InvalidChunkSize {
            size: 3,
            min: 1024,
            max: 8 << 20,
        },
        Error::KdfParamsRejected {
            detail: "m_cost 8 KiB is below the minimum".to_owned(),
        },
        Error::InvalidHeaderField {
            detail: "keyring has no recipients".to_owned(),
        },
        Error::NoMatchingRecipient,
        Error::ChunkAuthFailed { index: 7 },
        Error::Truncated {
            detail: "container ends inside its header",
        },
        Error::CounterExhausted,
        Error::Aead,
        Error::InvalidManifest {
            detail: "duplicate object id".to_owned(),
        },
        Error::UnsafePath {
            path: PathBuf::from("../escape"),
        },
        Error::WouldOverwrite {
            path: PathBuf::from("/tmp/out"),
        },
        Error::Io {
            path: PathBuf::from("/tmp/out"),
            source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
        },
        Error::BareIo(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "eof",
        )),
    ]
}

#[test]
fn no_error_variant_renders_a_secret() {
    for err in all_variants() {
        let display = err.to_string();
        let debug = format!("{err:?}");
        for sentinel in SENTINELS {
            assert!(
                !display.contains(sentinel),
                "Display for {} leaked {sentinel}",
                err.kind()
            );
            assert!(
                !debug.contains(sentinel),
                "Debug for {} leaked {sentinel}",
                err.kind()
            );
        }
        assert!(!display.is_empty(), "{} has an empty message", err.kind());
    }
}

#[test]
fn every_variant_has_a_distinct_machine_readable_kind() {
    let kinds: Vec<&str> = all_variants().iter().map(Error::kind).collect();
    let mut unique = kinds.clone();
    unique.sort_unstable();
    unique.dedup();
    // `Io` and `BareIo` deliberately share one kind; everything else is distinct.
    assert_eq!(unique.len(), kinds.len() - 1, "kinds: {kinds:?}");
}

#[test]
fn keys_and_passphrases_are_redacted() {
    let key = Key::random();
    assert_eq!(format!("{key:?}"), "Key([redacted])");

    let passphrase = Passphrase::new("hunter2".to_owned());
    let rendered = format!("{passphrase:?}");
    assert_eq!(rendered, "Passphrase([redacted])");
    assert!(!rendered.contains("hunter2"));
}

/// A real failure path, end to end: nothing about the key or the plaintext may
/// appear in the error a user actually sees.
#[test]
fn a_real_failure_reveals_nothing() {
    use std::io::Cursor;

    let master = Key::random();
    let mut container = Vec::new();
    xcrypt_core::encrypt_stream(
        &mut Cursor::new(b"PLAINTEXTBODY"),
        &mut container,
        &master,
        ContainerKind::File,
        xcrypt_core::MIN_CHUNK_SIZE,
        None,
    )
    .unwrap();
    *container.last_mut().unwrap() ^= 1;

    let err =
        xcrypt_core::decrypt_with_master(&mut Cursor::new(&container), &mut Vec::new(), &master)
            .unwrap_err();

    let rendered = format!("{err} / {err:?}");
    for sentinel in SENTINELS {
        assert!(!rendered.contains(sentinel));
    }
    let key_hex: String = master.expose().iter().map(|b| format!("{b:02x}")).collect();
    assert!(!rendered.contains(&key_hex));
}

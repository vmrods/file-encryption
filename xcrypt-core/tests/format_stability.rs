//! Format stability: a golden archive committed to the repository, decrypted on
//! every test run.
//!
//! This is the test that makes backward compatibility a deliberate act. Any
//! change to the container layout, the canonical header encoding, the HKDF
//! labels, the AAD rule, the wrap AAD, or the manifest encoding will fail here —
//! and the only way to make it pass is to regenerate the fixture, which is a
//! visible commit that says "this build cannot read old archives".
//!
//! To regenerate deliberately:
//!
//! ```text
//! cargo test -p xcrypt-core --test format_stability -- --ignored regenerate
//! ```

use std::path::{Path, PathBuf};

use xcrypt_core::{
    decrypt_archive, list_archive, verify_archive, DecryptOptions, EntryKind, KdfPolicy,
    NoProgress, Passphrase,
};

/// Passphrase for the committed fixture. Public by design: the fixture protects
/// nothing, it pins a format.
const FIXTURE_PASSPHRASE: &str = "xcrypt-golden-fixture-passphrase";

/// Where the fixture lives.
fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/golden-archive")
}

fn pass() -> Passphrase {
    Passphrase::new(FIXTURE_PASSPHRASE.to_owned())
}

/// The exact contents the fixture must yield, forever, until deliberately changed.
fn expected() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("fixture/hello.txt", b"hello, xcrypt\n".to_vec()),
        ("fixture/empty.txt", Vec::new()),
        (
            "fixture/nested/counting.bin",
            (0u32..=1023).map(|i| (i % 256) as u8).collect(),
        ),
        (
            "fixture/ünïcödé/naïve 🔐.txt",
            "unicode path, unicode content: ünïcödé 🔐\n"
                .as_bytes()
                .to_vec(),
        ),
    ]
}

#[test]
fn the_golden_archive_still_decrypts() {
    let archive = fixture_dir();
    assert!(
        archive.join("MANIFEST.xcr").exists(),
        "the golden fixture is missing; regenerate it with:\n  \
         cargo test -p xcrypt-core --test format_stability -- --ignored regenerate"
    );

    let dest = tempfile::tempdir().unwrap();
    let options = DecryptOptions {
        force: false,
        restore_modes: false,
        policy: KdfPolicy::default(),
    };
    decrypt_archive(&archive, dest.path(), &pass(), &options, &NoProgress)
        .expect("the committed fixture must decrypt under the default policy");

    for (relative, contents) in expected() {
        let path = dest.path().join(relative);
        let actual = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("{} is missing from the fixture: {e}", path.display()));
        assert_eq!(
            actual, contents,
            "{relative} decrypted to different bytes than the format promises"
        );
    }
}

#[test]
fn the_golden_archive_authenticates() {
    verify_archive(&fixture_dir(), &pass(), &KdfPolicy::default(), &NoProgress)
        .expect("every byte of the fixture must authenticate");
}

#[test]
fn the_golden_archive_lists_the_expected_metadata() {
    let manifest = list_archive(&fixture_dir(), &pass(), &KdfPolicy::default()).unwrap();

    assert_eq!(manifest.version, 1);
    assert_eq!(manifest.file_count(), 4);

    let mut paths: Vec<String> = manifest
        .entries
        .iter()
        .map(|e| e.display_path().to_string_lossy().into_owned())
        .collect();
    paths.sort();
    assert_eq!(
        paths,
        vec![
            "fixture",
            "fixture/empty.txt",
            "fixture/hello.txt",
            "fixture/nested",
            "fixture/nested/counting.bin",
            "fixture/ünïcödé",
            "fixture/ünïcödé/naïve 🔐.txt",
        ]
    );

    let sizes: Vec<u64> = manifest
        .entries
        .iter()
        .filter_map(|e| match e.kind {
            EntryKind::File { size, .. } => Some(size),
            _ => None,
        })
        .collect();
    assert_eq!(sizes.iter().sum::<u64>(), manifest.total_size());
}

/// The fixture must be readable under the *default* policy, not a relaxed one:
/// its recorded Argon2 cost has to satisfy the floor this build enforces.
#[test]
fn the_golden_archive_satisfies_the_default_kdf_policy() {
    let path = fixture_dir().join("MANIFEST.xcr");
    let mut file = std::fs::File::open(&path).unwrap();
    let parsed = xcrypt_core::Header::read_from(&mut file).unwrap();
    let keyring = parsed.header.keyring.as_ref().expect("root container");
    KdfPolicy::default()
        .check(&keyring.kdf)
        .expect("the fixture's KDF parameters must satisfy the shipped policy");
}

/// Regenerating is deliberate and manual. Run with `--ignored regenerate`.
#[test]
#[ignore = "regenerates the committed golden fixture; run only when the format changes on purpose"]
fn regenerate_the_golden_archive() {
    let work = tempfile::tempdir().unwrap();
    let source = work.path().join("fixture");

    let write = |relative: &str, contents: &[u8]| {
        let path = source.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    };
    write("hello.txt", b"hello, xcrypt\n");
    write("empty.txt", b"");
    write(
        "nested/counting.bin",
        &(0u32..=1023).map(|i| (i % 256) as u8).collect::<Vec<u8>>(),
    );
    write(
        "ünïcödé/naïve 🔐.txt",
        "unicode path, unicode content: ünïcödé 🔐\n".as_bytes(),
    );

    let archive = fixture_dir();
    if archive.exists() {
        std::fs::remove_dir_all(&archive).unwrap();
    }
    std::fs::create_dir_all(&archive).unwrap();

    let options = xcrypt_core::EncryptOptions {
        chunk_size: 1024,
        // The lowest cost the default policy accepts, so the fixture is cheap to
        // decrypt on every CI run but still exercises the real policy check.
        m_cost_kib: 19 * 1024,
        t_cost: 2,
        p_cost: 1,
        pad_sizes: false,
        force: true,
        policy: KdfPolicy::default(),
    };

    xcrypt_core::encrypt_paths(&[source], &archive, &pass(), &options, &NoProgress).unwrap();

    eprintln!(
        "regenerated the golden fixture at {} — commit it deliberately",
        archive.display()
    );
}

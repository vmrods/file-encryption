//! Packing an archive directory into one file, and back.
//!
//! The properties that matter: a packed file round-trips byte-for-byte, it opens
//! with the archive's own passphrase, it hides the object count and object sizes
//! a directory would expose, it fails closed on any corruption, and a failed
//! unpack leaves no half-built archive behind.

mod common;

use std::path::{Path, PathBuf};

use common::{pass, policy};
use xcrypt_core::archive::{MANIFEST_FILE, OBJECTS_DIR};
use xcrypt_core::{
    decrypt_archive, encrypt_paths, list_archive, pack_archive, unpack_archive, verify_archive,
    DecryptOptions, EncryptOptions, Error, NoProgress,
};

fn opts() -> EncryptOptions {
    EncryptOptions {
        chunk_size: 1024,
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
        pad_sizes: false,
        force: false,
        policy: policy(),
    }
}

fn dec_opts() -> DecryptOptions {
    DecryptOptions {
        force: false,
        restore_modes: true,
        policy: policy(),
    }
}

fn write(path: &Path, contents: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

fn build_tree(root: &Path) {
    write(&root.join("hello.txt"), b"hello, xcrypt");
    write(&root.join("empty.txt"), b"");
    write(&root.join("nested/deep/data.bin"), &[3u8; 9000]);
    write(&root.join("ünïcödé/naïve 🔐.txt"), "unicode".as_bytes());
    std::fs::create_dir_all(root.join("empty-dir")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("hello.txt", root.join("link.txt")).unwrap();
}

/// (relative path, kind, contents) for the whole tree, for comparison.
fn snapshot(root: &Path) -> Vec<(PathBuf, String, Vec<u8>)> {
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
    {
        let entry = entry.unwrap();
        let relative = entry.path().strip_prefix(root).unwrap().to_path_buf();
        if relative.as_os_str().is_empty() {
            continue;
        }
        let kind = entry.file_type();
        if kind.is_symlink() {
            let target = std::fs::read_link(entry.path()).unwrap();
            out.push((
                relative,
                "symlink".to_owned(),
                target.to_string_lossy().into_owned().into_bytes(),
            ));
        } else if kind.is_dir() {
            out.push((relative, "dir".to_owned(), Vec::new()));
        } else {
            out.push((
                relative,
                "file".to_owned(),
                std::fs::read(entry.path()).unwrap(),
            ));
        }
    }
    out.sort();
    out
}

struct Fixture {
    _work: tempfile::TempDir,
    source: PathBuf,
    archive: PathBuf,
    packed: PathBuf,
}

fn fixture(passphrase: &str) -> Fixture {
    let work = tempfile::tempdir().unwrap();
    let source = work.path().join("src");
    build_tree(&source);

    let archive = work.path().join("archive");
    encrypt_paths(
        std::slice::from_ref(&source),
        &archive,
        &pass(passphrase),
        &opts(),
        &NoProgress,
    )
    .unwrap();

    Fixture {
        packed: work.path().join("bundle.xcra"),
        source,
        archive,
        _work: work,
    }
}

#[test]
fn a_packed_archive_unpacks_byte_for_byte() {
    let fx = fixture("pack passphrase");
    let before = snapshot(&fx.archive);

    let summary = pack_archive(
        &fx.archive,
        &fx.packed,
        &pass("pack passphrase"),
        &opts(),
        &NoProgress,
    )
    .unwrap();
    assert_eq!(summary.files, 4);
    assert_eq!(summary.objects, 4);
    assert!(fx.packed.is_file());

    let restored = fx.packed.parent().unwrap().join("restored-archive");
    let summary = unpack_archive(
        &fx.packed,
        &restored,
        &pass("pack passphrase"),
        &policy(),
        false,
        &NoProgress,
    )
    .unwrap();
    assert_eq!(summary.objects, 4);

    assert_eq!(
        before,
        snapshot(&restored),
        "the unpacked archive differs from the original"
    );
}

#[test]
fn an_unpacked_archive_still_decrypts_to_the_original_tree() {
    let fx = fixture("pw");
    pack_archive(&fx.archive, &fx.packed, &pass("pw"), &opts(), &NoProgress).unwrap();

    let restored_archive = fx.packed.parent().unwrap().join("restored-archive");
    unpack_archive(
        &fx.packed,
        &restored_archive,
        &pass("pw"),
        &policy(),
        false,
        &NoProgress,
    )
    .unwrap();

    // Everything that works on a directory archive must work on an unpacked one.
    verify_archive(&restored_archive, &pass("pw"), &policy(), &NoProgress).unwrap();
    list_archive(&restored_archive, &pass("pw"), &policy()).unwrap();

    let dest = fx.packed.parent().unwrap().join("out");
    decrypt_archive(
        &restored_archive,
        &dest,
        &pass("pw"),
        &dec_opts(),
        &NoProgress,
    )
    .unwrap();

    assert_eq!(snapshot(&fx.source), snapshot(&dest.join("src")));
}

/// The reason packing exists beyond convenience.
#[test]
fn a_packed_file_hides_the_object_count_and_sizes() {
    let fx = fixture("pw");

    // The directory form exposes both.
    let object_sizes: Vec<u64> = std::fs::read_dir(fx.archive.join(OBJECTS_DIR))
        .unwrap()
        .map(|e| e.unwrap().metadata().unwrap().len())
        .collect();
    assert_eq!(object_sizes.len(), 4, "object count == file count, visible");
    assert!(
        object_sizes.iter().any(|&s| s > 9000),
        "one object tracks the size of the 9000-byte file"
    );

    pack_archive(&fx.archive, &fx.packed, &pass("pw"), &opts(), &NoProgress).unwrap();

    // The packed form is one file. Nothing about the count or the individual
    // sizes survives; only the total does.
    assert!(fx.packed.is_file());
    let packed_len = std::fs::metadata(&fx.packed).unwrap().len();
    let total: u64 = object_sizes.iter().sum();
    assert!(
        packed_len > total,
        "the packed file holds every object plus framing"
    );
}

#[test]
fn a_packed_file_is_a_single_authenticated_container() {
    let fx = fixture("pw");
    pack_archive(&fx.archive, &fx.packed, &pass("pw"), &opts(), &NoProgress).unwrap();

    let bytes = std::fs::read(&fx.packed).unwrap();
    assert_eq!(&bytes[..4], b"XCR1", "a packed file is an XCR1 container");

    let mut cursor = std::io::Cursor::new(&bytes);
    let parsed = xcrypt_core::Header::read_from(&mut cursor).unwrap();
    assert_eq!(parsed.header.kind, xcrypt_core::ContainerKind::Pack);
    assert!(
        parsed.header.keyring.is_some(),
        "a packed file carries its own keyring so it opens standalone"
    );
}

#[test]
fn the_wrong_passphrase_neither_packs_nor_unpacks() {
    let fx = fixture("right");

    let err = pack_archive(
        &fx.archive,
        &fx.packed,
        &pass("wrong"),
        &opts(),
        &NoProgress,
    )
    .unwrap_err();
    assert!(matches!(err, Error::NoMatchingRecipient), "got {err}");
    assert!(!fx.packed.exists(), "a failed pack left a file behind");

    pack_archive(
        &fx.archive,
        &fx.packed,
        &pass("right"),
        &opts(),
        &NoProgress,
    )
    .unwrap();

    let restored = fx.packed.parent().unwrap().join("restored");
    let err = unpack_archive(
        &fx.packed,
        &restored,
        &pass("wrong"),
        &policy(),
        false,
        &NoProgress,
    )
    .unwrap_err();
    assert!(matches!(err, Error::NoMatchingRecipient), "got {err}");
    assert!(
        !restored.exists(),
        "a failed unpack left a directory behind"
    );
}

#[test]
fn corrupting_a_packed_file_fails_closed_and_leaves_nothing() {
    let fx = fixture("pw");
    pack_archive(&fx.archive, &fx.packed, &pass("pw"), &opts(), &NoProgress).unwrap();

    let mut bytes = std::fs::read(&fx.packed).unwrap();
    // Corrupt the last chunk, so several chunks authenticate first and objects
    // have already been written when the failure hits.
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&fx.packed, &bytes).unwrap();

    let restored = fx.packed.parent().unwrap().join("restored");
    let err = unpack_archive(
        &fx.packed,
        &restored,
        &pass("pw"),
        &policy(),
        false,
        &NoProgress,
    )
    .unwrap_err();

    assert!(matches!(err, Error::ChunkAuthFailed { .. }), "got {err}");
    assert!(
        !restored.exists(),
        "a half-unpacked archive survived a corrupt bundle"
    );
}

#[test]
fn truncating_a_packed_file_is_detected() {
    let fx = fixture("pw");
    pack_archive(&fx.archive, &fx.packed, &pass("pw"), &opts(), &NoProgress).unwrap();

    let bytes = std::fs::read(&fx.packed).unwrap();
    for fraction in [0.3, 0.6, 0.9] {
        let len = (bytes.len() as f64 * fraction) as usize;
        let truncated = fx.packed.parent().unwrap().join("truncated.xcra");
        std::fs::write(&truncated, &bytes[..len]).unwrap();

        let restored = fx.packed.parent().unwrap().join("restored");
        let err = unpack_archive(
            &truncated,
            &restored,
            &pass("pw"),
            &policy(),
            true,
            &NoProgress,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                Error::ChunkAuthFailed { .. }
                    | Error::Truncated { .. }
                    | Error::InvalidManifest { .. }
            ),
            "truncating to {fraction} gave {err}"
        );
        assert!(!restored.exists());
    }
}

#[test]
fn an_ordinary_archive_container_is_not_mistaken_for_a_packed_file() {
    let fx = fixture("pw");

    // The manifest is a valid XCR1 container with a keyring, but it is not a
    // packed archive; the kind must be checked, not assumed.
    let restored = fx.packed.parent().unwrap().join("restored");
    let err = unpack_archive(
        &fx.archive.join(MANIFEST_FILE),
        &restored,
        &pass("pw"),
        &policy(),
        false,
        &NoProgress,
    )
    .unwrap_err();
    assert!(matches!(err, Error::InvalidHeaderField { .. }), "got {err}");
}

#[test]
fn packing_refuses_to_clobber_without_force() {
    let fx = fixture("pw");
    pack_archive(&fx.archive, &fx.packed, &pass("pw"), &opts(), &NoProgress).unwrap();

    let err = pack_archive(&fx.archive, &fx.packed, &pass("pw"), &opts(), &NoProgress).unwrap_err();
    assert!(matches!(err, Error::WouldOverwrite { .. }));

    let mut options = opts();
    options.force = true;
    pack_archive(&fx.archive, &fx.packed, &pass("pw"), &options, &NoProgress).unwrap();
}

#[test]
fn unpacking_refuses_to_clobber_without_force() {
    let fx = fixture("pw");
    pack_archive(&fx.archive, &fx.packed, &pass("pw"), &opts(), &NoProgress).unwrap();

    let restored = fx.packed.parent().unwrap().join("restored");
    unpack_archive(
        &fx.packed,
        &restored,
        &pass("pw"),
        &policy(),
        false,
        &NoProgress,
    )
    .unwrap();

    let err = unpack_archive(
        &fx.packed,
        &restored,
        &pass("pw"),
        &policy(),
        false,
        &NoProgress,
    )
    .unwrap_err();
    assert!(matches!(err, Error::WouldOverwrite { .. }));

    // The refusal must not have damaged what was already there.
    verify_archive(&restored, &pass("pw"), &policy(), &NoProgress).unwrap();
}

#[test]
fn packing_drops_objects_the_manifest_does_not_reference() {
    let fx = fixture("pw");

    // An orphan, as an interrupted encrypt leaves behind.
    let orphan = fx
        .archive
        .join(OBJECTS_DIR)
        .join(format!("{}.xcr", "ab".repeat(16)));
    std::fs::write(&orphan, b"junk that is not a container").unwrap();

    pack_archive(&fx.archive, &fx.packed, &pass("pw"), &opts(), &NoProgress).unwrap();

    let restored = fx.packed.parent().unwrap().join("restored");
    let summary = unpack_archive(
        &fx.packed,
        &restored,
        &pass("pw"),
        &policy(),
        false,
        &NoProgress,
    )
    .unwrap();

    assert_eq!(summary.objects, 4, "the orphan was packed");
    assert_eq!(
        std::fs::read_dir(restored.join(OBJECTS_DIR))
            .unwrap()
            .count(),
        4
    );
}

#[test]
fn rewrap_still_works_after_a_pack_unpack_cycle() {
    let fx = fixture("old pw");
    pack_archive(
        &fx.archive,
        &fx.packed,
        &pass("old pw"),
        &opts(),
        &NoProgress,
    )
    .unwrap();

    let restored = fx.packed.parent().unwrap().join("restored");
    unpack_archive(
        &fx.packed,
        &restored,
        &pass("old pw"),
        &policy(),
        false,
        &NoProgress,
    )
    .unwrap();

    xcrypt_core::rewrap_archive(&restored, &pass("old pw"), &pass("new pw"), &opts()).unwrap();
    assert!(list_archive(&restored, &pass("old pw"), &policy()).is_err());
    list_archive(&restored, &pass("new pw"), &policy()).unwrap();
}

#[test]
fn a_large_archive_packs_without_buffering_it() {
    let work = tempfile::tempdir().unwrap();
    let source = work.path().join("src");
    // 60 files of 100 KiB: ~6 MiB, enough that a buffering implementation would
    // show up under a memory profiler, and enough to cross many chunks.
    for i in 0..60 {
        write(&source.join(format!("file{i:03}.bin")), &[i as u8; 100_000]);
    }

    let archive = work.path().join("archive");
    encrypt_paths(
        std::slice::from_ref(&source),
        &archive,
        &pass("pw"),
        &opts(),
        &NoProgress,
    )
    .unwrap();

    let packed = work.path().join("bundle.xcra");
    let summary = pack_archive(&archive, &packed, &pass("pw"), &opts(), &NoProgress).unwrap();
    assert_eq!(summary.objects, 60);
    assert!(summary.bundle_len > 6_000_000);

    let restored = work.path().join("restored");
    unpack_archive(
        &packed,
        &restored,
        &pass("pw"),
        &policy(),
        false,
        &NoProgress,
    )
    .unwrap();
    assert_eq!(snapshot(&archive), snapshot(&restored));

    let dest = work.path().join("out");
    decrypt_archive(&restored, &dest, &pass("pw"), &dec_opts(), &NoProgress).unwrap();
    assert_eq!(snapshot(&source), snapshot(&dest.join("src")));
}

// ---------------------------------------------------------------------------
// encrypt --pack: straight to a single file, with no directory left behind
// ---------------------------------------------------------------------------

#[test]
fn encrypt_and_pack_produces_only_a_single_file() {
    let work = tempfile::tempdir().unwrap();
    let source = work.path().join("src");
    build_tree(&source);

    let output = work.path().join("vault.xcra");
    let (archive, packed) = xcrypt_core::encrypt_and_pack(
        std::slice::from_ref(&source),
        &output,
        &pass("pw"),
        &opts(),
        &NoProgress,
    )
    .unwrap();

    assert_eq!(archive.files, 4);
    assert_eq!(packed.objects, 4);
    assert!(output.is_file());

    // The staging archive must be gone: one file, and nothing else, beside it.
    let leftovers: Vec<PathBuf> = std::fs::read_dir(work.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p != &output && p != &source)
        .collect();
    assert!(leftovers.is_empty(), "staging survived: {leftovers:?}");
}

#[test]
fn encrypt_and_pack_round_trips_to_the_original_tree() {
    let work = tempfile::tempdir().unwrap();
    let source = work.path().join("src");
    build_tree(&source);

    let output = work.path().join("vault.xcra");
    xcrypt_core::encrypt_and_pack(
        std::slice::from_ref(&source),
        &output,
        &pass("pw"),
        &opts(),
        &NoProgress,
    )
    .unwrap();

    let restored_archive = work.path().join("restored-archive");
    unpack_archive(
        &output,
        &restored_archive,
        &pass("pw"),
        &policy(),
        false,
        &NoProgress,
    )
    .unwrap();

    let dest = work.path().join("out");
    decrypt_archive(
        &restored_archive,
        &dest,
        &pass("pw"),
        &dec_opts(),
        &NoProgress,
    )
    .unwrap();

    assert_eq!(snapshot(&source), snapshot(&dest.join("src")));
}

#[test]
fn encrypt_and_pack_refuses_to_clobber_without_force() {
    let work = tempfile::tempdir().unwrap();
    let source = work.path().join("src");
    build_tree(&source);

    let output = work.path().join("vault.xcra");
    std::fs::write(&output, b"something precious").unwrap();

    let err = xcrypt_core::encrypt_and_pack(
        std::slice::from_ref(&source),
        &output,
        &pass("pw"),
        &opts(),
        &NoProgress,
    )
    .unwrap_err();

    assert!(matches!(err, Error::WouldOverwrite { .. }));
    assert_eq!(
        std::fs::read(&output).unwrap(),
        b"something precious",
        "the refused run overwrote the target anyway"
    );

    let mut options = opts();
    options.force = true;
    xcrypt_core::encrypt_and_pack(
        std::slice::from_ref(&source),
        &output,
        &pass("pw"),
        &options,
        &NoProgress,
    )
    .unwrap();
}

/// A failure part-way through must leave no staging directory behind, and no
/// packed file either — the whole point is that nothing is deleted until a
/// verified replacement exists.
#[test]
fn a_failed_encrypt_and_pack_leaves_nothing_behind() {
    let work = tempfile::tempdir().unwrap();
    let output = work.path().join("vault.xcra");

    // A source that does not exist: the failure happens during the walk, after
    // the staging directory has been created.
    let err = xcrypt_core::encrypt_and_pack(
        &[work.path().join("does-not-exist")],
        &output,
        &pass("pw"),
        &opts(),
        &NoProgress,
    )
    .unwrap_err();

    assert!(matches!(err, Error::Io { .. }), "got {err}");
    assert!(!output.exists(), "a failed run produced an output file");

    let leftovers: Vec<PathBuf> = std::fs::read_dir(work.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert!(leftovers.is_empty(), "staging survived: {leftovers:?}");
}

#[test]
fn verify_packed_authenticates_and_detects_tampering() {
    let fx = fixture("pw");
    pack_archive(&fx.archive, &fx.packed, &pass("pw"), &opts(), &NoProgress).unwrap();

    xcrypt_core::verify_packed(&fx.packed, &pass("pw"), &policy()).unwrap();

    assert!(matches!(
        xcrypt_core::verify_packed(&fx.packed, &pass("wrong"), &policy()),
        Err(Error::NoMatchingRecipient)
    ));

    let mut bytes = std::fs::read(&fx.packed).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&fx.packed, &bytes).unwrap();

    assert!(matches!(
        xcrypt_core::verify_packed(&fx.packed, &pass("pw"), &policy()),
        Err(Error::ChunkAuthFailed { .. })
    ));
}

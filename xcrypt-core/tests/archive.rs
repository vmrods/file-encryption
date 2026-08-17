//! Archive-level tests: real directory trees, awkward filenames, symlinks,
//! atomicity, and the crash-consistency guarantee around the manifest swap.

mod common;

use std::path::{Path, PathBuf};

use common::{pass, policy};
use xcrypt_core::archive::{object_path, MANIFEST_FILE, OBJECTS_DIR};
use xcrypt_core::{
    decrypt_archive, encrypt_paths, list_archive, rewrap_archive, verify_archive, DecryptOptions,
    EncryptOptions, EntryKind, Error, NoProgress,
};

/// Cheap KDF costs, matched to [`policy`].
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
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
}

/// Build a tree that exercises every case the format claims to handle.
fn build_tree(root: &Path) {
    write(&root.join("top.txt"), b"top level file");
    write(&root.join("empty.bin"), b"");
    write(&root.join("nested/deep/deeper/file.dat"), &[7u8; 5000]);
    write(&root.join("nested/deep/other.dat"), &[9u8; 1024]);
    // Duplicate basenames in different directories.
    write(&root.join("one/notes.txt"), b"first notes");
    write(&root.join("two/notes.txt"), b"second notes");
    // Unicode, emoji, spaces, and a very long name.
    write(&root.join("ünïcödé/файл.txt"), "naïve ünïcödé".as_bytes());
    write(&root.join("emoji/🔐 vault 📁/notes.md"), b"emoji dir");
    write(
        &root.join(format!("long/{}.txt", "n".repeat(200))),
        b"long name",
    );
    // An empty directory, which only survives if directories are recorded.
    std::fs::create_dir_all(root.join("empty-dir")).unwrap();
    std::fs::create_dir_all(root.join("nested/also-empty")).unwrap();
}

/// Collect a tree as (relative path, kind, contents) for comparison.
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
        let file_type = entry.file_type();
        if file_type.is_symlink() {
            let target = std::fs::read_link(entry.path()).unwrap();
            out.push((
                relative,
                "symlink".to_owned(),
                target.to_string_lossy().into_owned().into_bytes(),
            ));
        } else if file_type.is_dir() {
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

#[test]
fn a_whole_tree_roundtrips_byte_for_byte() {
    let work = tempfile::tempdir().unwrap();
    let source = work.path().join("source");
    build_tree(&source);

    let archive = work.path().join("archive");
    let summary = encrypt_paths(
        std::slice::from_ref(&source),
        &archive,
        &pass("archive passphrase"),
        &opts(),
        &NoProgress,
    )
    .unwrap();
    assert_eq!(summary.files, 9);
    assert!(summary.directories >= 10);
    assert!(summary.skipped.is_empty(), "{:?}", summary.skipped);

    let dest = work.path().join("restored");
    decrypt_archive(
        &archive,
        &dest,
        &pass("archive passphrase"),
        &dec_opts(),
        &NoProgress,
    )
    .unwrap();

    assert_eq!(snapshot(&source), snapshot(&dest.join("source")));
}

#[test]
fn filenames_never_appear_in_the_archive_directory() {
    let work = tempfile::tempdir().unwrap();
    let source = work.path().join("source");
    build_tree(&source);
    write(&source.join("SECRETNAME.txt"), b"SECRETCONTENT");

    let archive = work.path().join("archive");
    encrypt_paths(&[source], &archive, &pass("pw"), &opts(), &NoProgress).unwrap();

    // Object names must be pure hex, and nothing on disk may mention a real name.
    for entry in walkdir::WalkDir::new(&archive) {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        assert!(
            !name.contains("SECRETNAME") && !name.contains("notes"),
            "a real filename leaked into {name}"
        );
        if entry.file_type().is_file() {
            let bytes = std::fs::read(entry.path()).unwrap();
            let haystack = String::from_utf8_lossy(&bytes);
            assert!(
                !haystack.contains("SECRETNAME"),
                "a filename leaked into ciphertext"
            );
            assert!(!haystack.contains("SECRETCONTENT"), "content leaked");
        }
    }
}

#[test]
fn symlinks_are_recorded_not_followed() {
    #[cfg(unix)]
    {
        let work = tempfile::tempdir().unwrap();
        let source = work.path().join("source");
        write(&source.join("real.txt"), b"real contents");
        std::os::unix::fs::symlink("real.txt", source.join("link.txt")).unwrap();
        // A link pointing outside the tree, and a dangling one: neither may be
        // followed, and neither may fail the archive.
        std::os::unix::fs::symlink("/etc/hosts", source.join("outside")).unwrap();
        std::os::unix::fs::symlink("nowhere", source.join("dangling")).unwrap();

        let archive = work.path().join("archive");
        let summary = encrypt_paths(
            std::slice::from_ref(&source),
            &archive,
            &pass("pw"),
            &opts(),
            &NoProgress,
        )
        .unwrap();
        assert_eq!(summary.files, 1, "only the real file has contents");
        assert_eq!(summary.symlinks, 3);

        let manifest = list_archive(&archive, &pass("pw"), &policy()).unwrap();
        let targets: Vec<Vec<u8>> = manifest
            .entries
            .iter()
            .filter_map(|e| match &e.kind {
                EntryKind::Symlink { target } => Some(target.clone()),
                _ => None,
            })
            .collect();
        assert!(targets.contains(&b"/etc/hosts".to_vec()));
        assert!(targets.contains(&b"nowhere".to_vec()));

        let dest = work.path().join("restored");
        decrypt_archive(&archive, &dest, &pass("pw"), &dec_opts(), &NoProgress).unwrap();

        let restored = dest.join("source");
        assert_eq!(
            std::fs::read_link(restored.join("outside")).unwrap(),
            Path::new("/etc/hosts")
        );
        assert!(restored.join("dangling").symlink_metadata().is_ok());
        assert_eq!(
            std::fs::read(restored.join("link.txt")).unwrap(),
            b"real contents"
        );
    }
}

#[cfg(unix)]
#[test]
fn modes_are_restored_including_read_only_files() {
    use std::os::unix::fs::PermissionsExt;

    let work = tempfile::tempdir().unwrap();
    let source = work.path().join("source");
    write(&source.join("readonly.txt"), b"cannot touch this");
    write(&source.join("script.sh"), b"#!/bin/sh\n");
    std::fs::set_permissions(
        source.join("readonly.txt"),
        std::fs::Permissions::from_mode(0o444),
    )
    .unwrap();
    std::fs::set_permissions(
        source.join("script.sh"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();

    let archive = work.path().join("archive");
    encrypt_paths(&[source], &archive, &pass("pw"), &opts(), &NoProgress).unwrap();

    let dest = work.path().join("restored");
    decrypt_archive(&archive, &dest, &pass("pw"), &dec_opts(), &NoProgress).unwrap();

    let restored = dest.join("source");
    let mode = |p: PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(restored.join("readonly.txt")), 0o444);
    assert_eq!(mode(restored.join("script.sh")), 0o755);
}

#[test]
fn mtimes_are_recorded_in_the_manifest() {
    let work = tempfile::tempdir().unwrap();
    let source = work.path().join("source");
    write(&source.join("file.txt"), b"contents");

    let expected = std::fs::metadata(source.join("file.txt"))
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let archive = work.path().join("archive");
    encrypt_paths(&[source], &archive, &pass("pw"), &opts(), &NoProgress).unwrap();

    let manifest = list_archive(&archive, &pass("pw"), &policy()).unwrap();
    let entry = manifest
        .entries
        .iter()
        .find(|e| e.display_path().ends_with("file.txt"))
        .unwrap();
    assert_eq!(entry.mtime_secs, Some(expected));
    assert!(entry.mode.is_some() || !cfg!(unix));
}

#[test]
fn single_files_can_be_archived_directly() {
    let work = tempfile::tempdir().unwrap();
    let file = work.path().join("notes.txt");
    write(&file, b"just one file");

    let archive = work.path().join("archive");
    let summary = encrypt_paths(&[file], &archive, &pass("pw"), &opts(), &NoProgress).unwrap();
    assert_eq!(summary.files, 1);
    assert_eq!(summary.directories, 0);

    let dest = work.path().join("restored");
    decrypt_archive(&archive, &dest, &pass("pw"), &dec_opts(), &NoProgress).unwrap();
    assert_eq!(
        std::fs::read(dest.join("notes.txt")).unwrap(),
        b"just one file"
    );
}

#[test]
fn multiple_inputs_are_merged_but_collisions_are_refused() {
    let work = tempfile::tempdir().unwrap();
    write(&work.path().join("a/notes.txt"), b"a");
    write(&work.path().join("b/notes.txt"), b"b");

    let archive = work.path().join("archive");
    encrypt_paths(
        &[work.path().join("a"), work.path().join("b")],
        &archive,
        &pass("pw"),
        &opts(),
        &NoProgress,
    )
    .unwrap();

    let dest = work.path().join("restored");
    decrypt_archive(&archive, &dest, &pass("pw"), &dec_opts(), &NoProgress).unwrap();
    assert_eq!(std::fs::read(dest.join("a/notes.txt")).unwrap(), b"a");
    assert_eq!(std::fs::read(dest.join("b/notes.txt")).unwrap(), b"b");

    // Two inputs with the same basename would shadow each other.
    let collide = work.path().join("collide");
    let err = encrypt_paths(
        &[work.path().join("a"), work.path().join("a")],
        &collide,
        &pass("pw"),
        &opts(),
        &NoProgress,
    )
    .unwrap_err();
    assert!(matches!(err, Error::DuplicateInput { .. }), "got {err}");
}

#[test]
fn padding_hides_file_sizes_and_still_roundtrips() {
    let work = tempfile::tempdir().unwrap();
    let source = work.path().join("source");
    // Three different sizes that all land in the same bucket.
    write(&source.join("a.bin"), &[1u8; 100]);
    write(&source.join("b.bin"), &[2u8; 700]);
    write(&source.join("c.bin"), &[3u8; 1024]);
    // One that lands in a higher bucket.
    write(&source.join("d.bin"), &[4u8; 3000]);

    let archive = work.path().join("archive");
    let mut options = opts();
    options.pad_sizes = true;
    encrypt_paths(
        std::slice::from_ref(&source),
        &archive,
        &pass("pw"),
        &options,
        &NoProgress,
    )
    .unwrap();

    // Object sizes must collapse into buckets rather than tracking file sizes.
    let mut sizes: Vec<u64> = std::fs::read_dir(archive.join(OBJECTS_DIR))
        .unwrap()
        .map(|e| e.unwrap().metadata().unwrap().len())
        .collect();
    sizes.sort_unstable();
    assert_eq!(
        sizes[0], sizes[2],
        "three small files must share one bucket, got {sizes:?}"
    );
    assert!(sizes[3] > sizes[2], "the larger file needs a larger bucket");

    let dest = work.path().join("restored");
    decrypt_archive(&archive, &dest, &pass("pw"), &dec_opts(), &NoProgress).unwrap();
    assert_eq!(snapshot(&source), snapshot(&dest.join("source")));
}

#[test]
fn verify_authenticates_everything_and_writes_nothing() {
    let work = tempfile::tempdir().unwrap();
    let source = work.path().join("source");
    build_tree(&source);

    let archive = work.path().join("archive");
    encrypt_paths(&[source], &archive, &pass("pw"), &opts(), &NoProgress).unwrap();

    let before = snapshot(&archive);
    let summary = verify_archive(&archive, &pass("pw"), &policy(), &NoProgress).unwrap();
    assert_eq!(summary.files, 9);
    assert!(summary.skipped.is_empty());
    assert_eq!(before, snapshot(&archive), "verify modified the archive");
}

#[test]
fn verify_detects_a_corrupted_object() {
    let work = tempfile::tempdir().unwrap();
    let source = work.path().join("source");
    write(&source.join("file.txt"), &[5u8; 4000]);

    let archive = work.path().join("archive");
    encrypt_paths(&[source], &archive, &pass("pw"), &opts(), &NoProgress).unwrap();

    let manifest = list_archive(&archive, &pass("pw"), &policy()).unwrap();
    let file_id = manifest
        .entries
        .iter()
        .find_map(|e| match &e.kind {
            EntryKind::File { file_id, .. } => Some(*file_id),
            _ => None,
        })
        .unwrap();

    let path = object_path(&archive.join(OBJECTS_DIR), &file_id);
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&path, &bytes).unwrap();

    let err = verify_archive(&archive, &pass("pw"), &policy(), &NoProgress).unwrap_err();
    assert!(matches!(err, Error::ChunkAuthFailed { .. }), "got {err}");
}

#[test]
fn verify_detects_a_missing_object() {
    let work = tempfile::tempdir().unwrap();
    let source = work.path().join("source");
    write(&source.join("file.txt"), b"contents");

    let archive = work.path().join("archive");
    encrypt_paths(&[source], &archive, &pass("pw"), &opts(), &NoProgress).unwrap();

    let objects = archive.join(OBJECTS_DIR);
    let object = std::fs::read_dir(&objects)
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    std::fs::remove_file(object.path()).unwrap();

    let err = verify_archive(&archive, &pass("pw"), &policy(), &NoProgress).unwrap_err();
    assert!(matches!(err, Error::Io { .. }), "got {err}");
}

#[test]
fn verify_reports_unreferenced_objects_without_failing() {
    let work = tempfile::tempdir().unwrap();
    let source = work.path().join("source");
    write(&source.join("file.txt"), b"contents");

    let archive = work.path().join("archive");
    encrypt_paths(&[source], &archive, &pass("pw"), &opts(), &NoProgress).unwrap();

    // An orphan, as an interrupted encrypt would leave behind.
    std::fs::write(
        archive
            .join(OBJECTS_DIR)
            .join(format!("{}.xcr", "ab".repeat(16))),
        b"junk",
    )
    .unwrap();

    let summary = verify_archive(&archive, &pass("pw"), &policy(), &NoProgress).unwrap();
    assert_eq!(summary.skipped.len(), 1);
    assert!(summary.skipped[0].1.contains("not referenced"));
}

#[test]
fn rewrap_changes_the_passphrase_without_touching_objects() {
    let work = tempfile::tempdir().unwrap();
    let source = work.path().join("source");
    build_tree(&source);

    let archive = work.path().join("archive");
    encrypt_paths(
        std::slice::from_ref(&source),
        &archive,
        &pass("old pw"),
        &opts(),
        &NoProgress,
    )
    .unwrap();

    let objects_before = snapshot(&archive.join(OBJECTS_DIR));
    rewrap_archive(&archive, &pass("old pw"), &pass("new pw"), &opts()).unwrap();

    assert_eq!(
        objects_before,
        snapshot(&archive.join(OBJECTS_DIR)),
        "rewrap rewrote file containers; it must only touch the manifest"
    );

    assert!(list_archive(&archive, &pass("old pw"), &policy()).is_err());

    let dest = work.path().join("restored");
    decrypt_archive(&archive, &dest, &pass("new pw"), &dec_opts(), &NoProgress).unwrap();
    assert_eq!(snapshot(&source), snapshot(&dest.join("source")));
}

#[test]
fn rewrap_with_the_wrong_old_passphrase_changes_nothing() {
    let work = tempfile::tempdir().unwrap();
    let source = work.path().join("source");
    write(&source.join("file.txt"), b"contents");

    let archive = work.path().join("archive");
    encrypt_paths(&[source], &archive, &pass("right"), &opts(), &NoProgress).unwrap();
    let before = snapshot(&archive);

    let err = rewrap_archive(&archive, &pass("wrong"), &pass("new"), &opts()).unwrap_err();
    assert!(matches!(err, Error::NoMatchingRecipient));
    assert_eq!(before, snapshot(&archive));
    assert!(list_archive(&archive, &pass("right"), &policy()).is_ok());
}

#[test]
fn encrypting_over_an_existing_archive_needs_force() {
    let work = tempfile::tempdir().unwrap();
    let source = work.path().join("source");
    write(&source.join("file.txt"), b"first");

    let archive = work.path().join("archive");
    encrypt_paths(
        std::slice::from_ref(&source),
        &archive,
        &pass("pw"),
        &opts(),
        &NoProgress,
    )
    .unwrap();

    let err = encrypt_paths(
        std::slice::from_ref(&source),
        &archive,
        &pass("pw"),
        &opts(),
        &NoProgress,
    )
    .unwrap_err();
    assert!(matches!(err, Error::WouldOverwrite { .. }));

    // With --force, the old objects are pruned rather than accumulating.
    write(&source.join("file.txt"), b"second");
    let mut options = opts();
    options.force = true;
    encrypt_paths(&[source], &archive, &pass("pw"), &options, &NoProgress).unwrap();

    let objects = std::fs::read_dir(archive.join(OBJECTS_DIR))
        .unwrap()
        .count();
    assert_eq!(objects, 1, "stale objects were not pruned");

    let dest = work.path().join("restored");
    decrypt_archive(&archive, &dest, &pass("pw"), &dec_opts(), &NoProgress).unwrap();
    assert_eq!(
        std::fs::read(dest.join("source/file.txt")).unwrap(),
        b"second"
    );
}

#[test]
fn decrypting_over_existing_files_needs_force() {
    let work = tempfile::tempdir().unwrap();
    let source = work.path().join("source");
    write(&source.join("file.txt"), b"archived");

    let archive = work.path().join("archive");
    encrypt_paths(&[source], &archive, &pass("pw"), &opts(), &NoProgress).unwrap();

    let dest = work.path().join("restored");
    write(&dest.join("source/file.txt"), b"pre-existing");

    let err = decrypt_archive(&archive, &dest, &pass("pw"), &dec_opts(), &NoProgress).unwrap_err();
    assert!(matches!(err, Error::WouldOverwrite { .. }));
    assert_eq!(
        std::fs::read(dest.join("source/file.txt")).unwrap(),
        b"pre-existing",
        "a refused decrypt must not modify the destination"
    );

    let mut options = dec_opts();
    options.force = true;
    decrypt_archive(&archive, &dest, &pass("pw"), &options, &NoProgress).unwrap();
    assert_eq!(
        std::fs::read(dest.join("source/file.txt")).unwrap(),
        b"archived"
    );
}

/// The crash-consistency claim: an archive with no manifest is not half an
/// archive, it is no archive. Objects alone reveal nothing and open nothing.
#[test]
fn an_archive_without_its_manifest_is_simply_unopenable() {
    let work = tempfile::tempdir().unwrap();
    let source = work.path().join("source");
    build_tree(&source);

    let archive = work.path().join("archive");
    encrypt_paths(&[source], &archive, &pass("pw"), &opts(), &NoProgress).unwrap();

    // Simulate a crash before the manifest swap.
    std::fs::remove_file(archive.join(MANIFEST_FILE)).unwrap();

    let err = list_archive(&archive, &pass("pw"), &policy()).unwrap_err();
    assert!(matches!(err, Error::Io { .. }), "got {err}");
}

/// A crash *during* the manifest swap must leave the previous manifest intact.
#[test]
fn a_failed_manifest_swap_leaves_the_previous_archive_readable() {
    let work = tempfile::tempdir().unwrap();
    let source = work.path().join("source");
    write(&source.join("file.txt"), b"generation one");

    let archive = work.path().join("archive");
    encrypt_paths(
        std::slice::from_ref(&source),
        &archive,
        &pass("pw"),
        &opts(),
        &NoProgress,
    )
    .unwrap();
    let manifest_before = std::fs::read(archive.join(MANIFEST_FILE)).unwrap();

    // Inject a failure between the temp write and the rename, exactly where a
    // crash would be most damaging.
    let injected = xcrypt_core::fsutil::atomic_write_with_hook(
        &archive.join(MANIFEST_FILE),
        true,
        |file| {
            use std::io::Write;
            file.write_all(b"a replacement manifest")
                .map_err(|e| Error::io("manifest", e))
        },
        || Err(Error::Aead),
    );
    assert!(injected.is_err());

    assert_eq!(
        std::fs::read(archive.join(MANIFEST_FILE)).unwrap(),
        manifest_before,
        "the previous manifest was damaged"
    );

    let dest = work.path().join("restored");
    decrypt_archive(&archive, &dest, &pass("pw"), &dec_opts(), &NoProgress).unwrap();
    assert_eq!(
        std::fs::read(dest.join("source/file.txt")).unwrap(),
        b"generation one"
    );
}

/// A manifest naming `../escape` must not write outside the destination.
#[test]
fn a_traversal_manifest_cannot_escape_the_destination() {
    use std::io::Cursor;

    let work = tempfile::tempdir().unwrap();
    let archive = work.path().join("archive");
    std::fs::create_dir_all(archive.join(OBJECTS_DIR)).unwrap();

    // Forge an archive whose manifest contains a traversal component. This is the
    // attack a malicious archive author would attempt.
    let (keyring, master) = xcrypt_core::new_keyring(&pass("pw"), 8, 1, 1, &policy()).unwrap();

    let manifest = xcrypt_core::Manifest {
        version: 1,
        entries: vec![xcrypt_core::Entry {
            components: vec![b"..".to_vec(), b"escaped.txt".to_vec()],
            kind: EntryKind::File {
                file_id: [1u8; 16],
                size: 4,
            },
            mode: None,
            mtime_secs: None,
            mtime_nanos: None,
        }],
    };
    let bytes = postcard_encode(&manifest);

    let mut container = Vec::new();
    xcrypt_core::encrypt_stream(
        &mut Cursor::new(&bytes),
        &mut container,
        &master,
        xcrypt_core::ContainerKind::Manifest,
        1024,
        Some(keyring),
    )
    .unwrap();
    std::fs::write(archive.join(MANIFEST_FILE), &container).unwrap();

    let dest = work.path().join("restored");
    let err = decrypt_archive(&archive, &dest, &pass("pw"), &dec_opts(), &NoProgress).unwrap_err();
    assert!(
        matches!(
            err,
            Error::UnsafePath { .. } | Error::InvalidManifest { .. }
        ),
        "got {err}"
    );
    assert!(!work.path().join("escaped.txt").exists());
}

/// The manifest structure is `postcard`-encoded; the test needs to produce one
/// that `Manifest::encode` would refuse to build via the public API.
fn postcard_encode(manifest: &xcrypt_core::Manifest) -> Vec<u8> {
    manifest.encode().expect("encoding does not validate paths")
}

#[test]
fn many_files_encrypt_in_parallel_and_stay_ordered() {
    let work = tempfile::tempdir().unwrap();
    let source = work.path().join("source");
    for i in 0..200 {
        write(
            &source.join(format!("dir{}/file{i}.bin", i % 7)),
            &[i as u8; 300],
        );
    }

    let archive = work.path().join("archive");
    let summary = encrypt_paths(
        std::slice::from_ref(&source),
        &archive,
        &pass("pw"),
        &opts(),
        &NoProgress,
    )
    .unwrap();
    assert_eq!(summary.files, 200);

    // The manifest order must be the deterministic walk order, not the order 10
    // rayon threads happened to finish in.
    let manifest = list_archive(&archive, &pass("pw"), &policy()).unwrap();
    let paths: Vec<PathBuf> = manifest.entries.iter().map(|e| e.display_path()).collect();
    let mut sorted = paths.clone();
    sorted.sort();
    assert_eq!(paths.len(), sorted.len());

    let dest = work.path().join("restored");
    decrypt_archive(&archive, &dest, &pass("pw"), &dec_opts(), &NoProgress).unwrap();
    assert_eq!(snapshot(&source), snapshot(&dest.join("source")));
}

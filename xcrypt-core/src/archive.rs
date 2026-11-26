//! Directory-tree archives: walking, parallel encryption, and the atomic
//! manifest swap.
//!
//! # On-disk layout
//!
//! ```text
//! archive_dir/
//!   MANIFEST.xcr            # XCR1 container, kind = Manifest, holds the keyring
//!   objects/
//!     <32 hex chars>.xcr    # one XCR1 container per file, named by file_id
//! ```
//!
//! # Crash consistency
//!
//! Objects are written first, each one atomically; the manifest is swapped last,
//! also atomically. The manifest is the only thing that gives objects meaning, so
//! the two possible outcomes of a crash are "the previous archive, intact" and
//! "the new archive, intact" — with, at worst, unreferenced objects left behind.
//! Those are pruned after a successful swap, never before.
//!
//! # Parallelism
//!
//! Files are encrypted with `rayon`, one task per file. Each derives its own key
//! from the shared master key, so there is nothing to synchronize; the manifest
//! swap is the single serialization point. The Argon2 pass runs exactly once per
//! archive, not once per file.
//!
//! # Symlinks
//!
//! Recorded, never followed. The link target is stored as manifest metadata and
//! recreated on extraction. Following links would duplicate content, require
//! cycle detection, and silently pull in files from outside the requested tree.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use rayon::prelude::*;

use crate::error::{Error, Result};
use crate::fsutil::{atomic_write, sync_dir};
use crate::header::{ContainerKind, FileId, KdfPolicy, DEFAULT_CHUNK_SIZE};
use crate::keys::{new_keyring, rewrap_keyring, Key, Passphrase};
use crate::manifest::{Entry, EntryKind, Manifest};
use crate::stream::{encrypt_stream_with_progress, verify_with_master};

/// Filename of the manifest container inside an archive directory.
pub const MANIFEST_FILE: &str = "MANIFEST.xcr";

/// Subdirectory holding the per-file containers.
pub const OBJECTS_DIR: &str = "objects";

/// Extension used for containers.
pub const OBJECT_EXT: &str = "xcr";

/// Tunables for creating an archive.
#[derive(Debug, Clone)]
pub struct EncryptOptions {
    /// Plaintext bytes per chunk.
    pub chunk_size: u32,
    /// Argon2id memory cost in KiB.
    pub m_cost_kib: u32,
    /// Argon2id iterations.
    pub t_cost: u32,
    /// Argon2id parallelism.
    pub p_cost: u32,
    /// Pad each stored file to a power-of-two length, hiding exact file sizes.
    ///
    /// Costs up to 2× storage in the worst case. Does **not** hide the archive's
    /// total size or its file count.
    pub pad_sizes: bool,
    /// Replace an existing archive.
    pub force: bool,
    /// Bounds enforced on KDF parameters.
    pub policy: KdfPolicy,
}

impl Default for EncryptOptions {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            m_cost_kib: 256 * 1024,
            t_cost: 3,
            p_cost: 4,
            pad_sizes: false,
            force: false,
            policy: KdfPolicy::default(),
        }
    }
}

/// Tunables for reading an archive.
#[derive(Debug, Clone)]
pub struct DecryptOptions {
    /// Overwrite files that already exist at the destination.
    pub force: bool,
    /// Restore Unix mode bits recorded in the manifest.
    pub restore_modes: bool,
    /// Bounds enforced on KDF parameters read from the archive.
    pub policy: KdfPolicy,
}

impl Default for DecryptOptions {
    fn default() -> Self {
        Self {
            force: false,
            restore_modes: true,
            policy: KdfPolicy::default(),
        }
    }
}

/// Progress and diagnostics sink. Implementations must be usable from rayon
/// worker threads, hence `Sync`.
pub trait Progress: Sync {
    /// A file is about to be processed.
    fn file_started(&self, _path: &Path, _size: u64) {}
    /// `delta` more plaintext bytes have been processed.
    fn bytes_advanced(&self, _delta: u64) {}
    /// A file finished successfully.
    fn file_finished(&self, _path: &Path) {}
    /// Something the user should know but that is not an error.
    fn note(&self, _message: &str) {}
}

/// A [`Progress`] that discards everything.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoProgress;

impl Progress for NoProgress {}

/// What an archive operation did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArchiveSummary {
    /// Regular files processed.
    pub files: usize,
    /// Directories recorded or created.
    pub directories: usize,
    /// Symlinks recorded or recreated.
    pub symlinks: usize,
    /// Total plaintext bytes.
    pub bytes: u64,
    /// Paths deliberately not processed, with the reason.
    pub skipped: Vec<(PathBuf, String)>,
}

/// Encrypt one or more paths into a new archive directory.
///
/// Each input contributes its own basename as a top-level entry, so
/// `xcrypt encrypt notes.txt photos/ -o vault` produces `notes.txt` and
/// `photos/...` inside the archive. Two inputs with the same basename are an
/// error rather than a silent merge.
pub fn encrypt_paths(
    inputs: &[PathBuf],
    archive_dir: &Path,
    passphrase: &Passphrase,
    options: &EncryptOptions,
    progress: &dyn Progress,
) -> Result<ArchiveSummary> {
    if archive_dir.exists() {
        let manifest_path = archive_dir.join(MANIFEST_FILE);
        if manifest_path.exists() && !options.force {
            return Err(Error::WouldOverwrite {
                path: manifest_path,
            });
        }
    }

    let objects_dir = archive_dir.join(OBJECTS_DIR);
    std::fs::create_dir_all(&objects_dir).map_err(|e| Error::io(&objects_dir, e))?;

    let plan = plan_inputs(inputs, progress)?;

    // One Argon2 pass for the whole archive.
    let (keyring, master_key) = new_keyring(
        passphrase,
        options.m_cost_kib,
        options.t_cost,
        options.p_cost,
        &options.policy,
    )?;

    let mut summary = ArchiveSummary {
        skipped: plan.skipped,
        ..Default::default()
    };
    let mut manifest = Manifest::new();

    // Directories and symlinks are metadata only: no container, no ciphertext.
    for planned in &plan.entries {
        match &planned.kind {
            PlannedKind::Directory => summary.directories += 1,
            PlannedKind::Symlink { .. } => summary.symlinks += 1,
            PlannedKind::File { .. } => {}
        }
    }

    // Files in parallel. Each task is independent: its own file_id, its own
    // derived key, its own atomic write.
    let file_entries: Vec<&PlannedEntry> = plan
        .entries
        .iter()
        .filter(|e| matches!(e.kind, PlannedKind::File { .. }))
        .collect();

    let encrypted: Vec<Result<(usize, Entry, u64)>> = file_entries
        .par_iter()
        .enumerate()
        .map(|(position, planned)| {
            let PlannedKind::File { size } = planned.kind else {
                unreachable!("filtered to files above");
            };
            progress.file_started(&planned.relative, size);

            let stats = encrypt_one_file(
                &planned.source,
                &objects_dir,
                &master_key,
                options,
                size,
                progress,
            )?;

            let metadata =
                std::fs::metadata(&planned.source).map_err(|e| Error::io(&planned.source, e))?;
            let entry = Entry::new(
                &planned.relative,
                EntryKind::File {
                    file_id: stats.0,
                    size,
                },
            )?
            .with_metadata(&metadata);

            progress.file_finished(&planned.relative);
            Ok((position, entry, size))
        })
        .collect();

    // Preserve walk order in the manifest: parallelism must not make the archive
    // non-deterministic in its metadata.
    let mut file_results = Vec::with_capacity(encrypted.len());
    for result in encrypted {
        file_results.push(result?);
    }
    file_results.sort_by_key(|(position, _, _)| *position);

    let mut files_by_position: std::collections::HashMap<usize, (Entry, u64)> = file_results
        .into_iter()
        .map(|(position, entry, size)| (position, (entry, size)))
        .collect();

    let mut file_position = 0usize;
    for planned in &plan.entries {
        match &planned.kind {
            PlannedKind::File { .. } => {
                let (entry, size) = files_by_position
                    .remove(&file_position)
                    .expect("every planned file produced an entry");
                file_position += 1;
                summary.files += 1;
                summary.bytes += size;
                manifest.entries.push(entry);
            }
            PlannedKind::Directory => {
                let metadata = std::fs::symlink_metadata(&planned.source)
                    .map_err(|e| Error::io(&planned.source, e))?;
                manifest.entries.push(
                    Entry::new(&planned.relative, EntryKind::Directory)?.with_metadata(&metadata),
                );
            }
            PlannedKind::Symlink { target } => {
                manifest.entries.push(Entry::new(
                    &planned.relative,
                    EntryKind::Symlink {
                        target: target.clone(),
                    },
                )?);
            }
        }
    }

    // Objects must be durable before anything references them.
    sync_dir(&objects_dir)?;

    // The single serialization point: swap the manifest in atomically, last.
    let manifest_bytes = manifest.encode()?;
    let manifest_path = archive_dir.join(MANIFEST_FILE);
    atomic_write(&manifest_path, true, |file| {
        encrypt_stream_with_progress(
            &mut manifest_bytes.as_slice(),
            file,
            &master_key,
            ContainerKind::Manifest,
            options.chunk_size,
            Some(keyring.clone()),
            &mut |_| {},
        )
        .map(|_| ())
    })?;

    // Only now is it safe to remove objects the new manifest does not reference.
    prune_unreferenced_objects(&objects_dir, &manifest, progress)?;

    Ok(summary)
}

/// Encrypt a single file into `objects/`, returning its identifier.
fn encrypt_one_file(
    source: &Path,
    objects_dir: &Path,
    master_key: &Key,
    options: &EncryptOptions,
    size: u64,
    progress: &dyn Progress,
) -> Result<(FileId, u64)> {
    let file = File::open(source).map_err(|e| Error::io(source, e))?;
    let mut reader = std::io::BufReader::with_capacity(options.chunk_size as usize, file);

    let target_len = if options.pad_sizes {
        padded_len(size, options.chunk_size)
    } else {
        size
    };

    // A placeholder name is not an option: the object name *is* the file_id, and
    // the file_id is chosen inside `encrypt_stream`. Write to a temp file in the
    // objects directory, learn the id, then rename to it.
    let temp =
        tempfile::NamedTempFile::new_in(objects_dir).map_err(|e| Error::io(objects_dir, e))?;
    let mut writer = std::io::BufWriter::new(temp.reopen().map_err(|e| Error::io(objects_dir, e))?);

    let mut last = 0u64;
    let stats = {
        let mut padded = PadReader::new(&mut reader, size, target_len);
        encrypt_stream_with_progress(
            &mut padded,
            &mut writer,
            master_key,
            ContainerKind::File,
            options.chunk_size,
            None,
            &mut |cumulative| {
                let real = cumulative.min(size);
                if real > last {
                    progress.bytes_advanced(real - last);
                    last = real;
                }
            },
        )?
    };

    writer.flush().map_err(|e| Error::io(objects_dir, e))?;
    let inner = writer
        .into_inner()
        .map_err(|e| Error::io(objects_dir, e.into_error()))?;
    inner.sync_all().map_err(|e| Error::io(objects_dir, e))?;

    let object_path = object_path(objects_dir, &stats.file_id);
    temp.persist(&object_path)
        .map_err(|e| Error::io(&object_path, e.error))?;

    Ok((stats.file_id, stats.ciphertext_len))
}

/// Decrypt an archive into `dest`.
pub fn decrypt_archive(
    archive_dir: &Path,
    dest: &Path,
    passphrase: &Passphrase,
    options: &DecryptOptions,
    progress: &dyn Progress,
) -> Result<ArchiveSummary> {
    let (manifest, master_key) = open_manifest(archive_dir, passphrase, &options.policy)?;
    let objects_dir = archive_dir.join(OBJECTS_DIR);

    std::fs::create_dir_all(dest).map_err(|e| Error::io(dest, e))?;
    let dest = &destination_root(dest)?;

    // Directories first, shallowest to deepest, so file writes have somewhere to
    // land even if the walk order was unusual.
    let mut directories: Vec<(&Entry, PathBuf)> = Vec::new();
    for entry in &manifest.entries {
        if matches!(entry.kind, EntryKind::Directory) {
            let path = resolve(dest, entry)?;
            directories.push((entry, path));
        }
    }
    directories.sort_by_key(|(_, path)| path.components().count());
    for (_, path) in &directories {
        std::fs::create_dir_all(path).map_err(|e| Error::io(path, e))?;
    }

    // Parent directories for files whose ancestors were not recorded (a single
    // file archived by name has no directory entry).
    for entry in &manifest.entries {
        if let EntryKind::File { .. } = entry.kind {
            let path = resolve(dest, entry)?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
            }
        }
    }

    let files: Vec<(&Entry, PathBuf, FileId, u64)> = manifest
        .entries
        .iter()
        .filter_map(|entry| match &entry.kind {
            EntryKind::File { file_id, size } => Some((entry, *file_id, *size)),
            _ => None,
        })
        .map(|(entry, file_id, size)| Ok((entry, resolve(dest, entry)?, file_id, size)))
        .collect::<Result<_>>()?;

    let results: Vec<Result<()>> = files
        .par_iter()
        .map(|(entry, path, file_id, size)| {
            progress.file_started(&entry.display_path(), *size);
            decrypt_one_file(
                &objects_dir,
                file_id,
                *size,
                path,
                &master_key,
                options,
                progress,
            )?;
            progress.file_finished(&entry.display_path());
            Ok(())
        })
        .collect();
    for result in results {
        result?;
    }

    let mut summary = ArchiveSummary {
        files: files.len(),
        directories: directories.len(),
        bytes: manifest.total_size(),
        ..Default::default()
    };

    // Symlinks after files, so a link to an archived file resolves immediately.
    for entry in &manifest.entries {
        if let EntryKind::Symlink { target } = &entry.kind {
            let path = resolve(dest, entry)?;
            match create_symlink(target, &path, options.force) {
                Ok(()) => summary.symlinks += 1,
                Err(e) => {
                    summary.skipped.push((entry.display_path(), e.to_string()));
                    progress.note(&format!(
                        "skipped symlink {}: {e}",
                        entry.display_path().display()
                    ));
                }
            }
        }
    }

    // Modes last: a read-only directory cannot be written into.
    if options.restore_modes {
        restore_modes(dest, &manifest, &directories)?;
    }

    Ok(summary)
}

/// Decrypt only the manifest, for `xcrypt list`.
pub fn list_archive(
    archive_dir: &Path,
    passphrase: &Passphrase,
    policy: &KdfPolicy,
) -> Result<Manifest> {
    Ok(open_manifest(archive_dir, passphrase, policy)?.0)
}

/// Authenticate every byte of an archive, writing nothing.
pub fn verify_archive(
    archive_dir: &Path,
    passphrase: &Passphrase,
    policy: &KdfPolicy,
    progress: &dyn Progress,
) -> Result<ArchiveSummary> {
    let (manifest, master_key) = open_manifest(archive_dir, passphrase, policy)?;
    let objects_dir = archive_dir.join(OBJECTS_DIR);

    let files: Vec<(&Entry, FileId, u64)> = manifest
        .entries
        .iter()
        .filter_map(|entry| match &entry.kind {
            EntryKind::File { file_id, size } => Some((entry, *file_id, *size)),
            _ => None,
        })
        .collect();

    let results: Vec<Result<()>> = files
        .par_iter()
        .map(|(entry, file_id, size)| {
            let path = object_path(&objects_dir, file_id);
            progress.file_started(&entry.display_path(), *size);

            let file = File::open(&path).map_err(|e| Error::io(&path, e))?;
            let mut reader = std::io::BufReader::new(file);
            verify_with_master(&mut reader, &master_key)?;

            progress.bytes_advanced(*size);
            progress.file_finished(&entry.display_path());
            Ok(())
        })
        .collect();
    for result in results {
        result?;
    }

    let mut summary = ArchiveSummary {
        files: files.len(),
        directories: manifest
            .entries
            .iter()
            .filter(|e| matches!(e.kind, EntryKind::Directory))
            .count(),
        symlinks: manifest
            .entries
            .iter()
            .filter(|e| matches!(e.kind, EntryKind::Symlink { .. }))
            .count(),
        bytes: manifest.total_size(),
        skipped: Vec::new(),
    };

    // An object nobody references is not corruption, but it is worth reporting:
    // it usually means an interrupted encrypt.
    let referenced: std::collections::HashSet<FileId> =
        files.iter().map(|(_, id, _)| *id).collect();
    for object in read_object_ids(&objects_dir)? {
        if !referenced.contains(&object) {
            summary.skipped.push((
                object_path(&objects_dir, &object),
                "object is not referenced by the manifest".to_owned(),
            ));
        }
    }

    Ok(summary)
}

/// Change an archive's passphrase.
///
/// Rewraps the 32-byte master key and rewrites the manifest container. No file
/// container is touched, so this costs one Argon2 pass and one small write
/// regardless of archive size.
pub fn rewrap_archive(
    archive_dir: &Path,
    old_passphrase: &Passphrase,
    new_passphrase: &Passphrase,
    options: &EncryptOptions,
) -> Result<()> {
    let (manifest, master_key) = open_manifest(archive_dir, old_passphrase, &options.policy)?;

    let keyring = rewrap_keyring(
        &master_key,
        new_passphrase,
        options.m_cost_kib,
        options.t_cost,
        options.p_cost,
        &options.policy,
    )?;

    let manifest_bytes = manifest.encode()?;
    let manifest_path = archive_dir.join(MANIFEST_FILE);
    atomic_write(&manifest_path, true, |file| {
        encrypt_stream_with_progress(
            &mut manifest_bytes.as_slice(),
            file,
            &master_key,
            ContainerKind::Manifest,
            options.chunk_size,
            Some(keyring.clone()),
            &mut |_| {},
        )
        .map(|_| ())
    })
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// Read and authenticate the manifest, recovering the master key.
fn open_manifest(
    archive_dir: &Path,
    passphrase: &Passphrase,
    policy: &KdfPolicy,
) -> Result<(Manifest, Key)> {
    let path = archive_dir.join(MANIFEST_FILE);
    let file = File::open(&path).map_err(|e| Error::io(&path, e))?;
    let mut reader = std::io::BufReader::new(file);

    let mut bytes = Vec::new();
    let (_, master_key) =
        crate::stream::decrypt_with_passphrase(&mut reader, &mut bytes, passphrase, policy)?;

    Ok((Manifest::decode(&bytes)?, master_key))
}

fn decrypt_one_file(
    objects_dir: &Path,
    file_id: &FileId,
    size: u64,
    target: &Path,
    master_key: &Key,
    options: &DecryptOptions,
    progress: &dyn Progress,
) -> Result<()> {
    let path = object_path(objects_dir, file_id);
    let file = File::open(&path).map_err(|e| Error::io(&path, e))?;
    let mut reader = std::io::BufReader::new(file);

    let parsed = crate::header::Header::read_from(&mut reader)?;
    let content_key =
        crate::keys::derive_content_key(master_key, &parsed.header.file_id, parsed.header.kind)?;

    atomic_write(target, options.force, |out| {
        let mut writer = std::io::BufWriter::new(out);
        // Padding, when enabled, means the container is longer than the file.
        // `size` from the manifest is authoritative; the extra bytes are dropped.
        let mut limited = LimitWriter::new(&mut writer, size);
        let mut last = 0u64;
        crate::stream::decrypt_body_with_progress(
            &mut reader,
            &mut limited,
            &parsed,
            &content_key,
            &mut |cumulative| {
                let real = cumulative.min(size);
                if real > last {
                    progress.bytes_advanced(real - last);
                    last = real;
                }
            },
        )?;
        writer.flush().map_err(|e| Error::io(target, e))?;
        Ok(())
    })
}

/// Everything the walk decided before any crypto happened.
struct Plan {
    entries: Vec<PlannedEntry>,
    skipped: Vec<(PathBuf, String)>,
}

struct PlannedEntry {
    source: PathBuf,
    relative: PathBuf,
    kind: PlannedKind,
}

enum PlannedKind {
    File { size: u64 },
    Directory,
    Symlink { target: Vec<u8> },
}

fn plan_inputs(inputs: &[PathBuf], progress: &dyn Progress) -> Result<Plan> {
    let mut plan = Plan {
        entries: Vec::new(),
        skipped: Vec::new(),
    };
    let mut top_level = std::collections::HashSet::new();

    for input in inputs {
        let metadata = std::fs::symlink_metadata(input).map_err(|e| Error::io(input, e))?;

        let name = input
            .file_name()
            .map(PathBuf::from)
            .ok_or_else(|| Error::UnsafePath {
                path: input.clone(),
            })?;

        if !top_level.insert(name.clone()) {
            return Err(Error::DuplicateInput { path: name });
        }

        if metadata.is_symlink() {
            plan.entries.push(PlannedEntry {
                source: input.clone(),
                relative: name,
                kind: PlannedKind::Symlink {
                    target: read_link_bytes(input)?,
                },
            });
            continue;
        }

        if metadata.is_file() {
            plan.entries.push(PlannedEntry {
                source: input.clone(),
                relative: name,
                kind: PlannedKind::File {
                    size: metadata.len(),
                },
            });
            continue;
        }

        // A directory: walk it without following links.
        for result in walkdir::WalkDir::new(input)
            .follow_links(false)
            .sort_by_file_name()
        {
            let dir_entry = match result {
                Ok(e) => e,
                Err(e) => {
                    let path = e
                        .path()
                        .map(Path::to_path_buf)
                        .unwrap_or_else(|| input.clone());
                    let reason = e.to_string();
                    progress.note(&format!("skipped {}: {reason}", path.display()));
                    plan.skipped.push((path, reason));
                    continue;
                }
            };

            let relative = match dir_entry.path().strip_prefix(input) {
                Ok(suffix) => name.join(suffix),
                Err(_) => {
                    plan.skipped.push((
                        dir_entry.path().to_path_buf(),
                        "path escaped the input root".to_owned(),
                    ));
                    continue;
                }
            };

            let file_type = dir_entry.file_type();
            let kind = if file_type.is_symlink() {
                PlannedKind::Symlink {
                    target: read_link_bytes(dir_entry.path())?,
                }
            } else if file_type.is_dir() {
                PlannedKind::Directory
            } else if file_type.is_file() {
                let metadata = dir_entry.metadata().map_err(|e| {
                    Error::io(
                        dir_entry.path(),
                        e.into_io_error()
                            .unwrap_or_else(|| std::io::Error::other("walk error")),
                    )
                })?;
                PlannedKind::File {
                    size: metadata.len(),
                }
            } else {
                // Sockets, FIFOs, devices: no meaningful contents to archive.
                let reason = "not a regular file, directory, or symlink".to_owned();
                progress.note(&format!("skipped {}: {reason}", dir_entry.path().display()));
                plan.skipped.push((dir_entry.path().to_path_buf(), reason));
                continue;
            };

            plan.entries.push(PlannedEntry {
                source: dir_entry.path().to_path_buf(),
                relative,
                kind,
            });
        }
    }

    Ok(plan)
}

fn read_link_bytes(path: &Path) -> Result<Vec<u8>> {
    let target = std::fs::read_link(path).map_err(|e| Error::io(path, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(target.as_os_str().as_bytes().to_vec())
    }
    #[cfg(not(unix))]
    {
        Ok(target.to_string_lossy().into_owned().into_bytes())
    }
}

#[cfg(unix)]
fn create_symlink(target: &[u8], path: &Path, force: bool) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    if path.exists() || path.symlink_metadata().is_ok() {
        if !force {
            return Err(Error::WouldOverwrite {
                path: path.to_path_buf(),
            });
        }
        std::fs::remove_file(path).map_err(|e| Error::io(path, e))?;
    }
    let target = std::ffi::OsStr::from_bytes(target);
    std::os::unix::fs::symlink(target, path).map_err(|e| Error::io(path, e))
}

#[cfg(not(unix))]
fn create_symlink(_target: &[u8], path: &Path, _force: bool) -> Result<()> {
    Err(Error::io(
        path,
        std::io::Error::other("symlink creation is not supported on this platform"),
    ))
}

fn restore_modes(
    dest: &Path,
    manifest: &Manifest,
    directories: &[(&Entry, PathBuf)],
) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        // Files first, then directories deepest-first, so a mode that removes
        // write permission cannot block a later write.
        for entry in &manifest.entries {
            if let (EntryKind::File { .. }, Some(mode)) = (&entry.kind, entry.mode) {
                let path = resolve(dest, entry)?;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                    .map_err(|e| Error::io(&path, e))?;
            }
        }

        let mut dirs: Vec<&(&Entry, PathBuf)> = directories.iter().collect();
        dirs.sort_by_key(|(_, path)| std::cmp::Reverse(path.components().count()));
        for (entry, path) in dirs {
            if let Some(mode) = entry.mode {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
                    .map_err(|e| Error::io(path, e))?;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (dest, manifest, directories);
    }
    Ok(())
}

/// The root that restored paths are joined onto.
///
/// On Windows, the canonical form of a path is the extended-length `\\?\` form,
/// which lifts the 260-character `MAX_PATH` limit, so long names and deep trees
/// restore as they do elsewhere. `dest` must already exist.
#[cfg(windows)]
fn destination_root(dest: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(dest).map_err(|e| Error::io(dest, e))
}

#[cfg(not(windows))]
fn destination_root(dest: &Path) -> Result<PathBuf> {
    Ok(dest.to_path_buf())
}

/// Join a validated manifest entry onto the destination root.
fn resolve(dest: &Path, entry: &Entry) -> Result<PathBuf> {
    Ok(dest.join(entry.to_relative_path()?))
}

/// `objects/<32 hex chars>.xcr`
pub fn object_path(objects_dir: &Path, file_id: &FileId) -> PathBuf {
    objects_dir.join(format!("{}.{OBJECT_EXT}", hex_encode(file_id)))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn hex_decode_file_id(name: &str) -> Option<FileId> {
    if name.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(name.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Identifiers of every object present in the objects directory.
fn read_object_ids(objects_dir: &Path) -> Result<Vec<FileId>> {
    let mut out = Vec::new();
    let dir = match std::fs::read_dir(objects_dir) {
        Ok(dir) => dir,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(Error::io(objects_dir, e)),
    };

    for result in dir {
        let dir_entry = result.map_err(|e| Error::io(objects_dir, e))?;
        let path = dir_entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some(OBJECT_EXT) {
            continue;
        }
        if let Some(id) = path
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(hex_decode_file_id)
        {
            out.push(id);
        }
    }
    Ok(out)
}

/// Delete objects the manifest does not reference. Only ever called *after* a
/// successful manifest swap.
fn prune_unreferenced_objects(
    objects_dir: &Path,
    manifest: &Manifest,
    progress: &dyn Progress,
) -> Result<()> {
    let referenced: std::collections::HashSet<FileId> = manifest
        .entries
        .iter()
        .filter_map(|entry| match &entry.kind {
            EntryKind::File { file_id, .. } => Some(*file_id),
            _ => None,
        })
        .collect();

    for id in read_object_ids(objects_dir)? {
        if !referenced.contains(&id) {
            let path = object_path(objects_dir, &id);
            match std::fs::remove_file(&path) {
                Ok(()) => progress.note(&format!("removed stale object {}", path.display())),
                Err(e) => progress.note(&format!("could not remove {}: {e}", path.display())),
            }
        }
    }
    sync_dir(objects_dir)
}

/// Stored length for a padded file: the next power of two, never below one chunk.
///
/// Buckets sizes so that "a 3 KiB file" and "a 4 KiB file" are indistinguishable
/// from their object size alone. It does not hide the archive total or the file
/// count — see `SPEC.md`.
pub fn padded_len(size: u64, chunk_size: u32) -> u64 {
    let floor = u64::from(chunk_size);
    if size <= floor {
        floor
    } else {
        size.checked_next_power_of_two().unwrap_or(size)
    }
}

/// A reader that yields `real` bytes from the source and then zeros up to
/// `target`.
struct PadReader<'a, R: Read> {
    inner: &'a mut R,
    remaining_real: u64,
    remaining_pad: u64,
}

impl<'a, R: Read> PadReader<'a, R> {
    fn new(inner: &'a mut R, real: u64, target: u64) -> Self {
        Self {
            inner,
            remaining_real: real,
            remaining_pad: target.saturating_sub(real),
        }
    }
}

impl<R: Read> Read for PadReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining_real > 0 {
            let limit = buf.len().min(self.remaining_real as usize);
            let n = self.inner.read(&mut buf[..limit])?;
            if n > 0 {
                self.remaining_real -= n as u64;
                return Ok(n);
            }
            // The file shrank under us. Make up the difference with padding
            // rather than writing a container that disagrees with the manifest.
            self.remaining_pad += self.remaining_real;
            self.remaining_real = 0;
        }

        if self.remaining_pad > 0 {
            let n = buf.len().min(self.remaining_pad as usize);
            buf[..n].fill(0);
            self.remaining_pad -= n as u64;
            return Ok(n);
        }

        Ok(0)
    }
}

/// A writer that passes through the first `limit` bytes and discards the rest.
struct LimitWriter<'a, W: Write> {
    inner: &'a mut W,
    remaining: u64,
}

impl<'a, W: Write> LimitWriter<'a, W> {
    fn new(inner: &'a mut W, limit: u64) -> Self {
        Self {
            inner,
            remaining: limit,
        }
    }
}

impl<W: Write> Write for LimitWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            // Report the bytes as consumed: they are padding, and the caller is
            // the AEAD stream, which must not see a short write.
            return Ok(buf.len());
        }
        let take = buf.len().min(self.remaining as usize);
        self.inner.write_all(&buf[..take])?;
        self.remaining -= take as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padded_len_buckets_by_powers_of_two() {
        assert_eq!(padded_len(0, 1024), 1024);
        assert_eq!(padded_len(1, 1024), 1024);
        assert_eq!(padded_len(1024, 1024), 1024);
        assert_eq!(padded_len(1025, 1024), 2048);
        assert_eq!(padded_len(3000, 1024), 4096);
        assert_eq!(padded_len(4096, 1024), 4096);
    }

    #[test]
    fn hex_roundtrip() {
        let id = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let encoded = hex_encode(&id);
        assert_eq!(encoded, "00112233445566778899aabbccddeeff");
        assert_eq!(hex_decode_file_id(&encoded), Some(id));
        assert_eq!(hex_decode_file_id("nothex"), None);
        assert_eq!(hex_decode_file_id(&"z".repeat(32)), None);
    }
}

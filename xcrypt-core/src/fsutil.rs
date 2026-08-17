//! Durable, atomic file replacement.
//!
//! The sequence is not negotiable if a crash must never leave a half-written
//! file behind:
//!
//! 1. write to a temporary file **in the destination directory** — `rename` is
//!    only atomic within a filesystem, and a temp file in `/tmp` may well be on
//!    another one;
//! 2. `fsync` the temp file, so its *contents* are durable before anything points
//!    at them;
//! 3. `rename` over the target, which is atomic: readers see either the old file
//!    or the new one;
//! 4. `fsync` the **parent directory**, so the *rename itself* is durable.
//!
//! Step 4 is the one that gets skipped. Without it, a crash can leave a
//! directory entry that still points at the old inode — or at nothing — even
//! though step 2 succeeded, because the directory block never reached the disk.

use std::fs::File;
use std::io::Write;
use std::path::Path;

use crate::error::{Error, Result};

/// Write `target` atomically and durably.
///
/// `write` receives the temporary file. If it returns an error, the temporary
/// file is removed and `target` is left exactly as it was — which is how this
/// crate guarantees that a failed decryption never leaves partial plaintext on
/// disk.
///
/// Set `force` to replace an existing `target`; otherwise an existing path is an
/// [`Error::WouldOverwrite`].
pub fn atomic_write<F>(target: &Path, force: bool, write: F) -> Result<()>
where
    F: FnOnce(&mut File) -> Result<()>,
{
    atomic_write_with_hook(target, force, write, || Ok(()))
}

/// [`atomic_write`], with a hook invoked after the temp file is synced and
/// immediately before the rename.
///
/// Exists so the atomicity test can inject a failure at precisely the moment
/// that matters. Production code calls [`atomic_write`].
pub fn atomic_write_with_hook<F, H>(
    target: &Path,
    force: bool,
    write: F,
    before_rename: H,
) -> Result<()>
where
    F: FnOnce(&mut File) -> Result<()>,
    H: FnOnce() -> Result<()>,
{
    if !force && target.exists() {
        return Err(Error::WouldOverwrite {
            path: target.to_path_buf(),
        });
    }

    let parent = target.parent().filter(|p| !p.as_os_str().is_empty());
    let dir = parent.unwrap_or_else(|| Path::new("."));

    // Same directory as the target: same filesystem, so the rename is atomic.
    let mut temp = tempfile::NamedTempFile::new_in(dir).map_err(|e| Error::io(dir, e))?;

    write(temp.as_file_mut())?;
    temp.as_file_mut()
        .flush()
        .map_err(|e| Error::io(temp.path(), e))?;
    temp.as_file()
        .sync_all()
        .map_err(|e| Error::io(temp.path(), e))?;

    before_rename()?;

    temp.persist(target)
        .map_err(|e| Error::io(target, e.error))?;

    sync_dir(dir)
}

/// `fsync` a directory so entries created or renamed inside it are durable.
///
/// On platforms where a directory cannot be opened for this purpose (Windows),
/// this is a no-op: `ReplaceFile`/`MoveFileEx` provide the ordering there.
pub fn sync_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let handle = File::open(dir).map_err(|e| Error::io(dir, e))?;
        handle.sync_all().map_err(|e| Error::io(dir, e))?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_and_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("data");

        atomic_write(&target, false, |f| {
            f.write_all(b"first").map_err(|e| Error::io("data", e))
        })
        .unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"first");

        atomic_write(&target, true, |f| {
            f.write_all(b"second").map_err(|e| Error::io("data", e))
        })
        .unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"second");
    }

    #[test]
    fn refuses_to_clobber_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("data");
        std::fs::write(&target, b"original").unwrap();

        let err = atomic_write(&target, false, |f| {
            f.write_all(b"new").map_err(|e| Error::io("data", e))
        })
        .unwrap_err();

        assert!(matches!(err, Error::WouldOverwrite { .. }));
        assert_eq!(std::fs::read(&target).unwrap(), b"original");
    }

    #[test]
    fn failure_during_write_leaves_no_trace() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("data");

        let err = atomic_write(&target, false, |f| {
            f.write_all(b"partial").map_err(|e| Error::io("data", e))?;
            Err(Error::Aead)
        })
        .unwrap_err();

        assert!(matches!(err, Error::Aead));
        assert!(!target.exists());
        // The temp file must be gone too, not merely unreferenced.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn failure_between_sync_and_rename_leaves_the_old_file_intact() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("data");
        std::fs::write(&target, b"old").unwrap();

        let err = atomic_write_with_hook(
            &target,
            true,
            |f| f.write_all(b"new").map_err(|e| Error::io("data", e)),
            || Err(Error::Aead),
        )
        .unwrap_err();

        assert!(matches!(err, Error::Aead));
        assert_eq!(std::fs::read(&target).unwrap(), b"old");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}

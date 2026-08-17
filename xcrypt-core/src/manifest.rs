//! The encrypted manifest: everything about a tree that is *not* file contents.
//!
//! Ciphertext objects on disk are named by their random `file_id` and carry no
//! metadata. Real paths, sizes, modes, mtimes, and symlink targets live here, and
//! this structure is itself stored as an `XCR1` container (kind
//! [`ContainerKind::Manifest`](crate::header::ContainerKind::Manifest)), so an
//! attacker with the archive directory sees only: object count, object sizes, and
//! the total.
//!
//! # Paths are stored as component byte strings
//!
//! Not as a single string, and not as UTF-8. Two reasons:
//!
//! * Unix paths are arbitrary bytes; forcing UTF-8 would make perfectly ordinary
//!   files unarchivable. Components are `Vec<u8>` and converted back with
//!   `OsStrExt` on Unix.
//! * A pre-split component list makes path traversal checkable by construction.
//!   [`Entry::to_relative_path`] rejects `..`, absolute roots, empty components,
//!   embedded separators, and NUL bytes, so a hostile manifest cannot write
//!   outside the destination directory.

use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

use crate::error::{Error, Result};
use crate::header::FileId;

/// Manifest format version, independent of the container version.
pub const MANIFEST_VERSION: u16 = 1;

/// What an entry describes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryKind {
    /// A regular file, stored as `objects/<hex file_id>.xcr`.
    File {
        /// Identifier of the container holding the contents.
        file_id: FileId,
        /// True plaintext length. The stored container may be longer when
        /// `--pad-names` is in effect; decryption truncates to this.
        size: u64,
    },
    /// A directory. Recorded explicitly so empty directories survive.
    Directory,
    /// A symbolic link, recorded rather than followed.
    Symlink {
        /// The link target exactly as it was read, byte for byte.
        target: Vec<u8>,
    },
}

/// One archived path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Path components relative to the archive root.
    pub components: Vec<Vec<u8>>,
    /// What lives at that path.
    pub kind: EntryKind,
    /// Unix mode bits, when the source filesystem had them.
    pub mode: Option<u32>,
    /// Modification time, seconds since the Unix epoch.
    pub mtime_secs: Option<i64>,
    /// Sub-second part of the modification time.
    pub mtime_nanos: Option<u32>,
}

impl Entry {
    /// Build an entry from a path relative to the archive root.
    pub fn new(relative: &Path, kind: EntryKind) -> Result<Self> {
        let components = encode_components(relative)?;
        Ok(Self {
            components,
            kind,
            mode: None,
            mtime_secs: None,
            mtime_nanos: None,
        })
    }

    /// Attach ownership-free metadata read from the source filesystem.
    pub fn with_metadata(mut self, metadata: &std::fs::Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            self.mode = Some(metadata.permissions().mode());
        }
        if let Ok(mtime) = metadata.modified() {
            match mtime.duration_since(std::time::UNIX_EPOCH) {
                Ok(d) => {
                    self.mtime_secs = Some(d.as_secs() as i64);
                    self.mtime_nanos = Some(d.subsec_nanos());
                }
                // Timestamps before 1970 are legal; record them as negative.
                Err(e) => {
                    let d = e.duration();
                    self.mtime_secs = Some(-(d.as_secs() as i64));
                    self.mtime_nanos = Some(d.subsec_nanos());
                }
            }
        }
        self
    }

    /// Validate the components and rebuild a relative path.
    ///
    /// This is the only sanctioned way to turn manifest bytes into a path. It
    /// refuses anything that could escape the destination directory, so a
    /// tampered or maliciously authored manifest cannot write to `/etc` or
    /// `../..`.
    pub fn to_relative_path(&self) -> Result<PathBuf> {
        if self.components.is_empty() {
            return Err(Error::InvalidManifest {
                detail: "entry has no path components".to_owned(),
            });
        }

        let mut path = PathBuf::new();
        for raw in &self.components {
            let component = decode_component(raw)?;
            let as_path = Path::new(&component);
            // Exactly one ordinary component, nothing else.
            let mut parts = as_path.components();
            match (parts.next(), parts.next()) {
                (Some(Component::Normal(_)), None) => {}
                _ => {
                    return Err(Error::UnsafePath {
                        path: self.display_path(),
                    })
                }
            }
            path.push(component);
        }
        Ok(path)
    }

    /// A lossy, human-readable path for listings and error messages.
    pub fn display_path(&self) -> PathBuf {
        let mut path = PathBuf::new();
        for raw in &self.components {
            path.push(String::from_utf8_lossy(raw).into_owned());
        }
        path
    }

    /// Plaintext size for files; zero for anything else.
    pub fn size(&self) -> u64 {
        match &self.kind {
            EntryKind::File { size, .. } => *size,
            _ => 0,
        }
    }
}

/// The whole archive's metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Manifest format version.
    pub version: u16,
    /// Every archived path, in the order it was walked.
    pub entries: Vec<Entry>,
}

impl Manifest {
    /// An empty manifest at the current version.
    pub fn new() -> Self {
        Self {
            version: MANIFEST_VERSION,
            entries: Vec::new(),
        }
    }

    /// Encode to `postcard`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self).map_err(|_| Error::InvalidManifest {
            detail: "manifest could not be encoded".to_owned(),
        })
    }

    /// Decode and validate.
    ///
    /// Validation happens here rather than at use sites: an unknown version, a
    /// duplicate object, or a traversal attempt is rejected before any caller can
    /// act on an entry.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let manifest: Manifest =
            postcard::from_bytes(bytes).map_err(|_| Error::InvalidManifest {
                detail: "manifest is malformed".to_owned(),
            })?;

        if manifest.version != MANIFEST_VERSION {
            return Err(Error::InvalidManifest {
                detail: format!(
                    "manifest version {} is not supported (this build reads {MANIFEST_VERSION})",
                    manifest.version
                ),
            });
        }

        let mut seen_ids = std::collections::HashSet::new();
        let mut seen_paths = std::collections::HashSet::new();
        for entry in &manifest.entries {
            let path = entry.to_relative_path()?;
            if !seen_paths.insert(path.clone()) {
                return Err(Error::InvalidManifest {
                    detail: format!("duplicate entry for {}", path.display()),
                });
            }
            if let EntryKind::File { file_id, .. } = &entry.kind {
                if !seen_ids.insert(*file_id) {
                    return Err(Error::InvalidManifest {
                        detail: "two entries name the same object".to_owned(),
                    });
                }
            }
        }

        Ok(manifest)
    }

    /// Total plaintext bytes across all files.
    pub fn total_size(&self) -> u64 {
        self.entries.iter().map(Entry::size).sum()
    }

    /// Count of file entries.
    pub fn file_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| matches!(e.kind, EntryKind::File { .. }))
            .count()
    }
}

impl Default for Manifest {
    fn default() -> Self {
        Self::new()
    }
}

/// Split a relative path into raw component bytes, rejecting anything unsafe.
fn encode_components(relative: &Path) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => out.push(os_str_bytes(part)),
            // A path being *archived* should already be relative and normalized;
            // anything else is a bug in the walker, not user error.
            _ => {
                return Err(Error::UnsafePath {
                    path: relative.to_path_buf(),
                })
            }
        }
    }
    if out.is_empty() {
        return Err(Error::UnsafePath {
            path: relative.to_path_buf(),
        });
    }
    Ok(out)
}

/// Reject NUL bytes and separators inside a single component, then decode.
fn decode_component(raw: &[u8]) -> Result<std::ffi::OsString> {
    if raw.is_empty()
        || raw.contains(&0)
        || raw.contains(&b'/')
        || raw.contains(&b'\\')
        || raw == b"."
        || raw == b".."
    {
        return Err(Error::InvalidManifest {
            detail: "path component is empty, reserved, or contains a separator".to_owned(),
        });
    }
    os_string_from_bytes(raw)
}

#[cfg(unix)]
fn os_str_bytes(s: &std::ffi::OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    s.as_bytes().to_vec()
}

#[cfg(not(unix))]
fn os_str_bytes(s: &std::ffi::OsStr) -> Vec<u8> {
    // Non-Unix targets go through UTF-8, which is what their filesystems use.
    s.to_string_lossy().into_owned().into_bytes()
}

#[cfg(unix)]
fn os_string_from_bytes(raw: &[u8]) -> Result<std::ffi::OsString> {
    use std::os::unix::ffi::OsStringExt;
    Ok(std::ffi::OsString::from_vec(raw.to_vec()))
}

#[cfg(not(unix))]
fn os_string_from_bytes(raw: &[u8]) -> Result<std::ffi::OsString> {
    String::from_utf8(raw.to_vec())
        .map(Into::into)
        .map_err(|_| Error::InvalidManifest {
            detail: "path component is not valid UTF-8 and this platform requires it".to_owned(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_entry(path: &str) -> Entry {
        Entry::new(
            Path::new(path),
            EntryKind::File {
                file_id: [1u8; 16],
                size: 10,
            },
        )
        .unwrap()
    }

    #[test]
    fn roundtrip() {
        let mut manifest = Manifest::new();
        manifest.entries.push(file_entry("a/b/c.txt"));
        manifest
            .entries
            .push(Entry::new(Path::new("a/b"), EntryKind::Directory).unwrap());
        manifest.entries.push(
            Entry::new(
                Path::new("a/link"),
                EntryKind::Symlink {
                    target: b"../elsewhere".to_vec(),
                },
            )
            .unwrap(),
        );

        let bytes = manifest.encode().unwrap();
        assert_eq!(Manifest::decode(&bytes).unwrap(), manifest);
    }

    #[test]
    fn unicode_and_emoji_paths_survive() {
        for path in [
            "ünïcödé/файл.txt",
            "emoji/🔐📁/naïve.md",
            "spaces  and.tabs",
        ] {
            let mut manifest = Manifest::new();
            manifest.entries.push(file_entry(path));
            let decoded = Manifest::decode(&manifest.encode().unwrap()).unwrap();
            assert_eq!(
                decoded.entries[0].to_relative_path().unwrap(),
                Path::new(path)
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_paths_survive() {
        use std::os::unix::ffi::OsStrExt;
        let raw = std::ffi::OsStr::from_bytes(b"weird\xff\xfename");
        let entry = Entry::new(
            Path::new(raw),
            EntryKind::File {
                file_id: [2u8; 16],
                size: 0,
            },
        )
        .unwrap();

        let mut manifest = Manifest::new();
        manifest.entries.push(entry);
        let decoded = Manifest::decode(&manifest.encode().unwrap()).unwrap();
        assert_eq!(
            decoded.entries[0].to_relative_path().unwrap(),
            Path::new(raw)
        );
    }

    #[test]
    fn traversal_components_are_rejected() {
        for evil in [
            vec![b"..".to_vec()],
            vec![b"ok".to_vec(), b"..".to_vec()],
            vec![b"/etc".to_vec()],
            vec![b"a/b".to_vec()],
            vec![b"a\\b".to_vec()],
            vec![b".".to_vec()],
            vec![b"".to_vec()],
            vec![b"nul\0byte".to_vec()],
            vec![],
        ] {
            let entry = Entry {
                components: evil.clone(),
                kind: EntryKind::Directory,
                mode: None,
                mtime_secs: None,
                mtime_nanos: None,
            };
            assert!(
                entry.to_relative_path().is_err(),
                "components {evil:?} were accepted"
            );

            let manifest = Manifest {
                version: MANIFEST_VERSION,
                entries: vec![entry],
            };
            assert!(
                Manifest::decode(&manifest.encode().unwrap()).is_err(),
                "components {evil:?} survived manifest validation"
            );
        }
    }

    #[test]
    fn duplicate_paths_are_rejected() {
        let manifest = Manifest {
            version: MANIFEST_VERSION,
            entries: vec![file_entry("a.txt"), file_entry("a.txt")],
        };
        assert!(matches!(
            Manifest::decode(&manifest.encode().unwrap()),
            Err(Error::InvalidManifest { .. })
        ));
    }

    #[test]
    fn duplicate_object_ids_are_rejected() {
        let manifest = Manifest {
            version: MANIFEST_VERSION,
            entries: vec![file_entry("a.txt"), file_entry("b.txt")],
        };
        assert!(matches!(
            Manifest::decode(&manifest.encode().unwrap()),
            Err(Error::InvalidManifest { .. })
        ));
    }

    #[test]
    fn unknown_manifest_version_is_rejected() {
        let manifest = Manifest {
            version: MANIFEST_VERSION + 1,
            entries: vec![],
        };
        assert!(matches!(
            Manifest::decode(&manifest.encode().unwrap()),
            Err(Error::InvalidManifest { .. })
        ));
    }

    #[test]
    fn duplicate_basenames_in_different_directories_are_fine() {
        let manifest = Manifest {
            version: MANIFEST_VERSION,
            entries: vec![
                Entry::new(
                    Path::new("one/notes.txt"),
                    EntryKind::File {
                        file_id: [1u8; 16],
                        size: 1,
                    },
                )
                .unwrap(),
                Entry::new(
                    Path::new("two/notes.txt"),
                    EntryKind::File {
                        file_id: [2u8; 16],
                        size: 1,
                    },
                )
                .unwrap(),
            ],
        };
        assert!(Manifest::decode(&manifest.encode().unwrap()).is_ok());
    }
}

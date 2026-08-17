//! Bundling an archive directory into a single file, and back.
//!
//! An archive directory is the working format: it is what makes atomic object
//! writes, a cheap `rewrap`, and parallel encryption possible. A packed file is
//! what you hand to someone, upload, or drop on a USB stick.
//!
//! # What packing adds beyond convenience
//!
//! A directory leaks two things a packed file does not: **how many objects there
//! are** (which is how many files you archived) and **how large each one is**
//! (which tracks file sizes unless `--pad-names` was used). A packed file is a
//! single `XCR1` container, so an observer sees one blob and its total size.
//!
//! # Layout
//!
//! The packed file is an ordinary `XCR1` container of
//! [`ContainerKind::Pack`], carrying the archive's own keyring, so it opens with
//! the archive's passphrase and no second Argon2 pass is introduced. Its
//! *plaintext* is a simple framed bundle:
//!
//! ```text
//! "XPK1" ‖ u16_le version
//! entry* ‖ 0xFF
//!
//! entry := 0x01 ‖ file_id[16] ‖ u64_le len ‖ object_bytes      (an object)
//!        | 0x00 ‖              u64_le len ‖ manifest_bytes     (the manifest)
//! ```
//!
//! Objects come first and the manifest last, so unpacking writes the manifest
//! last too — the same ordering that makes a directory archive crash-consistent.
//!
//! Both directions stream. Packing a 100 GiB archive never buffers more than one
//! chunk, and unpacking writes each object to a temporary file that is renamed
//! into place only once its length is complete.
//!
//! # On double encryption
//!
//! Objects inside a packed file are encrypted twice: once as their own
//! containers, once as part of the pack stream. That is a CPU cost (ChaCha20
//! runs at gigabytes per second) and not a security problem — but it is why
//! packing is a deliberate step rather than the default output format.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

use crate::archive::{object_path, MANIFEST_FILE, OBJECTS_DIR};
use crate::archive::{EncryptOptions, Progress};
use crate::error::{Error, Result};
use crate::fsutil::{atomic_write, sync_dir};
use crate::header::{ContainerKind, FileId, Header, KdfPolicy, FILE_ID_LEN};
use crate::keys::{derive_content_key, unwrap_master_key, Passphrase};
use crate::manifest::Manifest;
use crate::stream::{decrypt_body_with_progress, encrypt_stream_with_progress};

/// Magic at the start of a bundle's plaintext.
pub const BUNDLE_MAGIC: [u8; 4] = *b"XPK1";

/// Bundle framing version.
pub const BUNDLE_VERSION: u16 = 1;

/// Conventional extension for a packed archive.
pub const PACK_EXT: &str = "xcra";

const TAG_MANIFEST: u8 = 0x00;
const TAG_OBJECT: u8 = 0x01;
const TAG_END: u8 = 0xFF;

/// Bytes of bundle preamble: magic plus version.
const PREAMBLE: usize = 6;

/// What a pack or unpack produced.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PackSummary {
    /// Object containers bundled or restored.
    pub objects: usize,
    /// Files the manifest describes.
    pub files: usize,
    /// Bytes of bundle plaintext (the sum of every container packed).
    pub bundle_len: u64,
    /// Size of the packed file on disk, or of the file that was unpacked.
    pub packed_len: u64,
}

/// Bundle an archive directory into a single packed file.
///
/// Opens the archive first: the passphrase must be correct, and the manifest
/// must authenticate, before anything is written. The keyring is copied into the
/// packed file's header, so the packed file opens with the same passphrase.
pub fn pack_archive(
    archive_dir: &Path,
    output: &Path,
    passphrase: &Passphrase,
    options: &EncryptOptions,
    progress: &dyn Progress,
) -> Result<PackSummary> {
    let manifest_path = archive_dir.join(MANIFEST_FILE);
    let objects_dir = archive_dir.join(OBJECTS_DIR);

    // Authenticate the archive and recover both the keyring and the master key.
    let mut reader = std::io::BufReader::new(
        File::open(&manifest_path).map_err(|e| Error::io(&manifest_path, e))?,
    );
    let parsed = Header::read_from(&mut reader)?;
    let keyring = parsed
        .header
        .keyring
        .clone()
        .ok_or_else(|| Error::InvalidHeaderField {
            detail: "archive manifest carries no keyring".to_owned(),
        })?;

    let master_key = unwrap_master_key(&keyring, passphrase, &options.policy)?;
    let content_key = derive_content_key(&master_key, &parsed.header.file_id, parsed.header.kind)?;

    let mut manifest_bytes = Vec::new();
    decrypt_body_with_progress(
        &mut reader,
        &mut manifest_bytes,
        &parsed,
        &content_key,
        &mut |_| {},
    )?;
    let manifest = Manifest::decode(&manifest_bytes)?;

    // Every object the manifest references, in manifest order. Objects present
    // on disk but unreferenced are deliberately dropped: packing is a good
    // moment to shed the debris of an interrupted encrypt.
    let mut parts: VecDeque<Part> = VecDeque::new();
    let mut preamble = Vec::with_capacity(PREAMBLE);
    preamble.extend_from_slice(&BUNDLE_MAGIC);
    preamble.extend_from_slice(&BUNDLE_VERSION.to_le_bytes());
    parts.push_back(Part::bytes(preamble));

    let mut bundle_len = PREAMBLE as u64;
    let mut objects = 0usize;

    for file_id in manifest.object_ids() {
        let path = object_path(&objects_dir, &file_id);
        let len = std::fs::metadata(&path)
            .map_err(|e| Error::io(&path, e))?
            .len();

        let mut header = Vec::with_capacity(1 + FILE_ID_LEN + 8);
        header.push(TAG_OBJECT);
        header.extend_from_slice(&file_id);
        header.extend_from_slice(&len.to_le_bytes());

        bundle_len += header.len() as u64 + len;
        parts.push_back(Part::bytes(header));
        parts.push_back(Part::file(path, len));
        objects += 1;
    }

    // The manifest goes last, so unpacking persists it last.
    let manifest_len = std::fs::metadata(&manifest_path)
        .map_err(|e| Error::io(&manifest_path, e))?
        .len();
    let mut header = Vec::with_capacity(9);
    header.push(TAG_MANIFEST);
    header.extend_from_slice(&manifest_len.to_le_bytes());
    bundle_len += header.len() as u64 + manifest_len + 1;
    parts.push_back(Part::bytes(header));
    parts.push_back(Part::file(manifest_path, manifest_len));
    parts.push_back(Part::bytes(vec![TAG_END]));

    progress.file_started(output, bundle_len);

    let mut last = 0u64;
    atomic_write(output, options.force, |file| {
        let mut writer = std::io::BufWriter::new(file);
        let mut bundle = BundleReader { parts };
        encrypt_stream_with_progress(
            &mut bundle,
            &mut writer,
            &master_key,
            ContainerKind::Pack,
            options.chunk_size,
            Some(keyring.clone()),
            &mut |cumulative| {
                if cumulative > last {
                    progress.bytes_advanced(cumulative - last);
                    last = cumulative;
                }
            },
        )?;
        writer.flush().map_err(|e| Error::io(output, e))?;
        Ok(())
    })?;

    progress.file_finished(output);

    Ok(PackSummary {
        objects,
        files: manifest.file_count(),
        bundle_len,
        packed_len: std::fs::metadata(output).map(|m| m.len()).unwrap_or(0),
    })
}

/// Restore a packed file into an archive directory.
///
/// The directory produced is byte-for-byte the archive that was packed, so
/// `list`, `verify`, `decrypt`, and `rewrap` all work on it exactly as before.
///
/// On any failure the destination is removed, because a partially unpacked
/// archive is not a smaller archive — it is one whose manifest references
/// objects that are not there.
pub fn unpack_archive(
    packed: &Path,
    archive_dir: &Path,
    passphrase: &Passphrase,
    policy: &KdfPolicy,
    force: bool,
    progress: &dyn Progress,
) -> Result<PackSummary> {
    if archive_dir.exists() {
        let manifest = archive_dir.join(MANIFEST_FILE);
        if manifest.exists() && !force {
            return Err(Error::WouldOverwrite { path: manifest });
        }
    }

    let packed_len = std::fs::metadata(packed)
        .map_err(|e| Error::io(packed, e))?
        .len();

    let mut reader = std::io::BufReader::new(File::open(packed).map_err(|e| Error::io(packed, e))?);
    let parsed = Header::read_from(&mut reader)?;

    if parsed.header.kind != ContainerKind::Pack {
        return Err(Error::InvalidHeaderField {
            detail: "this file is a container but not a packed archive".to_owned(),
        });
    }

    let keyring = parsed
        .header
        .keyring
        .as_ref()
        .ok_or_else(|| Error::InvalidHeaderField {
            detail: "packed archive carries no keyring".to_owned(),
        })?;
    let master_key = unwrap_master_key(keyring, passphrase, policy)?;
    let content_key = derive_content_key(&master_key, &parsed.header.file_id, parsed.header.kind)?;

    let objects_dir = archive_dir.join(OBJECTS_DIR);
    std::fs::create_dir_all(&objects_dir).map_err(|e| Error::io(&objects_dir, e))?;

    let result = (|| -> Result<PackSummary> {
        let mut sink = BundleWriter::new(archive_dir.to_path_buf(), objects_dir.clone());
        let mut last = 0u64;

        decrypt_body_with_progress(
            &mut reader,
            &mut sink,
            &parsed,
            &content_key,
            &mut |cumulative| {
                if cumulative > last {
                    progress.bytes_advanced(cumulative - last);
                    last = cumulative;
                }
            },
        )
        .map_err(|e| sink.take_failure().unwrap_or(e))?;

        let objects = sink.finish()?;
        sync_dir(&objects_dir)?;
        sync_dir(archive_dir)?;

        // Read the manifest back through the ordinary path: an unpacked archive
        // that cannot be listed is not an archive.
        let manifest = crate::archive::list_archive(archive_dir, passphrase, policy)?;

        Ok(PackSummary {
            objects,
            files: manifest.file_count(),
            bundle_len: last,
            packed_len,
        })
    })();

    if result.is_err() {
        // A half-unpacked directory is worse than none: it would list objects
        // the manifest does not describe, or a manifest whose objects are absent.
        let _ = std::fs::remove_dir_all(archive_dir);
    }

    result
}

// ---------------------------------------------------------------------------
// Packing: a reader that concatenates in-memory frames and whole files
// ---------------------------------------------------------------------------

enum Part {
    Bytes(Cursor<Vec<u8>>),
    File {
        path: PathBuf,
        handle: Option<File>,
        remaining: u64,
    },
}

impl Part {
    fn bytes(data: Vec<u8>) -> Self {
        Part::Bytes(Cursor::new(data))
    }

    fn file(path: PathBuf, len: u64) -> Self {
        Part::File {
            path,
            handle: None,
            remaining: len,
        }
    }
}

/// Streams the bundle framing without ever holding an object in memory.
struct BundleReader {
    parts: VecDeque<Part>,
}

impl Read for BundleReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while let Some(part) = self.parts.front_mut() {
            match part {
                Part::Bytes(cursor) => {
                    let n = cursor.read(buf)?;
                    if n > 0 {
                        return Ok(n);
                    }
                    self.parts.pop_front();
                }
                Part::File {
                    path,
                    handle,
                    remaining,
                } => {
                    if *remaining == 0 {
                        self.parts.pop_front();
                        continue;
                    }
                    if handle.is_none() {
                        *handle = Some(File::open(&*path)?);
                    }
                    let file = handle.as_mut().expect("just opened");
                    let limit = buf.len().min(*remaining as usize);
                    let n = file.read(&mut buf[..limit])?;
                    if n == 0 {
                        // The declared length and the file disagree. Refusing is
                        // the only safe option: a short object would produce a
                        // bundle whose framing no longer lines up.
                        return Err(std::io::Error::other(format!(
                            "{} shrank while it was being packed",
                            path.display()
                        )));
                    }
                    *remaining -= n as u64;
                    return Ok(n);
                }
            }
        }
        Ok(0)
    }
}

// ---------------------------------------------------------------------------
// Unpacking: a writer that parses the framing as chunks authenticate
// ---------------------------------------------------------------------------

enum State {
    Preamble(Vec<u8>),
    Tag,
    ManifestLen(Vec<u8>),
    ObjectHeader(Vec<u8>),
    Payload {
        remaining: u64,
        temp: tempfile::NamedTempFile,
        target: PathBuf,
    },
    Done,
}

/// Consumes bundle plaintext incrementally, writing each entry to its own file.
///
/// Implemented as a `Write` so it can sit directly under the AEAD stream: every
/// byte it sees has already been authenticated by the chunk it arrived in.
struct BundleWriter {
    archive_dir: PathBuf,
    objects_dir: PathBuf,
    state: State,
    objects: usize,
    failure: Option<Error>,
}

impl BundleWriter {
    fn new(archive_dir: PathBuf, objects_dir: PathBuf) -> Self {
        Self {
            archive_dir,
            objects_dir,
            state: State::Preamble(Vec::with_capacity(PREAMBLE)),
            objects: 0,
            failure: None,
        }
    }

    /// Take the typed error, if the failure originated here rather than in the
    /// AEAD. Keeps `io::Error` from swallowing a precise diagnosis.
    fn take_failure(&mut self) -> Option<Error> {
        self.failure.take()
    }

    fn finish(mut self) -> Result<usize> {
        if let Some(error) = self.failure.take() {
            return Err(error);
        }
        match self.state {
            State::Done => Ok(self.objects),
            _ => Err(Error::Truncated {
                detail: "packed archive ends before its bundle is complete",
            }),
        }
    }

    fn fail(&mut self, error: Error) -> std::io::Error {
        let message = error.to_string();
        self.failure = Some(error);
        std::io::Error::other(message)
    }

    /// Consume as much of `buf` as the current state wants; return how much.
    ///
    /// The state is moved out for the duration so that `self` stays free for
    /// helper calls, and moved back afterwards. On error it is left as `Done`
    /// and the typed cause is recorded in `failure`.
    fn step(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let state = std::mem::replace(&mut self.state, State::Done);
        let (consumed, next) = self.advance(state, buf)?;
        self.state = next;
        Ok(consumed)
    }

    fn advance(&mut self, state: State, buf: &[u8]) -> std::io::Result<(usize, State)> {
        match state {
            State::Preamble(mut got) => {
                let take = buf.len().min(PREAMBLE - got.len());
                got.extend_from_slice(&buf[..take]);
                if got.len() < PREAMBLE {
                    return Ok((take, State::Preamble(got)));
                }
                if got[..4] != BUNDLE_MAGIC {
                    return Err(self.fail(Error::InvalidManifest {
                        detail: "packed archive does not start with a bundle header".to_owned(),
                    }));
                }
                let version = u16::from_le_bytes([got[4], got[5]]);
                if version != BUNDLE_VERSION {
                    return Err(self.fail(Error::InvalidManifest {
                        detail: format!(
                            "bundle version {version} is not supported \
                             (this build reads {BUNDLE_VERSION})"
                        ),
                    }));
                }
                Ok((take, State::Tag))
            }

            State::Tag => match buf[0] {
                TAG_OBJECT => Ok((1, State::ObjectHeader(Vec::with_capacity(FILE_ID_LEN + 8)))),
                TAG_MANIFEST => Ok((1, State::ManifestLen(Vec::with_capacity(8)))),
                TAG_END => Ok((1, State::Done)),
                other => Err(self.fail(Error::InvalidManifest {
                    detail: format!("unknown bundle entry tag 0x{other:02x}"),
                })),
            },

            State::ManifestLen(mut got) => {
                let take = buf.len().min(8 - got.len());
                got.extend_from_slice(&buf[..take]);
                if got.len() < 8 {
                    return Ok((take, State::ManifestLen(got)));
                }
                let len = u64::from_le_bytes(got[..8].try_into().expect("eight bytes"));
                let target = self.archive_dir.join(MANIFEST_FILE);
                let dir = self.archive_dir.clone();
                Ok((take, self.begin_payload(len, target, &dir)?))
            }

            State::ObjectHeader(mut got) => {
                let want = FILE_ID_LEN + 8;
                let take = buf.len().min(want - got.len());
                got.extend_from_slice(&buf[..take]);
                if got.len() < want {
                    return Ok((take, State::ObjectHeader(got)));
                }
                let file_id: FileId = got[..FILE_ID_LEN].try_into().expect("sixteen bytes");
                let len =
                    u64::from_le_bytes(got[FILE_ID_LEN..want].try_into().expect("eight bytes"));
                let target = object_path(&self.objects_dir, &file_id);
                let dir = self.objects_dir.clone();
                self.objects += 1;
                Ok((take, self.begin_payload(len, target, &dir)?))
            }

            State::Payload {
                mut remaining,
                mut temp,
                target,
            } => {
                let take = buf.len().min(remaining as usize);
                temp.as_file_mut().write_all(&buf[..take])?;
                remaining -= take as u64;

                if remaining > 0 {
                    return Ok((
                        take,
                        State::Payload {
                            remaining,
                            temp,
                            target,
                        },
                    ));
                }

                // Same durability rule as everywhere else: sync, then rename.
                temp.as_file().sync_all()?;
                temp.persist(&target)
                    .map_err(|e| std::io::Error::other(e.error))?;
                Ok((take, State::Tag))
            }

            State::Done => Err(self.fail(Error::InvalidManifest {
                detail: "packed archive has data after its end marker".to_owned(),
            })),
        }
    }

    fn begin_payload(&mut self, len: u64, target: PathBuf, dir: &Path) -> std::io::Result<State> {
        let temp = tempfile::NamedTempFile::new_in(dir)?;
        Ok(State::Payload {
            remaining: len,
            temp,
            target,
        })
    }
}

impl Write for BundleWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut consumed = 0;
        while consumed < buf.len() {
            let n = self.step(&buf[consumed..])?;
            if n == 0 {
                // Only reachable if a state consumed nothing, which would spin.
                return Err(self.fail(Error::InvalidManifest {
                    detail: "bundle parser made no progress".to_owned(),
                }));
            }
            consumed += n;
        }
        Ok(consumed)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_reader_concatenates_parts() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("payload");
        std::fs::write(&file, b"file contents").unwrap();

        let mut parts = VecDeque::new();
        parts.push_back(Part::bytes(b"head".to_vec()));
        parts.push_back(Part::file(file, 13));
        parts.push_back(Part::bytes(b"tail".to_vec()));

        let mut out = Vec::new();
        BundleReader { parts }.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"headfile contentstail");
    }

    #[test]
    fn bundle_reader_refuses_a_file_that_shrank() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("payload");
        std::fs::write(&file, b"short").unwrap();

        let mut parts = VecDeque::new();
        parts.push_back(Part::file(file, 500));

        let mut out = Vec::new();
        assert!(BundleReader { parts }.read_to_end(&mut out).is_err());
    }

    #[test]
    fn bundle_writer_rejects_a_bad_preamble() {
        let dir = tempfile::tempdir().unwrap();
        let mut writer = BundleWriter::new(dir.path().to_path_buf(), dir.path().to_path_buf());
        assert!(writer.write_all(b"NOPE\x01\x00").is_err());
        assert!(writer.take_failure().is_some());
    }

    #[test]
    fn bundle_writer_rejects_an_unfinished_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let mut writer = BundleWriter::new(dir.path().to_path_buf(), dir.path().to_path_buf());
        let mut preamble = BUNDLE_MAGIC.to_vec();
        preamble.extend_from_slice(&BUNDLE_VERSION.to_le_bytes());
        writer.write_all(&preamble).unwrap();
        assert!(matches!(writer.finish(), Err(Error::Truncated { .. })));
    }
}

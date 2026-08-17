//! The single error type for every fallible operation in this crate.
//!
//! Two properties are load-bearing and are enforced by tests:
//!
//! 1. **Distinguishable.** Every way a container can be malformed maps to its
//!    own variant, so callers (and the corruption test suite) can assert *how*
//!    a bad archive failed, not merely that it did.
//! 2. **Secret-free.** No variant carries a key, a passphrase, or plaintext,
//!    and none of the `Display` strings interpolate one. `tests::no_secrets`
//!    formats every variant to keep it that way.

use std::path::PathBuf;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// What went wrong.
///
/// Marked `#[non_exhaustive]`: new failure modes may be added without a
/// breaking change, so match with a `_` arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The first four bytes were not `XCR1`. Not an xcrypt container at all.
    #[error("not an xcrypt container: bad magic bytes")]
    BadMagic,

    /// The container declares a format version this build cannot read.
    #[error("unsupported container version {found} (this build reads version {supported})")]
    UnsupportedVersion {
        /// Version read from the container.
        found: u16,
        /// Version this build understands.
        supported: u16,
    },

    /// The declared header length is implausible. Rejected *before* allocating,
    /// so a hostile length field cannot exhaust memory.
    #[error("declared header length {len} exceeds the {limit} byte limit")]
    HeaderTooLarge {
        /// Length claimed by the container.
        len: u64,
        /// Maximum this build will allocate for a header.
        limit: u64,
    },

    /// The header bytes are not a valid encoding of a header.
    #[error("container header is malformed")]
    MalformedHeader,

    /// The header decoded, but re-encoding it does not reproduce the bytes on
    /// disk. Accepting non-canonical encodings would let an attacker mutate the
    /// AAD-covered bytes without changing their meaning.
    #[error("container header is not canonically encoded")]
    NonCanonicalHeader,

    /// The header declares a chunk size outside the permitted range.
    #[error("header declares chunk size {size}, outside the permitted range {min}..={max}")]
    InvalidChunkSize {
        /// Size claimed by the header.
        size: u32,
        /// Smallest accepted chunk size.
        min: u32,
        /// Largest accepted chunk size.
        max: u32,
    },

    /// The header declares KDF parameters the active policy refuses.
    ///
    /// Low values are the interesting case: they are a cost-downgrade attempt,
    /// which is why this is a hard error rather than a warning. High values are
    /// refused as a memory-exhaustion guard.
    #[error("header declares KDF parameters outside policy: {detail}")]
    KdfParamsRejected {
        /// Which bound was violated, with the offending value.
        detail: String,
    },

    /// A structural field was inconsistent (recipient count, wrapped-key
    /// length, and similar shape checks).
    #[error("container header is structurally invalid: {detail}")]
    InvalidHeaderField {
        /// Which invariant failed.
        detail: String,
    },

    /// No recipient in the keyring could be unwrapped with the supplied
    /// credential.
    ///
    /// This is what a wrong passphrase looks like. It is deliberately *also*
    /// what in-policy tampered KDF parameters look like: both cases end with a
    /// KEK that fails to authenticate the wrapped master key, and pretending to
    /// tell them apart would mean trusting attacker-controlled bytes.
    #[error(
        "no recipient could be unwrapped (wrong passphrase, or the keyring was tampered with)"
    )]
    NoMatchingRecipient,

    /// A chunk failed authentication: the data has been modified, reordered,
    /// duplicated, spliced in from elsewhere, or the wrong key was used.
    #[error("authentication failed for chunk {index}: data is corrupt or has been tampered with")]
    ChunkAuthFailed {
        /// Zero-based index of the offending chunk.
        index: u64,
    },

    /// The container ended earlier than its own structure requires.
    #[error("container is truncated: {detail}")]
    Truncated {
        /// Where the shortfall was detected.
        detail: &'static str,
    },

    /// The STREAM chunk counter would wrap. Wrapping would reuse a nonce, so
    /// this is a hard error instead.
    #[error("chunk counter exhausted: input is too large for one container")]
    CounterExhausted,

    /// Encryption or key wrapping failed inside the AEAD. Should not happen for
    /// well-formed inputs; surfaced rather than unwrapped.
    #[error("AEAD operation failed")]
    Aead,

    /// The manifest is internally inconsistent (bad path, missing object).
    #[error("archive manifest is invalid: {detail}")]
    InvalidManifest {
        /// What was wrong with the manifest.
        detail: String,
    },

    /// A manifest entry named a path that escapes the destination directory.
    #[error("manifest entry rejected: path {path} escapes the destination directory")]
    UnsafePath {
        /// The rejected path, as recorded in the manifest.
        path: PathBuf,
    },

    /// Two inputs would occupy the same top-level name in the archive.
    ///
    /// Merging them silently would let one input shadow the other, so this is an
    /// error the user has to resolve.
    #[error("two inputs would both be archived as {path}; rename one or archive them separately")]
    DuplicateInput {
        /// The colliding top-level name.
        path: PathBuf,
    },

    /// Refusing to clobber something that already exists.
    #[error("{path} already exists (pass --force to overwrite)")]
    WouldOverwrite {
        /// The existing path.
        path: PathBuf,
    },

    /// An I/O error, tagged with the path it happened on.
    #[error("i/o error on {path}: {source}")]
    Io {
        /// Path being operated on.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// An I/O error with no meaningful path (in-memory readers, stdin/stdout).
    #[error("i/o error: {0}")]
    BareIo(#[source] std::io::Error),
}

impl Error {
    /// Attach a path to an [`std::io::Error`].
    ///
    /// Public because callers doing their own I/O around this crate — the CLI,
    /// the closure passed to [`crate::fsutil::atomic_write`] — need to produce
    /// the same shape of error.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.into(),
            source,
        }
    }

    /// A short, stable, machine-readable tag for `--json` output and tests.
    ///
    /// These strings are part of the CLI contract; changing one is a breaking
    /// change for anyone matching on them.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::BadMagic => "bad_magic",
            Error::UnsupportedVersion { .. } => "unsupported_version",
            Error::HeaderTooLarge { .. } => "header_too_large",
            Error::MalformedHeader => "malformed_header",
            Error::NonCanonicalHeader => "non_canonical_header",
            Error::InvalidChunkSize { .. } => "invalid_chunk_size",
            Error::KdfParamsRejected { .. } => "kdf_params_rejected",
            Error::InvalidHeaderField { .. } => "invalid_header_field",
            Error::NoMatchingRecipient => "no_matching_recipient",
            Error::ChunkAuthFailed { .. } => "chunk_auth_failed",
            Error::Truncated { .. } => "truncated",
            Error::CounterExhausted => "counter_exhausted",
            Error::Aead => "aead",
            Error::InvalidManifest { .. } => "invalid_manifest",
            Error::UnsafePath { .. } => "unsafe_path",
            Error::DuplicateInput { .. } => "duplicate_input",
            Error::WouldOverwrite { .. } => "would_overwrite",
            Error::Io { .. } | Error::BareIo(_) => "io",
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::BareIo(e)
    }
}

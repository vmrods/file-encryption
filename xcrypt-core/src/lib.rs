//! `xcrypt-core` — authenticated, streaming encryption of files and directory
//! trees.
//!
//! This crate owns the container format, the key hierarchy, and the crypto
//! policy. It performs I/O through [`std::io`] traits and, for archives, through
//! [`fsutil`], but it makes no decisions about progress reporting, prompting, or
//! argument parsing — those belong to `xcrypt-cli`.
//!
//! Nothing cryptographic is implemented here. Every primitive comes from the
//! RustCrypto ecosystem: Argon2id for password hashing, HKDF-SHA256 for key
//! derivation, XChaCha20-Poly1305 for the AEAD, and the STREAM construction for
//! chunked authentication.
//!
//! # Reading order
//!
//! * [`header`] — the on-disk format, its limits, and why the header is AAD.
//! * [`keys`] — passphrase → KEK → master key → per-container key.
//! * [`stream`] — chunked encrypt/decrypt, with a worked example.
//! * [`fsutil`] — atomic, durable replacement of a file.
//!
//! `SPEC.md` documents the byte layout and the threat model.
//!
//! # What this defends against, in one line each
//!
//! * An attacker holding the ciphertext learns nothing but its size and how many
//!   containers exist. Filenames, paths, sizes, and mtimes live in an encrypted
//!   manifest; on-disk objects are named by a random `file_id`.
//! * Any modification — a flipped bit, a reordered chunk, a truncated file, a
//!   swapped header, a downgraded KDF cost — fails authentication and produces a
//!   typed error, never partial plaintext.
//!
//! It does **not** defend against an attacker on the running machine, keys
//! resident in memory during an operation, correlation of total archive size, or
//! coercion.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod archive;
pub mod error;
pub mod fsutil;
pub mod header;
pub mod keys;
pub mod manifest;
pub mod pack;
pub mod stream;

pub use archive::{
    decrypt_archive, encrypt_paths, list_archive, rewrap_archive, verify_archive, ArchiveSummary,
    DecryptOptions, EncryptOptions, NoProgress, Progress,
};
pub use error::{Error, Result};
pub use header::{
    ContainerKind, FileId, Header, KdfAlgorithm, KdfParams, KdfPolicy, Keyring, ParsedHeader,
    Recipient, RecipientKind, DEFAULT_CHUNK_SIZE, MAGIC, MAX_CHUNK_SIZE, MAX_HEADER_LEN,
    MIN_CHUNK_SIZE, VERSION,
};
pub use keys::{
    derive_content_key, derive_kek, new_keyring, rewrap_keyring, unwrap_master_key, Key, Passphrase,
};
pub use manifest::{Entry, EntryKind, Manifest};
pub use pack::{pack_archive, unpack_archive, PackSummary, PACK_EXT};
pub use stream::{
    decrypt_body, decrypt_with_master, decrypt_with_passphrase, encrypt_stream,
    encrypt_stream_with_progress, verify_with_master, ContainerStats,
};

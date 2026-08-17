//! The `XCR1` container header: its types, its canonical encoding, and the
//! limits applied to it before a single byte is trusted.
//!
//! # Wire layout
//!
//! ```text
//! "XCR1" ‖ u32_le header_len ‖ header_bytes ‖ chunk[0] ‖ … ‖ chunk[n]
//! ```
//!
//! `header_bytes` is the canonical [`postcard`] encoding of [`Header`], and the
//! **entire blob is fed as AAD to every chunk's AEAD**. That single decision is
//! what makes header swapping, keyring substitution, and KDF cost downgrade
//! detectable rather than merely improbable: alter any header byte and no chunk
//! authenticates.
//!
//! Because the header is AAD, the bytes on disk — not a re-serialization — are
//! what must be used. [`ParsedHeader`] keeps them together for that reason, and
//! [`Header::parse`] rejects any encoding that is not the canonical one, so
//! "same meaning, different bytes" is not a way to move the AAD around.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Magic bytes at offset 0 of every container.
pub const MAGIC: [u8; 4] = *b"XCR1";

/// Format version this build writes and reads.
pub const VERSION: u16 = 1;

/// Bytes of `MAGIC` plus the `u32_le` header length.
pub const PREAMBLE_LEN: usize = 8;

/// Largest header this build will allocate for. Real headers are ~150–200 bytes;
/// this is generous by two orders of magnitude and still bounds the allocation a
/// hostile length field can request.
pub const MAX_HEADER_LEN: u32 = 64 * 1024;

/// STREAM nonce prefix length: XChaCha20-Poly1305's 24-byte nonce minus the
/// 5 bytes `StreamBE32` reserves for the counter and last-block flag.
pub const NONCE_PREFIX_LEN: usize = 19;

/// Nonce length for the one-shot XChaCha20-Poly1305 key wrap.
pub const WRAP_NONCE_LEN: usize = 24;

/// A wrapped master key: 32 key bytes plus a 16-byte Poly1305 tag.
pub const WRAPPED_KEY_LEN: usize = 48;

/// Length of the random per-file identifier.
pub const FILE_ID_LEN: usize = 16;

/// Length of the Argon2 salt.
pub const SALT_LEN: usize = 32;

/// Default plaintext chunk size (64 KiB).
pub const DEFAULT_CHUNK_SIZE: u32 = 64 * 1024;

/// Smallest permitted chunk size. Below this the per-chunk 16-byte tag becomes a
/// significant fraction of the container.
pub const MIN_CHUNK_SIZE: u32 = 1024;

/// Largest permitted chunk size. Bounds the streaming buffer a header can make
/// the decryptor allocate.
pub const MAX_CHUNK_SIZE: u32 = 8 * 1024 * 1024;

/// Largest permitted recipient count.
pub const MAX_RECIPIENTS: usize = 16;

/// Longest permitted recipient label, in bytes.
pub const MAX_RECIPIENT_LABEL_LEN: usize = 128;

/// Random per-file identifier. Also the on-disk object name, so stored files
/// leak nothing about their original names.
pub type FileId = [u8; FILE_ID_LEN];

/// Which HKDF label a container's content key is derived under.
///
/// Domain separation: a manifest container can never be swapped in for a file
/// container, because the two derive different keys from the same master key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainerKind {
    /// A user file's contents.
    File,
    /// The archive manifest (paths, sizes, modes, mtimes).
    Manifest,
    /// A whole archive directory bundled into one file by `xcrypt pack`.
    ///
    /// Added after version 1 shipped. The discriminant is appended, so every
    /// container written before it still parses; a build that predates this
    /// variant rejects a packed file as a malformed header rather than
    /// misreading it.
    Pack,
}

impl ContainerKind {
    /// The HKDF `info` label suffix for this kind.
    pub(crate) const fn hkdf_label(self) -> &'static [u8] {
        match self {
            ContainerKind::File => b"xcrypt-v1-file",
            ContainerKind::Manifest => b"xcrypt-v1-manifest",
            ContainerKind::Pack => b"xcrypt-v1-pack",
        }
    }
}

/// Password-hashing algorithm identifier. An enum rather than a bool so a future
/// migration is a format addition, not a format break.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KdfAlgorithm {
    /// Argon2id, version 0x13.
    Argon2id,
}

/// Argon2id parameters and salt, stored so archives written under old defaults
/// stay openable after the defaults change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Algorithm identifier.
    pub algorithm: KdfAlgorithm,
    /// Memory cost in KiB (Argon2 `m`).
    pub m_cost_kib: u32,
    /// Iteration count (Argon2 `t`).
    pub t_cost: u32,
    /// Parallelism (Argon2 `p`).
    pub p_cost: u32,
    /// Salt. 32 random bytes.
    pub salt: [u8; SALT_LEN],
}

impl KdfParams {
    /// Default cost: `m = 256 MiB, t = 3, p = 4`, with a fresh random salt.
    pub fn new_default(salt: [u8; SALT_LEN]) -> Self {
        Self {
            algorithm: KdfAlgorithm::Argon2id,
            m_cost_kib: 256 * 1024,
            t_cost: 3,
            p_cost: 4,
            salt,
        }
    }
}

/// How a recipient's copy of the master key is protected.
///
/// The keyring is a list from day one so that hardware tokens and printed
/// recovery keys are later a new variant here plus a new unwrap path — not a
/// format break.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecipientKind {
    /// KEK derived from a passphrase via the header's [`KdfParams`].
    Passphrase,
}

/// One wrapped copy of the archive's master key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recipient {
    /// How to derive this recipient's key-encryption key.
    pub kind: RecipientKind,
    /// Optional non-secret hint shown by `xcrypt list` (e.g. `"laptop yubikey"`).
    pub label: Option<String>,
    /// Nonce for the wrap AEAD.
    pub nonce: [u8; WRAP_NONCE_LEN],
    /// The wrapped master key: 32 bytes of ciphertext plus a 16-byte tag.
    ///
    /// `Vec<u8>` rather than `[u8; 48]` only because future recipient kinds may
    /// carry a different length; header validation pins it to exactly
    /// [`WRAPPED_KEY_LEN`] for the kinds that exist today.
    pub wrapped_master_key: Vec<u8>,
}

impl Recipient {
    fn validate(&self) -> Result<()> {
        if self.wrapped_master_key.len() != WRAPPED_KEY_LEN {
            return Err(Error::InvalidHeaderField {
                detail: format!(
                    "wrapped master key is {} bytes, expected {WRAPPED_KEY_LEN}",
                    self.wrapped_master_key.len()
                ),
            });
        }
        if let Some(label) = &self.label {
            if label.len() > MAX_RECIPIENT_LABEL_LEN {
                return Err(Error::InvalidHeaderField {
                    detail: format!(
                        "recipient label is {} bytes, limit is {MAX_RECIPIENT_LABEL_LEN}",
                        label.len()
                    ),
                });
            }
        }
        Ok(())
    }
}

/// The keyring: KDF parameters plus every wrapped copy of the master key.
///
/// Present in exactly one container per archive (the manifest). File containers
/// carry `keyring: None` and are keyed straight from the master key, which is
/// what makes changing a passphrase a rewrite of one small container instead of
/// every file in the archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Keyring {
    /// Parameters used to derive every passphrase recipient's KEK.
    pub kdf: KdfParams,
    /// Wrapped master keys, tried in order.
    pub recipients: Vec<Recipient>,
}

/// A container header.
///
/// Deliberately has no `Debug`-visible secrets: every field is either public
/// metadata or ciphertext. There is no key material here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// Format version. Must equal [`VERSION`].
    pub version: u16,
    /// Which HKDF label the content key was derived under.
    pub kind: ContainerKind,
    /// Random per-container identifier, and the HKDF salt-substitute that makes
    /// each container's content key unique.
    pub file_id: FileId,
    /// Plaintext bytes per chunk.
    pub chunk_size: u32,
    /// STREAM nonce prefix, from the OS CSPRNG.
    pub nonce_prefix: [u8; NONCE_PREFIX_LEN],
    /// Wrapped master keys, present only in the archive's root container.
    pub keyring: Option<Keyring>,
}

/// Bounds applied to attacker-supplied KDF parameters at decrypt time.
///
/// The minimums are the security-relevant half: without them, an attacker who
/// can rewrite a header rewrites `m = 256 MiB` to `m = 8 KiB`, hands the archive
/// back, and brute-forces the passphrase cheaply offline. The maximums bound how
/// much memory a header can make this process request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfPolicy {
    /// Smallest accepted memory cost, in KiB.
    pub min_m_cost_kib: u32,
    /// Largest accepted memory cost, in KiB.
    pub max_m_cost_kib: u32,
    /// Smallest accepted iteration count.
    pub min_t_cost: u32,
    /// Largest accepted iteration count.
    pub max_t_cost: u32,
    /// Largest accepted parallelism.
    pub max_p_cost: u32,
}

impl Default for KdfPolicy {
    /// 19 MiB / t=2 minimum (the OWASP floor for Argon2id), 2 GiB / t=32 ceiling.
    fn default() -> Self {
        Self {
            min_m_cost_kib: 19 * 1024,
            max_m_cost_kib: 2 * 1024 * 1024,
            min_t_cost: 2,
            max_t_cost: 32,
            max_p_cost: 64,
        }
    }
}

impl KdfPolicy {
    /// A policy with no lower bound, for tests and benchmarks that cannot afford
    /// a real KDF. Never use this on data anyone cares about.
    pub const fn permissive() -> Self {
        Self {
            min_m_cost_kib: 8,
            max_m_cost_kib: 2 * 1024 * 1024,
            min_t_cost: 1,
            max_t_cost: 32,
            max_p_cost: 64,
        }
    }

    /// Check `params` against this policy.
    pub fn check(&self, params: &KdfParams) -> Result<()> {
        let reject = |detail: String| Err(Error::KdfParamsRejected { detail });

        if params.m_cost_kib < self.min_m_cost_kib {
            return reject(format!(
                "m_cost {} KiB is below the {} KiB minimum (cost-downgrade attempt?)",
                params.m_cost_kib, self.min_m_cost_kib
            ));
        }
        if params.m_cost_kib > self.max_m_cost_kib {
            return reject(format!(
                "m_cost {} KiB exceeds the {} KiB maximum",
                params.m_cost_kib, self.max_m_cost_kib
            ));
        }
        if params.t_cost < self.min_t_cost {
            return reject(format!(
                "t_cost {} is below the minimum of {} (cost-downgrade attempt?)",
                params.t_cost, self.min_t_cost
            ));
        }
        if params.t_cost > self.max_t_cost {
            return reject(format!(
                "t_cost {} exceeds the maximum of {}",
                params.t_cost, self.max_t_cost
            ));
        }
        if params.p_cost == 0 || params.p_cost > self.max_p_cost {
            return reject(format!(
                "p_cost {} is outside 1..={}",
                params.p_cost, self.max_p_cost
            ));
        }
        Ok(())
    }
}

/// A header together with the exact bytes it was decoded from.
///
/// The bytes are the AAD, so they must be preserved verbatim rather than
/// reconstructed.
#[derive(Debug, Clone)]
pub struct ParsedHeader {
    /// The decoded header.
    pub header: Header,
    /// The canonical encoding, byte-for-byte as it appeared on disk. This is the
    /// AAD for every chunk.
    pub aad: Vec<u8>,
}

impl Header {
    /// Encode to the canonical `postcard` form.
    ///
    /// Deterministic: the same `Header` always produces the same bytes, which is
    /// what lets [`Header::parse`] treat a mismatch as tampering.
    pub fn encode(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self).map_err(|_| Error::MalformedHeader)
    }

    /// Decode and validate `bytes`, which must be a whole header blob.
    ///
    /// Rejects: unknown versions, non-canonical encodings, trailing garbage,
    /// out-of-range chunk sizes, and structurally impossible keyrings. Does *not*
    /// apply [`KdfPolicy`] — that happens where a passphrase is available, so
    /// that `list`-style callers can inspect an archive's parameters first.
    pub fn parse(bytes: &[u8]) -> Result<ParsedHeader> {
        let (header, rest): (Header, &[u8]) =
            postcard::take_from_bytes(bytes).map_err(|_| Error::MalformedHeader)?;
        if !rest.is_empty() {
            // Extra bytes inside the header region: the length field and the
            // encoding disagree. Refuse rather than ignore the remainder.
            return Err(Error::MalformedHeader);
        }

        if header.version != VERSION {
            return Err(Error::UnsupportedVersion {
                found: header.version,
                supported: VERSION,
            });
        }

        // Canonicality: re-encode and compare. A non-minimal varint or any other
        // alternate encoding of the same values is rejected here.
        let reencoded = header.encode()?;
        if reencoded != bytes {
            return Err(Error::NonCanonicalHeader);
        }

        header.validate()?;

        Ok(ParsedHeader {
            header,
            aad: reencoded,
        })
    }

    /// Read `MAGIC`, the length prefix, and the header from `reader`, leaving it
    /// positioned at `chunk[0]`.
    pub fn read_from<R: std::io::Read>(reader: &mut R) -> Result<ParsedHeader> {
        let mut preamble = [0u8; PREAMBLE_LEN];
        read_exact_or_truncated(
            reader,
            &mut preamble,
            "container is shorter than its preamble",
        )?;

        if preamble[..4] != MAGIC {
            return Err(Error::BadMagic);
        }

        let len = u32::from_le_bytes([preamble[4], preamble[5], preamble[6], preamble[7]]);
        // Bound-check before allocating: this is the resource-exhaustion guard.
        if len > MAX_HEADER_LEN {
            return Err(Error::HeaderTooLarge {
                len: u64::from(len),
                limit: u64::from(MAX_HEADER_LEN),
            });
        }
        if len == 0 {
            return Err(Error::MalformedHeader);
        }

        let mut bytes = vec![0u8; len as usize];
        read_exact_or_truncated(reader, &mut bytes, "container ends inside its header")?;
        Header::parse(&bytes)
    }

    /// Write `MAGIC`, the length prefix, and `aad` to `writer`.
    pub(crate) fn write_to<W: std::io::Write>(writer: &mut W, aad: &[u8]) -> Result<()> {
        debug_assert!(aad.len() <= MAX_HEADER_LEN as usize);
        let len = u32::try_from(aad.len()).map_err(|_| Error::MalformedHeader)?;
        writer.write_all(&MAGIC)?;
        writer.write_all(&len.to_le_bytes())?;
        writer.write_all(aad)?;
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if self.chunk_size < MIN_CHUNK_SIZE || self.chunk_size > MAX_CHUNK_SIZE {
            return Err(Error::InvalidChunkSize {
                size: self.chunk_size,
                min: MIN_CHUNK_SIZE,
                max: MAX_CHUNK_SIZE,
            });
        }
        if let Some(keyring) = &self.keyring {
            if keyring.recipients.is_empty() {
                return Err(Error::InvalidHeaderField {
                    detail: "keyring has no recipients".to_owned(),
                });
            }
            if keyring.recipients.len() > MAX_RECIPIENTS {
                return Err(Error::InvalidHeaderField {
                    detail: format!(
                        "keyring has {} recipients, limit is {MAX_RECIPIENTS}",
                        keyring.recipients.len()
                    ),
                });
            }
            for recipient in &keyring.recipients {
                recipient.validate()?;
            }
        }
        Ok(())
    }
}

/// `read_exact`, but EOF becomes a typed truncation error rather than an
/// `io::ErrorKind::UnexpectedEof`.
fn read_exact_or_truncated<R: std::io::Read>(
    reader: &mut R,
    buf: &mut [u8],
    detail: &'static str,
) -> Result<()> {
    match reader.read_exact(buf) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Err(Error::Truncated { detail }),
        Err(e) => Err(Error::BareIo(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(keyring: bool) -> Header {
        Header {
            version: VERSION,
            kind: ContainerKind::File,
            file_id: [7u8; FILE_ID_LEN],
            chunk_size: DEFAULT_CHUNK_SIZE,
            nonce_prefix: [9u8; NONCE_PREFIX_LEN],
            keyring: keyring.then(|| Keyring {
                kdf: KdfParams::new_default([3u8; SALT_LEN]),
                recipients: vec![Recipient {
                    kind: RecipientKind::Passphrase,
                    label: Some("primary".to_owned()),
                    nonce: [1u8; WRAP_NONCE_LEN],
                    wrapped_master_key: vec![2u8; WRAPPED_KEY_LEN],
                }],
            }),
        }
    }

    #[test]
    fn roundtrip_with_and_without_keyring() {
        for keyring in [false, true] {
            let header = sample(keyring);
            let bytes = header.encode().unwrap();
            let parsed = Header::parse(&bytes).unwrap();
            assert_eq!(parsed.header, header);
            assert_eq!(parsed.aad, bytes);
        }
    }

    #[test]
    fn encoding_is_deterministic() {
        let header = sample(true);
        assert_eq!(header.encode().unwrap(), header.encode().unwrap());
    }

    #[test]
    fn real_headers_are_far_below_the_length_limit() {
        assert!(sample(true).encode().unwrap().len() < 512);
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = sample(false).encode().unwrap();
        bytes.push(0);
        assert!(matches!(
            Header::parse(&bytes),
            Err(Error::MalformedHeader | Error::NonCanonicalHeader)
        ));
    }

    #[test]
    fn empty_keyring_is_rejected() {
        let mut header = sample(true);
        header.keyring.as_mut().unwrap().recipients.clear();
        let bytes = header.encode().unwrap();
        assert!(matches!(
            Header::parse(&bytes),
            Err(Error::InvalidHeaderField { .. })
        ));
    }

    #[test]
    fn short_wrapped_key_is_rejected() {
        let mut header = sample(true);
        header.keyring.as_mut().unwrap().recipients[0]
            .wrapped_master_key
            .truncate(WRAPPED_KEY_LEN - 1);
        let bytes = header.encode().unwrap();
        assert!(matches!(
            Header::parse(&bytes),
            Err(Error::InvalidHeaderField { .. })
        ));
    }

    #[test]
    fn absurd_chunk_size_is_rejected() {
        for size in [0, MIN_CHUNK_SIZE - 1, MAX_CHUNK_SIZE + 1, u32::MAX] {
            let mut header = sample(false);
            header.chunk_size = size;
            let bytes = header.encode().unwrap();
            assert!(
                matches!(Header::parse(&bytes), Err(Error::InvalidChunkSize { .. })),
                "chunk_size {size} was accepted"
            );
        }
    }

    #[test]
    fn unknown_version_is_rejected() {
        let mut header = sample(false);
        header.version = VERSION + 1;
        let bytes = header.encode().unwrap();
        assert!(matches!(
            Header::parse(&bytes),
            Err(Error::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut bytes = b"XCR0\x01\x00\x00\x00".to_vec();
        bytes.push(0);
        assert!(matches!(
            Header::read_from(&mut bytes.as_slice()),
            Err(Error::BadMagic)
        ));
    }

    #[test]
    fn absurd_header_len_is_rejected_before_allocating() {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        // No header body follows: the length must be rejected on its own.
        assert!(matches!(
            Header::read_from(&mut bytes.as_slice()),
            Err(Error::HeaderTooLarge { .. })
        ));
    }

    #[test]
    fn policy_rejects_downgraded_and_absurd_costs() {
        let policy = KdfPolicy::default();
        let mut params = KdfParams::new_default([0u8; SALT_LEN]);
        policy.check(&params).unwrap();

        params.m_cost_kib = 8;
        assert!(matches!(
            policy.check(&params),
            Err(Error::KdfParamsRejected { .. })
        ));

        params = KdfParams::new_default([0u8; SALT_LEN]);
        params.m_cost_kib = u32::MAX;
        assert!(matches!(
            policy.check(&params),
            Err(Error::KdfParamsRejected { .. })
        ));

        params = KdfParams::new_default([0u8; SALT_LEN]);
        params.t_cost = 1;
        assert!(matches!(
            policy.check(&params),
            Err(Error::KdfParamsRejected { .. })
        ));

        params = KdfParams::new_default([0u8; SALT_LEN]);
        params.p_cost = 0;
        assert!(matches!(
            policy.check(&params),
            Err(Error::KdfParamsRejected { .. })
        ));
    }
}

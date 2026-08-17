//! Streaming container encryption and decryption.
//!
//! Uses the STREAM construction (`EncryptorBE32` / `DecryptorBE32` over
//! XChaCha20-Poly1305) rather than a hand-rolled nonce scheme. STREAM gives
//! three properties that are tedious and error-prone to reimplement:
//!
//! * the per-chunk nonce is `prefix ‖ u32_be counter ‖ last_block_flag`, so
//!   chunk **reordering** and **duplication** change the nonce and fail
//!   authentication;
//! * the final chunk sets the flag bit, so **truncation** — including dropping
//!   the last chunk entirely — fails authentication rather than silently
//!   yielding a shorter file;
//! * the counter is managed by the construction, so there is no arithmetic here
//!   to get wrong.
//!
//! Every chunk additionally authenticates the whole header blob as AAD, which
//! binds the ciphertext to its parameters and its keyring.
//!
//! Memory use is bounded at two chunks plus tags, regardless of file size.
//!
//! # Example
//!
//! ```
//! use std::io::Cursor;
//! use xcrypt_core::{ContainerKind, Key, DEFAULT_CHUNK_SIZE, decrypt_with_master, encrypt_stream};
//!
//! // In a real archive the master key comes from a keyring; see `keys`.
//! let master = Key::random();
//! let plaintext = b"the quick brown fox".repeat(10_000);
//!
//! let mut container = Vec::new();
//! let stats = encrypt_stream(
//!     &mut Cursor::new(&plaintext),
//!     &mut container,
//!     &master,
//!     ContainerKind::File,
//!     DEFAULT_CHUNK_SIZE,
//!     None, // no keyring: this container is keyed straight from the master key
//! )?;
//! assert_eq!(stats.plaintext_len, plaintext.len() as u64);
//!
//! let mut recovered = Vec::new();
//! decrypt_with_master(&mut Cursor::new(&container), &mut recovered, &master)?;
//! assert_eq!(recovered, plaintext);
//!
//! // Any single-bit change anywhere in the container is detected.
//! let mut tampered = container.clone();
//! *tampered.last_mut().unwrap() ^= 1;
//! assert!(decrypt_with_master(&mut Cursor::new(&tampered), &mut Vec::new(), &master).is_err());
//! # Ok::<(), xcrypt_core::Error>(())
//! ```

use std::io::{Read, Write};

use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};

use crate::error::{Error, Result};
use crate::header::{
    ContainerKind, FileId, Header, KdfPolicy, Keyring, ParsedHeader, NONCE_PREFIX_LEN, VERSION,
};
use crate::keys::{
    derive_content_key, random_bytes, random_file_id, unwrap_master_key, Key, Passphrase,
};

/// Poly1305 tag length; each chunk grows by this much.
pub const TAG_LEN: usize = 16;

/// Chunks a single container may hold, bounded by STREAM's 32-bit counter.
///
/// At the 64 KiB default that is 256 TiB per container; hitting it is a hard
/// error rather than a counter wrap, because wrapping would reuse a nonce.
pub const MAX_CHUNKS: u64 = u32::MAX as u64;

/// What a completed container encryption produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainerStats {
    /// The container's random identifier — also its on-disk object name.
    pub file_id: FileId,
    /// Plaintext bytes consumed.
    pub plaintext_len: u64,
    /// Container bytes written, header and tags included.
    pub ciphertext_len: u64,
    /// Chunks written. Always at least one, even for empty input.
    pub chunks: u64,
}

/// Called with the number of plaintext bytes completed so far, for progress UI.
pub type ProgressFn<'a> = &'a mut dyn FnMut(u64);

fn no_progress(_: u64) {}

/// Encrypt `reader` into a complete `XCR1` container on `writer`.
///
/// `keyring` is `Some` only for an archive's root container; file containers pass
/// `None` and are keyed directly from `master_key`.
///
/// The container is written strictly forward with no seeking, so `writer` may be
/// a pipe. Nothing is buffered beyond two chunks.
pub fn encrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    master_key: &Key,
    kind: ContainerKind,
    chunk_size: u32,
    keyring: Option<Keyring>,
) -> Result<ContainerStats> {
    encrypt_stream_with_progress(
        reader,
        writer,
        master_key,
        kind,
        chunk_size,
        keyring,
        &mut no_progress,
    )
}

/// [`encrypt_stream`] with a progress callback.
pub fn encrypt_stream_with_progress<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    master_key: &Key,
    kind: ContainerKind,
    chunk_size: u32,
    keyring: Option<Keyring>,
    progress: ProgressFn<'_>,
) -> Result<ContainerStats> {
    let header = Header {
        version: VERSION,
        kind,
        file_id: random_file_id(),
        chunk_size,
        nonce_prefix: random_bytes::<NONCE_PREFIX_LEN>(),
        keyring,
    };

    // Encode, then parse our own output. The parse applies exactly the checks a
    // decryptor applies, so it is impossible to write a container this build
    // would refuse to read, and it yields the canonical AAD bytes.
    let encoded = header.encode()?;
    let parsed = Header::parse(&encoded)?;

    let content_key = derive_content_key(master_key, &header.file_id, kind)?;
    let cipher = XChaCha20Poly1305::new(content_key.expose().into());
    let mut encryptor = Some(EncryptorBE32::from_aead(
        cipher,
        GenericArray::from_slice(&header.nonce_prefix),
    ));

    Header::write_to(writer, &parsed.aad)?;
    let mut ciphertext_len = (crate::header::PREAMBLE_LEN + parsed.aad.len()) as u64;
    let mut plaintext_len = 0u64;
    let mut chunks = 0u64;

    let chunk_size = chunk_size as usize;
    let mut buf = Vec::with_capacity(chunk_size + TAG_LEN);

    loop {
        buf.clear();
        let n = read_up_to(reader, &mut buf, chunk_size)?;
        let is_last = n < chunk_size;

        if chunks >= MAX_CHUNKS {
            return Err(Error::CounterExhausted);
        }

        if is_last {
            encryptor
                .take()
                .expect("encryptor is consumed only on the final chunk")
                .encrypt_last_in_place(&parsed.aad, &mut buf)
                .map_err(|_| Error::Aead)?;
        } else {
            encryptor
                .as_mut()
                .expect("encryptor is consumed only on the final chunk")
                .encrypt_next_in_place(&parsed.aad, &mut buf)
                .map_err(|_| Error::CounterExhausted)?;
        }

        writer.write_all(&buf)?;
        ciphertext_len += buf.len() as u64;
        plaintext_len += n as u64;
        chunks += 1;
        progress(plaintext_len);

        if is_last {
            break;
        }
    }

    Ok(ContainerStats {
        file_id: header.file_id,
        plaintext_len,
        ciphertext_len,
        chunks,
    })
}

/// Decrypt a container's body, given its already-parsed header and content key.
///
/// Plaintext is handed to `writer` chunk by chunk *as it authenticates*, so a
/// container that fails partway through will already have written earlier
/// chunks. Callers that must not expose partial plaintext — all of them, in this
/// crate — write to a temporary file and rename only on success; see
/// [`crate::fsutil::atomic_write`].
pub fn decrypt_body<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    parsed: &ParsedHeader,
    content_key: &Key,
) -> Result<u64> {
    decrypt_body_with_progress(reader, writer, parsed, content_key, &mut no_progress)
}

/// [`decrypt_body`] with a progress callback.
pub fn decrypt_body_with_progress<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    parsed: &ParsedHeader,
    content_key: &Key,
    progress: ProgressFn<'_>,
) -> Result<u64> {
    let cipher = XChaCha20Poly1305::new(content_key.expose().into());
    let mut decryptor = Some(DecryptorBE32::from_aead(
        cipher,
        GenericArray::from_slice(&parsed.header.nonce_prefix),
    ));

    let ct_chunk_len = parsed.header.chunk_size as usize + TAG_LEN;
    let mut current = Vec::with_capacity(ct_chunk_len);
    let mut lookahead = Vec::with_capacity(ct_chunk_len);
    let mut plaintext_len = 0u64;
    let mut index = 0u64;

    // One chunk of lookahead is what distinguishes "final chunk" from "next
    // chunk": the flag bit differs, so guessing wrong is an authentication
    // failure rather than a silent misparse.
    let mut have = read_up_to(reader, &mut current, ct_chunk_len)?;
    if have == 0 {
        return Err(Error::Truncated {
            detail: "container has no chunks",
        });
    }

    loop {
        lookahead.clear();
        let next_len = read_up_to(reader, &mut lookahead, ct_chunk_len)?;
        let is_last = next_len == 0;

        if have < TAG_LEN {
            return Err(Error::Truncated {
                detail: "final chunk is shorter than its authentication tag",
            });
        }
        if !is_last && have != ct_chunk_len {
            // Unreachable via `read_up_to`, which returns short only at EOF.
            return Err(Error::Truncated {
                detail: "interior chunk is short",
            });
        }
        if index >= MAX_CHUNKS {
            return Err(Error::CounterExhausted);
        }

        let result = if is_last {
            decryptor
                .take()
                .expect("decryptor is consumed only on the final chunk")
                .decrypt_last_in_place(&parsed.aad, &mut current)
        } else {
            decryptor
                .as_mut()
                .expect("decryptor is consumed only on the final chunk")
                .decrypt_next_in_place(&parsed.aad, &mut current)
        };
        result.map_err(|_| Error::ChunkAuthFailed { index })?;

        writer.write_all(&current)?;
        plaintext_len += current.len() as u64;
        index += 1;
        progress(plaintext_len);

        if is_last {
            break;
        }

        std::mem::swap(&mut current, &mut lookahead);
        have = next_len;
    }

    Ok(plaintext_len)
}

/// Read a container whose content key derives from `master_key`.
///
/// Ignores any keyring in the header: the caller already holds the master key.
pub fn decrypt_with_master<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    master_key: &Key,
) -> Result<u64> {
    let parsed = Header::read_from(reader)?;
    let content_key = derive_content_key(master_key, &parsed.header.file_id, parsed.header.kind)?;
    decrypt_body(reader, writer, &parsed, &content_key)
}

/// Read a root container, unwrapping the master key from its own keyring.
///
/// Returns the recovered master key alongside the plaintext length, so callers
/// can go on to open the file containers the manifest names.
pub fn decrypt_with_passphrase<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    passphrase: &Passphrase,
    policy: &KdfPolicy,
) -> Result<(u64, Key)> {
    let parsed = Header::read_from(reader)?;
    let keyring = parsed
        .header
        .keyring
        .as_ref()
        .ok_or_else(|| Error::InvalidHeaderField {
            detail: "container has no keyring; it can only be opened with a master key".to_owned(),
        })?;

    let master_key = unwrap_master_key(keyring, passphrase, policy)?;
    let content_key = derive_content_key(&master_key, &parsed.header.file_id, parsed.header.kind)?;
    let len = decrypt_body(reader, writer, &parsed, &content_key)?;
    Ok((len, master_key))
}

/// Authenticate a container without keeping its plaintext.
pub fn verify_with_master<R: Read>(reader: &mut R, master_key: &Key) -> Result<u64> {
    decrypt_with_master(reader, &mut std::io::sink(), master_key)
}

/// Read up to `limit` bytes into `buf`, returning the count.
///
/// Returns fewer than `limit` bytes only at end of input — `Read::read` is free
/// to return short reads, and treating one as EOF would corrupt the chunk
/// boundaries.
fn read_up_to<R: Read>(reader: &mut R, buf: &mut Vec<u8>, limit: usize) -> Result<usize> {
    let start = buf.len();
    buf.resize(start + limit, 0);
    let mut filled = 0;

    while filled < limit {
        match reader.read(&mut buf[start + filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                buf.truncate(start);
                return Err(Error::BareIo(e));
            }
        }
    }

    buf.truncate(start + filled);
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{DEFAULT_CHUNK_SIZE, MIN_CHUNK_SIZE};
    use std::io::Cursor;

    fn roundtrip(plaintext: &[u8], chunk_size: u32) {
        let master = Key::random();
        let mut container = Vec::new();
        let stats = encrypt_stream(
            &mut Cursor::new(plaintext),
            &mut container,
            &master,
            ContainerKind::File,
            chunk_size,
            None,
        )
        .unwrap();

        assert_eq!(stats.plaintext_len, plaintext.len() as u64);
        assert_eq!(stats.ciphertext_len, container.len() as u64);
        assert!(stats.chunks >= 1);

        let mut out = Vec::new();
        decrypt_with_master(&mut Cursor::new(&container), &mut out, &master).unwrap();
        assert_eq!(
            out, plaintext,
            "roundtrip failed at chunk_size {chunk_size}"
        );
    }

    #[test]
    fn roundtrip_at_chunk_boundaries() {
        let cs = MIN_CHUNK_SIZE as usize;
        for len in [0, 1, cs - 1, cs, cs + 1, 3 * cs, 3 * cs + 7] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            roundtrip(&data, MIN_CHUNK_SIZE);
        }
    }

    #[test]
    fn roundtrip_multi_megabyte() {
        let data: Vec<u8> = (0..3_000_000).map(|i| (i % 256) as u8).collect();
        roundtrip(&data, DEFAULT_CHUNK_SIZE);
    }

    #[test]
    fn empty_input_still_produces_one_flagged_chunk() {
        let master = Key::random();
        let mut container = Vec::new();
        let stats = encrypt_stream(
            &mut Cursor::new(b""),
            &mut container,
            &master,
            ContainerKind::File,
            MIN_CHUNK_SIZE,
            None,
        )
        .unwrap();
        assert_eq!(stats.chunks, 1);
        assert_eq!(stats.plaintext_len, 0);

        let mut out = Vec::new();
        decrypt_with_master(&mut Cursor::new(&container), &mut out, &master).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn short_reads_do_not_break_chunking() {
        /// A reader that returns one byte at a time, as a pipe or slow socket may.
        struct Dribble<'a>(&'a [u8]);
        impl Read for Dribble<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0.is_empty() || buf.is_empty() {
                    return Ok(0);
                }
                buf[0] = self.0[0];
                self.0 = &self.0[1..];
                Ok(1)
            }
        }

        let plaintext: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let master = Key::random();
        let mut container = Vec::new();
        encrypt_stream(
            &mut Dribble(&plaintext),
            &mut container,
            &master,
            ContainerKind::File,
            MIN_CHUNK_SIZE,
            None,
        )
        .unwrap();

        let mut out = Vec::new();
        decrypt_with_master(&mut Dribble(&container), &mut out, &master).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn wrong_master_key_fails_on_the_first_chunk() {
        let master = Key::random();
        let mut container = Vec::new();
        encrypt_stream(
            &mut Cursor::new(b"secret"),
            &mut container,
            &master,
            ContainerKind::File,
            MIN_CHUNK_SIZE,
            None,
        )
        .unwrap();

        let err = decrypt_with_master(
            &mut Cursor::new(&container),
            &mut Vec::new(),
            &Key::random(),
        )
        .unwrap_err();
        assert!(matches!(err, Error::ChunkAuthFailed { index: 0 }));
    }

    #[test]
    fn manifest_container_cannot_be_read_as_a_file_container() {
        let master = Key::random();
        let mut container = Vec::new();
        encrypt_stream(
            &mut Cursor::new(b"paths and modes"),
            &mut container,
            &master,
            ContainerKind::Manifest,
            MIN_CHUNK_SIZE,
            None,
        )
        .unwrap();

        // Rewriting the kind changes the HKDF label *and* the AAD; both break.
        let parsed = Header::read_from(&mut Cursor::new(&container)).unwrap();
        let mut swapped = parsed.header.clone();
        swapped.kind = ContainerKind::File;
        let aad = swapped.encode().unwrap();

        let mut forged = Vec::new();
        Header::write_to(&mut forged, &aad).unwrap();
        forged.extend_from_slice(&container[crate::header::PREAMBLE_LEN + parsed.aad.len()..]);

        assert!(matches!(
            decrypt_with_master(&mut Cursor::new(&forged), &mut Vec::new(), &master),
            Err(Error::ChunkAuthFailed { .. })
        ));
    }
}

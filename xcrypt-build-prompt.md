# Build Prompt: `xcrypt` — Authenticated File & Folder Encryption in Rust

You are an experienced Rust systems engineer with an applied-cryptography background. Build a production-quality CLI tool and library called `xcrypt` that encrypts files and directory trees. Use only vetted primitives from the RustCrypto ecosystem — **do not implement any cipher, hash, or KDF from scratch.** The engineering is in the protocol, the format, and the failure modes.

Work incrementally. After each milestone, show the code, state what is tested, and stop for review before continuing.

---

## Non-negotiable requirements

**Language & edition:** Rust 2021, stable toolchain, `#![forbid(unsafe_code)]` in both crates.

**Workspace layout:**
```
xcrypt/
  Cargo.toml          # workspace
  xcrypt-core/        # library: format, crypto, no I/O policy
  xcrypt-cli/         # binary: argument parsing, walking, progress
  xcrypt-core/tests/  # integration + corruption suite
  fuzz/               # cargo-fuzz targets
```

**Dependencies (pin minor versions):** `argon2`, `chacha20poly1305` (with `stream` feature), `hkdf`, `sha2`, `zeroize`, `secrecy`, `subtle`, `rand_core`/`getrandom` with `OsRng`, `walkdir`, `rayon`, `tempfile`, `clap` v4 (derive), `thiserror`, `postcard`, `rpassword`, `indicatif`.

---

## Cryptographic design — implement exactly this

### Key hierarchy
- `KEK = Argon2id(password, salt)` — salt is 32 random bytes. Default params `m = 256 MiB, t = 3, p = 4`, all three stored in the header so old archives remain openable when defaults change.
- `master_key` = 32 bytes from `OsRng`, wrapped under the KEK with `XChaCha20-Poly1305`. Password change rewraps only these 32 bytes.
- Per-file: `file_key = HKDF-SHA256(ikm = master_key, salt = none, info = file_id ‖ b"xcrypt-v1-file")`, where `file_id` is a fresh random 16-byte value per file.
- Design the wrapped-key section as a **list of recipients** from day one (passphrase now; hardware token / printed recovery key later), even if the CLI only exposes one.

### Container format
```
"XCR1" ‖ u32_le header_len ‖ header_bytes ‖ chunk[0] ‖ chunk[1] ‖ ... ‖ chunk[n]
```
`header_bytes` is a canonical `postcard` encoding of: version, Argon2 params, salt, recipient list (wrapped master keys), `file_id`, `chunk_size`.

**The entire `header_bytes` blob is passed as AAD to every chunk's AEAD.** This binds ciphertext to its parameters and defeats header swapping and KDF-cost downgrade.

### Streaming
- Fixed plaintext chunks, default 64 KiB, configurable in the header. Never buffer a whole file.
- Use `chacha20poly1305::aead::stream::EncryptorBE32` / `DecryptorBE32` (the STREAM construction). Its 7-byte nonce prefix comes from `OsRng`; the counter and last-block flag are handled by the construction. Do not hand-roll nonce derivation.
- Truncation, chunk reordering, and chunk duplication must all fail — verify this, don't assume it.
- Hard-error rather than wrap the chunk counter.

### Metadata
- Ciphertext is stored on disk named by `file_id`, never by original filename.
- Real paths, sizes, modes, and mtimes live in an **encrypted manifest** — itself an `XCR1` container keyed from the `master_key` with `info = b"xcrypt-v1-manifest"`.
- Provide an optional `--pad-names` mode that buckets stored lengths to blunt size correlation. Document precisely what the format does and does not hide (it does not hide total archive size or file count without padding).

### Key hygiene
Every key, KEK, and derived secret is `Zeroizing<[u8; 32]>` or wrapped in `secrecy::Secret`. Password comparison and any tag checks outside the AEAD use `subtle::ConstantTimeEq`. No secret ever lands in `Debug`, `Display`, logs, or error messages — enforce this with `#[derive]` discipline and a test that formats the error enum.

---

## Durability

- Write to a `NamedTempFile` **in the destination directory** (cross-filesystem rename is not atomic).
- `fsync` the temp file → `rename()` over the target → **`fsync` the parent directory**. The parent fsync is mandatory.
- On directory encryption: write all file containers, then swap the manifest last. A crash must leave a consistent prior state, never a half-written manifest.
- Encrypt files in parallel with `rayon`; the manifest swap is the single serialization point.

---

## CLI surface

```
xcrypt encrypt <path>... -o <archive_dir> [--chunk-size] [--argon2-mem] [--pad-names]
xcrypt decrypt <archive_dir> -o <dest>
xcrypt list <archive_dir>              # decrypts manifest only
xcrypt verify <archive_dir>            # authenticates everything, writes nothing
xcrypt rewrap <archive_dir>            # change passphrase
```
Passphrase via `rpassword` prompt or `XCRYPT_PASSPHRASE` env var; **never** a command-line flag. Confirm on encrypt. Refuse to overwrite existing outputs unless `--force`. Progress bars go to stderr; a `--json` mode emits machine-readable results on stdout.

---

## Testing — this is the deliverable, not an afterthought

1. **Known-answer tests.** RFC 8439 ChaCha20-Poly1305 vectors and Argon2id reference vectors, asserted against the dependency versions you pinned, so a bad upgrade is caught immediately.
2. **Round-trip property tests** (`proptest`): random content across sizes `0`, `1`, `chunk_size - 1`, `chunk_size`, `chunk_size + 1`, `3 * chunk_size`, and multi-megabyte. Random chunk sizes and passphrases including empty, very long, and non-ASCII.
3. **Corruption suite — the important one.** Each case must fail closed with a *distinguishable* typed error, and must never emit partial plaintext to disk:
   - flip one bit in the magic, header length, header body, a middle chunk, the final chunk, any auth tag
   - truncate the file: mid-header, at a chunk boundary, mid-chunk, drop the final chunk entirely
   - reorder two chunks; duplicate a chunk; splice a chunk from a different file
   - swap headers between two archives encrypted under the same passphrase
   - present a header claiming absurd `chunk_size` or `header_len` (resource-exhaustion guard)
   - wrong passphrase, and a header with tampered Argon2 params (downgrade attempt)
4. **Filesystem tests:** nested trees, empty directories, unicode and emoji filenames, very long paths, symlinks (define and test the policy — follow, skip, or record), duplicate basenames in different directories, files that are zero-length or read-only.
5. **Atomicity test:** inject a failure between temp-write and rename, assert the target is either fully old or fully new, never partial.
6. **Format-stability test:** commit a golden archive fixture to the repo; a test decrypts it on every run. Breaking backward compatibility must require deliberately regenerating that fixture.
7. **Fuzzing:** `cargo-fuzz` targets over the header parser and the full decrypt path. The decryptor must never panic, never allocate unboundedly, and never index out of bounds on arbitrary input.
8. **CI:** `cargo test`, `clippy -- -D warnings`, `cargo fmt --check`, `cargo deny check advisories`, and a `cargo audit` run.

---

## Documentation

- `SPEC.md`: byte-level format description precise enough for an independent reimplementation, plus an explicit threat model — what this defends against (offline attacker with the ciphertext) and what it does not (malware on the running machine, memory-resident keys during operation, traffic analysis of archive size, rubber-hose).
- Rustdoc on every public item, with a doc example for the streaming API.
- A short "why" section covering the AAD-binds-header decision, the STREAM choice over hand-rolled nonces, and the parent-directory fsync.

---

## Milestones — pause after each

1. Workspace, error enum, header struct + canonical serialization, header round-trip tests.
2. Key hierarchy: Argon2id, master-key wrap/unwrap, HKDF derivation, recipient list. KAT tests.
3. Single-file streaming encrypt/decrypt with header-as-AAD. Round-trip + property tests.
4. Full corruption suite. Do not proceed until every case fails closed.
5. Manifest, directory walk, rayon parallelism, atomic writes with parent fsync.
6. CLI, progress, `rewrap`, `verify`.
7. Fuzz targets, golden fixture, CI, `SPEC.md`.

Flag any point where you believe the design above is wrong or where a simpler construction would be safer — argue the case rather than silently substituting.

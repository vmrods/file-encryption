# xcrypt

Authenticated encryption for files and directory trees, in Rust.

`xcrypt` encrypts a tree into an archive directory where **no filename, path,
size, mode, or mtime is visible** — that metadata lives in an encrypted manifest,
and ciphertext objects are named by random identifiers. Every byte is
authenticated: a flipped bit, a reordered chunk, a truncated file, a swapped
header, or a downgraded key-derivation cost all fail with a specific, typed error
rather than yielding partial or wrong plaintext.

No cryptography is implemented here. Every primitive comes from the
[RustCrypto](https://github.com/RustCrypto) ecosystem; the engineering is in the
protocol, the format, and the failure modes.

- **[SPEC.md](SPEC.md)** — byte-level format, key hierarchy, and threat model.
- `#![forbid(unsafe_code)]` in every crate.

---

## Install

```sh
git clone <this repo> && cd file-encryption
cargo build --release          # target/release/xcrypt
./build.sh                     # release binaries for macOS, Linux, Windows → dist/
```

Requires a stable Rust toolchain (1.74 or newer).

## Use

```sh
# Encrypt. Prompts for a passphrase, twice.
xcrypt encrypt ~/Documents ~/notes.txt -o ~/vault

# List what is inside. Decrypts only the manifest.
xcrypt list ~/vault

# Authenticate every byte without writing anything.
xcrypt verify ~/vault

# Restore.
xcrypt decrypt ~/vault -o ~/restored

# Change the passphrase. Rewraps 32 bytes; does not re-encrypt any file.
xcrypt rewrap ~/vault

# Bundle the archive into one file to move, upload, or hand over — and back.
xcrypt pack ~/vault -o vault.xcra
xcrypt unpack vault.xcra -o ~/vault
```

An archive is a **directory** while you work with it, and optionally a **single
file** when you move it. The directory form is what makes atomic object writes, a
cheap `rewrap`, and parallel encryption possible; packing is the step you take
when you're done.

Packing is not just convenience. A directory reveals how many objects it holds —
which is your file count — and how large each one is. A packed file is a single
container that reveals only a total size. It opens with the same passphrase, adds
no second Argon2 pass, streams in both directions regardless of archive size, and
`unpack` reproduces the directory byte-for-byte.

Useful flags:

| flag | effect |
|---|---|
| `--pad-names` | Pad stored files to power-of-two lengths, hiding exact file sizes. Up to 2× storage. |
| `--chunk-size 64KiB` | Plaintext bytes per chunk (1 KiB … 8 MiB). |
| `--argon2-mem 256MiB` | Argon2id memory cost. Also `--argon2-time`, `--argon2-lanes`. |
| `--force` | Replace existing outputs. Without it, nothing is overwritten. |
| `--json` | One machine-readable object on stdout, including on failure. |
| `--quiet` | No progress output. |

### Passphrases

There is deliberately **no `--passphrase` flag**: command lines appear in `ps`,
in shell history, and in CI logs. Supply one of:

- an interactive prompt (confirmed on `encrypt` and `rewrap`);
- `XCRYPT_PASSPHRASE` for scripts, plus `XCRYPT_NEW_PASSPHRASE` for `rewrap`.

Exit codes: `0` success, `1` operation failed, `2` bad command line.

---

## Design decisions worth the words

### The header is the AAD

The entire header blob — version, KDF parameters, salt, keyring, `file_id`,
`chunk_size`, nonce prefix — is passed as associated data to **every** chunk's
AEAD. Not a hash of it; the bytes themselves.

This is what turns a pile of parameters into something an attacker cannot touch.
Without it, a header is just unauthenticated metadata: swap one archive's header
onto another's body, rewrite `chunk_size`, or downgrade `m = 256 MiB` to
`m = 8 KiB` and hand the archive back to be brute-forced. With it, altering any
header byte breaks every chunk in the container.

The rule has a consequence that is easy to get wrong: because the AAD is the bytes
on disk, a decoder must not re-serialize the parsed header and use that. `xcrypt`
keeps the original bytes, and additionally rejects any header whose re-encoding
differs from its input — so "same values, different encoding" is not a way to
mutate the AAD unnoticed.

### STREAM, not hand-rolled nonces

Chunked encryption needs a nonce per chunk and a way to know where the stream
ends. Deriving those by hand is where this kind of tool usually breaks: a
counter that wraps, an off-by-one that reuses a nonce, or no end-of-stream marker
so truncation looks like a shorter file.

The STREAM construction (`EncryptorBE32`/`DecryptorBE32`) handles all three. The
nonce is `random_prefix ‖ counter ‖ last_block_flag`, so reordering and
duplication change the nonce and fail authentication, and the final chunk's flag
bit makes truncation — including dropping the last chunk entirely — an
authentication failure rather than silent data loss. The counter is 32 bits; when
it would wrap, `xcrypt` errors out instead.

### `fsync` the parent directory

The write path is: temp file **in the destination directory** → `fsync` the temp
file → `rename` over the target → **`fsync` the parent directory**.

The last step is the one that gets left out. `fsync` on the file makes its
*contents* durable; it says nothing about the directory entry that names them.
After a crash, a name can still resolve to the old inode — or to nothing at all —
even though the data reached the disk. The temp file must also live in the
destination directory, because `rename` is atomic only within a filesystem, and
`/tmp` is frequently a different one.

### Two more, argued in [SPEC.md](SPEC.md)

- **A floor on KDF cost.** Argon2 parameters are stored in the header, which makes
  them attacker-controlled. `xcrypt` refuses parameters below the OWASP Argon2id
  minimum (19 MiB, t = 2) instead of dutifully hashing at whatever cost the file
  claims.
- **The keyring lives only in the manifest.** File containers are keyed straight
  from the master key. Duplicating the wrapped key into every file header would
  make changing a passphrase an O(files) rewrite instead of one small write.

---

## Testing

```sh
cargo test --workspace          # everything
cargo test -p xcrypt-core --test corruption        # the failure modes
cargo test -p xcrypt-core --test format_stability  # the golden fixture
cargo clippy --workspace --all-targets -- -D warnings
cargo +nightly fuzz run header_parse               # requires cargo-fuzz
```

The suite is the deliverable, not an afterthought:

| suite | what it pins |
|---|---|
| `kat.rs` | RFC 8439, RFC 9106 §5.3, RFC 5869 §A.1/A.3 vectors against the pinned dependency versions |
| `corruption.rs` | Every bit flip, truncation, reorder, duplication, splice, header graft, and cost downgrade fails closed with a distinguishable error — and leaves no plaintext on disk |
| `properties.rs` | Round trips across every chunk boundary; arbitrary corruption, truncation, and extension always fail |
| `archive.rs` | Real trees: nesting, empty directories, unicode and emoji names, 200-byte filenames, non-UTF-8 names, symlinks, read-only and zero-length files, duplicate basenames, parallel encryption, atomic manifest swap, traversal defence |
| `pack.rs` | Packed archives round-trip byte-for-byte, hide the object count and sizes, refuse a wrong passphrase, fail closed on corruption or truncation, and never leave a half-unpacked directory |
| `format_stability.rs` | A committed golden archive decrypts on every run, so breaking compatibility takes a deliberate commit |
| `no_secrets_in_errors.rs` | No error variant renders a key, passphrase, or plaintext |
| `cli.rs` | Exit codes, stdout/stderr discipline, JSON shape, and the absence of a passphrase flag |
| `fuzz/` | The header parser, both decrypt paths, the manifest decoder, and the round trip, under `cargo-fuzz` |

## Layout

```text
Cargo.toml          workspace
xcrypt-core/        format, crypto, archive logic — no I/O policy
xcrypt-cli/         argument parsing, prompting, progress, output
fuzz/               cargo-fuzz targets (own toolchain, outside the workspace)
SPEC.md             format specification and threat model
build.sh            cross-platform release builds
deny.toml           cargo-deny: advisories, licenses, banned crypto stacks
```

## What this does not protect you from

Summarised here, in full in [SPEC.md §6](SPEC.md): malware on the running
machine, keys resident in memory (or swapped to disk) while `xcrypt` runs, the
total size of an archive (and its file count, unless you `pack` it), deletion or
rollback of an archive by someone with write access, and coercion. It protects the ciphertext against an
offline attacker. That is the claim, and it is the whole claim.

## Licence

MIT OR Apache-2.0.

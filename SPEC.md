# The `XCR1` format

Version 1. This document is precise enough to reimplement the format from
scratch, and is the normative description: where it and the code disagree, that
is a bug in one of them.

All multi-byte integers in the framing are **little-endian**. All
`postcard`-encoded structures use `postcard` 1.x's default varint encoding, which
is little-endian base-128 with the continuation bit in the high bit of each byte.

---

## 1. Primitives

| Purpose | Algorithm | Notes |
|---|---|---|
| Password hashing | Argon2id, version `0x13` | Parameters stored in the header |
| Key derivation | HKDF-SHA256 (expand only, no salt) | IKM is already uniform |
| AEAD | XChaCha20-Poly1305 | 24-byte nonce, 16-byte tag |
| Chunked AEAD | STREAM, `BE32` variant | 19-byte nonce prefix + 4-byte counter + 1 flag byte |
| CSPRNG | OS entropy (`getrandom`) | Salt, master key, `file_id`, nonces |

Nothing is implemented locally; every primitive comes from the RustCrypto crates
pinned in `Cargo.lock`.

---

## 2. Container layout

A container is a single byte stream, written strictly forward, never seeked:

```text
offset  size          field
------  ------------  ---------------------------------------------------------
0       4             magic, the ASCII bytes "XCR1" (0x58 0x43 0x52 0x31)
4       4             header_len, u32 little-endian
8       header_len    header_bytes, canonical postcard encoding of Header
8+hl    variable      chunk[0]
...     variable      chunk[1] … chunk[n]
```

### 2.1 Chunks

Let `C = header.chunk_size` (plaintext bytes per chunk).

* Chunks `0 … n-1` are each exactly `C + 16` bytes: `C` bytes of ciphertext
  followed by a 16-byte Poly1305 tag.
* Chunk `n`, the final chunk, is `L + 16` bytes where `0 ≤ L ≤ C`.
* **Every container has at least one chunk.** A zero-byte plaintext is stored as
  one final chunk of exactly 16 bytes (an empty ciphertext plus its tag).
* When the plaintext length is an exact multiple of `C`, the final chunk is the
  16-byte empty chunk. There is no ambiguity about where a container ends.

A decoder identifies the final chunk by lookahead: read up to `C + 16` bytes; if
the *next* read returns zero bytes, the chunk just read is final. Guessing wrong
is not a silent misparse — the final chunk sets a flag bit in its nonce, so a
final chunk decrypted as an interior chunk (or vice versa) fails authentication.

### 2.2 Nonces

STREAM `BE32` composes each chunk's 24-byte XChaCha20 nonce as:

```text
nonce[0..19]  = header.nonce_prefix          (19 random bytes)
nonce[19..23] = chunk_index as u32 big-endian
nonce[23]     = 0x00 for an interior chunk, 0x01 for the final chunk
```

The counter is 32 bits, capping a container at `2^32 - 1` chunks. Reaching that
limit is a hard error (`counter_exhausted`); it is never allowed to wrap, because
wrapping would reuse a nonce under the same key.

### 2.3 Associated data

**The entire `header_bytes` blob is the AAD for every chunk in the container.**
Not a hash of it, not a subset — the bytes as they appear on disk.

Consequences, all of which are tested in `xcrypt-core/tests/corruption.rs`:

* A header cannot be swapped between two containers, even ones encrypted under
  the same passphrase.
* `chunk_size`, `file_id`, `nonce_prefix`, `kind`, and the whole keyring are
  authenticated. Rewriting any of them breaks every chunk.
* An Argon2 cost downgrade cannot be hidden, because the parameters are covered.

Because the header is AAD, a decoder must use the bytes it read, not a
re-serialization of the parsed structure. To keep that safe, `header_bytes` must
be the *canonical* encoding: a decoder re-encodes the parsed header and rejects
the container if the result differs (`non_canonical_header`). Alternate encodings
of the same values — non-minimal varints, for instance — are therefore not a way
to mutate the AAD.

---

## 3. The header

`header_bytes` is the `postcard` encoding of:

```rust
struct Header {
    version: u16,                      // must be 1
    kind: ContainerKind,               // enum: 0 = File, 1 = Manifest
    file_id: [u8; 16],                 // random; also the on-disk object name
    chunk_size: u32,                   // plaintext bytes per chunk
    nonce_prefix: [u8; 19],            // random STREAM prefix
    keyring: Option<Keyring>,          // Some only in an archive's root container
}

struct Keyring {
    kdf: KdfParams,
    recipients: Vec<Recipient>,        // at least 1, at most 16
}

struct KdfParams {
    algorithm: KdfAlgorithm,           // enum: 0 = Argon2id
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
    salt: [u8; 32],
}

struct Recipient {
    kind: RecipientKind,               // enum: 0 = Passphrase
    label: Option<String>,             // non-secret hint, ≤ 128 bytes
    nonce: [u8; 24],
    wrapped_master_key: Vec<u8>,       // exactly 48 bytes for Passphrase
}
```

`postcard` encodes fixed-size byte arrays as their bytes with no length prefix,
`Vec<T>` and `String` with a varint length prefix, `Option` as `0x00` for `None`
or `0x01` followed by the value, and each enum as a varint discriminant followed
by its payload. A real header is 60–200 bytes.

### 3.1 Limits enforced before any allocation

| Field | Bound | Error |
|---|---|---|
| `header_len` | ≤ 65536, and > 0 | `header_too_large`, `malformed_header` |
| `version` | = 1 | `unsupported_version` |
| `chunk_size` | 1024 … 8388608 | `invalid_chunk_size` |
| `recipients.len()` | 1 … 16 | `invalid_header_field` |
| `wrapped_master_key.len()` | = 48 | `invalid_header_field` |
| `label.len()` | ≤ 128 | `invalid_header_field` |
| `m_cost_kib` | 19456 … 2097152 | `kdf_params_rejected` |
| `t_cost` | 2 … 32 | `kdf_params_rejected` |
| `p_cost` | 1 … 64 | `kdf_params_rejected` |

`header_len` is checked before the buffer for it is allocated, and `chunk_size`
before the streaming buffer is allocated, so neither field is a memory-exhaustion
lever. The KDF bounds are checked before Argon2 runs, so neither is a CPU or
memory lever.

The KDF **minimums** are a security control, not a sanity check. Since the cost
parameters live in an attacker-modifiable header, without a floor an attacker
rewrites `m = 256 MiB` to `m = 8 KiB`, hands the archive back, and brute-forces
the passphrase cheaply. The floor is the OWASP-recommended Argon2id minimum
(19 MiB, t = 2). Archives written below it cannot be opened by this build; that
is deliberate.

---

## 4. Key hierarchy

```text
passphrase ──Argon2id(salt, m, t, p, len=32)──▶ KEK
                                                 │
                       XChaCha20-Poly1305 unwrap │ AAD = postcard(KdfParams)
                                                 ▼
                                     master_key (32 random bytes)
                                                 │
       HKDF-SHA256(ikm = master_key, salt = ∅,   │
                   info = file_id ‖ label)       │
                                                 ▼
                                   content_key for this container
```

* `label` is the ASCII string `xcrypt-v1-file` for `kind = File` and
  `xcrypt-v1-manifest` for `kind = Manifest`. This is domain separation: a
  manifest container can never be substituted for a file container, because the
  two derive different keys from the same master key.
* HKDF is used **without a salt**. The IKM is 32 bytes straight from the CSPRNG,
  which is exactly the case where the extract step has nothing to add.
  Uniqueness comes from `info`, whose `file_id` is 16 fresh random bytes per
  container.
* The wrap's AAD is the canonical `postcard` encoding of `KdfParams`. A tampered
  parameter set that still satisfies the policy therefore fails to unwrap rather
  than deriving a wrong-but-plausible key.
* Changing a passphrase rewraps 32 bytes: a new salt, a new KEK, a new wrapped
  master key, one rewritten manifest container. No file ciphertext is touched.

The recipient list is a list from version 1 even though only `Passphrase` exists.
Adding a hardware token or a printed recovery key is a new `RecipientKind` and a
new unwrap path — not a format break.

---

## 5. Archive layout

```text
archive_dir/
  MANIFEST.xcr          XCR1 container, kind = Manifest, keyring = Some
  objects/
    <32 lowercase hex>.xcr   XCR1 container, kind = File, keyring = None
```

Object filenames are the hex encoding of `file_id`. No original filename, path,
or extension appears anywhere in the archive directory.

The keyring appears in the manifest container only. File containers are keyed
directly from the master key, which is what makes a passphrase change O(1)
instead of O(files). A file container is consequently not independently openable
by passphrase: the manifest is required.

### 5.1 The manifest

```rust
struct Manifest {
    version: u16,              // must be 1
    entries: Vec<Entry>,
}

struct Entry {
    components: Vec<Vec<u8>>,  // path components, raw bytes, relative to the root
    kind: EntryKind,
    mode: Option<u32>,         // Unix mode bits
    mtime_secs: Option<i64>,   // seconds from the Unix epoch, may be negative
    mtime_nanos: Option<u32>,
}

enum EntryKind {
    File { file_id: [u8; 16], size: u64 },
    Directory,
    Symlink { target: Vec<u8> },
}
```

Paths are stored as a list of raw component byte strings, not as one string.
Unix filenames are arbitrary bytes, so requiring UTF-8 would make ordinary files
unarchivable; and a pre-split list makes traversal checkable by construction. On
decode, every component must be non-empty, must not be `.` or `..`, and must
contain no `/`, `\`, or NUL. `size` is authoritative for extraction: with padding
enabled the container is longer, and the extra bytes are discarded.

Directories are recorded explicitly, so empty directories survive. Symlinks are
recorded, never followed: the target bytes are stored verbatim and the link is
recreated on extraction. Following them would duplicate content, require cycle
detection, and silently pull in files from outside the requested tree.

### 5.2 Durability and crash consistency

Every file is written with the same sequence, and the last step is the one
usually forgotten:

1. write to a temporary file **in the destination directory** (`rename` is atomic
   only within a filesystem);
2. `fsync` the temporary file;
3. `rename` over the target;
4. **`fsync` the parent directory.**

Without step 4, the file's contents are durable but the directory entry pointing
at them may not be: after a crash the name can still resolve to the old inode, or
to nothing.

At archive level: all objects are written and their directory synced, then the
manifest is swapped in last. The manifest is the only thing that gives objects
meaning, so a crash leaves either the previous archive or the new one, never a
mixture. Unreferenced objects are pruned only *after* a successful swap.

Files are encrypted in parallel with `rayon`; each task derives its own key and
writes its own object, so the manifest swap is the single serialization point.
Manifest entry order is the deterministic walk order, not the order threads
finished in.

### 5.3 Packed archives

`xcrypt pack` bundles an archive directory into a single file. The packed file is
an ordinary `XCR1` container of `kind = Pack`, carrying a **copy of the archive's
keyring**, so it opens with the archive's own passphrase and introduces no second
Argon2 pass. Its content key is
`HKDF-SHA256(master_key, ∅, pack_file_id ‖ "xcrypt-v1-pack")` — a different key
from every file and from the manifest, by domain separation.

Its *plaintext* is a framed bundle:

```text
"XPK1" ‖ u16_le version ‖ entry* ‖ 0xFF

entry := 0x01 ‖ file_id[16] ‖ u64_le len ‖ object_bytes     (an object container)
       | 0x00 ‖              u64_le len ‖ manifest_bytes    (the manifest container)
```

Objects come first, the manifest last. Unpacking therefore persists the manifest
last, preserving the same crash-consistency ordering a directory archive has.
Each entry is written to a temporary file in the destination and renamed only
once its declared length is complete; a failed unpack removes the destination
entirely, because a partially unpacked archive is one whose manifest references
objects that are not present.

Both directions stream: neither packing nor unpacking buffers more than one
chunk, whatever the archive's size. Objects the manifest does not reference are
dropped during packing.

`xcrypt encrypt --pack` composes the two operations without leaving a directory
behind. The archive is staged in a temporary directory beside the output file —
the same filesystem, so the pack's `rename` stays atomic — then packed, then
authenticated end to end, and only then is the staging copy removed. If the
verification fails the output file is deleted too: a packed archive that does not
authenticate is not a backup, and leaving one behind invites someone to trust it.
No path through this operation deletes the only copy of anything before a checked
replacement exists.

**What packing changes about the threat model.** A directory archive exposes the
object count — which is the file count — and each object's size. A packed file is
one blob, so only its total size is visible. That closes the file-count leak in
§6.1 entirely and the per-file size leak without needing `--pad-names`.

Objects inside a packed file are encrypted twice: once as their own containers,
once as part of the pack stream. This costs CPU and nothing else, and is why
packing is a separate step rather than the default output.

`ContainerKind::Pack` was added after version 1 shipped. Its discriminant is
appended, so containers written before it still parse unchanged; a build
predating it rejects a packed file as a malformed header rather than misreading
one.

---

## 6. Threat model

### 6.1 Defended against

**An offline attacker holding the ciphertext**, with or without write access to
it. Such an attacker learns:

* that the archive exists and its total size;
* how many objects it contains, and each object's size — **only in the directory
  form**. `xcrypt pack` collapses the archive into one container and removes both
  leaks; `--pad-names` buckets object sizes to powers of two without hiding the
  count;
* nothing else. No filename, path, extension, directory structure, file count of
  any subtree, mode, mtime, or content.

Such an attacker cannot:

* recover any plaintext without the passphrase;
* modify any byte undetectably — every bit of every container is either covered
  by a Poly1305 tag or is the AAD those tags authenticate;
* truncate, reorder, duplicate, or splice chunks undetectably;
* swap headers or keyrings between archives;
* downgrade the KDF cost to make a brute force cheap;
* make the decoder allocate unboundedly, panic, or index out of bounds on
  arbitrary input (fuzzed continuously);
* cause a write outside the destination directory via a malicious manifest.

Every item above corresponds to a test. `xcrypt-core/tests/corruption.rs` is the
enumeration.

### 6.2 Explicitly **not** defended against

* **Malware or another user on the running machine.** Keys are in this process's
  memory while it runs. `Zeroizing` and `secrecy` shorten that window and keep
  secrets out of logs and `Debug` output; they do not survive an attacker who can
  read the process, ptrace it, or dump its memory.
* **Memory-resident keys during operation.** Nothing here pins pages or disables
  swap. A key can reach a swap file or a hibernation image. Use an encrypted swap
  device if that matters.
* **Traffic and size analysis.** Total archive size, object count, and (without
  `--pad-names`) individual file sizes are visible. `--pad-names` buckets file
  sizes to powers of two; it does **not** hide the total, the file count, or
  access timing.
* **A compromised source of randomness.** Everything rests on the OS CSPRNG.
* **Coercion.** There is no duress passphrase and no deniable volume. Someone who
  can compel the passphrase gets the data.
* **Metadata about the archive itself.** Its path, its mtime, and the fact that
  you ran `xcrypt` are all visible to anyone who can see the filesystem.
* **Deletion or rollback.** An attacker with write access can delete the archive,
  or restore an older copy of it. Nothing here provides freshness or
  anti-rollback. Detecting that requires a signed, monotonically versioned record
  kept somewhere the attacker cannot reach.
* **Filename length correlation, in the manifest.** The manifest's own size
  varies with how many paths it holds and how long they are, and the manifest is
  not padded. An attacker who can see the manifest's size learns roughly how much
  metadata it contains.

### 6.3 Passphrase handling

Passphrases are read from a TTY prompt or `XCRYPT_PASSPHRASE`, and never from a
command-line flag: command lines are visible in `ps`, recorded in shell history,
and echoed into CI logs. The passphrase is fed to Argon2id as its raw UTF-8 bytes
with **no Unicode normalization**, deliberately: normalization would mean an
archive's openability depended on a Unicode table version, and the same
passphrase typed identically would derive a different key after a library
upgrade. Users who type non-ASCII passphrases on multiple input methods should be
aware that the bytes must match exactly.

---

## 7. Error taxonomy

Each machine-readable `kind` is a stable string in `--json` output.

| kind | meaning |
|---|---|
| `bad_magic` | Not an `XCR1` container |
| `unsupported_version` | Container version this build cannot read |
| `header_too_large` | `header_len` above the limit; rejected before allocating |
| `malformed_header` | Header bytes are not a valid encoding |
| `non_canonical_header` | Header decodes, but is not the canonical encoding |
| `invalid_chunk_size` | `chunk_size` outside 1 KiB … 8 MiB |
| `kdf_params_rejected` | Cost parameters outside policy (downgrade or exhaustion) |
| `invalid_header_field` | Structural invariant violated |
| `no_matching_recipient` | Wrong passphrase, or the keyring was tampered with |
| `chunk_auth_failed` | A chunk failed authentication; carries the chunk index |
| `truncated` | Container ends before its structure allows |
| `counter_exhausted` | Input exceeds `2^32 - 1` chunks |
| `aead` | AEAD or KDF internal failure |
| `invalid_manifest` | Manifest malformed, duplicated, or wrong version |
| `unsafe_path` | Manifest entry would escape the destination |
| `duplicate_input` | Two inputs claim the same top-level name |
| `would_overwrite` | Output exists and `--force` was not given |
| `io` | Filesystem error |

No error message, `Display`, or `Debug` output contains key material, a
passphrase, or plaintext. `xcrypt-core/tests/no_secrets_in_errors.rs` enforces
this over every variant.

---

## 8. Reimplementation checklist

An independent implementation is compatible if it:

1. writes `"XCR1" ‖ u32_le header_len ‖ header_bytes ‖ chunks`;
2. produces `header_bytes` as the canonical `postcard` encoding of `Header`, and
   rejects non-canonical encodings on read;
3. uses that exact blob as the AAD for every chunk;
4. derives content keys as `HKDF-SHA256(master_key, ∅, file_id ‖ label)`;
5. wraps the master key with XChaCha20-Poly1305 under
   `Argon2id(passphrase, salt, m, t, p)`, with `postcard(KdfParams)` as AAD;
6. uses STREAM `BE32` with the 19-byte prefix from the header, and always emits a
   flagged final chunk — including for empty input;
7. names objects by lowercase hex `file_id` and stores all path metadata in the
   manifest container;
8. enforces the limits in §3.1 before allocating or hashing.

The committed fixture at `xcrypt-core/tests/fixtures/golden-archive` is the
conformance test. Its passphrase is `xcrypt-golden-fixture-passphrase`.

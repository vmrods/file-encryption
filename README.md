# xcrypt

[![CI](https://github.com/vmrods/file-encryption/actions/workflows/ci.yml/badge.svg)](https://github.com/vmrods/file-encryption/actions/workflows/ci.yml) ![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)

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

Requires a stable Rust toolchain, 1.85 or newer ([rustup.rs](https://rustup.rs)).

```sh
git clone <this repo> && cd file-encryption
./install.sh
```

`install.sh` runs the full test suite, builds in release mode, installs the
binary, and runs `--version` from the *installed* copy so a broken install cannot
pass silently. It installs to `/usr/local/bin` when that is writable — escalating
with `sudo` only for the copy itself — and falls back to `~/.local/bin`
otherwise, warning you with the exact `export PATH=` line if the destination is
not on your `PATH`.

| command | effect |
|---|---|
| `./install.sh` | test, build, install, smoke test |
| `./install.sh --shell-helper` | also add the `vault` shell function (see below) |
| `./install.sh --prefix ~/bin` | install somewhere specific |
| `./install.sh --from-dist` | install what `./build.sh` already produced, without rebuilding |
| `./install.sh --skip-tests` | faster; not recommended |
| `./install.sh --uninstall` | remove the installed binary |

Alternatives, if you would rather not use the script:

```sh
cargo install --path xcrypt-cli    # → ~/.cargo/bin/xcrypt
cargo build --release              # → target/release/xcrypt, copy it yourself
```

### Release binaries for other platforms

```sh
./build.sh                 # every default target
./build.sh macos           # or: linux | windows | host | <triple> ...
```

Artifacts land in `dist/<target>/xcrypt`, alongside a `.tar.gz` (`.zip` for
Windows) and `SHA256SUMS`. Targets that cannot be built on your machine are
reported with the exact toolchain to install (`cross` plus Docker for Linux,
`cargo-xwin` for Windows), never silently skipped. The version is a hardcoded
constant in [Cargo.toml](Cargo.toml) — nothing auto-increments.

---

## Storing your passphrase

A passphrase is **required**, and there is no recovery if you lose it. On macOS,
the right place to keep it is the login Keychain — never a file, and never a line
in `.zshrc`.

```sh
./set-passphrase.sh                   # hidden prompt, asked twice (recommended)
./set-passphrase.sh 'my passphrase'   # as an argument; warns about shell history
echo 'my passphrase' | ./set-passphrase.sh --stdin
./set-passphrase.sh --show            # print it back
./set-passphrase.sh --delete          # remove the entry

XCRYPT_KEYCHAIN_SERVICE=xcrypt-photos ./set-passphrase.sh   # a second archive
```

After storing, the script reads the value back and compares it byte-for-byte
before reporting success.

### Using the stored passphrase

`./install.sh --shell-helper` adds a `vault` function to your shell rc that
fetches the passphrase and runs `xcrypt` with it — scoped to that one command,
never exported:

```sh
vault encrypt ~/Documents -o ~/vault
vault list ~/vault
vault verify ~/vault
vault decrypt ~/vault -o ~/restored
```

Without the helper:

```sh
XCRYPT_PASSPHRASE="$(./set-passphrase.sh --show)" xcrypt list ~/vault
```

> **Do not use `security find-generic-password -w` directly.** It returns a *hex
> dump* rather than the text whenever the stored value is not plain ASCII, so a
> passphrase with an accent or an emoji would read back as something else and
> derive the wrong key. `set-passphrase.sh` stores every value base64-encoded
> behind an `xcb64:` marker for exactly this reason, and both `--show` and the
> `vault` helper decode it. Entries you created by hand with plain ASCII still
> work unchanged.

### What the Keychain does and does not protect

It keeps the passphrase off disk in cleartext, out of your shell history, out of
dotfile backups, and out of reach of other user accounts. It does **not** protect
against anything running as you — malware in your session can call `security`
exactly as the `vault` function does. That is the same boundary
[SPEC.md §6](SPEC.md) draws for the archives themselves.

Two practical notes: the Keychain is then your only copy, so keep an offline
backup somewhere physical; and scheduled jobs need a user-session agent
(`LaunchAgents`, not `LaunchDaemons`), because the login Keychain is locked until
you log in.

On Linux, use `secret-tool store --label=xcrypt xcrypt xcrypt-vault` and adapt
the helper; `set-passphrase.sh` is macOS-only and says so.

---

## Finder integration (macOS)

Right-click any file or folder → **Quick Actions** → *Encrypt with xcrypt*.

```sh
./install.sh                          # the binary
./set-passphrase.sh                   # the passphrase, in the Keychain
./finder/install-quick-actions.sh     # the two Quick Actions
```

That's it — no Xcode, no code signing, no developer account. The installer writes
two Automator workflow bundles into `~/Library/Services` and copies the handler
script to `~/Library/Application Support/xcrypt/`, so the actions keep working
even if you move or delete this repository.

| menu entry | on | result |
|---|---|---|
| Encrypt with xcrypt | any file or folder | `<name>.xcra` beside it, packed and verified |
| Decrypt with xcrypt | an `.xcra` file, or an archive directory | `<name>-restored/` beside it |

Multiple selections work — each item is handled in turn, and you get one
notification at the end.

**Nothing is ever overwritten.** If `notes.xcra` exists, the next run writes
`notes-1.xcra`. Results are revealed in Finder when the action finishes, and
failures raise an alert rather than a notification, because an encrypt that
silently did nothing is the worst possible outcome.

The passphrase comes from the Keychain entry `set-passphrase.sh` created. Without
one, each action shows a hidden password prompt instead. Because Automator runs
with a minimal `PATH`, the handler locates the binary itself — checking
`/usr/local/bin`, Homebrew, `~/.local/bin`, and `~/.cargo/bin`, or `XCRYPT_BIN`
if you set it.

If the entries do not appear right away, enable them in **System Settings →
General → Login Items & Extensions → Extensions → Finder**, or log out and back
in. To remove everything:

```sh
./finder/install-quick-actions.sh --uninstall
```

---

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

# Or go straight to a single file, with no directory left behind.
xcrypt encrypt ~/Desktop -o vault.xcra --pack
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

`encrypt --pack` does both steps in one command: it stages the archive in a
temporary directory **beside the output**, packs it, authenticates the packed
file, and only then removes the staging copy. Nothing is ever deleted before a
verified replacement exists, and a failure anywhere leaves neither a staging
directory nor an output file. The cost is two extra passes over the data — the
pack pass and the verification pass — which is why plain `encrypt` remains the
default when you are archiving locally.

Note that a packed file cannot be worked with directly: `list`, `verify`,
`decrypt`, and `rewrap` all need a directory, so unpack it first.

Useful flags:

| flag | effect |
|---|---|
| `--pack` | On `encrypt`: write one packed file instead of an archive directory. |
| `--pad-names` | Pad stored files to power-of-two lengths, hiding exact file sizes. Up to 2× storage. |
| `--chunk-size 64KiB` | Plaintext bytes per chunk (1 KiB … 8 MiB). |
| `--argon2-mem 256MiB` | Argon2id memory cost. Also `--argon2-time`, `--argon2-lanes`. |
| `--force` | Replace existing outputs. Without it, nothing is overwritten. |
| `--json` | One machine-readable object on stdout, including on failure. |
| `--quiet` | No progress output. |

Nothing is overwritten without `--force` — not an existing archive on `encrypt`,
not existing files on `decrypt`, not an existing packed file on `pack`. The first
`encrypt` also pauses for roughly half a second before doing anything: that is
Argon2id at the default 256 MiB, and it is the point. Lower it with
`--argon2-mem 64MiB` if you archive constantly; the enforced floor is 19 MiB.

### How the passphrase reaches the tool

There is deliberately **no `--passphrase` flag**: command lines appear in `ps`,
in shell history, and in CI logs. Supply one of:

- an interactive prompt — confirmed on `encrypt`, and on the new passphrase in
  `rewrap`;
- `XCRYPT_PASSPHRASE`, plus `XCRYPT_NEW_PASSPHRASE` for `rewrap`, for scripts and
  for the `vault` helper above.

Any passphrase is accepted, including empty and non-ASCII. It is hashed as raw
UTF-8 bytes with **no Unicode normalization**, so a passphrase with an emoji or
an accent must be typed byte-identically every time — see
[SPEC.md §6.3](SPEC.md) for why normalization is deliberately not applied.

Exit codes: `0` success, `1` operation failed, `2` bad command line.

### A first run, end to end

```sh
./install.sh --shell-helper
source ~/.zshrc                       # or open a new terminal
./set-passphrase.sh                   # prompts twice, hidden

vault encrypt ~/Documents -o ~/vault  # encrypt a tree
vault list ~/vault                    # check what went in
vault verify ~/vault                  # authenticate every byte
vault pack ~/vault -o vault.xcra      # one file, ready to move
```

Or, if you only ever want the single file:

```sh
vault encrypt ~/Documents -o vault.xcra --pack
vault unpack vault.xcra -o ~/vault    # when you need to work with it again
```

Try it on a copy first, and confirm the round trip yourself:

```sh
cp -r ~/Documents /tmp/testdata
vault encrypt /tmp/testdata -o /tmp/vault
vault decrypt /tmp/vault -o /tmp/restored
diff -r /tmp/testdata /tmp/restored/testdata && echo identical
```

Timestamps on restored files will be fresh: mtimes are recorded in the manifest
and shown by `list`, but not yet reapplied on extraction. Everything else —
contents, paths, modes, symlinks, empty directories — round-trips exactly.

Back up the **whole** archive directory, not just `objects/`. `MANIFEST.xcr`
holds the wrapped master key and every path; without it the objects are
unopenable noise.

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
install.sh          test, build, install, optional shell helper
set-passphrase.sh   store a passphrase in the macOS login Keychain
finder/             Finder Quick Actions: right-click encrypt and decrypt
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

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.

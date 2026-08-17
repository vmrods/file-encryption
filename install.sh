#!/usr/bin/env bash
#
# Install the `xcrypt` binary onto this system.
#
# Builds from source by default, or reuses the artifacts ./build.sh produced.
# Installs to /usr/local/bin when that is writable (with sudo if needed), and
# falls back to ~/.local/bin otherwise.
#
# Usage:
#   ./install.sh                        # build from source, install, smoke test
#   ./install.sh --prefix ~/bin         # install somewhere specific
#   ./install.sh --from-dist            # use dist/<host triple>/xcrypt from ./build.sh
#   ./install.sh --shell-helper         # also add a `vault` shell function (see below)
#   ./install.sh --skip-tests           # faster; not recommended
#   ./install.sh --uninstall            # remove the installed binary
#
# The optional shell helper is a `vault()` function that reads the passphrase
# from the macOS login Keychain and runs xcrypt with it, so you never type or
# store the passphrase in a file. Create the Keychain entry with
# ./set-passphrase.sh first.

set -euo pipefail

readonly BIN_NAME="xcrypt"
readonly PACKAGE="xcrypt-cli"
readonly ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly KEYCHAIN_SERVICE_DEFAULT="xcrypt-vault"
readonly HELPER_MARKER="# >>> xcrypt shell helper >>>"
readonly HELPER_END="# <<< xcrypt shell helper <<<"

PREFIX=""
FROM_DIST=0
SHELL_HELPER=0
SKIP_TESTS=0
UNINSTALL=0

log()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
    sed -n '3,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --prefix)       [[ $# -ge 2 ]] || fail "--prefix needs a directory"; PREFIX="$2"; shift 2 ;;
            --prefix=*)     PREFIX="${1#*=}"; shift ;;
            --from-dist)    FROM_DIST=1; shift ;;
            --shell-helper) SHELL_HELPER=1; shift ;;
            --skip-tests)   SKIP_TESTS=1; shift ;;
            --uninstall)    UNINSTALL=1; shift ;;
            -h|--help)      usage ;;
            *)              fail "unknown option: $1 (try --help)" ;;
        esac
    done
}

host_target() {
    rustc --version --verbose | awk '/^host:/ { print $2 }'
}

# Pick an install directory, preferring one already on PATH.
choose_prefix() {
    if [[ -n "$PREFIX" ]]; then
        printf '%s\n' "$PREFIX"
        return 0
    fi

    if [[ -w /usr/local/bin ]] || command -v sudo >/dev/null 2>&1; then
        printf '%s\n' /usr/local/bin
    else
        printf '%s\n' "$HOME/.local/bin"
    fi
}

# Copy into place, escalating with sudo only when the directory needs it.
install_file() {
    local source="$1" dest_dir="$2" dest="$2/$BIN_NAME"

    if [[ ! -d "$dest_dir" ]]; then
        if mkdir -p "$dest_dir" 2>/dev/null; then
            :
        elif command -v sudo >/dev/null 2>&1; then
            log "creating ${dest_dir} (needs sudo)"
            sudo mkdir -p "$dest_dir"
        else
            fail "cannot create ${dest_dir}"
        fi
    fi

    if [[ -w "$dest_dir" ]]; then
        install -m 755 "$source" "$dest"
    elif command -v sudo >/dev/null 2>&1; then
        log "installing to ${dest} (needs sudo)"
        sudo install -m 755 "$source" "$dest"
    else
        fail "${dest_dir} is not writable and sudo is unavailable; try --prefix ~/.local/bin"
    fi
}

remove_file() {
    local dest="$1/$BIN_NAME"
    if [[ ! -e "$dest" ]]; then
        warn "${dest} does not exist"
        return 0
    fi
    if [[ -w "$1" ]]; then
        rm -f "$dest"
    elif command -v sudo >/dev/null 2>&1; then
        sudo rm -f "$dest"
    else
        fail "cannot remove ${dest}"
    fi
    log "removed ${dest}"
}

on_path() {
    case ":${PATH}:" in
        *":$1:"*) return 0 ;;
        *)        return 1 ;;
    esac
}

# Append the `vault` helper to the user's shell rc, idempotently.
install_shell_helper() {
    local rc
    case "${SHELL##*/}" in
        zsh)  rc="$HOME/.zshrc" ;;
        bash) rc="$HOME/.bashrc" ;;
        *)
            warn "unrecognised shell '${SHELL}'; skipping the shell helper"
            return 0
            ;;
    esac

    if [[ -f "$rc" ]] && grep -qF "$HELPER_MARKER" "$rc"; then
        log "shell helper already present in ${rc}"
        return 0
    fi

    if [[ "$(uname -s)" != "Darwin" ]]; then
        warn "the shell helper uses the macOS Keychain; skipping on $(uname -s)"
        return 0
    fi

    cat >> "$rc" <<EOF

${HELPER_MARKER}
# Runs xcrypt with the passphrase read from the login Keychain, so it is never
# typed, exported, or written to a file. Create the entry with ./set-passphrase.sh
# Override the entry name with: XCRYPT_KEYCHAIN_SERVICE=xcrypt-photos vault list ...
#
# Values written by set-passphrase.sh are base64 behind an 'xcb64:' marker,
# because 'security -w' returns a hex dump instead of the text whenever the
# stored value is not plain ASCII. Entries created by hand are used as-is.
vault() {
  local service="\${XCRYPT_KEYCHAIN_SERVICE:-${KEYCHAIN_SERVICE_DEFAULT}}"
  local raw pw flag
  raw="\$(security find-generic-password -a "\$USER" -s "\$service" -w 2>/dev/null)" || {
    echo "vault: no Keychain entry '\$service' — run ./set-passphrase.sh" >&2
    return 1
  }
  if printf '' | base64 -d >/dev/null 2>&1; then flag=-d; else flag=-D; fi
  case "\$raw" in
    xcb64:*) pw="\$(printf '%s' "\${raw#xcb64:}" | base64 "\$flag")" ;;
    *)       pw="\$raw" ;;
  esac
  XCRYPT_PASSPHRASE="\$pw" command ${BIN_NAME} "\$@"
}
${HELPER_END}
EOF

    log "added the 'vault' helper to ${rc}"
    log "run 'source ${rc}' or open a new terminal to use it"
}

main() {
    parse_args "$@"
    cd "$ROOT_DIR"

    local prefix
    prefix="$(choose_prefix)"

    if [[ $UNINSTALL -eq 1 ]]; then
        remove_file "$prefix"
        log "the Keychain entry (if any) was left alone; remove it with:"
        printf '      security delete-generic-password -a "$USER" -s %s\n' "$KEYCHAIN_SERVICE_DEFAULT"
        return 0
    fi

    local source_bin
    if [[ $FROM_DIST -eq 1 ]]; then
        command -v rustc >/dev/null 2>&1 || fail "rustc not found; needed to determine the host triple"
        source_bin="${ROOT_DIR}/dist/$(host_target)/${BIN_NAME}"
        [[ -f "$source_bin" ]] || fail "no artifact at ${source_bin}; run ./build.sh first"
        log "installing the prebuilt binary from dist/"
    else
        command -v cargo >/dev/null 2>&1 || fail "cargo not found on PATH; install Rust from https://rustup.rs"

        if [[ $SKIP_TESTS -eq 0 ]]; then
            # Installing a build that fails its own corruption suite would defeat
            # the point of the tool.
            log "running the test suite"
            cargo test --workspace --locked --release
        fi

        log "building ${PACKAGE} in release mode"
        cargo build --release --locked --package "$PACKAGE"
        source_bin="${ROOT_DIR}/target/release/${BIN_NAME}"
    fi

    install_file "$source_bin" "$prefix"
    log "installed ${prefix}/${BIN_NAME}"

    # Run the installed copy, not the one in target/, so a broken install shows up.
    "${prefix}/${BIN_NAME}" --version

    if ! on_path "$prefix"; then
        warn "${prefix} is not on your PATH; add this to your shell rc:"
        printf '      export PATH="%s:$PATH"\n' "$prefix"
    fi

    [[ $SHELL_HELPER -eq 1 ]] && install_shell_helper

    echo
    log "next steps"
    printf '      ./set-passphrase.sh          store a passphrase in the login Keychain\n'
    printf '      %s encrypt ~/Documents -o ~/vault\n' "$BIN_NAME"
    printf '      %s list ~/vault\n' "$BIN_NAME"
}

main "$@"

#!/usr/bin/env bash
#
# Store an xcrypt passphrase in the macOS login Keychain, so it can be reused on
# this system without ever living in a file or in shell history.
#
# Usage:
#   ./set-passphrase.sh                     # prompt for the passphrase (recommended)
#   ./set-passphrase.sh 'my passphrase'     # take it as the only argument
#   echo 'my passphrase' | ./set-passphrase.sh --stdin
#
#   XCRYPT_KEYCHAIN_SERVICE=xcrypt-photos ./set-passphrase.sh    # a second archive
#
#   ./set-passphrase.sh --show              # print the stored passphrase
#   ./set-passphrase.sh --delete            # remove the entry
#
# PASSING THE PASSPHRASE AS AN ARGUMENT IS THE LEAST SAFE OPTION. It lands in
# your shell history, and on some systems it is briefly visible to other
# processes in `ps`. This script accepts it because it is convenient for
# scripted setup, warns when you use it, and defaults to a hidden prompt.
#
# Once stored, use it with the `vault` shell function (./install.sh
# --shell-helper), or directly:
#
#   XCRYPT_PASSPHRASE="$(security find-generic-password -a "$USER" \
#       -s xcrypt-vault -w)" xcrypt list ~/vault

set -euo pipefail

readonly SERVICE="${XCRYPT_KEYCHAIN_SERVICE:-xcrypt-vault}"
readonly ACCOUNT="${USER:-$(id -un)}"
readonly LABEL="xcrypt archive passphrase (${SERVICE})"

# Passphrases are stored base64-encoded behind this marker.
#
# Not decoration: `security find-generic-password -w` returns a *hex dump* rather
# than the text whenever the stored value is not plain ASCII, so a passphrase
# containing an accent or an emoji reads back as something else entirely — and
# xcrypt would then derive a different key without anyone noticing. Encoding
# every value keeps the stored form ASCII, and the marker distinguishes entries
# this script wrote from ones created by hand with plain text.
readonly ENCODING_MARKER="xcb64:"

log()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
    sed -n '3,28p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
}

require_macos() {
    [[ "$(uname -s)" == "Darwin" ]] ||
        fail "this script uses the macOS Keychain; on Linux use 'secret-tool store --label=xcrypt xcrypt ${SERVICE}'"
    command -v security >/dev/null 2>&1 || fail "the 'security' command was not found"
}

entry_exists() {
    security find-generic-password -a "$ACCOUNT" -s "$SERVICE" >/dev/null 2>&1
}

# GNU coreutils spells it -d, BSD/macOS historically -D. Probe once.
b64_decode_flag() {
    if printf '' | base64 -d >/dev/null 2>&1; then
        printf '%s' "-d"
    else
        printf '%s' "-D"
    fi
}

encode_passphrase() {
    printf '%s' "$1" | base64 | tr -d '\n'
}

# Read the entry and undo the encoding. Entries without the marker are assumed
# to be plain text, so hand-made entries keep working.
read_stored() {
    local raw
    raw="$(security find-generic-password -a "$ACCOUNT" -s "$SERVICE" -w)" || return 1

    case "$raw" in
        "${ENCODING_MARKER}"*)
            printf '%s' "${raw#"$ENCODING_MARKER"}" | base64 "$(b64_decode_flag)"
            ;;
        *)
            printf '%s' "$raw"
            ;;
    esac
}

show_entry() {
    entry_exists || fail "no Keychain entry '${SERVICE}' for account '${ACCOUNT}'"
    read_stored
    printf '\n'
}

delete_entry() {
    entry_exists || fail "no Keychain entry '${SERVICE}' for account '${ACCOUNT}'"
    security delete-generic-password -a "$ACCOUNT" -s "$SERVICE" >/dev/null
    log "removed the Keychain entry '${SERVICE}'"
    warn "any archive encrypted under it is now unopenable unless you have the passphrase elsewhere"
}

# Read a passphrase twice without echoing, and require the two to match.
prompt_for_passphrase() {
    local first second
    # Prompts go to stderr so stdout stays clean for callers.
    printf 'Passphrase for %s: ' "$SERVICE" >&2
    IFS= read -r -s first || fail "could not read from the terminal"
    printf '\n' >&2

    printf 'Confirm passphrase: ' >&2
    IFS= read -r -s second || fail "could not read from the terminal"
    printf '\n' >&2

    [[ "$first" == "$second" ]] || fail "the passphrases do not match"
    printf '%s' "$first"
}

store() {
    local passphrase="$1"

    if entry_exists; then
        log "an entry named '${SERVICE}' already exists and will be replaced"
        warn "archives encrypted under the old passphrase will no longer open with this entry"
        warn "if you meant to change an archive's passphrase, run 'xcrypt rewrap' first"
    fi

    # -U updates in place; -w with a value avoids a second interactive prompt.
    # The value reaches `security` as an argument, which is unavoidable with this
    # tool — but it is this script's argv, not your shell's history.
    security add-generic-password \
        -U \
        -a "$ACCOUNT" \
        -s "$SERVICE" \
        -l "$LABEL" \
        -j "Created by set-passphrase.sh on $(date '+%Y-%m-%d'); value is base64 after '${ENCODING_MARKER}'" \
        -w "${ENCODING_MARKER}$(encode_passphrase "$passphrase")"

    log "stored the passphrase as Keychain item '${SERVICE}' for account '${ACCOUNT}'"
}

# Read the value back and compare. This is not ceremony: it is what caught the
# hex-encoding behaviour of `security -w` for non-ASCII passphrases. A passphrase
# that reads back wrong would silently derive the wrong key at decrypt time.
verify_roundtrip() {
    local expected="$1" actual
    actual="$(read_stored)" ||
        fail "the entry was written but could not be read back"
    [[ "$actual" == "$expected" ]] ||
        fail "the entry read back differently than it was written"
    log "verified: the stored value reads back byte-for-byte"
}

main() {
    local passphrase="" from_stdin=0

    case "${1:---prompt}" in
        -h|--help) usage ;;
        --show)    require_macos; show_entry; exit 0 ;;
        --delete)  require_macos; delete_entry; exit 0 ;;
        --stdin)   from_stdin=1 ;;
        --prompt)  ;;
        -*)        fail "unknown option: $1 (try --help)" ;;
        *)         passphrase="$1" ;;
    esac

    [[ $# -le 1 ]] || fail "expected at most one argument: the passphrase"

    require_macos

    if [[ $from_stdin -eq 1 ]]; then
        # `read -r` without IFS keeps leading and trailing whitespace, which is
        # legal in a passphrase and must not be silently trimmed.
        IFS= read -r passphrase || fail "no passphrase on stdin"
    elif [[ -n "$passphrase" ]]; then
        warn "the passphrase was passed as an argument; it is now in your shell history"
        warn "clear it with: history -d \$((HISTCMD-1))   (zsh: use 'fc -R' or edit ~/.zsh_history)"
    else
        passphrase="$(prompt_for_passphrase)"
    fi

    # An empty passphrase is cryptographically legal — xcrypt accepts one — but
    # is almost never what someone means to store.
    if [[ -z "$passphrase" ]]; then
        warn "storing an EMPTY passphrase; anyone with the archive can open it"
    fi

    store "$passphrase"
    verify_roundtrip "$passphrase"

    echo
    log "use it with:"
    printf '      vault list ~/vault                  # if you installed the shell helper\n'
    printf '      XCRYPT_PASSPHRASE="$(./set-passphrase.sh --show)" xcrypt list ~/vault\n'
    echo
    warn "the Keychain is now your only copy — keep an offline backup somewhere physical"
}

main "$@"

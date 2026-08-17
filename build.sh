#!/usr/bin/env bash
#
# Build release binaries of `xcrypt` for macOS, Linux, and Windows.
#
# Cross-compiling Rust needs a linker for the target, which cargo alone does not
# provide. This script therefore uses, in order of preference:
#
#   1. plain `cargo` for the host target (always works);
#   2. `cross` (https://github.com/cross-rs/cross) for other targets, which runs
#      the build in a container that already has the right toolchain;
#   3. plain `cargo` for other targets, if the rustup target and a linker are
#      already installed locally.
#
# Targets that cannot be built are reported and skipped, not silently dropped:
# the exit status is non-zero if any requested target failed.
#
# Usage:
#   ./build.sh                    # every default target
#   ./build.sh macos              # one group: macos | linux | windows | host
#   ./build.sh aarch64-apple-darwin x86_64-unknown-linux-musl
#   NO_STRIP=1 ./build.sh         # keep debug symbols
#
# Output: dist/<target>/xcrypt[.exe], plus dist/xcrypt-<target>.tar.gz (or .zip
# for Windows) and dist/SHA256SUMS.

set -euo pipefail

readonly BIN_NAME="xcrypt"
readonly PACKAGE="xcrypt-cli"
readonly ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly DIST_DIR="${ROOT_DIR}/dist"

readonly MACOS_TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)
readonly LINUX_TARGETS=(x86_64-unknown-linux-musl aarch64-unknown-linux-musl)
readonly WINDOWS_TARGETS=(x86_64-pc-windows-msvc)

log()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; }

host_target() {
    rustc --version --verbose | awk '/^host:/ { print $2 }'
}

# Expand the argument list into concrete target triples.
resolve_targets() {
    local -a requested=("$@")
    local -a out=()

    if [[ ${#requested[@]} -eq 0 ]]; then
        out=("${MACOS_TARGETS[@]}" "${LINUX_TARGETS[@]}" "${WINDOWS_TARGETS[@]}")
    else
        local arg
        for arg in "${requested[@]}"; do
            case "$arg" in
                macos|darwin) out+=("${MACOS_TARGETS[@]}") ;;
                linux)        out+=("${LINUX_TARGETS[@]}") ;;
                windows|win)  out+=("${WINDOWS_TARGETS[@]}") ;;
                host)         out+=("$(host_target)") ;;
                *-*-*)        out+=("$arg") ;;
                *)
                    fail "unknown target or group: ${arg}"
                    return 1
                    ;;
            esac
        done
    fi

    printf '%s\n' "${out[@]}" | awk '!seen[$0]++'
}

# Does the *active* rustc have a standard library for this target?
#
# Deliberately not `rustup target list --installed`: the cargo on PATH may not be
# rustup's (a Homebrew or distro toolchain, say), in which case rustup's answer
# describes a toolchain that is not doing the build. Asking rustc where the target
# libdir is, and whether it exists, is true for every toolchain.
have_rust_std() {
    local target="$1" libdir
    libdir="$(rustc --target "$target" --print target-libdir 2>/dev/null)" || return 1
    [[ -n "$libdir" && -d "$libdir" ]]
}

# Choose the build driver for a target.
select_driver() {
    local target="$1"

    if [[ "$target" == "$(host_target)" ]]; then
        echo cargo
        return 0
    fi

    # Apple targets only build on macOS, and `cross` cannot help: the SDK is not
    # redistributable. Same story in reverse for the MSVC Windows target.
    case "$target" in
        *-apple-darwin)
            if [[ "$(uname -s)" == "Darwin" ]] && have_rust_std "$target"; then
                echo cargo
            else
                echo unavailable
            fi
            return 0
            ;;
        *-pc-windows-msvc)
            if command -v cargo-xwin >/dev/null 2>&1; then
                echo xwin
            elif [[ "$(uname -s)" == MINGW* || "$(uname -s)" == MSYS* ]] && have_rust_std "$target"; then
                echo cargo
            else
                echo unavailable
            fi
            return 0
            ;;
    esac

    if command -v cross >/dev/null 2>&1 && docker_available; then
        echo cross
    elif have_rust_std "$target"; then
        echo cargo
    else
        echo unavailable
    fi
}

docker_available() {
    command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1
}

# Explain what the user would need to install for a skipped target.
advise() {
    local target="$1"
    case "$target" in
        *-apple-darwin)
            warn "  ${target} requires macOS with the Xcode command line tools, plus: rustup target add ${target}"
            ;;
        *-pc-windows-msvc)
            warn "  ${target} requires 'cargo install cargo-xwin' (cross-compiles from any host), or a Windows host"
            ;;
        *-unknown-linux-*)
            warn "  ${target} requires 'cargo install cross' with a running Docker daemon, or a Linux host with the matching linker"
            ;;
        *)
            warn "  ${target}: install the toolchain, then: rustup target add ${target}"
            ;;
    esac
}

build_one() {
    local target="$1"
    local driver
    driver="$(select_driver "$target")"

    if [[ "$driver" == unavailable ]]; then
        warn "skipping ${target}: no usable toolchain on this host"
        advise "$target"
        return 1
    fi

    log "building ${target} (via ${driver})"

    case "$driver" in
        cargo) cargo build --release --locked --package "$PACKAGE" --target "$target" ;;
        cross) cross build --release --locked --package "$PACKAGE" --target "$target" ;;
        xwin)  cargo xwin build --release --locked --package "$PACKAGE" --target "$target" ;;
    esac
}

# Copy, strip, and archive one built binary.
package_one() {
    local target="$1"
    local suffix=""
    [[ "$target" == *windows* ]] && suffix=".exe"

    local built="${ROOT_DIR}/target/${target}/release/${BIN_NAME}${suffix}"
    if [[ ! -f "$built" ]]; then
        fail "expected binary not found: ${built}"
        return 1
    fi

    local out_dir="${DIST_DIR}/${target}"
    mkdir -p "$out_dir"
    cp "$built" "${out_dir}/"

    if [[ -z "${NO_STRIP:-}" && -z "$suffix" ]] && command -v strip >/dev/null 2>&1; then
        # A failed strip is not worth aborting a release build over.
        strip "${out_dir}/${BIN_NAME}" 2>/dev/null || warn "could not strip ${target} binary"
    fi

    if [[ -n "$suffix" ]] && command -v zip >/dev/null 2>&1; then
        (cd "$out_dir" && zip -q "${DIST_DIR}/${BIN_NAME}-${target}.zip" "${BIN_NAME}${suffix}")
    else
        tar -czf "${DIST_DIR}/${BIN_NAME}-${target}.tar.gz" -C "$out_dir" "${BIN_NAME}${suffix}"
    fi

    log "packaged ${target}"
}

write_checksums() {
    local -a archives=()
    while IFS= read -r archive; do
        archives+=("$archive")
    done < <(find "$DIST_DIR" -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.zip' \) | sort)

    [[ ${#archives[@]} -eq 0 ]] && return 0

    local sums="${DIST_DIR}/SHA256SUMS"
    : > "$sums"
    local archive
    for archive in "${archives[@]}"; do
        if command -v shasum >/dev/null 2>&1; then
            (cd "$DIST_DIR" && shasum -a 256 "$(basename "$archive")" >> "$sums")
        elif command -v sha256sum >/dev/null 2>&1; then
            (cd "$DIST_DIR" && sha256sum "$(basename "$archive")" >> "$sums")
        else
            warn "no sha256 tool found; skipping checksums"
            return 0
        fi
    done
    log "wrote $(basename "$sums")"
}

main() {
    cd "$ROOT_DIR"

    command -v cargo >/dev/null 2>&1 || { fail "cargo not found on PATH"; exit 1; }

    local -a targets=()
    while IFS= read -r target; do
        targets+=("$target")
    done < <(resolve_targets "$@")

    log "host: $(host_target)"
    log "targets: ${targets[*]}"

    # A release build that ships failing code is worse than no release.
    log "running the test suite"
    cargo test --workspace --locked --release

    mkdir -p "$DIST_DIR"

    local -a succeeded=() failed=()
    local target
    for target in "${targets[@]}"; do
        if build_one "$target" && package_one "$target"; then
            succeeded+=("$target")
        else
            failed+=("$target")
        fi
    done

    write_checksums

    echo
    log "built: ${#succeeded[@]} of ${#targets[@]}"
    # Guarded expansion: bash 3.2 (the macOS system bash) treats an empty array
    # as unset under `set -u`.
    for target in ${succeeded[@]+"${succeeded[@]}"}; do
        printf '  \033[32mok\033[0m      %s\n' "$target"
    done
    for target in ${failed[@]+"${failed[@]}"}; do
        printf '  \033[31mfailed\033[0m  %s\n' "$target"
    done

    [[ ${#failed[@]} -eq 0 ]]
}

main "$@"

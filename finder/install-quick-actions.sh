#!/usr/bin/env bash
#
# Install "Encrypt with xcrypt" and "Decrypt with xcrypt" as Finder Quick
# Actions, so both appear when you right-click a file or folder.
#
# A Quick Action is an Automator workflow bundle in ~/Library/Services. This
# script writes the two bundles directly — no Automator window, no clicking —
# and installs the handler script they call.
#
# Usage:
#   ./finder/install-quick-actions.sh              # install for the current user
#   ./finder/install-quick-actions.sh --uninstall  # remove them again
#   SERVICES_DIR=/tmp/x ./finder/install-quick-actions.sh   # install elsewhere (testing)
#
# After installing, the actions appear under the Quick Actions submenu when you
# right-click in Finder. If they do not show up immediately, log out and back in,
# or enable them in System Settings → General → Login Items & Extensions →
# Extensions → Finder.

set -euo pipefail

readonly ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly HANDLER_SOURCE="${ROOT_DIR}/finder/xcrypt-finder"
readonly HANDLER_DIR="${HOME}/Library/Application Support/xcrypt"
readonly HANDLER="${HANDLER_DIR}/xcrypt-finder"
SERVICES_DIR="${SERVICES_DIR:-${HOME}/Library/Services}"

readonly ENCRYPT_NAME="Encrypt with xcrypt"
readonly DECRYPT_NAME="Decrypt with xcrypt"

log()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[[ "$(uname -s)" == "Darwin" ]] || fail "Quick Actions are a macOS feature"

# Write one workflow bundle: Info.plist declares the Services menu entry,
# document.wflow is the single Run Shell Script action that calls the handler.
write_workflow() {
    local name="$1" mode="$2"
    local bundle="${SERVICES_DIR}/${name}.workflow"
    local contents="${bundle}/Contents"

    rm -rf "$bundle"
    mkdir -p "$contents"

    cat > "${contents}/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>NSServices</key>
    <array>
        <dict>
            <key>NSMenuItem</key>
            <dict>
                <key>default</key>
                <string>${name}</string>
            </dict>
            <key>NSMessage</key>
            <string>runWorkflowAsService</string>
            <key>NSRequiredContext</key>
            <dict>
                <key>NSApplicationIdentifier</key>
                <string>com.apple.finder</string>
            </dict>
            <key>NSSendFileTypes</key>
            <array>
                <string>public.item</string>
            </array>
        </dict>
    </array>
</dict>
</plist>
PLIST

    # `inputMethod` 1 means "pass the input as arguments", which is what makes
    # "$@" inside the shell action the list of selected Finder items.
    cat > "${contents}/document.wflow" <<WFLOW
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>AMApplicationBuild</key>
    <string>521</string>
    <key>AMApplicationVersion</key>
    <string>2.10</string>
    <key>AMDocumentVersion</key>
    <string>2</string>
    <key>actions</key>
    <array>
        <dict>
            <key>action</key>
            <dict>
                <key>AMAccepts</key>
                <dict>
                    <key>Container</key>
                    <string>List</string>
                    <key>Optional</key>
                    <true/>
                    <key>Types</key>
                    <array>
                        <string>com.apple.cocoa.string</string>
                    </array>
                </dict>
                <key>AMActionVersion</key>
                <string>2.0.3</string>
                <key>AMApplication</key>
                <array>
                    <string>Automator</string>
                </array>
                <key>AMParameterProperties</key>
                <dict>
                    <key>COMMAND_STRING</key>
                    <dict/>
                    <key>CheckedForUserDefaultShell</key>
                    <dict/>
                    <key>inputMethod</key>
                    <dict/>
                    <key>shell</key>
                    <dict/>
                    <key>source</key>
                    <dict/>
                </dict>
                <key>AMProvides</key>
                <dict>
                    <key>Container</key>
                    <string>List</string>
                    <key>Types</key>
                    <array>
                        <string>com.apple.cocoa.string</string>
                    </array>
                </dict>
                <key>ActionBundlePath</key>
                <string>/System/Library/Automator/Run Shell Script.action</string>
                <key>ActionName</key>
                <string>Run Shell Script</string>
                <key>ActionParameters</key>
                <dict>
                    <key>COMMAND_STRING</key>
                    <string>"\${HOME}/Library/Application Support/xcrypt/xcrypt-finder" ${mode} "\$@"</string>
                    <key>CheckedForUserDefaultShell</key>
                    <true/>
                    <key>inputMethod</key>
                    <integer>1</integer>
                    <key>shell</key>
                    <string>/bin/bash</string>
                    <key>source</key>
                    <string></string>
                </dict>
                <key>BundleIdentifier</key>
                <string>com.apple.RunShellScript</string>
                <key>CFBundleVersion</key>
                <string>2.0.3</string>
                <key>CanShowSelectedItemsWhenRun</key>
                <false/>
                <key>CanShowWhenRun</key>
                <true/>
                <key>Category</key>
                <array>
                    <string>AMCategoryUtilities</string>
                </array>
                <key>Class Name</key>
                <string>RunShellScriptAction</string>
                <key>InputUUID</key>
                <string>$(uuidgen)</string>
                <key>Keywords</key>
                <array>
                    <string>Shell</string>
                    <string>Script</string>
                    <string>Command</string>
                </array>
                <key>OutputUUID</key>
                <string>$(uuidgen)</string>
                <key>UUID</key>
                <string>$(uuidgen)</string>
                <key>UnlocalizedApplications</key>
                <array>
                    <string>Automator</string>
                </array>
                <key>arguments</key>
                <dict/>
                <key>isViewVisible</key>
                <integer>1</integer>
                <key>location</key>
                <string>309.000000:253.000000</string>
                <key>nibPath</key>
                <string>/System/Library/Automator/Run Shell Script.action/Contents/Resources/Base.lproj/main.nib</string>
            </dict>
            <key>isViewVisible</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>connectors</key>
    <dict/>
    <key>workflowMetaData</key>
    <dict>
        <key>serviceApplicationBundleID</key>
        <string>com.apple.finder</string>
        <key>serviceApplicationPath</key>
        <string>/System/Library/CoreServices/Finder.app</string>
        <key>serviceInputTypeIdentifier</key>
        <string>com.apple.Automator.fileSystemObject</string>
        <key>serviceOutputTypeIdentifier</key>
        <string>com.apple.Automator.nothing</string>
        <key>serviceProcessesInput</key>
        <integer>0</integer>
        <key>workflowTypeIdentifier</key>
        <string>com.apple.Automator.servicesMenu</string>
    </dict>
</dict>
</plist>
WFLOW

    plutil -lint "${contents}/Info.plist" >/dev/null || fail "generated Info.plist is invalid"
    plutil -lint "${contents}/document.wflow" >/dev/null || fail "generated document.wflow is invalid"

    log "installed ${bundle}"
}

uninstall() {
    local name
    for name in "$ENCRYPT_NAME" "$DECRYPT_NAME"; do
        if [[ -d "${SERVICES_DIR}/${name}.workflow" ]]; then
            rm -rf "${SERVICES_DIR}/${name}.workflow"
            log "removed ${SERVICES_DIR}/${name}.workflow"
        fi
    done
    [[ -f "$HANDLER" ]] && { rm -f "$HANDLER"; log "removed ${HANDLER}"; }
    /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister \
        -kill -r -domain local -domain user >/dev/null 2>&1 || true
    log "done — the menu entries disappear after Finder next reloads its services"
    exit 0
}

main() {
    [[ "${1:-}" == "--uninstall" ]] && uninstall

    [[ -f "$HANDLER_SOURCE" ]] || fail "handler not found at ${HANDLER_SOURCE}"

    # The handler is copied out of the repo so the Quick Actions keep working if
    # the repo moves or is deleted.
    mkdir -p "$HANDLER_DIR"
    install -m 755 "$HANDLER_SOURCE" "$HANDLER"
    log "installed handler at ${HANDLER}"

    mkdir -p "$SERVICES_DIR"
    write_workflow "$ENCRYPT_NAME" encrypt
    write_workflow "$DECRYPT_NAME" decrypt

    # Nudge Launch Services so the new entries appear without a logout.
    /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister \
        -kill -r -domain local -domain user >/dev/null 2>&1 || true

    if ! command -v xcrypt >/dev/null 2>&1 \
        && [[ ! -x /usr/local/bin/xcrypt && ! -x "${HOME}/.local/bin/xcrypt" && ! -x "${HOME}/.cargo/bin/xcrypt" ]]; then
        warn "xcrypt is not installed anywhere the handler looks; run ./install.sh first"
    fi

    if ! security find-generic-password -a "${USER}" -s "${XCRYPT_KEYCHAIN_SERVICE:-xcrypt-vault}" >/dev/null 2>&1; then
        warn "no Keychain passphrase found; the Quick Actions will prompt each time"
        warn "run ./set-passphrase.sh to store one"
    fi

    echo
    log "right-click any file or folder in Finder → Quick Actions"
    printf '      %s   → creates <name>.xcra beside it\n' "$ENCRYPT_NAME"
    printf '      %s   → restores into <name>-restored/\n' "$DECRYPT_NAME"
    echo
    log "if they do not appear: System Settings → General →"
    printf '      Login Items & Extensions → Extensions → Finder, and tick them\n'
}

main "$@"

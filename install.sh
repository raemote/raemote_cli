#!/bin/sh
# raemote server installer
#
#   curl -fsSL https://github.com/raemote/raemote_cli/raw/main/install.sh | sh
#
# Downloads the latest release (Gitee, falling back to GitHub), verifies its
# SHA-256, installs `raemote` + `raemoted` into ~/.local/bin, installs and
# starts the background service, and prints the pairing URI.
#
# Uninstall:
#   curl -fsSL .../install.sh | sh -s -- --uninstall [--purge]
set -eu

# ---------------------------------------------------------------------------
# Defaults (all overridable via env or flags)
# ---------------------------------------------------------------------------
GITEE_REPO="${RAEMOTE_GITEE_REPO:-pppkin/raemote_cli}"
GITHUB_REPO="${RAEMOTE_GITHUB_REPO:-raemote/raemote_cli}"
SOURCE="${RAEMOTE_SOURCE:-auto}"          # auto | gitee | github
BIN_DIR="${RAEMOTE_BIN_DIR:-$HOME/.local/bin}"
TAG="${RAEMOTE_TAG:-}"
BASE_URL_OVERRIDE="${RAEMOTE_BASE_URL:-}"

DO_SERVICE=1
if [ "${RAEMOTE_NO_SERVICE:-0}" = "1" ]; then DO_SERVICE=0; fi
PROXY=""
UNINSTALL=0
PURGE=0
DRY_RUN=0
JSON=0
QUIET=0

BASE_URL=""
ASSET=""

# ---------------------------------------------------------------------------
# Logging / helpers
# ---------------------------------------------------------------------------
log()  { [ "$QUIET" = 1 ] || printf '%s\n' "$*" >&2; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
    cat >&2 <<'EOF'
raemote installer

Options:
  --source gitee|github|auto   Where to fetch releases (default: auto)
  --tag TAG                    Pin a release tag instead of latest
  --base-url URL               Override the download base URL (testing)
  --bin-dir DIR                Install directory (default: ~/.local/bin)
  --no-service                 Install binaries only; don't set up the service
  --proxy URL                  Set [network] proxy in the config
  --uninstall                  Stop the service and remove the binaries
  --purge                      With --uninstall, also delete ~/.raemote
  --dry-run                    Resolve and print what would happen
  --json                       Emit a machine-readable summary
  --quiet                      Suppress progress output
  -h, --help                   Show this help

Env: RAEMOTE_SOURCE RAEMOTE_TAG RAEMOTE_BASE_URL RAEMOTE_BIN_DIR
     RAEMOTE_NO_SERVICE RAEMOTE_GITEE_REPO RAEMOTE_GITHUB_REPO
EOF
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --source)     SOURCE="${2:?--source needs a value}"; shift 2 ;;
        --tag)        TAG="${2:?--tag needs a value}"; shift 2 ;;
        --base-url)   BASE_URL_OVERRIDE="${2:?--base-url needs a value}"; shift 2 ;;
        --bin-dir)    BIN_DIR="${2:?--bin-dir needs a value}"; shift 2 ;;
        --no-service) DO_SERVICE=0; shift ;;
        --proxy)      PROXY="${2:?--proxy needs a value}"; shift 2 ;;
        --uninstall)  UNINSTALL=1; shift ;;
        --purge)      PURGE=1; shift ;;
        --dry-run)    DRY_RUN=1; shift ;;
        --json)       JSON=1; shift ;;
        --quiet)      QUIET=1; shift ;;
        -h|--help)    usage; exit 0 ;;
        *)            die "unknown argument: $1 (try --help)" ;;
    esac
done

case "$BIN_DIR" in
    "~"*) BIN_DIR="$HOME${BIN_DIR#\~}" ;;
esac

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------
detect_target() {
    os=$(uname -s)
    arch=$(uname -m)
    case "$os" in
        Darwin) os_part=darwin ;;
        Linux)  os_part=linux ;;
        *) die "unsupported OS '$os' (supported: macOS, Linux)" ;;
    esac
    case "$arch" in
        arm64|aarch64) arch_part=arm64 ;;
        x86_64|amd64)  arch_part=x86_64 ;;
        *) die "unsupported architecture '$arch'" ;;
    esac
    case "$os_part-$arch_part" in
        darwin-arm64|darwin-x86_64|linux-x86_64|linux-arm64) ;;
        *) die "unsupported platform '$os_part-$arch_part'" ;;
    esac
    printf 'raemote-%s-%s' "$os_part" "$arch_part"
}

# ---------------------------------------------------------------------------
# Download helpers
# ---------------------------------------------------------------------------
download() { # url dest
    if have curl; then curl -fsSL "$1" -o "$2"
    elif have wget; then wget -q -O "$2" "$1"
    else die "need 'curl' or 'wget' to download"; fi
}

fetch() { # url -> stdout
    if have curl; then curl -fsSL "$1"
    elif have wget; then wget -q -O - "$1"
    else die "need 'curl' or 'wget' to download"; fi
}

sha256_of() {
    if have sha256sum; then sha256sum "$1" | cut -d' ' -f1
    elif have shasum; then shasum -a 256 "$1" | cut -d' ' -f1
    else die "need 'sha256sum' or 'shasum' to verify"; fi
}

# ---------------------------------------------------------------------------
# Release resolution (no version pinning: always the latest)
# ---------------------------------------------------------------------------
gitee_base() {
    _tag="$TAG"
    if [ -z "$_tag" ]; then
        _json=$(fetch "https://gitee.com/api/v5/repos/$GITEE_REPO/releases/latest" 2>/dev/null) || return 1
        _tag=$(printf '%s' "$_json" \
            | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' \
            | head -n1 \
            | sed 's/.*"\([^"]*\)"$/\1/') || true
        [ -n "$_tag" ] || return 1
    fi
    printf 'https://gitee.com/%s/releases/download/%s' "$GITEE_REPO" "$_tag"
}

github_base() {
    if [ -n "$TAG" ]; then
        printf 'https://github.com/%s/releases/download/%s' "$GITHUB_REPO" "$TAG"
    else
        # GitHub redirects this to the latest release's asset.
        printf 'https://github.com/%s/releases/latest/download' "$GITHUB_REPO"
    fi
}

resolve_base() {
    if [ -n "$BASE_URL_OVERRIDE" ]; then
        BASE_URL="$BASE_URL_OVERRIDE"
        return
    fi
    case "$SOURCE" in
        gitee)  BASE_URL=$(gitee_base) || die "could not find a release on Gitee ($GITEE_REPO)" ;;
        github) BASE_URL=$(github_base) ;;
        auto)
            if BASE_URL=$(gitee_base); then
                :
            else
                log "Gitee release lookup failed; falling back to GitHub"
                BASE_URL=$(github_base)
            fi
            ;;
        *) die "invalid --source '$SOURCE' (expected auto|gitee|github)" ;;
    esac
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------
do_uninstall() {
    log "uninstalling raemote..."
    if [ -x "$BIN_DIR/raemote" ]; then
        "$BIN_DIR/raemote" service uninstall >/dev/null 2>&1 || true
    fi
    rm -f "$BIN_DIR/raemote" "$BIN_DIR/raemoted"
    if [ "$PURGE" = 1 ]; then
        rm -rf "$HOME/.raemote"
        log "removed ~/.raemote"
    fi
    log "uninstalled."
    if [ "$JSON" = 1 ]; then
        if [ "$PURGE" = 1 ]; then _purged=true; else _purged=false; fi
        printf '{"uninstalled":true,"purged":%s}\n' "$_purged"
    fi
    exit 0
}
if [ "$UNINSTALL" = 1 ]; then
    do_uninstall
fi

# ---------------------------------------------------------------------------
# Resolve + preflight
# ---------------------------------------------------------------------------
ASSET="$(detect_target).tar.gz"
resolve_base

log "raemote installer"
log "  platform : $ASSET"
log "  source   : $BASE_URL"

if [ "$DRY_RUN" = 1 ]; then
    log "  bin dir  : $BIN_DIR"
    log "  service  : $([ "$DO_SERVICE" = 1 ] && echo yes || echo no)"
    if [ -n "$PROXY" ]; then log "  proxy    : $PROXY"; fi
    log "dry run: nothing downloaded or installed."
    if [ "$JSON" = 1 ]; then
        printf '{"dry_run":true,"asset":"%s","base_url":"%s","bin_dir":"%s"}\n' \
            "$ASSET" "$BASE_URL" "$BIN_DIR"
    fi
    exit 0
fi

# ---------------------------------------------------------------------------
# Download + verify
# ---------------------------------------------------------------------------
tmp=$(mktemp -d 2>/dev/null || mktemp -d -t raemote)
trap 'rm -rf "$tmp"' EXIT INT TERM

log "downloading $ASSET ..."
download "$BASE_URL/$ASSET" "$tmp/$ASSET" || die "failed to download $BASE_URL/$ASSET"

log "verifying checksum ..."
download "$BASE_URL/checksums.txt" "$tmp/checksums.txt" || die "failed to download checksums.txt"
expected=$(awk -v f="$ASSET" '{n=$2; sub(/^\*/,"",n); if (n==f) {print $1; exit}}' "$tmp/checksums.txt")
[ -n "$expected" ] || die "no checksum found for $ASSET"
actual=$(sha256_of "$tmp/$ASSET")
[ "$expected" = "$actual" ] || die "checksum mismatch for $ASSET (expected $expected, got $actual)"

tar -xzf "$tmp/$ASSET" -C "$tmp" || die "failed to extract $ASSET"
# Only regular files at the two expected names may be installed: a symlink
# member would be dereferenced by the copy below (even pointing outside the
# staging dir) and a script member would be executed by the --version probe.
for bin in raemote raemoted; do
    if [ -L "$tmp/$bin" ] || [ ! -f "$tmp/$bin" ]; then
        die "archive member '$bin' is not a regular file; refusing to install"
    fi
done

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
log "installing to $BIN_DIR ..."
mkdir -p "$BIN_DIR"

# Stop any existing install so the binaries can be replaced cleanly.
if [ -x "$BIN_DIR/raemote" ]; then
    "$BIN_DIR/raemote" service uninstall >/dev/null 2>&1 || true
    "$BIN_DIR/raemote" stop >/dev/null 2>&1 || true
fi

for bin in raemote raemoted; do
    cp "$tmp/$bin" "$BIN_DIR/.$bin.new"
    chmod 0755 "$BIN_DIR/.$bin.new"
    mv "$BIN_DIR/.$bin.new" "$BIN_DIR/$bin"
    # Clear Gatekeeper quarantine on freshly downloaded binaries.
    if have xattr; then xattr -d com.apple.quarantine "$BIN_DIR/$bin" 2>/dev/null || true; fi
done

VERSION=$("$BIN_DIR/raemote" --version 2>/dev/null | awk '{print $NF}' || true)

# ---------------------------------------------------------------------------
# PATH
# ---------------------------------------------------------------------------
# Add BIN_DIR to the user's shell profiles so `raemote` works in new shells.
PATH_UPDATED=0
RC_HAS_PATH=0
path_line="export PATH=\"$BIN_DIR:\$PATH\""
shell_name=$(basename "${SHELL:-sh}")

add_to_profile() { # file
    rc="$1"
    if [ -e "$rc" ]; then
        if grep -qsF "$BIN_DIR" "$rc" 2>/dev/null; then
            RC_HAS_PATH=1
            return 0
        fi
    else
        # Don't create a profile for a shell the user doesn't run.
        case "$rc" in
            */.zshrc)  [ "$shell_name" = "zsh" ]  || return 0 ;;
            */.bashrc) [ "$shell_name" = "bash" ] || return 0 ;;
        esac
    fi
    {
        printf '\n# Added by the raemote installer\n'
        printf '%s\n' "$path_line"
    } >> "$rc" || { warn "could not update $rc"; return 0; }
    PATH_UPDATED=1
    RC_HAS_PATH=1
    log "added $BIN_DIR to PATH in $rc"
}

add_to_profile "$HOME/.zshrc"
add_to_profile "$HOME/.bashrc"

case ":$PATH:" in
    *":$BIN_DIR:"*)
        : # already usable in this session
        ;;
    *)
        log ""
        if [ "$PATH_UPDATED" = 1 ]; then
            log "Added $BIN_DIR to your PATH (~/.zshrc / ~/.bashrc)."
        elif [ "$RC_HAS_PATH" = 1 ]; then
            log "$BIN_DIR is already in your shell profile."
        else
            log "note: $BIN_DIR is not on your PATH."
        fi
        log "Reload your shell before running 'raemote':"
        log "    source ~/.zshrc     # or ~/.bashrc, or just open a new terminal"
        log "Until then, use the full path: $BIN_DIR/raemote"

        # Only wait when a human is at a terminal; a piped install
        # (`curl ... | sh`) must never read from stdin.
        if [ -t 0 ]; then
            printf 'Press Enter once your shell is reloaded to continue... ' >&2
            read -r _ || true
        fi
        ;;
esac

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
if [ ! -f "$HOME/.raemote/config.toml" ]; then
    log "creating default config ..."
    "$BIN_DIR/raemote" config init >/dev/null 2>&1 || true
fi
if [ -n "$PROXY" ]; then
    log "setting network.proxy = $PROXY"
    "$BIN_DIR/raemote" config set network.proxy "$PROXY" >/dev/null 2>&1 || \
        warn "could not set network.proxy"
fi

# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------
service_installed=false
if [ "$DO_SERVICE" = 1 ]; then
    log "installing background service ..."
    if "$BIN_DIR/raemote" service install; then
        service_installed=true
    else
        warn "service install failed; run '$BIN_DIR/raemote service install' manually"
    fi
    # Linux: keep the user service alive after logout.
    if have loginctl; then
        loginctl enable-linger "$(id -un)" >/dev/null 2>&1 || \
            warn "could not enable-linger; the service will stop when you log out"
    fi
fi

# ---------------------------------------------------------------------------
# Verify + pairing URI
# ---------------------------------------------------------------------------
uri=""
node_id=""
if [ "$DO_SERVICE" = 1 ]; then
    log "waiting for the daemon ..."
    i=0
    while [ "$i" -lt 20 ]; do
        if "$BIN_DIR/raemote" status --json >/dev/null 2>&1; then break; fi
        i=$((i + 1))
        sleep 0.5
    done

    if "$BIN_DIR/raemote" status --json >/dev/null 2>&1; then
        status_json=$("$BIN_DIR/raemote" status --json 2>/dev/null || true)
        node_id=$(printf '%s' "$status_json" | sed -n 's/.*"node_id":"\([^"]*\)".*/\1/p')
        qr_json=$("$BIN_DIR/raemote" qr --json 2>/dev/null || true)
        uri=$(printf '%s' "$qr_json" | sed -n 's/.*"uri":"\([^"]*\)".*/\1/p')
    else
        warn "the daemon is not answering yet; check: '$BIN_DIR/raemote status'"
    fi
fi

if [ "$JSON" = 1 ]; then
    printf '{"installed":true,"version":"%s","bin_dir":"%s","service":%s,"node_id":"%s","uri":"%s"}\n' \
        "${VERSION:-unknown}" "$BIN_DIR" "$service_installed" "$node_id" "$uri"
else
    log ""
    log "raemote ${VERSION:-?} installed into $BIN_DIR"
    if [ "$DO_SERVICE" = 1 ]; then
        if [ -n "$uri" ]; then
            log ""
            log "Next: install the Raemote app on your phone, open it,"
            log "tap +, and scan this QR code:"
            log ""
            "$BIN_DIR/raemote" qr >&2 || true
            log ""
            log "Or paste this link into the app's Manual Setup:"
            log "  $uri"
        else
            log ""
            log "Next: show the pairing code with '$BIN_DIR/raemote qr'"
        fi
    else
        log "Start it with: $BIN_DIR/raemote start"
        log "Then show the pairing code with: $BIN_DIR/raemote qr"
    fi
fi

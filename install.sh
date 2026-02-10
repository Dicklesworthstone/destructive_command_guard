#!/usr/bin/env bash
#
# dcg installer
#
# One-liner install (with cache buster):
#   curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/master/install.sh?$(date +%s)" | bash
#
# Or without cache buster:
#   curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/master/install.sh | bash
#
# Options:
#   --version vX.Y.Z   Install specific version (default: latest)
#   --dest DIR         Install to DIR (default: ~/.local/bin)
#   --system           Install to /usr/local/bin (requires sudo)
#   --easy-mode        Auto-update PATH in shell rc files
#   --verify           Run self-test after install
#   --from-source      Build from source instead of downloading binary
#   --quiet            Suppress non-error output
#   --no-gum           Disable gum formatting even if available
#   --no-configure     Skip AI agent hook configuration
#   --no-verify        Skip checksum + signature verification (for testing only)
#   --offline          Skip network preflight checks
#
set -euo pipefail
umask 022
shopt -s lastpipe 2>/dev/null || true

VERSION="${VERSION:-}"
OWNER="${OWNER:-Dicklesworthstone}"
REPO="${REPO:-destructive_command_guard}"
DEST_DEFAULT="$HOME/.local/bin"
DEST="${DEST:-$DEST_DEFAULT}"
EASY=0
QUIET=0
VERIFY=0
FROM_SOURCE=0
CHECKSUM="${CHECKSUM:-}"
CHECKSUM_URL="${CHECKSUM_URL:-}"
SIGSTORE_BUNDLE_URL="${SIGSTORE_BUNDLE_URL:-}"
COSIGN_IDENTITY_RE="${COSIGN_IDENTITY_RE:-^https://github.com/${OWNER}/${REPO}/.github/workflows/dist.yml@refs/tags/.*$}"
COSIGN_OIDC_ISSUER="${COSIGN_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"
ARTIFACT_URL="${ARTIFACT_URL:-}"
LOCK_FILE="/tmp/dcg-install.lock"
SYSTEM=0
NO_GUM=0
NO_CONFIGURE=0
NO_CHECKSUM=0
FORCE_INSTALL=0
OFFLINE="${DCG_OFFLINE:-0}"
AGENT_VERSION_LOOKUP="${DCG_INSTALLER_AGENT_VERSIONS:-0}"
AGENT_VERSION_TIMEOUT="${DCG_INSTALLER_AGENT_VERSION_TIMEOUT:-1}"

# Detect gum for fancy output (https://github.com/charmbracelet/gum)
HAS_GUM=0
if command -v gum &> /dev/null && [ -t 1 ]; then
  HAS_GUM=1
fi

# Logging functions with optional gum formatting
log() { [ "$QUIET" -eq 1 ] && return 0; echo -e "$@"; }

info() {
  [ "$QUIET" -eq 1 ] && return 0
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style --foreground 39 "→ $*"
  else
    echo -e "\033[0;34m→\033[0m $*"
  fi
}

ok() {
  [ "$QUIET" -eq 1 ] && return 0
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style --foreground 42 "✓ $*"
  else
    echo -e "\033[0;32m✓\033[0m $*"
  fi
}

warn() {
  [ "$QUIET" -eq 1 ] && return 0
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style --foreground 214 "⚠ $*"
  else
    echo -e "\033[1;33m⚠\033[0m $*"
  fi
}

err() {
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style --foreground 196 "✗ $*"
  else
    echo -e "\033[0;31m✗\033[0m $*"
  fi
}

# Spinner wrapper for long operations
run_with_spinner() {
  local title="$1"
  shift
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ] && [ "$QUIET" -eq 0 ]; then
    gum spin --spinner dot --title "$title" -- "$@"
  else
    info "$title"
    "$@"
  fi
}

# Draw a box around text with automatic width calculation
# Usage: draw_box "color_code" "line1" "line2" ...
# color_code: ANSI color (e.g., "1;33" for yellow bold, "0;32" for green)
draw_box() {
  local color="$1"
  shift
  local lines=("$@")
  local max_width=0
  local esc
  esc=$(printf '\033')
  local strip_ansi_sed="s/${esc}\\[[0-9;]*m//g"

  # Calculate max width (strip ANSI codes for accurate measurement)
  for line in "${lines[@]}"; do
    local stripped
    stripped=$(printf '%b' "$line" | LC_ALL=C sed "$strip_ansi_sed")
    local len=${#stripped}
    if [ "$len" -gt "$max_width" ]; then
      max_width=$len
    fi
  done

  # Add padding
  local inner_width=$((max_width + 4))
  local border=""
  for ((i=0; i<inner_width; i++)); do
    border+="═"
  done

  # Draw top border
  printf "\033[%sm╔%s╗\033[0m\n" "$color" "$border"

  # Draw each line with padding
  for line in "${lines[@]}"; do
    local stripped
    stripped=$(printf '%b' "$line" | LC_ALL=C sed "$strip_ansi_sed")
    local len=${#stripped}
    local padding=$((max_width - len))
    local pad_str=""
    for ((i=0; i<padding; i++)); do
      pad_str+=" "
    done
    printf "\033[%sm║\033[0m  %b%s  \033[%sm║\033[0m\n" "$color" "$line" "$pad_str" "$color"
  done

  # Draw bottom border
  printf "\033[%sm╚%s╝\033[0m\n" "$color" "$border"
}

# ═══════════════════════════════════════════════════════════════════════════════
# AI Agent Detection
# ═══════════════════════════════════════════════════════════════════════════════

# Arrays to track detected agents
DETECTED_AGENTS=()
CLAUDE_VERSION=""
CODEX_VERSION=""
GEMINI_VERSION=""
AIDER_VERSION=""
CONTINUE_VERSION=""
CURSOR_VERSION=""

print_agent_scan_notice() {
  [ "$QUIET" -eq 1 ] && return 0

  local line1="Scanning for installed coding agents..."
  local line2="This can take several minutes depending on your machine."
  local line3="The installer is still running - thanks for your patience."

  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    echo ""
    gum style \
      --border normal \
      --border-foreground 244 \
      --padding "0 1" \
      "$(gum style --foreground 212 --bold 'Agent scan')" \
      "$(gum style --foreground 247 "$line1")" \
      "$(gum style --foreground 245 "$line2")" \
      "$(gum style --foreground 245 "$line3")"
    echo ""
  else
    echo ""
    draw_box "0;36" "$line1" "$line2" "$line3"
    echo ""
  fi
}

try_version() {
  local cmd="$1"
  [[ "$AGENT_VERSION_LOOKUP" == "1" ]] || return 0
  command -v "$cmd" >/dev/null 2>&1 || return 0

  local timeout_secs="${AGENT_VERSION_TIMEOUT:-1}"
  if ! [[ "$timeout_secs" =~ ^[0-9]+$ ]]; then
    timeout_secs=1
  fi

  if command -v timeout >/dev/null 2>&1; then
    timeout "$timeout_secs" "$cmd" --version 2>/dev/null | head -1 || true
  elif command -v gtimeout >/dev/null 2>&1; then
    gtimeout "$timeout_secs" "$cmd" --version 2>/dev/null | head -1 || true
  else
    "$cmd" --version 2>/dev/null | head -1 || true
  fi
}

detect_agents() {
  DETECTED_AGENTS=()

  # Claude Code
  if [[ -d "$HOME/.claude" ]] || command -v claude &>/dev/null; then
    DETECTED_AGENTS+=("claude-code")
    CLAUDE_VERSION=$(try_version claude)
  fi

  # Codex CLI
  if [[ -d "$HOME/.codex" ]] || command -v codex &>/dev/null; then
    DETECTED_AGENTS+=("codex-cli")
    CODEX_VERSION=$(try_version codex)
  fi

  # Gemini CLI (check both ~/.gemini and ~/.gemini-cli for compatibility)
  if [[ -d "$HOME/.gemini" ]] || [[ -d "$HOME/.gemini-cli" ]] || command -v gemini &>/dev/null; then
    DETECTED_AGENTS+=("gemini-cli")
    GEMINI_VERSION=$(try_version gemini)
  fi

  # Aider
  if command -v aider &>/dev/null; then
    DETECTED_AGENTS+=("aider")
    AIDER_VERSION=$(try_version aider)
  fi

  # Continue
  if [[ -d "$HOME/.continue" ]]; then
    DETECTED_AGENTS+=("continue")
    # Continue doesn't have a standard CLI version command
    if [[ -f "$HOME/.continue/config.json" ]]; then
      CONTINUE_VERSION="config present"
    fi
  fi

  # Cursor IDE
  local cursor_detected=0
  local cursor_settings_mac="$HOME/Library/Application Support/Cursor/User/settings.json"
  local cursor_settings_linux="$HOME/.config/Cursor/User/settings.json"
  if [[ -d "$HOME/.cursor" ]] || [[ -f "$cursor_settings_mac" ]] || [[ -f "$cursor_settings_linux" ]] || command -v cursor &>/dev/null; then
    cursor_detected=1
  elif command -v pgrep >/dev/null 2>&1; then
    if pgrep -f "[Cc]ursor" >/dev/null 2>&1; then
      cursor_detected=1
    fi
  fi

  if [ "$cursor_detected" -eq 1 ]; then
    DETECTED_AGENTS+=("cursor-ide")
    CURSOR_VERSION=$(try_version cursor)
  fi
}

print_detected_agents() {
  if [[ ${#DETECTED_AGENTS[@]} -eq 0 ]]; then
    info "No AI coding agents detected"
    return
  fi

  local count=${#DETECTED_AGENTS[@]}
  local plural=""
  [[ $count -gt 1 ]] && plural="s"

  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    echo ""
    gum style --foreground 39 --bold "Detected AI Coding Agent${plural}:"
    for agent in "${DETECTED_AGENTS[@]}"; do
      case "$agent" in
        claude-code)
          local ver_info=""
          [[ -n "$CLAUDE_VERSION" ]] && ver_info=" (${CLAUDE_VERSION})"
          gum style --foreground 42 "  ✓ Claude Code${ver_info}"
          ;;
        codex-cli)
          local ver_info=""
          [[ -n "$CODEX_VERSION" ]] && ver_info=" (${CODEX_VERSION})"
          gum style --foreground 42 "  ✓ Codex CLI${ver_info}"
          ;;
        gemini-cli)
          local ver_info=""
          [[ -n "$GEMINI_VERSION" ]] && ver_info=" (${GEMINI_VERSION})"
          gum style --foreground 42 "  ✓ Gemini CLI${ver_info}"
          ;;
        aider)
          local ver_info=""
          [[ -n "$AIDER_VERSION" ]] && ver_info=" (${AIDER_VERSION})"
          gum style --foreground 42 "  ✓ Aider${ver_info}"
          ;;
        continue)
          local ver_info=""
          [[ -n "$CONTINUE_VERSION" ]] && ver_info=" (${CONTINUE_VERSION})"
          gum style --foreground 42 "  ✓ Continue${ver_info}"
          ;;
        cursor-ide)
          local ver_info=""
          [[ -n "$CURSOR_VERSION" ]] && ver_info=" (${CURSOR_VERSION})"
          gum style --foreground 42 "  ✓ Cursor IDE${ver_info}"
          ;;
      esac
    done
    echo ""
  else
    echo ""
    echo -e "\033[1;39mDetected AI Coding Agent${plural}:\033[0m"
    for agent in "${DETECTED_AGENTS[@]}"; do
      case "$agent" in
        claude-code)
          local ver_info=""
          [[ -n "$CLAUDE_VERSION" ]] && ver_info=" (${CLAUDE_VERSION})"
          echo -e "  \033[0;32m✓\033[0m Claude Code${ver_info}"
          ;;
        codex-cli)
          local ver_info=""
          [[ -n "$CODEX_VERSION" ]] && ver_info=" (${CODEX_VERSION})"
          echo -e "  \033[0;32m✓\033[0m Codex CLI${ver_info}"
          ;;
        gemini-cli)
          local ver_info=""
          [[ -n "$GEMINI_VERSION" ]] && ver_info=" (${GEMINI_VERSION})"
          echo -e "  \033[0;32m✓\033[0m Gemini CLI${ver_info}"
          ;;
        aider)
          local ver_info=""
          [[ -n "$AIDER_VERSION" ]] && ver_info=" (${AIDER_VERSION})"
          echo -e "  \033[0;32m✓\033[0m Aider${ver_info}"
          ;;
        continue)
          local ver_info=""
          [[ -n "$CONTINUE_VERSION" ]] && ver_info=" (${CONTINUE_VERSION})"
          echo -e "  \033[0;32m✓\033[0m Continue${ver_info}"
          ;;
        cursor-ide)
          local ver_info=""
          [[ -n "$CURSOR_VERSION" ]] && ver_info=" (${CURSOR_VERSION})"
          echo -e "  \033[0;32m✓\033[0m Cursor IDE${ver_info}"
          ;;
      esac
    done
    echo ""
  fi
}

# Check if a specific agent was detected
is_agent_detected() {
  local target="$1"
  for agent in "${DETECTED_AGENTS[@]}"; do
    [[ "$agent" == "$target" ]] && return 0
  done
  return 1
}

# Check if installed version matches target
# Returns 0 if versions match, 1 if they differ or dcg not installed
check_installed_version() {
  local target_version="$1"
  if [ ! -x "$DEST/dcg" ]; then
    return 1
  fi

  local installed_version
  installed_version=$("$DEST/dcg" --version 2>/dev/null | head -1 | sed 's/.*\([0-9]\+\.[0-9]\+\.[0-9]\+\).*/\1/')

  if [ -z "$installed_version" ]; then
    return 1
  fi

  # Normalize versions (strip 'v' prefix)
  local target_clean="${target_version#v}"
  local installed_clean="${installed_version#v}"

  if [ "$target_clean" = "$installed_clean" ]; then
    return 0
  fi

  return 1
}

resolve_version() {
  if [ -n "$VERSION" ]; then return 0; fi

  info "Resolving latest version..."
  local latest_url="https://api.github.com/repos/${OWNER}/${REPO}/releases/latest"
  local tag
  if ! tag=$(curl -fsSL -H "Accept: application/vnd.github.v3+json" "$latest_url" 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'); then
    tag=""
  fi

  if [ -n "$tag" ]; then
    VERSION="$tag"
    info "Resolved latest version: $VERSION"
  else
    # Try redirect-based resolution as fallback
    local redirect_url="https://github.com/${OWNER}/${REPO}/releases/latest"
    if tag=$(curl -fsSL -o /dev/null -w '%{url_effective}' "$redirect_url" 2>/dev/null | sed -E 's|.*/tag/||'); then
      # Validate: tag must be non-empty, start with 'v' + digit, and not contain URL chars
      if [ -n "$tag" ] && [[ "$tag" =~ ^v[0-9] ]] && [[ "$tag" != *"/"* ]]; then
        VERSION="$tag"
        info "Resolved latest version via redirect: $VERSION"
        return 0
      fi
    fi
    VERSION="v0.1.0"
    warn "Could not resolve latest version; defaulting to $VERSION"
  fi
}

detect_platform() {
  OS=$(uname -s | tr 'A-Z' 'a-z')
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64|amd64) ARCH="x86_64" ;;
    arm64|aarch64) ARCH="aarch64" ;;
    *) warn "Unknown arch $ARCH, using as-is" ;;
  esac

  TARGET=""
  case "${OS}-${ARCH}" in
    linux-x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
    linux-aarch64) TARGET="aarch64-unknown-linux-gnu" ;;
    darwin-x86_64) TARGET="x86_64-apple-darwin" ;;
    darwin-aarch64) TARGET="aarch64-apple-darwin" ;;
    *) :;;
  esac

  if [ -z "$TARGET" ] && [ "$FROM_SOURCE" -eq 0 ] && [ -z "$ARTIFACT_URL" ]; then
    warn "No prebuilt artifact for ${OS}/${ARCH}; falling back to build-from-source"
    FROM_SOURCE=1
  fi
}

set_artifact_url() {
  TAR=""
  URL=""
  if [ "$FROM_SOURCE" -eq 0 ]; then
    if [ -n "$ARTIFACT_URL" ]; then
      TAR=$(basename "$ARTIFACT_URL")
      URL="$ARTIFACT_URL"
    elif [ -n "$TARGET" ]; then
      TAR="dcg-${TARGET}.tar.xz"
      URL="https://github.com/${OWNER}/${REPO}/releases/download/${VERSION}/${TAR}"
    else
      warn "No prebuilt artifact for ${OS}/${ARCH}; falling back to build-from-source"
      FROM_SOURCE=1
    fi
  fi
}

check_disk_space() {
  local min_kb=10240
  local path="$DEST"
  if [ ! -d "$path" ]; then
    path=$(dirname "$path")
  fi
  if command -v df >/dev/null 2>&1; then
    local avail_kb
    avail_kb=$(df -Pk "$path" | awk 'NR==2 {print $4}')
    if [ -n "$avail_kb" ] && [ "$avail_kb" -lt "$min_kb" ]; then
      err "Insufficient disk space in $path (need at least 10MB)"
      exit 1
    fi
  else
    warn "df not found; skipping disk space check"
  fi
}

check_write_permissions() {
  if [ ! -d "$DEST" ]; then
    if ! mkdir -p "$DEST" 2>/dev/null; then
      err "Cannot create $DEST (insufficient permissions)"
      err "Try running with sudo or choose a writable --dest"
      exit 1
    fi
  fi
  if [ ! -w "$DEST" ]; then
    err "No write permission to $DEST"
    err "Try running with sudo or choose a writable --dest"
    exit 1
  fi
}

check_existing_install() {
  if [ -x "$DEST/dcg" ]; then
    local current
    current=$("$DEST/dcg" --version 2>/dev/null | head -1 || echo "")
    if [ -n "$current" ]; then
      info "Existing dcg detected: $current"
    fi
  fi
}

check_network() {
  if [ "$OFFLINE" -eq 1 ]; then
    info "Offline mode enabled; skipping network preflight"
    return 0
  fi
  if [ "$FROM_SOURCE" -eq 1 ]; then
    return 0
  fi
  if [ -z "$URL" ]; then
    return 0
  fi
  if ! command -v curl >/dev/null 2>&1; then
    warn "curl not found; skipping network check"
    return 0
  fi
  if ! curl -fsSL --connect-timeout 3 --max-time 5 -o /dev/null "$URL"; then
    warn "Network check failed for $URL"
    warn "Continuing; download may fail"
  fi
}

preflight_checks() {
  info "Running preflight checks"
  check_disk_space
  check_write_permissions
  check_existing_install
  check_network
}

maybe_add_path() {
  case ":$PATH:" in
    *:"$DEST":*) return 0;;
    *)
      if [ "$EASY" -eq 1 ]; then
        UPDATED=0
        for rc in "$HOME/.zshrc" "$HOME/.bashrc"; do
          if [ -e "$rc" ] && [ -w "$rc" ]; then
            if ! grep -F "$DEST" "$rc" >/dev/null 2>&1; then
              echo "export PATH=\"$DEST:\$PATH\"" >> "$rc"
            fi
            UPDATED=1
          fi
        done
        if [ "$UPDATED" -eq 1 ]; then
          warn "PATH updated in ~/.zshrc/.bashrc; restart shell to use dcg"
        else
          warn "Add $DEST to PATH to use dcg"
        fi
      else
        warn "Add $DEST to PATH to use dcg"
      fi
    ;;
  esac
}

detect_default_shell() {
  local shell="${SHELL:-}"
  [ -z "$shell" ] && return 1
  shell=$(basename "$shell")
  case "$shell" in
    bash|zsh|fish) echo "$shell"; return 0 ;;
    *) return 1 ;;
  esac
}

install_completions_for_shell() {
  local shell="$1"
  local bin="$DEST/dcg"
  if [ ! -x "$bin" ]; then
    warn "dcg binary not found at $bin; skipping completions"
    return 1
  fi

  # Check if the completions subcommand exists (added in v0.2.11+)
  if ! "$bin" completions --help >/dev/null 2>&1; then
    info "Shell completions: skipped (not supported in this version)"
    return 0
  fi

  local target=""
  case "$shell" in
    bash)
      target="${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions/dcg"
      ;;
    zsh)
      target="${XDG_DATA_HOME:-$HOME/.local/share}/zsh/site-functions/_dcg"
      ;;
    fish)
      target="${XDG_CONFIG_HOME:-$HOME/.config}/fish/completions/dcg.fish"
      ;;
    *)
      return 1
      ;;
  esac

  # Ensure target directory exists
  if ! mkdir -p "$(dirname "$target")" 2>/dev/null; then
    warn "Failed to create completions directory for $shell"
    return 1
  fi

  # Generate and install completions
  local error_output
  if error_output=$("$bin" completions "$shell" 2>&1) && [ -n "$error_output" ]; then
    printf '%s\n' "$error_output" > "$target"
    ok "Installed $shell completions to $target"
    return 0
  fi

  warn "Failed to install $shell completions"
  return 1
}

maybe_install_completions() {
  local shell=""
  if ! shell=$(detect_default_shell); then
    info "Shell completions: skipped (unknown shell)"
    return 0
  fi

  install_completions_for_shell "$shell" || true
}

ensure_rust() {
  if [ "${RUSTUP_INIT_SKIP:-0}" != "0" ]; then
    info "Skipping rustup install (RUSTUP_INIT_SKIP set)"
    return 0
  fi
  if command -v cargo >/dev/null 2>&1 && rustc --version 2>/dev/null | grep -q nightly; then return 0; fi
  if [ "$EASY" -ne 1 ]; then
    if [ -t 0 ]; then
      echo -n "Install Rust nightly via rustup? (y/N): "
      read -r ans
      case "$ans" in y|Y) :;; *) warn "Skipping rustup install"; return 0;; esac
    fi
  fi
  info "Installing rustup (nightly)"
  curl -fsSL https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly --profile minimal
  export PATH="$HOME/.cargo/bin:$PATH"
  rustup component add rustfmt clippy || true
}

# Verify SHA256 checksum of a file
# Usage: verify_checksum <file> <expected_checksum>
# Returns 0 on success, 1 on failure
verify_checksum() {
  local file="$1"
  local expected="$2"
  local actual=""

  if [ ! -f "$file" ]; then
    err "File not found: $file"
    return 1
  fi

  # Try sha256sum first (Linux), then shasum (macOS)
  if command -v sha256sum &>/dev/null; then
    actual=$(sha256sum "$file" | cut -d' ' -f1)
  elif command -v shasum &>/dev/null; then
    # macOS fallback
    actual=$(shasum -a 256 "$file" | cut -d' ' -f1)
  else
    warn "No SHA256 tool found (sha256sum or shasum), skipping verification"
    return 0
  fi

  if [ "$actual" != "$expected" ]; then
    err "Checksum verification FAILED!"
    err "Expected: $expected"
    err "Got:      $actual"
    err "The downloaded file may be corrupted or tampered with."
    # Clean up the corrupted file
    rm -f "$file"
    return 1
  fi

  ok "Checksum verified: ${actual:0:16}..."
  return 0
}

# Verify Sigstore/cosign bundle for a file (best-effort).
# Usage: verify_sigstore_bundle <file> <artifact_url>
# Returns 0 on success or when verification is skipped, 1 on verification failure.
verify_sigstore_bundle() {
  local file="$1"
  local artifact_url="$2"

  if ! command -v cosign &>/dev/null; then
    warn "cosign not found; skipping signature verification (install cosign for stronger authenticity checks)"
    return 0
  fi

  local bundle_url="$SIGSTORE_BUNDLE_URL"
  if [ -z "$bundle_url" ]; then
    bundle_url="${artifact_url}.sigstore.json"
  fi

  local bundle_file="$TMP/$(basename "$bundle_url")"
  info "Fetching sigstore bundle from ${bundle_url}"
  if ! curl -fsSL "$bundle_url" -o "$bundle_file"; then
    warn "Sigstore bundle not found; skipping signature verification"
    return 0
  fi

  if ! cosign verify-blob \
    --bundle "$bundle_file" \
    --certificate-identity-regexp "$COSIGN_IDENTITY_RE" \
    --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
    "$file"; then
    return 1
  fi

  ok "Signature verified (cosign)"
  return 0
}

usage() {
  cat <<EOFU
Usage: install.sh [--version vX.Y.Z] [--dest DIR] [--system] [--easy-mode] [--verify] \\
                  [--artifact-url URL] [--checksum HEX] [--checksum-url URL] [--quiet] \\
                  [--offline] [--no-gum] [--no-configure] [--no-verify] [--force]

Options:
  --version vX.Y.Z   Install specific version (default: latest)
  --dest DIR         Install to DIR (default: ~/.local/bin)
  --system           Install to /usr/local/bin (requires sudo)
  --easy-mode        Auto-update PATH in shell rc files
  --verify           Run self-test after install
  --from-source      Build from source instead of downloading binary
  --quiet            Suppress non-error output
  --offline          Skip network preflight checks
  --no-gum           Disable gum formatting even if available
  --no-configure     Skip AI agent hook configuration
  --no-verify        Skip checksum + signature verification (for testing only)
  --force            Force reinstall even if same version is installed
EOFU
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2;;
    --dest) DEST="$2"; shift 2;;
    --system) SYSTEM=1; DEST="/usr/local/bin"; shift;;
    --easy-mode) EASY=1; shift;;
    --verify) VERIFY=1; shift;;
    --artifact-url) ARTIFACT_URL="$2"; shift 2;;
    --checksum) CHECKSUM="$2"; shift 2;;
    --checksum-url) CHECKSUM_URL="$2"; shift 2;;
    --from-source) FROM_SOURCE=1; shift;;
    --quiet|-q) QUIET=1; shift;;
    --offline) OFFLINE=1; shift;;
    --no-gum) NO_GUM=1; shift;;
    --no-configure) NO_CONFIGURE=1; shift;;
    --no-verify) NO_CHECKSUM=1; shift;;
    --force) FORCE_INSTALL=1; shift;;
    -h|--help) usage; exit 0;;
    *) shift;;
  esac
done

# Show fancy header
if [ "$QUIET" -eq 0 ]; then
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style \
      --border normal \
      --border-foreground 39 \
      --padding "0 1" \
      --margin "1 0" \
      "$(gum style --foreground 42 --bold 'dcg installer')" \
      "$(gum style --foreground 245 'Blocks destructive commands')"
  else
    echo ""
    echo -e "\033[1;32mdcg installer\033[0m"
    echo -e "\033[0;90mBlocks destructive commands\033[0m"
    echo ""
  fi
fi

# Detect installed AI coding agents early (for informational display and smart configuration)
print_agent_scan_notice
detect_agents
if [ "$QUIET" -eq 0 ]; then
  print_detected_agents
fi

resolve_version
detect_platform
set_artifact_url
preflight_checks

# Check if already at target version (skip download if so, unless --force)
if [ "$FORCE_INSTALL" -eq 0 ] && check_installed_version "$VERSION"; then
  ok "dcg $VERSION is already installed at $DEST/dcg"
  info "Use --force to reinstall"

  if [ "$NO_CONFIGURE" -eq 0 ]; then
    # Still run agent configuration (idempotent) to ensure hooks are set up
    detect_predecessor
    if [ "$PREDECESSOR_FOUND" -eq 1 ]; then
      show_upgrade_banner
    fi

    # Configure agents (these are already idempotent)
    configure_claude_code "$CLAUDE_SETTINGS" "0"
    configure_gemini "$GEMINI_SETTINGS"
  else
    info "Skipping agent configuration (--no-configure)"
  fi

  # Show final summary even when skipping download
  echo ""
  case "$CLAUDE_STATUS" in
    already) ok "Claude Code: Already configured" ;;
    merged|created) ok "Claude Code: Configured" ;;
    clobbered) warn "Claude Code: Hook overwritten by running Claude process (re-run after closing Claude)" ;;
    *) : ;;
  esac
  case "$GEMINI_STATUS" in
    already) ok "Gemini CLI: Already configured" ;;
    merged|created) ok "Gemini CLI: Configured" ;;
    skipped|"") info "Gemini CLI: Not installed (skipped)" ;;
    *) : ;;
  esac

  maybe_install_completions

  exit 0
fi

# Cross-platform locking using mkdir (atomic on all POSIX systems including macOS)
LOCK_DIR="${LOCK_FILE}.d"
LOCKED=0
if mkdir "$LOCK_DIR" 2>/dev/null; then
  LOCKED=1
  echo $$ > "$LOCK_DIR/pid"
else
  # Check if existing lock is stale (process no longer running)
  if [ -f "$LOCK_DIR/pid" ]; then
    OLD_PID=$(cat "$LOCK_DIR/pid" 2>/dev/null || echo "")
    if [ -n "$OLD_PID" ] && ! kill -0 "$OLD_PID" 2>/dev/null; then
      rm -rf "$LOCK_DIR"
      if mkdir "$LOCK_DIR" 2>/dev/null; then
        LOCKED=1
        echo $$ > "$LOCK_DIR/pid"
      fi
    fi
  fi
  if [ "$LOCKED" -eq 0 ]; then
    err "Another installer is running (lock $LOCK_DIR)"
    exit 1
  fi
fi

cleanup() {
  rm -rf "$TMP"
  if [ "$LOCKED" -eq 1 ]; then rm -rf "$LOCK_DIR"; fi
}

TMP=$(mktemp -d)
trap cleanup EXIT

if [ "$FROM_SOURCE" -eq 0 ]; then
  info "Downloading $URL"
  if ! curl -fsSL "$URL" -o "$TMP/$TAR"; then
    warn "Artifact download failed; falling back to build-from-source"
    FROM_SOURCE=1
  fi
fi

if [ "$FROM_SOURCE" -eq 1 ]; then
  info "Building from source (requires git, rust nightly)"
  ensure_rust
  git clone --depth 1 "https://github.com/${OWNER}/${REPO}.git" "$TMP/src"
  (cd "$TMP/src" && cargo build --release)
  BIN="$TMP/src/target/release/dcg"
  [ -x "$BIN" ] || { err "Build failed"; exit 1; }
  install -m 0755 "$BIN" "$DEST/dcg"
  ok "Installed to $DEST/dcg (source build)"
  maybe_add_path
  if [ "$VERIFY" -eq 1 ]; then
    echo '{"tool_name":"Bash","tool_input":{"command":"git status"}}' | "$DEST/dcg" || true
    ok "Self-test complete"
  fi
  ok "Done. Binary at: $DEST/dcg"
  maybe_install_completions
  exit 0
fi

# Checksum verification (can be skipped with --no-verify for testing)
if [ "$NO_CHECKSUM" -eq 1 ]; then
  warn "Verification skipped (--no-verify)"
else
  if [ -z "$CHECKSUM" ]; then
    [ -z "$CHECKSUM_URL" ] && CHECKSUM_URL="${URL}.sha256"
    info "Fetching checksum from ${CHECKSUM_URL}"
    CHECKSUM_FILE="$TMP/checksum.sha256"
    if ! curl -fsSL "$CHECKSUM_URL" -o "$CHECKSUM_FILE"; then
      err "Checksum required and could not be fetched"
      err "Use --no-verify to skip checksum verification (not recommended)"
      exit 1
    fi
    CHECKSUM=$(awk '{print $1}' "$CHECKSUM_FILE")
    if [ -z "$CHECKSUM" ]; then
      err "Empty checksum file"
      exit 1
    fi
  fi

  if ! verify_checksum "$TMP/$TAR" "$CHECKSUM"; then
    err "Installation aborted due to checksum failure"
    exit 1
  fi

  if ! verify_sigstore_bundle "$TMP/$TAR" "$URL"; then
    err "Signature verification failed"
    err "The downloaded file may be corrupted or tampered with."
    exit 1
  fi
fi

info "Extracting"
tar -xf "$TMP/$TAR" -C "$TMP"
BIN="$TMP/dcg"
if [ ! -x "$BIN" ] && [ -n "$TARGET" ]; then
  BIN="$TMP/dcg-${TARGET}/dcg"
fi
if [ ! -x "$BIN" ]; then
  BIN=$(find "$TMP" -maxdepth 3 -type f -name "dcg" -perm -111 | head -n 1)
fi

[ -x "$BIN" ] || { err "Binary not found in tar"; exit 1; }
install -m 0755 "$BIN" "$DEST/dcg"
ok "Installed to $DEST/dcg"
maybe_add_path

if [ "$VERIFY" -eq 1 ]; then
  echo '{"tool_name":"Bash","tool_input":{"command":"git status"}}' | "$DEST/dcg" || true
  ok "Self-test complete"
fi

ok "Done. Binary at: $DEST/dcg"
maybe_install_completions
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# Predecessor Detection & Removal
# ═══════════════════════════════════════════════════════════════════════════════

PREDECESSOR_SCRIPT="git_safety_guard.py"
PREDECESSOR_FOUND=0
PREDECESSOR_LOCATIONS=()

detect_predecessor() {
  # Check common file locations for the predecessor script
  local locations=(
    "$HOME/.claude/hooks/$PREDECESSOR_SCRIPT"
    ".claude/hooks/$PREDECESSOR_SCRIPT"
  )

  for loc in "${locations[@]}"; do
    if [ -f "$loc" ]; then
      PREDECESSOR_FOUND=1
      PREDECESSOR_LOCATIONS+=("$loc")
    fi
  done

  # Also check if settings.json references the predecessor (even if file missing)
  if [ -f "$CLAUDE_SETTINGS" ] && grep -q 'git_safety_guard' "$CLAUDE_SETTINGS" 2>/dev/null; then
    PREDECESSOR_FOUND=1
  fi
}

show_upgrade_banner() {
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    echo ""
    gum style \
      --border double \
      --border-foreground 214 \
      --padding "1 2" \
      --margin "0 0 1 0" \
      "$(gum style --foreground 214 --bold 'UPGRADE DETECTED')" \
      "" \
      "$(gum style --foreground 252 "Found predecessor: $PREDECESSOR_SCRIPT")" \
      "$(gum style --foreground 245 'dcg is the modern, high-performance replacement')" \
      "" \
      "$(gum style --foreground 42 '+ 300+ detection patterns (vs ~10 in predecessor)')" \
      "$(gum style --foreground 42 '+ Sub-millisecond evaluation (vs Python startup)')" \
      "$(gum style --foreground 42 '+ Heredoc & multi-line command detection')" \
      "$(gum style --foreground 42 '+ Modular pack system with severity levels')" \
      "$(gum style --foreground 42 '+ Allow-once escape hatch for false positives')"
  else
    echo ""
    draw_box "1;33" \
      "\033[1;33mUPGRADE DETECTED\033[0m" \
      "" \
      "Found predecessor: \033[0;36m$PREDECESSOR_SCRIPT\033[0m" \
      "dcg is the modern, high-performance replacement" \
      "" \
      "\033[0;32m+\033[0m 300+ detection patterns (vs ~10 in predecessor)" \
      "\033[0;32m+\033[0m Sub-millisecond evaluation (vs Python startup)" \
      "\033[0;32m+\033[0m Heredoc & multi-line command detection" \
      "\033[0;32m+\033[0m Modular pack system with severity levels" \
      "\033[0;32m+\033[0m Allow-once escape hatch for false positives"
    echo ""
  fi
}

remove_predecessor() {
  local loc="$1"
  local dir=$(dirname "$loc")

  info "Removing predecessor hook: $loc"

  # Create backup
  local backup="${loc}.bak.$(date +%Y%m%d%H%M%S)"
  cp "$loc" "$backup" 2>/dev/null || true

  # Remove the script
  rm -f "$loc"

  # Remove hooks directory if empty
  if [ -d "$dir" ] && [ -z "$(ls -A "$dir" 2>/dev/null)" ]; then
    rmdir "$dir" 2>/dev/null || true
  fi

  ok "Removed: $loc (backup: $backup)"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Claude Code / Gemini CLI / Cursor Auto-Configuration
# ═══════════════════════════════════════════════════════════════════════════════

CLAUDE_SETTINGS="$HOME/.claude/settings.json"
GEMINI_SETTINGS="$HOME/.gemini/settings.json"
AIDER_SETTINGS="$HOME/.aider.conf.yml"
CURSOR_SETTINGS_MAC="$HOME/Library/Application Support/Cursor/User/settings.json"
CURSOR_SETTINGS_LINUX="$HOME/.config/Cursor/User/settings.json"
CURSOR_HOOKS_JSON="$HOME/.cursor/hooks.json"
CURSOR_HOOK_DIR="$HOME/.cursor/hooks"
CURSOR_HOOK_SCRIPT="$CURSOR_HOOK_DIR/dcg-pre-shell.py"
AUTO_CONFIGURED=0

# Detailed tracking for what was configured
CLAUDE_STATUS=""  # "created"|"merged"|"already"|"failed"|"clobbered"
GEMINI_STATUS=""  # "created"|"merged"|"already"|"failed"|"skipped"
AIDER_STATUS=""   # "created"|"merged"|"already"|"skipped"|"failed"
CONTINUE_STATUS="" # "unsupported"|"skipped"
CODEX_STATUS=""   # "unsupported"|"skipped"
CURSOR_STATUS=""  # "created"|"merged"|"already"|"skipped"|"failed"|"conflict"
CLAUDE_BACKUP=""
GEMINI_BACKUP=""
AIDER_BACKUP=""
CURSOR_BACKUP=""

configure_claude_code() {
  local settings_file="$1"
  local cleanup_predecessor="$2"
  # Default to cleaning up predecessor if not specified or empty
  [ -z "$cleanup_predecessor" ] && cleanup_predecessor=1
  local settings_dir=$(dirname "$settings_file")
  local claude_running=0
  if command -v pgrep >/dev/null 2>&1; then
    if pgrep -f '[Cc]laude' >/dev/null 2>&1; then
      claude_running=1
    fi
  fi

  # Always create the config directory if it doesn't exist
  if [ ! -d "$settings_dir" ]; then
    mkdir -p "$settings_dir"
  fi

  if [ -f "$settings_file" ]; then
    # Check if dcg is already configured
    if grep -q '"command".*dcg' "$settings_file" 2>/dev/null; then
      # Also check if predecessor is still present (needs cleanup)
      if grep -q 'git_safety_guard' "$settings_file" 2>/dev/null; then
        : # Fall through to cleanup logic below
      else
        CLAUDE_STATUS="already"
        AUTO_CONFIGURED=1
        return 0
      fi
    fi

    # Settings file exists, need to merge
    CLAUDE_BACKUP="${settings_file}.bak.$(date +%Y%m%d%H%M%S)"
    cp "$settings_file" "$CLAUDE_BACKUP"

    if command -v python3 >/dev/null 2>&1; then
      python3 - "$settings_file" "$DEST/dcg" "$cleanup_predecessor" <<'PYEOF'
import json
import sys

settings_file = sys.argv[1]
dcg_path = sys.argv[2]
cleanup_predecessor = sys.argv[3] == "1" if len(sys.argv) > 3 else True

try:
    with open(settings_file, 'r') as f:
        settings = json.load(f)
except (IOError, ValueError, json.JSONDecodeError):
    settings = {}

# Ensure hooks structure exists
if 'hooks' not in settings:
    settings['hooks'] = {}
if 'PreToolUse' not in settings['hooks']:
    settings['hooks']['PreToolUse'] = []

# First pass: process Bash matchers, optionally removing predecessor hooks
# and consolidate all Bash matchers into one
bash_hooks = []
new_pre_tool_use = []
predecessor_removed = False

for entry in settings['hooks']['PreToolUse']:
    if entry.get('matcher') == 'Bash':
        # Collect hooks from this Bash matcher
        if 'hooks' in entry:
            for hook in entry['hooks']:
                if isinstance(hook, dict) and 'command' in hook:
                    cmd = hook.get('command', '')
                    if 'git_safety_guard' in cmd:
                        if cleanup_predecessor:
                            predecessor_removed = True
                            continue  # Skip predecessor
                        else:
                            bash_hooks.append(hook)  # Keep predecessor
                    elif 'dcg' not in cmd:  # Don't duplicate dcg
                        bash_hooks.append(hook)
                    elif 'dcg' in cmd:
                        # Keep existing dcg hook but ensure path is updated
                        bash_hooks.append({"type": "command", "command": dcg_path})
                else:
                    bash_hooks.append(hook)
    else:
        new_pre_tool_use.append(entry)

# Add dcg hook at the beginning if not already present
dcg_hook = {"type": "command", "command": dcg_path}
dcg_exists = any('dcg' in h.get('command', '') for h in bash_hooks if isinstance(h, dict))
if not dcg_exists:
    bash_hooks.insert(0, dcg_hook)

# Create consolidated Bash matcher with dcg first
if bash_hooks:
    new_pre_tool_use.insert(0, {
        "matcher": "Bash",
        "hooks": bash_hooks
    })

settings['hooks']['PreToolUse'] = new_pre_tool_use

with open(settings_file, 'w') as f:
    json.dump(settings, f, indent=2)

if predecessor_removed:
    print("PREDECESSOR_CLEANED", file=sys.stderr)
PYEOF
      if [ $? -eq 0 ]; then
        # Verify the hook actually persisted (a running Claude process can overwrite)
        sleep 0.2
        if grep -q '"command".*dcg' "$settings_file" 2>/dev/null; then
          CLAUDE_STATUS="merged"
          AUTO_CONFIGURED=1
        else
          CLAUDE_STATUS="clobbered"
          AUTO_CONFIGURED=1
        fi
        if [ "$claude_running" -eq 1 ]; then
          warn "A running Claude process was detected."
          warn "It may overwrite $settings_file and remove the dcg hook."
          if [ "$CLAUDE_STATUS" = "clobbered" ]; then
            warn "Verification confirms the hook was already overwritten."
          else
            warn "The hook is present now, but may be lost when Claude saves settings."
          fi
          warn ""
          warn "If the hook is lost, add the following to $settings_file manually"
          warn "(inside \"hooks\" > \"PreToolUse\"):"
          warn ""
          warn '  {'
          warn '    "matcher": "Bash",'
          warn '    "hooks": [{ "type": "command", "command": "'"$DEST/dcg"'" }]'
          warn '  }'
          warn ""
          warn "Or re-run this installer after closing all Claude processes."
        fi
      else
        mv "$CLAUDE_BACKUP" "$settings_file" 2>/dev/null || true
        CLAUDE_STATUS="failed"
        CLAUDE_BACKUP=""
      fi
    else
      # python3 not available - remove unnecessary backup
      rm -f "$CLAUDE_BACKUP" 2>/dev/null || true
      CLAUDE_BACKUP=""
      CLAUDE_STATUS="failed"
      return 1
    fi
  else
    # Create new settings file
    cat > "$settings_file" <<EOFSET
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "$DEST/dcg"
          }
        ]
      }
    ]
  }
}
EOFSET
    CLAUDE_STATUS="created"
    AUTO_CONFIGURED=1
    if [ "$claude_running" -eq 1 ]; then
      warn "A running Claude process was detected."
      warn "It may overwrite $settings_file and remove the dcg hook."
      warn ""
      warn "If the hook is lost, add the following to $settings_file manually"
      warn "(inside \"hooks\" > \"PreToolUse\"):"
      warn ""
      warn '  {'
      warn '    "matcher": "Bash",'
      warn '    "hooks": [{ "type": "command", "command": "'"$DEST/dcg"'" }]'
      warn '  }'
      warn ""
      warn "Or re-run this installer after closing all Claude processes."
    fi
  fi
}

configure_gemini() {
  local settings_file="$1"
  local settings_dir=$(dirname "$settings_file")

  # Check if Gemini CLI appears to be installed (has config dir or gemini command exists)
  if [ ! -d "$settings_dir" ] && ! command -v gemini >/dev/null 2>&1; then
    # Gemini CLI not installed - skip without error
    GEMINI_STATUS="skipped"
    return 0
  fi

  # Create directory if needed (gemini command exists but no config dir yet)
  if [ ! -d "$settings_dir" ]; then
    mkdir -p "$settings_dir"
  fi

  if [ -f "$settings_file" ]; then
    if grep -q '"command".*dcg' "$settings_file" 2>/dev/null; then
      GEMINI_STATUS="already"
      AUTO_CONFIGURED=1
      return 0
    fi

    GEMINI_BACKUP="${settings_file}.bak.$(date +%Y%m%d%H%M%S)"
    cp "$settings_file" "$GEMINI_BACKUP"

    if command -v python3 >/dev/null 2>&1; then
      python3 - "$settings_file" "$DEST/dcg" <<'PYEOF'
import json
import sys

settings_file = sys.argv[1]
dcg_path = sys.argv[2]

try:
    with open(settings_file, 'r') as f:
        settings = json.load(f)
except (IOError, ValueError, json.JSONDecodeError):
    settings = {}

# Gemini CLI uses BeforeTool instead of PreToolUse
if 'hooks' not in settings:
    settings['hooks'] = {}
if 'BeforeTool' not in settings['hooks']:
    settings['hooks']['BeforeTool'] = []

dcg_hook = {"name": "dcg", "type": "command", "command": dcg_path, "timeout": 5000}

# Check if run_shell_command matcher exists
shell_matcher = None
for entry in settings['hooks']['BeforeTool']:
    if entry.get('matcher') == 'run_shell_command':
        shell_matcher = entry
        break

if shell_matcher:
    if 'hooks' not in shell_matcher:
        shell_matcher['hooks'] = []
    dcg_exists = any('dcg' in h.get('command', '') for h in shell_matcher['hooks'] if isinstance(h, dict))
    if not dcg_exists:
        shell_matcher['hooks'].insert(0, dcg_hook)
else:
    settings['hooks']['BeforeTool'].append({
        "matcher": "run_shell_command",
        "hooks": [dcg_hook]
    })

with open(settings_file, 'w') as f:
    json.dump(settings, f, indent=2)
PYEOF
      if [ $? -eq 0 ]; then
        GEMINI_STATUS="merged"
        AUTO_CONFIGURED=1
      else
        mv "$GEMINI_BACKUP" "$settings_file" 2>/dev/null || true
        GEMINI_STATUS="failed"
        GEMINI_BACKUP=""
      fi
    else
      # python3 not available - remove unnecessary backup
      rm -f "$GEMINI_BACKUP" 2>/dev/null || true
      GEMINI_BACKUP=""
      GEMINI_STATUS="failed"
      return 1
    fi
  else
    # Create new settings file with dcg hook
    cat > "$settings_file" <<EOFSET
{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "run_shell_command",
        "hooks": [
          {
            "name": "dcg",
            "type": "command",
            "command": "$DEST/dcg",
            "timeout": 5000
          }
        ]
      }
    ]
  }
}
EOFSET
    GEMINI_STATUS="created"
    AUTO_CONFIGURED=1
  fi
}

configure_aider() {
  local settings_file="$1"

  # Check if Aider is installed (command exists)
  if ! command -v aider >/dev/null 2>&1; then
    AIDER_STATUS="skipped"
    return 0
  fi

  # Aider does not have PreToolUse hooks like Claude Code or Gemini CLI.
  # Instead, we configure git-commit-verify to ensure git hooks run,
  # so if DCG is installed as a git pre-commit hook, it will be executed.
  #
  # Aider's YAML config supports:
  #   git-commit-verify: true  (enables git hooks, default is false)
  #
  # This is a limited integration - Aider will still execute shell commands
  # without dcg validation unless the user sets up additional git hooks.

  if [ -f "$settings_file" ]; then
    # Check if git-commit-verify is already set to true
    if grep -qE '^\s*git-commit-verify:\s*true' "$settings_file" 2>/dev/null; then
      AIDER_STATUS="already"
      AUTO_CONFIGURED=1
      return 0
    fi

    # Check if git-commit-verify exists but is false
    if grep -qE '^\s*git-commit-verify:' "$settings_file" 2>/dev/null; then
      # Update existing setting to true
      AIDER_BACKUP="${settings_file}.bak.$(date +%Y%m%d%H%M%S)"
      cp "$settings_file" "$AIDER_BACKUP"

      if command -v sed >/dev/null 2>&1; then
        sed -i.tmp 's/^\(\s*git-commit-verify:\s*\).*/\1true/' "$settings_file" && rm -f "${settings_file}.tmp"
        AIDER_STATUS="merged"
        AUTO_CONFIGURED=1
      else
        mv "$AIDER_BACKUP" "$settings_file" 2>/dev/null || true
        AIDER_STATUS="failed"
        AIDER_BACKUP=""
      fi
    else
      # Add git-commit-verify setting to existing file
      AIDER_BACKUP="${settings_file}.bak.$(date +%Y%m%d%H%M%S)"
      cp "$settings_file" "$AIDER_BACKUP"

      # Append the setting
      echo "" >> "$settings_file"
      echo "# Added by dcg installer - enables git hooks so dcg pre-commit can run" >> "$settings_file"
      echo "git-commit-verify: true" >> "$settings_file"
      AIDER_STATUS="merged"
      AUTO_CONFIGURED=1
    fi
  else
    # Create new settings file
    cat > "$settings_file" <<'EOFAIDER'
# Aider configuration
# Created by dcg installer
#
# git-commit-verify: enables git hooks (including pre-commit)
# This allows dcg to validate commands when installed as a git hook.
#
# Note: Aider does not have shell command interception hooks like Claude Code.
# For full protection, consider using dcg as a git pre-commit hook.

git-commit-verify: true
EOFAIDER
    AIDER_STATUS="created"
    AUTO_CONFIGURED=1
  fi
}

configure_continue() {
  # Continue (https://continue.dev) is an AI coding assistant for IDEs.
  # Detection: check for ~/.continue directory or `cn` CLI command.
  #
  # IMPORTANT: Continue does NOT have shell command interception hooks.
  # Unlike Claude Code (PreToolUse) or Gemini CLI (BeforeTool), Continue
  # executes commands directly without a hook mechanism.
  #
  # There is also no git-commit-verify equivalent setting like Aider has.
  #
  # For users who want dcg protection with Continue, the recommended approach
  # is to install dcg as a git pre-commit hook (see docs/scan-precommit-guide.md).

  # Check if Continue is installed
  local continue_installed=0

  # Check for CLI command
  if command -v cn >/dev/null 2>&1; then
    continue_installed=1
  fi

  # Check for config directory (IDE extension)
  if [ -d "$HOME/.continue" ]; then
    continue_installed=1
  fi

  if [ "$continue_installed" -eq 0 ]; then
    CONTINUE_STATUS="skipped"
    return 0
  fi

  # Continue is installed but has no shell command hooks
  CONTINUE_STATUS="unsupported"
}

configure_codex() {
  # Codex CLI (https://github.com/openai/codex) is OpenAI's coding assistant.
  # Detection: check for ~/.codex directory or `codex` command in PATH.
  #
  # IMPORTANT: Codex CLI does NOT have pre-execution command hooks.
  # As of 2025, Codex CLI only supports post-execution hooks:
  # - notify: Send notifications after events
  # - agent-turn-complete: Callback after agent completes work
  #
  # See: https://github.com/openai/codex/discussions/2150
  #
  # For users who want dcg protection with Codex CLI, the recommended approach
  # is to install dcg as a git pre-commit hook (see docs/scan-precommit-guide.md).

  # Check if Codex is installed
  local codex_installed=0

  # Check for CLI command
  if command -v codex >/dev/null 2>&1; then
    codex_installed=1
  fi

  # Check for config directory
  if [ -d "$HOME/.codex" ]; then
    codex_installed=1
  fi

  if [ "$codex_installed" -eq 0 ]; then
    CODEX_STATUS="skipped"
    return 0
  fi

  # Codex is installed but has no pre-execution command hooks
  CODEX_STATUS="unsupported"
}

configure_cursor() {
  # Cursor IDE (https://cursor.com) supports hooks via ~/.cursor/hooks.json.
  # We install a beforeShellExecution hook that delegates to dcg.
  local settings_file="$CURSOR_HOOKS_JSON"
  local hook_dir="$CURSOR_HOOK_DIR"
  local hook_script="$CURSOR_HOOK_SCRIPT"

  local cursor_installed=0
  if [[ -d "$HOME/.cursor" ]] || [[ -f "$CURSOR_SETTINGS_MAC" ]] || [[ -f "$CURSOR_SETTINGS_LINUX" ]] || command -v cursor >/dev/null 2>&1; then
    cursor_installed=1
  elif command -v pgrep >/dev/null 2>&1; then
    if pgrep -f "[Cc]ursor" >/dev/null 2>&1; then
      cursor_installed=1
    fi
  fi

  if [ "$cursor_installed" -eq 0 ]; then
    CURSOR_STATUS="skipped"
    return 0
  fi

  if ! command -v python3 >/dev/null 2>&1; then
    CURSOR_STATUS="failed"
    return 1
  fi

  mkdir -p "$hook_dir"

  local marker="dcg-cursor-hook"
  if [ -f "$hook_script" ] && ! grep -q "$marker" "$hook_script" 2>/dev/null; then
    CURSOR_STATUS="conflict"
    return 1
  fi

  cat > "$hook_script" <<'PYEOF'
#!/usr/bin/env python3
# dcg-cursor-hook: generated by dcg installer
import json
import os
import subprocess
import sys

def emit(payload):
    sys.stdout.write(json.dumps(payload))
    sys.stdout.flush()

def allow():
    emit({
        "permission": "allow",
        "continue": True,
        "userMessage": "",
        "agentMessage": "",
        "user_message": "",
        "agent_message": "",
    })

def deny(reason):
    emit({
        "permission": "deny",
        "continue": False,
        "userMessage": reason,
        "agentMessage": reason,
        "user_message": reason,
        "agent_message": reason,
    })

def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        allow()
        return 0

    command = payload.get("command") or ""
    cwd = payload.get("cwd") or ""
    if cwd:
        try:
            os.chdir(cwd)
        except Exception:
            pass

    if not command:
        allow()
        return 0

    dcg_bin = os.environ.get("DCG_BIN", "dcg")
    hook_input = {"tool_name": "Bash", "tool_input": {"command": command}}

    try:
        proc = subprocess.run(
            [dcg_bin],
            input=json.dumps(hook_input),
            text=True,
            capture_output=True,
        )
    except Exception:
        allow()
        return 0

    output = (proc.stdout or "").strip()
    if not output:
        allow()
        return 0

    try:
        dcg_out = json.loads(output)
    except Exception:
        allow()
        return 0

    decision = (
        dcg_out.get("hookSpecificOutput", {})
        .get("permissionDecision")
    )
    reason = (
        dcg_out.get("hookSpecificOutput", {})
        .get("permissionDecisionReason", "Blocked by dcg")
    )

    if decision == "deny":
        deny(reason)
        return 0

    allow()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
PYEOF
  chmod +x "$hook_script" 2>/dev/null || true

  if [ -f "$settings_file" ]; then
    if grep -q "$hook_script" "$settings_file" 2>/dev/null; then
      CURSOR_STATUS="already"
      AUTO_CONFIGURED=1
      return 0
    fi

    CURSOR_BACKUP="${settings_file}.bak.$(date +%Y%m%d%H%M%S)"
    cp "$settings_file" "$CURSOR_BACKUP"

    python3 - "$settings_file" "$hook_script" <<'PYEOF'
import json
import sys

settings_file = sys.argv[1]
hook_cmd = sys.argv[2]

try:
    with open(settings_file, "r") as f:
        settings = json.load(f)
except Exception:
    settings = {}

if not isinstance(settings, dict):
    settings = {}

settings.setdefault("version", 1)
hooks = settings.setdefault("hooks", {})
if not isinstance(hooks, dict):
    hooks = {}
    settings["hooks"] = hooks

entries = hooks.get("beforeShellExecution")
if not isinstance(entries, list):
    entries = []
hooks["beforeShellExecution"] = entries

def is_match(entry):
    return isinstance(entry, dict) and entry.get("command") == hook_cmd

if not any(is_match(entry) for entry in entries):
    entries.insert(0, {"command": hook_cmd})

with open(settings_file, "w") as f:
    json.dump(settings, f, indent=2)
PYEOF
    if [ $? -eq 0 ]; then
      CURSOR_STATUS="merged"
      AUTO_CONFIGURED=1
    else
      mv "$CURSOR_BACKUP" "$settings_file" 2>/dev/null || true
      CURSOR_STATUS="failed"
      CURSOR_BACKUP=""
      return 1
    fi
  else
    cat > "$settings_file" <<EOFSET
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [
      {
        "command": "$hook_script"
      }
    ]
  }
}
EOFSET
    CURSOR_STATUS="created"
    AUTO_CONFIGURED=1
  fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Run Auto-Configuration
# ═══════════════════════════════════════════════════════════════════════════════

if [ "$NO_CONFIGURE" -eq 0 ]; then
  # Detect predecessor
  detect_predecessor

  # Default: don't remove predecessor (set before conditional block)
  REMOVE_PREDECESSOR=0

  if [ "$PREDECESSOR_FOUND" -eq 1 ]; then
    show_upgrade_banner

    # Decide whether to remove predecessor
    if [ "$EASY" -eq 1 ]; then
      # Easy mode: always remove
      REMOVE_PREDECESSOR=1
      info "Easy mode: auto-removing predecessor"
    elif [ -t 0 ]; then
      # Interactive: ask user
      if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
        if gum confirm "Remove predecessor ($PREDECESSOR_SCRIPT) and upgrade to dcg?"; then
          REMOVE_PREDECESSOR=1
        fi
      else
        echo -n "Remove predecessor ($PREDECESSOR_SCRIPT) and upgrade to dcg? (Y/n): "
        read -r ans
        case "$ans" in
          n|N|no|No|NO) REMOVE_PREDECESSOR=0;;
          *) REMOVE_PREDECESSOR=1;;
        esac
      fi
    else
      # Non-interactive without --easy-mode: default to removing (user ran installer intentionally)
      REMOVE_PREDECESSOR=1
      info "Non-interactive mode: auto-removing predecessor (use --easy-mode to suppress this message)"
    fi

    if [ "$REMOVE_PREDECESSOR" -eq 1 ]; then
      for loc in "${PREDECESSOR_LOCATIONS[@]}"; do
        remove_predecessor "$loc"
      done
      # Note: settings.json cleanup is handled by configure_claude_code() below
    else
      warn "Keeping predecessor; dcg will run alongside it"
      warn "Consider removing $PREDECESSOR_SCRIPT manually to avoid duplicate checks"
    fi
  fi

  # Always configure Claude Code (creates directory if needed)
  configure_claude_code "$CLAUDE_SETTINGS" "$REMOVE_PREDECESSOR"

  # Configure Gemini CLI (if installed)
  configure_gemini "$GEMINI_SETTINGS"

  # Configure Aider (if installed)
  configure_aider "$AIDER_SETTINGS"

  # Configure Continue (if installed)
  configure_continue

  # Configure Codex CLI (if installed)
  configure_codex

  # Configure Cursor IDE (if installed)
  configure_cursor
else
  info "Skipping agent configuration (--no-configure)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Final Summary
# ═══════════════════════════════════════════════════════════════════════════════

echo ""

if [ "$NO_CONFIGURE" -eq 1 ]; then
  summary_lines=("Agent configuration skipped (--no-configure)")
else
  # Build summary of what was done
  summary_lines=()

case "$CLAUDE_STATUS" in
  created)
    summary_lines+=("Claude Code: Created $CLAUDE_SETTINGS with dcg hook")
    ;;
  merged)
    summary_lines+=("Claude Code: Added dcg hook to existing $CLAUDE_SETTINGS")
    [ -n "$CLAUDE_BACKUP" ] && summary_lines+=("             Backup: $CLAUDE_BACKUP")
    ;;
  clobbered)
    summary_lines+=("Claude Code: ⚠ Hook written but overwritten by running Claude process")
    summary_lines+=("             Re-run installer after closing Claude, or add hook manually")
    [ -n "$CLAUDE_BACKUP" ] && summary_lines+=("             Backup: $CLAUDE_BACKUP")
    ;;
  already)
    summary_lines+=("Claude Code: Already configured (no changes)")
    ;;
  failed)
    summary_lines+=("Claude Code: Configuration failed (python3 required)")
    ;;
  *)
    summary_lines+=("Claude Code: Configured")
    ;;
esac

case "$GEMINI_STATUS" in
  created)
    summary_lines+=("Gemini CLI:  Created $GEMINI_SETTINGS with dcg hook")
    ;;
  merged)
    summary_lines+=("Gemini CLI:  Added dcg hook to existing $GEMINI_SETTINGS")
    [ -n "$GEMINI_BACKUP" ] && summary_lines+=("             Backup: $GEMINI_BACKUP")
    ;;
  already)
    summary_lines+=("Gemini CLI:  Already configured (no changes)")
    ;;
  skipped|"")
    summary_lines+=("Gemini CLI:  Not installed (skipped)")
    ;;
  failed)
    summary_lines+=("Gemini CLI:  Configuration failed")
    ;;
esac

case "$AIDER_STATUS" in
  created)
    summary_lines+=("Aider:       Created $AIDER_SETTINGS (git hooks enabled)")
    summary_lines+=("             Note: Aider lacks shell hooks; uses git-commit-verify for git hook support")
    ;;
  merged)
    summary_lines+=("Aider:       Enabled git-commit-verify in $AIDER_SETTINGS")
    [ -n "$AIDER_BACKUP" ] && summary_lines+=("             Backup: $AIDER_BACKUP")
    summary_lines+=("             Note: Aider lacks shell hooks; git hooks now enabled for dcg")
    ;;
  already)
    summary_lines+=("Aider:       Already configured (git-commit-verify enabled)")
    ;;
  skipped|"")
    summary_lines+=("Aider:       Not installed (skipped)")
    ;;
  failed)
    summary_lines+=("Aider:       Configuration failed")
    ;;
esac

case "$CONTINUE_STATUS" in
  unsupported)
    summary_lines+=("Continue:    Detected but has no shell command hooks")
    summary_lines+=("             Tip: Install dcg as git pre-commit hook for protection")
    ;;
  skipped|"")
    summary_lines+=("Continue:    Not installed (skipped)")
    ;;
esac

case "$CODEX_STATUS" in
  unsupported)
    summary_lines+=("Codex CLI:   Detected but has no pre-execution hooks")
    summary_lines+=("             Tip: Install dcg as git pre-commit hook for protection")
    ;;
  skipped|"")
    summary_lines+=("Codex CLI:   Not installed (skipped)")
    ;;
esac

  case "$CURSOR_STATUS" in
  created)
    summary_lines+=("Cursor IDE:  Created $CURSOR_HOOKS_JSON with dcg hook")
    ;;
  merged)
    summary_lines+=("Cursor IDE:  Added dcg hook to existing $CURSOR_HOOKS_JSON")
    [ -n "$CURSOR_BACKUP" ] && summary_lines+=("             Backup: $CURSOR_BACKUP")
    ;;
  already)
    summary_lines+=("Cursor IDE:  Already configured (no changes)")
    ;;
  conflict)
    summary_lines+=("Cursor IDE:  Found existing hook script at $CURSOR_HOOK_SCRIPT")
    summary_lines+=("             Tip: remove or rename it to let dcg configure Cursor hooks")
    ;;
  skipped|"")
    summary_lines+=("Cursor IDE:  Not installed (skipped)")
    ;;
  failed)
    summary_lines+=("Cursor IDE:  Configuration failed (python3 required)")
    ;;
esac
fi

# Show summary
if [ "$QUIET" -eq 0 ]; then
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    {
      gum style --foreground 42 --bold "dcg is now active!"
      echo ""
      for line in "${summary_lines[@]}"; do
        gum style --foreground 245 "$line"
      done
      echo ""
      gum style --foreground 245 "All Bash commands will be scanned for destructive patterns."
      gum style --foreground 245 "Use \"dcg explain <command>\" to see why a command was blocked."
    } | gum style --border normal --border-foreground 42 --padding "1 2"
  else
    echo -e "\033[1;32mdcg is now active!\033[0m"
    echo ""
    for line in "${summary_lines[@]}"; do
      echo -e "  \033[0;90m$line\033[0m"
    done
    echo ""
    echo -e "  All Bash commands will be scanned for destructive patterns."
    echo -e "  Use \"\033[0;36mdcg explain <command>\033[0m\" to see why a command was blocked."
  fi

  # Show reversal instructions
  echo ""
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style --foreground 245 --italic "To uninstall: rm $DEST/dcg && remove dcg hooks from settings files"
    if [ -n "$CLAUDE_BACKUP" ] || [ -n "$GEMINI_BACKUP" ]; then
      gum style --foreground 245 --italic "To revert:   restore from backup files listed above"
    fi
  else
    echo -e "\033[0;90mTo uninstall: rm $DEST/dcg && remove dcg hooks from settings files\033[0m"
    if [ -n "$CLAUDE_BACKUP" ] || [ -n "$GEMINI_BACKUP" ]; then
      echo -e "\033[0;90mTo revert:   restore from backup files listed above\033[0m"
    fi
  fi
fi

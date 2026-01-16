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
ARTIFACT_URL="${ARTIFACT_URL:-}"
LOCK_FILE="/tmp/dcg-install.lock"
SYSTEM=0
NO_GUM=0

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

usage() {
  cat <<EOFU
Usage: install.sh [--version vX.Y.Z] [--dest DIR] [--system] [--easy-mode] [--verify] \\
                  [--artifact-url URL] [--checksum HEX] [--checksum-url URL] [--quiet] [--no-gum]

Options:
  --version vX.Y.Z   Install specific version (default: latest)
  --dest DIR         Install to DIR (default: ~/.local/bin)
  --system           Install to /usr/local/bin (requires sudo)
  --easy-mode        Auto-update PATH in shell rc files
  --verify           Run self-test after install
  --from-source      Build from source instead of downloading binary
  --quiet            Suppress non-error output
  --no-gum           Disable gum formatting even if available
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
    --no-gum) NO_GUM=1; shift;;
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

resolve_version

mkdir -p "$DEST"
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

# Prefer prebuilt artifact when we know the target or the caller supplied a direct URL.
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
  exit 0
fi

if [ -z "$CHECKSUM" ]; then
  [ -z "$CHECKSUM_URL" ] && CHECKSUM_URL="${URL}.sha256"
  info "Fetching checksum from ${CHECKSUM_URL}"
  CHECKSUM_FILE="$TMP/checksum.sha256"
  if ! curl -fsSL "$CHECKSUM_URL" -o "$CHECKSUM_FILE"; then
    err "Checksum required and could not be fetched"; exit 1;
  fi
  CHECKSUM=$(awk '{print $1}' "$CHECKSUM_FILE")
  if [ -z "$CHECKSUM" ]; then err "Empty checksum file"; exit 1; fi
fi

echo "$CHECKSUM  $TMP/$TAR" | sha256sum -c - || { err "Checksum mismatch"; exit 1; }
ok "Checksum verified"

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
# Claude Code / Gemini CLI Auto-Configuration
# ═══════════════════════════════════════════════════════════════════════════════

CLAUDE_SETTINGS="$HOME/.claude/settings.json"
GEMINI_SETTINGS="$HOME/.gemini/settings.json"
AUTO_CONFIGURED=0

# Detailed tracking for what was configured
CLAUDE_STATUS=""  # "created"|"merged"|"already"|"failed"
GEMINI_STATUS=""  # "created"|"merged"|"already"|"failed"|"skipped"
CLAUDE_BACKUP=""
GEMINI_BACKUP=""

configure_claude_code() {
  local settings_file="$1"
  local cleanup_predecessor="$2"
  # Default to cleaning up predecessor if not specified or empty
  [ -z "$cleanup_predecessor" ] && cleanup_predecessor=1
  local settings_dir=$(dirname "$settings_file")

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
        CLAUDE_STATUS="merged"
        AUTO_CONFIGURED=1
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

# ═══════════════════════════════════════════════════════════════════════════════
# Run Auto-Configuration
# ═══════════════════════════════════════════════════════════════════════════════

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

# ═══════════════════════════════════════════════════════════════════════════════
# Final Summary
# ═══════════════════════════════════════════════════════════════════════════════

echo ""

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

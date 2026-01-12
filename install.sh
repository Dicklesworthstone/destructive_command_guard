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

update_settings_json() {
  local settings_file="$1"
  local backup="${settings_file}.bak.$(date +%Y%m%d%H%M%S)"

  if [ ! -f "$settings_file" ]; then
    return 1
  fi

  # Check if it references git_safety_guard.py
  if grep -q "$PREDECESSOR_SCRIPT" "$settings_file" 2>/dev/null; then
    info "Updating settings to replace predecessor with dcg..."
    cp "$settings_file" "$backup"

    # Use sed to replace git_safety_guard.py references with dcg path
    # This handles the command path in the hooks configuration
    if command -v python3 >/dev/null 2>&1; then
      python3 - "$settings_file" "$DEST/dcg" "$backup" <<'PYEOF'
import json
import sys
import os

settings_file = sys.argv[1]
dcg_path = sys.argv[2]
backup_file = sys.argv[3]

try:
    with open(settings_file, 'r') as f:
        settings = json.load(f)
except:
    sys.exit(1)

modified = False

# Navigate to hooks.PreToolUse
if 'hooks' in settings and 'PreToolUse' in settings['hooks']:
    for matcher_entry in settings['hooks']['PreToolUse']:
        if 'hooks' in matcher_entry:
            new_hooks = []
            for hook in matcher_entry['hooks']:
                if isinstance(hook, dict) and 'command' in hook:
                    cmd = hook['command']
                    if 'git_safety_guard.py' in cmd:
                        # Replace with dcg
                        hook['command'] = dcg_path
                        modified = True
                new_hooks.append(hook)
            matcher_entry['hooks'] = new_hooks

if modified:
    with open(settings_file, 'w') as f:
        json.dump(settings, f, indent=2)
    print(f"Updated {settings_file}")
else:
    # Restore backup since no changes were made
    os.rename(backup_file, settings_file)
PYEOF
      ok "Updated $settings_file (backup: $backup)"
    else
      warn "Python3 not available for JSON update; manual update required"
      return 1
    fi
  fi
  return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# Claude Code / Gemini CLI Auto-Configuration
# ═══════════════════════════════════════════════════════════════════════════════

CLAUDE_SETTINGS="$HOME/.claude/settings.json"
GEMINI_SETTINGS="$HOME/.gemini/settings.json"
AUTO_CONFIGURED=0

configure_claude_code() {
  local settings_file="$1"
  local settings_dir=$(dirname "$settings_file")

  if [ ! -d "$settings_dir" ]; then
    info "Creating Claude Code config directory: $settings_dir"
    mkdir -p "$settings_dir"
  fi

  if [ -f "$settings_file" ]; then
    # Check if dcg is already configured
    if grep -q '"command".*dcg' "$settings_file" 2>/dev/null; then
      ok "Claude Code already configured with dcg"
      return 0
    fi

    # Settings file exists, need to merge
    info "Merging dcg hook into existing Claude Code settings..."
    local backup="${settings_file}.bak.$(date +%Y%m%d%H%M%S)"
    cp "$settings_file" "$backup"

    if command -v python3 >/dev/null 2>&1; then
      python3 - "$settings_file" "$DEST/dcg" <<'PYEOF'
import json
import sys

settings_file = sys.argv[1]
dcg_path = sys.argv[2]

try:
    with open(settings_file, 'r') as f:
        settings = json.load(f)
except:
    settings = {}

# Ensure hooks structure exists
if 'hooks' not in settings:
    settings['hooks'] = {}
if 'PreToolUse' not in settings['hooks']:
    settings['hooks']['PreToolUse'] = []

# Check if Bash matcher already exists
bash_matcher = None
for entry in settings['hooks']['PreToolUse']:
    if entry.get('matcher') == 'Bash':
        bash_matcher = entry
        break

dcg_hook = {"type": "command", "command": dcg_path}

if bash_matcher:
    # Add dcg to existing Bash matcher
    if 'hooks' not in bash_matcher:
        bash_matcher['hooks'] = []
    # Check if dcg is already there
    dcg_exists = any('dcg' in h.get('command', '') for h in bash_matcher['hooks'] if isinstance(h, dict))
    if not dcg_exists:
        # Insert at beginning for priority
        bash_matcher['hooks'].insert(0, dcg_hook)
else:
    # Create new Bash matcher
    settings['hooks']['PreToolUse'].append({
        "matcher": "Bash",
        "hooks": [dcg_hook]
    })

with open(settings_file, 'w') as f:
    json.dump(settings, f, indent=2)
PYEOF
      if [ $? -eq 0 ]; then
        ok "Configured Claude Code (backup: $backup)"
        AUTO_CONFIGURED=1
      else
        warn "Failed to configure Claude Code; restoring backup"
        mv "$backup" "$settings_file" 2>/dev/null || true
      fi
    else
      warn "Python3 not available; showing manual instructions"
      return 1
    fi
  else
    # Create new settings file
    info "Creating Claude Code settings with dcg hook..."
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
    ok "Created $settings_file"
    AUTO_CONFIGURED=1
  fi
}

configure_gemini() {
  local settings_file="$1"
  local settings_dir=$(dirname "$settings_file")

  # Check if Gemini CLI is installed
  if [ ! -d "$settings_dir" ]; then
    # Gemini CLI not installed
    return 1
  fi

  if [ -f "$settings_file" ]; then
    if grep -q '"command".*dcg' "$settings_file" 2>/dev/null; then
      ok "Gemini CLI already configured with dcg"
      return 0
    fi

    info "Configuring Gemini CLI with dcg hook..."
    local backup="${settings_file}.bak.$(date +%Y%m%d%H%M%S)"
    cp "$settings_file" "$backup"

    if command -v python3 >/dev/null 2>&1; then
      python3 - "$settings_file" "$DEST/dcg" <<'PYEOF'
import json
import sys

settings_file = sys.argv[1]
dcg_path = sys.argv[2]

try:
    with open(settings_file, 'r') as f:
        settings = json.load(f)
except:
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
        ok "Configured Gemini CLI (backup: $backup)"
        AUTO_CONFIGURED=1
      else
        warn "Failed to configure Gemini CLI; restoring backup"
        mv "$backup" "$settings_file" 2>/dev/null || true
      fi
    else
      warn "Python3 not available; showing manual instructions"
      return 1
    fi
  else
    # Create new settings file with dcg hook
    # Note: directory must exist (we checked earlier), so just create the file
    info "Creating Gemini CLI settings with dcg hook..."
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
    ok "Created $settings_file"
    AUTO_CONFIGURED=1
  fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Run Auto-Configuration
# ═══════════════════════════════════════════════════════════════════════════════

# Detect predecessor
detect_predecessor

if [ "$PREDECESSOR_FOUND" -eq 1 ]; then
  show_upgrade_banner

  # Ask user if they want to remove predecessor
  REMOVE_PREDECESSOR=0
  if [ -t 0 ] && [ "$EASY" -ne 1 ]; then
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
  elif [ "$EASY" -eq 1 ]; then
    REMOVE_PREDECESSOR=1
    info "Easy mode: auto-removing predecessor"
  fi

  if [ "$REMOVE_PREDECESSOR" -eq 1 ]; then
    for loc in "${PREDECESSOR_LOCATIONS[@]}"; do
      remove_predecessor "$loc"
    done

    # Update settings.json to use dcg instead
    if [ -f "$CLAUDE_SETTINGS" ]; then
      update_settings_json "$CLAUDE_SETTINGS"
    fi
  else
    warn "Keeping predecessor; dcg will run alongside it"
    warn "Consider removing $PREDECESSOR_SCRIPT manually to avoid duplicate checks"
  fi
fi

# Configure Claude Code
if [ -d "$HOME/.claude" ] || [ "$EASY" -eq 1 ]; then
  info "Detecting Claude Code..."
  configure_claude_code "$CLAUDE_SETTINGS"
fi

# Configure Gemini CLI (if installed)
if [ -d "$HOME/.gemini" ]; then
  info "Detecting Gemini CLI..."
  configure_gemini "$GEMINI_SETTINGS"
fi

# Show final status
echo ""
if [ "$AUTO_CONFIGURED" -eq 1 ]; then
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style \
      --border normal \
      --border-foreground 42 \
      --padding "1 2" \
      "$(gum style --foreground 42 --bold '🛡️  dcg is now active!')" \
      "" \
      "$(gum style --foreground 245 'All Bash commands will be scanned for destructive patterns.')" \
      "$(gum style --foreground 245 'Use \"dcg explain <command>\" to see why a command was blocked.')"
  else
    echo -e "\033[0;32m╔════════════════════════════════════════════════════════════════╗\033[0m"
    echo -e "\033[0;32m║\033[0m  \033[1;32mdcg is now active!\033[0m                                              \033[0;32m║\033[0m"
    echo -e "\033[0;32m╠════════════════════════════════════════════════════════════════╣\033[0m"
    echo -e "\033[0;32m║\033[0m  All Bash commands will be scanned for destructive patterns.   \033[0;32m║\033[0m"
    echo -e "\033[0;32m║\033[0m  Use \"dcg explain <cmd>\" to see why a command was blocked.     \033[0;32m║\033[0m"
    echo -e "\033[0;32m╚════════════════════════════════════════════════════════════════╝\033[0m"
  fi
else
  info "To manually configure Claude Code, add to ~/.claude/settings.json:"
  cat <<EOF
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
EOF
fi

#!/usr/bin/env bash
#
# dcg installer
#
# One-liner install (with cache buster):
#   curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/install.sh?$(date +%s)" | bash
#
# Or without cache buster:
#   curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/install.sh | bash
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
#   --require-minisign Require a valid release .minisig and the minisign tool
#   --minisign-url URL Override the adjacent .minisig URL (including file://)
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
MINISIGN_SIGNATURE_URL="${MINISIGN_SIGNATURE_URL:-}"
# These are release trust roots, not caller-configurable settings. New releases
# use the DSR-managed key. The retired key remains valid only for v0.6.7, the
# sole historical release whose installable archives were signed with it.
readonly MINISIGN_PUBLIC_KEY="RWSoYi6NXJWzaRs1mJmOwwXrZfPWcq6MXnQlNMLBYKzlIQTLwuVQG6uO"
readonly MINISIGN_KEY_ID="69B3955C8D2E62A8"
readonly LEGACY_MINISIGN_PUBLIC_KEY="RWTQoKUb0Ue4NsqTpPWnABCrIU0+m25zsMlbv6UcRClQ7jmRP3A7NmTB"
readonly LEGACY_MINISIGN_KEY_ID="36B847D11BA5A0D0"
# Pinned self-managed cosign key for DSR/manual releases. GitHub Actions OIDC
# remains a separately accepted trust path for workflow-built releases.
readonly COSIGN_RELEASE_PUBLIC_KEY='-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExiRXKgfQ5rG9l5Bxd4CEefEwmhxA
5QzBI7X6X3RC4HWHwk5hRC9eVUkC8JEqV1eYxY5G3rHaxDs3yJ01IjUY5g==
-----END PUBLIC KEY-----'
COSIGN_IDENTITY_RE="${COSIGN_IDENTITY_RE:-^https://github.com/${OWNER}/${REPO}/.github/workflows/dist.yml@refs/tags/.*$}"
COSIGN_OIDC_ISSUER="${COSIGN_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"
ARTIFACT_URL="${ARTIFACT_URL:-}"
LOCK_FILE="/tmp/dcg-install.lock"
NO_GUM=0
NO_CONFIGURE=0
NO_CHECKSUM=0
REQUIRE_MINISIGN=0
FORCE_INSTALL=0
OFFLINE="${DCG_OFFLINE:-0}"
AGENT_VERSION_LOOKUP="${DCG_INSTALLER_AGENT_VERSIONS:-0}"
AGENT_VERSION_TIMEOUT="${DCG_INSTALLER_AGENT_VERSION_TIMEOUT:-1}"

# Detect gum for fancy output (https://github.com/charmbracelet/gum)
HAS_GUM=0
if command -v gum &> /dev/null && [ -t 1 ]; then
  HAS_GUM=1
fi

# Operator TTY detection (#251). Under `curl … | bash`, stdin is the script
# pipe, so `[ -t 0 ]` is false even though a human is sitting at a terminal.
# The controlling terminal is still reachable via /dev/tty, so prompts write
# to and read from it directly. Truly headless runs (CI, cron) have no
# controlling terminal, fail this probe, and take the documented defaults.
DCG_TTY=""
if ( : </dev/tty >/dev/tty ) 2>/dev/null; then
  DCG_TTY="/dev/tty"
fi

# True when an operator terminal is available for prompting.
have_tty() { [ -n "$DCG_TTY" ]; }

# Seconds an interactive prompt waits for a reply before taking its default
# (#251). A pty can exist with nobody attached to answer — `docker run -t`
# without `-i`, pty-allocating CI — and an untimed read would hang the
# install forever there. Overridable for tests.
DCG_PROMPT_TIMEOUT="${DCG_PROMPT_TIMEOUT:-120}"

# ask_yn "<prompt>" "<y|n default>" — ask a yes/no question on the operator
# TTY. Prints the prompt to /dev/tty and reads the reply from it, so it works
# under `curl … | bash`. Returns 0 for yes, 1 for no. The default answers
# empty input, a failed read, a missing TTY, or a reply timeout, and follows
# the same convention as the inline prompts it replaces: a "y" default only
# becomes no on an explicit no, an "n" default only becomes yes on an
# explicit yes.
ask_yn() {
  local prompt="$1"
  local default="${2:-n}"
  local reply=""
  local read_status=0
  if have_tty; then
    printf '%s ' "$prompt" >"$DCG_TTY" 2>/dev/null || true
    IFS= read -r -t "$DCG_PROMPT_TIMEOUT" reply <"$DCG_TTY" 2>/dev/null || read_status=$?
    if [ "$read_status" -ne 0 ]; then
      # Timed out or EOF: nobody is answering this pty. bash >= 4 marks a
      # timeout with an exit status > 128, but bash 3.2 (macOS /bin/bash)
      # returns 1 for both, so treat every failed TTY read the same — take
      # the default rather than hanging, and say so on the record.
      reply=""
      printf '\n' >"$DCG_TTY" 2>/dev/null || true
      warn "No reply (timeout after ${DCG_PROMPT_TIMEOUT}s or end of input); taking the default (${default})."
    fi
  fi
  [ -n "$reply" ] || reply="$default"
  if [ "$default" = "y" ]; then
    case "$reply" in n|N|no|No|NO) return 1 ;; *) return 0 ;; esac
  else
    case "$reply" in y|Y|yes|Yes|YES) return 0 ;; *) return 1 ;; esac
  fi
}

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
  for line in ${lines[@]+"${lines[@]}"}; do
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
  for line in ${lines[@]+"${lines[@]}"}; do
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
COPILOT_VERSION=""
HERMES_VERSION=""
POSIT_ASSISTANT_VERSION=""

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

# Posit Assistant ships as an IDE extension (Positron/RStudio), a standalone
# server, and the `pa` terminal client, so no single probe covers every
# install. Any one of these is enough to configure the shared global settings
# file:
#
#   - ~/.posit/assistant is the current config directory (created on first run)
#   - ~/.positai is the legacy config directory older installs still carry
#   - `pa` on PATH covers a fresh terminal-client install that has not run yet
#
# An IDE-only install that has never been launched matches none of these;
# launching Posit Assistant once and re-running the installer picks it up.
posit_assistant_installed() {
  [ -d "$HOME/.posit/assistant" ] ||
    [ -d "$HOME/.positai" ] ||
    command -v pa >/dev/null 2>&1
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

  # GitHub Copilot CLI
  if command -v copilot &>/dev/null || [[ -d "$HOME/.copilot" ]]; then
    DETECTED_AGENTS+=("github-copilot-cli")
    COPILOT_VERSION=$(try_version copilot)
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
    if pgrep -fl "[Cc]ursor" 2>/dev/null | grep -qv 'CursorUIViewService\|/System/Library/'; then
      cursor_detected=1
    fi
  fi

  if [ "$cursor_detected" -eq 1 ]; then
    DETECTED_AGENTS+=("cursor-ide")
    CURSOR_VERSION=$(try_version cursor)
  fi

  # Hermes Agent (NousResearch) — data dir at ${HERMES_HOME:-~/.hermes},
  # optional `hermes` CLI on PATH.
  if [[ -d "${HERMES_HOME:-$HOME/.hermes}" ]] || [[ -d "$HOME/.hermes" ]] ||
    command -v hermes &>/dev/null; then
    DETECTED_AGENTS+=("hermes")
    HERMES_VERSION=$(try_version hermes)
  fi

  # Posit Assistant (Posit Software, PBC)
  if posit_assistant_installed; then
    DETECTED_AGENTS+=("posit-assistant")
    POSIT_ASSISTANT_VERSION=$(try_version pa)
  fi

  # OpenCode (opencode.ai) — global config at ${XDG_CONFIG_HOME:-~/.config}/opencode,
  # optional `opencode` CLI on PATH.
  if [[ -d "${XDG_CONFIG_HOME:-$HOME/.config}/opencode" ]] || command -v opencode &>/dev/null; then
    DETECTED_AGENTS+=("opencode")
    OPENCODE_VERSION=$(try_version opencode)
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
    for agent in ${DETECTED_AGENTS[@]+"${DETECTED_AGENTS[@]}"}; do
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
        github-copilot-cli)
          local ver_info=""
          [[ -n "$COPILOT_VERSION" ]] && ver_info=" (${COPILOT_VERSION})"
          gum style --foreground 42 "  ✓ GitHub Copilot CLI${ver_info}"
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
        hermes)
          local ver_info=""
          [[ -n "$HERMES_VERSION" ]] && ver_info=" (${HERMES_VERSION})"
          gum style --foreground 42 "  ✓ Hermes Agent${ver_info}"
          ;;
        posit-assistant)
          local ver_info=""
          [[ -n "$POSIT_ASSISTANT_VERSION" ]] && ver_info=" (${POSIT_ASSISTANT_VERSION})"
          gum style --foreground 42 "  ✓ Posit Assistant${ver_info}"
          ;;
        opencode)
          local ver_info=""
          [[ -n "$OPENCODE_VERSION" ]] && ver_info=" (${OPENCODE_VERSION})"
          gum style --foreground 42 "  ✓ OpenCode${ver_info}"
          ;;
      esac
    done
    echo ""
  else
    echo ""
    echo -e "\033[1;39mDetected AI Coding Agent${plural}:\033[0m"
    for agent in ${DETECTED_AGENTS[@]+"${DETECTED_AGENTS[@]}"}; do
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
        github-copilot-cli)
          local ver_info=""
          [[ -n "$COPILOT_VERSION" ]] && ver_info=" (${COPILOT_VERSION})"
          echo -e "  \033[0;32m✓\033[0m GitHub Copilot CLI${ver_info}"
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
        hermes)
          local ver_info=""
          [[ -n "$HERMES_VERSION" ]] && ver_info=" (${HERMES_VERSION})"
          echo -e "  \033[0;32m✓\033[0m Hermes Agent${ver_info}"
          ;;
        posit-assistant)
          local ver_info=""
          [[ -n "$POSIT_ASSISTANT_VERSION" ]] && ver_info=" (${POSIT_ASSISTANT_VERSION})"
          echo -e "  \033[0;32m✓\033[0m Posit Assistant${ver_info}"
          ;;
        opencode)
          local ver_info=""
          [[ -n "$OPENCODE_VERSION" ]] && ver_info=" (${OPENCODE_VERSION})"
          echo -e "  \033[0;32m✓\033[0m OpenCode${ver_info}"
          ;;
      esac
    done
    echo ""
  fi
}

# Check if a specific agent was detected
is_agent_detected() {
  local target="$1"
  for agent in ${DETECTED_AGENTS[@]+"${DETECTED_AGENTS[@]}"}; do
    [[ "$agent" == "$target" ]] && return 0
  done
  return 1
}

normalize_version_tag() {
  local raw="${1:-}"
  local without_v="${raw#v}"
  local without_build="${without_v%%+*}"
  local prerelease=""
  local identifier

  # SemVer 2.0.0, with the repository's conventional optional leading `v`.
  # Core numeric identifiers may not have leading zeroes. Prerelease/build
  # identifiers use only the characters SemVer permits.
  if [[ ! "$raw" =~ ^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+)(\.[0-9A-Za-z-]+)*)?(\+([0-9A-Za-z-]+)(\.[0-9A-Za-z-]+)*)?$ ]]; then
    return 1
  fi

  if [[ "$without_build" == *-* ]]; then
    prerelease="${without_build#*-}"
    while IFS= read -r identifier; do
      if [[ "$identifier" =~ ^[0-9]+$ ]] && [ "${#identifier}" -gt 1 ] && [[ "$identifier" == 0* ]]; then
        return 1
      fi
    done < <(printf '%s\n' "$prerelease" | tr '.' '\n')
  fi

  printf 'v%s\n' "$without_v"
}

get_installed_version() {
  local output=""
  local line
  local candidate
  local normalized

  if [ ! -x "$DEST/dcg" ]; then
    return 1
  fi

  output=$("$DEST/dcg" --version 2>/dev/null) || return 1
  if [ -z "$output" ]; then
    output=$(NO_COLOR=1 "$DEST/dcg" --version 2>&1) || return 1
  fi

  while IFS= read -r line; do
    line="${line%$'\r'}"
    candidate="$line"
    if [[ "$candidate" == dcg[[:space:]]* ]]; then
      candidate="${candidate#dcg}"
      candidate="${candidate#"${candidate%%[![:space:]]*}"}"
    fi
    if normalized=$(normalize_version_tag "$candidate"); then
      printf '%s\n' "$normalized"
      return 0
    fi
  done <<< "$output"

  return 1
}

# Check if installed version matches target
# Returns 0 if versions match, 1 if they differ or dcg not installed
check_installed_version() {
  local target_version="$1"
  local installed_version
  local target_normalized

  target_normalized=$(normalize_version_tag "$target_version") || return 1
  installed_version=$(get_installed_version) || return 1
  [ "$target_normalized" = "$installed_version" ]
}

assert_installed_version() {
  local expected_version="${1:-}"
  local reported_version
  local expected_normalized

  if ! reported_version=$(get_installed_version); then
    err "Installed dcg failed its --version check"
    return 1
  fi

  if [ -n "$expected_version" ]; then
    expected_normalized=$(normalize_version_tag "$expected_version") || {
      err "Invalid expected release version: $expected_version"
      return 1
    }
    if [ "$reported_version" != "$expected_normalized" ]; then
      err "Installed dcg version mismatch: expected ${expected_normalized}, got ${reported_version}"
      return 1
    fi
  fi

  ok "Installed version verified: ${reported_version#v}"
}

run_install_self_test() {
  local allow_output
  local dcg_path
  local deny_output
  local deny_status

  info "Running self-test"
  dcg_path="$(cd -- "$DEST" && pwd -P)/dcg"
  if ! allow_output=$(cd "$TMP" && \
    HOME="$TMP/selftest-home" XDG_CONFIG_HOME="$TMP/selftest-xdg" \
    "$dcg_path" test --format json "git status" 2>&1); then
    err "Self-test failed while evaluating a safe command"
    return 1
  fi
  if ! printf '%s\n' "$allow_output" | grep -Eq '"decision"[[:space:]]*:[[:space:]]*"allow"'; then
    err "Self-test did not report allow for the safe probe"
    return 1
  fi

  # `dcg test` evaluates this string; it never executes it. A deny must be
  # represented by both exit 1 and structured output so a crash cannot pass.
  if deny_output=$(cd "$TMP" && \
    HOME="$TMP/selftest-home" XDG_CONFIG_HOME="$TMP/selftest-xdg" \
    "$dcg_path" test --format json "rm -rf /" 2>&1); then
    err "Self-test failed: destructive probe was allowed"
    return 1
  else
    deny_status=$?
  fi
  if [ "$deny_status" -ne 1 ] || \
     ! printf '%s\n' "$deny_output" | grep -Eq '"decision"[[:space:]]*:[[:space:]]*"deny"'; then
    err "Self-test failed while evaluating the destructive probe"
    return 1
  fi

  ok "Self-test complete"
}

resolve_version() {
  if [ -n "$VERSION" ]; then
    local requested_version="$VERSION"
    if ! VERSION=$(normalize_version_tag "$requested_version"); then
      err "Invalid version '$requested_version': expected SemVer such as v1.2.3"
      exit 2
    fi
    return 0
  fi
  if [ "$FROM_SOURCE" -eq 1 ] || [ -n "$ARTIFACT_URL" ]; then return 0; fi

  info "Resolving latest version..."
  local latest_url="https://api.github.com/repos/${OWNER}/${REPO}/releases/latest"
  local tag
  if ! tag=$(curl -fsSL -H "Accept: application/vnd.github.v3+json" "$latest_url" 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'); then
    tag=""
  fi

  if [ -n "$tag" ] && VERSION=$(normalize_version_tag "$tag"); then
    info "Resolved latest version: $VERSION"
  else
    # Try redirect-based resolution as fallback
    local redirect_url="https://github.com/${OWNER}/${REPO}/releases/latest"
    if tag=$(curl -fsSL -o /dev/null -w '%{url_effective}' "$redirect_url" 2>/dev/null | sed -E 's|.*/tag/||'); then
      if [ -n "$tag" ] && VERSION=$(normalize_version_tag "$tag"); then
        info "Resolved latest version via redirect: $VERSION"
        return 0
      fi
    fi
    err "Could not resolve latest release. Re-run with --version vX.Y.Z or --from-source."
    exit 1
  fi
}

clone_source_tree() {
  local destination="$1"
  local repository_url="https://github.com/${OWNER}/${REPO}.git"

  if [ -n "$VERSION" ]; then
    # Pin fallback builds to the same immutable release selected for the failed
    # artifact download. --single-branch prevents unrelated refs from being
    # fetched and --branch accepts the exact validated tag.
    git clone --depth 1 --branch "$VERSION" --single-branch \
      "$repository_url" "$destination"
  else
    git clone --depth 1 "$repository_url" "$destination"
  fi
}

detect_platform() {
  OS=$(uname -s | tr '[:upper:]' '[:lower:]')
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64|amd64) ARCH="x86_64" ;;
    arm64|aarch64) ARCH="aarch64" ;;
    *) warn "Unknown arch $ARCH, using as-is" ;;
  esac

  TARGET=""
  case "${OS}-${ARCH}" in
    # Linux x86_64 ships as a fully-static musl binary so the published
    # artifact runs on every glibc generation, including the LTS releases
    # (Ubuntu 22.04 ships glibc 2.35; RHEL 8/9, Amazon Linux 2, etc.).
    # The previous gnu mapping linked against the build runner's glibc
    # and rejected any older host with `GLIBC_2.39 not found`. See #114.
    linux-x86_64) TARGET="x86_64-unknown-linux-musl" ;;
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

      # Backward-compat fallback for the Linux x86_64 musl transition
      # (#114). Releases v0.5.2+ ship musl artifacts; v0.5.1 and earlier
      # ship gnu. If the operator pinned an older version that doesn't
      # have a musl asset, fall back to the gnu naming so they still
      # get a working binary. We probe with a HEAD request so this
      # adds at most one round-trip on the older-release path.
      if [ "$TARGET" = "x86_64-unknown-linux-musl" ] && command -v curl >/dev/null 2>&1; then
        local http_code
        http_code=$(curl -sSL -o /dev/null -w '%{http_code}' -I --max-time 10 "$URL" || echo "000")
        if [ "$http_code" != "200" ] && [ "$http_code" != "302" ]; then
          local legacy_target="x86_64-unknown-linux-gnu"
          local legacy_url="https://github.com/${OWNER}/${REPO}/releases/download/${VERSION}/dcg-${legacy_target}.tar.xz"
          local legacy_code
          legacy_code=$(curl -sSL -o /dev/null -w '%{http_code}' -I --max-time 10 "$legacy_url" || echo "000")
          if [ "$legacy_code" = "200" ] || [ "$legacy_code" = "302" ]; then
            warn "No musl artifact for ${VERSION}; falling back to gnu (host glibc must be >= the build runner's, see #114)"
            TARGET="$legacy_target"
            TAR="dcg-${TARGET}.tar.xz"
            URL="$legacy_url"
          fi
        fi
      fi
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

DCG_SHELL_CHECK_MARKER="# dcg: warn if hook was silently removed"

maybe_add_shell_check() {
  # Add a shell startup check that warns if the DCG hook has been silently
  # removed from ~/.claude/settings.json. Silent when present, fast (ms),
  # and only runs when both dcg and jq are on PATH.
  local snippet
  snippet=$(cat <<'EOFSNIPPET'

# dcg: warn if hook was silently removed from Claude Code settings
if command -v dcg &>/dev/null && command -v jq &>/dev/null; then
  if [ -f "$HOME/.claude/settings.json" ] && \
     ! jq -e '.hooks.PreToolUse[]? | select(.hooks[]?.command | test("dcg\"?$"))' \
       "$HOME/.claude/settings.json" &>/dev/null; then
    printf '\033[1;33m[dcg] Hook missing from ~/.claude/settings.json — run: dcg install\033[0m\n'
  fi
fi
EOFSNIPPET
  )

  local added=0
  for rc in "$HOME/.zshrc" "$HOME/.bashrc"; do
    if [ -e "$rc" ] && [ -w "$rc" ]; then
      if grep -qF "$DCG_SHELL_CHECK_MARKER" "$rc" 2>/dev/null; then
        added=1  # Already present — don't trigger fallback
        continue
      fi
      printf '%s\n' "$snippet" >> "$rc"
      added=1
      ok "Added shell startup check to $rc"
    fi
  done

  if [ "$added" -eq 0 ]; then
    # No RC files found or none writable — try to pick one based on shell
    local target_rc="$HOME/.bashrc"
    case "${SHELL:-}" in
      *zsh) target_rc="$HOME/.zshrc" ;;
    esac
    printf '%s\n' "$snippet" >> "$target_rc"
    ok "Added shell startup check to $target_rc"
  fi
}

# caller_user — the human who actually invoked the installer.
#
# Under `sudo`, the EUID is root and $SHELL/$HOME/$USER have been env_reset'd
# to root's values, which is the wrong identity for "whose shell completions
# are we installing." If $SUDO_USER is set and isn't itself root, that is the
# real caller. Otherwise fall back to $USER or the OS-reported login name.
caller_user() {
  if [ "${EUID:-$(id -u)}" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    printf '%s\n' "$SUDO_USER"
    return 0
  fi
  if [ -n "${USER:-}" ]; then
    printf '%s\n' "$USER"
    return 0
  fi
  id -un 2>/dev/null
}

# caller_home / caller_login_shell — resolve the caller's home directory and
# login shell from the OS user database, so they're stable under sudo where
# $HOME and $SHELL have been rewritten. Uses dscl on macOS (where /etc/passwd
# is not authoritative for user records) and getent on every other Unix.
caller_home() {
  local user
  user=$(caller_user) || return 1
  [ -z "$user" ] && return 1
  case "$(uname -s)" in
    Darwin)
      dscl . -read "/Users/$user" NFSHomeDirectory 2>/dev/null \
        | awk '/^NFSHomeDirectory:/ {print $2}'
      ;;
    *)
      getent passwd "$user" 2>/dev/null | cut -d: -f6
      ;;
  esac
}

caller_login_shell() {
  local user
  user=$(caller_user) || return 1
  [ -z "$user" ] && return 1
  case "$(uname -s)" in
    Darwin)
      dscl . -read "/Users/$user" UserShell 2>/dev/null \
        | awk '/^UserShell:/ {print $2}'
      ;;
    *)
      getent passwd "$user" 2>/dev/null | cut -d: -f7
      ;;
  esac
}

# detect_default_shell — pick which completion flavor to install.
#
# $SHELL is the obvious source, but `sudo` defaults to env_reset (since
# sudo 1.7.4), which rewrites $SHELL to the *target user's* login shell
# (root's). On Linux that's typically /bin/bash and produces a silent
# misplace into /root/.local/share/bash-completion. On macOS root's shell
# is /bin/sh and we'd print "skipped (unknown shell)" instead.
#
# When EUID==0 and $SUDO_USER is the actual caller, look up that user's
# login shell from the OS user database before falling back to $SHELL.
detect_default_shell() {
  local shell=""
  if [ "${EUID:-$(id -u)}" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    shell=$(caller_login_shell || true)
  fi
  [ -z "$shell" ] && shell="${SHELL:-}"
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

  # Resolve the *caller's* XDG paths, not root's. Under sudo $HOME points at
  # /root and $XDG_DATA_HOME/$XDG_CONFIG_HOME (if exported by the user's shell)
  # were stripped by env_reset, so we'd silently install into /root's home —
  # invisible to the user who actually ran the installer.
  local home xdg_data xdg_config running_sudo=0
  if [ "${EUID:-$(id -u)}" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    running_sudo=1
    home=$(caller_home || true)
    if [ -z "$home" ]; then
      warn "Could not resolve home directory for caller $SUDO_USER; falling back to \$HOME"
      home="$HOME"
    fi
    # Force defaults from caller's home; ignore root-shell-leaked XDG_*.
    xdg_data="$home/.local/share"
    xdg_config="$home/.config"
  else
    home="$HOME"
    xdg_data="${XDG_DATA_HOME:-$home/.local/share}"
    xdg_config="${XDG_CONFIG_HOME:-$home/.config}"
  fi

  local target=""
  case "$shell" in
    bash)
      target="$xdg_data/bash-completion/completions/dcg"
      ;;
    zsh)
      target="$xdg_data/zsh/site-functions/_dcg"
      ;;
    fish)
      target="$xdg_config/fish/completions/dcg.fish"
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

    # When the installer is running as root under sudo, the directory tree we
    # just (potentially) created and the completion file itself are owned by
    # root. The caller's shell loads completions as the caller, not as root —
    # ownership matters for any tooling that later re-writes these paths
    # (next dcg upgrade, package manager hooks). Hand the path back to them.
    if [ "$running_sudo" -eq 1 ]; then
      local caller_group
      caller_group=$(id -gn "$SUDO_USER" 2>/dev/null || printf '%s' "$SUDO_USER")
      chown "$SUDO_USER:$caller_group" "$target" 2>/dev/null || true
      # Walk up from the target's directory to (but not past) the caller's
      # $HOME, chowning anything we just created. Don't recurse into
      # pre-existing trees — that could clobber legitimate ownership of
      # files we didn't write.
      local dir
      dir=$(dirname "$target")
      while [ "$dir" != "$home" ] && [ "$dir" != "/" ] && [ -n "$dir" ]; do
        chown "$SUDO_USER:$caller_group" "$dir" 2>/dev/null || true
        dir=$(dirname "$dir")
      done
    fi

    ok "Installed $shell completions to $target"
    return 0
  fi

  warn "Failed to install $shell completions"
  return 1
}

maybe_install_completions() {
  local shell=""
  if ! shell=$(detect_default_shell); then
    # Distinguish the "running as root with no caller to attribute" case
    # (e.g. logged in directly as root, no sudo) from "user has an exotic
    # shell we don't generate completions for" — the remediation differs.
    if [ "${EUID:-$(id -u)}" -eq 0 ] && [ -z "${SUDO_USER:-}" ]; then
      info "Shell completions: skipped (no caller user detected; install as a regular user or via sudo)"
    else
      info "Shell completions: skipped (unsupported login shell; bash/zsh/fish only)"
    fi
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
    if have_tty; then
      if ! ask_yn "Install Rust nightly via rustup? (y/N):" "n"; then
        warn "Skipping rustup install"
        return 0
      fi
    else
      # No operator terminal: honor the documented (y/N) default and do NOT
      # install rustup unattended (#251).
      warn "Skipping rustup install (no TTY to confirm; the default answer is No)"
      info "Install a Rust nightly toolchain yourself (https://rustup.rs), or re-run the installer from a terminal to be prompted"
      return 0
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
    err "No SHA256 tool found (sha256sum or shasum); refusing unverified installation"
    return 1
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

# Verify the release's long-lived minisign signature (best-effort by default).
# A present signature is always verified when minisign is available; a bad
# signature is always fatal. --require-minisign additionally makes a missing
# sidecar or missing verifier fatal. SHA256 remains mandatory and runs first.
verify_minisign_signature() {
  local file="$1"
  local artifact_url="$2"
  local minisign_bin=""
  local minisign_public_key="$MINISIGN_PUBLIC_KEY"
  local minisign_key_id="$MINISIGN_KEY_ID"
  local signature_url="${MINISIGN_SIGNATURE_URL:-${artifact_url}.minisig}"
  local signature_file="$TMP/artifact.minisig"

  case "${VERSION:-}" in
    v0.6.7|0.6.7)
      minisign_public_key="$LEGACY_MINISIGN_PUBLIC_KEY"
      minisign_key_id="$LEGACY_MINISIGN_KEY_ID"
      ;;
  esac

  info "Fetching minisign signature from ${signature_url}"
  if ! curl -fsSL "$signature_url" -o "$signature_file"; then
    if [ "$REQUIRE_MINISIGN" -eq 1 ]; then
      err "Required minisign signature could not be fetched: ${signature_url}"
      return 1
    fi
    warn "Minisign signature not found; continuing after mandatory checksum verification"
    return 0
  fi

  # Strict mode must reach a real executable from PATH, never a shell function
  # or alias that can claim success without performing cryptographic work.
  minisign_bin=$(type -P minisign 2>/dev/null || true)
  if [ -z "$minisign_bin" ] || [ ! -x "$minisign_bin" ]; then
    if [ "$REQUIRE_MINISIGN" -eq 1 ]; then
      err "minisign is required but was not found on PATH"
      return 1
    fi
    warn "minisign not found; signature is present but cannot be verified"
    return 0
  fi

  if ! "$minisign_bin" -Vm "$file" -x "$signature_file" -P "$minisign_public_key"; then
    err "Minisign verification failed (expected key ID ${minisign_key_id})"
    return 1
  fi

  ok "Signature verified (minisign key ${minisign_key_id})"
  return 0
}

# Return success only for cosign releases that contain the repaired bundle
# verification logic from CVE-2026-22703 (>=2.6.2 or >=3.0.4).
cosign_version_is_patched() {
  local cosign_bin="$1"
  local version_json=""
  local version=""
  local major=""
  local minor=""
  local patch=""

  version_json=$("$cosign_bin" version --json 2>/dev/null) || return 1
  version=$(printf '%s\n' "$version_json" |
    sed -nE 's/.*"gitVersion"[[:space:]]*:[[:space:]]*"v([0-9]+)\.([0-9]+)\.([0-9]+)".*/\1.\2.\3/p' |
    head -n 1)
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  IFS=. read -r major minor patch <<< "$version"

  if (( major > 3 )); then
    return 0
  fi
  if (( major == 3 )); then
    (( minor > 0 || (minor == 0 && patch >= 4) ))
    return
  fi
  if (( major == 2 )); then
    (( minor > 6 || (minor == 6 && patch >= 2) ))
    return
  fi
  return 1
}

# Verify Sigstore/cosign bundle for a file (best-effort).
# Usage: verify_sigstore_bundle <file> <artifact_url>
# Returns 0 on success or when verification is skipped, 1 on verification failure.
verify_sigstore_bundle() {
  local file="$1"
  local artifact_url="$2"
  local cosign_bin=""

  cosign_bin=$(type -P cosign 2>/dev/null || true)
  if [ -z "$cosign_bin" ] || [ ! -x "$cosign_bin" ]; then
    warn "cosign not found; skipping signature verification (install cosign for stronger authenticity checks)"
    return 0
  fi

  local bundle_url="$SIGSTORE_BUNDLE_URL"
  if [ -z "$bundle_url" ]; then
    bundle_url="${artifact_url}.sigstore.json"
  fi

  local bundle_file
  bundle_file="$TMP/$(basename "$bundle_url")"
  info "Fetching sigstore bundle from ${bundle_url}"
  if ! curl -fsSL "$bundle_url" -o "$bundle_file"; then
    warn "Sigstore bundle not found; skipping signature verification"
    return 0
  fi

  if ! cosign_version_is_patched "$cosign_bin"; then
    warn "cosign is missing required bundle-verification security fixes (need >=2.6.2 or >=3.0.4); skipping signature verification (checksum already verified)"
    return 0
  fi

  local -a bundle_format_args=()
  if "$cosign_bin" verify-blob --help 2>/dev/null | grep -q -- "--new-bundle-format"; then
    bundle_format_args+=(--new-bundle-format)
  fi

  local cosign_public_key_file="$TMP/dcg-cosign-release.pub"
  printf '%s\n' "$COSIGN_RELEASE_PUBLIC_KEY" > "$cosign_public_key_file"

  # Manual/DSR releases use the pinned self-managed key. Workflow releases use
  # a Fulcio certificate bound to this repository's dist.yml identity.
  if "$cosign_bin" verify-blob \
    ${bundle_format_args[@]+"${bundle_format_args[@]}"} \
    --bundle "$bundle_file" \
    --key "$cosign_public_key_file" \
    "$file" >/dev/null 2>&1; then
    ok "Signature verified (cosign local release key)"
    return 0
  fi

  if ! "$cosign_bin" verify-blob \
    ${bundle_format_args[@]+"${bundle_format_args[@]}"} \
    --bundle "$bundle_file" \
    --certificate-identity-regexp "$COSIGN_IDENTITY_RE" \
    --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
    "$file"; then
    err "Sigstore bundle failed verification under both pinned release trust roots"
    return 1
  fi

  ok "Signature verified (cosign GitHub Actions identity)"
  return 0
}

usage() {
  cat <<EOFU
Usage: install.sh [--version vX.Y.Z] [--dest DIR] [--system] [--easy-mode] [--verify] \\
                  [--artifact-url URL] [--checksum HEX] [--checksum-url URL] [--quiet] \\
                  [--minisign-url URL] [--require-minisign] [--offline] [--no-gum] \\
                  [--no-configure] [--no-verify] [--force]

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
  --minisign-url URL Override the adjacent .minisig URL (supports file://)
  --require-minisign Require a valid .minisig and the minisign verifier
  --no-verify        Skip checksum + signature verification (for testing only)
  --force            Force reinstall even if same version is installed
EOFU
}

require_option_value() {
  local option="$1"
  local value="${2:-}"

  if [ -z "$value" ] || [[ "$value" == -* ]]; then
    err "$option requires a value"
    usage
    exit 2
  fi
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version) require_option_value "$1" "${2:-}"; VERSION="$2"; shift 2;;
    --dest) require_option_value "$1" "${2:-}"; DEST="$2"; shift 2;;
    --system) DEST="/usr/local/bin"; shift;;
    --easy-mode) EASY=1; shift;;
    --verify) VERIFY=1; shift;;
    --artifact-url) require_option_value "$1" "${2:-}"; ARTIFACT_URL="$2"; shift 2;;
    --checksum) require_option_value "$1" "${2:-}"; CHECKSUM="$2"; shift 2;;
    --checksum-url) require_option_value "$1" "${2:-}"; CHECKSUM_URL="$2"; shift 2;;
    --minisign-url) require_option_value "$1" "${2:-}"; MINISIGN_SIGNATURE_URL="$2"; shift 2;;
    --require-minisign) REQUIRE_MINISIGN=1; shift;;
    --from-source) FROM_SOURCE=1; shift;;
    --quiet|-q) QUIET=1; shift;;
    --offline) OFFLINE=1; shift;;
    --no-gum) NO_GUM=1; shift;;
    --no-configure) NO_CONFIGURE=1; shift;;
    --no-verify) NO_CHECKSUM=1; shift;;
    --force) FORCE_INSTALL=1; shift;;
    -h|--help) usage; exit 0;;
    *) err "Unknown option: $1"; usage; exit 2;;
  esac
done

if [ "$NO_CHECKSUM" -eq 1 ] && [ "$REQUIRE_MINISIGN" -eq 1 ]; then
  err "--no-verify and --require-minisign are mutually exclusive"
  exit 2
fi
if [ "$FROM_SOURCE" -eq 1 ] && [ "$REQUIRE_MINISIGN" -eq 1 ]; then
  err "--require-minisign authenticates release artifacts and cannot be used with --from-source"
  exit 2
fi

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

# Ensure the destination directory hierarchy exists before preflight checks
# (fixes issue #39: ~/.local/bin may not exist on fresh systems)
mkdir -p "$DEST" 2>/dev/null || true

preflight_checks

# Check if already at target version (skip download if so, unless --force)
if [ "$FORCE_INSTALL" -eq 0 ] && [ "$REQUIRE_MINISIGN" -eq 0 ] && check_installed_version "$VERSION"; then
  assert_installed_version "$VERSION" || exit 1
  ok "dcg $VERSION is already installed at $DEST/dcg"
  info "Use --force to reinstall"
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
    if [ "$REQUIRE_MINISIGN" -eq 1 ]; then
      err "Artifact download failed; refusing an unauthenticated source fallback under --require-minisign"
      exit 1
    fi
    warn "Artifact download failed; falling back to build-from-source"
    FROM_SOURCE=1
  fi
fi

if [ "$FROM_SOURCE" -eq 1 ] && [ "$REQUIRE_MINISIGN" -eq 1 ]; then
  err "No signed release artifact is available for this platform under --require-minisign"
  exit 1
fi

if [ "$FROM_SOURCE" -eq 1 ]; then
  info "Building from source (requires git, rust nightly)"
  ensure_rust
  clone_source_tree "$TMP/src"
  (cd "$TMP/src" && cargo build --release)
  BIN="$TMP/src/target/release/dcg"
  [ -x "$BIN" ] || { err "Build failed"; exit 1; }
  install -m 0755 "$BIN" "$DEST/dcg"
  ok "Installed to $DEST/dcg (source build)"
  assert_installed_version "$VERSION" || exit 1
  maybe_add_path
  if [ "$VERIFY" -eq 1 ]; then
    run_install_self_test || exit 1
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

  if ! verify_minisign_signature "$TMP/$TAR" "$URL"; then
    err "Installation aborted due to minisign verification failure"
    exit 1
  fi

  if ! verify_sigstore_bundle "$TMP/$TAR" "$URL"; then
    err "Signature verification failed"
    err "The downloaded file may be corrupted or tampered with."
    exit 1
  fi
fi

info "Extracting"
ARCHIVE_MEMBERS=$(tar -tf "$TMP/$TAR") || { err "Cannot list release archive"; exit 1; }
ARCHIVE_MEMBER_TYPE=$(tar -tvf "$TMP/$TAR" | cut -c1) || { err "Cannot inspect release archive"; exit 1; }
if [ "$ARCHIVE_MEMBERS" != "dcg" ] || [ "$ARCHIVE_MEMBER_TYPE" != "-" ]; then
  err "Release archive must contain exactly one root-level regular member named dcg"
  exit 1
fi
BIN="$TMP/dcg.extracted"
tar -xOf "$TMP/$TAR" dcg > "$BIN" || { err "Cannot stream dcg from release archive"; exit 1; }
[ -s "$BIN" ] || { err "Release archive contained an empty dcg binary"; exit 1; }
chmod 0755 "$BIN"
install -m 0755 "$BIN" "$DEST/dcg"
ok "Installed to $DEST/dcg"
assert_installed_version "$VERSION" || exit 1
maybe_add_path

if [ "$VERIFY" -eq 1 ]; then
  run_install_self_test || exit 1
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
  local dir
  dir=$(dirname "$loc")

  info "Removing predecessor hook: $loc"

  # Create backup
  local backup
  backup="${loc}.bak.$(date +%Y%m%d%H%M%S)"
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
CODEX_SETTINGS="$HOME/.codex/hooks.json"
CURSOR_SETTINGS_MAC="$HOME/Library/Application Support/Cursor/User/settings.json"
CURSOR_SETTINGS_LINUX="$HOME/.config/Cursor/User/settings.json"
CURSOR_HOOKS_JSON="$HOME/.cursor/hooks.json"
CURSOR_HOOK_DIR="$HOME/.cursor/hooks"
CURSOR_HOOK_SCRIPT="$CURSOR_HOOK_DIR/dcg-pre-shell.py"
# Hermes reads its data root from $HERMES_HOME when set (native-Windows
# installs set it; Unix users may too), defaulting to ~/.hermes on Unix.
HERMES_CONFIG="${HERMES_HOME:-$HOME/.hermes}/config.yaml"
POSIT_ASSISTANT_SETTINGS="$HOME/.posit/assistant/settings.json"
AUTO_CONFIGURED=0

# Detailed tracking for what was configured
CLAUDE_STATUS=""  # "created"|"merged"|"already"|"failed"
CLAUDE_FAILURE_REASON=""
GEMINI_STATUS=""  # "created"|"merged"|"already"|"failed"|"skipped"
AIDER_STATUS=""   # "created"|"merged"|"already"|"skipped"|"failed"
CONTINUE_STATUS="" # "unsupported"|"skipped"
CODEX_STATUS=""   # "created"|"merged"|"already"|"skipped"|"failed"
CODEX_BACKUP=""
CODEX_FAILURE_REASON=""
GEMINI_FAILURE_REASON=""
CURSOR_STATUS=""  # "created"|"merged"|"already"|"skipped"|"failed"|"conflict"
CURSOR_FAILURE_REASON=""
COPILOT_STATUS="" # "created"|"merged"|"already"|"skipped"|"failed"
HERMES_STATUS=""  # "created"|"merged"|"already"|"skipped"|"failed"
HERMES_FAILURE_REASON=""
POSIT_ASSISTANT_STATUS=""  # "created"|"merged"|"already"|"skipped"|"failed"
POSIT_ASSISTANT_FAILURE_REASON=""
OPENCODE_STATUS=""  # "created"|"merged"|"skipped"|"failed"|"conflict"
OPENCODE_FAILURE_REASON=""
POSIT_ASSISTANT_BACKUP=""
CLAUDE_BACKUP=""
GEMINI_BACKUP=""
AIDER_BACKUP=""
CURSOR_BACKUP=""
COPILOT_BACKUP=""
HERMES_BACKUP=""
COPILOT_HOOK_FILE=""
COPILOT_FAILURE_REASON=""

configure_claude_code() {
  local settings_file="$1"
  local cleanup_predecessor="$2"
  CLAUDE_FAILURE_REASON=""
  # Default to cleaning up predecessor if not specified or empty
  [ -z "$cleanup_predecessor" ] && cleanup_predecessor=1
  local settings_dir
  settings_dir=$(dirname "$settings_file")

  # Always create the config directory if it doesn't exist
  if [ ! -d "$settings_dir" ]; then
    mkdir -p "$settings_dir"
  fi

  if [ -f "$settings_file" ]; then
    # Check if the exact current dcg hook is already configured. A stale dcg
    # path, duplicate dcg entry, or predecessor hook that should be cleaned
    # must fall through to the merge path.
    if command -v python3 >/dev/null 2>&1; then
      local claude_hook_state
      claude_hook_state=$(python3 - "$settings_file" "$DEST/dcg" "$cleanup_predecessor" <<'PYEOF'
import json
import os
import shlex
import sys

settings_file = sys.argv[1]
dcg_path = sys.argv[2]
cleanup_predecessor = sys.argv[3] == "1" if len(sys.argv) > 3 else True

def is_dcg_command(cmd):
    if not isinstance(cmd, str) or not cmd:
        return False
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return False
    if not tokens:
        return False
    name = os.path.basename(tokens[0])
    if name.endswith('.exe'):
        name = name[:-4]
    return name == 'dcg'

try:
    with open(settings_file, 'r') as f:
        raw_settings = f.read()
except IOError:
    print("merge")
    raise SystemExit(0)

if raw_settings.strip():
    try:
        settings = json.loads(raw_settings)
    except (ValueError, json.JSONDecodeError):
        print("invalid")
        raise SystemExit(0)
else:
    settings = {}

if not isinstance(settings, dict):
    print("invalid")
    raise SystemExit(0)

hooks_obj = settings.get("hooks", {})
if not isinstance(hooks_obj, dict):
    print("invalid")
    raise SystemExit(0)

pre_tool_use = hooks_obj.get("PreToolUse", [])
if not isinstance(pre_tool_use, list):
    print("invalid")
    raise SystemExit(0)

# Claude Code matchers are regexes over the tool name. `Bash` alone leaves the
# native-Windows `PowerShell` tool completely unguarded (issue #226), so the
# canonical dcg registration covers both. A dcg hook still sitting under the
# legacy `Bash`-only matcher must be migrated, not left beside the new entry.
CANONICAL_MATCHER = "Bash|PowerShell"
LEGACY_MATCHERS = ("Bash",)

dcg_commands = []
predecessor_present = False
for entry in pre_tool_use:
    if not isinstance(entry, dict):
        continue
    matcher = entry.get("matcher")
    if matcher != CANONICAL_MATCHER and matcher not in LEGACY_MATCHERS:
        continue
    hooks = entry.get("hooks", [])
    if not isinstance(hooks, list):
        print("invalid")
        raise SystemExit(0)
    for hook in hooks:
        if not isinstance(hook, dict):
            continue
        cmd = hook.get("command")
        if isinstance(cmd, str) and "git_safety_guard" in cmd:
            predecessor_present = True
        if is_dcg_command(cmd):
            dcg_commands.append(cmd)

first_entry = pre_tool_use[0] if pre_tool_use else None
canonical_entry_is_first = False
if isinstance(first_entry, dict) and first_entry.get("matcher") == CANONICAL_MATCHER:
    first_hooks = first_entry.get("hooks", [])
    if isinstance(first_hooks, list) and first_hooks:
        first_hook = first_hooks[0]
        if isinstance(first_hook, dict):
            canonical_entry_is_first = first_hook.get("command") == dcg_path

if cleanup_predecessor and predecessor_present:
    print("merge")
elif dcg_commands == [dcg_path] and canonical_entry_is_first:
    print("already")
else:
    print("merge")
PYEOF
)
      if [ "$claude_hook_state" = "invalid" ]; then
        CLAUDE_STATUS="failed"
        CLAUDE_FAILURE_REASON="existing settings.json is invalid or has malformed hooks; left unchanged"
        warn "Claude Code settings.json is invalid or has malformed hooks; leaving it unchanged: $settings_file"
        return 0
      fi
      if [ "$claude_hook_state" = "already" ]; then
        CLAUDE_STATUS="already"
        AUTO_CONFIGURED=1
        return 0
      fi
    else
      # Fallback for systems without python3; the merge path below is also
      # python-backed. Only trust the exact hook path when it is already the
      # first command hook under the canonical `Bash|PowerShell` matcher — a
      # legacy `Bash`-only registration must fall through to the merge so the
      # native-Windows PowerShell tool stops being unguarded (issue #226).
      local dcg_hook_regex
      local compact_settings
      local dcg_command_marker
      local after_first_dcg
      dcg_hook_regex=$(printf '%s' "$DEST/dcg" | sed 's/[][\\.^$*+?{}()|]/\\&/g')
      # Strip ALL whitespace (including newlines) with tr: the GNU sed idiom
      # `:a;N;$!ba;...` is not portable — BSD sed (macOS) parses it as one
      # giant label, changes nothing, and a pretty-printed already-configured
      # settings.json was never recognized here.
      compact_settings=$(LC_ALL=C tr -d '[:space:]' < "$settings_file" 2>/dev/null || true)
      dcg_command_marker="\"command\":\"$DEST/dcg\""
      after_first_dcg="${compact_settings#*"$dcg_command_marker"}"
      if [ "$after_first_dcg" != "$compact_settings" ] &&
         [ "${after_first_dcg#*"$dcg_command_marker"}" = "$after_first_dcg" ] &&
         printf '%s\n' "$compact_settings" |
           grep -Eq "\"matcher\":\"Bash\\|PowerShell\",\"hooks\":\\[\\{[^}]*\"command\":\"$dcg_hook_regex\""; then
        CLAUDE_STATUS="already"
        AUTO_CONFIGURED=1
        return 0
      fi
    fi

    # Settings file exists, need to merge
    CLAUDE_BACKUP="${settings_file}.bak.$(date +%Y%m%d%H%M%S)"
    cp "$settings_file" "$CLAUDE_BACKUP"

    if command -v python3 >/dev/null 2>&1; then
      if python3 - "$settings_file" "$DEST/dcg" "$cleanup_predecessor" <<'PYEOF'
import json
import os
import shlex
import sys

settings_file = sys.argv[1]
dcg_path = sys.argv[2]
cleanup_predecessor = sys.argv[3] == "1" if len(sys.argv) > 3 else True

def is_dcg_command(cmd):
    """True iff `cmd` invokes the dcg binary (basename match, not substring).

    Without this, a substring check `'dcg' in cmd` would match unrelated
    user tools whose path or name happens to contain "dcg" — for example
    /opt/dcgrep/bin/scan, ~/.local/bin/dcgworkflow, my-dcg-helper.sh —
    causing the installer to skip merge ("dcg already there!") or, worse,
    causing the uninstaller to delete those entries on its --purge run.
    """
    if not cmd:
        return False
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        # Unparseable shell command (mismatched quotes, etc.) — treat as
        # NOT-dcg so we don't accidentally drop or replace it.
        return False
    if not tokens:
        return False
    name = os.path.basename(tokens[0])
    if name.endswith('.exe'):
        name = name[:-4]
    return name == 'dcg'

raw_settings = ""
try:
    with open(settings_file, 'r') as f:
        raw_settings = f.read()
except IOError:
    settings = {}

if raw_settings.strip():
    try:
        settings = json.loads(raw_settings)
    except (ValueError, json.JSONDecodeError):
        print(f"invalid Claude Code settings.json: {settings_file}", file=sys.stderr)
        raise SystemExit(1)
else:
    settings = {}

if not isinstance(settings, dict):
    print(f"Claude Code settings.json must contain a JSON object: {settings_file}", file=sys.stderr)
    raise SystemExit(1)

# Ensure hooks structure exists
if 'hooks' not in settings:
    settings['hooks'] = {}
elif not isinstance(settings['hooks'], dict):
    print(f"Claude Code settings.json hooks must contain a JSON object: {settings_file}", file=sys.stderr)
    raise SystemExit(1)
if 'PreToolUse' not in settings['hooks']:
    settings['hooks']['PreToolUse'] = []
elif not isinstance(settings['hooks']['PreToolUse'], list):
    print(f"Claude Code settings.json PreToolUse must contain a list: {settings_file}", file=sys.stderr)
    raise SystemExit(1)

# Claude Code matchers are regexes over the tool name. Registering only `Bash`
# leaves the native-Windows `PowerShell` tool unguarded (issue #226), so dcg
# owns a single `Bash|PowerShell` entry hoisted to the front of PreToolUse.
CANONICAL_MATCHER = "Bash|PowerShell"
LEGACY_MATCHERS = ("Bash",)

# First pass: strip dcg (and, when asked, its predecessor) out of every entry
# dcg may previously have owned. Other hooks keep their own matcher so their
# scope is never silently widened; entries emptied by the strip are dropped.
new_pre_tool_use = []
predecessor_removed = False

for entry in settings['hooks']['PreToolUse']:
    if not isinstance(entry, dict):
        new_pre_tool_use.append(entry)
        continue
    matcher = entry.get('matcher')
    if matcher != CANONICAL_MATCHER and matcher not in LEGACY_MATCHERS:
        new_pre_tool_use.append(entry)
        continue
    if 'hooks' not in entry:
        new_pre_tool_use.append(entry)
        continue
    if not isinstance(entry['hooks'], list):
        print(f"Claude Code {matcher} matcher hooks must contain a list: {settings_file}", file=sys.stderr)
        raise SystemExit(1)
    kept_hooks = []
    for hook in entry['hooks']:
        if isinstance(hook, dict) and 'command' in hook:
            cmd = hook.get('command', '')
            if 'git_safety_guard' in cmd:
                if cleanup_predecessor:
                    predecessor_removed = True
                    continue  # Skip predecessor
                kept_hooks.append(hook)  # Keep predecessor
            elif not is_dcg_command(cmd):  # Don't duplicate dcg
                kept_hooks.append(hook)
        else:
            kept_hooks.append(hook)
    if kept_hooks:
        entry['hooks'] = kept_hooks
        new_pre_tool_use.append(entry)

# Add exactly one current dcg hook, first, so it runs before any other hook.
# Existing dcg hooks, including stale paths, duplicates, and legacy `Bash`-only
# registrations, were collapsed above.
new_pre_tool_use.insert(0, {
    "matcher": CANONICAL_MATCHER,
    "hooks": [{"type": "command", "command": dcg_path}]
})

settings['hooks']['PreToolUse'] = new_pre_tool_use

with open(settings_file, 'w') as f:
    json.dump(settings, f, indent=2)

if predecessor_removed:
    print("PREDECESSOR_CLEANED", file=sys.stderr)
PYEOF
      then
        CLAUDE_STATUS="merged"
        AUTO_CONFIGURED=1
      else
        mv "$CLAUDE_BACKUP" "$settings_file" 2>/dev/null || true
        CLAUDE_STATUS="failed"
        CLAUDE_FAILURE_REASON="merge failed; restored backup"
        CLAUDE_BACKUP=""
      fi
    else
      # python3 not available - remove unnecessary backup
      rm -f "$CLAUDE_BACKUP" 2>/dev/null || true
      CLAUDE_BACKUP=""
      CLAUDE_STATUS="failed"
      CLAUDE_FAILURE_REASON="python3 required for merge"
      return 1
    fi
  else
    # Create new settings file
    cat > "$settings_file" <<EOFSET
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell",
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
  local settings_dir
  settings_dir=$(dirname "$settings_file")
  GEMINI_FAILURE_REASON=""
  GEMINI_BACKUP=""

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
    # Check whether the exact current dcg hook is already configured. Do not
    # trust a raw substring match: unrelated commands can contain "dcg" in
    # their path/name and would otherwise suppress Gemini hook installation.
    if command -v python3 >/dev/null 2>&1; then
      local gemini_hook_state
      gemini_hook_state=$(python3 - "$settings_file" "$DEST/dcg" <<'PYEOF'
import json
import os
import shlex
import sys

settings_file = sys.argv[1]
dcg_path = sys.argv[2]

def is_dcg_command(cmd):
    if not isinstance(cmd, str) or not cmd:
        return False
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return False
    if not tokens:
        return False
    name = os.path.basename(tokens[0])
    if name.endswith('.exe'):
        name = name[:-4]
    return name == 'dcg'

try:
    with open(settings_file, 'r') as f:
        settings = json.load(f)
except (IOError, ValueError, json.JSONDecodeError):
    print("invalid")
    raise SystemExit(0)

if not isinstance(settings, dict):
    print("invalid")
    raise SystemExit(0)

hooks_obj = settings.get("hooks", {})
if not isinstance(hooks_obj, dict):
    print("invalid")
    raise SystemExit(0)

before_tool = hooks_obj.get("BeforeTool", [])
if not isinstance(before_tool, list):
    print("invalid")
    raise SystemExit(0)

dcg_commands = []
first_shell_hook_command = None
first_shell_matcher_seen = False
for entry in before_tool:
    if not isinstance(entry, dict) or entry.get("matcher") != "run_shell_command":
        continue
    hooks = entry.get("hooks", [])
    if not isinstance(hooks, list):
        print("invalid")
        raise SystemExit(0)
    if not first_shell_matcher_seen:
        first_shell_matcher_seen = True
        first_hook = hooks[0] if hooks else None
        if isinstance(first_hook, dict):
            first_shell_hook_command = first_hook.get("command")
    for hook in hooks:
        if isinstance(hook, dict) and is_dcg_command(hook.get("command")):
            dcg_commands.append(hook.get("command"))

if dcg_commands == [dcg_path] and first_shell_hook_command == dcg_path:
    print("already")
else:
    print("merge")
PYEOF
)
      if [ "$gemini_hook_state" = "invalid" ]; then
        GEMINI_STATUS="failed"
        GEMINI_FAILURE_REASON="existing settings.json is invalid or has malformed hooks; left unchanged"
        warn "Gemini settings.json is invalid or has malformed hooks; leaving it unchanged: $settings_file"
        return 0
      fi
      if [ "$gemini_hook_state" = "already" ]; then
        GEMINI_STATUS="already"
        AUTO_CONFIGURED=1
        return 0
      fi
    else
      # Fallback for systems without python3; the merge path below also needs
      # python3, so only claim "already" when the exact current hook is first.
      local dcg_hook_regex
      local compact_settings
      local dcg_command_marker
      local after_first_dcg
      dcg_hook_regex=$(printf '%s' "$DEST/dcg" | sed 's/[][\\.^$*+?{}()|]/\\&/g')
      # tr, not GNU sed `:a;N;$!ba;...` — see the configure_claude_code
      # fallback above for why (BSD sed compatibility).
      compact_settings=$(LC_ALL=C tr -d '[:space:]' < "$settings_file" 2>/dev/null || true)
      dcg_command_marker="\"command\":\"$DEST/dcg\""
      after_first_dcg="${compact_settings#*"$dcg_command_marker"}"
      if [ "$after_first_dcg" != "$compact_settings" ] &&
         [ "${after_first_dcg#*"$dcg_command_marker"}" = "$after_first_dcg" ] &&
         printf '%s\n' "$compact_settings" |
           grep -Eq "\"matcher\":\"run_shell_command\",\"hooks\":\\[\\{[^}]*\"command\":\"$dcg_hook_regex\""; then
        GEMINI_STATUS="already"
        AUTO_CONFIGURED=1
        return 0
      fi
    fi

    GEMINI_BACKUP="${settings_file}.bak.$(date +%Y%m%d%H%M%S)"
    cp "$settings_file" "$GEMINI_BACKUP"

    if command -v python3 >/dev/null 2>&1; then
      if python3 - "$settings_file" "$DEST/dcg" <<'PYEOF'
import json
import os
import shlex
import sys

settings_file = sys.argv[1]
dcg_path = sys.argv[2]

def is_dcg_command(cmd):
    """True iff `cmd` invokes the dcg binary (basename match, not substring)."""
    if not cmd:
        return False
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return False
    if not tokens:
        return False
    name = os.path.basename(tokens[0])
    if name.endswith('.exe'):
        name = name[:-4]
    return name == 'dcg'

try:
    with open(settings_file, 'r') as f:
        settings = json.load(f)
except (IOError, ValueError, json.JSONDecodeError):
    print(f"invalid Gemini settings.json: {settings_file}", file=sys.stderr)
    raise SystemExit(1)

if not isinstance(settings, dict):
    print(f"Gemini settings.json must contain a JSON object: {settings_file}", file=sys.stderr)
    raise SystemExit(1)

# Gemini CLI uses BeforeTool instead of PreToolUse
if 'hooks' not in settings:
    settings['hooks'] = {}
elif not isinstance(settings['hooks'], dict):
    print(f"Gemini settings.json hooks must contain a JSON object: {settings_file}", file=sys.stderr)
    raise SystemExit(1)
if 'BeforeTool' not in settings['hooks']:
    settings['hooks']['BeforeTool'] = []
elif not isinstance(settings['hooks']['BeforeTool'], list):
    print(f"Gemini settings.json BeforeTool must contain a list: {settings_file}", file=sys.stderr)
    raise SystemExit(1)

dcg_hook = {"name": "dcg", "type": "command", "command": dcg_path, "timeout": 5000}

shell_hooks = []
new_before_tool = []
shell_sequential = None

for entry in settings['hooks']['BeforeTool']:
    if isinstance(entry, dict) and entry.get('matcher') == 'run_shell_command':
        if isinstance(entry.get('sequential'), bool):
            shell_sequential = (
                entry['sequential']
                if shell_sequential is None
                else shell_sequential or entry['sequential']
            )
        hooks = entry.get('hooks', [])
        if not isinstance(hooks, list):
            print(f"Gemini run_shell_command hooks must contain a list: {settings_file}", file=sys.stderr)
            raise SystemExit(1)
        for hook in hooks:
            if isinstance(hook, dict) and is_dcg_command(hook.get('command', '')):
                continue
            shell_hooks.append(hook)
    else:
        new_before_tool.append(entry)

shell_hooks.insert(0, dcg_hook)
shell_entry = {
    "matcher": "run_shell_command",
    "hooks": shell_hooks
}
if shell_sequential is not None:
    shell_entry["sequential"] = shell_sequential
new_before_tool.insert(0, shell_entry)
settings['hooks']['BeforeTool'] = new_before_tool

with open(settings_file, 'w') as f:
    json.dump(settings, f, indent=2)
PYEOF
      then
        GEMINI_STATUS="merged"
        AUTO_CONFIGURED=1
      else
        mv "$GEMINI_BACKUP" "$settings_file" 2>/dev/null || true
        GEMINI_STATUS="failed"
        GEMINI_FAILURE_REASON="merge failed; restored backup"
        GEMINI_BACKUP=""
      fi
    else
      # python3 not available - remove unnecessary backup
      rm -f "$GEMINI_BACKUP" 2>/dev/null || true
      GEMINI_BACKUP=""
      GEMINI_STATUS="failed"
      GEMINI_FAILURE_REASON="python3 required for merge"
      return 0
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
      {
        printf '\n'
        printf '%s\n' "# Added by dcg installer - enables git hooks so dcg pre-commit can run"
        printf '%s\n' "git-commit-verify: true"
      } >> "$settings_file"
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
  # Codex 0.125.0 marked PreToolUse hooks as STABLE (codex_hooks feature is
  # default-enabled). Hooks are loaded from either ~/.codex/hooks.json or
  # [[hooks.PreToolUse]] tables in ~/.codex/config.toml; both files in each
  # config layer are honored. We use hooks.json so install/uninstall touch
  # one dedicated file rather than mutating the user's main config.
  #
  # Wire shape mirrors Claude Code's: stdin carries
  # { tool_name: "Bash", tool_input: { command: "..." },
  #   hook_event_name: "PreToolUse", turn_id, tool_use_id, ... }.
  # Codex's denial parser is strict (#[serde(deny_unknown_fields)] on every
  # output struct in codex-rs/hooks/src/schema.rs), so dcg cannot send its
  # standard hookSpecificOutput here -- the extra fields (allowOnceCode,
  # ruleId, severity, remediation) cause the parser to fail and codex marks
  # the hook as Failed rather than Blocked, letting the destructive command
  # through.
  #
  # dcg disambiguates Codex from Claude Code via the `turn_id` stdin field
  # (codex-rs/hooks/src/schema.rs documents it as "Codex extension"; Claude
  # Code does not send it -- and `tool_use_id` is NOT a usable signal here
  # because Claude Code's PreToolUse stdin includes it too). On Codex
  # payloads dcg switches to codex's documented alternative
  # (codex-rs/hooks/src/events/pre_tool_use.rs): exit code 2 with the deny
  # reason on stderr. The hook config below is therefore unchanged from the
  # Claude Code shape -- the protocol switch is handled inside dcg.
  #
  # Note: The model can still work around this by writing its own script to
  # disk and then running that script, so treat this as a useful guardrail
  # rather than a complete enforcement boundary.
  #
  # See: https://developers.openai.com/codex/hooks

  local settings_file="$CODEX_SETTINGS"
  CODEX_FAILURE_REASON=""
  local settings_dir
  settings_dir=$(dirname "$settings_file")

  # Check if Codex is installed
  local codex_installed=0

  # Check for CLI command
  if command -v codex >/dev/null 2>&1; then
    codex_installed=1
  fi

  # Check for config directory
  if [ -d "$settings_dir" ]; then
    codex_installed=1
  fi

  if [ "$codex_installed" -eq 0 ]; then
    CODEX_STATUS="skipped"
    return 0
  fi

  # Create directory if needed (codex command exists but no config dir yet)
  if [ ! -d "$settings_dir" ]; then
    mkdir -p "$settings_dir"
  fi

  if [ -f "$settings_file" ]; then
    # Check if the exact current dcg hook is already configured. A stale dcg
    # path must still fall through to the merge path so it can be updated.
    if command -v python3 >/dev/null 2>&1; then
      local codex_hook_state
      codex_hook_state=$(python3 - "$settings_file" "$DEST/dcg" <<'PYEOF'
import json
import os
import shlex
import sys

hooks_file = sys.argv[1]
dcg_path = sys.argv[2]

def is_dcg_command(cmd):
    if not isinstance(cmd, str) or not cmd:
        return False
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return False
    if not tokens:
        return False
    name = os.path.basename(tokens[0])
    if name.endswith('.exe'):
        name = name[:-4]
    return name == 'dcg'

try:
    with open(hooks_file, 'r') as f:
        config = json.load(f)
except (IOError, ValueError, json.JSONDecodeError):
    print("invalid")
    raise SystemExit(0)

if not isinstance(config, dict):
    print("invalid")
    raise SystemExit(0)

hooks_obj = config.get("hooks", {})
if "hooks" in config and not isinstance(hooks_obj, dict):
    print("invalid")
    raise SystemExit(0)

pre_tool_use = hooks_obj.get("PreToolUse", [])
if "PreToolUse" in hooks_obj and not isinstance(pre_tool_use, list):
    print("invalid")
    raise SystemExit(0)

dcg_commands = []
first_bash_hook_command = None
first_bash_matcher_seen = False
for entry in pre_tool_use:
    if not isinstance(entry, dict) or entry.get("matcher") != "Bash":
        continue
    hooks = entry.get("hooks", [])
    if not isinstance(hooks, list):
        print("invalid")
        raise SystemExit(0)
    if not first_bash_matcher_seen:
        first_bash_matcher_seen = True
        first_hook = hooks[0] if hooks else None
        if isinstance(first_hook, dict):
            first_bash_hook_command = first_hook.get("command")
    for hook in hooks:
        if isinstance(hook, dict) and is_dcg_command(hook.get("command")):
            dcg_commands.append(hook.get("command"))

if dcg_commands == [dcg_path] and first_bash_hook_command == dcg_path:
    print("already")
else:
    print("merge")
PYEOF
)
      if [ "$codex_hook_state" = "invalid" ]; then
        CODEX_STATUS="failed"
        CODEX_FAILURE_REASON="existing hooks.json is invalid; left unchanged"
        warn "Codex hooks.json is invalid; leaving it unchanged: $settings_file"
        return 0
      fi
      if [ "$codex_hook_state" = "already" ]; then
        CODEX_STATUS="already"
        AUTO_CONFIGURED=1
        return 0
      fi
    fi

    # hooks.json exists, need to merge. Invalid JSON was detected above and is
    # deliberately not repaired here: replacing a hand-edited hooks file would
    # silently discard user configuration.
    CODEX_BACKUP="${settings_file}.bak.$(date +%Y%m%d%H%M%S)"
    cp "$settings_file" "$CODEX_BACKUP"

    if command -v python3 >/dev/null 2>&1; then
      if python3 - "$settings_file" "$DEST/dcg" <<'PYEOF'
import json
import os
import shlex
import sys

hooks_file = sys.argv[1]
dcg_path = sys.argv[2]

def is_dcg_command(cmd):
    """True iff `cmd` invokes the dcg binary (basename match, not substring)."""
    if not cmd:
        return False
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return False
    if not tokens:
        return False
    name = os.path.basename(tokens[0])
    if name.endswith('.exe'):
        name = name[:-4]
    return name == 'dcg'

try:
    with open(hooks_file, 'r') as f:
        config = json.load(f)
except (IOError, ValueError, json.JSONDecodeError):
    print(f"invalid Codex hooks.json: {hooks_file}", file=sys.stderr)
    raise SystemExit(1)

if not isinstance(config, dict):
    print(f"Codex hooks.json must contain a JSON object: {hooks_file}", file=sys.stderr)
    raise SystemExit(1)

# Preserve malformed top-level hook structures instead of replacing them. A
# user may have hand-edited data here; the installer should not discard it.
if 'hooks' not in config:
    config['hooks'] = {}
elif not isinstance(config['hooks'], dict):
    print(f"Codex hooks.json hooks must contain a JSON object: {hooks_file}", file=sys.stderr)
    raise SystemExit(1)

if 'PreToolUse' not in config['hooks']:
    config['hooks']['PreToolUse'] = []
elif not isinstance(config['hooks']['PreToolUse'], list):
    print(f"Codex hooks.json PreToolUse must contain a list: {hooks_file}", file=sys.stderr)
    raise SystemExit(1)

# Look for existing Bash matcher
bash_hooks = []
new_pre_tool_use = []
dcg_seen = False

for entry in config['hooks']['PreToolUse']:
    if not isinstance(entry, dict):
        new_pre_tool_use.append(entry)
    elif entry.get('matcher') == 'Bash':
        hooks = entry.get('hooks', [])
        if not isinstance(hooks, list):
            print(f"Codex Bash matcher hooks must contain a list: {hooks_file}", file=sys.stderr)
            raise SystemExit(1)
        for hook in hooks:
            if isinstance(hook, dict) and 'command' in hook:
                cmd = str(hook.get('command', ''))
                if not is_dcg_command(cmd):  # Don't duplicate dcg
                    bash_hooks.append(hook)
                else:
                    dcg_seen = True
            else:
                bash_hooks.append(hook)
    else:
        new_pre_tool_use.append(entry)

# Add exactly one dcg hook at the beginning. Existing dcg hooks, including stale
# paths or duplicates, are intentionally collapsed here.
dcg_hook = {"type": "command", "command": dcg_path}
if dcg_seen or not any(
    is_dcg_command(h.get('command', ''))
    for h in bash_hooks
    if isinstance(h, dict)
):
    bash_hooks.insert(0, dcg_hook)

# Create consolidated Bash matcher with dcg first
if bash_hooks:
    new_pre_tool_use.insert(0, {
        "matcher": "Bash",
        "hooks": bash_hooks
    })

config['hooks']['PreToolUse'] = new_pre_tool_use

with open(hooks_file, 'w') as f:
    json.dump(config, f, indent=2)
PYEOF
      then
        CODEX_STATUS="merged"
        AUTO_CONFIGURED=1
      else
        mv "$CODEX_BACKUP" "$settings_file" 2>/dev/null || true
        CODEX_STATUS="failed"
        CODEX_FAILURE_REASON="merge failed; restored backup"
        CODEX_BACKUP=""
      fi
    else
      # python3 not available - remove unnecessary backup
      rm -f "$CODEX_BACKUP" 2>/dev/null || true
      CODEX_BACKUP=""
      CODEX_STATUS="failed"
      CODEX_FAILURE_REASON="python3 required for merge"
      return 0
    fi
  else
    # Create new hooks.json file
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
    CODEX_STATUS="created"
    AUTO_CONFIGURED=1
  fi
}

configure_copilot() {
  # GitHub Copilot CLI supports user-level hooks under COPILOT_HOME/hooks (or
  # ~/.copilot/hooks). A destructive-command guard should protect every
  # workspace, so install the dedicated hook globally rather than modifying the
  # current repository (#182).
  #
  # We install/merge a dedicated file at:
  #   ${COPILOT_HOME:-$HOME/.copilot}/hooks/dcg.json
  #
  # containing a preToolUse command hook that executes dcg.

  COPILOT_FAILURE_REASON=""

  local copilot_installed=0
  local copilot_home="${COPILOT_HOME:-$HOME/.copilot}"
  if command -v copilot >/dev/null 2>&1 || [ -d "$copilot_home" ]; then
    copilot_installed=1
  fi

  if [ "$copilot_installed" -eq 0 ]; then
    COPILOT_STATUS="skipped"
    return 0
  fi

  local hook_dir="$copilot_home/hooks"
  local hook_file="$hook_dir/dcg.json"
  COPILOT_HOOK_FILE="$hook_file"

  mkdir -p "$hook_dir"

  if [ -f "$hook_file" ]; then
    # Merge into existing hook file.
    COPILOT_BACKUP="${hook_file}.bak.$(date +%Y%m%d%H%M%S)"
    cp "$hook_file" "$COPILOT_BACKUP"

    if command -v python3 >/dev/null 2>&1; then
      local py_result
      if py_result=$(python3 - "$hook_file" "$DEST/dcg" <<'PYEOF'
import json
import os
import shlex
import sys

hook_file = sys.argv[1]
dcg_path = sys.argv[2]

try:
    with open(hook_file, "r") as f:
        settings = json.load(f)
except (OSError, ValueError, json.JSONDecodeError):
    print(f"invalid Copilot hook file: {hook_file}", file=sys.stderr)
    raise SystemExit(1)

if not isinstance(settings, dict):
    print(f"Copilot hook file must contain a JSON object: {hook_file}", file=sys.stderr)
    raise SystemExit(1)

before = json.dumps(settings, sort_keys=True)

settings["version"] = 1
hooks = settings.setdefault("hooks", {})
if not isinstance(hooks, dict):
    print(f"Copilot hook file hooks must contain a JSON object: {hook_file}", file=sys.stderr)
    raise SystemExit(1)

# Copilot's published hooks schema names the event camelCase `preToolUse`,
# but dcg <= 0.8.0 merged case-sensitively and could leave a PascalCase
# `PreToolUse` (or a duplicate pair) behind. Resolve the key
# case-insensitively, adopt the file's existing spelling, and never create a
# duplicate second key (#253).
pre_tool_keys = [k for k in hooks if k.lower() == "pretooluse"]
for key in pre_tool_keys:
    if not isinstance(hooks[key], list):
        print(f"Copilot hook file {key} must contain a list: {hook_file}", file=sys.stderr)
        raise SystemExit(1)

if not pre_tool_keys:
    pre_tool_key = "preToolUse"
    pre_tool = []
    hooks[pre_tool_key] = pre_tool
elif len(pre_tool_keys) == 1:
    pre_tool_key = pre_tool_keys[0]
    pre_tool = hooks[pre_tool_key]
else:
    # Both casings exist (a file damaged by the old case-sensitive merge):
    # repair into the single canonical camelCase key, carrying over every
    # entry so non-dcg hooks are never dropped. dcg-owned entries are
    # stripped below before the canonical entry is prepended.
    pre_tool_key = "preToolUse"
    pre_tool = []
    for key in pre_tool_keys:
        pre_tool.extend(hooks.pop(key))
    hooks[pre_tool_key] = pre_tool

# The platform fields hold SHELL COMMAND strings, so the binary path is
# double-quoted (shlex-compatible, same convention as configure_posit_assistant)
# — an install path containing spaces would otherwise be word-split at run
# time, and the unquoted form defeats the shlex-based dcg-entry detection
# used for dedupe and uninstall (#253-adjacent).
desired = {
    "type": "command",
    "bash": f'"{dcg_path}"',
    "powershell": f'"{dcg_path}"',
    "cwd": ".",
    "timeoutSec": 30,
}

def command_invokes_dcg(cmd):
    if not isinstance(cmd, str) or not cmd:
        return False
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return False
    if not tokens:
        return False
    name = os.path.basename(tokens[0])
    if name.endswith(".exe"):
        name = name[:-4]
    return name == "dcg"

def strip_dcg_platform_fields(entry):
    if not isinstance(entry, dict):
        return False, [entry]

    cleaned = dict(entry)
    removed = False
    for key in ("bash", "powershell"):
        if command_invokes_dcg(cleaned.get(key)):
            removed = True
            cleaned.pop(key, None)

    if not removed:
        return False, [entry]
    if cleaned.get("bash") or cleaned.get("powershell"):
        return True, [cleaned]
    return True, []

found = False
preserved = []

for entry in pre_tool:
    removed, residual_entries = strip_dcg_platform_fields(entry)
    if removed:
        found = True
    preserved.extend(residual_entries)

next_pre_tool = [desired] + preserved
changed = pre_tool != next_pre_tool
hooks[pre_tool_key] = next_pre_tool

after = json.dumps(settings, sort_keys=True)
if not changed and before == after:
    print("UNCHANGED")
    raise SystemExit(0)

with open(hook_file, "w") as f:
    json.dump(settings, f, indent=2)

if found:
    print("UPDATED")
else:
    print("ADDED")
PYEOF
      ); then
        case "$py_result" in
          UNCHANGED)
            COPILOT_STATUS="already"
            rm -f "$COPILOT_BACKUP" 2>/dev/null || true
            COPILOT_BACKUP=""
            ;;
          UPDATED|ADDED)
            COPILOT_STATUS="merged"
            AUTO_CONFIGURED=1
            ;;
          *)
            COPILOT_STATUS="merged"
            AUTO_CONFIGURED=1
            ;;
        esac
      else
        mv "$COPILOT_BACKUP" "$hook_file" 2>/dev/null || true
        COPILOT_STATUS="failed"
        COPILOT_FAILURE_REASON="existing hook file is invalid or has malformed hooks; left unchanged"
        COPILOT_BACKUP=""
        return 1
      fi
    else
      # python3 not available - remove unnecessary backup
      rm -f "$COPILOT_BACKUP" 2>/dev/null || true
      COPILOT_BACKUP=""
      COPILOT_STATUS="failed"
      COPILOT_FAILURE_REASON="python3 required for merge"
      return 1
    fi
  else
    # Create new dedicated dcg hook file. The platform fields are shell
    # command strings, so the binary path is double-quoted (same convention
    # as configure_posit_assistant) to survive an install path with spaces.
    cat > "$hook_file" <<EOFSET
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "type": "command",
        "bash": "\\"$DEST/dcg\\"",
        "powershell": "\\"$DEST/dcg\\"",
        "cwd": ".",
        "timeoutSec": 30
      }
    ]
  }
}
EOFSET
    COPILOT_STATUS="created"
    AUTO_CONFIGURED=1
  fi
}

configure_cursor() {
  # Cursor IDE (https://cursor.com) supports hooks via ~/.cursor/hooks.json.
  # We install a beforeShellExecution hook that delegates to dcg.
  local settings_file="$CURSOR_HOOKS_JSON"
  local hook_dir="$CURSOR_HOOK_DIR"
  local hook_script="$CURSOR_HOOK_SCRIPT"
  CURSOR_FAILURE_REASON=""

  local cursor_installed=0
  if [[ -d "$HOME/.cursor" ]] || [[ -f "$CURSOR_SETTINGS_MAC" ]] || [[ -f "$CURSOR_SETTINGS_LINUX" ]] || command -v cursor >/dev/null 2>&1; then
    cursor_installed=1
  elif command -v pgrep >/dev/null 2>&1; then
    if pgrep -fl "[Cc]ursor" 2>/dev/null | grep -qv 'CursorUIViewService\|/System/Library/'; then
      cursor_installed=1
    fi
  fi

  if [ "$cursor_installed" -eq 0 ]; then
    CURSOR_STATUS="skipped"
    return 0
  fi

  if ! command -v python3 >/dev/null 2>&1; then
    CURSOR_STATUS="failed"
    CURSOR_FAILURE_REASON="python3 required for merge"
    return 1
  fi

  mkdir -p "$hook_dir"

  local marker="dcg-cursor-hook"
  if [ -f "$hook_script" ] && ! grep -q "$marker" "$hook_script" 2>/dev/null; then
    CURSOR_STATUS="conflict"
    return 1
  fi

  local dcg_path_literal
  dcg_path_literal=$(python3 - "$DEST/dcg" <<'PYEOF'
import sys

print(repr(sys.argv[1]))
PYEOF
)

  {
    cat <<'PYEOF'
#!/usr/bin/env python3
# dcg-cursor-hook: generated by dcg installer
PYEOF
    printf 'DCG_BIN_FALLBACK = %s\n' "$dcg_path_literal"
    cat <<'PYEOF'
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

    dcg_bin = os.environ.get("DCG_BIN") or DCG_BIN_FALLBACK
    hook_input = {"tool_name": "Bash", "tool_input": {"command": command}}

    env = os.environ.copy()
    env["CURSOR_IDE"] = "1"

    try:
        proc = subprocess.run(
            [dcg_bin],
            input=json.dumps(hook_input),
            text=True,
            capture_output=True,
            env=env,
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
  } > "$hook_script"
  chmod +x "$hook_script" 2>/dev/null || true

  if [ -f "$settings_file" ]; then
    local cursor_hook_state
    cursor_hook_state=$(python3 - "$settings_file" "$hook_script" <<'PYEOF'
import json
import sys

settings_file = sys.argv[1]
hook_cmd = sys.argv[2]

try:
    with open(settings_file, "r") as f:
        settings = json.load(f)
except Exception:
    print("invalid")
    raise SystemExit(0)

if not isinstance(settings, dict):
    print("invalid")
    raise SystemExit(0)

hooks = settings.get("hooks", {})
if "hooks" in settings and not isinstance(hooks, dict):
    print("invalid")
    raise SystemExit(0)

entries = hooks.get("beforeShellExecution", [])
if "beforeShellExecution" in hooks and not isinstance(entries, list):
    print("invalid")
    raise SystemExit(0)

matching_commands = [
    entry.get("command")
    for entry in entries
    if isinstance(entry, dict) and entry.get("command") == hook_cmd
]
first_command = entries[0].get("command") if entries and isinstance(entries[0], dict) else None

if matching_commands == [hook_cmd] and first_command == hook_cmd:
    print("already")
else:
    print("merge")
PYEOF
)
    if [ "$cursor_hook_state" = "invalid" ]; then
      CURSOR_STATUS="failed"
      CURSOR_FAILURE_REASON="existing hooks.json is invalid or has malformed hooks; left unchanged"
      warn "Cursor hooks.json is invalid or has malformed hooks; leaving it unchanged: $settings_file"
      return 0
    fi
    if [ "$cursor_hook_state" = "already" ]; then
      CURSOR_STATUS="already"
      AUTO_CONFIGURED=1
      return 0
    fi

    CURSOR_BACKUP="${settings_file}.bak.$(date +%Y%m%d%H%M%S)"
    cp "$settings_file" "$CURSOR_BACKUP"

    if python3 - "$settings_file" "$hook_script" <<'PYEOF'
import json
import sys

settings_file = sys.argv[1]
hook_cmd = sys.argv[2]

try:
    with open(settings_file, "r") as f:
        settings = json.load(f)
except Exception:
    print(f"invalid Cursor hooks.json: {settings_file}", file=sys.stderr)
    raise SystemExit(1)

if not isinstance(settings, dict):
    print(f"Cursor hooks.json must contain a JSON object: {settings_file}", file=sys.stderr)
    raise SystemExit(1)

settings.setdefault("version", 1)
hooks = settings.setdefault("hooks", {})
if not isinstance(hooks, dict):
    print(f"Cursor hooks.json hooks must contain a JSON object: {settings_file}", file=sys.stderr)
    raise SystemExit(1)

entries = hooks.get("beforeShellExecution")
if "beforeShellExecution" not in hooks:
    entries = []
elif not isinstance(entries, list):
    print(f"Cursor hooks.json beforeShellExecution must contain a list: {settings_file}", file=sys.stderr)
    raise SystemExit(1)
hooks["beforeShellExecution"] = entries

def is_match(entry):
    return isinstance(entry, dict) and entry.get("command") == hook_cmd

entries[:] = [entry for entry in entries if not is_match(entry)]
entries.insert(0, {"command": hook_cmd})

with open(settings_file, "w") as f:
    json.dump(settings, f, indent=2)
PYEOF
    then
      CURSOR_STATUS="merged"
      AUTO_CONFIGURED=1
    else
      mv "$CURSOR_BACKUP" "$settings_file" 2>/dev/null || true
      CURSOR_STATUS="failed"
      CURSOR_FAILURE_REASON="merge failed; restored backup"
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

configure_hermes() {
  # Hermes Agent (NousResearch — https://github.com/NousResearch/hermes-agent)
  # supports shell hooks via ${HERMES_HOME:-~/.hermes}/config.yaml. Wire shape:
  #   hooks:
  #     pre_tool_call:
  #       - matcher: "terminal"
  #         command: "/path/to/dcg"
  #         timeout: 30
  #
  # The hook script reads JSON on stdin and writes JSON on stdout; the
  # block decision lives in the JSON payload (`{"decision":"block",...}`),
  # NOT in the exit code — Hermes documents that "non-zero exit codes,
  # malformed JSON, and timeouts log a warning but never abort the agent
  # loop". dcg handles this by emitting `HookProtocol::Hermes` JSON when
  # it sees `tool_name="terminal"` or `hook_event_name="pre_tool_call"`
  # on stdin; no wrapper script is required.
  #
  # The matcher is a regex per the docs; we anchor to "terminal" exactly.
  #
  # We also need `hooks_auto_accept: true` for the hook to fire in
  # non-TTY contexts (gateway, cron) — the docs are explicit that
  # without one of `--accept-hooks` / `HERMES_ACCEPT_HOOKS=1` /
  # `hooks_auto_accept: true`, the hook "silently remains unregistered"
  # in non-interactive runs. We only set it if the user has not already
  # set it (preserving any existing `false`).
  #
  # See: https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/features/hooks.md

  local settings_file="$HERMES_CONFIG"
  HERMES_FAILURE_REASON=""
  local settings_dir
  settings_dir=$(dirname "$settings_file")

  # Detect Hermes installation: resolved data dir, legacy ~/.hermes, or
  # `hermes` on PATH. The hook is always WRITTEN to $HERMES_CONFIG.
  local hermes_installed=0
  if [ -d "$settings_dir" ] || [ -d "$HOME/.hermes" ] ||
    command -v hermes >/dev/null 2>&1; then
    hermes_installed=1
  fi

  if [ "$hermes_installed" -eq 0 ]; then
    HERMES_STATUS="skipped"
    return 0
  fi

  if ! command -v python3 >/dev/null 2>&1; then
    HERMES_STATUS="failed"
    HERMES_FAILURE_REASON="python3 required to safely merge YAML config"
    return 0
  fi

  # Verify PyYAML is available; the YAML merge is too risky to fake.
  if ! python3 -c 'import yaml' >/dev/null 2>&1; then
    HERMES_STATUS="failed"
    HERMES_FAILURE_REASON="python3 PyYAML required to safely merge ${HERMES_CONFIG}"
    return 0
  fi

  if [ ! -d "$settings_dir" ]; then
    mkdir -p "$settings_dir"
  fi

  if [ -f "$settings_file" ]; then
    # First pass: detect whether the exact current dcg hook is the only
    # dcg entry in pre_tool_call (so reinstall is a no-op).
    local hermes_hook_state
    hermes_hook_state=$(python3 - "$settings_file" "$DEST/dcg" <<'PYEOF'
import os
import shlex
import sys
import yaml

cfg_file = sys.argv[1]
dcg_path = sys.argv[2]

def is_dcg_command(cmd):
    if not isinstance(cmd, str) or not cmd:
        return False
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return False
    if not tokens:
        return False
    name = os.path.basename(tokens[0])
    if name.endswith(".exe"):
        name = name[:-4]
    return name == "dcg"

try:
    with open(cfg_file, "r") as f:
        cfg = yaml.safe_load(f)
except (IOError, yaml.YAMLError):
    print("invalid")
    raise SystemExit(0)

if cfg is None:
    cfg = {}
if not isinstance(cfg, dict):
    print("invalid")
    raise SystemExit(0)

hooks = cfg.get("hooks")
if hooks is None:
    print("merge")
    raise SystemExit(0)
if not isinstance(hooks, dict):
    print("invalid")
    raise SystemExit(0)

pre_tool_call = hooks.get("pre_tool_call")
if pre_tool_call is None:
    print("merge")
    raise SystemExit(0)
if not isinstance(pre_tool_call, list):
    print("invalid")
    raise SystemExit(0)

dcg_entries = []
first_command = None
for i, entry in enumerate(pre_tool_call):
    if not isinstance(entry, dict):
        continue
    cmd = entry.get("command")
    if i == 0:
        first_command = cmd
    if is_dcg_command(cmd):
        dcg_entries.append(cmd)

# Idempotent: exactly one dcg entry, it's our current path, and it's first.
if dcg_entries == [dcg_path] and first_command == dcg_path:
    print("already")
else:
    print("merge")
PYEOF
)
    if [ "$hermes_hook_state" = "invalid" ]; then
      HERMES_STATUS="failed"
      HERMES_FAILURE_REASON="existing config.yaml is invalid or has malformed hooks; left unchanged"
      warn "Hermes config.yaml is invalid or has malformed hooks; leaving it unchanged: $settings_file"
      return 0
    fi
    if [ "$hermes_hook_state" = "already" ]; then
      HERMES_STATUS="already"
      AUTO_CONFIGURED=1
      return 0
    fi

    HERMES_BACKUP="${settings_file}.bak.$(date +%Y%m%d%H%M%S)"
    cp "$settings_file" "$HERMES_BACKUP"

    if python3 - "$settings_file" "$DEST/dcg" <<'PYEOF'
import os
import shlex
import sys
import yaml

cfg_file = sys.argv[1]
dcg_path = sys.argv[2]

def is_dcg_command(cmd):
    """True iff `cmd` invokes the dcg binary (basename match, not substring)."""
    if not isinstance(cmd, str) or not cmd:
        return False
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return False
    if not tokens:
        return False
    name = os.path.basename(tokens[0])
    if name.endswith(".exe"):
        name = name[:-4]
    return name == "dcg"

try:
    with open(cfg_file, "r") as f:
        cfg = yaml.safe_load(f)
except (IOError, yaml.YAMLError) as exc:
    print(f"invalid Hermes config.yaml: {cfg_file}: {exc}", file=sys.stderr)
    raise SystemExit(1)

if cfg is None:
    cfg = {}
if not isinstance(cfg, dict):
    print(f"Hermes config.yaml must contain a YAML mapping: {cfg_file}", file=sys.stderr)
    raise SystemExit(1)

# Preserve any pre-existing top-level keys verbatim.
hooks = cfg.get("hooks")
if hooks is None:
    cfg["hooks"] = {}
    hooks = cfg["hooks"]
elif not isinstance(hooks, dict):
    print(f"Hermes config.yaml `hooks` must be a mapping: {cfg_file}", file=sys.stderr)
    raise SystemExit(1)

pre_tool_call = hooks.get("pre_tool_call")
if pre_tool_call is None:
    hooks["pre_tool_call"] = []
    pre_tool_call = hooks["pre_tool_call"]
elif not isinstance(pre_tool_call, list):
    print(f"Hermes config.yaml `pre_tool_call` must be a list: {cfg_file}", file=sys.stderr)
    raise SystemExit(1)

# Drop any pre-existing dcg entries (stale paths, duplicates).
filtered = []
for entry in pre_tool_call:
    if isinstance(entry, dict) and is_dcg_command(entry.get("command")):
        continue
    filtered.append(entry)

# Insert exactly one dcg entry at the front; matcher anchors to the
# documented Hermes shell tool name. timeout=30s is well under the
# documented 300s ceiling and matches our Gemini default scaling.
dcg_entry = {
    "matcher": "terminal",
    "command": dcg_path,
    "timeout": 30,
}
filtered.insert(0, dcg_entry)
hooks["pre_tool_call"] = filtered

# Set hooks_auto_accept ONLY if the user has not specified it. Hermes
# documents that without one of (--accept-hooks / HERMES_ACCEPT_HOOKS=1 /
# hooks_auto_accept: true), shell hooks "silently remain unregistered"
# in non-TTY contexts. Without this dcg would fail open in CI/cron.
if "hooks_auto_accept" not in cfg:
    cfg["hooks_auto_accept"] = True

with open(cfg_file, "w") as f:
    yaml.safe_dump(cfg, f, sort_keys=False, default_flow_style=False)
PYEOF
    then
      HERMES_STATUS="merged"
      AUTO_CONFIGURED=1
    else
      mv "$HERMES_BACKUP" "$settings_file" 2>/dev/null || true
      HERMES_STATUS="failed"
      HERMES_FAILURE_REASON="merge failed; restored backup"
      HERMES_BACKUP=""
      return 0
    fi
  else
    # Brand-new config.yaml. Write a minimal, well-commented config.
    cat > "$settings_file" <<EOFSET
# Hermes Agent configuration
# Created by dcg installer (https://github.com/Dicklesworthstone/destructive_command_guard)
#
# pre_tool_call hooks fire before any tool invocation. dcg blocks
# destructive shell commands by emitting {"decision":"block",...} on stdout.
# Hermes documents that exit codes are advisory — the JSON decision is what
# enforces the block.
#
# hooks_auto_accept is required so the hook actually registers in non-TTY
# (gateway/cron) Hermes runs. Override per-command consent with
# \`hermes hooks revoke\` if needed.

hooks:
  pre_tool_call:
    - matcher: "terminal"
      command: "$DEST/dcg"
      timeout: 30

hooks_auto_accept: true
EOFSET
    HERMES_STATUS="created"
    AUTO_CONFIGURED=1
  fi
}

configure_posit_assistant() {
  # Posit Assistant (Posit Software, PBC — https://positron.posit.co/assistant/)
  # reads Claude-Code-compatible lifecycle hooks from the global
  # ~/.posit/assistant/settings.json plus per-workspace overrides. We write the
  # global file so one install covers the Positron/RStudio extension, the
  # standalone server, and the `pa` terminal client in every workspace.
  #
  # The hook contract is not publicly documented yet; the behavior below is the
  # empirically-verified contract, pinned by tests in src/hook.rs: `PreToolUse`
  # stdin is the snake_case Claude shape with the command in
  # `tool_input.command`, exit code 2 blocks with stderr as the reason, and
  # `hookSpecificOutput.permissionDecision` is read on exit 0. dcg's existing
  # ClaudeCompatible protocol answers all of that, so only the config entry
  # differs from Claude Code's:
  #
  #   1. The matcher is lowercase "bash|powershell". A simple matcher string is
  #      an EXACT match against the tool name (with "|"/"," separating
  #      alternatives), and the shell tools are named "bash"/"powershell" — a
  #      matcher copied from the Claude entry would never fire. Listing both
  #      names covers a Windows PowerShell host with the same entry.
  #   2. Only documented handler fields are written: type, command, timeout.
  #      There is NO `shell` field (which the Windows Claude entry uses); the
  #      command path is quoted instead so an install path containing spaces
  #      survives shell-form execution (cmd.exe on Windows).
  #   3. `timeout` is in SECONDS and bounds a wedged hook.
  #
  # Unlike configure_claude_code, existing matcher groups are preserved
  # structurally rather than consolidated: hook config is additive (every group
  # whose matcher matches contributes), so a user's "bash,edit" group keeps
  # working untouched. dcg gets one dedicated group at the front — a denial
  # then fires before other hooks — and stale dcg entries anywhere else are
  # collapsed into it.

  local settings_file="$POSIT_ASSISTANT_SETTINGS"
  POSIT_ASSISTANT_FAILURE_REASON=""
  POSIT_ASSISTANT_BACKUP=""
  local settings_dir
  settings_dir=$(dirname "$settings_file")
  local pa_matcher="bash|powershell"
  # Contract detail 2: the stored command is the quoted binary path.
  local pa_command="\"$DEST/dcg\""

  if ! posit_assistant_installed; then
    POSIT_ASSISTANT_STATUS="skipped"
    return 0
  fi

  if [ ! -d "$settings_dir" ]; then
    mkdir -p "$settings_dir"
  fi

  # An existing but EMPTY (or whitespace-only) settings.json holds nothing to
  # merge or preserve — treat it exactly like a missing file and create
  # fresh. The first-pass state check below would otherwise misreport it as
  # invalid JSON and fail the configuration.
  if [ -f "$settings_file" ] && LC_ALL=C grep -q '[^[:space:]]' "$settings_file" 2>/dev/null; then
    if ! command -v python3 >/dev/null 2>&1; then
      POSIT_ASSISTANT_STATUS="failed"
      POSIT_ASSISTANT_FAILURE_REASON="python3 required to safely merge settings.json"
      return 0
    fi

    # First pass: is the exact current dcg hook already the sole dcg entry,
    # sitting first in its own matcher group? Stale paths and duplicates fall
    # through to the merge below so they get collapsed.
    local pa_hook_state
    pa_hook_state=$(python3 - "$settings_file" "$pa_command" "$pa_matcher" <<'PYEOF'
import json
import os
import shlex
import sys

settings_file = sys.argv[1]
dcg_command = sys.argv[2]
matcher = sys.argv[3]

def is_dcg_command(cmd):
    if not isinstance(cmd, str) or not cmd:
        return False
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return False
    if not tokens:
        return False
    name = os.path.basename(tokens[0])
    if name.endswith('.exe'):
        name = name[:-4]
    return name == 'dcg'

try:
    with open(settings_file, 'r') as f:
        settings = json.load(f)
except (IOError, ValueError, json.JSONDecodeError):
    print("invalid")
    raise SystemExit(0)

if not isinstance(settings, dict):
    print("invalid")
    raise SystemExit(0)

hooks_obj = settings.get("hooks", {})
if not isinstance(hooks_obj, dict):
    print("invalid")
    raise SystemExit(0)

pre_tool_use = hooks_obj.get("PreToolUse", [])
if not isinstance(pre_tool_use, list):
    print("invalid")
    raise SystemExit(0)

dcg_commands = []
for entry in pre_tool_use:
    if not isinstance(entry, dict):
        continue
    hooks = entry.get("hooks", [])
    if not isinstance(hooks, list):
        print("invalid")
        raise SystemExit(0)
    for hook in hooks:
        if isinstance(hook, dict) and is_dcg_command(hook.get("command")):
            dcg_commands.append(hook.get("command"))

first = pre_tool_use[0] if pre_tool_use else None
first_is_current = (
    isinstance(first, dict)
    and first.get("matcher") == matcher
    and isinstance(first.get("hooks"), list)
    and bool(first["hooks"])
    and isinstance(first["hooks"][0], dict)
    and first["hooks"][0].get("command") == dcg_command
)

if dcg_commands == [dcg_command] and first_is_current:
    print("already")
else:
    print("merge")
PYEOF
)
    if [ "$pa_hook_state" = "invalid" ]; then
      POSIT_ASSISTANT_STATUS="failed"
      POSIT_ASSISTANT_FAILURE_REASON="existing settings.json is invalid or has malformed hooks; left unchanged"
      warn "Posit Assistant settings.json is invalid or has malformed hooks; leaving it unchanged: $settings_file"
      return 0
    fi
    if [ "$pa_hook_state" = "already" ]; then
      POSIT_ASSISTANT_STATUS="already"
      AUTO_CONFIGURED=1
      return 0
    fi

    POSIT_ASSISTANT_BACKUP="${settings_file}.bak.$(date +%Y%m%d%H%M%S)"
    cp "$settings_file" "$POSIT_ASSISTANT_BACKUP"

    if python3 - "$settings_file" "$pa_command" "$pa_matcher" <<'PYEOF'
import json
import os
import shlex
import sys

settings_file = sys.argv[1]
dcg_command = sys.argv[2]
matcher = sys.argv[3]

def is_dcg_command(cmd):
    """True iff `cmd` invokes the dcg binary (basename match, not substring).

    A substring check would also match unrelated user tools whose path merely
    contains "dcg" (/opt/dcgrep/bin/scan, ~/.local/bin/dcgworkflow, ...) and
    would then drop or replace their hook entries.
    """
    if not isinstance(cmd, str) or not cmd:
        return False
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        # Unparseable command (mismatched quotes, ...) — treat as NOT-dcg so
        # it is never dropped or replaced.
        return False
    if not tokens:
        return False
    name = os.path.basename(tokens[0])
    if name.endswith('.exe'):
        name = name[:-4]
    return name == 'dcg'

try:
    with open(settings_file, 'r') as f:
        raw_settings = f.read()
except IOError:
    raw_settings = ""

if raw_settings.strip():
    try:
        settings = json.loads(raw_settings)
    except ValueError:
        print(f"invalid Posit Assistant settings.json: {settings_file}", file=sys.stderr)
        raise SystemExit(1)
else:
    settings = {}

if not isinstance(settings, dict):
    print(
        f"Posit Assistant settings.json must contain a JSON object: {settings_file}",
        file=sys.stderr,
    )
    raise SystemExit(1)

if 'hooks' not in settings:
    settings['hooks'] = {}
elif not isinstance(settings['hooks'], dict):
    print(
        f"Posit Assistant settings.json hooks must contain a JSON object: {settings_file}",
        file=sys.stderr,
    )
    raise SystemExit(1)

if 'PreToolUse' not in settings['hooks']:
    settings['hooks']['PreToolUse'] = []
elif not isinstance(settings['hooks']['PreToolUse'], list):
    print(
        f"Posit Assistant settings.json PreToolUse must contain a list: {settings_file}",
        file=sys.stderr,
    )
    raise SystemExit(1)

# Strip every pre-existing dcg entry (stale paths, duplicates) from all matcher
# groups; a group whose hooks list empties out as a result is pruned rather
# than left behind as an empty group. Non-dcg hooks and the user's group
# structure are otherwise preserved verbatim.
cleaned = []
for entry in settings['hooks']['PreToolUse']:
    if not isinstance(entry, dict):
        cleaned.append(entry)
        continue
    hooks = entry.get('hooks')
    if not isinstance(hooks, list):
        if 'hooks' in entry:
            print(
                f"Posit Assistant matcher-group hooks must contain a list: {settings_file}",
                file=sys.stderr,
            )
            raise SystemExit(1)
        cleaned.append(entry)
        continue
    kept = [
        hook
        for hook in hooks
        if not (isinstance(hook, dict) and is_dcg_command(hook.get('command')))
    ]
    if hooks and not kept:
        # The group existed only to run dcg; drop it.
        continue
    entry['hooks'] = kept
    cleaned.append(entry)

# dcg's dedicated group goes first so a denial fires before other hooks run.
cleaned.insert(
    0,
    {
        "matcher": matcher,
        "hooks": [{"type": "command", "command": dcg_command, "timeout": 10}],
    },
)

settings['hooks']['PreToolUse'] = cleaned

with open(settings_file, 'w') as f:
    json.dump(settings, f, indent=2)
    f.write("\n")
PYEOF
    then
      POSIT_ASSISTANT_STATUS="merged"
      AUTO_CONFIGURED=1
    else
      mv "$POSIT_ASSISTANT_BACKUP" "$settings_file" 2>/dev/null || true
      POSIT_ASSISTANT_STATUS="failed"
      POSIT_ASSISTANT_FAILURE_REASON="merge failed; restored backup"
      POSIT_ASSISTANT_BACKUP=""
    fi
  else
    cat > "$settings_file" <<EOFSET
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "$pa_matcher",
        "hooks": [
          {
            "type": "command",
            "command": "\\"$DEST/dcg\\"",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
EOFSET
    POSIT_ASSISTANT_STATUS="created"
    AUTO_CONFIGURED=1
  fi
}

configure_opencode() {
  # OpenCode (opencode.ai) intercepts shell commands only through plugins, so
  # dcg ships a native `tool.execute.before` plugin (#318). The freshly
  # installed binary is the single source of truth for the plugin content:
  # `dcg install --opencode` writes
  # ${XDG_CONFIG_HOME:-~/.config}/opencode/plugins/dcg-guard.js with an
  # ownership marker, refuses to overwrite a user-owned file of the same name,
  # and `--force` refreshes a dcg-owned one (keeping the embedded binary path
  # current across upgrades).
  if ! is_agent_detected "opencode"; then
    OPENCODE_STATUS="skipped"
    return 0
  fi

  local dcg_bin="$DEST/dcg"
  if [ ! -x "$dcg_bin" ]; then
    OPENCODE_STATUS="failed"
    OPENCODE_FAILURE_REASON="dcg binary not found at $dcg_bin"
    return 1
  fi

  local plugin_path="${XDG_CONFIG_HOME:-$HOME/.config}/opencode/plugins/dcg-guard.js"
  local existed=0
  [ -f "$plugin_path" ] && existed=1

  local output
  if output=$("$dcg_bin" install --opencode --force 2>&1); then
    if [ "$existed" -eq 1 ]; then
      OPENCODE_STATUS="merged"
    else
      OPENCODE_STATUS="created"
    fi
    AUTO_CONFIGURED=1
    return 0
  fi

  if printf '%s' "$output" | grep -q "was not generated by dcg"; then
    OPENCODE_STATUS="conflict"
    OPENCODE_FAILURE_REASON="existing $plugin_path is not dcg-owned"
  else
    OPENCODE_STATUS="failed"
    OPENCODE_FAILURE_REASON=$(printf '%s' "$output" | tail -n 1)
  fi
  return 1
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
    elif have_tty; then
      # Interactive: ask user (reads /dev/tty, so this works under curl|bash)
      if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
        if gum confirm "Remove predecessor ($PREDECESSOR_SCRIPT) and upgrade to dcg?" <"$DCG_TTY"; then
          REMOVE_PREDECESSOR=1
        fi
      else
        if ask_yn "Remove predecessor ($PREDECESSOR_SCRIPT) and upgrade to dcg? (Y/n):" "y"; then
          REMOVE_PREDECESSOR=1
        fi
      fi
    else
      # No TTY without --easy-mode: default to removing (user ran installer intentionally)
      REMOVE_PREDECESSOR=1
      info "No TTY available: auto-removing predecessor (use --easy-mode to suppress this message)"
    fi

    if [ "$REMOVE_PREDECESSOR" -eq 1 ]; then
      for loc in ${PREDECESSOR_LOCATIONS[@]+"${PREDECESSOR_LOCATIONS[@]}"}; do
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

  # Configure GitHub Copilot CLI's user-level hook (all workspaces).
  configure_copilot

  # Configure Cursor IDE (if installed)
  configure_cursor

  # Configure Hermes Agent (if installed)
  configure_hermes

  # Configure Posit Assistant (if installed)
  configure_posit_assistant

  # Configure OpenCode (if installed)
  configure_opencode
else
  info "Skipping agent configuration (--no-configure)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Shell Startup Check (detect silently removed hook)
# ═══════════════════════════════════════════════════════════════════════════════

if [ "$NO_CONFIGURE" -eq 0 ]; then
  # In easy mode or non-interactive, inject automatically; otherwise prompt.
  if [ "$EASY" -eq 1 ]; then
    maybe_add_shell_check
  elif have_tty; then
    echo ""
    if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
      gum style --foreground 39 --bold "Shell startup check"
      gum style --foreground 247 "Claude Code can silently remove the dcg hook when it rewrites settings.json."
      gum style --foreground 247 "A shell startup check will warn you on every new terminal if the hook goes missing."
      echo ""
      if gum confirm "Add shell startup check to your RC files?" <"$DCG_TTY"; then
        maybe_add_shell_check
      else
        info "Skipped. You can add it later with: dcg setup --shell-check"
      fi
    else
      echo -e "\033[1;36mShell startup check\033[0m"
      echo "Claude Code can silently remove the dcg hook when it rewrites settings.json."
      echo "A shell startup check will warn you on every new terminal if the hook goes missing."
      echo ""
      if ask_yn "Add shell startup check to your RC files? [Y/n]" "y"; then
        maybe_add_shell_check
      else
        info "Skipped. You can add it later with: dcg setup --shell-check"
      fi
    fi
  else
    # No TTY, non-easy-mode: auto-inject (user ran installer intentionally),
    # and say so explicitly since nobody was asked (#251).
    info "No TTY available: adding the shell startup check to your shell RC files (warns when the dcg hook goes missing; opt out next time with --no-configure)"
    maybe_add_shell_check
  fi
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
  already)
    summary_lines+=("Claude Code: Already configured (no changes)")
    ;;
  failed)
    if [ -n "$CLAUDE_FAILURE_REASON" ]; then
      summary_lines+=("Claude Code: Configuration failed ($CLAUDE_FAILURE_REASON)")
    else
      summary_lines+=("Claude Code: Configuration failed (python3 required)")
    fi
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
    if [ -n "$GEMINI_FAILURE_REASON" ]; then
      summary_lines+=("Gemini CLI:  Configuration failed ($GEMINI_FAILURE_REASON)")
    else
      summary_lines+=("Gemini CLI:  Configuration failed")
    fi
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
  created)
    summary_lines+=("Codex CLI:   Created $CODEX_SETTINGS with dcg hook")
    ;;
  merged)
    summary_lines+=("Codex CLI:   Added dcg hook to existing $CODEX_SETTINGS")
    [ -n "$CODEX_BACKUP" ] && summary_lines+=("             Backup: $CODEX_BACKUP")
    ;;
  already)
    summary_lines+=("Codex CLI:   Already configured (no changes)")
    ;;
  failed)
    if [ -n "$CODEX_FAILURE_REASON" ]; then
      summary_lines+=("Codex CLI:   Configuration failed ($CODEX_FAILURE_REASON)")
    else
      summary_lines+=("Codex CLI:   Configuration failed")
    fi
    ;;
  skipped|"")
    summary_lines+=("Codex CLI:   Not installed (skipped)")
    ;;
esac

case "$COPILOT_STATUS" in
  created)
    summary_lines+=("GitHub Copilot CLI: Created $COPILOT_HOOK_FILE with dcg hook")
    ;;
  merged)
    summary_lines+=("GitHub Copilot CLI: Added/updated dcg hook in $COPILOT_HOOK_FILE")
    [ -n "$COPILOT_BACKUP" ] && summary_lines+=("             Backup: $COPILOT_BACKUP")
    ;;
  already)
    summary_lines+=("GitHub Copilot CLI: Already configured (no changes)")
    ;;
  skipped|"")
    summary_lines+=("GitHub Copilot CLI: Not installed (skipped)")
    ;;
  failed)
    if [ -n "$COPILOT_FAILURE_REASON" ]; then
      summary_lines+=("GitHub Copilot CLI: Configuration failed ($COPILOT_FAILURE_REASON)")
    else
      summary_lines+=("GitHub Copilot CLI: Configuration failed")
    fi
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
    if [ -n "$CURSOR_FAILURE_REASON" ]; then
      summary_lines+=("Cursor IDE:  Configuration failed ($CURSOR_FAILURE_REASON)")
    else
      summary_lines+=("Cursor IDE:  Configuration failed")
    fi
    ;;
esac

case "$HERMES_STATUS" in
  created)
    summary_lines+=("Hermes:      Created $HERMES_CONFIG with pre_tool_call hook")
    ;;
  merged)
    summary_lines+=("Hermes:      Added pre_tool_call hook to existing $HERMES_CONFIG")
    [ -n "$HERMES_BACKUP" ] && summary_lines+=("             Backup: $HERMES_BACKUP")
    ;;
  already)
    summary_lines+=("Hermes:      Already configured (no changes)")
    ;;
  skipped|"")
    summary_lines+=("Hermes:      Not installed (skipped)")
    ;;
  failed)
    if [ -n "$HERMES_FAILURE_REASON" ]; then
      summary_lines+=("Hermes:      Configuration failed ($HERMES_FAILURE_REASON)")
    else
      summary_lines+=("Hermes:      Configuration failed")
    fi
    ;;
esac

case "$POSIT_ASSISTANT_STATUS" in
  created)
    summary_lines+=("Posit Assistant: Created $POSIT_ASSISTANT_SETTINGS with dcg hook")
    ;;
  merged)
    summary_lines+=("Posit Assistant: Added dcg hook to existing $POSIT_ASSISTANT_SETTINGS")
    [ -n "$POSIT_ASSISTANT_BACKUP" ] && summary_lines+=("             Backup: $POSIT_ASSISTANT_BACKUP")
    ;;
  already)
    summary_lines+=("Posit Assistant: Already configured (no changes)")
    ;;
  skipped|"")
    summary_lines+=("Posit Assistant: Not installed (skipped)")
    ;;
  failed)
    if [ -n "$POSIT_ASSISTANT_FAILURE_REASON" ]; then
      summary_lines+=("Posit Assistant: Configuration failed ($POSIT_ASSISTANT_FAILURE_REASON)")
    else
      summary_lines+=("Posit Assistant: Configuration failed")
    fi
    ;;
esac

case "$OPENCODE_STATUS" in
  created)
    summary_lines+=("OpenCode:    Installed native tool.execute.before plugin (dcg-guard.js)")
    summary_lines+=("             Restart OpenCode to load it")
    ;;
  merged)
    summary_lines+=("OpenCode:    Refreshed dcg-owned plugin (dcg-guard.js)")
    ;;
  skipped|"")
    summary_lines+=("OpenCode:    Not installed (skipped)")
    ;;
  conflict)
    summary_lines+=("OpenCode:    Skipped — existing dcg-guard.js is not dcg-owned ($OPENCODE_FAILURE_REASON)")
    ;;
  failed)
    if [ -n "$OPENCODE_FAILURE_REASON" ]; then
      summary_lines+=("OpenCode:    Configuration failed ($OPENCODE_FAILURE_REASON)")
    else
      summary_lines+=("OpenCode:    Configuration failed")
    fi
    ;;
esac

if [ "$AUTO_CONFIGURED" -eq 0 ]; then
  summary_lines+=("Agent hooks: No supported integration was configured")
fi
fi

# Show summary
if [ "$QUIET" -eq 0 ]; then
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    {
      gum style --foreground 42 --bold "dcg is now active!"
      echo ""
      for line in ${summary_lines[@]+"${summary_lines[@]}"}; do
        gum style --foreground 245 "$line"
      done
      echo ""
      gum style --foreground 245 "All Bash commands will be scanned for destructive patterns."
      gum style --foreground 245 "Use \"dcg explain <command>\" to see why a command was blocked."
    } | gum style --border normal --border-foreground 42 --padding "1 2"
  else
    echo -e "\033[1;32mdcg is now active!\033[0m"
    echo ""
    for line in ${summary_lines[@]+"${summary_lines[@]}"}; do
      echo -e "  \033[0;90m$line\033[0m"
    done
    echo ""
    echo -e "  All Bash commands will be scanned for destructive patterns."
    echo -e "  Use \"\033[0;36mdcg explain <command>\033[0m\" to see why a command was blocked."
  fi

  # Show reversal instructions
  echo ""
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style --foreground 245 --italic "To uninstall: rm $DEST/dcg && remove dcg hooks from settings files and repo hook files"
    if [ -n "$CLAUDE_BACKUP" ] || [ -n "$GEMINI_BACKUP" ] || [ -n "$COPILOT_BACKUP" ]; then
      gum style --foreground 245 --italic "To revert:   restore from backup files listed above"
    fi
  else
    echo -e "\033[0;90mTo uninstall: rm $DEST/dcg && remove dcg hooks from settings files and repo hook files\033[0m"
    if [ -n "$CLAUDE_BACKUP" ] || [ -n "$GEMINI_BACKUP" ] || [ -n "$COPILOT_BACKUP" ]; then
      echo -e "\033[0;90mTo revert:   restore from backup files listed above\033[0m"
    fi
  fi
fi

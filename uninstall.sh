#!/usr/bin/env bash
#
# dcg uninstaller
#
# One-liner uninstall:
#   curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/master/uninstall.sh | bash
#
# Options:
#   --yes            Skip confirmation prompt
#   --keep-config    Keep configuration files (~/.config/dcg/)
#   --keep-history   Keep history database (~/.local/share/dcg/)
#   --purge          Remove everything (overrides keep flags)
#   --quiet          Suppress non-error output
#
set -euo pipefail

# Defaults
YES=0
KEEP_CONFIG=0
KEEP_HISTORY=0
PURGE=0
QUIET=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Color

# Logging functions
log() { [ "$QUIET" -eq 1 ] && return 0; echo -e "$@"; }
ok() { [ "$QUIET" -eq 1 ] && return 0; echo -e "${GREEN}✓${NC} $*"; }
warn() { [ "$QUIET" -eq 1 ] && return 0; echo -e "${YELLOW}⚠${NC} $*"; }
err() { echo -e "${RED}✗${NC} $*" >&2; }

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes|-y)
            YES=1
            shift
            ;;
        --keep-config)
            KEEP_CONFIG=1
            shift
            ;;
        --keep-history)
            KEEP_HISTORY=1
            shift
            ;;
        --purge)
            PURGE=1
            shift
            ;;
        --quiet|-q)
            QUIET=1
            shift
            ;;
        *)
            err "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Purge overrides keep flags
if [ "$PURGE" -eq 1 ]; then
    KEEP_CONFIG=0
    KEEP_HISTORY=0
fi

# Find dcg binary location
find_dcg_binary() {
    # Check common locations
    local locations=(
        "$HOME/.local/bin/dcg"
        "/usr/local/bin/dcg"
        "/usr/bin/dcg"
    )

    for loc in "${locations[@]}"; do
        if [ -x "$loc" ]; then
            echo "$loc"
            return 0
        fi
    done

    # Fall back to which
    command -v dcg 2>/dev/null || true
}

# Remove dcg hook from Claude Code settings
unconfigure_claude_code() {
    local settings="$HOME/.claude/settings.json"

    if [ ! -f "$settings" ]; then
        return 0
    fi

    # Check if dcg is configured
    if ! grep -q '"command".*dcg' "$settings" 2>/dev/null; then
        return 0
    fi

    # Use python3 to remove the hook safely
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$settings" <<'PYEOF'
import json
import sys

settings_file = sys.argv[1]

try:
    with open(settings_file, 'r') as f:
        settings = json.load(f)
except (IOError, ValueError, json.JSONDecodeError):
    sys.exit(0)

if 'hooks' not in settings:
    sys.exit(0)
if 'PreToolUse' not in settings['hooks']:
    sys.exit(0)

pre_tool_use = settings['hooks']['PreToolUse']
if not isinstance(pre_tool_use, list):
    sys.exit(0)

# Filter out dcg hooks
new_hooks = []
for entry in pre_tool_use:
    if isinstance(entry, dict) and entry.get('matcher') == 'Bash':
        hooks = entry.get('hooks', [])
        filtered = [h for h in hooks if 'dcg' not in h.get('command', '')]
        if filtered:
            entry['hooks'] = filtered
            new_hooks.append(entry)
    else:
        new_hooks.append(entry)

settings['hooks']['PreToolUse'] = new_hooks

with open(settings_file, 'w') as f:
    json.dump(settings, f, indent=2)

print("removed", file=sys.stderr)
PYEOF
        return $?
    else
        warn "python3 not available - cannot safely edit Claude Code settings"
        warn "Please manually remove dcg from $settings"
        return 1
    fi
}

# Remove dcg hook from Gemini CLI settings
unconfigure_gemini() {
    local settings="$HOME/.gemini/settings.json"

    if [ ! -f "$settings" ]; then
        return 0
    fi

    # Check if dcg is configured
    if ! grep -q '"command".*dcg' "$settings" 2>/dev/null; then
        return 0
    fi

    if command -v python3 >/dev/null 2>&1; then
        python3 - "$settings" <<'PYEOF'
import json
import sys

settings_file = sys.argv[1]

try:
    with open(settings_file, 'r') as f:
        settings = json.load(f)
except (IOError, ValueError, json.JSONDecodeError):
    sys.exit(0)

if 'hooks' not in settings:
    sys.exit(0)
if 'BeforeTool' not in settings['hooks']:
    sys.exit(0)

before_tool = settings['hooks']['BeforeTool']
if not isinstance(before_tool, list):
    sys.exit(0)

# Filter out dcg hooks
new_hooks = []
for entry in before_tool:
    if isinstance(entry, dict):
        hooks = entry.get('hooks', [])
        filtered = [h for h in hooks if 'dcg' not in h.get('command', '')]
        if filtered:
            entry['hooks'] = filtered
            new_hooks.append(entry)
    else:
        new_hooks.append(entry)

settings['hooks']['BeforeTool'] = new_hooks

with open(settings_file, 'w') as f:
    json.dump(settings, f, indent=2)

print("removed", file=sys.stderr)
PYEOF
        return $?
    else
        warn "python3 not available - cannot safely edit Gemini CLI settings"
        return 1
    fi
}

# Remove dcg hook from GitHub Copilot CLI repo-local hook file
unconfigure_copilot() {
    if ! command -v git >/dev/null 2>&1; then
        return 0
    fi

    local repo_root=""
    repo_root=$(git rev-parse --show-toplevel 2>/dev/null || true)
    if [ -z "$repo_root" ]; then
        return 0
    fi

    local hook_file="$repo_root/.github/hooks/dcg.json"
    if [ ! -f "$hook_file" ]; then
        return 0
    fi

    if ! grep -q 'dcg' "$hook_file" 2>/dev/null; then
        return 0
    fi

    if command -v python3 >/dev/null 2>&1; then
        python3 - "$hook_file" <<'PYEOF'
import json
import os
import sys

hook_file = sys.argv[1]

try:
    with open(hook_file, "r", encoding="utf-8") as f:
        settings = json.load(f)
except (IOError, ValueError, json.JSONDecodeError):
    sys.exit(0)

if not isinstance(settings, dict):
    sys.exit(0)

hooks = settings.get("hooks")
if not isinstance(hooks, dict):
    sys.exit(0)

pre_tool = hooks.get("preToolUse")
if not isinstance(pre_tool, list):
    sys.exit(0)

def is_dcg_entry(entry):
    if not isinstance(entry, dict):
        return False
    bash_cmd = str(entry.get("bash", ""))
    pwsh_cmd = str(entry.get("powershell", ""))
    return "dcg" in bash_cmd or "dcg" in pwsh_cmd

new_pre = [entry for entry in pre_tool if not is_dcg_entry(entry)]
if len(new_pre) == len(pre_tool):
    sys.exit(0)

if new_pre:
    hooks["preToolUse"] = new_pre
else:
    hooks.pop("preToolUse", None)

for key in list(hooks.keys()):
    if hooks.get(key) == []:
        hooks.pop(key, None)

if not hooks:
    settings.pop("hooks", None)

if not settings or settings == {"version": 1}:
    os.remove(hook_file)
else:
    with open(hook_file, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)

print("removed", file=sys.stderr)
PYEOF
        return $?
    else
        warn "python3 not available - cannot safely edit GitHub Copilot hook file"
        warn "Please manually remove dcg from $hook_file"
        return 1
    fi
}

# Remove dcg settings from Aider config
unconfigure_aider() {
    local config="$HOME/.aider.conf.yml"

    if [ ! -f "$config" ]; then
        return 0
    fi

    # Check if our settings exist
    if ! grep -q 'Added by dcg installer' "$config" 2>/dev/null; then
        return 0
    fi

    # Create backup
    cp "$config" "${config}.bak.$(date +%Y%m%d%H%M%S)"

    # Remove lines added by dcg installer
    local tmp="${config}.tmp"
    awk '
        /Added by dcg installer/ { skip=1; next }
        skip && /git-commit-verify:/ { skip=0; next }
        { skip=0; print }
    ' "$config" > "$tmp"

    # Check if file is now empty (just whitespace)
    if [ ! -s "$tmp" ] || ! grep -q '[^[:space:]]' "$tmp"; then
        rm -f "$tmp" "$config"
    else
        mv "$tmp" "$config"
    fi

    return 0
}

# Main uninstall function
main() {
    log "${BOLD}dcg uninstaller${NC}"
    log ""

    # Find binary
    local binary
    binary=$(find_dcg_binary)

    # Determine paths
    local config_dir="$HOME/.config/dcg"
    local data_dir="$HOME/.local/share/dcg"
    local claude_settings="$HOME/.claude/settings.json"
    local gemini_settings="$HOME/.gemini/settings.json"
    local aider_config="$HOME/.aider.conf.yml"
    local copilot_hook_file=""

    if command -v git >/dev/null 2>&1; then
        local repo_root=""
        repo_root=$(git rev-parse --show-toplevel 2>/dev/null || true)
        if [ -n "$repo_root" ]; then
            copilot_hook_file="$repo_root/.github/hooks/dcg.json"
        fi
    fi

    # Show what will be removed
    log "The following will be removed:"
    log ""

    local found_anything=0

    # Agent hooks
    if [ -f "$claude_settings" ] && grep -q '"command".*dcg' "$claude_settings" 2>/dev/null; then
        log "  • Claude Code hook ($claude_settings)"
        found_anything=1
    fi
    if [ -f "$gemini_settings" ] && grep -q '"command".*dcg' "$gemini_settings" 2>/dev/null; then
        log "  • Gemini CLI hook ($gemini_settings)"
        found_anything=1
    fi
    if [ -f "$aider_config" ] && grep -q 'Added by dcg installer' "$aider_config" 2>/dev/null; then
        log "  • Aider configuration ($aider_config)"
        found_anything=1
    fi
    if [ -n "$copilot_hook_file" ] && [ -f "$copilot_hook_file" ] && grep -q 'dcg' "$copilot_hook_file" 2>/dev/null; then
        log "  • GitHub Copilot CLI hook ($copilot_hook_file)"
        found_anything=1
    fi

    # Config
    if [ "$KEEP_CONFIG" -eq 0 ] && [ -d "$config_dir" ]; then
        log "  • Configuration directory ($config_dir)"
        found_anything=1
    fi

    # History
    if [ "$KEEP_HISTORY" -eq 0 ] && [ -d "$data_dir" ]; then
        log "  • History data ($data_dir)"
        found_anything=1
    fi

    # Binary
    if [ -n "$binary" ] && [ -f "$binary" ]; then
        log "  • Binary ($binary)"
        found_anything=1
    fi

    if [ "$found_anything" -eq 0 ]; then
        log "  ${DIM}Nothing to remove - dcg does not appear to be installed${NC}"
        return 0
    fi

    log ""

    # Confirmation
    if [ "$YES" -eq 0 ]; then
        printf "${YELLOW}Proceed with uninstall? [y/N]${NC} "
        read -r response
        case "$response" in
            [yY]|[yY][eE][sS])
                ;;
            *)
                log "${YELLOW}Uninstall cancelled.${NC}"
                return 0
                ;;
        esac
    fi

    log ""

    # Remove Claude Code hook
    if unconfigure_claude_code 2>&1 | grep -q "removed"; then
        ok "Removed Claude Code hook"
    fi

    # Remove Gemini CLI hook
    if unconfigure_gemini 2>&1 | grep -q "removed"; then
        ok "Removed Gemini CLI hook"
    fi

    # Remove GitHub Copilot CLI hook (repo-local .github/hooks/dcg.json)
    if unconfigure_copilot 2>&1 | grep -q "removed"; then
        ok "Removed GitHub Copilot CLI hook"
    fi

    # Remove Aider config
    if unconfigure_aider; then
        if [ ! -f "$aider_config" ] || ! grep -q 'Added by dcg installer' "$aider_config" 2>/dev/null; then
            ok "Removed Aider configuration"
        fi
    fi

    # Remove config directory
    if [ "$KEEP_CONFIG" -eq 0 ] && [ -d "$config_dir" ]; then
        if rm -rf "$config_dir" 2>/dev/null; then
            ok "Removed configuration directory"
        else
            warn "Failed to remove configuration directory"
        fi
    fi

    # Remove data directory
    if [ "$KEEP_HISTORY" -eq 0 ] && [ -d "$data_dir" ]; then
        if rm -rf "$data_dir" 2>/dev/null; then
            ok "Removed history data"
        else
            warn "Failed to remove history data"
        fi
    fi

    # Remove binary
    if [ -n "$binary" ] && [ -f "$binary" ]; then
        if rm -f "$binary" 2>/dev/null; then
            ok "Removed binary"
        else
            warn "Failed to remove binary - you may need sudo"
            warn "  Run: sudo rm -f $binary"
        fi
    fi

    log ""
    log "${GREEN}${BOLD}Uninstall complete!${NC}"
    log "${DIM}Restart any AI coding agents for changes to take effect.${NC}"
}

main "$@"

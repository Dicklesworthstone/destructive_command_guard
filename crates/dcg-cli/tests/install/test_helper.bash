#!/usr/bin/env bash
# Test helper for install.sh Bats tests
#
# This file is sourced by Bats test files to provide:
# - Common setup/teardown functions
# - install.sh function extraction
# - Utility functions for isolated testing

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INSTALL_SCRIPT="$PROJECT_ROOT/install.sh"
UNINSTALL_SCRIPT="$PROJECT_ROOT/uninstall.sh"

# Extract and source functions from install.sh
# We create a temporary file with just the functions (no execution)
extract_install_functions() {
    local tmp_functions
    tmp_functions="$(mktemp)"

    # Create a modified version of install.sh that can be sourced.
    # Functions are defined throughout the file, including after the download
    # phase. Strip top-level execution blocks while preserving definitions.
    {
        sed '
            # Skip shebang
            1d
            # Replace set -euo pipefail with softer settings
            s/^set -euo pipefail/set -e/
            # Disable exit on errors for sourcing
            s/^umask 022/umask 022; set +e/
            # Drop the top-level install/download execution block. Later hook
            # configuration functions still need to be sourced.
            /^set_artifact_url$/,/^# Claude Code \/ Gemini CLI \/ Cursor Auto-Configuration$/ {
                /^# Claude Code \/ Gemini CLI \/ Cursor Auto-Configuration$/!d
            }
            # Return before the final auto-configuration execution block.
            /^# Run Auto-Configuration$/i\
return 0 2>/dev/null || true
        ' "$INSTALL_SCRIPT"
    } > "$tmp_functions"

    # Suppress all output from sourcing
    # shellcheck disable=SC1090
    source "$tmp_functions" >/dev/null 2>&1 || true
    rm -f "$tmp_functions"
}

# Extract and source functions from uninstall.sh without running main().
extract_uninstall_functions() {
    local tmp_functions
    tmp_functions="$(mktemp)"

    {
        sed '
            1d
            s/^set -euo pipefail/set +e/
            /^main "\$@"/i\
return 0 2>/dev/null || true
        ' "$UNINSTALL_SCRIPT"
    } > "$tmp_functions"

    # shellcheck disable=SC1090
    source "$tmp_functions" >/dev/null 2>&1 || true
    set +e
    rm -f "$tmp_functions"
}

# Create isolated test environment
setup_isolated_home() {
    export TEST_TMPDIR
    TEST_TMPDIR="$(mktemp -d)"
    export ORIGINAL_HOME="$HOME"
    export ORIGINAL_PATH="$PATH"
    export HOME="$TEST_TMPDIR/home"
    mkdir -p "$HOME"

    # Create minimal isolated PATH with only essential tools
    # This prevents detection of user-installed agents like claude, aider, etc.
    mkdir -p "$TEST_TMPDIR/bin"
    export PATH="$TEST_TMPDIR/bin:/usr/bin:/bin"

    # Suppress gum and colors for testing
    export HAS_GUM=0
    export NO_GUM=1
    export QUIET=1
}

# Cleanup test environment
teardown_isolated_home() {
    if [[ -n "${TEST_TMPDIR:-}" && -d "${TEST_TMPDIR:-}" ]]; then
        rm -rf "$TEST_TMPDIR"
    fi
    if [[ -n "${ORIGINAL_HOME:-}" ]]; then
        export HOME="$ORIGINAL_HOME"
    fi
    if [[ -n "${ORIGINAL_PATH:-}" ]]; then
        export PATH="$ORIGINAL_PATH"
    fi
}

# Create mock Claude Code installation
setup_mock_claude() {
    mkdir -p "$HOME/.claude"
    echo '{"hooks": []}' > "$HOME/.claude/settings.json"
}

# Create mock Codex CLI installation
setup_mock_codex() {
    mkdir -p "$HOME/.codex"
    touch "$HOME/.codex/config.toml"
}

codex_hooks_file() {
    echo "${CODEX_SETTINGS:-$HOME/.codex/hooks.json}"
}

seed_codex_hooks_json() {
    local hooks_json
    hooks_json="$(codex_hooks_file)"
    mkdir -p "$(dirname "$hooks_json")"
    printf '%s\n' "$1" > "$hooks_json"
    cp "$hooks_json" "$TEST_TMPDIR/codex_hooks_snapshot.json"
    log_test "Seeded Codex hooks: $(cat "$hooks_json")"
}

save_codex_hooks_snapshot() {
    local hooks_json
    hooks_json="$(codex_hooks_file)"
    if [ -f "$hooks_json" ]; then
        cp "$hooks_json" "$TEST_TMPDIR/codex_hooks_snapshot.json"
    else
        rm -f "$TEST_TMPDIR/codex_hooks_snapshot.json"
    fi
}

assert_codex_hooks_deleted() {
    local hooks_json
    hooks_json="$(codex_hooks_file)"
    [ ! -e "$hooks_json" ]
}

assert_codex_hooks_contains() {
    local hooks_json
    hooks_json="$(codex_hooks_file)"
    grep -qF "$1" "$hooks_json"
}

assert_codex_hooks_not_contains() {
    local hooks_json
    hooks_json="$(codex_hooks_file)"
    ! grep -qF "$1" "$hooks_json"
}

assert_codex_hooks_unchanged() {
    local hooks_json
    hooks_json="$(codex_hooks_file)"
    if [ -f "$TEST_TMPDIR/codex_hooks_snapshot.json" ]; then
        cmp -s "$TEST_TMPDIR/codex_hooks_snapshot.json" "$hooks_json"
    else
        [ ! -e "$hooks_json" ]
    fi
}

# Create mock Gemini CLI installation
setup_mock_gemini() {
    mkdir -p "$HOME/.gemini"
    echo '{}' > "$HOME/.gemini/settings.json"
}

# Create mock Aider installation (just needs command in PATH)
setup_mock_aider() {
    mkdir -p "$TEST_TMPDIR/bin"
    cat > "$TEST_TMPDIR/bin/aider" << 'EOF'
#!/bin/bash
echo "aider 0.50.0"
EOF
    chmod +x "$TEST_TMPDIR/bin/aider"
    export PATH="$TEST_TMPDIR/bin:$PATH"
}

# Create mock Continue installation
setup_mock_continue() {
    mkdir -p "$HOME/.continue"
    echo '{}' > "$HOME/.continue/config.json"
}

# Create mock Hermes Agent installation (config dir + optional pre-existing config)
setup_mock_hermes() {
    mkdir -p "$HOME/.hermes"
    HERMES_CONFIG="$HOME/.hermes/config.yaml"
    export HERMES_CONFIG
}

hermes_config_file() {
    echo "${HERMES_CONFIG:-$HOME/.hermes/config.yaml}"
}

seed_hermes_config() {
    local cfg
    cfg="$(hermes_config_file)"
    mkdir -p "$(dirname "$cfg")"
    printf '%s\n' "$1" > "$cfg"
    cp "$cfg" "$TEST_TMPDIR/hermes_config_snapshot.yaml"
    log_test "Seeded Hermes config: $(cat "$cfg")"
}

assert_hermes_config_contains() {
    local cfg
    cfg="$(hermes_config_file)"
    grep -qF "$1" "$cfg"
}

assert_hermes_config_not_contains() {
    local cfg
    cfg="$(hermes_config_file)"
    ! grep -qF "$1" "$cfg"
}

# Count occurrences of dcg in the pre_tool_call list (requires Python+PyYAML).
hermes_dcg_pre_tool_call_count() {
    local cfg
    cfg="$(hermes_config_file)"
    if ! command -v python3 >/dev/null 2>&1; then
        echo "?"
        return 0
    fi
    if ! python3 -c 'import yaml' >/dev/null 2>&1; then
        echo "?"
        return 0
    fi
    python3 - "$cfg" <<'PYEOF'
import os, shlex, sys, yaml

def is_dcg(cmd):
    if not isinstance(cmd, str) or not cmd:
        return False
    try:
        parts = shlex.split(cmd)
    except ValueError:
        return False
    if not parts:
        return False
    name = os.path.basename(parts[0])
    if name.endswith(".exe"):
        name = name[:-4]
    return name == "dcg"

cfg = sys.argv[1]
try:
    with open(cfg) as f:
        data = yaml.safe_load(f) or {}
except Exception:
    print(0); sys.exit(0)

hooks = (data or {}).get("hooks") or {}
ptc = hooks.get("pre_tool_call") if isinstance(hooks, dict) else None
if not isinstance(ptc, list):
    print(0); sys.exit(0)
print(sum(1 for e in ptc if isinstance(e, dict) and is_dcg(e.get("command"))))
PYEOF
}

# Create a test file with known content and checksum
create_test_file_with_checksum() {
    local content="$1"
    local file="$2"

    echo -n "$content" > "$file"

    # Calculate checksum
    if command -v sha256sum &>/dev/null; then
        sha256sum "$file" | cut -d' ' -f1
    elif command -v shasum &>/dev/null; then
        shasum -a 256 "$file" | cut -d' ' -f1
    fi
}

# Log file for verbose test output
setup_test_log() {
    local test_name="$1"
    export TEST_LOG="$TEST_TMPDIR/test_${test_name}.log"
    echo "=== Test started: $test_name ===" >> "$TEST_LOG"
}

log_test() {
    echo "$@" >> "${TEST_LOG:-/dev/null}"
}

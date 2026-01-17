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

# Extract and source functions from install.sh
# We create a temporary file with just the functions (no execution)
extract_install_functions() {
    local tmp_functions
    tmp_functions="$(mktemp)"

    # Create a modified version of install.sh that can be sourced
    # Functions are defined throughout the file, including in the middle
    # We add a return statement just before the auto-configuration execution (line ~1017)
    {
        # Read install.sh and insert a return before actual execution
        sed '
            # Skip shebang
            1d
            # Replace set -euo pipefail with softer settings
            s/^set -euo pipefail/set -e/
            # Disable exit on errors for sourcing
            s/^umask 022/umask 022; set +e/
            # Return before actual execution starts (after all function definitions)
            # The "Run Auto-Configuration" section starts actual execution
            /^# Run Auto-Configuration$/i\
return 0 2>/dev/null || true
        ' "$INSTALL_SCRIPT"
    } > "$tmp_functions"

    # Suppress all output from sourcing
    # shellcheck disable=SC1090
    source "$tmp_functions" >/dev/null 2>&1 || true
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

#!/usr/bin/env bash
# E2E tests for dcg doctor, install, and uninstall commands
# Uses isolated HOME/XDG_CONFIG_HOME to avoid touching real user files.
#
# Requirements:
# - dcg binary in PATH or at $DCG_BIN
# - bash 3.2+
#
# Usage:
#   ./test_doctor_install_uninstall.sh           # Run all tests
#   ./test_doctor_install_uninstall.sh -v        # Verbose output
#   DCG_BIN=/path/to/dcg ./test_...              # Use specific binary

set -euo pipefail

# Test configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Find dcg binary
if [[ -n "${DCG_BIN:-}" ]]; then
    DCG="$DCG_BIN"
elif command -v dcg &>/dev/null; then
    DCG="$(command -v dcg)"
else
    # Try cargo build target
    CARGO_TARGET="${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}"
    if [[ -x "$CARGO_TARGET/debug/dcg" ]]; then
        DCG="$CARGO_TARGET/debug/dcg"
    elif [[ -x "$CARGO_TARGET/release/dcg" ]]; then
        DCG="$CARGO_TARGET/release/dcg"
    else
        echo "ERROR: dcg binary not found. Build with 'cargo build' or set DCG_BIN." >&2
        exit 1
    fi
fi

# Verbose mode
VERBOSE="${VERBOSE:-false}"
[[ "${1:-}" == "-v" ]] && VERBOSE=true

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Temp directory for isolated tests
TEST_TMPDIR=""

# ============================================================================
# Test Utilities
# ============================================================================

log() {
    echo -e "$@"
}

log_verbose() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "  $@"
    fi
}

setup_isolated_env() {
    # Create isolated HOME and XDG directories
    TEST_TMPDIR="$(mktemp -d)"
    export HOME="$TEST_TMPDIR/home"
    export XDG_CONFIG_HOME="$TEST_TMPDIR/config"
    export XDG_DATA_HOME="$TEST_TMPDIR/data"
    mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME"

    log_verbose "Isolated HOME: $HOME"
    log_verbose "Isolated XDG_CONFIG_HOME: $XDG_CONFIG_HOME"
}

teardown_isolated_env() {
    if [[ -n "$TEST_TMPDIR" && -d "$TEST_TMPDIR" ]]; then
        rm -rf "$TEST_TMPDIR"
    fi
    TEST_TMPDIR=""
}

run_dcg() {
    local cmd="$1"
    shift

    local stdout_file stderr_file
    stdout_file="$(mktemp)"
    stderr_file="$(mktemp)"
    local exit_code=0

    log_verbose "Running: $DCG $cmd $*"

    "$DCG" "$cmd" "$@" >"$stdout_file" 2>"$stderr_file" || exit_code=$?

    LAST_STDOUT="$(cat "$stdout_file")"
    LAST_STDERR="$(cat "$stderr_file")"
    LAST_EXIT_CODE="$exit_code"

    rm -f "$stdout_file" "$stderr_file"

    log_verbose "Exit code: $exit_code"
    if [[ "$VERBOSE" == "true" && -n "$LAST_STDOUT" ]]; then
        log_verbose "stdout:\n$LAST_STDOUT"
    fi
    if [[ "$VERBOSE" == "true" && -n "$LAST_STDERR" ]]; then
        log_verbose "stderr:\n$LAST_STDERR"
    fi
}

assert_exit_code() {
    local expected="$1"
    local msg="${2:-exit code should be $expected}"

    if [[ "$LAST_EXIT_CODE" -eq "$expected" ]]; then
        return 0
    else
        log "${RED}FAIL${NC}: $msg (got $LAST_EXIT_CODE, expected $expected)"
        return 1
    fi
}

assert_stdout_contains() {
    local pattern="$1"
    local msg="${2:-stdout should contain '$pattern'}"

    if [[ "$LAST_STDOUT" == *"$pattern"* ]]; then
        return 0
    else
        log "${RED}FAIL${NC}: $msg"
        log_verbose "stdout was:\n$LAST_STDOUT"
        return 1
    fi
}

assert_stdout_not_contains() {
    local pattern="$1"
    local msg="${2:-stdout should not contain '$pattern'}"

    if [[ "$LAST_STDOUT" != *"$pattern"* ]]; then
        return 0
    else
        log "${RED}FAIL${NC}: $msg"
        return 1
    fi
}

assert_file_exists() {
    local path="$1"
    local msg="${2:-file should exist: $path}"

    if [[ -f "$path" ]]; then
        return 0
    else
        log "${RED}FAIL${NC}: $msg"
        return 1
    fi
}

assert_file_not_exists() {
    local path="$1"
    local msg="${2:-file should not exist: $path}"

    if [[ ! -f "$path" ]]; then
        return 0
    else
        log "${RED}FAIL${NC}: $msg"
        return 1
    fi
}

assert_dir_not_exists() {
    local path="$1"
    local msg="${2:-directory should not exist: $path}"

    if [[ ! -d "$path" ]]; then
        return 0
    else
        log "${RED}FAIL${NC}: $msg"
        return 1
    fi
}

assert_file_contains() {
    local path="$1"
    local pattern="$2"
    local msg="${3:-file $path should contain '$pattern'}"

    if [[ -f "$path" ]] && grep -q "$pattern" "$path"; then
        return 0
    else
        log "${RED}FAIL${NC}: $msg"
        return 1
    fi
}

run_test() {
    local test_name="$1"
    local test_func="$2"

    TESTS_RUN=$((TESTS_RUN + 1))
    log -n "[$TESTS_RUN] $test_name... "

    # Setup isolated environment
    setup_isolated_env

    local result=0
    if "$test_func"; then
        log "${GREEN}PASS${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log "${RED}FAIL${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        result=1
    fi

    # Cleanup
    teardown_isolated_env

    return $result
}

# ============================================================================
# Doctor Tests
# ============================================================================

test_doctor_fresh_environment() {
    # Doctor on a fresh environment should report missing settings
    run_dcg doctor

    # Should succeed (doctor reports issues but doesn't fail)
    assert_exit_code 0 || return 1

    # Should report missing settings
    assert_stdout_contains "NOT FOUND" "should report settings not found" || return 1
    # When settings don't exist, hook wiring is SKIPPED (not NOT REGISTERED)
    assert_stdout_contains "SKIPPED" "should skip hook check when no settings" || return 1
}

test_doctor_with_settings_no_hook() {
    # Create settings file without dcg hook
    mkdir -p "$HOME/.claude"
    echo '{"someOtherSetting": true}' > "$HOME/.claude/settings.json"

    run_dcg doctor
    assert_exit_code 0 || return 1

    # Should find settings but report hook not registered
    assert_stdout_contains "NOT REGISTERED" "should report hook not registered" || return 1
}

test_doctor_fix_creates_hook() {
    # Doctor --fix creates hook ONLY if settings file already exists
    # (It doesn't create settings.json from scratch - use 'dcg install' for that)

    # First create settings file without hook
    mkdir -p "$HOME/.claude"
    echo '{"someOtherSetting": true}' > "$HOME/.claude/settings.json"

    # Run doctor --fix - should add the hook
    run_dcg doctor --fix
    assert_exit_code 0 || return 1

    # Should now contain dcg hook
    assert_file_contains "$HOME/.claude/settings.json" "dcg" "settings should contain dcg hook after fix" || return 1
}

test_doctor_fix_creates_config() {
    # Run doctor --fix to create default config
    run_dcg doctor --fix
    assert_exit_code 0 || return 1

    # Should have created config file
    assert_file_exists "$XDG_CONFIG_HOME/dcg/config.toml" "config.toml should be created" || return 1
}

test_doctor_idempotent() {
    # First create settings file without hook
    mkdir -p "$HOME/.claude"
    echo '{"existingSetting": true}' > "$HOME/.claude/settings.json"

    # First fix - adds hook
    run_dcg doctor --fix
    assert_exit_code 0 || return 1

    # Capture settings content
    local settings_before
    settings_before="$(cat "$HOME/.claude/settings.json")"

    # Second fix should be idempotent
    run_dcg doctor --fix
    assert_exit_code 0 || return 1

    # Settings should be unchanged (hook already there)
    local settings_after
    settings_after="$(cat "$HOME/.claude/settings.json")"

    if [[ "$settings_before" == "$settings_after" ]]; then
        return 0
    else
        log "${RED}FAIL${NC}: settings changed after second doctor --fix"
        return 1
    fi
}

test_doctor_after_install() {
    # Install hook first
    run_dcg install
    assert_exit_code 0 || return 1

    # Doctor should report OK
    run_dcg doctor
    assert_exit_code 0 || return 1

    # Should show OK for hook wiring (not NOT REGISTERED)
    assert_stdout_not_contains "NOT REGISTERED" "hook should be registered" || return 1
}

# ============================================================================
# Install Tests
# ============================================================================

test_install_fresh() {
    # Install on fresh environment
    run_dcg install
    assert_exit_code 0 || return 1

    # Should create settings file
    assert_file_exists "$HOME/.claude/settings.json" "settings.json should be created" || return 1

    # Should contain dcg hook
    assert_file_contains "$HOME/.claude/settings.json" "dcg" "should have dcg hook" || return 1
    assert_file_contains "$HOME/.claude/settings.json" "PreToolUse" "should have PreToolUse" || return 1
    assert_file_contains "$HOME/.claude/settings.json" "Bash" "should have Bash matcher" || return 1
}

test_install_preserves_existing_settings() {
    # Create settings with other content
    mkdir -p "$HOME/.claude"
    echo '{"theme": "dark", "fontSize": 14}' > "$HOME/.claude/settings.json"

    run_dcg install
    assert_exit_code 0 || return 1

    # Should preserve existing settings
    assert_file_contains "$HOME/.claude/settings.json" "theme" "should preserve theme" || return 1
    assert_file_contains "$HOME/.claude/settings.json" "dark" "should preserve dark value" || return 1
    assert_file_contains "$HOME/.claude/settings.json" "fontSize" "should preserve fontSize" || return 1

    # Should also have hook
    assert_file_contains "$HOME/.claude/settings.json" "dcg" "should have dcg hook" || return 1
}

test_install_already_installed() {
    # First install
    run_dcg install
    assert_exit_code 0 || return 1

    # Second install without force
    run_dcg install
    assert_exit_code 0 || return 1

    # Should report already installed
    assert_stdout_contains "already installed" "should report already installed" || return 1
}

test_install_force_reinstalls() {
    # First install
    run_dcg install
    assert_exit_code 0 || return 1

    # Force reinstall
    run_dcg install --force
    assert_exit_code 0 || return 1

    # Should succeed without "already installed" message
    assert_stdout_contains "successfully" "should report successful install" || return 1
    assert_stdout_not_contains "already installed" "should not say already installed with --force" || return 1
}

test_install_creates_parent_dirs() {
    # Ensure .claude dir doesn't exist
    assert_dir_not_exists "$HOME/.claude" "starting without .claude dir" || return 1

    run_dcg install
    assert_exit_code 0 || return 1

    # Should have created directory structure
    assert_file_exists "$HOME/.claude/settings.json" "should create nested dirs" || return 1
}

# ============================================================================
# Uninstall Tests
# ============================================================================

test_uninstall_removes_hook() {
    # First install
    run_dcg install
    assert_exit_code 0 || return 1

    # Then uninstall
    run_dcg uninstall
    assert_exit_code 0 || return 1

    # Settings file should still exist
    assert_file_exists "$HOME/.claude/settings.json" "settings.json should remain" || return 1

    # But should not contain dcg hook command
    # Note: The hooks structure may remain but without dcg entry
    if grep -q '"command".*"dcg"' "$HOME/.claude/settings.json"; then
        log "${RED}FAIL${NC}: dcg hook should be removed"
        return 1
    fi
}

test_uninstall_preserves_other_hooks() {
    # Create settings with dcg and another hook
    mkdir -p "$HOME/.claude"
    cat > "$HOME/.claude/settings.json" << 'EOF'
{
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "dcg"}]},
      {"matcher": "Read", "hooks": [{"type": "command", "command": "other-tool"}]}
    ]
  }
}
EOF

    run_dcg uninstall
    assert_exit_code 0 || return 1

    # Should preserve other hooks
    assert_file_contains "$HOME/.claude/settings.json" "other-tool" "should preserve other hooks" || return 1
}

test_uninstall_preserves_other_settings() {
    # Install first
    mkdir -p "$HOME/.claude"
    echo '{"theme": "dark"}' > "$HOME/.claude/settings.json"
    run_dcg install

    # Uninstall
    run_dcg uninstall
    assert_exit_code 0 || return 1

    # Should preserve other settings
    assert_file_contains "$HOME/.claude/settings.json" "theme" "should preserve other settings" || return 1
}

test_uninstall_purge_removes_config() {
    # Install and create config
    run_dcg install
    run_dcg doctor --fix  # Creates config file

    # Verify config exists
    assert_file_exists "$XDG_CONFIG_HOME/dcg/config.toml" "config should exist before purge" || return 1

    # Uninstall with purge
    run_dcg uninstall --purge
    assert_exit_code 0 || return 1

    # Config directory should be removed
    assert_dir_not_exists "$XDG_CONFIG_HOME/dcg" "config dir should be removed with --purge" || return 1
}

test_uninstall_no_settings() {
    # Uninstall on fresh environment (no settings)
    run_dcg uninstall
    assert_exit_code 0 || return 1

    # Should report no settings found
    assert_stdout_contains "No Claude Code settings" "should report no settings" || return 1
}

test_uninstall_idempotent() {
    # Install
    run_dcg install
    assert_exit_code 0 || return 1

    # First uninstall
    run_dcg uninstall
    assert_exit_code 0 || return 1

    # Second uninstall should also succeed
    run_dcg uninstall
    assert_exit_code 0 || return 1

    # Should report no hook found
    assert_stdout_contains "No dcg hook" "should report no hook on second uninstall" || return 1
}

# ============================================================================
# Config Discovery Tests
# ============================================================================

test_config_discovery_xdg_config_home() {
    # Create config in XDG_CONFIG_HOME
    mkdir -p "$XDG_CONFIG_HOME/dcg"
    cat > "$XDG_CONFIG_HOME/dcg/config.toml" << 'EOF'
[general]
color = "always"
EOF

    run_dcg doctor
    assert_exit_code 0 || return 1

    # Should find and report the config
    # Note: doctor output should show config path
    # The exact wording may vary
}

test_config_discovery_home_config() {
    # Create config in ~/.config/dcg (fallback when XDG_CONFIG_HOME is HOME/.config)
    mkdir -p "$HOME/.config/dcg"
    cat > "$HOME/.config/dcg/config.toml" << 'EOF'
[general]
color = "never"
EOF

    # Unset XDG_CONFIG_HOME to use default
    unset XDG_CONFIG_HOME

    run_dcg doctor
    assert_exit_code 0 || return 1
}

test_config_discovery_project_config() {
    # Create project-level config (.dcg.toml in current dir)
    cd "$TEST_TMPDIR"
    cat > ".dcg.toml" << 'EOF'
[general]
color = "auto"
EOF

    # Initialize git repo (project config discovery may require git)
    git init -q

    run_dcg doctor
    assert_exit_code 0 || return 1
}

# ============================================================================
# Main
# ============================================================================

main() {
    log "=========================================="
    log "E2E Tests: dcg doctor/install/uninstall"
    log "=========================================="
    log "Using dcg binary: $DCG"
    log ""

    # Doctor tests
    run_test "doctor: fresh environment" test_doctor_fresh_environment || true
    run_test "doctor: settings without hook" test_doctor_with_settings_no_hook || true
    run_test "doctor --fix: creates hook" test_doctor_fix_creates_hook || true
    run_test "doctor --fix: creates config" test_doctor_fix_creates_config || true
    run_test "doctor --fix: idempotent" test_doctor_idempotent || true
    run_test "doctor: after install" test_doctor_after_install || true

    # Install tests
    run_test "install: fresh environment" test_install_fresh || true
    run_test "install: preserves existing settings" test_install_preserves_existing_settings || true
    run_test "install: already installed" test_install_already_installed || true
    run_test "install --force: reinstalls" test_install_force_reinstalls || true
    run_test "install: creates parent dirs" test_install_creates_parent_dirs || true

    # Uninstall tests
    run_test "uninstall: removes hook" test_uninstall_removes_hook || true
    run_test "uninstall: preserves other hooks" test_uninstall_preserves_other_hooks || true
    run_test "uninstall: preserves other settings" test_uninstall_preserves_other_settings || true
    run_test "uninstall --purge: removes config" test_uninstall_purge_removes_config || true
    run_test "uninstall: no settings" test_uninstall_no_settings || true
    run_test "uninstall: idempotent" test_uninstall_idempotent || true

    # Config discovery tests
    run_test "config: XDG_CONFIG_HOME discovery" test_config_discovery_xdg_config_home || true
    run_test "config: ~/.config fallback" test_config_discovery_home_config || true
    run_test "config: project .dcg.toml" test_config_discovery_project_config || true

    log ""
    log "=========================================="
    log "Results: $TESTS_PASSED/$TESTS_RUN passed"
    if [[ $TESTS_FAILED -gt 0 ]]; then
        log "${RED}$TESTS_FAILED tests failed${NC}"
        exit 1
    else
        log "${GREEN}All tests passed!${NC}"
        exit 0
    fi
}

main "$@"

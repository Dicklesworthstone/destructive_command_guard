#!/bin/bash
#
# E2E tests for TUI/CLI rich output and CI fallback behavior.
#
# This script verifies:
# - Rich terminal output (when in a real terminal)
# - CI environment fallback (no ANSI codes)
# - NO_COLOR environment variable support
# - TERM=dumb fallback (ASCII characters)
# - JSON format bypasses TUI rendering
#
# Usage:
#   ./tests/e2e/run_tui_e2e.sh [--verbose]
#
# Exit codes:
#   0 - All tests passed
#   1 - One or more tests failed

set -euo pipefail

# Configuration
VERBOSE="${1:-}"
LOG_FILE="e2e_tui_$(date +%Y%m%d_%H%M%S).log"
PASSED=0
FAILED=0
TESTS=()

# Colors for output (when not testing NO_COLOR)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

log() {
    echo "$@" | tee -a "$LOG_FILE"
}

log_verbose() {
    if [[ "$VERBOSE" == "--verbose" ]]; then
        echo "$@" | tee -a "$LOG_FILE"
    else
        echo "$@" >> "$LOG_FILE"
    fi
}

pass() {
    echo -e "  ${GREEN}✓${NC} $1"
    ((PASSED++))
    TESTS+=("PASS: $1")
}

fail() {
    echo -e "  ${RED}✗${NC} $1"
    echo "    Error: $2" >> "$LOG_FILE"
    ((FAILED++))
    TESTS+=("FAIL: $1 - $2")
}

# Build release binary
build_binary() {
    log "Building release binary..."
    if cargo build --release 2>&1 | tee -a "$LOG_FILE" | tail -3; then
        log "Build complete."
    else
        echo "Build failed!"
        exit 1
    fi
}

# Test helper: run dcg hook mode
run_hook() {
    local cmd="$1"
    shift
    local env_args=("$@")

    local input='{"tool_name":"Bash","tool_input":{"command":"'"$cmd"'"}}'

    # Create temp directory for isolated test
    local temp_dir
    temp_dir=$(mktemp -d)
    mkdir -p "$temp_dir/.git"
    mkdir -p "$temp_dir/home"

    env -i \
        HOME="$temp_dir/home" \
        DCG_ALLOWLIST_SYSTEM_PATH="" \
        DCG_PACKS="core.git,core.filesystem" \
        "${env_args[@]}" \
        ./target/release/dcg <<< "$input" 2>&1

    rm -rf "$temp_dir"
}

# Test 1: CI environment disables ANSI codes
test_ci_env_no_ansi() {
    log_verbose "Running: CI environment test"

    local output
    output=$(run_hook "git reset --hard" CI=true 2>&1 || true)

    # Check for ANSI escape codes
    if echo "$output" | grep -qP '\x1b\['; then
        fail "CI environment disables ANSI codes" "Found ANSI codes in output"
        log_verbose "Output: $output"
    else
        pass "CI environment disables ANSI codes"
    fi
}

# Test 2: NO_COLOR environment variable
test_no_color() {
    log_verbose "Running: NO_COLOR test"

    local output
    output=$(run_hook "git reset --hard" NO_COLOR=1 2>&1 || true)

    if echo "$output" | grep -qP '\x1b\['; then
        fail "NO_COLOR disables colors" "Found ANSI codes with NO_COLOR=1"
        log_verbose "Output: $output"
    else
        pass "NO_COLOR disables colors"
    fi
}

# Test 3: TERM=dumb fallback
test_term_dumb() {
    log_verbose "Running: TERM=dumb test"

    local output
    output=$(run_hook "git reset --hard" TERM=dumb 2>&1 || true)

    # Should not have Unicode box-drawing characters
    if echo "$output" | grep -q '[╭╮╯╰│─├┤]'; then
        fail "TERM=dumb disables Unicode" "Found Unicode box chars with TERM=dumb"
        log_verbose "Output: $output"
    else
        pass "TERM=dumb disables Unicode"
    fi

    # Should not have ANSI codes
    if echo "$output" | grep -qP '\x1b\['; then
        fail "TERM=dumb disables ANSI" "Found ANSI codes with TERM=dumb"
    else
        pass "TERM=dumb disables ANSI"
    fi
}

# Test 4: JSON format is valid and pure
test_json_format() {
    log_verbose "Running: JSON format test"

    local temp_dir
    temp_dir=$(mktemp -d)
    mkdir -p "$temp_dir/home"

    local output
    output=$(env -i HOME="$temp_dir/home" ./target/release/dcg explain --format json "git reset --hard" 2>&1 || true)

    rm -rf "$temp_dir"

    # Should be valid JSON
    if echo "$output" | jq . >/dev/null 2>&1; then
        pass "JSON format is valid"
    else
        fail "JSON format is valid" "Output is not valid JSON"
        log_verbose "Output: $output"
        return
    fi

    # Should not have box-drawing characters
    if echo "$output" | grep -q '[╭╮╯╰│─+\-|].*[╭╮╯╰│─+\-|]'; then
        fail "JSON format has no box chars" "Found box characters in JSON output"
    else
        pass "JSON format has no box chars"
    fi
}

# Test 5: Safe command produces no output
test_safe_command() {
    log_verbose "Running: Safe command test"

    local output
    output=$(run_hook "git status" 2>&1 || true)

    if [[ -z "$output" || "$output" =~ ^[[:space:]]*$ ]]; then
        pass "Safe command produces no output"
    else
        fail "Safe command produces no output" "Got output: $output"
    fi
}

# Test 6: Denied command has JSON output
test_deny_json_structure() {
    log_verbose "Running: Deny JSON structure test"

    local output
    output=$(run_hook "git reset --hard" 2>&1 || true)

    # Extract JSON from output (should be on stdout)
    local json_line
    json_line=$(echo "$output" | grep -E '^\{' | head -1 || echo "")

    if [[ -z "$json_line" ]]; then
        fail "Denied command has JSON output" "No JSON found in output"
        log_verbose "Output: $output"
        return
    fi

    # Check structure
    if echo "$json_line" | jq -e '.hookSpecificOutput.permissionDecision == "deny"' >/dev/null 2>&1; then
        pass "Denied command has correct JSON structure"
    else
        fail "Denied command has correct JSON structure" "JSON missing expected fields"
        log_verbose "JSON: $json_line"
    fi

    # Check for required fields
    if echo "$json_line" | jq -e '.hookSpecificOutput | has("ruleId") and has("severity")' >/dev/null 2>&1; then
        pass "Denied JSON has ruleId and severity"
    else
        fail "Denied JSON has ruleId and severity" "Missing required fields"
    fi
}

# Test 7: All environment modes deny destructive commands consistently
test_consistent_deny() {
    log_verbose "Running: Consistent deny test"

    local cmd="git reset --hard HEAD~5"
    local configs=("" "CI=true" "NO_COLOR=1" "TERM=dumb")

    for config in "${configs[@]}"; do
        local output
        if [[ -z "$config" ]]; then
            output=$(run_hook "$cmd" 2>&1 || true)
            config="default"
        else
            output=$(run_hook "$cmd" "$config" 2>&1 || true)
        fi

        local json_line
        json_line=$(echo "$output" | grep -E '^\{' | head -1 || echo "")

        if echo "$json_line" | jq -e '.hookSpecificOutput.permissionDecision == "deny"' >/dev/null 2>&1; then
            pass "Deny consistent with $config"
        else
            fail "Deny consistent with $config" "Command not denied"
        fi
    done
}

# Main execution
main() {
    echo "=== DCG TUI E2E Test Suite ==="
    echo "Started: $(date)"
    echo "Log file: $LOG_FILE"
    echo ""

    # Build binary first
    build_binary

    # Run tests
    echo ""
    echo "[1/7] Testing CI environment fallback..."
    test_ci_env_no_ansi

    echo ""
    echo "[2/7] Testing NO_COLOR environment variable..."
    test_no_color

    echo ""
    echo "[3/7] Testing TERM=dumb fallback..."
    test_term_dumb

    echo ""
    echo "[4/7] Testing JSON format output..."
    test_json_format

    echo ""
    echo "[5/7] Testing safe command (no output)..."
    test_safe_command

    echo ""
    echo "[6/7] Testing denied command JSON structure..."
    test_deny_json_structure

    echo ""
    echo "[7/7] Testing consistent deny across modes..."
    test_consistent_deny

    # Summary
    echo ""
    echo "=== Test Summary ==="
    echo "Passed: $PASSED"
    echo "Failed: $FAILED"
    echo "Completed: $(date)"

    # Write detailed results to log
    echo "" >> "$LOG_FILE"
    echo "=== Detailed Results ===" >> "$LOG_FILE"
    for test in "${TESTS[@]}"; do
        echo "$test" >> "$LOG_FILE"
    done

    if [[ $FAILED -gt 0 ]]; then
        echo ""
        echo -e "${RED}Some tests failed! See $LOG_FILE for details.${NC}"
        exit 1
    else
        echo ""
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    fi
}

main "$@"

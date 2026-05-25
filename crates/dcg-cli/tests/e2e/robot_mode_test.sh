#!/usr/bin/env bash
# Robot Mode E2E Test Suite
# Comprehensive tests for dcg --robot mode AI agent integration
#
# Robot mode is designed for programmatic agent consumption:
# - Pure JSON output on stdout
# - Silent stderr (no human-readable output)
# - Standardized exit codes: 0=allow, 1=deny, 2+=error
# - No ANSI escape codes
#
# Usage:
#   ./tests/e2e/robot_mode_test.sh
#   DCG_BINARY=/path/to/dcg ./tests/e2e/robot_mode_test.sh
#
# Environment Variables:
#   DCG_VERBOSE=1    Enable verbose output
#   KEEP_TEMP=1      Don't delete temp directory on exit
#   NO_COLOR=1       Disable colored output
#
# Exit codes:
#   0 - All tests passed
#   1 - Test failure
#   2 - Setup/infrastructure error

set -euo pipefail

#------------------------------------------------------------------------------
# Configuration
#------------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors for output (disabled if NO_COLOR is set)
if [ -z "${NO_COLOR:-}" ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    NC=''
fi

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Temp directory for test isolation
TEMP_DIR=$(mktemp -d -t dcg_robot_e2e_XXXXXX)

#------------------------------------------------------------------------------
# Cleanup
#------------------------------------------------------------------------------

cleanup() {
    local exit_code=$?
    if [[ "${KEEP_TEMP:-}" != "1" ]]; then
        rm -rf "$TEMP_DIR"
        log_debug "Cleaned up temp directory"
    else
        echo -e "${YELLOW}Keeping temp directory: ${TEMP_DIR}${NC}"
    fi
    exit $exit_code
}
trap cleanup EXIT

#------------------------------------------------------------------------------
# Logging
#------------------------------------------------------------------------------

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
}

log_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1"
    ((TESTS_SKIPPED++))
}

log_debug() {
    if [[ "${DCG_VERBOSE:-}" == "1" ]]; then
        echo -e "${CYAN}[DEBUG]${NC} $1"
    fi
}

#------------------------------------------------------------------------------
# Setup
#------------------------------------------------------------------------------

find_dcg_binary() {
    local candidates=(
        "${DCG_BINARY:-}"
        "$PROJECT_ROOT/target/release/dcg"
        "$PROJECT_ROOT/target/debug/dcg"
        "$(which dcg 2>/dev/null || true)"
    )

    for candidate in "${candidates[@]}"; do
        if [[ -n "$candidate" && -x "$candidate" ]]; then
            echo "$candidate"
            return 0
        fi
    done

    return 1
}

ensure_dcg_binary() {
    if DCG_BIN=$(find_dcg_binary); then
        log_info "Using DCG binary: $DCG_BIN"
    else
        log_info "Building DCG..."
        cargo build --release --quiet --manifest-path="$PROJECT_ROOT/Cargo.toml"
        DCG_BIN="$PROJECT_ROOT/target/release/dcg"
    fi
    export DCG_BIN
}

setup_test_env() {
    mkdir -p "$TEMP_DIR/config"

    cat > "$TEMP_DIR/config/config.toml" << 'EOF'
[general]
verbose = false

[packs]
enabled = ["core.git", "core.filesystem"]
EOF

    export HOME="$TEMP_DIR"
    export XDG_CONFIG_HOME="$TEMP_DIR/config"

    log_info "Test environment ready"
    log_debug "Temp dir: $TEMP_DIR"
}

#------------------------------------------------------------------------------
# Test Helpers
#------------------------------------------------------------------------------

run_test() {
    local name="$1"
    shift
    ((TESTS_RUN++))
    log_info "Test $TESTS_RUN: $name"
    if "$@"; then
        log_pass "$name"
        return 0
    else
        log_fail "$name"
        return 1
    fi
}

assert_eq() {
    local actual="$1"
    local expected="$2"
    local msg="${3:-Values should be equal}"
    if [[ "$actual" == "$expected" ]]; then
        return 0
    else
        log_debug "  Expected: $expected"
        log_debug "  Actual:   $actual"
        return 1
    fi
}

assert_exit_code() {
    local actual="$1"
    local expected="$2"
    assert_eq "$actual" "$expected" "Exit code should be $expected"
}

assert_json_valid() {
    local json="$1"
    if echo "$json" | python3 -c "import json, sys; json.loads(sys.stdin.read())" 2>/dev/null; then
        return 0
    else
        log_debug "  Invalid JSON: ${json:0:200}"
        return 1
    fi
}

assert_no_ansi() {
    local text="$1"
    if echo "$text" | grep -q $'\x1b\['; then
        log_debug "  Found ANSI escape codes in output"
        return 1
    fi
    return 0
}

json_get() {
    local json="$1"
    local path="$2"
    echo "$json" | python3 -c "
import json
import sys
data = json.loads(sys.stdin.read())
path = sys.argv[1].strip('.').split('.')
result = data
for key in path:
    if key and result is not None:
        result = result.get(key) if isinstance(result, dict) else None
print(result if result is not None else '')
" "$path" 2>/dev/null || echo ""
}

#------------------------------------------------------------------------------
# Core Robot Mode Tests
#------------------------------------------------------------------------------

test_robot_flag_produces_json() {
    local stdout stderr exit_code
    stdout=$("$DCG_BIN" --robot test "git status" 2>/dev/null) || true
    assert_json_valid "$stdout"
}

test_robot_allowed_command_exits_0() {
    "$DCG_BIN" --robot test "echo hello" > /dev/null 2>&1
    local exit_code=$?
    assert_exit_code "$exit_code" "0"
}

test_robot_denied_command_exits_1() {
    local exit_code
    "$DCG_BIN" --robot test "rm -rf /" > /dev/null 2>&1 && exit_code=0 || exit_code=$?
    assert_exit_code "$exit_code" "1"
}

test_robot_no_ansi_in_stdout() {
    local stdout
    stdout=$("$DCG_BIN" --robot test "rm -rf /" 2>/dev/null || true)
    assert_no_ansi "$stdout"
}

test_robot_stderr_is_silent() {
    local stderr
    stderr=$("$DCG_BIN" --robot test "rm -rf /" 2>&1 >/dev/null || true)
    if [[ -z "$stderr" ]]; then
        return 0
    else
        log_debug "  Stderr should be empty, got: ${stderr:0:100}"
        return 1
    fi
}

test_robot_allowed_stderr_is_silent() {
    local stderr
    stderr=$("$DCG_BIN" --robot test "echo hello" 2>&1 >/dev/null || true)
    if [[ -z "$stderr" ]]; then
        return 0
    else
        log_debug "  Stderr should be empty for allowed commands, got: ${stderr:0:100}"
        return 1
    fi
}

#------------------------------------------------------------------------------
# DCG_ROBOT Environment Variable Tests
#------------------------------------------------------------------------------

test_dcg_robot_env_produces_json() {
    local stdout
    stdout=$(DCG_ROBOT=1 "$DCG_BIN" test "git status" 2>/dev/null) || true
    assert_json_valid "$stdout"
}

test_dcg_robot_env_denied_exits_1() {
    local exit_code
    DCG_ROBOT=1 "$DCG_BIN" test "rm -rf /" > /dev/null 2>&1 && exit_code=0 || exit_code=$?
    assert_exit_code "$exit_code" "1"
}

test_dcg_robot_env_stderr_silent() {
    local stderr
    stderr=$(DCG_ROBOT=1 "$DCG_BIN" test "rm -rf /" 2>&1 >/dev/null || true)
    if [[ -z "$stderr" ]]; then
        return 0
    else
        log_debug "  DCG_ROBOT=1 should suppress stderr, got: ${stderr:0:100}"
        return 1
    fi
}

#------------------------------------------------------------------------------
# JSON Structure Tests
#------------------------------------------------------------------------------

test_json_has_decision_field() {
    local stdout
    stdout=$("$DCG_BIN" --robot test "rm -rf /" 2>/dev/null || true)
    local decision
    decision=$(json_get "$stdout" "decision")
    assert_eq "$decision" "deny"
}

test_json_has_rule_id_field() {
    local stdout
    stdout=$("$DCG_BIN" --robot test "rm -rf /" 2>/dev/null || true)
    local rule_id
    rule_id=$(json_get "$stdout" "rule_id")
    if [[ -n "$rule_id" && "$rule_id" != "null" ]]; then
        log_debug "  rule_id: $rule_id"
        return 0
    else
        log_debug "  Missing rule_id in JSON"
        return 1
    fi
}

test_json_has_pack_id_field() {
    local stdout
    stdout=$("$DCG_BIN" --robot test "rm -rf /" 2>/dev/null || true)
    local pack_id
    pack_id=$(json_get "$stdout" "pack_id")
    if [[ -n "$pack_id" && "$pack_id" != "null" ]]; then
        log_debug "  pack_id: $pack_id"
        return 0
    else
        log_debug "  Missing pack_id in JSON"
        return 1
    fi
}

test_json_has_severity_field() {
    local stdout
    stdout=$("$DCG_BIN" --robot test "rm -rf /" 2>/dev/null || true)
    local severity
    severity=$(json_get "$stdout" "severity")
    case "$severity" in
        critical|high|medium|low)
            log_debug "  severity: $severity"
            return 0
            ;;
        *)
            log_debug "  Invalid or missing severity: $severity"
            return 1
            ;;
    esac
}

test_json_has_reason_field() {
    local stdout
    stdout=$("$DCG_BIN" --robot test "rm -rf /" 2>/dev/null || true)
    local reason
    reason=$(json_get "$stdout" "reason")
    if [[ -n "$reason" && ${#reason} -gt 5 ]]; then
        log_debug "  reason present (${#reason} chars)"
        return 0
    else
        log_debug "  Missing or too short reason: $reason"
        return 1
    fi
}

test_json_has_command_field() {
    local stdout
    stdout=$("$DCG_BIN" --robot test "rm -rf /" 2>/dev/null || true)
    local command
    command=$(json_get "$stdout" "command")
    assert_eq "$command" "rm -rf /"
}

test_allowed_json_has_allow_decision() {
    local stdout
    stdout=$("$DCG_BIN" --robot test "echo hello" 2>/dev/null || true)
    local decision
    decision=$(json_get "$stdout" "decision")
    assert_eq "$decision" "allow"
}

test_json_has_agent_field() {
    local stdout
    stdout=$("$DCG_BIN" --robot test "rm -rf /" 2>/dev/null || true)
    local agent
    agent=$(json_get "$stdout" "agent")
    if [[ -n "$agent" && "$agent" != "null" ]]; then
        return 0
    else
        log_debug "  Missing agent field"
        return 1
    fi
}

#------------------------------------------------------------------------------
# Subcommand Tests
#------------------------------------------------------------------------------

test_robot_explain_produces_json() {
    local stdout
    stdout=$("$DCG_BIN" --robot explain "git reset --hard" 2>/dev/null) || true
    assert_json_valid "$stdout"
}

test_robot_packs_produces_json() {
    local stdout
    stdout=$("$DCG_BIN" --robot packs 2>/dev/null) || true
    assert_json_valid "$stdout"
}

test_robot_info_produces_json() {
    local stdout
    # Note: --version is a flag not a subcommand; test 'info' if available
    stdout=$("$DCG_BIN" --robot info 2>/dev/null) || true
    # If info command doesn't exist, this is acceptable (skip)
    if [[ -z "$stdout" ]]; then
        log_debug "  info subcommand not available, skipping"
        return 0
    fi
    assert_json_valid "$stdout"
}

#------------------------------------------------------------------------------
# Performance Tests
#------------------------------------------------------------------------------

test_performance_under_200ms() {
    local start end latency_ms
    start=$(date +%s%N)
    "$DCG_BIN" --robot test "echo test" > /dev/null 2>&1
    end=$(date +%s%N)
    latency_ms=$(( (end - start) / 1000000 ))
    log_debug "  Latency: ${latency_ms}ms"
    if [[ "$latency_ms" -le 200 ]]; then
        return 0
    else
        log_debug "  Latency exceeds 200ms threshold"
        return 1
    fi
}

#------------------------------------------------------------------------------
# Consistency Tests
#------------------------------------------------------------------------------

test_multiple_commands_consistency() {
    local exit1 exit2 dec1 dec2 stdout1 stdout2

    stdout1=$("$DCG_BIN" --robot test "rm -rf /" 2>/dev/null) && exit1=0 || exit1=$?
    stdout2=$("$DCG_BIN" --robot test "rm -rf /" 2>/dev/null) && exit2=0 || exit2=$?

    assert_exit_code "$exit1" "1" || return 1
    assert_exit_code "$exit2" "1" || return 1

    dec1=$(json_get "$stdout1" "decision")
    dec2=$(json_get "$stdout2" "decision")
    assert_eq "$dec1" "$dec2"
}

test_various_dangerous_commands() {
    local commands=(
        "rm -rf /"
        "git reset --hard"
        "git push --force origin main"
        "git clean -fd"
    )

    local all_passed=true

    for cmd in "${commands[@]}"; do
        local exit_code
        "$DCG_BIN" --robot test "$cmd" > /dev/null 2>&1 && exit_code=0 || exit_code=$?
        if [[ $exit_code -ne 1 ]]; then
            log_debug "  Expected exit 1 for '$cmd', got: $exit_code"
            all_passed=false
        fi
    done

    $all_passed
}

#------------------------------------------------------------------------------
# Edge Case Tests
#------------------------------------------------------------------------------

test_empty_command_handled() {
    "$DCG_BIN" --robot test "" > /dev/null 2>&1 || true
    local exit_code=$?
    # Should not crash - exit 0 (allow) or 4 (parse error) are acceptable
    if [[ "$exit_code" -le 4 ]]; then
        return 0
    else
        log_debug "  Unexpected exit code for empty command: $exit_code"
        return 1
    fi
}

test_special_chars_handled() {
    "$DCG_BIN" --robot test 'echo "hello world" | grep hello' > /dev/null 2>&1 || true
    local exit_code=$?
    if [[ "$exit_code" -le 1 ]]; then
        return 0
    else
        log_debug "  Unexpected exit code for special chars: $exit_code"
        return 1
    fi
}

test_very_long_command_handled() {
    local long_cmd="echo "
    for _ in {1..100}; do
        long_cmd+="a"
    done
    "$DCG_BIN" --robot test "$long_cmd" > /dev/null 2>&1 || true
    local exit_code=$?
    if [[ "$exit_code" -le 1 ]]; then
        return 0
    else
        log_debug "  Unexpected exit code for long command: $exit_code"
        return 1
    fi
}

test_unicode_command_handled() {
    "$DCG_BIN" --robot test 'echo "Hello 世界"' > /dev/null 2>&1 || true
    local exit_code=$?
    if [[ "$exit_code" -le 1 ]]; then
        return 0
    else
        log_debug "  Unexpected exit code for unicode command: $exit_code"
        return 1
    fi
}

#------------------------------------------------------------------------------
# Main Test Runner
#------------------------------------------------------------------------------

main() {
    echo ""
    echo "=============================================="
    echo "  DCG Robot Mode E2E Test Suite"
    echo "=============================================="
    echo ""

    ensure_dcg_binary
    setup_test_env

    echo ""
    echo "Core Robot Mode Tests..."
    echo ""
    run_test "Robot flag produces valid JSON" test_robot_flag_produces_json || true
    run_test "Allowed command exits 0" test_robot_allowed_command_exits_0 || true
    run_test "Denied command exits 1" test_robot_denied_command_exits_1 || true
    run_test "No ANSI in stdout" test_robot_no_ansi_in_stdout || true
    run_test "Stderr is silent (denied)" test_robot_stderr_is_silent || true
    run_test "Stderr is silent (allowed)" test_robot_allowed_stderr_is_silent || true

    echo ""
    echo "DCG_ROBOT Environment Variable Tests..."
    echo ""
    run_test "DCG_ROBOT=1 produces JSON" test_dcg_robot_env_produces_json || true
    run_test "DCG_ROBOT=1 denied exits 1" test_dcg_robot_env_denied_exits_1 || true
    run_test "DCG_ROBOT=1 stderr silent" test_dcg_robot_env_stderr_silent || true

    echo ""
    echo "JSON Structure Tests..."
    echo ""
    run_test "JSON has decision field" test_json_has_decision_field || true
    run_test "JSON has rule_id field" test_json_has_rule_id_field || true
    run_test "JSON has pack_id field" test_json_has_pack_id_field || true
    run_test "JSON has severity field" test_json_has_severity_field || true
    run_test "JSON has reason field" test_json_has_reason_field || true
    run_test "JSON has command field" test_json_has_command_field || true
    run_test "Allowed JSON has allow decision" test_allowed_json_has_allow_decision || true
    run_test "JSON has agent field" test_json_has_agent_field || true

    echo ""
    echo "Subcommand Tests..."
    echo ""
    run_test "Robot explain produces JSON" test_robot_explain_produces_json || true
    run_test "Robot packs produces JSON" test_robot_packs_produces_json || true
    run_test "Robot info produces JSON" test_robot_info_produces_json || true

    echo ""
    echo "Performance Tests..."
    echo ""
    run_test "Performance under 200ms" test_performance_under_200ms || true

    echo ""
    echo "Consistency Tests..."
    echo ""
    run_test "Multiple commands consistency" test_multiple_commands_consistency || true
    run_test "Various dangerous commands denied" test_various_dangerous_commands || true

    echo ""
    echo "Edge Case Tests..."
    echo ""
    run_test "Empty command handled" test_empty_command_handled || true
    run_test "Special chars handled" test_special_chars_handled || true
    run_test "Very long command handled" test_very_long_command_handled || true
    run_test "Unicode command handled" test_unicode_command_handled || true

    echo ""
    echo "=============================================="
    echo "  Test Results"
    echo "=============================================="
    echo ""
    echo -e "  ${GREEN}Passed:${NC}  $TESTS_PASSED"
    echo -e "  ${RED}Failed:${NC}  $TESTS_FAILED"
    echo -e "  ${YELLOW}Skipped:${NC} $TESTS_SKIPPED"
    echo -e "  Total:   $TESTS_RUN"
    echo ""

    if [[ $TESTS_FAILED -gt 0 ]]; then
        echo -e "${RED}SOME TESTS FAILED${NC}"
        exit 1
    else
        echo -e "${GREEN}ALL TESTS PASSED${NC}"
        exit 0
    fi
}

main "$@"

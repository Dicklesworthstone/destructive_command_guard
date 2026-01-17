#!/usr/bin/env bash
# Agent Ergonomics E2E Test Runner
#
# This script runs comprehensive end-to-end tests for AI agent integration features.
# It verifies Claude Code hook protocol compliance, JSON output structure,
# and agent-facing fields like ruleId, severity, and remediation suggestions.
#
# Usage:
#   ./tests/e2e/run_agent_e2e.sh
#
# Environment Variables:
#   DCG_VERBOSE=1    Enable verbose output
#   KEEP_TEMP=1      Don't delete temp directory on exit (for debugging)

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Create temp directory for test isolation
TEMP_DIR=$(mktemp -d -t dcg_agent_e2e_XXXXXX)
DCG_CONFIG_DIR="${TEMP_DIR}/config"

# Cleanup handler
cleanup() {
    local exit_code=$?
    if [[ "${KEEP_TEMP:-}" != "1" ]]; then
        rm -rf "$TEMP_DIR"
        echo -e "${BLUE}Cleaned up temp directory${NC}"
    else
        echo -e "${YELLOW}Keeping temp directory: ${TEMP_DIR}${NC}"
    fi
    exit $exit_code
}
trap cleanup EXIT

# Log functions
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

# Find the DCG binary
find_dcg_binary() {
    local candidates=(
        "./target/release/dcg"
        "./target/debug/dcg"
        "$(which dcg 2>/dev/null || true)"
    )

    for candidate in "${candidates[@]}"; do
        if [[ -x "$candidate" ]]; then
            echo "$candidate"
            return 0
        fi
    done

    return 1
}

# Build DCG if needed
ensure_dcg_binary() {
    if DCG_BIN=$(find_dcg_binary); then
        log_info "Using existing DCG binary: $DCG_BIN"
    else
        log_info "Building DCG..."
        cargo build --release --quiet
        DCG_BIN="./target/release/dcg"
    fi
    export DCG_BIN
}

# Setup test environment
setup_test_env() {
    mkdir -p "$DCG_CONFIG_DIR"

    # Create a minimal config
    cat > "${DCG_CONFIG_DIR}/config.toml" << 'EOF'
[general]
verbose = false

[packs]
enabled = ["core.git", "core.filesystem"]
EOF

    export DCG_CONFIG="${DCG_CONFIG_DIR}/config.toml"
    export HOME="$TEMP_DIR"
    export XDG_CONFIG_HOME="$DCG_CONFIG_DIR"

    log_info "Test environment setup complete"
    log_info "  Temp dir: $TEMP_DIR"
}

# Run DCG in hook mode with JSON input
run_hook_mode() {
    local command="$1"
    # Escape backslashes and double quotes for JSON
    local escaped_command
    escaped_command=$(printf '%s' "$command" | sed 's/\\/\\\\/g; s/"/\\"/g')
    local input="{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"$escaped_command\"}}"

    log_debug "Input: $input"

    local result
    result=$(echo "$input" | "$DCG_BIN" 2>/dev/null || true)

    log_debug "Output: $result"
    echo "$result"
}

# Check if jq is available
check_jq() {
    if command -v jq &>/dev/null; then
        return 0
    else
        return 1
    fi
}

# JSON field extraction (works with or without jq)
json_get() {
    local json="$1"
    local path="$2"

    if check_jq; then
        echo "$json" | jq -r "$path" 2>/dev/null || echo ""
    else
        # Fallback: use python for JSON parsing
        python3 -c "
import json
import sys
data = json.loads(sys.argv[1])
path = sys.argv[2].strip('.').split('.')
result = data
for key in path:
    if key and result is not None:
        result = result.get(key) if isinstance(result, dict) else None
print(result if result is not None else '')
" "$json" "$path" 2>/dev/null || echo ""
    fi
}

# =============================================================================
# Claude Code Hook Protocol Tests
# =============================================================================

test_exit_0_on_allow() {
    log_info "Testing: Exit 0 on allowed command..."

    local input='{"tool_name":"Bash","tool_input":{"command":"ls -la"}}'
    local result
    result=$(echo "$input" | "$DCG_BIN" 2>/dev/null)
    local exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log_pass "Exit 0 on allowed command"
        return 0
    else
        log_fail "Expected exit 0, got: $exit_code"
        return 1
    fi
}

test_exit_0_on_deny() {
    log_info "Testing: Exit 0 on denied command (decision in JSON)..."

    local input='{"tool_name":"Bash","tool_input":{"command":"git reset --hard"}}'
    local result
    result=$(echo "$input" | "$DCG_BIN" 2>/dev/null)
    local exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log_pass "Exit 0 on denied command (per Claude Code protocol)"
        return 0
    else
        log_fail "Expected exit 0 even on deny, got: $exit_code"
        return 1
    fi
}

test_no_output_on_allow() {
    log_info "Testing: No stdout on allowed command..."

    local result
    result=$(run_hook_mode "git status")

    if [[ -z "${result// /}" ]]; then
        log_pass "No output on allowed command"
        return 0
    else
        log_fail "Expected empty stdout, got: $result"
        return 1
    fi
}

test_json_output_on_deny() {
    log_info "Testing: JSON output on denied command..."

    local result
    result=$(run_hook_mode "git reset --hard")

    if [[ -n "$result" ]]; then
        # Verify it's valid JSON
        if echo "$result" | python3 -c "import json, sys; json.loads(sys.stdin.read())" 2>/dev/null; then
            log_pass "JSON output on denied command"
            return 0
        else
            log_fail "Output is not valid JSON: $result"
            return 1
        fi
    else
        log_fail "Expected JSON output, got empty string"
        return 1
    fi
}

# =============================================================================
# HookSpecificOutput Field Tests
# =============================================================================

test_hook_event_name() {
    log_info "Testing: hookEventName field present..."

    local result
    result=$(run_hook_mode "git reset --hard")

    local hook_event
    hook_event=$(json_get "$result" ".hookSpecificOutput.hookEventName")

    if [[ "$hook_event" == "PreToolUse" ]]; then
        log_pass "hookEventName = PreToolUse"
        return 0
    else
        log_fail "Expected hookEventName='PreToolUse', got: '$hook_event'"
        return 1
    fi
}

test_permission_decision() {
    log_info "Testing: permissionDecision field..."

    local result
    result=$(run_hook_mode "git reset --hard")

    local decision
    decision=$(json_get "$result" ".hookSpecificOutput.permissionDecision")

    if [[ "$decision" == "deny" ]]; then
        log_pass "permissionDecision = deny for dangerous command"
        return 0
    else
        log_fail "Expected permissionDecision='deny', got: '$decision'"
        return 1
    fi
}

test_rule_id_format() {
    log_info "Testing: ruleId format (packId:patternName)..."

    local result
    result=$(run_hook_mode "git reset --hard")

    local rule_id
    rule_id=$(json_get "$result" ".hookSpecificOutput.ruleId")

    if [[ -z "$rule_id" ]]; then
        log_fail "ruleId not present"
        return 1
    fi

    # Rule ID should have format packId:patternName
    if [[ "$rule_id" == *":"* ]]; then
        log_pass "ruleId format correct: $rule_id"
        return 0
    else
        log_fail "ruleId should contain ':', got: '$rule_id'"
        return 1
    fi
}

test_pack_id_present() {
    log_info "Testing: packId field present..."

    local result
    result=$(run_hook_mode "git reset --hard")

    local pack_id
    pack_id=$(json_get "$result" ".hookSpecificOutput.packId")

    if [[ -n "$pack_id" ]]; then
        log_pass "packId present: $pack_id"
        return 0
    else
        log_fail "packId not present"
        return 1
    fi
}

test_severity_valid() {
    log_info "Testing: severity field has valid value..."

    local result
    result=$(run_hook_mode "git reset --hard")

    local severity
    severity=$(json_get "$result" ".hookSpecificOutput.severity")

    # Valid severities: critical, high, medium, low
    case "$severity" in
        critical|high|medium|low)
            log_pass "severity valid: $severity"
            return 0
            ;;
        *)
            log_fail "Invalid severity: '$severity' (expected: critical/high/medium/low)"
            return 1
            ;;
    esac
}

test_remediation_present() {
    log_info "Testing: remediation field present..."

    local result
    result=$(run_hook_mode "git reset --hard")

    local explanation
    explanation=$(json_get "$result" ".hookSpecificOutput.remediation.explanation")

    if [[ -n "$explanation" ]]; then
        log_pass "remediation.explanation present"
        return 0
    else
        log_fail "remediation.explanation not present"
        return 1
    fi
}

test_allow_once_code() {
    log_info "Testing: allowOnceCode present for denied command..."

    local result
    result=$(run_hook_mode "git reset --hard")

    local code
    code=$(json_get "$result" ".hookSpecificOutput.allowOnceCode")

    if [[ -n "$code" && "$code" != "null" ]]; then
        log_pass "allowOnceCode present: ${code:0:16}..."
        return 0
    else
        log_fail "allowOnceCode not present"
        return 1
    fi
}

test_allow_once_command() {
    log_info "Testing: remediation.allowOnceCommand contains 'dcg allow-once'..."

    local result
    result=$(run_hook_mode "git reset --hard")

    local cmd
    cmd=$(json_get "$result" ".hookSpecificOutput.remediation.allowOnceCommand")

    if [[ "$cmd" == *"dcg allow-once"* ]]; then
        log_pass "allowOnceCommand contains 'dcg allow-once'"
        return 0
    else
        log_fail "allowOnceCommand should contain 'dcg allow-once', got: '$cmd'"
        return 1
    fi
}

test_permission_decision_reason() {
    log_info "Testing: permissionDecisionReason field..."

    local result
    result=$(run_hook_mode "git reset --hard")

    local reason
    reason=$(json_get "$result" ".hookSpecificOutput.permissionDecisionReason")

    if [[ -n "$reason" && ${#reason} -gt 10 ]]; then
        log_pass "permissionDecisionReason present (${#reason} chars)"
        return 0
    else
        log_fail "permissionDecisionReason missing or too short: '$reason'"
        return 1
    fi
}

# =============================================================================
# JSON Schema Validation Tests
# =============================================================================

test_json_root_is_object() {
    log_info "Testing: JSON root is object..."

    local result
    result=$(run_hook_mode "git reset --hard")

    local is_object
    is_object=$(echo "$result" | python3 -c "
import json
import sys
data = json.loads(sys.stdin.read())
print('true' if isinstance(data, dict) else 'false')
" 2>/dev/null || echo "false")

    if [[ "$is_object" == "true" ]]; then
        log_pass "JSON root is object"
        return 0
    else
        log_fail "JSON root should be object"
        return 1
    fi
}

test_hook_specific_output_present() {
    log_info "Testing: hookSpecificOutput field present..."

    local result
    result=$(run_hook_mode "git reset --hard")

    local has_field
    has_field=$(echo "$result" | python3 -c "
import json
import sys
data = json.loads(sys.stdin.read())
print('true' if 'hookSpecificOutput' in data else 'false')
" 2>/dev/null || echo "false")

    if [[ "$has_field" == "true" ]]; then
        log_pass "hookSpecificOutput field present"
        return 0
    else
        log_fail "hookSpecificOutput field missing"
        return 1
    fi
}

# =============================================================================
# CLI Command JSON Output Tests
# =============================================================================

test_cli_test_command_json() {
    log_info "Testing: 'dcg test --format json' output..."

    local result
    result=$("$DCG_BIN" test --format json "git reset --hard" 2>/dev/null || true)

    if [[ -z "$result" ]]; then
        log_fail "No output from 'dcg test --format json'"
        return 1
    fi

    # Verify it's valid JSON
    if echo "$result" | python3 -c "import json, sys; json.loads(sys.stdin.read())" 2>/dev/null; then
        local decision
        decision=$(json_get "$result" ".decision")
        if [[ "$decision" == "deny" ]]; then
            log_pass "'dcg test --format json' produces valid JSON with decision"
            return 0
        else
            log_fail "Expected decision='deny', got: '$decision'"
            return 1
        fi
    else
        log_fail "Invalid JSON from 'dcg test --format json'"
        return 1
    fi
}

test_cli_packs_command_json() {
    log_info "Testing: 'dcg packs --format json' output..."

    local result
    result=$("$DCG_BIN" packs --format json 2>/dev/null || true)

    if [[ -z "$result" ]]; then
        log_fail "No output from 'dcg packs --format json'"
        return 1
    fi

    # Verify it's valid JSON with packs array
    local packs_count
    packs_count=$(echo "$result" | python3 -c "
import json
import sys
data = json.loads(sys.stdin.read())
packs = data.get('packs', [])
print(len(packs))
" 2>/dev/null || echo "0")

    if [[ "$packs_count" -gt 0 ]]; then
        log_pass "'dcg packs --format json' produces JSON with $packs_count packs"
        return 0
    else
        log_fail "Expected packs array, got count: $packs_count"
        return 1
    fi
}

# =============================================================================
# Multiple Dangerous Commands Consistency Test
# =============================================================================

test_consistency_across_commands() {
    log_info "Testing: Consistent output across dangerous commands..."

    local commands=(
        "git reset --hard"
        "git clean -fd"
        "rm -rf /important"
        "git push --force origin main"
    )

    local all_passed=true

    for cmd in "${commands[@]}"; do
        local result
        result=$(run_hook_mode "$cmd")

        if [[ -z "$result" ]]; then
            log_debug "No output for: $cmd (might be allowed)"
            continue
        fi

        local decision
        decision=$(json_get "$result" ".hookSpecificOutput.permissionDecision")

        if [[ "$decision" != "deny" ]]; then
            log_fail "Expected deny for '$cmd', got: '$decision'"
            all_passed=false
        fi
    done

    if [[ "$all_passed" == "true" ]]; then
        log_pass "Consistent deny decision across dangerous commands"
        return 0
    else
        return 1
    fi
}

# =============================================================================
# Non-Bash Tool Handling Test
# =============================================================================

test_non_bash_tool_skip() {
    log_info "Testing: Non-Bash tools are skipped (exit 0, no output)..."

    local input='{"tool_name":"Read","tool_input":{"file_path":"/etc/passwd"}}'
    local result
    result=$(echo "$input" | "$DCG_BIN" 2>/dev/null || true)
    local exit_code=$?

    if [[ $exit_code -eq 0 && -z "${result// /}" ]]; then
        log_pass "Non-Bash tool skipped correctly"
        return 0
    else
        log_fail "Expected exit 0 with no output for non-Bash tool"
        return 1
    fi
}

# =============================================================================
# Main Test Runner
# =============================================================================

main() {
    echo ""
    echo "=============================================="
    echo "  DCG Agent Ergonomics E2E Test Suite"
    echo "=============================================="
    echo ""

    # Setup
    ensure_dcg_binary
    setup_test_env

    echo ""
    echo "Running Claude Code Hook Protocol Tests..."
    echo ""

    test_exit_0_on_allow || true
    test_exit_0_on_deny || true
    test_no_output_on_allow || true
    test_json_output_on_deny || true

    echo ""
    echo "Running HookSpecificOutput Field Tests..."
    echo ""

    test_hook_event_name || true
    test_permission_decision || true
    test_rule_id_format || true
    test_pack_id_present || true
    test_severity_valid || true
    test_remediation_present || true
    test_allow_once_code || true
    test_allow_once_command || true
    test_permission_decision_reason || true

    echo ""
    echo "Running JSON Schema Tests..."
    echo ""

    test_json_root_is_object || true
    test_hook_specific_output_present || true
    test_cli_test_command_json || true
    test_cli_packs_command_json || true

    echo ""
    echo "Running Consistency Tests..."
    echo ""

    test_consistency_across_commands || true
    test_non_bash_tool_skip || true

    echo ""
    echo "=============================================="
    echo "  Test Results"
    echo "=============================================="
    echo ""
    echo -e "  ${GREEN}Passed:${NC}  $TESTS_PASSED"
    echo -e "  ${RED}Failed:${NC}  $TESTS_FAILED"
    echo -e "  ${YELLOW}Skipped:${NC} $TESTS_SKIPPED"
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

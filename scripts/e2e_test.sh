#!/bin/bash
#
# End-to-End Test Script for dcg
#
# This script tests the hook binary with real-world command scenarios,
# verifying both blocking and allowing behavior with detailed logging.
#
# Usage:
#   ./scripts/e2e_test.sh [--verbose] [--binary PATH] [--json] [--artifacts DIR] [--full]
#
# Options:
#   --verbose     Show detailed output for each test (includes timing and test IDs)
#   --binary      Path to dcg binary (default: searches PATH)
#   --json        Output results in JSON format (machine-readable)
#   --artifacts   Directory to store failure artifacts (stdout/stderr captures)
#   --full        Run slow/expensive tests (memory test execution)
#
# Exit codes:
#   0  All tests passed
#   1  One or more tests failed
#   2  Binary not found or other setup error

set -euo pipefail

# Hermetic behavior: avoid inheriting CI markers from the parent environment.
# Some allowlist tests intentionally assert behavior when `CI` is *unset* unless
# explicitly provided via per-test env overrides.
unset CI

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Configuration
VERBOSE=false
BINARY=""
JSON_OUTPUT=false
ARTIFACTS_DIR=""
RUN_FULL=false
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Timing data
declare -a TEST_TIMES=()
declare -a TEST_NAMES=()
declare -a TEST_RESULTS=()
declare -a TEST_OUTPUTS=()
SUITE_START_TIME=""
SUITE_END_TIME=""

# Get current timestamp in milliseconds
get_timestamp_ms() {
    # Use date with nanoseconds if available, fall back to seconds
    if date +%s%N &>/dev/null; then
        echo $(( $(date +%s%N) / 1000000 ))
    else
        echo $(( $(date +%s) * 1000 ))
    fi
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --binary|-b)
            BINARY="$2"
            shift 2
            ;;
        --json|-j)
            JSON_OUTPUT=true
            shift
            ;;
        --artifacts|-a)
            ARTIFACTS_DIR="$2"
            shift 2
            ;;
        --full)
            RUN_FULL=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--verbose] [--binary PATH] [--json] [--artifacts DIR] [--full]"
            echo ""
            echo "Options:"
            echo "  --verbose, -v     Show detailed output for each test"
            echo "  --binary, -b      Path to dcg binary"
            echo "  --json, -j        Output results in JSON format (machine-readable)"
            echo "  --artifacts, -a   Directory to store failure artifacts (stdout/stderr)"
            echo "  --full            Run slow/expensive tests (memory test execution)"
            echo "  --help, -h        Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 2
            ;;
    esac
done

# Find binary
if [[ -z "$BINARY" ]]; then
    # Prefer in-repo build artifacts over any globally installed `dcg` to keep
    # the test suite hermetic and reproducible.
    if [[ -f "./target/release/dcg" ]]; then
        BINARY="./target/release/dcg"
    elif [[ -f "./target/debug/dcg" ]]; then
        BINARY="./target/debug/dcg"
    elif command -v dcg &> /dev/null; then
        BINARY="$(command -v dcg)"
    else
        echo -e "${RED}Error: dcg binary not found${NC}"
        echo "Run 'cargo build --release' first or specify --binary PATH"
        exit 2
    fi
fi

# Convert binary path to absolute (required for allowlist tests that cd to temp dirs)
# Handle all relative paths, not just those starting with "./"
if [[ "$BINARY" != /* ]]; then
    BINARY="$(cd "$(dirname "$BINARY")" && pwd)/$(basename "$BINARY")"
fi

# Repo root (used by CI feature tests)
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Setup artifacts directory if specified
if [[ -n "$ARTIFACTS_DIR" ]]; then
    mkdir -p "$ARTIFACTS_DIR"
    ARTIFACTS_DIR="$(cd "$ARTIFACTS_DIR" && pwd)"  # Convert to absolute path
fi

# Hermetic test environment (avoid picking up developer machine config/allowlists)
#
# Many tests depend on the *default* pack set (core-only) unless explicitly
# overridden via DCG_PACKS. If we read ~/.config/dcg/config.toml, results become
# machine-dependent (e.g., docker pack enabled by default).
TEST_ENV_ROOT=$(mktemp -d)
TEST_ENV_HOME="$TEST_ENV_ROOT/home"
TEST_ENV_XDG="$TEST_ENV_ROOT/xdg_config"
mkdir -p "$TEST_ENV_HOME" "$TEST_ENV_XDG"

# Start timing the full suite
SUITE_START_TIME=$(get_timestamp_ms)

if ! $JSON_OUTPUT; then
    echo -e "${BOLD}${BLUE}dcg End-to-End Test Suite${NC}"
    echo -e "${CYAN}Binary: ${BINARY}${NC}"
    if [[ -n "$ARTIFACTS_DIR" ]]; then
        echo -e "${CYAN}Artifacts: ${ARTIFACTS_DIR}${NC}"
    fi
    echo ""
fi

# Current test timing state
CURRENT_TEST_START=""
CURRENT_TEST_ID=""

# Logging functions
log_test_start() {
    local desc="$1"
    ((++TESTS_TOTAL))
    CURRENT_TEST_ID="T${TESTS_TOTAL}"
    CURRENT_TEST_START=$(get_timestamp_ms)
    if $VERBOSE && ! $JSON_OUTPUT; then
        echo -e "${CYAN}[${CURRENT_TEST_ID}]${NC} $desc"
    fi
}

# Record test result with timing
record_test_result() {
    local result="$1"  # "pass" or "fail"
    local desc="$2"
    local output="$3"  # captured output for failures

    local end_time
    end_time=$(get_timestamp_ms)
    local duration_ms=$((end_time - CURRENT_TEST_START))

    TEST_TIMES+=("$duration_ms")
    TEST_NAMES+=("$desc")
    TEST_RESULTS+=("$result")
    TEST_OUTPUTS+=("$output")
}

log_pass() {
    local desc="$1"
    ((++TESTS_PASSED))
    record_test_result "pass" "$desc" ""

    if ! $JSON_OUTPUT; then
        if $VERBOSE && ! $JSON_OUTPUT; then
            local duration_ms="${TEST_TIMES[-1]}"
            echo -e "${GREEN}✓${NC} $desc ${CYAN}(${duration_ms}ms)${NC}"
        else
            echo -e "${GREEN}✓${NC} $desc"
        fi
    fi
}

log_fail() {
    local desc="$1"
    local expected="$2"
    local actual="$3"
    ((++TESTS_FAILED))

    local output="Expected: $expected\nActual: $actual"
    record_test_result "fail" "$desc" "$output"

    # Save artifact if directory specified
    if [[ -n "$ARTIFACTS_DIR" ]]; then
        local artifact_file="$ARTIFACTS_DIR/${CURRENT_TEST_ID}_failure.txt"
        {
            echo "Test ID: $CURRENT_TEST_ID"
            echo "Description: $desc"
            echo "Expected: $expected"
            echo "Actual: $actual"
            echo ""
            echo "--- Raw Output ---"
            echo "$actual"
        } > "$artifact_file"
    fi

    if ! $JSON_OUTPUT; then
        local duration_ms="${TEST_TIMES[-1]}"
        if $VERBOSE && ! $JSON_OUTPUT; then
            echo -e "${RED}✗${NC} $desc ${CYAN}(${duration_ms}ms)${NC}"
            echo -e "  ${YELLOW}Expected:${NC} $expected"
            echo -e "  ${YELLOW}Actual:${NC} $actual"
        else
            echo -e "${RED}✗${NC} $desc"
            echo -e "  ${YELLOW}Expected:${NC} $expected"
            echo -e "  ${YELLOW}Actual:${NC} $actual"
        fi
    fi
}

log_section() {
    local title="$1"
    if ! $JSON_OUTPUT; then
        echo ""
        echo -e "${BOLD}${BLUE}=== $title ===${NC}"
    fi
}

# Log informational details (non-test output)
log_info() {
    local desc="$1"
    if $VERBOSE && ! $JSON_OUTPUT; then
        echo -e "  ${CYAN}ℹ${NC} $desc"
    fi
}

# Log a skipped test (informational, not a failure)
log_skip() {
    local desc="$1"
    local reason="${2:-}"
    # Count skipped tests as passed (they're not failures)
    ((++TESTS_PASSED))
    record_test_result "skip" "$desc" ""

    if ! $JSON_OUTPUT; then
        if [[ -n "$reason" ]]; then
            echo -e "${YELLOW}⊘${NC} SKIPPED: $desc (${reason})"
        else
            echo -e "${YELLOW}⊘${NC} SKIPPED: $desc"
        fi
    fi
}

# Log a warning (test passed but with caveats)
log_warn() {
    local desc="$1"
    ((++TESTS_PASSED))
    record_test_result "warn" "$desc" ""

    if ! $JSON_OUTPUT; then
        echo -e "${YELLOW}⚠${NC} $desc"
    fi
}

# Truncate long commands for readable logs.
truncate_cmd() {
    local s="$1"
    local max=160
    if [[ ${#s} -le $max ]]; then
        echo -n "$s"
    else
        echo -n "${s:0:$max}..."
    fi
}

# JSON-escape a string for safe embedding in a JSON string literal.
json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    echo -n "$s"
}

# Test helper: run command and check result
test_command() {
    local cmd="$1"
    local expected="$2"  # "block" or "allow"
    local desc="$3"

    log_test_start "$desc"
    if $VERBOSE && ! $JSON_OUTPUT; then
        echo -e "  ${CYAN}Command:${NC} $(truncate_cmd "$cmd")"
    fi

    # Create JSON input and base64 encode it to avoid interference from
    # any existing git safety hooks that might scan command arguments
    local escaped_cmd
    escaped_cmd=$(json_escape "$cmd")
    local json="{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"$escaped_cmd\"}}"
    local encoded
    encoded=$(echo -n "$json" | base64 -w 0)

    # Run the binary with decoded input
    local result
    result=$(echo "$encoded" | base64 -d | \
        HOME="$TEST_ENV_HOME" \
        XDG_CONFIG_HOME="$TEST_ENV_XDG" \
        DCG_ALLOWLIST_SYSTEM_PATH="" \
        "$BINARY" 2>/dev/null || true)

    # Check result
    if [[ "$expected" == "block" ]]; then
        if echo "$result" | grep -q '"permissionDecision"'; then
            if echo "$result" | grep -q '"deny"'; then
                log_pass "BLOCKED: $desc"
                if $VERBOSE && ! $JSON_OUTPUT; then
                    local decision_reason
                    decision_reason=$(echo "$result" | grep -o '"permissionDecisionReason":"[^"]*"' | head -1 | cut -d'"' -f4)
                    # Extract the human reason line from the hook message.
                    local reason_line
                    reason_line=${decision_reason#*Reason: }
                    # Best-effort rule attribution: our heredoc/inline path encodes `rule <pack>:<pattern>`
                    # inside the reason string.
                    local rule_id=""
                    rule_id=$(
                        echo "$reason_line" | grep -Eo 'rule [^,)]+' | head -1 | sed 's/^rule //' || true
                    )
                    echo -e "  ${CYAN}Reason:${NC} $(echo "$reason_line" | head -c 160)..."
                    if [[ -n "$rule_id" ]]; then
                        echo -e "  ${CYAN}Rule:${NC} $rule_id"
                    fi
                fi
                return 0
            fi
        fi
        log_fail "Should BLOCK: $desc" "JSON with permissionDecision: deny" "${result:-<empty>}"
        return 0
    else
        # Expected: allow (empty output)
        if [[ -z "$result" ]]; then
            log_pass "ALLOWED: $desc"
            return 0
        else
            log_fail "Should ALLOW: $desc" "<empty output>" "$result"
            return 0
        fi
    fi
}

# Test non-Bash tool (should always allow)
test_non_bash_tool() {
    local tool="$1"
    local desc="$2"

    log_test_start "$desc"
    if $VERBOSE && ! $JSON_OUTPUT; then
        echo -e "  ${CYAN}Tool:${NC} $tool"
    fi

    # Use a harmless command to avoid hook interference
    local json="{\"tool_name\":\"$tool\",\"tool_input\":{\"command\":\"echo test\"}}"
    local encoded
    encoded=$(echo -n "$json" | base64 -w 0)
    local result
    result=$(echo "$encoded" | base64 -d | \
        HOME="$TEST_ENV_HOME" \
        XDG_CONFIG_HOME="$TEST_ENV_XDG" \
        DCG_ALLOWLIST_SYSTEM_PATH="" \
        "$BINARY" 2>/dev/null || true)

    if [[ -z "$result" ]]; then
        log_pass "Non-Bash tool ignored: $desc"
        return 0
    else
        log_fail "Non-Bash tool should be ignored: $desc" "<empty output>" "$result"
        return 0
    fi
}

# Test malformed input (should allow/ignore)
test_malformed_input() {
    local input="$1"
    local desc="$2"

    log_test_start "$desc"

    # Write to temp file to avoid any shell interpretation issues
    local tmpfile
    tmpfile=$(mktemp)
    echo -n "$input" > "$tmpfile"
    local result
    result=$(
        HOME="$TEST_ENV_HOME" \
            XDG_CONFIG_HOME="$TEST_ENV_XDG" \
            DCG_ALLOWLIST_SYSTEM_PATH="" \
            "$BINARY" < "$tmpfile" 2>/dev/null || true
    )

    if [[ -z "$result" ]]; then
        log_pass "Malformed input handled: $desc"
        return 0
    else
        log_fail "Malformed input should be ignored: $desc" "<empty output>" "$result"
        return 0
    fi
}

# Test command with specific packs enabled (regression test for non-core packs)
# This verifies that the pack-aware quick reject allows non-core packs to be evaluated
test_command_with_packs() {
    local cmd="$1"
    local expected="$2"  # "block" or "allow"
    local packs="$3"     # comma-separated pack list
    local desc="$4"

    log_test_start "$desc"
    if $VERBOSE && ! $JSON_OUTPUT; then
        echo -e "  ${CYAN}Packs:${NC} $packs"
        echo -e "  ${CYAN}Command:${NC} $(truncate_cmd "$cmd")"
    fi

    # Create JSON input and base64 encode it
    local escaped_cmd
    escaped_cmd=$(json_escape "$cmd")
    local json="{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"$escaped_cmd\"}}"
    local encoded
    encoded=$(echo -n "$json" | base64 -w 0)

    # Run the binary with DCG_PACKS environment variable
    local result
    result=$(echo "$encoded" | base64 -d | \
        HOME="$TEST_ENV_HOME" \
        XDG_CONFIG_HOME="$TEST_ENV_XDG" \
        DCG_ALLOWLIST_SYSTEM_PATH="" \
        DCG_PACKS="$packs" \
        "$BINARY" 2>/dev/null || true)

    # Check result
    if [[ "$expected" == "block" ]]; then
        if echo "$result" | grep -q '"permissionDecision"'; then
            if echo "$result" | grep -q '"deny"'; then
                log_pass "BLOCKED (pack=$packs): $desc"
                if $VERBOSE && ! $JSON_OUTPUT; then
                    echo -e "  ${CYAN}Reason:${NC} $(echo "$result" | grep -o '"permissionDecisionReason":"[^"]*"' | head -1 | cut -d'"' -f4 | head -c 80)..."
                fi
                return 0
            fi
        fi
        log_fail "Should BLOCK with pack=$packs: $desc" "JSON with permissionDecision: deny" "${result:-<empty>}"
        return 0
    else
        # Expected: allow (empty output)
        if [[ -z "$result" ]]; then
            log_pass "ALLOWED (pack=$packs): $desc"
            return 0
        else
            log_fail "Should ALLOW with pack=$packs: $desc" "<empty output>" "$result"
            return 0
        fi
    fi
}

# Test helper: run command WITHOUT policy override to test default severity behavior
# Medium severity patterns should warn by default (recoverable operations)
test_default_severity_behavior() {
    local cmd="$1"
    local expected="$2"  # "warn" for Medium severity
    local desc="$3"

    log_test_start "$desc"
    if $VERBOSE && ! $JSON_OUTPUT; then
        echo -e "  ${CYAN}Command:${NC} $(truncate_cmd "$cmd")"
        echo -e "  ${CYAN}Expected:${NC} $expected (default severity-based)"
    fi

    local escaped_cmd
    escaped_cmd=$(json_escape "$cmd")
    local json="{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"$escaped_cmd\"}}"
    local encoded
    encoded=$(echo -n "$json" | base64 -w 0)

    local out_file err_file
    out_file=$(mktemp)
    err_file=$(mktemp)

    # Run WITHOUT DCG_POLICY_DEFAULT_MODE to test default severity behavior
    echo "$encoded" | base64 -d | \
        HOME="$TEST_ENV_HOME" \
        XDG_CONFIG_HOME="$TEST_ENV_XDG" \
        DCG_ALLOWLIST_SYSTEM_PATH="" \
        "$BINARY" >"$out_file" 2>"$err_file" || true

    local out err
    out=$(cat "$out_file")
    err=$(cat "$err_file")

    case "$expected" in
        warn)
            if [[ -z "$out" ]] && [[ -n "$err" ]] && echo "$err" | grep -q "dcg WARNING"; then
                log_pass "WARNED (default severity): $desc"
            else
                log_fail "Should WARN (default severity): $desc" "stdout empty; stderr contains dcg WARNING" "stdout=${out:-<empty>} | stderr=${err:-<empty>}"
            fi
            ;;
        *)
            log_fail "Invalid expected mode: $desc" "warn" "$expected"
            ;;
    esac
}

# Test helper: run command WITH explicit DCG_POLICY_DEFAULT_MODE and check stdout/stderr
# Use this to test policy override behavior (deny/warn/log modes)
test_command_with_policy() {
    local cmd="$1"
    local policy_mode="$2"   # "deny" | "warn" | "log"
    local expected="$3"      # "block" | "warn" | "silent"
    local desc="$4"

    log_test_start "$desc"
    if $VERBOSE && ! $JSON_OUTPUT; then
        echo -e "  ${CYAN}Policy default:${NC} $policy_mode"
        echo -e "  ${CYAN}Command:${NC} $(truncate_cmd "$cmd")"
    fi

    local escaped_cmd
    escaped_cmd=$(json_escape "$cmd")
    local json="{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"$escaped_cmd\"}}"
    local encoded
    encoded=$(echo -n "$json" | base64 -w 0)

    local out_file err_file
    out_file=$(mktemp)
    err_file=$(mktemp)

    # Run the binary with policy env; capture stdout + stderr separately.
    echo "$encoded" | base64 -d | \
        HOME="$TEST_ENV_HOME" \
        XDG_CONFIG_HOME="$TEST_ENV_XDG" \
        DCG_ALLOWLIST_SYSTEM_PATH="" \
        DCG_POLICY_DEFAULT_MODE="$policy_mode" \
        "$BINARY" >"$out_file" 2>"$err_file" || true

    local out err
    out=$(cat "$out_file")
    err=$(cat "$err_file")

    case "$expected" in
        block)
            if echo "$out" | grep -q '"permissionDecision"' && echo "$out" | grep -q '"deny"'; then
                log_pass "BLOCKED (policy=$policy_mode): $desc"
            else
                log_fail "Should BLOCK (policy=$policy_mode): $desc" "JSON with permissionDecision: deny" "${out:-<empty>}"
            fi
            ;;
        warn)
            if [[ -z "$out" ]] && [[ -n "$err" ]] && echo "$err" | grep -q "dcg WARNING"; then
                log_pass "WARNED (policy=$policy_mode): $desc"
            else
                log_fail "Should WARN (policy=$policy_mode): $desc" "stdout empty; stderr contains dcg WARNING" "stdout=${out:-<empty>} | stderr=${err:-<empty>}"
            fi
            ;;
        silent)
            if [[ -z "$out" ]] && [[ -z "$err" ]]; then
                log_pass "ALLOWED (policy=$policy_mode): $desc"
            else
                log_fail "Should be silent allow (policy=$policy_mode): $desc" "stdout+stderr empty" "stdout=${out:-<empty>} | stderr=${err:-<empty>}"
            fi
            ;;
        *)
            log_fail "Invalid expected mode: $desc" "block|warn|silent" "$expected"
            ;;
    esac
}

# CI feature tests (git_safety_guard-cuo)
test_memory_tests_exist() {
    local desc="Memory tests exist"
    local test_file="$REPO_ROOT/tests/memory_tests.rs"

    log_test_start "$desc"

    if [[ ! -f "$test_file" ]]; then
        log_fail "$desc" "memory test file present" "missing: $test_file"
        return 0
    fi

    local required_tests=(
        "memory_hook_input_parsing"
        "memory_pattern_evaluation"
        "memory_heredoc_extraction"
        "memory_full_pipeline"
        "memory_leak_self_test"
    )

    local missing=()
    for test in "${required_tests[@]}"; do
        if ! grep -q "fn $test" "$test_file"; then
            missing+=("$test")
        fi
    done

    if [[ ${#missing[@]} -eq 0 ]]; then
        log_pass "$desc"
    else
        log_fail "$desc" "all required tests present" "missing: ${missing[*]}"
    fi
}

test_memory_tests_run() {
    local desc="Memory tests execution (release)"

    log_test_start "$desc"

    if [[ "$RUN_FULL" != "true" ]]; then
        log_skip "$desc" "use --full to run"
        return 0
    fi

    if ! command -v cargo >/dev/null 2>&1; then
        log_skip "$desc" "cargo not available"
        return 0
    fi

    local output_root="$TEST_ENV_ROOT"
    if [[ -n "$ARTIFACTS_DIR" ]]; then
        output_root="$ARTIFACTS_DIR"
    fi
    local output_file="$output_root/memory_tests_output.log"

    log_info "Running memory tests; output -> $output_file"

    if (cd "$REPO_ROOT" && cargo test --test memory_tests --release -- \
        --nocapture --test-threads=1 2>&1 | tee "$output_file"); then
        if grep -q "memory_leak_self_test.*PASSED" "$output_file"; then
            log_pass "$desc"
        else
            log_warn "$desc (self-test status unclear)"
        fi
    else
        log_fail "$desc" "cargo test memory_tests succeeds" "see $output_file"
    fi
}

test_ci_config_valid() {
    local desc="CI workflow config valid"
    local ci_file="$REPO_ROOT/.github/workflows/ci.yml"

    log_test_start "$desc"

    if [[ ! -f "$ci_file" ]]; then
        log_fail "$desc" "workflow present" "missing: $ci_file"
        return 0
    fi

    local required_jobs=(
        "check"
        "coverage"
        "memory-tests"
        "e2e"
        "benchmarks"
        "fuzz"
    )

    local missing_jobs=()
    for job in "${required_jobs[@]}"; do
        if ! grep -qE "^  $job:" "$ci_file"; then
            missing_jobs+=("$job")
        fi
    done

    local missing_ubs=false
    if ! grep -q "Install UBS" "$ci_file"; then
        missing_ubs=true
    fi

    if command -v yq >/dev/null 2>&1; then
        if ! yq eval . "$ci_file" >/dev/null 2>&1; then
            log_fail "$desc" "valid YAML" "invalid YAML syntax"
            return 0
        fi
    else
        log_info "yq not installed; skipping YAML validation"
    fi

    if [[ ${#missing_jobs[@]} -gt 0 || "$missing_ubs" == "true" ]]; then
        local details=""
        if [[ ${#missing_jobs[@]} -gt 0 ]]; then
            details="missing jobs: ${missing_jobs[*]}"
        fi
        if [[ "$missing_ubs" == "true" ]]; then
            if [[ -n "$details" ]]; then
                details="$details; "
            fi
            details="${details}missing UBS step"
        fi
        log_warn "$desc ($details)"
    else
        log_pass "$desc"
    fi
}

test_dependabot_config() {
    local desc="Dependabot config"
    local config_file="$REPO_ROOT/.github/dependabot.yml"

    log_test_start "$desc"

    if [[ ! -f "$config_file" ]]; then
        log_skip "$desc" "dependabot config not present"
        return 0
    fi

    if ! grep -q "cargo" "$config_file"; then
        log_fail "$desc" "cargo ecosystem configured" "cargo missing"
        return 0
    fi

    if ! grep -q "github-actions" "$config_file"; then
        log_fail "$desc" "github-actions ecosystem configured" "github-actions missing"
        return 0
    fi

    if command -v yq >/dev/null 2>&1; then
        if ! yq eval . "$config_file" >/dev/null 2>&1; then
            log_fail "$desc" "valid YAML" "invalid YAML syntax"
            return 0
        fi
    else
        log_info "yq not installed; skipping dependabot YAML validation"
    fi

    log_pass "$desc"
}

test_ubsignore() {
    local desc="UBS ignore config"
    local ignore_file="$REPO_ROOT/.ubsignore"

    log_test_start "$desc"

    if [[ ! -f "$ignore_file" ]]; then
        log_skip "$desc" ".ubsignore not present"
        return 0
    fi

    local required_patterns=(
        "tests/"
        "benches/"
        "fuzz/"
        "target/"
    )

    local missing=()
    for pattern in "${required_patterns[@]}"; do
        if ! grep -q "$pattern" "$ignore_file"; then
            missing+=("$pattern")
        fi
    done

    if [[ ${#missing[@]} -eq 0 ]]; then
        log_pass "$desc"
    else
        log_warn "$desc (missing: ${missing[*]})"
    fi
}

test_codecov_config() {
    log_section "Codecov Integration Tests (git_safety_guard-aw0)"

    # Test: Verify codecov.yml exists and is valid
    log_test_start "codecov.yml exists"
    if [[ -f "$REPO_ROOT/codecov.yml" ]]; then
        log_pass "codecov.yml exists"
    else
        log_skip "codecov.yml not found" "Codecov integration not configured"
    fi

    # Test: Verify codecov.yml has required settings (target coverage thresholds)
    log_test_start "codecov.yml has coverage settings"
    if [[ -f "$REPO_ROOT/codecov.yml" ]]; then
        if grep -q "target:" "$REPO_ROOT/codecov.yml" && grep -q "ignore:" "$REPO_ROOT/codecov.yml"; then
            log_pass "codecov.yml has required coverage settings"
        else
            log_warn "codecov.yml may be missing required settings (target or ignore)"
        fi
    else
        log_skip "codecov.yml not found" "skipping settings check"
    fi

    # Test: Verify codecov.yml is valid YAML (basic check - no syntax errors)
    log_test_start "codecov.yml is valid YAML"
    if [[ -f "$REPO_ROOT/codecov.yml" ]]; then
        # Validate YAML only if a validator is available (non-blocking).
        if command -v yq &>/dev/null; then
            if yq eval . "$REPO_ROOT/codecov.yml" >/dev/null 2>&1; then
                log_pass "codecov.yml is valid YAML (yq validated)"
            else
                log_fail "codecov.yml YAML validation" "valid YAML" "invalid YAML syntax"
            fi
        elif command -v python3 &>/dev/null && python3 -c "import yaml" >/dev/null 2>&1; then
            if python3 - "$REPO_ROOT/codecov.yml" <<'PY' >/dev/null 2>&1
import sys
import yaml

with open(sys.argv[1], "r", encoding="utf-8") as f:
    yaml.safe_load(f)
PY
            then
                log_pass "codecov.yml is valid YAML (python3 + PyYAML validated)"
            else
                log_fail "codecov.yml YAML validation" "valid YAML" "invalid YAML syntax"
            fi
        else
            log_skip "YAML validator" "yq not installed and PyYAML not available"
        fi
    else
        log_skip "codecov.yml not found" "skipping YAML validation"
    fi

    # Test: Verify badge URL is accessible (non-blocking - badge may not exist yet)
    log_test_start "Codecov badge accessible"
    local badge_url="https://codecov.io/gh/Dicklesworthstone/destructive_command_guard/branch/master/graph/badge.svg"
    if command -v curl &>/dev/null; then
        if curl -sf --max-time 5 "$badge_url" >/dev/null 2>&1; then
            log_pass "Codecov badge accessible"
        else
            log_warn "Codecov badge not accessible (may take time after first upload)"
        fi
    else
        log_skip "curl not available" "cannot test badge URL"
    fi
}

run_ci_feature_tests() {
    log_section "CI Feature Tests (git_safety_guard-cuo)"

    test_ci_config_valid
    test_memory_tests_exist
    test_codecov_config
    test_dependabot_config
    test_ubsignore
    test_memory_tests_run
}

#
# TEST SECTIONS
#

log_section "Destructive Git Commands (should BLOCK)"

test_command "git reset --hard" "block" "git reset --hard"
test_command "git reset --hard HEAD~1" "block" "git reset --hard HEAD~1"
test_command "git reset --hard origin/main" "block" "git reset --hard origin/main"
test_command "git reset --merge" "block" "git reset --merge"
test_command "git checkout -- file.txt" "block" "git checkout -- file.txt"
test_command "git checkout -- ." "block" "git checkout -- ."
test_command "git checkout HEAD -- file.txt" "block" "git checkout HEAD -- file.txt"
test_command "git restore file.txt" "block" "git restore file.txt"
test_command "git restore --worktree file.txt" "block" "git restore --worktree file.txt"
test_command "git restore -W file.txt" "block" "git restore -W file.txt"
test_command "git clean -f" "block" "git clean -f"
test_command "git clean -df" "block" "git clean -df"
test_command "git clean -fd" "block" "git clean -fd"
test_command "git push --force" "block" "git push --force"
test_command "git push -f" "block" "git push -f"
test_command "git push origin main --force" "block" "git push origin main --force"
test_command "git push --force origin main" "block" "git push --force origin main"
# Note: git branch -D and git stash drop are Medium severity (recoverable via reflog/fsck)
# and default to Warn mode per the policy system. Use test_command_with_policy for explicit tests.
# These tests verify the default warn behavior for Medium severity patterns.
test_command "git stash clear" "block" "git stash clear"
test_command '"git" reset --hard' "block" '"git" reset --hard (quoted command word)'
test_command '"/usr/bin/git" reset --hard' "block" '"/usr/bin/git" reset --hard (quoted absolute path)'

log_section "Decision Mode Policy (warn/log behavior)"

# Medium severity patterns default to warn (recoverable operations)
# These use the new test helper that doesn't set DCG_POLICY_DEFAULT_MODE
test_default_severity_behavior "git branch -D feature" "warn" "default: git branch -D warns (Medium severity)"
test_default_severity_behavior "git stash drop" "warn" "default: git stash drop warns (Medium severity)"
test_default_severity_behavior "git stash drop stash@{0}" "warn" "default: git stash drop stash@{0} warns (Medium severity)"

# Medium severity rule respects explicit policy overrides
test_command_with_policy "git branch -D feature" "warn" "warn" "policy warn: git branch -D feature"
test_command_with_policy "git branch -D feature" "log" "silent" "policy log: git branch -D feature"

# Critical rules must remain blocked even under global warn/log.
test_command_with_policy "git reset --hard" "warn" "block" "policy warn: git reset --hard remains blocked (critical)"

log_section "Destructive Filesystem Commands (should BLOCK)"

test_command "rm -rf /" "block" "rm -rf /"
test_command "rm -rf /etc" "block" "rm -rf /etc"
test_command "rm -rf /home" "block" "rm -rf /home"
test_command "rm -rf ~/" "block" "rm -rf ~/"
test_command "rm -rf ~/Documents" "block" "rm -rf ~/Documents"
test_command "rm -rf ./build" "block" "rm -rf ./build"
test_command "rm -rf node_modules" "block" "rm -rf node_modules"
test_command "rm -rf src" "block" "rm -rf src"
test_command "rm -rf /tmp/../etc" "block" "rm -rf /tmp/../etc (path traversal escapes /tmp)"
test_command "rm -rf /var/tmp/../etc" "block" "rm -rf /var/tmp/../etc (path traversal escapes /var/tmp)"
test_command 'rm -rf $TMPDIR/../etc' "block" 'rm -rf $TMPDIR/../etc (path traversal escapes $TMPDIR)'
test_command 'rm -rf ${TMPDIR}/../etc' "block" 'rm -rf ${TMPDIR}/../etc (path traversal escapes ${TMPDIR})'
test_command 'rm -rf "$TMPDIR/../etc"' "block" 'rm -rf "$TMPDIR/../etc" (path traversal escapes quoted $TMPDIR)'
test_command "rm -r -f /tmp/../etc" "block" "rm -r -f /tmp/../etc (path traversal escapes /tmp)"
test_command "rm --recursive --force /tmp/../etc" "block" "rm --recursive --force /tmp/../etc (path traversal escapes /tmp)"
test_command "rm -fr /etc" "block" "rm -fr /etc"
test_command "rm -Rf /home" "block" "rm -Rf /home"
test_command "rm -r -f /etc" "block" "rm -r -f /etc"
test_command "rm -f -r /etc" "block" "rm -f -r /etc"
test_command "rm --recursive --force /etc" "block" "rm --recursive --force /etc"
test_command "rm --force --recursive /etc" "block" "rm --force --recursive /etc"
test_command '"rm" -rf /etc' "block" '"rm" -rf /etc (quoted command word)'
test_command '"/bin/rm" -rf /etc' "block" '"/bin/rm" -rf /etc (quoted absolute path)'
test_command 'echo hi; "rm" -rf /etc' "block" 'echo hi; "rm" -rf /etc (quoted in later segment)'
test_command 'sudo -u root "rm" -rf /etc' "block" 'sudo -u root "rm" -rf /etc (quoted after sudo options)'

log_section "Safe Git Commands (should ALLOW)"

test_command "git status" "allow" "git status"
test_command "git log" "allow" "git log"
test_command "git log --oneline -10" "allow" "git log --oneline -10"
test_command "git diff" "allow" "git diff"
test_command "git diff HEAD" "allow" "git diff HEAD"
test_command "git add ." "allow" "git add ."
test_command "git add -A" "allow" "git add -A"
test_command "git commit -m 'test'" "allow" "git commit -m 'test'"
test_command "git push" "allow" "git push"
test_command "git push origin main" "allow" "git push origin main"
test_command "git push --force-with-lease" "allow" "git push --force-with-lease"
test_command "git pull" "allow" "git pull"
test_command "git fetch" "allow" "git fetch"
test_command "git fetch --all" "allow" "git fetch --all"
test_command "git branch -a" "allow" "git branch -a"
test_command "git branch -d feature" "allow" "git branch -d feature"
test_command "git checkout main" "allow" "git checkout main"
test_command "git checkout -b feature" "allow" "git checkout -b feature"
test_command "git checkout --orphan gh-pages" "allow" "git checkout --orphan gh-pages"
test_command "git restore --staged file.txt" "allow" "git restore --staged file.txt"
test_command "git restore -S file.txt" "allow" "git restore -S file.txt"
test_command "git clean -n" "allow" "git clean -n (dry run)"
test_command "git clean --dry-run" "allow" "git clean --dry-run"
test_command "git clean -dn" "allow" "git clean -dn"
test_command "git stash" "allow" "git stash"
test_command "git stash pop" "allow" "git stash pop"
test_command "git stash list" "allow" "git stash list"
test_command "git merge feature" "allow" "git merge feature"
test_command "git rebase main" "allow" "git rebase main"
test_command "git reset --soft HEAD~1" "allow" "git reset --soft HEAD~1"
test_command "git reset --mixed HEAD" "allow" "git reset --mixed HEAD"
test_command "git reset HEAD" "allow" "git reset HEAD"

log_section "Safe Filesystem Commands (should ALLOW)"

test_command "rm -rf /tmp/build" "allow" "rm -rf /tmp/build"
test_command "rm -rf /tmp/test-dir" "allow" "rm -rf /tmp/test-dir"
test_command "rm -rf /tmp/foo..bar" "allow" "rm -rf /tmp/foo..bar (dotdot in filename)"
test_command "rm -rf /var/tmp/cache" "allow" "rm -rf /var/tmp/cache"
test_command "rm -fr /tmp/stuff" "allow" "rm -fr /tmp/stuff"
test_command "rm -Rf /tmp/more" "allow" "rm -Rf /tmp/more"
test_command "rm -r -f /tmp/test" "allow" "rm -r -f /tmp/test"
test_command "rm -f -r /tmp/test" "allow" "rm -f -r /tmp/test"
test_command "rm --recursive --force /tmp/test" "allow" "rm --recursive --force /tmp/test"
test_command "rm --force --recursive /tmp/test" "allow" "rm --force --recursive /tmp/test"
test_command 'rm -rf $TMPDIR/test' "allow" 'rm -rf $TMPDIR/test'
test_command 'rm -rf ${TMPDIR}/test' "allow" 'rm -rf ${TMPDIR}/test'
test_command 'rm -rf "$TMPDIR/test"' "allow" 'rm -rf "$TMPDIR/test"'
test_command "rm file.txt" "allow" "rm file.txt (no -rf)"
test_command "rm -f file.txt" "allow" "rm -f file.txt (force only)"
test_command "rm -r directory" "allow" "rm -r directory (recursive only)"
test_command "rm -i file.txt" "allow" "rm -i file.txt (interactive)"

log_section "Non-Git/Rm Commands (should ALLOW via quick reject)"

test_command "ls -la" "allow" "ls -la"
test_command "cat file.txt" "allow" "cat file.txt"
test_command "echo 'hello world'" "allow" "echo 'hello world'"
test_command "cargo build" "allow" "cargo build"
test_command "cargo test" "allow" "cargo test"
test_command "npm install" "allow" "npm install"
test_command "python script.py" "allow" "python script.py"
test_command "node app.js" "allow" "node app.js"
test_command "docker ps" "allow" "docker ps"
test_command "kubectl get pods" "allow" "kubectl get pods"
test_command "make all" "allow" "make all"
test_command "curl https://example.com" "allow" "curl https://example.com"

log_section "Absolute Path Commands (should normalize correctly)"

test_command "/usr/bin/git reset --hard" "block" "/usr/bin/git reset --hard"
test_command "/usr/local/bin/git checkout -- ." "block" "/usr/local/bin/git checkout -- ."
test_command "/bin/rm -rf /etc" "block" "/bin/rm -rf /etc"
test_command "/usr/bin/rm -rf /home" "block" "/usr/bin/rm -rf /home"
test_command "/usr/bin/git checkout -b feature" "allow" "/usr/bin/git checkout -b feature"
test_command "/bin/rm -rf /tmp/cache" "allow" "/bin/rm -rf /tmp/cache"
test_command "/usr/bin/git status" "allow" "/usr/bin/git status"

log_section "Non-Bash Tools (should ALLOW/ignore)"

test_non_bash_tool "Read" "Read tool"
test_non_bash_tool "Write" "Write tool"
test_non_bash_tool "Edit" "Edit tool"
test_non_bash_tool "Grep" "Grep tool"
test_non_bash_tool "Glob" "Glob tool"

log_section "Malformed Input (should handle gracefully)"

test_malformed_input "" "Empty input"
test_malformed_input "not json" "Plain text"
test_malformed_input "{}" "Empty JSON object"
test_malformed_input '{"tool_name":"Bash"}' "Missing tool_input"
test_malformed_input '{"tool_name":"Bash","tool_input":{}}' "Missing command"
test_malformed_input '{"tool_name":"Bash","tool_input":{"command":""}}' "Empty command"
test_malformed_input '{"tool_name":"Bash","tool_input":{"command":123}}' "Non-string command"
test_malformed_input '{"invalid json' "Invalid JSON syntax"

log_section "Edge Cases"

test_command "git add /usr/bin/something" "allow" "git add with /usr/bin path as argument"
test_command "cat .gitignore" "allow" "cat .gitignore (contains 'git' but not git command)"
test_command "ls .git" "allow" "ls .git (contains 'git' but not git command)"
test_command "sudo rm -rf /" "block" "sudo rm -rf /"
test_command "sudo git reset --hard" "block" "sudo git reset --hard"

# Regression tests for quoted bypasses (git_safety_guard-audit-2025-01-10)
test_command 'git "reset" --hard' "block" 'git "reset" --hard (quoted subcommand)'
test_command '"git" reset --hard' "block" '"git" reset --hard (quoted binary)'
test_command 'sudo "/bin/git" reset --hard' "block" 'sudo "/bin/git" reset --hard (quoted binary with path and wrapper)'
test_command "python3 << \"EOF SPACE\"
import shutil
shutil.rmtree('/tmp/test')
EOF SPACE" "block" "heredoc with spaced delimiter"

log_section "Non-Core Pack Regression Tests (git_safety_guard-99e.1.2)"
# These tests verify that non-core packs are reachable in hook mode.
# Previously, global quick reject only checked for "git" and "rm" keywords,
# which prevented packs like docker/kubectl/database from being evaluated.

# Docker pack tests
test_command_with_packs "docker system prune" "block" "containers.docker" "docker system prune (docker pack enabled)"
test_command_with_packs "docker system prune --all" "block" "containers.docker" "docker system prune --all (docker pack enabled)"
test_command_with_packs "docker volume prune" "block" "containers.docker" "docker volume prune (docker pack enabled)"
test_command_with_packs "docker ps" "allow" "containers.docker" "docker ps (docker pack enabled, safe command)"

# Kubernetes pack tests
test_command_with_packs "kubectl delete namespace production" "block" "kubernetes.kubectl" "kubectl delete namespace (kubectl pack enabled)"
test_command_with_packs "kubectl delete deployment my-app" "block" "kubernetes.kubectl" "kubectl delete deployment (kubectl pack enabled)"
test_command_with_packs "kubectl delete pods --all" "block" "kubernetes.kubectl" "kubectl delete pods --all (kubectl pack enabled)"
test_command_with_packs "kubectl drain node-1" "block" "kubernetes.kubectl" "kubectl drain (kubectl pack enabled)"
test_command_with_packs "kubectl get pods" "allow" "kubernetes.kubectl" "kubectl get pods (kubectl pack enabled, safe command)"

# S3 pack tests
test_command_with_packs "aws s3 rb s3://bucket" "block" "storage.s3" "aws s3 rb (s3 pack enabled)"
test_command_with_packs "aws s3 rb s3://bucket --force" "block" "storage.s3" "aws s3 rb --force (s3 pack enabled)"
test_command_with_packs "aws s3 rm s3://bucket --recursive" "block" "storage.s3" "aws s3 rm --recursive (s3 pack enabled)"
test_command_with_packs "aws s3 sync s3://src s3://dest --delete" "block" "storage.s3" "aws s3 sync --delete (s3 pack enabled)"
test_command_with_packs "aws s3 sync s3://src s3://dest" "allow" "storage.s3" "aws s3 sync (s3 pack enabled, safe command)"
test_command_with_packs "aws s3 ls s3://bucket" "allow" "storage.s3" "aws s3 ls (s3 pack enabled, safe command)"

# rsync pack tests
test_command_with_packs "rsync --delete src/ dest/" "block" "remote.rsync" "rsync --delete (rsync pack enabled)"
test_command_with_packs "rsync --del src/ dest/" "block" "remote.rsync" "rsync --del (rsync pack enabled)"
test_command_with_packs "rsync --delete-before src/ dest/" "block" "remote.rsync" "rsync --delete-before (rsync pack enabled)"
test_command_with_packs "rsync --list-only src/ dest/" "allow" "remote.rsync" "rsync --list-only (rsync pack enabled, safe command)"
test_command_with_packs "rsync -avzn src/ dest/" "allow" "remote.rsync" "rsync -n (rsync pack enabled, safe command)"

# scp pack tests
test_command_with_packs "scp user@host:/etc/hosts ." "allow" "remote.scp" "scp download from /etc (scp pack enabled, safe command)"
test_command_with_packs "scp config.conf user@host:/etc/" "block" "remote.scp" "scp to /etc (scp pack enabled)"
test_command_with_packs "scp -r ./data user@host:/" "block" "remote.scp" "scp -r to / (scp pack enabled)"
test_command_with_packs "scp file.txt user@host:/tmp/backup/" "allow" "remote.scp" "scp to /tmp (scp pack enabled, safe command)"

# CloudFront pack tests
test_command_with_packs "aws cloudfront list-distributions" "allow" "cdn.cloudfront" "aws cloudfront list-distributions (cloudfront pack enabled, safe command)"
test_command_with_packs "aws cloudfront get-distribution --id ABC" "allow" "cdn.cloudfront" "aws cloudfront get-distribution (cloudfront pack enabled, safe command)"
test_command_with_packs "aws cloudfront delete-distribution --id ABC --if-match ETAG" "block" "cdn.cloudfront" "aws cloudfront delete-distribution (cloudfront pack enabled)"
test_command_with_packs "aws cloudfront create-invalidation --distribution-id ABC --paths '/*'" "block" "cdn.cloudfront" "aws cloudfront create-invalidation (cloudfront pack enabled)"

# AWS SES pack tests
test_command_with_packs "aws ses list-identities" "allow" "email.ses" "aws ses list-identities (ses pack enabled, safe command)"
test_command_with_packs "aws ses delete-identity --identity example.com" "block" "email.ses" "aws ses delete-identity (ses pack enabled)"
test_command_with_packs "aws sesv2 list-email-identities" "allow" "email.ses" "aws sesv2 list-email-identities (ses pack enabled, safe command)"
test_command_with_packs "aws sesv2 delete-email-identity --email-identity example.com" "block" "email.ses" "aws sesv2 delete-email-identity (ses pack enabled)"

# SendGrid pack tests
test_command_with_packs "curl https://api.sendgrid.com/v3/templates" "allow" "email.sendgrid" "sendgrid list templates (sendgrid pack enabled, safe command)"
test_command_with_packs "curl -X DELETE https://api.sendgrid.com/v3/templates/d-abc123" "block" "email.sendgrid" "sendgrid delete template (sendgrid pack enabled)"
test_command_with_packs "curl -X DELETE https://api.sendgrid.com/v3/api_keys/abc123" "block" "email.sendgrid" "sendgrid delete api key (sendgrid pack enabled)"

# Kong API Gateway pack tests
test_command_with_packs "deck diff" "allow" "apigateway.kong" "deck diff (kong pack enabled, safe command)"
test_command_with_packs "deck reset" "block" "apigateway.kong" "deck reset (kong pack enabled)"
test_command_with_packs "curl localhost:8001/services" "allow" "apigateway.kong" "curl localhost:8001/services (kong pack enabled, safe command)"
test_command_with_packs "curl -X DELETE localhost:8001/services/my-service" "block" "apigateway.kong" "curl -X DELETE localhost:8001/services (kong pack enabled)"

# Apigee API Gateway pack tests
test_command_with_packs "gcloud apigee apis list" "allow" "apigateway.apigee" "gcloud apigee apis list (apigee pack enabled, safe command)"
test_command_with_packs "gcloud apigee apis delete my-api" "block" "apigateway.apigee" "gcloud apigee apis delete (apigee pack enabled)"
test_command_with_packs "apigeecli apis list" "allow" "apigateway.apigee" "apigeecli apis list (apigee pack enabled, safe command)"
test_command_with_packs "apigeecli apis delete -n my-api" "block" "apigateway.apigee" "apigeecli apis delete (apigee pack enabled)"

# PostgreSQL pack tests
test_command_with_packs "psql -c 'DROP DATABASE production;'" "block" "database.postgresql" "psql DROP DATABASE (postgresql pack enabled)"
test_command_with_packs "psql -c 'DROP DATABASE IF EXISTS production;'" "block" "database.postgresql" "psql DROP DATABASE IF EXISTS (postgresql pack enabled)"
test_command_with_packs "psql -c 'DROP TABLE IF EXISTS users;'" "block" "database.postgresql" "psql DROP TABLE IF EXISTS (postgresql pack enabled)"
test_command_with_packs "psql -c 'TRUNCATE TABLE users RESTART IDENTITY;'" "block" "database.postgresql" "psql TRUNCATE ... RESTART IDENTITY (postgresql pack enabled)"
test_command_with_packs "psql -c 'DELETE FROM users;'" "block" "database.postgresql" "psql DELETE without WHERE (postgresql pack enabled)"
test_command_with_packs "psql -c 'SELECT 1;'" "allow" "database.postgresql" "psql SELECT (postgresql pack enabled, safe command)"

# SQLite pack tests
test_command_with_packs "sqlite3 my.db 'DROP TABLE IF EXISTS users;'" "block" "database.sqlite" "sqlite3 DROP TABLE IF EXISTS (sqlite pack enabled)"
test_command_with_packs "sqlite3 my.db 'SELECT 1;'" "allow" "database.sqlite" "sqlite3 SELECT (sqlite pack enabled, safe command)"

# Redis pack tests
test_command_with_packs "redis-cli FLUSHALL" "block" "database.redis" "redis-cli FLUSHALL (redis pack enabled)"
test_command_with_packs "redis-cli GET key" "allow" "database.redis" "redis-cli GET (redis pack enabled, safe command)"

# Terraform pack tests
test_command_with_packs "terraform destroy" "block" "infrastructure.terraform" "terraform destroy (terraform pack enabled)"
test_command_with_packs "terraform plan" "allow" "infrastructure.terraform" "terraform plan (terraform pack enabled, safe command)"

# GitHub Actions pack tests
test_command_with_packs "gh secret delete FOO" "block" "cicd.github_actions" "gh secret delete (github actions pack enabled)"
test_command_with_packs "gh -R owner/repo secret remove FOO" "block" "cicd.github_actions" "gh -R ... secret remove (github actions pack enabled)"
test_command_with_packs "gh variable delete FOO" "block" "cicd.github_actions" "gh variable delete (github actions pack enabled)"
test_command_with_packs "gh workflow disable 123" "block" "cicd.github_actions" "gh workflow disable (github actions pack enabled)"
test_command_with_packs "gh run cancel 123" "block" "cicd.github_actions" "gh run cancel (github actions pack enabled)"
test_command_with_packs "gh api -X DELETE repos/o/r/actions/secrets/FOO" "block" "cicd.github_actions" "gh api -X DELETE .../actions/secrets (github actions pack enabled)"
test_command_with_packs "gh secret list" "allow" "cicd.github_actions" "gh secret list (github actions pack enabled, safe command)"

# GitLab Platform pack tests
test_command_with_packs "glab repo delete my/group" "block" "platform.gitlab" "glab repo delete (gitlab platform pack enabled)"
test_command_with_packs "glab repo archive my/group" "block" "platform.gitlab" "glab repo archive (gitlab platform pack enabled)"
test_command_with_packs "glab release delete v1.2.3" "block" "platform.gitlab" "glab release delete (gitlab platform pack enabled)"
test_command_with_packs "glab api -X DELETE /projects/123" "block" "platform.gitlab" "glab api DELETE /projects (gitlab platform pack enabled)"
test_command_with_packs "glab api --method DELETE /projects/123/protected_branches/main" "block" "platform.gitlab" "glab api DELETE protected_branches (gitlab platform pack enabled)"
test_command_with_packs "glab api -X DELETE /projects/123/hooks/456" "block" "platform.gitlab" "glab api DELETE hooks (gitlab platform pack enabled)"
test_command_with_packs "gitlab-rails runner \"Project.destroy_all\"" "block" "platform.gitlab" "gitlab-rails runner destroy_all (gitlab platform pack enabled)"
test_command_with_packs "gitlab-rake gitlab:backup:restore" "block" "platform.gitlab" "gitlab-rake backup:restore (gitlab platform pack enabled)"
test_command_with_packs "glab repo list" "allow" "platform.gitlab" "glab repo list (gitlab platform pack enabled, safe command)"
test_command_with_packs "glab repo view my/group" "allow" "platform.gitlab" "glab repo view (gitlab platform pack enabled, safe command)"
test_command_with_packs "glab repo clone my/group" "allow" "platform.gitlab" "glab repo clone (gitlab platform pack enabled, safe command)"
test_command_with_packs "glab mr list" "allow" "platform.gitlab" "glab mr list (gitlab platform pack enabled, safe command)"
test_command_with_packs "glab issue list" "allow" "platform.gitlab" "glab issue list (gitlab platform pack enabled, safe command)"
test_command_with_packs "glab release list" "allow" "platform.gitlab" "glab release list (gitlab platform pack enabled, safe command)"
test_command_with_packs "glab api -X GET /projects/123" "allow" "platform.gitlab" "glab api GET (gitlab platform pack enabled, safe command)"

# Cloudflare DNS pack tests
test_command_with_packs "wrangler dns-records delete --zone-id abc --record-id def" "block" "dns.cloudflare" "wrangler dns-records delete (cloudflare dns pack enabled)"
test_command_with_packs "curl -X DELETE https://api.cloudflare.com/client/v4/zones/abc/dns_records/def" "block" "dns.cloudflare" "curl DELETE dns_records (cloudflare dns pack enabled)"
test_command_with_packs "curl -X DELETE https://api.cloudflare.com/client/v4/zones/abc" "block" "dns.cloudflare" "curl DELETE zone (cloudflare dns pack enabled)"
test_command_with_packs "wrangler dns-records list --zone-id abc" "allow" "dns.cloudflare" "wrangler dns-records list (cloudflare dns pack enabled, safe command)"
test_command_with_packs "wrangler whoami" "allow" "dns.cloudflare" "wrangler whoami (cloudflare dns pack enabled, safe command)"
test_command_with_packs "curl -X GET https://api.cloudflare.com/client/v4/zones" "allow" "dns.cloudflare" "curl GET zones (cloudflare dns pack enabled, safe command)"

# Route53 DNS pack tests
test_command_with_packs "aws route53 delete-hosted-zone --id Z123" "block" "dns.route53" "aws route53 delete-hosted-zone (route53 dns pack enabled)"
test_command_with_packs "aws route53 change-resource-record-sets --hosted-zone-id Z123 --change-batch '{\"Changes\":[{\"Action\":\"DELETE\"}]}'" "block" "dns.route53" "aws route53 change-resource-record-sets DELETE (route53 dns pack enabled)"
test_command_with_packs "aws route53 delete-health-check --health-check-id abc" "block" "dns.route53" "aws route53 delete-health-check (route53 dns pack enabled)"
test_command_with_packs "aws route53 delete-query-logging-config --id abc" "block" "dns.route53" "aws route53 delete-query-logging-config (route53 dns pack enabled)"
test_command_with_packs "aws route53 delete-traffic-policy --id abc --version 1" "block" "dns.route53" "aws route53 delete-traffic-policy (route53 dns pack enabled)"
test_command_with_packs "aws route53 delete-reusable-delegation-set --id N123" "block" "dns.route53" "aws route53 delete-reusable-delegation-set (route53 dns pack enabled)"
test_command_with_packs "aws route53 list-hosted-zones" "allow" "dns.route53" "aws route53 list-hosted-zones (route53 dns pack enabled, safe command)"
test_command_with_packs "aws route53 list-resource-record-sets --hosted-zone-id Z123" "allow" "dns.route53" "aws route53 list-resource-record-sets (route53 dns pack enabled, safe command)"
test_command_with_packs "aws route53 get-hosted-zone --id Z123" "allow" "dns.route53" "aws route53 get-hosted-zone (route53 dns pack enabled, safe command)"
test_command_with_packs "aws route53 test-dns-answer --hosted-zone-id Z123 --record-name example.com" "allow" "dns.route53" "aws route53 test-dns-answer (route53 dns pack enabled, safe command)"

# Generic DNS tools pack tests
test_command_with_packs "echo 'delete example.com' | nsupdate" "block" "dns.generic" "nsupdate delete via pipe (generic dns pack enabled)"
test_command_with_packs "nsupdate -l" "block" "dns.generic" "nsupdate -l local update (generic dns pack enabled)"
test_command_with_packs "dig axfr example.com" "block" "dns.generic" "dig axfr zone transfer (generic dns pack enabled)"
test_command_with_packs "dig example.com" "allow" "dns.generic" "dig query (generic dns pack enabled, safe command)"
test_command_with_packs "dig +short example.com" "allow" "dns.generic" "dig +short (generic dns pack enabled, safe command)"
test_command_with_packs "host example.com" "allow" "dns.generic" "host lookup (generic dns pack enabled, safe command)"
test_command_with_packs "nslookup example.com" "allow" "dns.generic" "nslookup lookup (generic dns pack enabled, safe command)"

# Multiple packs enabled simultaneously
test_command_with_packs "docker system prune" "block" "containers.docker,kubernetes.kubectl" "docker system prune (multiple packs enabled)"
test_command_with_packs "kubectl delete namespace foo" "block" "containers.docker,kubernetes.kubectl" "kubectl delete namespace (multiple packs enabled)"

# Verify commands WITHOUT their pack enabled are allowed (quick reject works)
test_command "docker system prune" "allow" "docker system prune (no docker pack, quick reject)"
test_command "kubectl delete namespace foo" "allow" "kubectl delete namespace (no kubectl pack, quick reject)"

log_section "Heredoc / Inline Script Tests (git_safety_guard-e2eh)"

# Must BLOCK: destructive operations inside heredocs (requires Tier 1→2→3 integration)
test_command $'node <<EOF\nconst fs = require(\'fs\');\nfs.rmSync(\'/etc\', { recursive: true });\nEOF\n' "block" "node heredoc fs.rmSync('/etc', {recursive:true})"

# Must BLOCK: cross-language heredoc cases (at least 3 languages)
test_command $'python3 <<EOF\nimport shutil\nshutil.rmtree(\"/tmp/test\")\nEOF\n' "block" "python heredoc shutil.rmtree('/tmp/test')"
test_command $'ruby <<EOF\nrequire \"fileutils\"\nFileUtils.rm_rf(\"/\")\nEOF\n' "block" "ruby heredoc FileUtils.rm_rf('/')"
test_command $'perl <<EOF\nsystem(\"rm -rf /\");\nEOF\n' "block" "perl heredoc system(\"rm -rf /\")"
test_command $'bash <<EOF\nrm -rf /etc\nEOF\n' "block" "bash heredoc rm -rf /etc"

# Must ALLOW: safe heredoc content should not be blocked
test_command $'node <<EOF\nconsole.log(\"hello\");\nEOF\n' "allow" "node heredoc safe content"
test_command $'python3 <<EOF\nprint(\"hello\")\nEOF\n' "allow" "python heredoc safe content"

# Must ALLOW: heredoc/inline trigger strings inside known-safe string args must not be treated as executed
test_command 'git commit -m "example: node -e \"require(\x27child_process\x27).execSync(\x27rm -rf /\x27)\""' "allow" "git commit -m contains node -e rm -rf (data context)"

log_section "Execution Context Regression Tests (git_safety_guard-t8x.3)"

# Must ALLOW (data contexts)
test_command 'bd create --description="This pattern blocks rm -rf"' "allow" "bd create --description contains rm -rf (data context)"
test_command 'bd update git_safety_guard-99e --notes "example: git reset --hard"' "allow" "bd update --notes contains git reset --hard (data context)"
test_command 'git commit -m "Fix git push --force detection"' "allow" "git commit -m contains git push --force (data context)"
test_command 'git tag -m "Document rm -rf" v1.2.3' "allow" "git tag -m contains rm -rf (data context)"
test_command 'echo "example: kubectl delete namespace prod"' "allow" "echo contains kubectl delete namespace (data context)"
test_command 'rg -n "rm -rf" src/main.rs' "allow" "rg positional pattern contains rm -rf (data context)"
test_command 'grep -e "DROP TABLE" schema.sql' "allow" "grep -e contains DROP TABLE (data context)"

# Must BLOCK (executed contexts)
test_command 'bash -c "rm -rf /"' "block" "bash -c executes rm -rf /"
test_command 'echo hi | bash -c "rm -rf /"' "block" "pipe to bash -c executes rm -rf /"
test_command "python -c \"import os; os.system('rm -rf /')\"" "block" "python -c executes rm -rf /"
test_command "node -e \"require('child_process').execSync('rm -rf /')\"" "block" "node -e executes rm -rf /"
test_command 'echo $(rm -rf /home/user)' "block" "command substitution executes rm -rf"
test_command 'echo `rm -rf /home/user`' "block" "backticks substitution executes rm -rf"

# Edge cases: wrappers/prefixes
test_command 'sudo git commit -m "Fix rm -rf detection"' "allow" "sudo git commit -m contains rm -rf (data context)"
test_command 'FOO=1 git commit -m "Fix rm -rf detection"' "allow" "env assignment + git commit -m contains rm -rf (data context)"
test_command 'sudo bash -c "rm -rf /"' "block" "sudo bash -c executes rm -rf /"
test_command 'env FOO=1 bash -c "rm -rf /"' "block" "env VAR=... bash -c executes rm -rf /"

log_section "Allowlist E2E Tests (git_safety_guard-1gt.2.6)"

# Test helper: run command with a project allowlist file in an isolated directory.
# This tests the real hook path with allowlist layering.
test_command_with_allowlist() {
    local cmd="$1"
    local allowlist_content="$2"
    local expected="$3"  # "block" or "allow"
    local desc="$4"

    log_test_start "$desc"
    if $VERBOSE && ! $JSON_OUTPUT; then
        echo -e "  ${CYAN}Command:${NC} $(truncate_cmd "$cmd")"
        echo -e "  ${CYAN}Allowlist:${NC} $(echo "$allowlist_content" | tr '\n' ' ' | head -c 80)..."
    fi

    # Create isolated temp directory with .dcg/allowlist.toml
    # IMPORTANT: Initialize a git repo so allowlist discovery works (finds repo root)
    local tmpdir
    tmpdir=$(mktemp -d)
    (cd "$tmpdir" && git init -q) 2>/dev/null || true
    mkdir -p "$tmpdir/.dcg"
    echo "$allowlist_content" > "$tmpdir/.dcg/allowlist.toml"

    # Create JSON input and base64 encode it
    local escaped_cmd
    escaped_cmd=$(json_escape "$cmd")
    local json="{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"$escaped_cmd\"}}"
    local encoded
    encoded=$(echo -n "$json" | base64 -w 0)

    # Run the binary from the temp directory so it discovers the project allowlist
    local result
    result=$(cd "$tmpdir" && echo "$encoded" | base64 -d | \
        HOME="$TEST_ENV_HOME" \
        XDG_CONFIG_HOME="$TEST_ENV_XDG" \
        DCG_ALLOWLIST_SYSTEM_PATH="" \
        "$BINARY" 2>/dev/null || true)

    # Note: do not delete tmpdir here; destructive cleanup is intentionally avoided.

    # Check result
    if [[ "$expected" == "block" ]]; then
        if echo "$result" | grep -q '"permissionDecision"' && echo "$result" | grep -q '"deny"'; then
            log_pass "BLOCKED (with allowlist): $desc"
            return 0
        fi
        log_fail "Should BLOCK (with allowlist): $desc" "JSON with permissionDecision: deny" "${result:-<empty>}"
        return 0
    else
        # Expected: allow (empty output)
        if [[ -z "$result" ]]; then
            log_pass "ALLOWED (with allowlist): $desc"
            return 0
        else
            log_fail "Should ALLOW (with allowlist): $desc" "<empty output>" "$result"
            return 0
        fi
    fi
}

# 1) Baseline: verify a known destructive command is blocked without allowlist
test_command "git reset --hard" "block" "Baseline: git reset --hard blocked (no allowlist)"

# 2) Project allowlist overrides exact rule (core.git:reset-hard)
test_command_with_allowlist \
    "git reset --hard" \
    '[[allow]]
rule = "core.git:reset-hard"
reason = "Allowed for E2E testing"
added_by = "e2e_test.sh"' \
    "allow" \
    "Allowlist: core.git:reset-hard overrides deny"

# 3) Non-target rule remains enforced (git clean -f is NOT allowlisted)
test_command_with_allowlist \
    "git clean -f" \
    '[[allow]]
rule = "core.git:reset-hard"
reason = "Only reset-hard is allowed"
added_by = "e2e_test.sh"' \
    "block" \
    "Allowlist: git clean -f remains blocked (non-target rule)"

# 4) Expired allowlist entry does NOT apply
test_command_with_allowlist \
    "git reset --hard" \
    '[[allow]]
rule = "core.git:reset-hard"
reason = "This entry has expired"
added_by = "e2e_test.sh"
expires_at = "2020-01-01"' \
    "block" \
    "Allowlist: expired entry does not apply"

# 5) Future expiration still applies
test_command_with_allowlist \
    "git reset --hard" \
    '[[allow]]
rule = "core.git:reset-hard"
reason = "This entry has not expired yet"
added_by = "e2e_test.sh"
expires_at = "2099-12-31"' \
    "allow" \
    "Allowlist: future expiration still applies"

# 6) Wildcard pack rule (core.git:*) works without risk acknowledgement
# Note: The implementation allows pack-scoped wildcards without explicit ack.
# They're less dangerous than regex patterns which DO require acknowledgement.
test_command_with_allowlist \
    "git reset --hard" \
    '[[allow]]
rule = "core.git:*"
reason = "Wildcard allows all rules in pack"
added_by = "e2e_test.sh"' \
    "allow" \
    "Allowlist: wildcard core.git:* allows all git rules"

# 7) Global wildcard (*:*) is rejected (never allowed)
# Even with risk_acknowledged, we never allow bypassing ALL packs.
test_command_with_allowlist \
    "git reset --hard" \
    '[[allow]]
rule = "*:reset-hard"
reason = "Global pack wildcard should be rejected"
added_by = "e2e_test.sh"
risk_acknowledged = true' \
    "block" \
    "Allowlist: global wildcard *:pattern is rejected"

# 8) Regex entry without risk_acknowledged is ignored
test_command_with_allowlist \
    "git reset --hard" \
    '[[allow]]
pattern = "git reset"
reason = "Regex without ack should be ignored"
added_by = "e2e_test.sh"' \
    "block" \
    "Allowlist: regex without risk_acknowledged is ignored"

# NOTE: Regex pattern allowlist entries (pattern = "...") are parsed but NOT YET
# implemented in the evaluation flow. Test 9 is reserved for when that feature
# is added. For now, only rule-based entries are supported (rule = "pack:name").

# 9) Condition not met: entry skipped
test_command_with_allowlist \
    "git reset --hard" \
    '[[allow]]
rule = "core.git:reset-hard"
reason = "Only in CI"
added_by = "e2e_test.sh"
conditions = { CI = "true" }' \
    "block" \
    "Allowlist: entry with unmet condition is skipped"

# 10) Condition met: entry applies (set CI=true in env)
# Note: We need a modified test helper for this case
test_command_with_allowlist_and_env() {
    local cmd="$1"
    local allowlist_content="$2"
    local env_vars="$3"
    local expected="$4"
    local desc="$5"

    log_test_start "$desc"
    if $VERBOSE && ! $JSON_OUTPUT; then
        echo -e "  ${CYAN}Command:${NC} $(truncate_cmd "$cmd")"
        echo -e "  ${CYAN}Env:${NC} $env_vars"
    fi

    local tmpdir
    tmpdir=$(mktemp -d)
    (cd "$tmpdir" && git init -q) 2>/dev/null || true
    mkdir -p "$tmpdir/.dcg"
    echo "$allowlist_content" > "$tmpdir/.dcg/allowlist.toml"

    local escaped_cmd
    escaped_cmd=$(json_escape "$cmd")
    local json="{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"$escaped_cmd\"}}"
    local encoded
    encoded=$(echo -n "$json" | base64 -w 0)

    local result
    result=$(cd "$tmpdir" && echo "$encoded" | base64 -d | env \
        HOME="$TEST_ENV_HOME" \
        XDG_CONFIG_HOME="$TEST_ENV_XDG" \
        DCG_ALLOWLIST_SYSTEM_PATH="" \
        $env_vars "$BINARY" 2>/dev/null || true)

    # Note: do not delete tmpdir here; destructive cleanup is intentionally avoided.

    if [[ "$expected" == "block" ]]; then
        if echo "$result" | grep -q '"permissionDecision"' && echo "$result" | grep -q '"deny"'; then
            log_pass "BLOCKED (with env): $desc"
            return 0
        fi
        log_fail "Should BLOCK (with env): $desc" "JSON with permissionDecision: deny" "${result:-<empty>}"
        return 0
    else
        if [[ -z "$result" ]]; then
            log_pass "ALLOWED (with env): $desc"
            return 0
        else
            log_fail "Should ALLOW (with env): $desc" "<empty output>" "$result"
            return 0
        fi
    fi
}

test_command_with_layered_allowlists() {
    local cmd="$1"
    local project_allowlist="$2"
    local user_allowlist="$3"
    local system_allowlist="$4"
    local env_vars="$5"
    local expected="$6"
    local expected_layer="$7"
    local desc="$8"

    log_test_start "$desc"
    if $VERBOSE && ! $JSON_OUTPUT; then
        echo -e "  ${CYAN}Command:${NC} $(truncate_cmd "$cmd")"
        echo -e "  ${CYAN}Expected layer:${NC} ${expected_layer:-<none>}"
        if [[ -n "$env_vars" ]]; then
            echo -e "  ${CYAN}Env:${NC} $env_vars"
        fi
        if [[ -n "$project_allowlist" ]]; then
            echo -e "  ${CYAN}Project allowlist:${NC} $(echo "$project_allowlist" | tr '\n' ' ' | head -c 80)..."
        fi
        if [[ -n "$user_allowlist" ]]; then
            echo -e "  ${CYAN}User allowlist:${NC} $(echo "$user_allowlist" | tr '\n' ' ' | head -c 80)..."
        fi
        if [[ -n "$system_allowlist" ]]; then
            echo -e "  ${CYAN}System allowlist:${NC} $(echo "$system_allowlist" | tr '\n' ' ' | head -c 80)..."
        fi
    fi

    local tmpdir
    tmpdir=$(mktemp -d)

    local project_dir="$tmpdir/project"
    local home_dir="$tmpdir/home"
    local user_config_dir="$tmpdir/user-config"
    local system_dir="$tmpdir/system"
    local system_path="$system_dir/allowlist.toml"

    mkdir -p "$project_dir" "$home_dir" "$user_config_dir" "$system_dir"
    (cd "$project_dir" && git init -q) 2>/dev/null || true

    if [[ -n "$project_allowlist" ]]; then
        mkdir -p "$project_dir/.dcg"
        echo "$project_allowlist" > "$project_dir/.dcg/allowlist.toml"
    fi

    if [[ -n "$user_allowlist" ]]; then
        mkdir -p "$user_config_dir/dcg"
        echo "$user_allowlist" > "$user_config_dir/dcg/allowlist.toml"
    fi

    if [[ -n "$system_allowlist" ]]; then
        echo "$system_allowlist" > "$system_path"
    fi

    local escaped_cmd
    escaped_cmd=$(json_escape "$cmd")
    local json="{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"$escaped_cmd\"}}"
    local encoded
    encoded=$(echo -n "$json" | base64 -w 0)

    local result
    result=$(cd "$project_dir" && echo "$encoded" | base64 -d | env \
        HOME="$home_dir" \
        XDG_CONFIG_HOME="$user_config_dir" \
        DCG_ALLOWLIST_SYSTEM_PATH="$system_path" \
        $env_vars "$BINARY" 2>/dev/null || true)

    # Note: do not delete tmpdir here; destructive cleanup is intentionally avoided.

    if [[ "$expected" == "block" ]]; then
        if echo "$result" | grep -q '"permissionDecision"' && echo "$result" | grep -q '"deny"'; then
            log_pass "BLOCKED (layered allowlist): $desc"
            return 0
        fi
        log_fail "Should BLOCK (layered allowlist): $desc" "deny (expected layer: ${expected_layer:-<none>})" "${result:-<empty>}"
        return 0
    else
        if [[ -z "$result" ]]; then
            log_pass "ALLOWED (layered allowlist): $desc"
            return 0
        else
            log_fail "Should ALLOW (layered allowlist): $desc" "allow (expected layer: ${expected_layer:-<none>})" "$result"
            return 0
        fi
    fi
}

test_command_with_allowlist_and_env \
    "git reset --hard" \
    '[[allow]]
rule = "core.git:reset-hard"
reason = "Only in CI"
added_by = "e2e_test.sh"
conditions = { CI = "true" }' \
    "CI=true" \
    "allow" \
    "Allowlist: entry with met condition applies"

# 11) Multiple allowlist entries: second one matches
test_command_with_allowlist \
    "git clean -f" \
    '[[allow]]
rule = "core.git:reset-hard"
reason = "Only reset-hard"
added_by = "e2e_test.sh"

[[allow]]
rule = "core.git:clean-force"
reason = "Also allow clean"
added_by = "e2e_test.sh"' \
    "allow" \
    "Allowlist: multiple entries, second one matches"

log_section "Allowlist Layering E2E Tests (git_safety_guard-s1u)"

test_command_with_layered_allowlists \
    "git reset --hard" \
    '[[allow]]
rule = "core.git:reset-hard"
reason = "Project layer allow"
added_by = "e2e_test.sh"' \
    "" \
    "" \
    "" \
    "allow" \
    "project" \
    "Layering: project allowlist applies"

test_command_with_layered_allowlists \
    "git reset --hard" \
    '[[allow]]
rule = "core.git:reset-hard"
reason = "Expired project allowlist"
added_by = "e2e_test.sh"
expires_at = "2020-01-01"' \
    '[[allow]]
rule = "core.git:reset-hard"
reason = "User layer allow"
added_by = "e2e_test.sh"' \
    "" \
    "" \
    "allow" \
    "user" \
    "Layering: expired project entry falls back to user"

test_command_with_layered_allowlists \
    "git reset --hard" \
    '[[allow]]
rule = "core.git:reset-hard"
reason = "Project requires CI"
added_by = "e2e_test.sh"
conditions = { CI = "true" }' \
    '[[allow]]
rule = "core.git:reset-hard"
reason = "User fallback"
added_by = "e2e_test.sh"' \
    "" \
    "" \
    "allow" \
    "user" \
    "Layering: unmet project condition falls back to user"

test_command_with_layered_allowlists \
    "git reset --hard" \
    "" \
    '[[allow]]
rule = "core.git:reset-hard"
reason = "Expired user allowlist"
added_by = "e2e_test.sh"
expires_at = "2020-01-01"' \
    '[[allow]]
rule = "core.git:reset-hard"
reason = "System layer allow"
added_by = "e2e_test.sh"' \
    "" \
    "allow" \
    "system" \
    "Layering: expired user entry falls back to system"

test_command_with_layered_allowlists \
    "git reset --hard" \
    "" \
    "" \
    '[[allow]]
rule = "core.git:reset-hard"
reason = "System requires CI"
added_by = "e2e_test.sh"
conditions = { CI = "true" }' \
    "" \
    "block" \
    "none" \
    "Layering: system condition unmet blocks (no other layer)"

test_command_with_layered_allowlists \
    "git reset --hard" \
    "" \
    "" \
    '[[allow]]
rule = "core.git:reset-hard"
reason = "System allows in CI"
added_by = "e2e_test.sh"
conditions = { CI = "true" }' \
    "CI=true" \
    "allow" \
    "system" \
    "Layering: system condition met allows"

run_ci_feature_tests

#
# SUMMARY
#

SUITE_END_TIME=$(get_timestamp_ms)
SUITE_DURATION_MS=$((SUITE_END_TIME - SUITE_START_TIME))

# Calculate timing statistics
calculate_timing_stats() {
    local min_ms=999999999
    local max_ms=0
    local total_ms=0
    local count=${#TEST_TIMES[@]}

    for t in "${TEST_TIMES[@]}"; do
        total_ms=$((total_ms + t))
        if [[ $t -lt $min_ms ]]; then
            min_ms=$t
        fi
        if [[ $t -gt $max_ms ]]; then
            max_ms=$t
        fi
    done

    if [[ $count -gt 0 ]]; then
        local avg_ms=$((total_ms / count))
        echo "$min_ms $max_ms $avg_ms $total_ms"
    else
        echo "0 0 0 0"
    fi
}

# Format milliseconds as human-readable
format_duration() {
    local ms=$1
    if [[ $ms -lt 1000 ]]; then
        echo "${ms}ms"
    elif [[ $ms -lt 60000 ]]; then
        local secs=$((ms / 1000))
        local remainder=$((ms % 1000))
        echo "${secs}.${remainder}s"
    else
        local mins=$((ms / 60000))
        local secs=$(((ms % 60000) / 1000))
        echo "${mins}m${secs}s"
    fi
}

# Output JSON results
output_json() {
    local stats
    stats=$(calculate_timing_stats)
    read -r min_ms max_ms avg_ms total_ms <<< "$stats"

    echo "{"
    echo "  \"summary\": {"
    echo "    \"total\": $TESTS_TOTAL,"
    echo "    \"passed\": $TESTS_PASSED,"
    echo "    \"failed\": $TESTS_FAILED,"
    echo "    \"success\": $( [[ $TESTS_FAILED -eq 0 ]] && echo "true" || echo "false" )"
    echo "  },"
    echo "  \"timing\": {"
    echo "    \"suite_duration_ms\": $SUITE_DURATION_MS,"
    echo "    \"test_total_ms\": $total_ms,"
    echo "    \"test_min_ms\": $min_ms,"
    echo "    \"test_max_ms\": $max_ms,"
    echo "    \"test_avg_ms\": $avg_ms"
    echo "  },"
    echo "  \"binary\": \"$(json_escape "$BINARY")\","
    if [[ -n "$ARTIFACTS_DIR" ]]; then
        echo "  \"artifacts_dir\": \"$(json_escape "$ARTIFACTS_DIR")\","
    fi
    echo "  \"tests\": ["

    local first=true
    for i in "${!TEST_NAMES[@]}"; do
        if $first; then
            first=false
        else
            echo ","
        fi
        local result="${TEST_RESULTS[$i]}"
        local name="${TEST_NAMES[$i]}"
        local time="${TEST_TIMES[$i]}"
        local output="${TEST_OUTPUTS[$i]}"
        echo -n "    {"
        echo -n "\"id\": \"T$((i + 1))\", "
        echo -n "\"name\": \"$(json_escape "$name")\", "
        echo -n "\"result\": \"$result\", "
        echo -n "\"duration_ms\": $time"
        if [[ -n "$output" ]]; then
            echo -n ", \"output\": \"$(json_escape "$output")\""
        fi
        echo -n "}"
    done
    echo ""
    echo "  ]"
    echo "}"
}

if $JSON_OUTPUT; then
    output_json
    if [[ $TESTS_FAILED -gt 0 ]]; then
        exit 1
    else
        exit 0
    fi
fi

# Human-readable summary
echo ""
echo -e "${BOLD}${BLUE}=== Test Summary ===${NC}"
echo -e "Total:  ${TESTS_TOTAL}"
echo -e "${GREEN}Passed: ${TESTS_PASSED}${NC}"
if [[ $TESTS_FAILED -gt 0 ]]; then
    echo -e "${RED}Failed: ${TESTS_FAILED}${NC}"
else
    echo -e "Failed: 0"
fi

# Timing summary
stats=$(calculate_timing_stats)
read -r min_ms max_ms avg_ms total_ms <<< "$stats"
echo ""
echo -e "${BOLD}${BLUE}=== Timing Summary ===${NC}"
echo -e "Suite duration: $(format_duration $SUITE_DURATION_MS)"
echo -e "Test time:      $(format_duration $total_ms)"
echo -e "Min/Avg/Max:    $(format_duration $min_ms) / $(format_duration $avg_ms) / $(format_duration $max_ms)"

# List artifacts if any were created
if [[ -n "$ARTIFACTS_DIR" && $TESTS_FAILED -gt 0 ]]; then
    echo ""
    echo -e "${BOLD}${YELLOW}=== Failure Artifacts ===${NC}"
    for f in "$ARTIFACTS_DIR"/*_failure.txt; do
        if [[ -f "$f" ]]; then
            echo -e "  ${CYAN}$(basename "$f")${NC}"
        fi
    done
fi

echo ""
if [[ $TESTS_FAILED -gt 0 ]]; then
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
else
    echo -e "${GREEN}${BOLD}All tests passed!${NC}"
    exit 0
fi

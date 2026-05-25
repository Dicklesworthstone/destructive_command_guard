#!/usr/bin/env bash
# run_e2e_tests.sh - Master E2E Test Runner for DCG
# Part of bead [E0-T1] E2E test infrastructure
#
# This script orchestrates all E2E tests for the Destructive Command Guard.
# It builds DCG, sets up the test environment, runs tests, and generates reports.

set -euo pipefail

# === Configuration ===
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTS_DIR="$PROJECT_ROOT/tests"
E2E_DIR="$TESTS_DIR/e2e"
FIXTURES_DIR="$E2E_DIR/fixtures"
REPORT_DIR="${REPORT_DIR:-$PROJECT_ROOT/target/e2e-reports}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# === Logging Functions ===
log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[PASS]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[FAIL]${NC} $*"; }
log_section() { echo -e "\n${CYAN}══════════════════════════════════════════════════════════════${NC}"; echo -e "${CYAN}  $*${NC}"; echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}\n"; }

# === Help ===
show_help() {
    cat << EOF
DCG E2E Test Runner

Usage: $(basename "$0") [OPTIONS] [TEST_PATTERN]

Options:
    -h, --help          Show this help message
    -v, --verbose       Enable verbose output
    -q, --quiet         Minimal output (errors only)
    --release           Build and test in release mode
    --no-build          Skip building DCG (use existing binary)
    --filter PATTERN    Run only tests matching PATTERN
    --config FILE       Use specific config fixture for all tests
    --report FORMAT     Generate report in FORMAT (json|markdown|both)
    --parallel N        Run N tests in parallel (default: 1)
    --timeout SECS      Per-test timeout in seconds (default: 30)
    --fail-fast         Stop on first failure
    --list              List available tests without running
    --shell-tests       Also run legacy shell-based e2e tests
    --rust-tests        Run Rust-based e2e tests (default)
    --all               Run all test suites (shell + rust)

Environment:
    DCG_BINARY          Path to dcg binary (overrides build)
    DCG_TEST_VERBOSE    Enable verbose test output
    DCG_REPORT_DIR      Directory for test reports
    RUST_LOG            Rust logging level

Examples:
    $(basename "$0")                      # Run all Rust e2e tests
    $(basename "$0") --release            # Run in release mode
    $(basename "$0") --filter dangerous   # Run tests matching 'dangerous'
    $(basename "$0") --all --verbose      # Run everything with verbose output
    $(basename "$0") --list               # List available tests

EOF
    exit 0
}

# === Parse Arguments ===
VERBOSE=false
QUIET=false
RELEASE_MODE=false
NO_BUILD=false
FILTER=""
CONFIG_FILE=""
REPORT_FORMAT="markdown"
PARALLEL=1
TIMEOUT=30
FAIL_FAST=false
LIST_ONLY=false
RUN_SHELL_TESTS=false
RUN_RUST_TESTS=true
TEST_PATTERN=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help) show_help ;;
        -v|--verbose) VERBOSE=true; shift ;;
        -q|--quiet) QUIET=true; shift ;;
        --release) RELEASE_MODE=true; shift ;;
        --no-build) NO_BUILD=true; shift ;;
        --filter) FILTER="$2"; shift 2 ;;
        --config) CONFIG_FILE="$2"; shift 2 ;;
        --report) REPORT_FORMAT="$2"; shift 2 ;;
        --parallel) PARALLEL="$2"; shift 2 ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --fail-fast) FAIL_FAST=true; shift ;;
        --list) LIST_ONLY=true; shift ;;
        --shell-tests) RUN_SHELL_TESTS=true; RUN_RUST_TESTS=false; shift ;;
        --rust-tests) RUN_RUST_TESTS=true; shift ;;
        --all) RUN_SHELL_TESTS=true; RUN_RUST_TESTS=true; shift ;;
        -*) log_error "Unknown option: $1"; exit 1 ;;
        *) TEST_PATTERN="$1"; shift ;;
    esac
done

# === Pre-flight Checks ===
preflight_checks() {
    log_section "Pre-flight Checks"

    local checks_passed=true

    # Check Rust toolchain
    if command -v cargo &> /dev/null; then
        local rust_version=$(rustc --version)
        log_info "Rust: $rust_version"
    else
        log_error "Rust toolchain not found"
        checks_passed=false
    fi

    # Check project structure
    if [[ ! -f "$PROJECT_ROOT/Cargo.toml" ]]; then
        log_error "Not in DCG project root"
        checks_passed=false
    else
        log_info "Project root: $PROJECT_ROOT"
    fi

    # Check fixtures exist
    if [[ -d "$FIXTURES_DIR" ]]; then
        local config_count=$(find "$FIXTURES_DIR/configs" -name "*.toml" 2>/dev/null | wc -l)
        local command_count=$(find "$FIXTURES_DIR/commands" -name "*.txt" 2>/dev/null | wc -l)
        log_info "Fixtures: $config_count configs, $command_count command sets"
    else
        log_warn "Fixtures directory not found: $FIXTURES_DIR"
    fi

    # Create report directory
    mkdir -p "$REPORT_DIR"
    log_info "Reports: $REPORT_DIR"

    if [[ "$checks_passed" != "true" ]]; then
        log_error "Pre-flight checks failed"
        exit 1
    fi

    log_success "All pre-flight checks passed"
}

# === Build DCG ===
build_dcg() {
    if [[ "$NO_BUILD" == "true" ]]; then
        log_info "Skipping build (--no-build)"
        return
    fi

    log_section "Building DCG"

    local build_args=()
    if [[ "$RELEASE_MODE" == "true" ]]; then
        build_args+=("--release")
    fi

    if [[ "$VERBOSE" == "true" ]]; then
        cargo build "${build_args[@]}" 2>&1
    else
        cargo build "${build_args[@]}" 2>&1 | tail -5
    fi

    # Set binary path
    if [[ "$RELEASE_MODE" == "true" ]]; then
        DCG_BINARY="${DCG_BINARY:-$PROJECT_ROOT/target/release/dcg}"
    else
        DCG_BINARY="${DCG_BINARY:-$PROJECT_ROOT/target/debug/dcg}"
    fi

    if [[ ! -x "$DCG_BINARY" ]]; then
        log_error "DCG binary not found: $DCG_BINARY"
        exit 1
    fi

    log_success "Built: $DCG_BINARY"
    export DCG_BINARY
}

# === List Available Tests ===
list_tests() {
    log_section "Available E2E Tests"

    echo "Rust E2E Tests:"
    echo "  (Run with: cargo test --test '*' -- --list)"
    cargo test --test '*' -- --list 2>/dev/null | grep "test " | sed 's/^/    /' || echo "    (none found)"

    echo ""
    echo "Shell E2E Tests:"
    if [[ -x "$PROJECT_ROOT/scripts/e2e_test.sh" ]]; then
        echo "    scripts/e2e_test.sh (comprehensive shell tests)"
    fi

    echo ""
    echo "Fixture-based Tests:"
    echo "  Config fixtures:"
    find "$FIXTURES_DIR/configs" -name "*.toml" 2>/dev/null | while read -r f; do
        echo "    - $(basename "$f" .toml)"
    done

    echo "  Command fixtures:"
    find "$FIXTURES_DIR/commands" -name "*.txt" 2>/dev/null | while read -r f; do
        echo "    - $(basename "$f" .txt)"
    done
}

# === Run Rust E2E Tests ===
run_rust_tests() {
    log_section "Running Rust E2E Tests"

    local test_args=("--test" "*")

    if [[ "$RELEASE_MODE" == "true" ]]; then
        test_args+=("--release")
    fi

    # Filter pattern
    if [[ -n "$FILTER" ]]; then
        test_args+=("--" "$FILTER")
    elif [[ -n "$TEST_PATTERN" ]]; then
        test_args+=("--" "$TEST_PATTERN")
    fi

    # Verbose mode
    if [[ "$VERBOSE" == "true" ]]; then
        test_args+=("--nocapture")
        export RUST_LOG="${RUST_LOG:-debug}"
    fi

    local start_time=$(date +%s)
    local exit_code=0

    # Run tests
    if cargo test "${test_args[@]}" 2>&1; then
        log_success "Rust E2E tests passed"
    else
        exit_code=$?
        log_error "Rust E2E tests failed"
    fi

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    log_info "Duration: ${duration}s"

    return $exit_code
}

# === Run Shell E2E Tests ===
run_shell_tests() {
    log_section "Running Shell E2E Tests"

    local shell_script="$PROJECT_ROOT/scripts/e2e_test.sh"

    if [[ ! -x "$shell_script" ]]; then
        log_warn "Shell test script not found: $shell_script"
        return 0
    fi

    local start_time=$(date +%s)
    local exit_code=0

    # Run shell tests
    if [[ "$VERBOSE" == "true" ]]; then
        "$shell_script" 2>&1
    else
        "$shell_script" 2>&1 | grep -E '(PASS|FAIL|ERROR|Summary)'
    fi
    exit_code=${PIPESTATUS[0]}

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    log_info "Duration: ${duration}s"

    if [[ $exit_code -eq 0 ]]; then
        log_success "Shell E2E tests passed"
    else
        log_error "Shell E2E tests failed"
    fi

    return $exit_code
}

# === Run Fixture Tests ===
run_fixture_tests() {
    log_section "Running Fixture-based Tests"

    local passed=0
    local failed=0
    local skipped=0

    # Test each command fixture against each config
    for cmd_file in "$FIXTURES_DIR/commands"/*.txt; do
        [[ -f "$cmd_file" ]] || continue

        local cmd_name=$(basename "$cmd_file" .txt)

        # Apply filter if specified
        if [[ -n "$FILTER" ]] && [[ "$cmd_name" != *"$FILTER"* ]]; then
            ((skipped++))
            continue
        fi

        log_info "Testing command set: $cmd_name"

        # Read commands from fixture
        while IFS= read -r line || [[ -n "$line" ]]; do
            # Skip comments and empty lines
            [[ "$line" =~ ^# ]] && continue
            [[ -z "$line" ]] && continue

            # Parse expected result and command
            local expected=""
            local command=""

            if [[ "$line" =~ ^(BLOCK|ALLOW|WARN): ]]; then
                expected="${line%%:*}"
                command="${line#*:}"
            else
                # safe.txt format - no prefix means ALLOW
                command="$line"
                if [[ "$cmd_name" == "dangerous" ]]; then
                    expected="BLOCK"
                else
                    expected="ALLOW"
                fi
            fi

            # Run DCG check
            local result
            local hook_input
            hook_input=$(printf '{"tool_name":"Bash","tool_input":{"command":"%s"}}' "$command")

            if result=$(echo "$hook_input" | timeout "$TIMEOUT" "$DCG_BINARY" check 2>&1); then
                # DCG allowed (exit 0 or empty output)
                if [[ "$expected" == "ALLOW" ]]; then
                    ((passed++))
                    [[ "$VERBOSE" == "true" ]] && log_success "ALLOW: $command"
                else
                    ((failed++))
                    log_error "Expected $expected but got ALLOW: $command"
                    [[ "$FAIL_FAST" == "true" ]] && return 1
                fi
            else
                # DCG blocked (exit non-zero or denial output)
                if [[ "$expected" == "BLOCK" ]]; then
                    ((passed++))
                    [[ "$VERBOSE" == "true" ]] && log_success "BLOCK: $command"
                else
                    ((failed++))
                    log_error "Expected $expected but got BLOCK: $command"
                    [[ "$FAIL_FAST" == "true" ]] && return 1
                fi
            fi

        done < "$cmd_file"
    done

    log_info "Results: $passed passed, $failed failed, $skipped skipped"

    [[ $failed -eq 0 ]]
}

# === Generate Report ===
generate_report() {
    local total_passed=$1
    local total_failed=$2
    local duration=$3

    log_section "Generating Report"

    local report_file="$REPORT_DIR/e2e_report_$TIMESTAMP"

    if [[ "$REPORT_FORMAT" == "json" ]] || [[ "$REPORT_FORMAT" == "both" ]]; then
        cat > "${report_file}.json" << EOF
{
    "timestamp": "$(date -Iseconds)",
    "dcg_version": "$(cat "$PROJECT_ROOT/Cargo.toml" | grep '^version' | head -1 | cut -d'"' -f2)",
    "rust_version": "$(rustc --version)",
    "passed": $total_passed,
    "failed": $total_failed,
    "duration_seconds": $duration,
    "release_mode": $RELEASE_MODE,
    "filter": "$FILTER"
}
EOF
        log_info "JSON report: ${report_file}.json"
    fi

    if [[ "$REPORT_FORMAT" == "markdown" ]] || [[ "$REPORT_FORMAT" == "both" ]]; then
        cat > "${report_file}.md" << EOF
# DCG E2E Test Report

**Generated:** $(date)
**DCG Version:** $(cat "$PROJECT_ROOT/Cargo.toml" | grep '^version' | head -1 | cut -d'"' -f2)
**Rust Version:** $(rustc --version)

## Summary

| Metric | Value |
|--------|-------|
| Passed | $total_passed |
| Failed | $total_failed |
| Duration | ${duration}s |
| Mode | $(if $RELEASE_MODE; then echo "release"; else echo "debug"; fi) |

## Test Suites

- Rust E2E Tests: $(if $RUN_RUST_TESTS; then echo "✓ Run"; else echo "○ Skipped"; fi)
- Shell E2E Tests: $(if $RUN_SHELL_TESTS; then echo "✓ Run"; else echo "○ Skipped"; fi)

---
*Report generated by run_e2e_tests.sh*
EOF
        log_info "Markdown report: ${report_file}.md"
    fi
}

# === Main ===
main() {
    local start_time=$(date +%s)
    local total_passed=0
    local total_failed=0

    # Header
    if [[ "$QUIET" != "true" ]]; then
        echo -e "${CYAN}"
        echo "╔════════════════════════════════════════════════════════════════╗"
        echo "║         DCG E2E Test Runner                                    ║"
        echo "║         Destructive Command Guard - End-to-End Tests          ║"
        echo "╚════════════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
    fi

    # List only mode
    if [[ "$LIST_ONLY" == "true" ]]; then
        list_tests
        exit 0
    fi

    # Run pre-flight checks
    preflight_checks

    # Build
    build_dcg

    # Run test suites
    if [[ "$RUN_RUST_TESTS" == "true" ]]; then
        if run_rust_tests; then
            ((total_passed++))
        else
            ((total_failed++))
            [[ "$FAIL_FAST" == "true" ]] && exit 1
        fi
    fi

    if [[ "$RUN_SHELL_TESTS" == "true" ]]; then
        if run_shell_tests; then
            ((total_passed++))
        else
            ((total_failed++))
            [[ "$FAIL_FAST" == "true" ]] && exit 1
        fi
    fi

    # Calculate duration
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    # Generate report
    generate_report $total_passed $total_failed $duration

    # Final summary
    log_section "Final Summary"
    echo "  Test Suites Passed: $total_passed"
    echo "  Test Suites Failed: $total_failed"
    echo "  Total Duration: ${duration}s"
    echo ""

    if [[ $total_failed -eq 0 ]]; then
        log_success "All E2E tests passed!"
        exit 0
    else
        log_error "Some E2E tests failed"
        exit 1
    fi
}

# Run main
main "$@"

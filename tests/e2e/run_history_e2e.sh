#!/usr/bin/env bash
# History E2E Test Runner
#
# This script runs comprehensive end-to-end tests for the DCG history system.
# It verifies database creation, command logging, querying, and cleanup.
#
# Usage:
#   ./tests/e2e/run_history_e2e.sh
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
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Create temp directory for test isolation
TEMP_DIR=$(mktemp -d -t dcg_history_e2e_XXXXXX)
HISTORY_DB="${TEMP_DIR}/history.db"
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

# Run a single SQLite query and print the first column of the first row.
db_query() {
    local query="$1"
    python3 - "$HISTORY_DB" "$query" << 'PY'
import os
import sqlite3
import sys

db_path = sys.argv[1]
query = sys.argv[2]

if not os.path.exists(db_path):
    print("0")
    sys.exit(0)

conn = sqlite3.connect(db_path)
try:
    row = conn.execute(query).fetchone()
    if row is None:
        print("")
    else:
        print(row[0])
finally:
    conn.close()
PY
}

# Find the DCG binary
find_dcg_binary() {
    # Try release first, then debug
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

    # Create a minimal config that enables history
    cat > "${DCG_CONFIG_DIR}/config.toml" << 'EOF'
[general]
verbose = false

[packs]
enabled = ["core.git", "core.filesystem"]

[history]
enabled = true
EOF

    # Export environment variables for test isolation
    export DCG_HISTORY_DB="$HISTORY_DB"
    export DCG_CONFIG="${DCG_CONFIG_DIR}/config.toml"
    export HOME="$TEMP_DIR"
    export XDG_CONFIG_HOME="$DCG_CONFIG_DIR"

    log_info "Test environment setup complete"
    log_info "  Temp dir: $TEMP_DIR"
    log_info "  History DB: $HISTORY_DB"
}

# =============================================================================
# Test Scenarios
# =============================================================================

test_database_creation() {
    log_info "Testing: Database creation on first command..."

    # Database shouldn't exist yet
    if [[ -f "$HISTORY_DB" ]]; then
        log_fail "Database exists before first run"
        return 1
    fi

    # Run a safe command through hook mode
    local input='{"tool_name":"Bash","tool_input":{"command":"git status"}}'
    echo "$input" | "$DCG_BIN" 2>/dev/null || true

    # Database should now exist
    if [[ -f "$HISTORY_DB" ]]; then
        log_pass "Database created on first command"
        return 0
    else
        log_fail "Database not created"
        return 1
    fi
}

test_command_logging() {
    log_info "Testing: Command logging via hook..."

    # Run a few commands
    local commands=(
        '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}'
        '{"tool_name":"Bash","tool_input":{"command":"echo hello"}}'
        '{"tool_name":"Bash","tool_input":{"command":"pwd"}}'
    )

    for cmd in "${commands[@]}"; do
        echo "$cmd" | "$DCG_BIN" 2>/dev/null || true
    done

    # Verify commands were logged by checking database
    local count
    count=$(db_query "SELECT COUNT(*) FROM commands;" || echo "0")

    if [[ "$count" -ge 4 ]]; then  # 1 from previous test + 3 new
        log_pass "Commands logged to database (count: $count)"
        return 0
    else
        log_fail "Expected at least 4 commands, got: $count"
        return 1
    fi
}

test_blocked_command_logging() {
    log_info "Testing: Blocked command logging..."

    local before_count
    before_count=$(db_query "SELECT COUNT(*) FROM commands WHERE outcome='deny';" || echo "0")

    # Run a dangerous command (should be blocked)
    local input='{"tool_name":"Bash","tool_input":{"command":"git reset --hard HEAD"}}'
    echo "$input" | "$DCG_BIN" 2>/dev/null || true

    local after_count
    after_count=$(db_query "SELECT COUNT(*) FROM commands WHERE outcome='deny';" || echo "0")

    if [[ "$after_count" -gt "$before_count" ]]; then
        log_pass "Blocked command logged with outcome='deny'"
        return 0
    else
        log_fail "Blocked command not logged correctly"
        return 1
    fi
}

test_schema_version() {
    log_info "Testing: Schema version tracking..."

    local version
    version=$(db_query "SELECT MAX(version) FROM schema_version;" || echo "0")

    if [[ "$version" -ge 1 ]]; then
        log_pass "Schema version tracked (v$version)"
        return 0
    else
        log_fail "Schema version not found"
        return 1
    fi
}

test_fts_search() {
    log_info "Testing: Full-text search functionality..."

    # Run a unique command
    local unique_cmd="echo history_e2e_test_marker_$(date +%s)"
    local input="{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"$unique_cmd\"}}"
    echo "$input" | "$DCG_BIN" 2>/dev/null || true

    # Search for it via FTS
    local found
    found=$(db_query "SELECT COUNT(*) FROM commands_fts WHERE commands_fts MATCH 'history_e2e_test_marker';" || echo "0")

    if [[ "$found" -ge 1 ]]; then
        log_pass "Full-text search working"
        return 0
    else
        log_fail "Full-text search failed"
        return 1
    fi
}

test_indexes_exist() {
    log_info "Testing: Performance indexes..."

    local indexes
    indexes=$(db_query "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%';" || echo "0")

    if [[ "$indexes" -ge 5 ]]; then
        log_pass "Performance indexes created ($indexes indexes)"
        return 0
    else
        log_fail "Missing performance indexes (found: $indexes)"
        return 1
    fi
}

test_wal_mode() {
    log_info "Testing: WAL journal mode..."

    local mode
    mode=$(db_query "PRAGMA journal_mode;" || echo "unknown")

    if [[ "$mode" == "wal" ]]; then
        log_pass "WAL mode enabled"
        return 0
    else
        log_fail "WAL mode not enabled (mode: $mode)"
        return 1
    fi
}

test_performance_1000_commands() {
    log_info "Testing: Performance benchmark (1000 commands)..."

    local start_time
    start_time=$(date +%s%N)

    # Insert 1000 commands
    for i in $(seq 1 1000); do
        local input="{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"perf_test_cmd_$i\"}}"
        echo "$input" | "$DCG_BIN" 2>/dev/null || true
    done

    local end_time
    end_time=$(date +%s%N)

    local duration_ms=$(( (end_time - start_time) / 1000000 ))
    local per_cmd_us=$(( (end_time - start_time) / 1000 / 1000 ))

    if [[ $duration_ms -lt 30000 ]]; then  # 30 seconds max
        log_pass "Performance OK: 1000 commands in ${duration_ms}ms (${per_cmd_us}us/cmd)"
        return 0
    else
        log_fail "Performance too slow: ${duration_ms}ms"
        return 1
    fi
}

# =============================================================================
# Main Test Runner
# =============================================================================

main() {
    echo ""
    echo "=============================================="
    echo "  DCG History E2E Test Suite"
    echo "=============================================="
    echo ""

    # Setup
    ensure_dcg_binary
    setup_test_env

    echo ""
    echo "Running tests..."
    echo ""

    # Run all tests
    test_database_creation || true
    test_command_logging || true
    test_blocked_command_logging || true
    test_schema_version || true
    test_fts_search || true
    test_indexes_exist || true
    test_wal_mode || true

    # Optional performance test (skip in CI for speed)
    if [[ "${SKIP_PERF_TEST:-}" != "1" ]]; then
        test_performance_1000_commands || true
    else
        log_skip "Performance test (SKIP_PERF_TEST=1)"
    fi

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

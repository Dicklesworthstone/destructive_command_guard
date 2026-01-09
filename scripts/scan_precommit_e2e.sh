#!/bin/bash
#
# End-to-End Test Script for `dcg scan --staged`
#
# This script tests the pre-commit scanning workflow with a fixture repo:
#   - Creates a temp git repo with test files
#   - Stages files with known findings (destructive commands in executed contexts)
#   - Stages files with data-only mentions (should NOT trigger findings)
#   - Runs `dcg scan --staged` and asserts correct output/exit code
#
# Usage:
#   ./scripts/scan_precommit_e2e.sh [--verbose] [--binary PATH]
#
# Exit codes:
#   0  All tests passed
#   1  One or more tests failed
#   2  Binary not found or other setup error

set -euo pipefail

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
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

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
        --help|-h)
            echo "Usage: $0 [--verbose] [--binary PATH]"
            echo ""
            echo "Options:"
            echo "  --verbose, -v   Show detailed output for each test"
            echo "  --binary, -b    Path to dcg binary"
            echo "  --help, -h      Show this help message"
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
    if command -v dcg &> /dev/null; then
        BINARY="dcg"
    elif [[ -f "./target/release/dcg" ]]; then
        BINARY="./target/release/dcg"
    elif [[ -f "./target/debug/dcg" ]]; then
        BINARY="./target/debug/dcg"
    else
        echo -e "${RED}Error: dcg binary not found${NC}"
        echo "Run 'cargo build --release' first or specify --binary PATH"
        exit 2
    fi
fi

# Convert to absolute path
if [[ "$BINARY" != /* ]]; then
    BINARY="$(cd "$(dirname "$BINARY")" && pwd)/$(basename "$BINARY")"
fi

echo -e "${BOLD}${BLUE}dcg scan --staged E2E Test Suite${NC}"
echo -e "${CYAN}Binary: ${BINARY}${NC}"
echo ""

# Logging functions
log_test_start() {
    local desc="$1"
    ((++TESTS_TOTAL))
    if $VERBOSE; then
        echo -e "${CYAN}[TEST ${TESTS_TOTAL}]${NC} $desc"
    fi
}

log_pass() {
    local desc="$1"
    ((++TESTS_PASSED))
    echo -e "${GREEN}✓${NC} $desc"
}

log_fail() {
    local desc="$1"
    local expected="${2:-}"
    local actual="${3:-}"
    ((++TESTS_FAILED))
    echo -e "${RED}✗${NC} $desc"
    if $VERBOSE && [[ -n "$expected" ]]; then
        echo -e "  ${YELLOW}Expected:${NC} $expected"
        echo -e "  ${YELLOW}Actual:${NC} $actual"
    fi
}

log_section() {
    local title="$1"
    echo ""
    echo -e "${BOLD}${BLUE}=== $title ===${NC}"
}

log_info() {
    local msg="$1"
    if $VERBOSE; then
        echo -e "  ${CYAN}Info:${NC} $msg"
    fi
}

# Create a fixture git repo with test files
create_fixture_repo() {
    local tmp_dir
    tmp_dir=$(mktemp -d)

    cd "$tmp_dir"
    git init --quiet
    git config user.email "test@example.com"
    git config user.name "Test User"

    # Initial commit so we have a valid repo
    echo "# Test Repo" > README.md
    git add README.md
    git commit --quiet -m "Initial commit"

    echo "$tmp_dir"
}

# Cleanup helper
cleanup_repo() {
    local repo_dir="$1"
    if [[ -d "$repo_dir" ]]; then
        rm -rf "$repo_dir"
    fi
}

# ============================================================================
# Test: Empty staged files (no findings)
# ============================================================================
test_empty_staged() {
    log_section "Test: Empty staged files"

    local repo
    repo=$(create_fixture_repo)
    log_info "Created fixture repo at: $repo"

    cd "$repo"

    # No staged files
    log_test_start "Empty staged files returns exit 0"

    local exit_code=0
    local output
    output=$("$BINARY" scan --staged --format json 2>&1) || exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        # Verify JSON output has 0 findings
        local findings_count
        findings_count=$(echo "$output" | jq -r '.summary.findings_total // 0')
        if [[ "$findings_count" == "0" ]]; then
            log_pass "Empty staged returns exit 0 with 0 findings"
        else
            log_fail "Empty staged returns exit 0 with 0 findings" "0 findings" "$findings_count findings"
        fi
    else
        log_fail "Empty staged returns exit 0" "exit 0" "exit $exit_code"
    fi

    cleanup_repo "$repo"
}

# ============================================================================
# Test: Staged shell script with destructive command (should find)
# ============================================================================
test_staged_destructive_shell() {
    log_section "Test: Staged shell script with destructive command"

    local repo
    repo=$(create_fixture_repo)
    log_info "Created fixture repo at: $repo"

    cd "$repo"

    # Create a shell script with a destructive command
    cat > dangerous.sh << 'SHELL_EOF'
#!/bin/bash
# This script does bad things
git reset --hard HEAD~5
echo "Done"
SHELL_EOF

    git add dangerous.sh
    log_info "Staged dangerous.sh with 'git reset --hard'"

    log_test_start "Destructive shell script triggers finding"

    local exit_code=0
    local output
    output=$("$BINARY" scan --staged --format json --fail-on error 2>&1) || exit_code=$?

    if $VERBOSE; then
        echo -e "  ${CYAN}Output:${NC}"
        echo "$output" | head -30
    fi

    # Should exit non-zero due to error finding
    if [[ $exit_code -ne 0 ]]; then
        log_pass "Exit code is non-zero (found error)"
    else
        log_fail "Exit code should be non-zero" "non-zero" "0"
    fi

    # Verify the finding details
    log_test_start "Finding includes correct file:line"
    local finding_file
    local finding_line
    finding_file=$(echo "$output" | jq -r '.findings[0].file // ""')
    finding_line=$(echo "$output" | jq -r '.findings[0].line // 0')

    if [[ "$finding_file" == "dangerous.sh" ]] && [[ "$finding_line" == "3" ]]; then
        log_pass "Finding has file=dangerous.sh, line=3"
    else
        log_fail "Finding file:line" "dangerous.sh:3" "${finding_file}:${finding_line}"
    fi

    log_test_start "Finding includes rule_id"
    local rule_id
    rule_id=$(echo "$output" | jq -r '.findings[0].rule_id // ""')

    if [[ "$rule_id" == *"git"* ]] || [[ "$rule_id" == *"reset"* ]]; then
        log_pass "Finding has rule_id containing git/reset: $rule_id"
    else
        log_fail "Finding rule_id" "contains git/reset" "$rule_id"
    fi

    log_test_start "Finding includes reason"
    local reason
    reason=$(echo "$output" | jq -r '.findings[0].reason // ""')

    if [[ -n "$reason" ]]; then
        log_pass "Finding has reason: ${reason:0:60}..."
    else
        log_fail "Finding reason" "non-empty" "<empty>"
    fi

    log_test_start "Finding includes extracted_command"
    local extracted
    extracted=$(echo "$output" | jq -r '.findings[0].extracted_command // ""')

    if [[ "$extracted" == *"git reset"* ]]; then
        log_pass "Finding has extracted_command containing 'git reset'"
    else
        log_fail "Finding extracted_command" "contains 'git reset'" "$extracted"
    fi

    cleanup_repo "$repo"
}

# ============================================================================
# Test: Staged file with data-only mention (should NOT find)
# ============================================================================
test_staged_data_only() {
    log_section "Test: Staged file with data-only dangerous string"

    local repo
    repo=$(create_fixture_repo)
    log_info "Created fixture repo at: $repo"

    cd "$repo"

    # Create a markdown file that mentions dangerous commands but doesn't execute them
    cat > README.md << 'MD_EOF'
# Security Documentation

## Dangerous Commands to Avoid

Never run these commands:
- `git reset --hard` - loses uncommitted changes
- `rm -rf /` - deletes everything
- `git push --force` - overwrites remote history

## Safe Alternatives

Instead of `git reset --hard`, consider:
- `git stash` to save changes
- `git checkout .` to discard working changes
MD_EOF

    git add README.md
    log_info "Staged README.md with data-only mentions of dangerous commands"

    log_test_start "Data-only file does not trigger finding"

    local exit_code=0
    local output
    output=$("$BINARY" scan --staged --format json --fail-on error 2>&1) || exit_code=$?

    if $VERBOSE; then
        echo -e "  ${CYAN}Output:${NC}"
        echo "$output" | head -20
    fi

    # Should exit 0 (no error findings)
    if [[ $exit_code -eq 0 ]]; then
        log_pass "Exit code is 0 (no error findings for data-only)"
    else
        log_fail "Exit code should be 0 for data-only file" "0" "$exit_code"
        if $VERBOSE; then
            echo -e "  ${YELLOW}Findings:${NC}"
            echo "$output" | jq '.findings[]?' 2>/dev/null || echo "$output"
        fi
    fi

    # Verify no findings in output
    log_test_start "Zero findings for data-only content"
    local findings_count
    findings_count=$(echo "$output" | jq -r '.summary.findings_total // 0')

    if [[ "$findings_count" == "0" ]]; then
        log_pass "Zero findings for markdown docs"
    else
        log_fail "Zero findings for data-only" "0" "$findings_count"
    fi

    cleanup_repo "$repo"
}

# ============================================================================
# Test: Mixed staged files (one destructive, one safe)
# ============================================================================
test_staged_mixed() {
    log_section "Test: Mixed staged files (destructive + safe)"

    local repo
    repo=$(create_fixture_repo)
    log_info "Created fixture repo at: $repo"

    cd "$repo"

    # Create a safe shell script
    cat > safe.sh << 'SHELL_EOF'
#!/bin/bash
echo "Hello world"
git status
git log --oneline -5
SHELL_EOF

    # Create a dangerous Dockerfile
    cat > Dockerfile << 'DOCKER_EOF'
FROM ubuntu:22.04
RUN apt-get update
RUN rm -rf /var/lib/apt/lists/*
RUN git reset --hard
DOCKER_EOF

    git add safe.sh Dockerfile
    log_info "Staged safe.sh and Dockerfile"

    log_test_start "Mixed files: only dangerous ones produce findings"

    local exit_code=0
    local output
    output=$("$BINARY" scan --staged --format json --fail-on error 2>&1) || exit_code=$?

    if $VERBOSE; then
        echo -e "  ${CYAN}Output:${NC}"
        echo "$output" | head -40
    fi

    # Should find findings in Dockerfile
    local findings_count
    findings_count=$(echo "$output" | jq -r '.summary.findings_total // 0')

    log_test_start "Findings count > 0"
    if [[ "$findings_count" -gt 0 ]]; then
        log_pass "Found $findings_count finding(s)"
    else
        log_fail "Should find findings in Dockerfile" ">0" "$findings_count"
    fi

    # Verify finding is from Dockerfile, not safe.sh
    log_test_start "Finding is from Dockerfile (not safe.sh)"
    local finding_files
    finding_files=$(echo "$output" | jq -r '.findings[].file' | sort -u)

    if echo "$finding_files" | grep -q "Dockerfile"; then
        log_pass "Finding is from Dockerfile"
    else
        log_fail "Finding should be from Dockerfile" "Dockerfile" "$finding_files"
    fi

    if echo "$finding_files" | grep -q "safe.sh"; then
        log_fail "safe.sh should not have findings" "no safe.sh findings" "found safe.sh"
    else
        log_pass "safe.sh has no findings (correct)"
    fi

    cleanup_repo "$repo"
}

# ============================================================================
# Test: --fail-on policy behavior
# ============================================================================
test_fail_on_policy() {
    log_section "Test: --fail-on policy behavior"

    local repo
    repo=$(create_fixture_repo)
    log_info "Created fixture repo at: $repo"

    cd "$repo"

    # Create a shell script with destructive command (use git reset --hard which is always error)
    cat > danger.sh << 'SHELL_EOF'
#!/bin/bash
git reset --hard HEAD~10
SHELL_EOF

    git add danger.sh

    log_test_start "--fail-on error exits non-zero for error finding"
    local exit_code=0
    "$BINARY" scan --staged --format json --fail-on error >/dev/null 2>&1 || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        log_pass "--fail-on error exits $exit_code"
    else
        log_fail "--fail-on error should exit non-zero" "non-zero" "$exit_code"
    fi

    log_test_start "--fail-on none always exits 0"
    exit_code=0
    "$BINARY" scan --staged --format json --fail-on none >/dev/null 2>&1 || exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log_pass "--fail-on none exits 0"
    else
        log_fail "--fail-on none should exit 0" "0" "$exit_code"
    fi

    cleanup_repo "$repo"
}

# ============================================================================
# Test: Output format consistency (JSON schema)
# ============================================================================
test_json_schema() {
    log_section "Test: JSON output schema"

    local repo
    repo=$(create_fixture_repo)
    log_info "Created fixture repo at: $repo"

    cd "$repo"

    cat > test.sh << 'SHELL_EOF'
#!/bin/bash
git push --force origin main
SHELL_EOF

    git add test.sh

    log_test_start "JSON output has required fields"
    local output
    output=$("$BINARY" scan --staged --format json --fail-on none 2>&1)

    # Check schema_version
    local schema_version
    schema_version=$(echo "$output" | jq -r '.schema_version // "missing"')
    if [[ "$schema_version" != "missing" ]] && [[ "$schema_version" -gt 0 ]]; then
        log_pass "Has schema_version: $schema_version"
    else
        log_fail "Missing schema_version" "integer > 0" "$schema_version"
    fi

    # Check summary
    local has_summary
    has_summary=$(echo "$output" | jq -r 'has("summary")')
    if [[ "$has_summary" == "true" ]]; then
        log_pass "Has summary object"
    else
        log_fail "Missing summary" "true" "$has_summary"
    fi

    # Check summary fields
    log_test_start "Summary has required fields"
    local files_scanned findings_total
    files_scanned=$(echo "$output" | jq -r '.summary.files_scanned // "missing"')
    findings_total=$(echo "$output" | jq -r '.summary.findings_total // "missing"')

    if [[ "$files_scanned" != "missing" ]] && [[ "$findings_total" != "missing" ]]; then
        log_pass "Summary has files_scanned=$files_scanned, findings_total=$findings_total"
    else
        log_fail "Summary fields" "files_scanned, findings_total" "files=$files_scanned, findings=$findings_total"
    fi

    # Check findings array
    log_test_start "Findings have required fields"
    local finding_fields
    finding_fields=$(echo "$output" | jq -r '.findings[0] | keys[]' 2>/dev/null | sort | tr '\n' ',')

    # Required: file, line, extractor_id, extracted_command, decision, severity
    if echo "$finding_fields" | grep -q "file" && \
       echo "$finding_fields" | grep -q "line" && \
       echo "$finding_fields" | grep -q "extractor_id" && \
       echo "$finding_fields" | grep -q "extracted_command" && \
       echo "$finding_fields" | grep -q "severity"; then
        log_pass "Finding has required fields"
    else
        log_fail "Finding fields" "file,line,extractor_id,extracted_command,severity" "$finding_fields"
    fi

    cleanup_repo "$repo"
}

# ============================================================================
# Test: Deterministic output ordering
# ============================================================================
test_deterministic_order() {
    log_section "Test: Deterministic output ordering"

    local repo
    repo=$(create_fixture_repo)
    log_info "Created fixture repo at: $repo"

    cd "$repo"

    # Create multiple files with findings
    cat > z_last.sh << 'SHELL_EOF'
#!/bin/bash
rm -rf /z
SHELL_EOF

    cat > a_first.sh << 'SHELL_EOF'
#!/bin/bash
rm -rf /a
SHELL_EOF

    git add z_last.sh a_first.sh

    log_test_start "Output is deterministic across runs"

    local output1 output2
    output1=$("$BINARY" scan --staged --format json --fail-on none 2>&1)
    output2=$("$BINARY" scan --staged --format json --fail-on none 2>&1)

    # Extract finding order
    local order1 order2
    order1=$(echo "$output1" | jq -r '.findings[].file' | tr '\n' ',')
    order2=$(echo "$output2" | jq -r '.findings[].file' | tr '\n' ',')

    if [[ "$order1" == "$order2" ]]; then
        log_pass "Ordering is deterministic: $order1"
    else
        log_fail "Ordering should be deterministic" "$order1" "$order2"
    fi

    log_test_start "Files are sorted alphabetically"
    local first_file
    first_file=$(echo "$output1" | jq -r '.findings[0].file')

    if [[ "$first_file" == "a_first.sh" ]]; then
        log_pass "a_first.sh comes before z_last.sh"
    else
        log_fail "Should sort alphabetically" "a_first.sh first" "$first_file first"
    fi

    cleanup_repo "$repo"
}

# ============================================================================
# Test: GitHub Actions workflow extraction
# ============================================================================
test_github_actions_extraction() {
    log_section "Test: GitHub Actions workflow extraction"

    local repo
    repo=$(create_fixture_repo)
    log_info "Created fixture repo at: $repo"

    cd "$repo"

    mkdir -p .github/workflows
    cat > .github/workflows/ci.yml << 'YAML_EOF'
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Dangerous step
        run: git reset --hard HEAD~10
      - name: Safe step
        run: echo "Hello"
YAML_EOF

    git add .github/workflows/ci.yml
    log_info "Staged .github/workflows/ci.yml"

    log_test_start "Extracts run: steps from GitHub Actions"

    local exit_code=0
    local output
    output=$("$BINARY" scan --staged --format json --fail-on error 2>&1) || exit_code=$?

    if $VERBOSE; then
        echo -e "  ${CYAN}Output:${NC}"
        echo "$output" | head -30
    fi

    # Should find the dangerous step
    local findings_count
    findings_count=$(echo "$output" | jq -r '.summary.findings_total // 0')

    if [[ "$findings_count" -gt 0 ]]; then
        log_pass "Found $findings_count finding(s) in GitHub Actions workflow"
    else
        log_fail "Should find dangerous step in workflow" ">0" "$findings_count"
    fi

    # Verify extractor_id
    log_test_start "Finding has github_actions extractor"
    local extractor
    extractor=$(echo "$output" | jq -r '.findings[0].extractor_id // ""')

    if [[ "$extractor" == *"github"* ]] || [[ "$extractor" == *"actions"* ]] || [[ "$extractor" == *"yaml"* ]]; then
        log_pass "Extractor: $extractor"
    else
        log_fail "Extractor should be github_actions" "github_actions" "$extractor"
    fi

    cleanup_repo "$repo"
}

# ============================================================================
# Run all tests
# ============================================================================
main() {
    test_empty_staged
    test_staged_destructive_shell
    test_staged_data_only
    test_staged_mixed
    test_fail_on_policy
    test_json_schema
    test_deterministic_order
    test_github_actions_extraction

    # Summary
    echo ""
    echo -e "${BOLD}${BLUE}=== Summary ===${NC}"
    echo -e "Total tests: ${TESTS_TOTAL}"
    echo -e "${GREEN}Passed: ${TESTS_PASSED}${NC}"
    if [[ $TESTS_FAILED -gt 0 ]]; then
        echo -e "${RED}Failed: ${TESTS_FAILED}${NC}"
        exit 1
    else
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    fi
}

main

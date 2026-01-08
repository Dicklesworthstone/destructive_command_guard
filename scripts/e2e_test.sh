#!/bin/bash
#
# End-to-End Test Script for dcg
#
# This script tests the hook binary with real-world command scenarios,
# verifying both blocking and allowing behavior with detailed logging.
#
# Usage:
#   ./scripts/e2e_test.sh [--verbose] [--binary PATH]
#
# Options:
#   --verbose   Show detailed output for each test
#   --binary    Path to dcg binary (default: searches PATH)
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

echo -e "${BOLD}${BLUE}dcg End-to-End Test Suite${NC}"
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
    local expected="$2"
    local actual="$3"
    ((++TESTS_FAILED))
    echo -e "${RED}✗${NC} $desc"
    if $VERBOSE; then
        echo -e "  ${YELLOW}Expected:${NC} $expected"
        echo -e "  ${YELLOW}Actual:${NC} $actual"
    fi
}

log_section() {
    local title="$1"
    echo ""
    echo -e "${BOLD}${BLUE}=== $title ===${NC}"
}

# Test helper: run command and check result
test_command() {
    local cmd="$1"
    local expected="$2"  # "block" or "allow"
    local desc="$3"

    log_test_start "$desc"

    # Create JSON input and base64 encode it to avoid interference from
    # any existing git safety hooks that might scan command arguments
    local json="{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"$cmd\"}}"
    local encoded
    encoded=$(echo -n "$json" | base64 -w 0)

    # Run the binary with decoded input
    local result
    result=$(echo "$encoded" | base64 -d | "$BINARY" 2>/dev/null || true)

    # Check result
    if [[ "$expected" == "block" ]]; then
        if echo "$result" | grep -q '"permissionDecision"'; then
            if echo "$result" | grep -q '"deny"'; then
                log_pass "BLOCKED: $desc"
                if $VERBOSE; then
                    echo -e "  ${CYAN}Reason:${NC} $(echo "$result" | grep -o '"permissionDecisionReason":"[^"]*"' | head -1 | cut -d'"' -f4 | head -c 80)..."
                fi
                return 0
            fi
        fi
        log_fail "Should BLOCK: $desc" "JSON with permissionDecision: deny" "${result:-<empty>}"
        return 1
    else
        # Expected: allow (empty output)
        if [[ -z "$result" ]]; then
            log_pass "ALLOWED: $desc"
            return 0
        else
            log_fail "Should ALLOW: $desc" "<empty output>" "$result"
            return 1
        fi
    fi
}

# Test non-Bash tool (should always allow)
test_non_bash_tool() {
    local tool="$1"
    local desc="$2"

    log_test_start "$desc"

    # Use a harmless command to avoid hook interference
    local json="{\"tool_name\":\"$tool\",\"tool_input\":{\"command\":\"echo test\"}}"
    local encoded
    encoded=$(echo -n "$json" | base64 -w 0)
    local result
    result=$(echo "$encoded" | base64 -d | "$BINARY" 2>/dev/null || true)

    if [[ -z "$result" ]]; then
        log_pass "Non-Bash tool ignored: $desc"
        return 0
    else
        log_fail "Non-Bash tool should be ignored: $desc" "<empty output>" "$result"
        return 1
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
    result=$("$BINARY" < "$tmpfile" 2>/dev/null || true)
    rm -f "$tmpfile"

    if [[ -z "$result" ]]; then
        log_pass "Malformed input handled: $desc"
        return 0
    else
        log_fail "Malformed input should be ignored: $desc" "<empty output>" "$result"
        return 1
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

    # Create JSON input and base64 encode it
    local json="{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"$cmd\"}}"
    local encoded
    encoded=$(echo -n "$json" | base64 -w 0)

    # Run the binary with DCG_PACKS environment variable
    local result
    result=$(echo "$encoded" | base64 -d | DCG_PACKS="$packs" "$BINARY" 2>/dev/null || true)

    # Check result
    if [[ "$expected" == "block" ]]; then
        if echo "$result" | grep -q '"permissionDecision"'; then
            if echo "$result" | grep -q '"deny"'; then
                log_pass "BLOCKED (pack=$packs): $desc"
                if $VERBOSE; then
                    echo -e "  ${CYAN}Reason:${NC} $(echo "$result" | grep -o '"permissionDecisionReason":"[^"]*"' | head -1 | cut -d'"' -f4 | head -c 80)..."
                fi
                return 0
            fi
        fi
        log_fail "Should BLOCK with pack=$packs: $desc" "JSON with permissionDecision: deny" "${result:-<empty>}"
        return 1
    else
        # Expected: allow (empty output)
        if [[ -z "$result" ]]; then
            log_pass "ALLOWED (pack=$packs): $desc"
            return 0
        else
            log_fail "Should ALLOW with pack=$packs: $desc" "<empty output>" "$result"
            return 1
        fi
    fi
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
test_command "git branch -D feature" "block" "git branch -D feature"
test_command "git stash drop" "block" "git stash drop"
test_command "git stash drop stash@{0}" "block" "git stash drop stash@{0}"
test_command "git stash clear" "block" "git stash clear"

log_section "Destructive Filesystem Commands (should BLOCK)"

test_command "rm -rf /" "block" "rm -rf /"
test_command "rm -rf /etc" "block" "rm -rf /etc"
test_command "rm -rf /home" "block" "rm -rf /home"
test_command "rm -rf ~/" "block" "rm -rf ~/"
test_command "rm -rf ~/Documents" "block" "rm -rf ~/Documents"
test_command "rm -rf ./build" "block" "rm -rf ./build"
test_command "rm -rf node_modules" "block" "rm -rf node_modules"
test_command "rm -rf src" "block" "rm -rf src"
test_command "rm -fr /etc" "block" "rm -fr /etc"
test_command "rm -Rf /home" "block" "rm -Rf /home"
test_command "rm -r -f /etc" "block" "rm -r -f /etc"
test_command "rm -f -r /etc" "block" "rm -f -r /etc"
test_command "rm --recursive --force /etc" "block" "rm --recursive --force /etc"
test_command "rm --force --recursive /etc" "block" "rm --force --recursive /etc"

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

# PostgreSQL pack tests
test_command_with_packs "psql -c 'DROP DATABASE production;'" "block" "database.postgresql" "psql DROP DATABASE (postgresql pack enabled)"
test_command_with_packs "psql -c 'DELETE FROM users;'" "block" "database.postgresql" "psql DELETE without WHERE (postgresql pack enabled)"
test_command_with_packs "psql -c 'SELECT 1;'" "allow" "database.postgresql" "psql SELECT (postgresql pack enabled, safe command)"

# Redis pack tests
test_command_with_packs "redis-cli FLUSHALL" "block" "database.redis" "redis-cli FLUSHALL (redis pack enabled)"
test_command_with_packs "redis-cli GET key" "allow" "database.redis" "redis-cli GET (redis pack enabled, safe command)"

# Terraform pack tests
test_command_with_packs "terraform destroy" "block" "infrastructure.terraform" "terraform destroy (terraform pack enabled)"
test_command_with_packs "terraform plan" "allow" "infrastructure.terraform" "terraform plan (terraform pack enabled, safe command)"

# Multiple packs enabled simultaneously
test_command_with_packs "docker system prune" "block" "containers.docker,kubernetes.kubectl" "docker system prune (multiple packs enabled)"
test_command_with_packs "kubectl delete namespace foo" "block" "containers.docker,kubernetes.kubectl" "kubectl delete namespace (multiple packs enabled)"

# Verify commands WITHOUT their pack enabled are allowed (quick reject works)
test_command "docker system prune" "allow" "docker system prune (no docker pack, quick reject)"
test_command "kubectl delete namespace foo" "allow" "kubectl delete namespace (no kubectl pack, quick reject)"

#
# SUMMARY
#

echo ""
echo -e "${BOLD}${BLUE}=== Test Summary ===${NC}"
echo -e "Total:  ${TESTS_TOTAL}"
echo -e "${GREEN}Passed: ${TESTS_PASSED}${NC}"
if [[ $TESTS_FAILED -gt 0 ]]; then
    echo -e "${RED}Failed: ${TESTS_FAILED}${NC}"
    echo ""
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
else
    echo -e "Failed: 0"
    echo ""
    echo -e "${GREEN}${BOLD}All tests passed!${NC}"
    exit 0
fi

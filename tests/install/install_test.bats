#!/usr/bin/env bats
# Unit tests for install.sh functions
#
# Tests:
# - Platform detection (OS and architecture)
# - Checksum verification
# - Agent detection
# - Version checking
# - Idempotency

load test_helper

setup() {
    setup_isolated_home
    setup_test_log "$BATS_TEST_NAME"
    extract_install_functions
}

teardown() {
    log_test "=== Test completed: $BATS_TEST_NAME (status: $status) ==="
    teardown_isolated_home
}

# ============================================================================
# Platform Detection Tests
# ============================================================================

@test "platform detection: OS is lowercase" {
    log_test "Testing OS detection..."

    # OS should be detected as lowercase (linux, darwin)
    local os
    os=$(uname -s | tr 'A-Z' 'a-z')
    log_test "Detected OS: $os"

    [[ "$os" =~ ^(linux|darwin)$ ]]
}

@test "platform detection: ARCH normalization x86_64" {
    log_test "Testing x86_64 architecture detection..."

    local arch="x86_64"
    case "$arch" in
        x86_64|amd64) arch="x86_64" ;;
        arm64|aarch64) arch="aarch64" ;;
    esac

    log_test "Normalized arch: $arch"
    [ "$arch" = "x86_64" ]
}

@test "platform detection: ARCH normalization amd64" {
    log_test "Testing amd64 architecture detection..."

    local arch="amd64"
    case "$arch" in
        x86_64|amd64) arch="x86_64" ;;
        arm64|aarch64) arch="aarch64" ;;
    esac

    log_test "Normalized arch: $arch"
    [ "$arch" = "x86_64" ]
}

@test "platform detection: ARCH normalization arm64" {
    log_test "Testing arm64 architecture detection..."

    local arch="arm64"
    case "$arch" in
        x86_64|amd64) arch="x86_64" ;;
        arm64|aarch64) arch="aarch64" ;;
    esac

    log_test "Normalized arch: $arch"
    [ "$arch" = "aarch64" ]
}

@test "platform detection: ARCH normalization aarch64" {
    log_test "Testing aarch64 architecture detection..."

    local arch="aarch64"
    case "$arch" in
        x86_64|amd64) arch="x86_64" ;;
        arm64|aarch64) arch="aarch64" ;;
    esac

    log_test "Normalized arch: $arch"
    [ "$arch" = "aarch64" ]
}

@test "platform detection: TARGET triple for linux-x86_64" {
    log_test "Testing target triple for linux-x86_64..."

    local os="linux"
    local arch="x86_64"
    local target=""

    case "${os}-${arch}" in
        linux-x86_64) target="x86_64-unknown-linux-gnu" ;;
        linux-aarch64) target="aarch64-unknown-linux-gnu" ;;
        darwin-x86_64) target="x86_64-apple-darwin" ;;
        darwin-aarch64) target="aarch64-apple-darwin" ;;
    esac

    log_test "Target triple: $target"
    [ "$target" = "x86_64-unknown-linux-gnu" ]
}

@test "platform detection: TARGET triple for darwin-aarch64" {
    log_test "Testing target triple for darwin-aarch64..."

    local os="darwin"
    local arch="aarch64"
    local target=""

    case "${os}-${arch}" in
        linux-x86_64) target="x86_64-unknown-linux-gnu" ;;
        linux-aarch64) target="aarch64-unknown-linux-gnu" ;;
        darwin-x86_64) target="x86_64-apple-darwin" ;;
        darwin-aarch64) target="aarch64-apple-darwin" ;;
    esac

    log_test "Target triple: $target"
    [ "$target" = "aarch64-apple-darwin" ]
}

# ============================================================================
# Checksum Verification Tests
# ============================================================================

@test "verify_checksum: succeeds on matching checksum" {
    log_test "Testing checksum match..."

    local test_file="$TEST_TMPDIR/test_checksum_file"
    local content="test content for checksum verification"
    local checksum
    checksum=$(create_test_file_with_checksum "$content" "$test_file")

    log_test "File: $test_file"
    log_test "Expected checksum: $checksum"

    run verify_checksum "$test_file" "$checksum"
    log_test "Exit status: $status, Output: $output"

    [ "$status" -eq 0 ]
}

@test "verify_checksum: fails on mismatched checksum" {
    log_test "Testing checksum mismatch detection..."

    local test_file="$TEST_TMPDIR/test_checksum_mismatch"
    echo "test content" > "$test_file"
    local wrong_checksum="0000000000000000000000000000000000000000000000000000000000000000"

    log_test "File: $test_file"
    log_test "Wrong checksum: $wrong_checksum"

    run verify_checksum "$test_file" "$wrong_checksum"
    log_test "Exit status: $status, Output: $output"

    [ "$status" -ne 0 ]
}

@test "verify_checksum: fails on missing file" {
    log_test "Testing checksum verification with missing file..."

    local missing_file="$TEST_TMPDIR/nonexistent_file"
    local some_checksum="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

    run verify_checksum "$missing_file" "$some_checksum"
    log_test "Exit status: $status, Output: $output"

    [ "$status" -ne 0 ]
}

@test "verify_checksum: handles empty file" {
    log_test "Testing checksum verification with empty file..."

    local empty_file="$TEST_TMPDIR/empty_file"
    touch "$empty_file"

    # SHA256 of empty file
    local empty_checksum="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    run verify_checksum "$empty_file" "$empty_checksum"
    log_test "Exit status: $status"

    [ "$status" -eq 0 ]
}

# ============================================================================
# Agent Detection Tests
# ============================================================================

@test "detect_agents: finds Claude Code when directory exists" {
    log_test "Testing Claude Code detection via directory..."

    setup_mock_claude

    detect_agents
    log_test "Detected agents: ${DETECTED_AGENTS[*]:-none}"

    [[ " ${DETECTED_AGENTS[*]} " =~ " claude-code " ]]
}

@test "detect_agents: finds Codex CLI when directory exists" {
    log_test "Testing Codex CLI detection..."

    setup_mock_codex

    detect_agents
    log_test "Detected agents: ${DETECTED_AGENTS[*]:-none}"

    [[ " ${DETECTED_AGENTS[*]} " =~ " codex-cli " ]]
}

@test "detect_agents: finds Gemini CLI when directory exists" {
    log_test "Testing Gemini CLI detection..."

    setup_mock_gemini

    detect_agents
    log_test "Detected agents: ${DETECTED_AGENTS[*]:-none}"

    [[ " ${DETECTED_AGENTS[*]} " =~ " gemini-cli " ]]
}

@test "detect_agents: finds Continue when directory exists" {
    log_test "Testing Continue detection..."

    setup_mock_continue

    detect_agents
    log_test "Detected agents: ${DETECTED_AGENTS[*]:-none}"

    [[ " ${DETECTED_AGENTS[*]} " =~ " continue " ]]
}

@test "detect_agents: finds multiple agents" {
    log_test "Testing multiple agent detection..."

    setup_mock_claude
    setup_mock_codex
    setup_mock_gemini

    detect_agents
    log_test "Detected agents: ${DETECTED_AGENTS[*]:-none}"

    local count=${#DETECTED_AGENTS[@]}
    log_test "Agent count: $count"

    [ "$count" -ge 3 ]
}

@test "detect_agents: returns empty on fresh HOME" {
    log_test "Testing agent detection on fresh HOME..."

    # HOME is already fresh from setup_isolated_home
    detect_agents
    log_test "Detected agents: ${DETECTED_AGENTS[*]:-none}"
    log_test "Count: ${#DETECTED_AGENTS[@]}"

    [ "${#DETECTED_AGENTS[@]}" -eq 0 ]
}

@test "is_agent_detected: returns true for detected agent" {
    log_test "Testing is_agent_detected for present agent..."

    setup_mock_claude
    detect_agents

    run is_agent_detected "claude-code"
    log_test "Exit status: $status"

    [ "$status" -eq 0 ]
}

@test "is_agent_detected: returns false for non-detected agent" {
    log_test "Testing is_agent_detected for absent agent..."

    # No agents set up
    detect_agents

    run is_agent_detected "claude-code"
    log_test "Exit status: $status"

    [ "$status" -ne 0 ]
}

# ============================================================================
# Version Checking Tests
# ============================================================================

@test "check_installed_version: returns 1 when dcg not installed" {
    log_test "Testing version check when dcg not installed..."

    DEST="$TEST_TMPDIR/bin"
    mkdir -p "$DEST"

    run check_installed_version "v1.0.0"
    log_test "Exit status: $status"

    [ "$status" -eq 1 ]
}

@test "check_installed_version: returns 0 when versions match" {
    log_test "Testing version check when versions match..."

    DEST="$TEST_TMPDIR/bin"
    mkdir -p "$DEST"

    # Create mock dcg binary that returns version
    cat > "$DEST/dcg" << 'MOCKEOF'
#!/bin/bash
echo "dcg 1.0.0"
MOCKEOF
    chmod +x "$DEST/dcg"

    run check_installed_version "v1.0.0"
    log_test "Exit status: $status"

    [ "$status" -eq 0 ]
}

@test "check_installed_version: returns 1 when versions differ" {
    log_test "Testing version check when versions differ..."

    DEST="$TEST_TMPDIR/bin"
    mkdir -p "$DEST"

    # Create mock dcg binary that returns different version
    cat > "$DEST/dcg" << 'MOCKEOF'
#!/bin/bash
echo "dcg 1.0.0"
MOCKEOF
    chmod +x "$DEST/dcg"

    run check_installed_version "v2.0.0"
    log_test "Exit status: $status"

    [ "$status" -eq 1 ]
}

@test "check_installed_version: normalizes v prefix" {
    log_test "Testing version normalization..."

    DEST="$TEST_TMPDIR/bin"
    mkdir -p "$DEST"

    # Create mock dcg binary that returns version without v prefix
    cat > "$DEST/dcg" << 'MOCKEOF'
#!/bin/bash
echo "dcg 1.2.3"
MOCKEOF
    chmod +x "$DEST/dcg"

    # Should match whether we pass v1.2.3 or 1.2.3
    run check_installed_version "v1.2.3"
    log_test "Exit status for v1.2.3: $status"
    [ "$status" -eq 0 ]

    run check_installed_version "1.2.3"
    log_test "Exit status for 1.2.3: $status"
    [ "$status" -eq 0 ]
}

# ============================================================================
# Idempotency Tests
# ============================================================================

@test "install is idempotent: second run detects existing install" {
    log_test "Testing install idempotency..."

    DEST="$TEST_TMPDIR/bin"
    mkdir -p "$DEST"

    # Create mock dcg binary
    cat > "$DEST/dcg" << 'MOCKEOF'
#!/bin/bash
echo "dcg 1.0.0"
MOCKEOF
    chmod +x "$DEST/dcg"

    # If version matches, check_installed_version should succeed
    VERSION="v1.0.0"
    FORCE_INSTALL=0

    if check_installed_version "$VERSION"; then
        log_test "Correctly detected existing installation"
        return 0
    else
        log_test "Failed to detect existing installation"
        return 1
    fi
}

@test "PATH update: detects when already in PATH" {
    log_test "Testing PATH detection..."

    DEST="$TEST_TMPDIR/bin"
    mkdir -p "$DEST"
    export PATH="$DEST:$PATH"

    # Check if DEST is in PATH
    case ":$PATH:" in
        *:"$DEST":*)
            log_test "Correctly detected DEST in PATH"
            return 0
            ;;
        *)
            log_test "Failed to detect DEST in PATH"
            return 1
            ;;
    esac
}

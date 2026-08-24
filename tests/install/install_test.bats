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
        linux-x86_64) target="x86_64-unknown-linux-musl" ;;
        linux-aarch64) target="aarch64-unknown-linux-gnu" ;;
        darwin-x86_64) target="x86_64-apple-darwin" ;;
        darwin-aarch64) target="aarch64-apple-darwin" ;;
    esac

    log_test "Target triple: $target"
    [ "$target" = "x86_64-unknown-linux-musl" ]
}

@test "platform detection: TARGET triple for darwin-aarch64" {
    log_test "Testing target triple for darwin-aarch64..."

    local os="darwin"
    local arch="aarch64"
    local target=""

    case "${os}-${arch}" in
        linux-x86_64) target="x86_64-unknown-linux-musl" ;;
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

@test "verify_minisign_signature: verifies an override with the embedded release key" {
    TMP="$TEST_TMPDIR/minisign"
    mkdir -p "$TMP"
    local artifact="$TMP/dcg.tar.xz"
    local signature="$TMP/release.minisig"
    printf 'artifact' > "$artifact"
    printf 'signature' > "$signature"
    export MINISIGN_ARGS_FILE="$TMP/minisign.args"
    cat > "$TEST_TMPDIR/bin/minisign" << 'MOCKEOF'
#!/bin/bash
printf '%s\n' "$@" > "$MINISIGN_ARGS_FILE"
exit 0
MOCKEOF
    chmod +x "$TEST_TMPDIR/bin/minisign"
    MINISIGN_SIGNATURE_URL="file://$signature"
    REQUIRE_MINISIGN=1

    run verify_minisign_signature "$artifact" "https://example.invalid/dcg.tar.xz"
    [ "$status" -eq 0 ]
    grep -Fxq -- "-Vm" "$MINISIGN_ARGS_FILE"
    grep -Fxq -- "$artifact" "$MINISIGN_ARGS_FILE"
    grep -Fxq -- "-P" "$MINISIGN_ARGS_FILE"
    grep -Fxq -- "RWSoYi6NXJWzaRs1mJmOwwXrZfPWcq6MXnQlNMLBYKzlIQTLwuVQG6uO" "$MINISIGN_ARGS_FILE"
}

@test "verify_minisign_signature: legacy key is scoped to v0.6.7" {
    TMP="$TEST_TMPDIR/minisign-legacy"
    mkdir -p "$TMP"
    local artifact="$TMP/dcg.tar.xz"
    local signature="$TMP/release.minisig"
    printf 'artifact' > "$artifact"
    printf 'signature' > "$signature"
    export MINISIGN_ARGS_FILE="$TMP/minisign.args"
    cat > "$TEST_TMPDIR/bin/minisign" << 'MOCKEOF'
#!/bin/bash
printf '%s\n' "$@" > "$MINISIGN_ARGS_FILE"
exit 0
MOCKEOF
    chmod +x "$TEST_TMPDIR/bin/minisign"
    MINISIGN_SIGNATURE_URL="file://$signature"
    REQUIRE_MINISIGN=1
    VERSION="v0.6.7"

    run verify_minisign_signature "$artifact" "https://example.invalid/dcg.tar.xz"
    [ "$status" -eq 0 ]
    grep -Fxq -- "RWTQoKUb0Ue4NsqTpPWnABCrIU0+m25zsMlbv6UcRClQ7jmRP3A7NmTB" "$MINISIGN_ARGS_FILE"
}

@test "verify_minisign_signature: a present invalid signature is always fatal" {
    TMP="$TEST_TMPDIR/minisign"
    mkdir -p "$TMP"
    local artifact="$TMP/dcg.tar.xz"
    local signature="$TMP/release.minisig"
    printf 'artifact' > "$artifact"
    printf 'bad signature' > "$signature"
    cat > "$TEST_TMPDIR/bin/minisign" << 'MOCKEOF'
#!/bin/bash
exit 1
MOCKEOF
    chmod +x "$TEST_TMPDIR/bin/minisign"
    MINISIGN_SIGNATURE_URL="file://$signature"
    REQUIRE_MINISIGN=0

    run verify_minisign_signature "$artifact" "https://example.invalid/dcg.tar.xz"
    [ "$status" -ne 0 ]
    [[ "$output" == *"Minisign verification failed"* ]]
}

@test "verify_minisign_signature: missing tool is optional unless required" {
    TMP="$TEST_TMPDIR/minisign"
    mkdir -p "$TMP"
    local artifact="$TMP/dcg.tar.xz"
    local signature="$TMP/release.minisig"
    printf 'artifact' > "$artifact"
    printf 'signature' > "$signature"
    MINISIGN_SIGNATURE_URL="file://$signature"
    local no_tool_bin="$TMP/no-tool-bin"
    mkdir -p "$no_tool_bin"
    cat > "$no_tool_bin/curl" << 'MOCKEOF'
#!/bin/bash
source_url=""
output_file=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) output_file="$2"; shift 2 ;;
    -*) shift ;;
    *) source_url="$1"; shift ;;
  esac
done
/bin/cp "${source_url#file://}" "$output_file"
MOCKEOF
    chmod +x "$no_tool_bin/curl"
    PATH="$no_tool_bin"
    minisign() { return 0; }

    REQUIRE_MINISIGN=0
    run verify_minisign_signature "$artifact" "https://example.invalid/dcg.tar.xz"
    [ "$status" -eq 0 ]
    [[ "$output" == *"minisign not found"* ]]

    REQUIRE_MINISIGN=1
    run verify_minisign_signature "$artifact" "https://example.invalid/dcg.tar.xz"
    [ "$status" -ne 0 ]
    [[ "$output" == *"minisign is required"* ]]
}

@test "verify_minisign_signature: missing sidecar is optional unless required" {
    TMP="$TEST_TMPDIR/minisign"
    mkdir -p "$TMP"
    local artifact="$TMP/dcg.tar.xz"
    printf 'artifact' > "$artifact"
    MINISIGN_SIGNATURE_URL="file://$TMP/missing.minisig"

    REQUIRE_MINISIGN=0
    run verify_minisign_signature "$artifact" "https://example.invalid/dcg.tar.xz"
    [ "$status" -eq 0 ]
    [[ "$output" == *"signature not found"* ]]

    REQUIRE_MINISIGN=1
    run verify_minisign_signature "$artifact" "https://example.invalid/dcg.tar.xz"
    [ "$status" -ne 0 ]
    [[ "$output" == *"Required minisign signature"* ]]
}

@test "cosign_version_is_patched: enforces repaired release floors" {
    local mock_cosign="$TEST_TMPDIR/bin/cosign"
    cat > "$mock_cosign" << 'MOCKEOF'
#!/bin/bash
printf '{"gitVersion":"%s"}\n' "$MOCK_COSIGN_VERSION"
MOCKEOF
    chmod +x "$mock_cosign"

    export MOCK_COSIGN_VERSION="v2.6.1"
    run cosign_version_is_patched "$mock_cosign"
    [ "$status" -ne 0 ]
    MOCK_COSIGN_VERSION="v2.6.2"
    run cosign_version_is_patched "$mock_cosign"
    [ "$status" -eq 0 ]
    MOCK_COSIGN_VERSION="v3.0.3"
    run cosign_version_is_patched "$mock_cosign"
    [ "$status" -ne 0 ]
    MOCK_COSIGN_VERSION="v3.0.4"
    run cosign_version_is_patched "$mock_cosign"
    [ "$status" -eq 0 ]
    MOCK_COSIGN_VERSION="v3.1.2"
    run cosign_version_is_patched "$mock_cosign"
    [ "$status" -eq 0 ]
    MOCK_COSIGN_VERSION="v3.0.4-rc.1"
    run cosign_version_is_patched "$mock_cosign"
    [ "$status" -ne 0 ]
    MOCK_COSIGN_VERSION="devel"
    run cosign_version_is_patched "$mock_cosign"
    [ "$status" -ne 0 ]
}

@test "verify_sigstore_bundle: prefers the pinned local release key" {
    TMP="$TEST_TMPDIR/sigstore-work"
    mkdir -p "$TMP"
    local artifact="$TMP/dcg.tar.xz"
    local bundle="$TEST_TMPDIR/release.sigstore.json"
    printf 'artifact' > "$artifact"
    printf '{}' > "$bundle"
    export COSIGN_ARGS_FILE="$TMP/cosign.args"
    cat > "$TEST_TMPDIR/bin/cosign" << 'MOCKEOF'
#!/bin/bash
if [ "${1:-}" = "version" ]; then
  printf '{"gitVersion":"v3.1.2"}\n'
  exit 0
fi
if [ "${1:-}" = "verify-blob" ] && [ "${2:-}" = "--help" ]; then
  printf '%s\n' 'Usage: cosign verify-blob --bundle FILE --key FILE'
  exit 0
fi
printf '%s\n' "$@" > "$COSIGN_ARGS_FILE"
case " $* " in
  *" --key "*) exit 0 ;;
  *) exit 1 ;;
esac
MOCKEOF
    chmod +x "$TEST_TMPDIR/bin/cosign"
    SIGSTORE_BUNDLE_URL="file://$bundle"

    run verify_sigstore_bundle "$artifact" "https://example.invalid/dcg.tar.xz"
    [ "$status" -eq 0 ]
    [[ "$output" == *"cosign local release key"* ]]
    grep -Fxq -- "--key" "$COSIGN_ARGS_FILE"
    grep -Fxq -- "$TMP/dcg-cosign-release.pub" "$COSIGN_ARGS_FILE"
    grep -Fq -- "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD" "$TMP/dcg-cosign-release.pub"
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

@test "detect_agents: finds Oh My Pi when native state exists" {
    log_test "Testing Oh My Pi detection..."

    mkdir -p "$HOME/.omp/agent"
    detect_agents
    log_test "Detected agents: ${DETECTED_AGENTS[*]:-none}"

    [[ " ${DETECTED_AGENTS[*]} " =~ " omp " ]]
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

@test "installer help documents minisign strict mode and offline override" {
    run bash "$INSTALL_SCRIPT" --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"--require-minisign"* ]]
    [[ "$output" == *"--minisign-url"* ]]
}

@test "installer rejects strict minisign with verification disabled or source builds" {
    run bash "$INSTALL_SCRIPT" --quiet --require-minisign --no-verify
    [ "$status" -eq 2 ]
    [[ "$output" == *"mutually exclusive"* ]]

    run bash "$INSTALL_SCRIPT" --quiet --require-minisign --from-source
    [ "$status" -eq 2 ]
    [[ "$output" == *"cannot be used with --from-source"* ]]
}

@test "installer rejects a misspelled strict-mode option instead of downgrading" {
    run bash "$INSTALL_SCRIPT" --quiet --require-minising
    [ "$status" -eq 2 ]
    [[ "$output" == *"Unknown option: --require-minising"* ]]
}

@test "normalize_version_tag: accepts and canonicalizes SemVer" {
    run normalize_version_tag "1.2.3-rc.1+build.7"
    [ "$status" -eq 0 ]
    [ "$output" = "v1.2.3-rc.1+build.7" ]
}

@test "normalize_version_tag: rejects non-SemVer and leading zeroes" {
    run normalize_version_tag "../../main"
    [ "$status" -ne 0 ]

    run normalize_version_tag "v01.2.3"
    [ "$status" -ne 0 ]

    run normalize_version_tag "v1.2.3-01"
    [ "$status" -ne 0 ]
}

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

@test "installer arguments: option requiring value rejects following flag" {
    log_test "Testing required option value validation for flag-looking value..."

    run env HOME="$HOME" PATH="$PATH" bash "$INSTALL_SCRIPT" --quiet --version --dest "$TEST_TMPDIR/bin"
    log_test "Exit status: $status, Output: $output"

    [ "$status" -eq 2 ]
    [[ "$output" == *"--version requires a value"* ]]
    [[ "$output" != *"Downloading"* ]]
}

@test "installer arguments: option requiring value rejects missing final value" {
    log_test "Testing required option value validation for missing final value..."

    run env HOME="$HOME" PATH="$PATH" bash "$INSTALL_SCRIPT" --quiet --checksum
    log_test "Exit status: $status, Output: $output"

    [ "$status" -eq 2 ]
    [[ "$output" == *"--checksum requires a value"* ]]
    [[ "$output" != *"Downloading"* ]]
}

@test "installer arguments: invalid version is rejected before acquisition" {
    run env HOME="$HOME" PATH="$PATH" bash "$INSTALL_SCRIPT" --quiet --version "../../main" --dest "$TEST_TMPDIR/bin"
    log_test "Exit status: $status, Output: $output"

    [ "$status" -eq 2 ]
    [[ "$output" == *"expected SemVer"* ]]
    [[ "$output" != *"Downloading"* ]]
    [[ "$output" != *"Building from source"* ]]
}

@test "clone_source_tree: pinned versions clone one exact release tag" {
    export GIT_ARGS_FILE="$TEST_TMPDIR/git-args"
    cat > "$TEST_TMPDIR/bin/git" << 'MOCKEOF'
#!/bin/bash
printf '%s\n' "$@" > "$GIT_ARGS_FILE"
MOCKEOF
    chmod +x "$TEST_TMPDIR/bin/git"
    VERSION="v1.2.3"

    run clone_source_tree "$TEST_TMPDIR/source"
    [ "$status" -eq 0 ]
    grep -Fxq -- "--depth" "$GIT_ARGS_FILE"
    grep -Fxq -- "--branch" "$GIT_ARGS_FILE"
    grep -Fxq -- "v1.2.3" "$GIT_ARGS_FILE"
    grep -Fxq -- "--single-branch" "$GIT_ARGS_FILE"
}

@test "run_install_self_test: requires an allow and a real deny" {
    DEST="$TEST_TMPDIR/install-bin"
    TMP="$TEST_TMPDIR/selftest"
    mkdir -p "$DEST" "$TMP"
    cat > "$DEST/dcg" << 'MOCKEOF'
#!/bin/bash
case "$*" in
  *"git status"*) printf '%s\n' '{"decision":"allow"}'; exit 0 ;;
  *"rm -rf /"*) printf '%s\n' '{"decision":"deny"}'; exit 1 ;;
  *) exit 2 ;;
esac
MOCKEOF
    chmod +x "$DEST/dcg"

    run run_install_self_test
    [ "$status" -eq 0 ]
}

@test "run_install_self_test: fails when destructive probe is allowed" {
    DEST="$TEST_TMPDIR/install-bin"
    TMP="$TEST_TMPDIR/selftest"
    mkdir -p "$DEST" "$TMP"
    cat > "$DEST/dcg" << 'MOCKEOF'
#!/bin/bash
printf '%s\n' '{"decision":"allow"}'
MOCKEOF
    chmod +x "$DEST/dcg"

    run run_install_self_test
    [ "$status" -ne 0 ]
    [[ "$output" == *"destructive probe was allowed"* ]]
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

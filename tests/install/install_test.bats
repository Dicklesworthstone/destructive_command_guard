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
# Parsing
# ============================================================================

@test "install.sh parses under every bash on the host, including macOS /bin/bash 3.2" {
    # `curl … | bash` runs whichever bash is first on PATH; on stock macOS
    # that is /bin/bash 3.2, which rejects a `case` inside `$(...)` that bash
    # 5 accepts. A parse error there fails the whole install before it starts.
    local shells=() candidate
    for candidate in /bin/bash "$(command -v bash)"; do
        [ -x "$candidate" ] && shells+=("$candidate")
    done
    [ "${#shells[@]}" -gt 0 ] || skip "no bash executable found"
    for candidate in "${shells[@]}"; do
        run "$candidate" -n "$INSTALL_SCRIPT"
        [ "$status" -eq 0 ] || {
            echo "$candidate ($("$candidate" -c 'echo "$BASH_VERSION"')): $output"
            return 1
        }
        # uninstall.sh is piped to the same bash by its own one-liner.
        run "$candidate" -n "$UNINSTALL_SCRIPT"
        [ "$status" -eq 0 ] || {
            echo "$candidate uninstall.sh: $output"
            return 1
        }
    done
}

# Feed a script on stdin to a shell, the way `curl ... | <shell>` does. Every
# destination is pinned under the test's temp dir and only `--help` is asked
# for, so even a broken guard cannot install anything.
run_piped_script() {
    local shell_cmd="$1" script="$2"
    # shellcheck disable=SC2086 # "bash --posix" must split into two words
    run env -i HOME="$HOME" PATH=/usr/bin:/bin DEST="$TEST_TMPDIR/dest" \
        VERSION=v0.0.0-test $shell_cmd -s -- --help < "$script"
}

@test "install.sh and uninstall.sh piped to a non-bash shell stop with a clear message (#587)" {
    local shells=() candidate script
    for candidate in dash zsh ksh mksh posh; do
        command -v "$candidate" >/dev/null 2>&1 && shells+=("$(command -v "$candidate")")
    done
    [ "${#shells[@]}" -gt 0 ] || skip "no non-bash shell installed"
    for candidate in "${shells[@]}"; do
        for script in "$INSTALL_SCRIPT" "$UNINSTALL_SCRIPT"; do
            run_piped_script "$candidate" "$script"
            [ "$status" -eq 1 ] || {
                echo "$candidate $(basename "$script"): status $status: $output"
                return 1
            }
            [[ "$output" == *"this script needs bash"* ]] || {
                echo "$candidate $(basename "$script"): $output"
                return 1
            }
        done
    done
    [ ! -e "$TEST_TMPDIR/dest" ]
}

@test "install.sh run by bash in POSIX mode (curl ... | sh where sh is bash) still runs (#587)" {
    # POSIX-mode bash rejects process substitution, which install.sh uses, so
    # the script must leave POSIX mode before reaching it.
    run_piped_script "bash --posix" "$INSTALL_SCRIPT"
    [ "$status" -eq 0 ] || {
        echo "status $status: $output"
        return 1
    }
    [[ "$output" == *"Usage: install.sh"* ]]
    if [ -x /bin/bash ]; then
        run_piped_script "/bin/bash --posix" "$INSTALL_SCRIPT"
        [ "$status" -eq 0 ] || {
            echo "/bin/bash --posix: status $status: $output"
            return 1
        }
    fi
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

    # version|expected status (0 = patched)
    local cases=(
        "v2.6.1|1"
        "v2.6.2|0"
        "v3.0.3|1"
        "v3.0.4|0"
        "v3.1.2|0"
        "v3.0.4-rc.1|1"
        "v2.6.2-rc.1|1"
        "devel|1"
        "v3.1.3+dirty|0"
        "v3.0.4+dirty|0"
        "v3.0.3+dirty|1"
        "3.1.3|0"
        "v3.1.3-dirty|0"
        "v3.0.4-dirty|1"
        "v3.0.4-3-gabc1234|1"
        "v3.1.0-rc.1+build.5|0"
        "v2.6.10|0"
        "v2.08.0|0"
        "v4.0.0-rc.1|0"
        "v1.13.9|1"
        "v3.1|1"
        "v3.1.3 junk|1"
        "|1"
    )
    local entry version expected
    for entry in "${cases[@]}"; do
        version="${entry%|*}"
        expected="${entry##*|}"
        export MOCK_COSIGN_VERSION="$version"
        run cosign_version_is_patched "$mock_cosign"
        if [ "$expected" -eq 0 ]; then
            [ "$status" -eq 0 ] || { echo "expected '$version' to count as patched"; return 1; }
        else
            [ "$status" -ne 0 ] || { echo "expected '$version' to be rejected"; return 1; }
        fi
    done
}

@test "cosign_version_is_patched: reads pretty JSON and the plain-text GitVersion line (GH #505)" {
    local mock_cosign="$TEST_TMPDIR/bin/cosign"
    cat > "$mock_cosign" << 'MOCKEOF'
#!/bin/bash
if [ "${2:-}" = "--json" ]; then
  [ "$MOCK_COSIGN_JSON" = 0 ] && exit 1
  printf '{\n  "gitVersion": "%s",\n  "gitTreeState": "dirty"\n}\n' "$MOCK_COSIGN_VERSION"
  exit 0
fi
printf '  ______\nGitVersion:    %s\nGitCommit:     11926fa\n' "$MOCK_COSIGN_VERSION"
MOCKEOF
    chmod +x "$mock_cosign"

    export MOCK_COSIGN_VERSION="v3.1.3+dirty"
    export MOCK_COSIGN_JSON=1
    run cosign_version_is_patched "$mock_cosign"
    [ "$status" -eq 0 ]
    MOCK_COSIGN_JSON=0
    run cosign_version_is_patched "$mock_cosign"
    [ "$status" -eq 0 ]
    MOCK_COSIGN_VERSION="v3.0.3+dirty"
    run cosign_version_is_patched "$mock_cosign"
    [ "$status" -ne 0 ]
}

@test "verify_sigstore_bundle: a distro cosign build verifies instead of being skipped (GH #505)" {
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
  printf '{"gitVersion":"%s"}\n' "$MOCK_COSIGN_VERSION"
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

    export MOCK_COSIGN_VERSION="v3.1.3+dirty"
    run verify_sigstore_bundle "$artifact" "https://example.invalid/dcg.tar.xz"
    [ "$status" -eq 0 ]
    [[ "$output" == *"cosign local release key"* ]]
    grep -Fxq -- "--key" "$COSIGN_ARGS_FILE"

    rm -f "$COSIGN_ARGS_FILE"
    MOCK_COSIGN_VERSION="v3.0.3+dirty"
    run verify_sigstore_bundle "$artifact" "https://example.invalid/dcg.tar.xz"
    [ "$status" -eq 0 ]
    [[ "$output" == *"cosign reports version 'v3.0.3+dirty'"* ]]
    [ ! -e "$COSIGN_ARGS_FILE" ]
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

@test "Claude settings resolver: default, empty, absolute, relative, tilde and literal path values" {
    unset CLAUDE_CONFIG_DIR
    [ "$(claude_config_dir)" = "$HOME/.claude" ]
    export CLAUDE_CONFIG_DIR=""
    [ "$(claude_config_dir)" = "$HOME/.claude" ]

    export CLAUDE_CONFIG_DIR="$TEST_TMPDIR/active Claude"
    [ "$(claude_config_dir)" = "$TEST_TMPDIR/active Claude" ]
    export CLAUDE_CONFIG_DIR="relative Claude/../active"
    [ "$(claude_config_dir)" = "$PWD/relative Claude/../active" ]
    export CLAUDE_CONFIG_DIR='~/active Claude'
    [ "$(claude_config_dir)" = "$HOME/active Claude" ]
    export CLAUDE_CONFIG_DIR='~'
    [ "$(claude_config_dir)" = "$HOME" ]

    export CLAUDE_CONFIG_DIR='~someone/$HOME/$(touch should-not-execute)'
    [ "$(claude_config_dir)" = "$PWD/~someone/\$HOME/\$(touch should-not-execute)" ]
    [ ! -e "$PWD/should-not-execute" ]
    export CLAUDE_CONFIG_DIR=$'active\n'
    # Keep the helper's terminating newline distinct from the literal path.
    local resolved
    resolved="$(claude_config_dir; printf .)"
    [ "${resolved%$'\n.'}" = "$PWD/"$'active\n' ]
}

@test "detect_agents: explicit CLAUDE_CONFIG_DIR detects Claude before its directory exists" {
    setup_mock_codex
    export CLAUDE_CONFIG_DIR="$TEST_TMPDIR/active Claude"
    detect_agents
    [[ " ${DETECTED_AGENTS[*]} " =~ " claude-code " ]]
    [[ " ${DETECTED_AGENTS[*]} " =~ " codex-cli " ]]
    [ ! -e "$CLAUDE_CONFIG_DIR" ]

    mkdir -p "$CLAUDE_CONFIG_DIR"
    detect_agents
    [[ " ${DETECTED_AGENTS[*]} " =~ " claude-code " ]]
}

@test "shell startup check: resolves active Claude directory each time and warns when missing" {
    command -v jq >/dev/null || skip "jq not available"
    cat > "$TEST_TMPDIR/bin/dcg" <<'EOF'
#!/bin/bash
exit 0
EOF
    chmod +x "$TEST_TMPDIR/bin/dcg"
    mkdir -p "$HOME/.claude" "$HOME/active Claude"
    printf '%s\n' '{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"dcg"}]}]}}' > "$HOME/.claude/settings.json"
    printf '{}\n' > "$HOME/active Claude/settings.json"

    maybe_add_shell_check
    run bash --noprofile --norc -c 'source "$HOME/.bashrc"'
    [ "$status" -eq 0 ]
    [ -z "$output" ]

    export CLAUDE_CONFIG_DIR='~/active Claude'
    run bash --noprofile --norc -c 'source "$HOME/.bashrc"'
    [ "$status" -eq 0 ]
    [[ "$output" == *"Hook missing from $HOME/active Claude/settings.json"* ]]

    export CLAUDE_CONFIG_DIR='missing Claude'
    run bash --noprofile --norc -c 'source "$HOME/.bashrc"'
    [ "$status" -eq 0 ]
    [[ "$output" == *"Hook missing from $PWD/missing Claude/settings.json"* ]]

    export CLAUDE_CONFIG_DIR=""
    run bash --noprofile --norc -c 'source "$HOME/.bashrc"'
    [ "$status" -eq 0 ]
    [ -z "$output" ]

    mv "$HOME/.claude/settings.json" "$TEST_TMPDIR/protected-default.json"
    unset CLAUDE_CONFIG_DIR
    run bash --noprofile --norc -c 'source "$HOME/.bashrc"'
    [ "$status" -eq 0 ]
    [ -z "$output" ]
    export CLAUDE_CONFIG_DIR=""
    run bash --noprofile --norc -c 'source "$HOME/.bashrc"'
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

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

@test "detect_agents: ignores stale Oh My Pi native state without an executable" {
    log_test "Testing stale Oh My Pi native state..."

    mkdir -p "$HOME/.omp/agent"
    detect_agents
    log_test "Detected agents: ${DETECTED_AGENTS[*]:-none}"

    [[ ! " ${DETECTED_AGENTS[*]} " =~ " omp " ]]
}

@test "detect_agents: ignores stale Oh My Pi path and profile selectors" {
    log_test "Testing stale Oh My Pi selectors..."

    export PI_CONFIG_DIR=".custom-omp"
    mkdir -p "$HOME/.custom-omp/agent"
    export PI_CODING_AGENT_DIR="$HOME/.custom-agent"
    mkdir -p "$PI_CODING_AGENT_DIR"
    export OMP_PROFILE="work"
    export PI_PROFILE="legacy"
    detect_agents

    [[ ! " ${DETECTED_AGENTS[*]} " =~ " omp " ]]
}

@test "detect_agents: ignores a non-executable omp PATH candidate" {
    log_test "Testing a non-executable Oh My Pi PATH candidate..."

    printf '#!/usr/bin/env bash\nprintf "not executable\\n"\n' > "$TEST_TMPDIR/bin/omp"
    detect_agents

    [[ ! " ${DETECTED_AGENTS[*]} " =~ " omp " ]]
}

@test "detect_agents: ignores an omp shell function without an external executable" {
    log_test "Testing an Oh My Pi function-only shadow..."

    omp() { printf 'function-shadow\n'; }
    detect_agents

    [[ ! " ${DETECTED_AGENTS[*]} " =~ " omp " ]]
}

@test "detect_agents: resolves the external omp executable behind a function" {
    log_test "Testing exact external Oh My Pi executable resolution..."

    cat > "$TEST_TMPDIR/bin/omp" << 'EOF'
#!/usr/bin/env bash
printf 'omp/external-1.2.3\n'
EOF
    chmod +x "$TEST_TMPDIR/bin/omp"
    omp() { printf 'function-shadow\n'; }
    type() { printf '/definitely/not/omp\n'; }
    AGENT_VERSION_LOOKUP=1
    detect_agents

    [[ " ${DETECTED_AGENTS[*]} " =~ " omp " ]]
    [ "$OMP_VERSION" = "omp/external-1.2.3" ]
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
# Binary replacement (bd-0zx5)
# ============================================================================

# A mock dcg of about 4 MiB. The padding after `exit` is never read by sh, but
# it makes the copy long enough that an unlink-then-copy leaves a window a
# concurrent exec can land in.
write_padded_mock_dcg() {
    local path="$1" version="$2"
    {
        printf '#!/bin/sh\necho "dcg %s"\nexit 0\n' "$version"
        head -c 4194304 /dev/zero | tr '\0' '#'
        printf '\n'
    } > "$path"
    chmod 0755 "$path"
}

@test "install_binary_atomically: a dcg exec'd during replacement is never missing or partial" {
    DEST="$TEST_TMPDIR/live-bin"
    mkdir -p "$DEST"
    write_padded_mock_dcg "$TEST_TMPDIR/dcg-a" 1.0.0
    write_padded_mock_dcg "$TEST_TMPDIR/dcg-b" 2.0.0
    cp "$TEST_TMPDIR/dcg-a" "$DEST/dcg"

    local failures="$TEST_TMPDIR/exec-failures"
    local stop="$TEST_TMPDIR/stop-reader"
    : > "$failures"
    # The hook's view: exec the installed path over and over while it is
    # replaced. A missing file, a file without its mode yet, or an empty one
    # all show up as a failed exec or a wrong version line.
    (
        while [ ! -e "$stop" ]; do
            if ! out=$("$DEST/dcg" --version 2>&1); then
                printf 'exec failed: %s\n' "$out" >> "$failures"
            fi
            case "$out" in
                "dcg 1.0.0" | "dcg 2.0.0") ;;
                *) printf 'unexpected output: %s\n' "$out" >> "$failures" ;;
            esac
        done
    ) &
    local reader=$!
    local round
    for round in $(seq 1 40); do
        install_binary_atomically "$TEST_TMPDIR/dcg-b"
        install_binary_atomically "$TEST_TMPDIR/dcg-a"
    done
    touch "$stop"
    wait "$reader"

    if [ -s "$failures" ]; then
        sort "$failures" | uniq -c
        false
    fi
    [ "$("$DEST/dcg" --version)" = "dcg 1.0.0" ]
    [[ "$(ls -l "$DEST/dcg")" == -rwxr-xr-x* ]]
    # No staged copy is left behind.
    [ -z "$(find "$DEST" -name '.dcg.*')" ]
}

@test "install_binary_atomically: a new binary that cannot run leaves the installed one in place" {
    DEST="$TEST_TMPDIR/live-bin"
    mkdir -p "$DEST"
    write_padded_mock_dcg "$DEST/dcg" 1.0.0
    printf '#!/bin/sh\nexit 3\n' > "$TEST_TMPDIR/broken-dcg"

    run install_binary_atomically "$TEST_TMPDIR/broken-dcg"
    [ "$status" -ne 0 ]
    [[ "$output" == *"was not replaced"* ]]
    [ "$("$DEST/dcg" --version)" = "dcg 1.0.0" ]
    [ -z "$(find "$DEST" -name '.dcg.*')" ]
}

# Qualification must finish before the one rename that publishes a candidate.
# These are local classifier fixtures: the destructive strings are arguments
# to `test`, never shell commands that this suite executes.
write_transaction_dcg() {
    local path="$1" version="$2" behavior="$3" record="${4:-1}"
    if [ "$behavior" = launch-failure ]; then
        printf '#!/no/such/dcg-test-interpreter\n' > "$path"
    else
        {
            printf '#!/bin/sh\nreported_version=%s\nbehavior=%s\nrecord=%s\n' \
                "$version" "$behavior" "$record"
            cat <<'MOCKEOF'
if [ "$record" = 1 ] && [ -n "${DCG_TEST_TRANSACTION_EVENTS:-}" ]; then
    printf 'candidate|%s|%s\n' "$0" "$*" >> "$DCG_TEST_TRANSACTION_EVENTS"
fi
case "$*" in
    --version)
        case "$behavior" in
            wrong-version) printf 'dcg 9.9.9\n' ;;
            malformed-version) printf 'not a dcg version\n' ;;
            version-failure) printf 'dcg %s\n' "$reported_version"; exit 7 ;;
            stderr-version) printf 'dcg %s\n' "$reported_version" >&2 ;;
            *) printf 'dcg %s\n' "$reported_version" ;;
        esac
        ;;
    'test --format json git status')
        case "$behavior" in
            safe-failure) printf '{"decision":"allow"}\n'; exit 2 ;;
            safe-malformed) printf 'not a decision\n' ;;
            *) printf '{"decision":"allow"}\n' ;;
        esac
        ;;
    'test --format json rm -rf /')
        case "$behavior" in
            deny-allowed) printf '{"decision":"allow"}\n'; exit 0 ;;
            deny-failure) printf '{"decision":"deny"}\n'; exit 2 ;;
            deny-malformed) printf 'not a decision\n'; exit 1 ;;
            *) printf '{"decision":"deny"}\n'; exit 1 ;;
        esac
        ;;
    *) exit 2 ;;
esac
MOCKEOF
        } > "$path"
    fi
    chmod 0755 "$path"
}

setup_install_transaction() {
    DEST="$TEST_TMPDIR/live bin"
    TMP="$TEST_TMPDIR/self test"
    TRANSACTION_SOURCE="$TEST_TMPDIR/payload/dcg"
    mkdir -p "$DEST" "$TMP" "$(dirname "$TRANSACTION_SOURCE")"
    write_transaction_dcg "$DEST/dcg" 1.0.0 good 0
    chmod 0751 "$DEST/dcg"
    cp "$DEST/dcg" "$TEST_TMPDIR/incumbent-dcg"
    export DCG_TEST_TRANSACTION_EVENTS="$TEST_TMPDIR/transaction-events"
}

assert_incumbent_preserved() {
    cmp -s "$TEST_TMPDIR/incumbent-dcg" "$DEST/dcg"
    [[ "$(ls -l "$DEST/dcg")" == -rwxr-x--x* ]]
    [ -z "$(find "$DEST" -name '.dcg.*')" ]
}

@test "install_binary_atomically: rejects wrong, malformed, failed, and unlaunchable versions before promotion" {
    setup_install_transaction
    local behavior
    for behavior in wrong-version malformed-version version-failure launch-failure; do
        write_transaction_dcg "$TRANSACTION_SOURCE" 2.0.0 "$behavior"
        run install_binary_atomically "$TRANSACTION_SOURCE" v2.0.0 0
        [ "$status" -ne 0 ] || { echo "$behavior was accepted"; return 1; }
        [[ "$output" == *"was not replaced"* ]]
        assert_incumbent_preserved
    done
}

@test "install_binary_atomically: every failed self-test keeps the incumbent bytes and mode" {
    setup_install_transaction
    local behavior
    for behavior in safe-failure safe-malformed deny-allowed deny-failure deny-malformed; do
        write_transaction_dcg "$TRANSACTION_SOURCE" 2.0.0 "$behavior"
        run install_binary_atomically "$TRANSACTION_SOURCE" v2.0.0 1
        [ "$status" -ne 0 ] || { echo "$behavior was accepted"; return 1; }
        [[ "$output" == *"failed its self-test"* ]]
        assert_incumbent_preserved
    done
}

fail_transaction_operation() (
    case "$1" in
        mktemp) mktemp() { return 71; } ;;
        cp) cp() { return 72; } ;;
        chmod) chmod() { return 73; } ;;
        mv) mv() { return 74; } ;;
        *) return 2 ;;
    esac
    install_binary_atomically "$TRANSACTION_SOURCE" v2.0.0 1
)

@test "install_binary_atomically: staging and promotion failures preserve the live executable" {
    setup_install_transaction
    write_transaction_dcg "$TRANSACTION_SOURCE" 2.0.0 good
    local operation
    for operation in mktemp cp chmod mv; do
        run fail_transaction_operation "$operation"
        [ "$status" -ne 0 ] || { echo "$operation failure was ignored"; return 1; }
        assert_incumbent_preserved
    done
}

@test "install_binary_atomically: only a fully qualified staged candidate replaces the incumbent" {
    setup_install_transaction
    write_transaction_dcg "$TRANSACTION_SOURCE" 2.0.0 good
    run install_binary_atomically "$TRANSACTION_SOURCE" v2.0.0 1
    [ "$status" -eq 0 ]
    cmp -s "$TRANSACTION_SOURCE" "$DEST/dcg"
    [[ "$(ls -l "$DEST/dcg")" == -rwxr-xr-x* ]]
    [ "$(wc -l < "$DCG_TEST_TRANSACTION_EVENTS" | tr -d ' ')" -eq 3 ]
    local event path arguments
    while IFS='|' read -r event path arguments; do
        [ "$event" = candidate ]
        [[ "$path" == "$DEST"/.dcg.* ]]
    done < "$DCG_TEST_TRANSACTION_EVENTS"
    [ -z "$(find "$DEST" -name '.dcg.*')" ]
}

@test "install_binary_atomically: accepts stderr versions and relative destinations with spaces" {
    setup_install_transaction
    DEST='relative live bin'
    mkdir -p "$DEST"
    write_transaction_dcg "$TRANSACTION_SOURCE" 2.0.0 stderr-version
    run install_binary_atomically "$TRANSACTION_SOURCE" v2.0.0 1
    [ "$status" -eq 0 ]
    cmp -s "$TRANSACTION_SOURCE" "$DEST/dcg"
    [ -z "$(find "$DEST" -name '.dcg.*')" ]
}

@test "install_binary_atomically: rejected fresh installs publish no executable" {
    setup_install_transaction
    DEST="$TEST_TMPDIR/fresh bin"
    mkdir -p "$DEST"
    write_transaction_dcg "$TRANSACTION_SOURCE" 2.0.0 deny-allowed
    run install_binary_atomically "$TRANSACTION_SOURCE" v2.0.0 1
    [ "$status" -ne 0 ]
    [ ! -e "$DEST/dcg" ]
    [ -z "$(find "$DEST" -name '.dcg.*')" ]

    write_transaction_dcg "$TRANSACTION_SOURCE" 2.0.0 good
    run install_binary_atomically "$TRANSACTION_SOURCE" v2.0.0 1
    [ "$status" -eq 0 ]
    cmp -s "$TRANSACTION_SOURCE" "$DEST/dcg"
}

@test "install_binary_atomically: directory destinations cannot turn promotion into a nested move" {
    setup_install_transaction
    write_transaction_dcg "$TRANSACTION_SOURCE" 2.0.0 good
    local kind
    for kind in directory symlink; do
        DEST="$TEST_TMPDIR/$kind bin"
        mkdir -p "$DEST" "$TEST_TMPDIR/$kind target"
        if [ "$kind" = directory ]; then
            mkdir "$DEST/dcg"
        else
            ln -s "$TEST_TMPDIR/$kind target" "$DEST/dcg"
        fi
        run install_binary_atomically "$TRANSACTION_SOURCE" v2.0.0 1
        [ "$status" -ne 0 ]
        [ -d "$DEST/dcg" ]
        [ -z "$(find "$DEST" "$TEST_TMPDIR/$kind target" -name '.dcg.*')" ]
    done
}

prepare_transaction_release() {
    TRANSACTION_ARCHIVE="$TEST_TMPDIR/candidate.tar.gz"
    tar -czf "$TRANSACTION_ARCHIVE" -C "$(dirname "$TRANSACTION_SOURCE")" dcg
    if command -v sha256sum >/dev/null 2>&1; then
        TRANSACTION_CHECKSUM=$(sha256sum "$TRANSACTION_ARCHIVE" | cut -d' ' -f1)
    else
        TRANSACTION_CHECKSUM=$(shasum -a 256 "$TRANSACTION_ARCHIVE" | cut -d' ' -f1)
    fi
    printf 'local verifier fixture, not a release signature\n' > "$TEST_TMPDIR/candidate.minisig"
    # The transaction tests mock the verifier, not the hash or installation
    # pipeline. Real release signatures have independent qualification tests.
    cat > "$TEST_TMPDIR/bin/minisign" <<'MOCKEOF'
#!/bin/sh
printf 'signature\n' >> "$DCG_TEST_TRANSACTION_EVENTS"
exit "${DCG_TEST_SIGNATURE_STATUS:-0}"
MOCKEOF
    chmod +x "$TEST_TMPDIR/bin/minisign"
}

run_transaction_release_installer() {
    run env DCG_SELF_HEAL_HOOK=0 bash "$INSTALL_SCRIPT" \
        --quiet --offline --no-gum --no-configure --force --verify \
        --require-minisign --version v2.0.0 --dest "$DEST" \
        --artifact-url "file://$TRANSACTION_ARCHIVE" \
        --checksum "$TRANSACTION_CHECKSUM" \
        --minisign-url "file://$TEST_TMPDIR/candidate.minisig" "$@"
}

prepare_transaction_source_build() {
    export MOCK_TRANSACTION_SOURCE="$TRANSACTION_SOURCE"
    cat > "$TEST_TMPDIR/bin/git" <<'MOCKEOF'
#!/bin/sh
[ "$1" = clone ] || exit 91
for destination in "$@"; do :; done
mkdir -p "$destination"
MOCKEOF
    cat > "$TEST_TMPDIR/bin/cargo" <<'MOCKEOF'
#!/bin/sh
[ "$*" = 'build --release' ] || exit 92
mkdir -p target/release
cp "$MOCK_TRANSACTION_SOURCE" target/release/dcg
MOCKEOF
    chmod +x "$TEST_TMPDIR/bin/git" "$TEST_TMPDIR/bin/cargo"
}

@test "installer: release and source version or self-test rejection preserves the previous guard" {
    setup_install_transaction
    prepare_transaction_source_build
    local acquisition behavior
    for acquisition in release source; do
        for behavior in wrong-version deny-allowed; do
            write_transaction_dcg "$TRANSACTION_SOURCE" 2.0.0 "$behavior"
            if [ "$acquisition" = release ]; then
                prepare_transaction_release
                run_transaction_release_installer
            else
                run env DCG_SELF_HEAL_HOOK=0 RUSTUP_INIT_SKIP=1 bash "$INSTALL_SCRIPT" \
                    --quiet --offline --no-gum --no-configure --force --verify \
                    --from-source --version v2.0.0 --dest "$DEST"
            fi
            [ "$status" -ne 0 ] || { echo "$acquisition accepted $behavior"; return 1; }
            assert_incumbent_preserved
            [[ "$output" == *"was not replaced"* ]]
        done
    done
}

@test "installer: authentication precedes staged qualification and successful promotion" {
    setup_install_transaction
    write_transaction_dcg "$TRANSACTION_SOURCE" 2.0.0 good
    prepare_transaction_release
    run_transaction_release_installer
    [ "$status" -eq 0 ]
    cmp -s "$TRANSACTION_SOURCE" "$DEST/dcg"
    [ "$(head -1 "$DCG_TEST_TRANSACTION_EVENTS")" = signature ]
    [ "$(grep -c '^candidate|' "$DCG_TEST_TRANSACTION_EVENTS")" -eq 3 ]
    local event path arguments
    while IFS='|' read -r event path arguments; do
        [ "$event" != candidate ] || [[ "$path" == "$DEST"/.dcg.* ]]
    done < "$DCG_TEST_TRANSACTION_EVENTS"
    [ -z "$(find "$DEST" -name '.dcg.*')" ]
}

@test "installer: checksum and signature failures never execute a candidate or alter the incumbent" {
    setup_install_transaction
    write_transaction_dcg "$TRANSACTION_SOURCE" 2.0.0 good
    prepare_transaction_release
    run_transaction_release_installer --checksum "$(printf '%064d' 0)"
    [ "$status" -ne 0 ]
    [ ! -e "$DCG_TEST_TRANSACTION_EVENTS" ]
    assert_incumbent_preserved

    export DCG_TEST_SIGNATURE_STATUS=1
    run_transaction_release_installer
    [ "$status" -ne 0 ]
    [ "$(cat "$DCG_TEST_TRANSACTION_EVENTS")" = signature ]
    assert_incumbent_preserved
}

@test "installer: --verify also qualifies an existing same-version installation" {
    setup_install_transaction
    local behavior expected
    for behavior in good deny-allowed; do
        write_transaction_dcg "$DEST/dcg" 2.0.0 "$behavior" 0
        chmod 0751 "$DEST/dcg"
        cp "$DEST/dcg" "$TEST_TMPDIR/incumbent-dcg"
        expected=0
        [ "$behavior" != deny-allowed ] || expected=1
        run env DCG_SELF_HEAL_HOOK=0 bash "$INSTALL_SCRIPT" \
            --quiet --offline --no-gum --no-configure --verify \
            --version v2.0.0 --dest "$DEST" \
            --artifact-url "file://$TEST_TMPDIR/must-not-download"
        [ "$status" -eq "$expected" ]
        assert_incumbent_preserved
    done
}

# ============================================================================
# Shell completions (bd-qny3)
# ============================================================================

# A dcg whose `completions <shell>` output is one marked line.
write_completing_mock_dcg() {
    cat > "$1" <<'MOCKEOF'
#!/bin/sh
case "$1" in
    --version) echo "dcg 1.0.0" ;;
    completions)
        [ "$2" = "--help" ] && exit 0
        echo "#compdef dcg (generated for $2)" ;;
esac
MOCKEOF
    chmod 0755 "$1"
}

setup_zsh_completion_fixture() {
    DEST="$TEST_TMPDIR/completion-bin"
    mkdir -p "$DEST"
    write_completing_mock_dcg "$DEST/dcg"
    export SHELL=/bin/zsh
    export XDG_DATA_HOME="$HOME/.local/share"
    ZSH_COMPLETIONS="$XDG_DATA_HOME/zsh/site-functions"
    mkdir -p "$ZSH_COMPLETIONS"
    printf '#compdef dcg (user edited)\n' > "$ZSH_COMPLETIONS/_dcg"
    QUIET=0
}

@test "completions: --no-configure leaves the completion directories unchanged" {
    setup_zsh_completion_fixture
    NO_CONFIGURE=1

    run maybe_install_completions
    [ "$status" -eq 0 ]
    [[ "$output" == *"Shell completions: skipped (--no-configure)"* ]]
    [ "$(cat "$ZSH_COMPLETIONS/_dcg")" = "#compdef dcg (user edited)" ]
    [ "$(ls -A "$ZSH_COMPLETIONS")" = "_dcg" ]
}

@test "completions: replacing a different file keeps a backup that compinit does not load" {
    setup_zsh_completion_fixture
    NO_CONFIGURE=0

    run maybe_install_completions
    [ "$status" -eq 0 ]
    [ "$(cat "$ZSH_COMPLETIONS/_dcg")" = "#compdef dcg (generated for zsh)" ]
    local backups=("$ZSH_COMPLETIONS"/._dcg.bak.*)
    [ "${#backups[@]}" -eq 1 ]
    [ "$(cat "${backups[0]}")" = "#compdef dcg (user edited)" ]
    # compinit autoloads every `_*` file on fpath; `_dcg` must stay the only one.
    [ "$(cd "$ZSH_COMPLETIONS" && printf '%s\n' _*)" = "_dcg" ]

    # The same content again: nothing is rewritten and no second backup appears.
    run maybe_install_completions
    [ "$status" -eq 0 ]
    [[ "$output" == *"are current"* ]]
    [ "$(ls -A "$ZSH_COMPLETIONS" | wc -l | tr -d ' ')" -eq 2 ]
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

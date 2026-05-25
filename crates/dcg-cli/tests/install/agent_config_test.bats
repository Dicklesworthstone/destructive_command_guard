#!/usr/bin/env bats
# Unit tests for agent configuration functions in install.sh
#
# Tests:
# - Claude Code configuration (configure_claude_code)
# - Gemini CLI configuration (configure_gemini)
# - Configuration idempotency
# - Existing settings preservation

load test_helper

setup() {
    setup_isolated_home
    setup_test_log "$BATS_TEST_NAME"
    extract_install_functions
    extract_uninstall_functions

    # Set default DEST for configuration
    DEST="$TEST_TMPDIR/bin"
    mkdir -p "$DEST"

    # Create mock dcg binary for path references
    cat > "$DEST/dcg" << 'MOCKEOF'
#!/bin/bash
echo "dcg 1.0.0"
MOCKEOF
    chmod +x "$DEST/dcg"
}

teardown() {
    log_test "=== Test completed: $BATS_TEST_NAME (status: $status) ==="
    teardown_isolated_home
}

# ============================================================================
# Claude Code Configuration Tests
# ============================================================================

@test "configure_claude_code: creates settings.json when directory missing" {
    log_test "Testing Claude Code configuration with missing directory..."

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"

    # Directory doesn't exist yet
    [ ! -d "$HOME/.claude" ]

    configure_claude_code "$CLAUDE_SETTINGS" "0"

    log_test "Settings file exists: $([ -f "$CLAUDE_SETTINGS" ] && echo yes || echo no)"
    log_test "Settings content: $(cat "$CLAUDE_SETTINGS" 2>/dev/null || echo 'N/A')"

    [ -f "$CLAUDE_SETTINGS" ]
    grep -q "dcg" "$CLAUDE_SETTINGS"
}

@test "configure_claude_code: creates settings.json with correct hook structure" {
    log_test "Testing Claude Code hook structure..."

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"

    configure_claude_code "$CLAUDE_SETTINGS" "0"

    log_test "Settings content: $(cat "$CLAUDE_SETTINGS")"

    # Check for required structure
    grep -q "PreToolUse" "$CLAUDE_SETTINGS"
    grep -q "Bash" "$CLAUDE_SETTINGS"
    grep -q "dcg" "$CLAUDE_SETTINGS"
}

@test "configure_claude_code: preserves existing settings" {
    log_test "Testing Claude Code existing settings preservation..."

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"

    # Create existing settings with other content
    cat > "$CLAUDE_SETTINGS" << 'EOF'
{
  "theme": "dark",
  "fontSize": 14,
  "someOtherSetting": true
}
EOF

    log_test "Initial settings: $(cat "$CLAUDE_SETTINGS")"

    configure_claude_code "$CLAUDE_SETTINGS" "0"

    log_test "Final settings: $(cat "$CLAUDE_SETTINGS")"

    # Should have dcg hook
    grep -q "dcg" "$CLAUDE_SETTINGS"

    # Should preserve existing settings (python3 merge should keep them)
    # Note: This depends on python3 being available for merge
    if command -v python3 &>/dev/null; then
        grep -q "theme" "$CLAUDE_SETTINGS"
        grep -q "dark" "$CLAUDE_SETTINGS"
    fi
}

@test "configure_claude_code: is idempotent" {
    log_test "Testing Claude Code config idempotency..."

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"

    # Create settings with dcg hook already present
    cat > "$CLAUDE_SETTINGS" << EOF
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "$DEST/dcg"}
        ]
      }
    ]
  }
}
EOF

    local before
    before=$(cat "$CLAUDE_SETTINGS")
    log_test "Before: $before"

    configure_claude_code "$CLAUDE_SETTINGS" "0"

    local after
    after=$(cat "$CLAUDE_SETTINGS")
    log_test "After: $after"

    # CLAUDE_STATUS should be "already"
    [ "$CLAUDE_STATUS" = "already" ]
}

@test "configure_claude_code: does not duplicate hooks" {
    log_test "Testing Claude Code no duplicate hooks..."

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"
    echo '{}' > "$CLAUDE_SETTINGS"

    # Configure twice
    configure_claude_code "$CLAUDE_SETTINGS" "0"
    configure_claude_code "$CLAUDE_SETTINGS" "0"

    log_test "Final settings: $(cat "$CLAUDE_SETTINGS")"

    # Count dcg occurrences in command fields
    local dcg_count
    dcg_count=$(grep -o '"command".*dcg' "$CLAUDE_SETTINGS" | wc -l)
    log_test "dcg command count: $dcg_count"

    # Second call should detect already configured
    [ "$dcg_count" -le 1 ]
}

@test "configure_claude_code: reorders current dcg hook to first" {
    log_test "Testing Claude Code reorders existing dcg hook to first..."
    command -v python3 &>/dev/null || skip "python3 not available"

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"

    cat > "$CLAUDE_SETTINGS" << EOF
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "atuin history start"},
          {"type": "command", "command": "$DEST/dcg"}
        ]
      }
    ]
  }
}
EOF

    configure_claude_code "$CLAUDE_SETTINGS" "0"

    log_test "CLAUDE_STATUS: $CLAUDE_STATUS"
    log_test "After: $(cat "$CLAUDE_SETTINGS")"

    [ "$CLAUDE_STATUS" = "merged" ]
    python3 - "$CLAUDE_SETTINGS" "$DEST/dcg" <<'PY'
import json
import sys

settings_file, dcg_path = sys.argv[1:3]
with open(settings_file, "r") as f:
    settings = json.load(f)

commands = []
for entry in settings["hooks"]["PreToolUse"]:
    if entry.get("matcher") == "Bash":
        commands.extend(
            hook.get("command")
            for hook in entry.get("hooks", [])
            if isinstance(hook, dict)
        )

assert commands[0] == dcg_path, commands
assert commands.count(dcg_path) == 1, commands
assert "atuin history start" in commands, commands
PY
}

@test "configure_claude_code: does not treat dcg substring commands as installed" {
    log_test "Testing Claude Code exact dcg command detection..."

    command -v python3 &>/dev/null || skip "python3 not available"

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"

    cat > "$CLAUDE_SETTINGS" << 'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/opt/dcgrep/bin/scan"}
        ]
      }
    ]
  }
}
EOF

    configure_claude_code "$CLAUDE_SETTINGS" "0"

    log_test "CLAUDE_STATUS: $CLAUDE_STATUS"
    log_test "After: $(cat "$CLAUDE_SETTINGS")"

    [ "$CLAUDE_STATUS" = "merged" ]
    python3 - "$CLAUDE_SETTINGS" "$DEST/dcg" <<'PY'
import json
import sys

settings_file, dcg_path = sys.argv[1:3]
with open(settings_file, "r") as f:
    settings = json.load(f)

commands = []
for entry in settings["hooks"]["PreToolUse"]:
    if entry.get("matcher") == "Bash":
        for hook in entry.get("hooks", []):
            commands.append(hook.get("command"))

assert dcg_path in commands, commands
assert "/opt/dcgrep/bin/scan" in commands, commands
assert commands.count(dcg_path) == 1, commands
PY
}

@test "configure_claude_code: no-python fallback ignores dcg substrings" {
    log_test "Testing Claude Code no-python fallback exact detection..."

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"

    cat > "$CLAUDE_SETTINGS" << 'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/opt/dcgrep/bin/scan"}
        ]
      }
    ]
  }
}
EOF

    local no_python_path="$TEST_TMPDIR/no-python-bin"
    mkdir -p "$no_python_path"
    local tool
    for tool in dirname mkdir cp date grep sed rm mv cat; do
        ln -s "$(command -v "$tool")" "$no_python_path/$tool"
    done

    local old_path="$PATH"
    PATH="$no_python_path"
    configure_claude_code "$CLAUDE_SETTINGS" "0"
    local rc=$?
    PATH="$old_path"

    log_test "CLAUDE_STATUS: $CLAUDE_STATUS rc=$rc"
    log_test "After: $(cat "$CLAUDE_SETTINGS")"

    [ "$rc" -eq 1 ]
    [ "$CLAUDE_STATUS" = "failed" ]
    grep -qF '/opt/dcgrep/bin/scan' "$CLAUDE_SETTINGS"
    ! grep -qF "$DEST/dcg" "$CLAUDE_SETTINGS"
}

@test "configure_claude_code: no-python fallback recognizes exact dcg hook" {
    log_test "Testing Claude Code no-python fallback exact already-configured state..."

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"

    cat > "$CLAUDE_SETTINGS" << EOF
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "$DEST/dcg"}
        ]
      }
    ]
  }
}
EOF

    local no_python_path="$TEST_TMPDIR/no-python-bin"
    mkdir -p "$no_python_path"
    local tool
    for tool in dirname mkdir cp date grep sed rm mv cat; do
        ln -s "$(command -v "$tool")" "$no_python_path/$tool"
    done

    local old_path="$PATH"
    PATH="$no_python_path"
    configure_claude_code "$CLAUDE_SETTINGS" "0"
    local rc=$?
    PATH="$old_path"

    log_test "CLAUDE_STATUS: $CLAUDE_STATUS rc=$rc"

    [ "$rc" -eq 0 ]
    [ "$CLAUDE_STATUS" = "already" ]
}

@test "configure_claude_code: no-python fallback recognizes minified dcg hook" {
    log_test "Testing Claude Code no-python fallback with minified JSON..."

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"
    printf '{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"%s"}]}]}}\n' "$DEST/dcg" > "$CLAUDE_SETTINGS"

    local no_python_path="$TEST_TMPDIR/no-python-bin"
    mkdir -p "$no_python_path"
    local tool
    for tool in dirname mkdir cp date grep sed rm mv cat; do
        ln -s "$(command -v "$tool")" "$no_python_path/$tool"
    done

    local old_path="$PATH"
    PATH="$no_python_path"
    configure_claude_code "$CLAUDE_SETTINGS" "0"
    local rc=$?
    PATH="$old_path"

    log_test "CLAUDE_STATUS: $CLAUDE_STATUS rc=$rc"

    [ "$rc" -eq 0 ]
    [ "$CLAUDE_STATUS" = "already" ]
}

@test "configure_claude_code: no-python fallback rejects misordered dcg hook" {
    log_test "Testing Claude Code no-python fallback does not accept dcg after another hook..."

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"

    cat > "$CLAUDE_SETTINGS" << EOF
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "atuin history start"},
          {"type": "command", "command": "$DEST/dcg"}
        ]
      }
    ]
  }
}
EOF

    local no_python_path="$TEST_TMPDIR/no-python-bin"
    mkdir -p "$no_python_path"
    local tool
    for tool in dirname mkdir cp date grep sed rm mv cat; do
        ln -s "$(command -v "$tool")" "$no_python_path/$tool"
    done

    local old_path="$PATH"
    PATH="$no_python_path"
    configure_claude_code "$CLAUDE_SETTINGS" "0"
    local rc=$?
    PATH="$old_path"

    log_test "CLAUDE_STATUS: $CLAUDE_STATUS rc=$rc"
    log_test "After: $(cat "$CLAUDE_SETTINGS")"

    [ "$rc" -eq 1 ]
    [ "$CLAUDE_STATUS" = "failed" ]
    grep -qF 'atuin history start' "$CLAUDE_SETTINGS"
    grep -qF "$DEST/dcg" "$CLAUDE_SETTINGS"
}

# ============================================================================
# Gemini CLI Configuration Tests
# ============================================================================

@test "configure_gemini: skips when not installed" {
    log_test "Testing Gemini CLI skips when not installed..."

    GEMINI_SETTINGS="$HOME/.gemini/settings.json"

    # Gemini not installed (no directory, no command)
    configure_gemini "$GEMINI_SETTINGS"

    log_test "GEMINI_STATUS: $GEMINI_STATUS"

    [ "$GEMINI_STATUS" = "skipped" ]
}

@test "configure_gemini: creates settings.json when directory exists" {
    log_test "Testing Gemini CLI configuration..."

    GEMINI_SETTINGS="$HOME/.gemini/settings.json"
    setup_mock_gemini
    rm -f "$GEMINI_SETTINGS"  # Remove the mock settings

    configure_gemini "$GEMINI_SETTINGS"

    log_test "Settings file exists: $([ -f "$GEMINI_SETTINGS" ] && echo yes || echo no)"
    log_test "Settings content: $(cat "$GEMINI_SETTINGS" 2>/dev/null || echo 'N/A')"

    [ -f "$GEMINI_SETTINGS" ]
    grep -q "dcg" "$GEMINI_SETTINGS"
}

@test "configure_gemini: uses BeforeTool hook type" {
    log_test "Testing Gemini CLI uses BeforeTool..."

    GEMINI_SETTINGS="$HOME/.gemini/settings.json"
    setup_mock_gemini
    rm -f "$GEMINI_SETTINGS"

    configure_gemini "$GEMINI_SETTINGS"

    log_test "Settings content: $(cat "$GEMINI_SETTINGS")"

    # Gemini uses BeforeTool instead of PreToolUse
    grep -q "BeforeTool" "$GEMINI_SETTINGS"
    grep -q "run_shell_command" "$GEMINI_SETTINGS"
}

@test "configure_gemini: is idempotent" {
    log_test "Testing Gemini CLI config idempotency..."

    GEMINI_SETTINGS="$HOME/.gemini/settings.json"
    setup_mock_gemini

    # Create settings with dcg hook already present
    cat > "$GEMINI_SETTINGS" << EOF
{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "run_shell_command",
        "hooks": [
          {"name": "dcg", "type": "command", "command": "$DEST/dcg", "timeout": 5000}
        ]
      }
    ]
  }
}
EOF

    configure_gemini "$GEMINI_SETTINGS"

    log_test "GEMINI_STATUS: $GEMINI_STATUS"

    [ "$GEMINI_STATUS" = "already" ]
}

@test "configure_gemini: reorders current dcg hook to first" {
    log_test "Testing Gemini reorders existing dcg hook to first..."
    command -v python3 &>/dev/null || skip "python3 not available"

    GEMINI_SETTINGS="$HOME/.gemini/settings.json"
    setup_mock_gemini

    cat > "$GEMINI_SETTINGS" << EOF
{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "run_shell_command",
        "hooks": [
          {"name": "other", "type": "command", "command": "atuin history start", "timeout": 5000},
          {"name": "dcg", "type": "command", "command": "$DEST/dcg", "timeout": 5000}
        ]
      }
    ]
  }
}
EOF

    configure_gemini "$GEMINI_SETTINGS"

    log_test "GEMINI_STATUS: $GEMINI_STATUS"
    log_test "Settings content: $(cat "$GEMINI_SETTINGS")"

    [ "$GEMINI_STATUS" = "merged" ]
    python3 - "$GEMINI_SETTINGS" "$DEST/dcg" <<'PYEOF'
import json
import sys

settings_file, dcg_path = sys.argv[1:3]
with open(settings_file, "r") as f:
    settings = json.load(f)

commands = []
for entry in settings["hooks"]["BeforeTool"]:
    if entry.get("matcher") == "run_shell_command":
        commands.extend(
            hook.get("command")
            for hook in entry.get("hooks", [])
            if isinstance(hook, dict)
        )

assert commands[0] == dcg_path, commands
assert commands.count(dcg_path) == 1, commands
assert "atuin history start" in commands, commands
PYEOF
}

@test "configure_gemini: no-python fallback rejects misordered dcg hook" {
    log_test "Testing Gemini no-python fallback does not accept dcg after another hook..."

    GEMINI_SETTINGS="$HOME/.gemini/settings.json"
    setup_mock_gemini

    cat > "$GEMINI_SETTINGS" << EOF
{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "run_shell_command",
        "hooks": [
          {"name": "other", "type": "command", "command": "atuin history start", "timeout": 5000},
          {"name": "dcg", "type": "command", "command": "$DEST/dcg", "timeout": 5000}
        ]
      }
    ]
  }
}
EOF

    local no_python_path="$TEST_TMPDIR/no-python-bin"
    mkdir -p "$no_python_path"
    local tool
    for tool in dirname mkdir cp date grep sed rm mv cat; do
        ln -s "$(command -v "$tool")" "$no_python_path/$tool"
    done

    local old_path="$PATH"
    PATH="$no_python_path"
    configure_gemini "$GEMINI_SETTINGS"
    local rc=$?
    PATH="$old_path"

    log_test "GEMINI_STATUS: $GEMINI_STATUS rc=$rc"
    log_test "GEMINI_FAILURE_REASON: ${GEMINI_FAILURE_REASON:-}"
    log_test "Settings content: $(cat "$GEMINI_SETTINGS")"

    [ "$rc" -eq 0 ]
    [ "$GEMINI_STATUS" = "failed" ]
    [[ "$GEMINI_FAILURE_REASON" == *"python3"* ]]
    grep -qF 'atuin history start' "$GEMINI_SETTINGS"
    grep -qF "$DEST/dcg" "$GEMINI_SETTINGS"
}

@test "configure_gemini: does not treat dcg substring commands as installed" {
    log_test "Testing Gemini exact dcg command detection..."
    command -v python3 &>/dev/null || skip "python3 not available"

    GEMINI_SETTINGS="$HOME/.gemini/settings.json"
    setup_mock_gemini

    cat > "$GEMINI_SETTINGS" <<'EOF'
{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "run_shell_command",
        "hooks": [
          {"name": "not-dcg", "type": "command", "command": "/opt/not-dcg-wrapper/bin/hook", "timeout": 5000}
        ]
      }
    ]
  }
}
EOF

    configure_gemini "$GEMINI_SETTINGS"

    log_test "GEMINI_STATUS: $GEMINI_STATUS"
    log_test "Settings content: $(cat "$GEMINI_SETTINGS")"

    [ "$GEMINI_STATUS" = "merged" ]
    grep -q "\"command\": \"$DEST/dcg\"" "$GEMINI_SETTINGS"
    grep -q "/opt/not-dcg-wrapper/bin/hook" "$GEMINI_SETTINGS"
}

@test "configure_gemini: updates stale dcg hook path and removes duplicates" {
    log_test "Testing Gemini stale dcg hook path update and duplicate cleanup..."
    command -v python3 &>/dev/null || skip "python3 not available"

    GEMINI_SETTINGS="$HOME/.gemini/settings.json"
    setup_mock_gemini

    cat > "$GEMINI_SETTINGS" <<EOF
{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "run_shell_command",
        "sequential": true,
        "hooks": [
          {"name": "dcg", "type": "command", "command": "/old/bin/dcg", "timeout": 5000},
          {"name": "other", "type": "command", "command": "atuin history start", "timeout": 5000}
        ]
      },
      {
        "matcher": "run_shell_command",
        "hooks": [
          {"name": "dcg", "type": "command", "command": "$DEST/dcg", "timeout": 5000}
        ]
      }
    ]
  }
}
EOF

    configure_gemini "$GEMINI_SETTINGS"

    log_test "GEMINI_STATUS: $GEMINI_STATUS"
    log_test "Settings content: $(cat "$GEMINI_SETTINGS")"

    [ "$GEMINI_STATUS" = "merged" ]
    grep -q "\"command\": \"$DEST/dcg\"" "$GEMINI_SETTINGS"
    if grep -q "/old/bin/dcg" "$GEMINI_SETTINGS"; then
        return 1
    fi
    grep -q "atuin history start" "$GEMINI_SETTINGS"

    python3 - "$GEMINI_SETTINGS" "$DEST/dcg" <<'PYEOF'
import json
import sys

settings_file, dcg_path = sys.argv[1], sys.argv[2]
with open(settings_file, "r") as f:
    settings = json.load(f)

before_tool = settings["hooks"]["BeforeTool"]
shell_entries = [entry for entry in before_tool if entry.get("matcher") == "run_shell_command"]
assert len(shell_entries) == 1, shell_entries
assert shell_entries[0].get("sequential") is True, shell_entries[0]

commands = [
    hook.get("command")
    for hook in shell_entries[0].get("hooks", [])
    if isinstance(hook, dict)
]
assert commands[0] == dcg_path, commands
assert commands.count(dcg_path) == 1, commands
PYEOF
}

@test "configure_gemini: invalid settings.json is preserved and reports failed" {
    log_test "Testing Gemini invalid settings.json preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"

    GEMINI_SETTINGS="$HOME/.gemini/settings.json"
    setup_mock_gemini
    printf '%s\n' '{"hooks":{"BeforeTool":[' > "$GEMINI_SETTINGS"
    local before
    before=$(cat "$GEMINI_SETTINGS")

    configure_gemini "$GEMINI_SETTINGS"
    local rc=$?

    log_test "GEMINI_STATUS: $GEMINI_STATUS"
    log_test "GEMINI_FAILURE_REASON: ${GEMINI_FAILURE_REASON:-}"
    log_test "Settings content: $(cat "$GEMINI_SETTINGS")"

    [ "$rc" -eq 0 ]
    [ "$GEMINI_STATUS" = "failed" ]
    [[ "$GEMINI_FAILURE_REASON" == *"invalid"* ]]
    [ "$(cat "$GEMINI_SETTINGS")" = "$before" ]
    [ -z "$GEMINI_BACKUP" ]
}

@test "configure_gemini: non-object hooks is preserved and reports failed" {
    log_test "Testing Gemini non-object hooks preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"

    GEMINI_SETTINGS="$HOME/.gemini/settings.json"
    setup_mock_gemini
    cat > "$GEMINI_SETTINGS" <<'EOF'
{"hooks":["bad-shape"]}
EOF
    local before
    before=$(cat "$GEMINI_SETTINGS")

    configure_gemini "$GEMINI_SETTINGS"
    local rc=$?

    log_test "GEMINI_STATUS: $GEMINI_STATUS"
    log_test "GEMINI_FAILURE_REASON: ${GEMINI_FAILURE_REASON:-}"
    log_test "Settings content: $(cat "$GEMINI_SETTINGS")"

    [ "$rc" -eq 0 ]
    [ "$GEMINI_STATUS" = "failed" ]
    [[ "$GEMINI_FAILURE_REASON" == *"invalid"* ]]
    [ "$(cat "$GEMINI_SETTINGS")" = "$before" ]
    [ -z "$GEMINI_BACKUP" ]
}

@test "configure_gemini: non-list BeforeTool is preserved and reports failed" {
    log_test "Testing Gemini non-list BeforeTool preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"

    GEMINI_SETTINGS="$HOME/.gemini/settings.json"
    setup_mock_gemini
    cat > "$GEMINI_SETTINGS" <<'EOF'
{
  "hooks": {
    "BeforeTool": {
      "matcher": "run_shell_command",
      "hooks": [
        {"name": "dcg", "type": "command", "command": "/old/bin/dcg", "timeout": 5000}
      ]
    },
    "AfterTool": [
      {
        "matcher": "run_shell_command",
        "hooks": [
          {"name": "other", "type": "command", "command": "atuin history end", "timeout": 5000}
        ]
      }
    ]
  }
}
EOF
    local before
    before=$(cat "$GEMINI_SETTINGS")

    configure_gemini "$GEMINI_SETTINGS"
    local rc=$?

    log_test "GEMINI_STATUS: $GEMINI_STATUS"
    log_test "GEMINI_FAILURE_REASON: ${GEMINI_FAILURE_REASON:-}"
    log_test "Settings content: $(cat "$GEMINI_SETTINGS")"

    [ "$rc" -eq 0 ]
    [ "$GEMINI_STATUS" = "failed" ]
    [[ "$GEMINI_FAILURE_REASON" == *"invalid"* ]]
    [ "$(cat "$GEMINI_SETTINGS")" = "$before" ]
    [ -z "$GEMINI_BACKUP" ]
}

@test "configure_gemini: run_shell_command with non-list hooks is preserved and reports failed" {
    log_test "Testing Gemini malformed run_shell_command hooks preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"

    GEMINI_SETTINGS="$HOME/.gemini/settings.json"
    setup_mock_gemini
    cat > "$GEMINI_SETTINGS" <<'EOF'
{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "run_shell_command",
        "hooks": {"bad": "shape"}
      },
      {
        "matcher": "read_file",
        "hooks": [
          {"name": "read", "type": "command", "command": "echo read", "timeout": 5000}
        ]
      }
    ]
  }
}
EOF
    local before
    before=$(cat "$GEMINI_SETTINGS")

    configure_gemini "$GEMINI_SETTINGS"
    local rc=$?

    log_test "GEMINI_STATUS: $GEMINI_STATUS"
    log_test "GEMINI_FAILURE_REASON: ${GEMINI_FAILURE_REASON:-}"
    log_test "Settings content: $(cat "$GEMINI_SETTINGS")"

    [ "$rc" -eq 0 ]
    [ "$GEMINI_STATUS" = "failed" ]
    [[ "$GEMINI_FAILURE_REASON" == *"invalid"* ]]
    [ "$(cat "$GEMINI_SETTINGS")" = "$before" ]
    [ -z "$GEMINI_BACKUP" ]
}

# ============================================================================
# Predecessor Migration Tests
# ============================================================================

@test "configure_claude_code: removes predecessor hook when requested" {
    log_test "Testing predecessor removal..."

    # Skip if python3 not available (needed for JSON manipulation)
    command -v python3 &>/dev/null || skip "python3 not available"

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"

    # Create settings with predecessor hook
    cat > "$CLAUDE_SETTINGS" << 'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/path/to/git_safety_guard.py"}
        ]
      }
    ]
  }
}
EOF

    log_test "Before: $(cat "$CLAUDE_SETTINGS")"

    # Configure with cleanup_predecessor=1
    configure_claude_code "$CLAUDE_SETTINGS" "1"

    log_test "After: $(cat "$CLAUDE_SETTINGS")"

    # Should have dcg
    grep -q "dcg" "$CLAUDE_SETTINGS"

    # Should NOT have git_safety_guard
    ! grep -q "git_safety_guard" "$CLAUDE_SETTINGS"
}

@test "configure_claude_code: keeps predecessor when not requested" {
    log_test "Testing predecessor preservation..."

    # Skip if python3 not available
    command -v python3 &>/dev/null || skip "python3 not available"

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"

    # Create settings with predecessor hook
    cat > "$CLAUDE_SETTINGS" << 'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/path/to/git_safety_guard.py"}
        ]
      }
    ]
  }
}
EOF

    log_test "Before: $(cat "$CLAUDE_SETTINGS")"

    # Configure with cleanup_predecessor=0
    configure_claude_code "$CLAUDE_SETTINGS" "0"

    log_test "After: $(cat "$CLAUDE_SETTINGS")"

    # Should have dcg
    grep -q "dcg" "$CLAUDE_SETTINGS"

    # Should still have git_safety_guard
    grep -q "git_safety_guard" "$CLAUDE_SETTINGS"
}

# ============================================================================
# Edge Cases
# ============================================================================

@test "configure_claude_code: handles malformed JSON gracefully" {
    log_test "Testing malformed JSON handling..."
    command -v python3 &>/dev/null || skip "python3 not available"

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"

    # Create malformed JSON
    echo "not valid json {{{" > "$CLAUDE_SETTINGS"
    local before
    before=$(cat "$CLAUDE_SETTINGS")

    log_test "Malformed content: $(cat "$CLAUDE_SETTINGS")"

    configure_claude_code "$CLAUDE_SETTINGS" "0"

    log_test "CLAUDE_STATUS: $CLAUDE_STATUS"
    log_test "CLAUDE_FAILURE_REASON: ${CLAUDE_FAILURE_REASON:-}"
    log_test "After: $(cat "$CLAUDE_SETTINGS" 2>/dev/null || echo 'N/A')"

    [ "$CLAUDE_STATUS" = "failed" ]
    [[ "$CLAUDE_FAILURE_REASON" == *"invalid"* ]]
    [ -z "$CLAUDE_BACKUP" ]
    [ "$(cat "$CLAUDE_SETTINGS")" = "$before" ]
}

@test "configure_claude_code: non-object hooks is preserved and reports failed" {
    log_test "Testing Claude Code malformed hooks preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"
    printf '%s\n' '{"hooks":["bad-shape"]}' > "$CLAUDE_SETTINGS"
    local before
    before=$(cat "$CLAUDE_SETTINGS")

    configure_claude_code "$CLAUDE_SETTINGS" "0"

    log_test "CLAUDE_STATUS: $CLAUDE_STATUS"
    log_test "CLAUDE_FAILURE_REASON: ${CLAUDE_FAILURE_REASON:-}"
    log_test "After: $(cat "$CLAUDE_SETTINGS")"

    [ "$CLAUDE_STATUS" = "failed" ]
    [[ "$CLAUDE_FAILURE_REASON" == *"invalid"* ]]
    [ -z "$CLAUDE_BACKUP" ]
    [ "$(cat "$CLAUDE_SETTINGS")" = "$before" ]
}

@test "configure_claude_code: non-list PreToolUse is preserved and reports failed" {
    log_test "Testing Claude Code malformed PreToolUse preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"
    cat > "$CLAUDE_SETTINGS" <<'EOF'
{
  "hooks": {
    "PreToolUse": {"bad": "shape"}
  },
  "theme": "dark"
}
EOF
    local before
    before=$(cat "$CLAUDE_SETTINGS")

    configure_claude_code "$CLAUDE_SETTINGS" "0"

    log_test "CLAUDE_STATUS: $CLAUDE_STATUS"
    log_test "CLAUDE_FAILURE_REASON: ${CLAUDE_FAILURE_REASON:-}"
    log_test "After: $(cat "$CLAUDE_SETTINGS")"

    [ "$CLAUDE_STATUS" = "failed" ]
    [[ "$CLAUDE_FAILURE_REASON" == *"invalid"* ]]
    [ -z "$CLAUDE_BACKUP" ]
    [ "$(cat "$CLAUDE_SETTINGS")" = "$before" ]
}

@test "configure_claude_code: Bash matcher with non-list hooks is preserved and reports failed" {
    log_test "Testing Claude Code malformed Bash matcher hooks preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"
    cat > "$CLAUDE_SETTINGS" <<'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": {"bad": "shape"}
      }
    ]
  },
  "theme": "dark"
}
EOF
    local before
    before=$(cat "$CLAUDE_SETTINGS")

    configure_claude_code "$CLAUDE_SETTINGS" "0"

    log_test "CLAUDE_STATUS: $CLAUDE_STATUS"
    log_test "CLAUDE_FAILURE_REASON: ${CLAUDE_FAILURE_REASON:-}"
    log_test "After: $(cat "$CLAUDE_SETTINGS")"

    [ "$CLAUDE_STATUS" = "failed" ]
    [[ "$CLAUDE_FAILURE_REASON" == *"invalid"* ]]
    [ -z "$CLAUDE_BACKUP" ]
    [ "$(cat "$CLAUDE_SETTINGS")" = "$before" ]
}

@test "configure_claude_code: handles empty settings file" {
    log_test "Testing empty settings file..."

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"

    # Create empty file
    touch "$CLAUDE_SETTINGS"

    configure_claude_code "$CLAUDE_SETTINGS" "0"

    log_test "CLAUDE_STATUS: $CLAUDE_STATUS"
    log_test "After: $(cat "$CLAUDE_SETTINGS")"

    # Should have added dcg hook
    grep -q "dcg" "$CLAUDE_SETTINGS"
}

@test "configure_claude_code: handles settings with empty hooks array" {
    log_test "Testing empty hooks array..."

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"

    cat > "$CLAUDE_SETTINGS" << 'EOF'
{
  "hooks": {}
}
EOF

    configure_claude_code "$CLAUDE_SETTINGS" "0"

    log_test "CLAUDE_STATUS: $CLAUDE_STATUS"
    log_test "After: $(cat "$CLAUDE_SETTINGS")"

    # Should have added dcg hook
    grep -q "dcg" "$CLAUDE_SETTINGS"
}

# ============================================================================
# Aider Configuration Tests
# ============================================================================

@test "configure_aider: skips when not installed" {
    log_test "Testing Aider skips when not installed..."

    AIDER_SETTINGS="$HOME/.aider.conf.yml"

    # Aider not installed (no command in our isolated PATH)
    configure_aider "$AIDER_SETTINGS"

    log_test "AIDER_STATUS: $AIDER_STATUS"

    [ "$AIDER_STATUS" = "skipped" ]
}

@test "configure_aider: creates config file when installed" {
    log_test "Testing Aider configuration creation..."

    setup_mock_aider
    AIDER_SETTINGS="$HOME/.aider.conf.yml"

    # No existing config
    [ ! -f "$AIDER_SETTINGS" ]

    configure_aider "$AIDER_SETTINGS"

    log_test "AIDER_STATUS: $AIDER_STATUS"
    log_test "Config content: $(cat "$AIDER_SETTINGS" 2>/dev/null || echo 'N/A')"

    [ -f "$AIDER_SETTINGS" ]
    [ "$AIDER_STATUS" = "created" ]
    grep -q "git-commit-verify: true" "$AIDER_SETTINGS"
}

@test "configure_aider: sets git-commit-verify to true" {
    log_test "Testing Aider git-commit-verify setting..."

    setup_mock_aider
    AIDER_SETTINGS="$HOME/.aider.conf.yml"

    configure_aider "$AIDER_SETTINGS"

    log_test "Config content: $(cat "$AIDER_SETTINGS")"

    # Must have git-commit-verify: true
    grep -qE "git-commit-verify:\s*true" "$AIDER_SETTINGS"
}

@test "configure_aider: updates false to true" {
    log_test "Testing Aider updates git-commit-verify from false to true..."

    setup_mock_aider
    AIDER_SETTINGS="$HOME/.aider.conf.yml"

    # Create config with git-commit-verify: false
    cat > "$AIDER_SETTINGS" << 'EOF'
# Aider config
model: gpt-4
git-commit-verify: false
auto-commits: true
EOF

    log_test "Before: $(cat "$AIDER_SETTINGS")"

    configure_aider "$AIDER_SETTINGS"

    log_test "AIDER_STATUS: $AIDER_STATUS"
    log_test "After: $(cat "$AIDER_SETTINGS")"

    # Should now be true
    grep -qE "git-commit-verify:\s*true" "$AIDER_SETTINGS"
    [ "$AIDER_STATUS" = "merged" ]
}

@test "configure_aider: appends setting to existing config" {
    log_test "Testing Aider appends to existing config..."

    setup_mock_aider
    AIDER_SETTINGS="$HOME/.aider.conf.yml"

    # Create config without git-commit-verify
    cat > "$AIDER_SETTINGS" << 'EOF'
# Aider config
model: gpt-4
auto-commits: true
EOF

    log_test "Before: $(cat "$AIDER_SETTINGS")"

    configure_aider "$AIDER_SETTINGS"

    log_test "AIDER_STATUS: $AIDER_STATUS"
    log_test "After: $(cat "$AIDER_SETTINGS")"

    # Should have the setting added
    grep -qE "git-commit-verify:\s*true" "$AIDER_SETTINGS"
    # Should preserve existing settings
    grep -q "model: gpt-4" "$AIDER_SETTINGS"
    [ "$AIDER_STATUS" = "merged" ]
}

@test "configure_aider: is idempotent" {
    log_test "Testing Aider config idempotency..."

    setup_mock_aider
    AIDER_SETTINGS="$HOME/.aider.conf.yml"

    # Create config with git-commit-verify already true
    cat > "$AIDER_SETTINGS" << 'EOF'
# Aider config
git-commit-verify: true
model: gpt-4
EOF

    configure_aider "$AIDER_SETTINGS"

    log_test "AIDER_STATUS: $AIDER_STATUS"

    [ "$AIDER_STATUS" = "already" ]
}

@test "configure_aider: creates backup when modifying" {
    log_test "Testing Aider creates backup..."

    setup_mock_aider
    AIDER_SETTINGS="$HOME/.aider.conf.yml"

    # Create config with git-commit-verify: false
    cat > "$AIDER_SETTINGS" << 'EOF'
model: gpt-4
git-commit-verify: false
EOF

    configure_aider "$AIDER_SETTINGS"

    log_test "AIDER_BACKUP: $AIDER_BACKUP"

    # Should have created backup
    [ -n "$AIDER_BACKUP" ]
    [ -f "$AIDER_BACKUP" ]
}

# ============================================================================
# Continue Configuration Tests
# ============================================================================

@test "configure_continue: skips when not installed" {
    log_test "Testing Continue skips when not installed..."

    # Continue not installed (no directory, no command)
    configure_continue

    log_test "CONTINUE_STATUS: $CONTINUE_STATUS"

    [ "$CONTINUE_STATUS" = "skipped" ]
}

@test "configure_continue: detects via ~/.continue directory" {
    log_test "Testing Continue detection via directory..."

    setup_mock_continue

    configure_continue

    log_test "CONTINUE_STATUS: $CONTINUE_STATUS"

    # Should be unsupported (detected but no hooks available)
    [ "$CONTINUE_STATUS" = "unsupported" ]
}

@test "configure_continue: detects via cn command" {
    log_test "Testing Continue detection via cn command..."

    # Create mock cn binary
    mkdir -p "$TEST_TMPDIR/bin"
    cat > "$TEST_TMPDIR/bin/cn" << 'EOF'
#!/bin/bash
echo "Continue CLI v1.0.0"
EOF
    chmod +x "$TEST_TMPDIR/bin/cn"
    export PATH="$TEST_TMPDIR/bin:$PATH"

    configure_continue

    log_test "CONTINUE_STATUS: $CONTINUE_STATUS"

    # Should be unsupported (detected but no hooks available)
    [ "$CONTINUE_STATUS" = "unsupported" ]
}

@test "configure_continue: reports unsupported (no shell command hooks)" {
    log_test "Testing Continue reports unsupported status..."

    setup_mock_continue

    configure_continue

    log_test "CONTINUE_STATUS: $CONTINUE_STATUS"

    # Continue does not have shell command hooks like Claude Code or Gemini
    # Status should be "unsupported" to indicate detection but no auto-config
    [ "$CONTINUE_STATUS" = "unsupported" ]
}

# ============================================================================
# Cursor IDE Configuration Tests
# ============================================================================

setup_mock_cursor() {
    mkdir -p "$HOME/.cursor"
}

assert_cursor_first_hook_command() {
    command -v python3 &>/dev/null || skip "python3 not available"

    python3 - "$CURSOR_HOOKS_JSON" "$1" <<'PYEOF'
import json
import sys

hooks_file, expected = sys.argv[1:3]
with open(hooks_file, "r") as f:
    config = json.load(f)

actual = config["hooks"]["beforeShellExecution"][0]["command"]
if actual != expected:
    raise SystemExit(f"first Cursor hook was {actual!r}, expected {expected!r}")
PYEOF
}

assert_cursor_hook_count() {
    command -v python3 &>/dev/null || skip "python3 not available"

    python3 - "$CURSOR_HOOKS_JSON" "$CURSOR_HOOK_SCRIPT" "$1" <<'PYEOF'
import json
import sys

hooks_file, hook_cmd, expected_raw = sys.argv[1:4]
expected = int(expected_raw)
with open(hooks_file, "r") as f:
    config = json.load(f)

entries = config["hooks"]["beforeShellExecution"]
count = sum(
    1
    for entry in entries
    if isinstance(entry, dict) and entry.get("command") == hook_cmd
)
if count != expected:
    raise SystemExit(f"Cursor hook count was {count}, expected {expected}")
PYEOF
}

@test "configure_cursor: creates hooks json and generated hook script" {
    log_test "Testing Cursor hook creation..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_cursor

    configure_cursor

    log_test "CURSOR_STATUS: $CURSOR_STATUS"
    log_test "hooks.json: $(cat "$CURSOR_HOOKS_JSON" 2>/dev/null || echo 'missing')"

    [ "$CURSOR_STATUS" = "created" ]
    [ -f "$CURSOR_HOOKS_JSON" ]
    [ -f "$CURSOR_HOOK_SCRIPT" ]
    grep -qF "dcg-cursor-hook" "$CURSOR_HOOK_SCRIPT"
    grep -qF "DCG_BIN_FALLBACK" "$CURSOR_HOOK_SCRIPT"
    grep -qF "$DEST/dcg" "$CURSOR_HOOK_SCRIPT"
    assert_cursor_first_hook_command "$CURSOR_HOOK_SCRIPT"
    assert_cursor_hook_count 1
}

@test "configure_cursor: generated hook uses installed dcg path when PATH lacks dcg" {
    log_test "Testing Cursor hook absolute dcg fallback..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_cursor
    cat > "$DEST/dcg" << 'MOCKEOF'
#!/bin/sh
cat >/dev/null
printf '%s\n' '{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"blocked by mock dcg"}}'
MOCKEOF
    chmod +x "$DEST/dcg"

    configure_cursor

    local python_bin
    python_bin="$(command -v python3)"
    local output
    output=$(PATH="/usr/bin:/bin" DCG_BIN= "$python_bin" "$CURSOR_HOOK_SCRIPT" <<'JSON'
{"command":"rm -rf /","cwd":""}
JSON
)

    log_test "Cursor hook output: $output"
    [[ "$output" == *'"permission": "deny"'* ]]
    [[ "$output" == *'blocked by mock dcg'* ]]
}

@test "configure_cursor: does not treat hook script path outside entries as installed" {
    log_test "Testing Cursor exact hook entry detection..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_cursor
    cat > "$CURSOR_HOOKS_JSON" << EOF
{
  "version": 1,
  "notes": "$CURSOR_HOOK_SCRIPT"
}
EOF

    configure_cursor

    log_test "CURSOR_STATUS: $CURSOR_STATUS"
    log_test "hooks.json: $(cat "$CURSOR_HOOKS_JSON")"

    [ "$CURSOR_STATUS" = "merged" ]
    assert_cursor_first_hook_command "$CURSOR_HOOK_SCRIPT"
    assert_cursor_hook_count 1
    grep -qF '"notes"' "$CURSOR_HOOKS_JSON"
}

@test "configure_cursor: reorders current hook to first and removes duplicates" {
    log_test "Testing Cursor hook reorder and duplicate cleanup..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_cursor
    mkdir -p "$CURSOR_HOOK_DIR"
    cat > "$CURSOR_HOOKS_JSON" << EOF
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [
      {
        "command": "/opt/other-hook"
      },
      {
        "command": "$CURSOR_HOOK_SCRIPT"
      },
      {
        "command": "$CURSOR_HOOK_SCRIPT"
      }
    ]
  }
}
EOF

    configure_cursor

    log_test "CURSOR_STATUS: $CURSOR_STATUS"
    log_test "hooks.json: $(cat "$CURSOR_HOOKS_JSON")"

    [ "$CURSOR_STATUS" = "merged" ]
    assert_cursor_first_hook_command "$CURSOR_HOOK_SCRIPT"
    assert_cursor_hook_count 1
    grep -qF "/opt/other-hook" "$CURSOR_HOOKS_JSON"
}

@test "configure_cursor: invalid hooks json is preserved and reports failed" {
    log_test "Testing Cursor invalid hooks.json preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_cursor
    mkdir -p "$HOME/.cursor"
    printf '%s\n' '{"hooks":{"beforeShellExecution":[' > "$CURSOR_HOOKS_JSON"
    local before
    before=$(cat "$CURSOR_HOOKS_JSON")

    configure_cursor
    local rc=$?

    log_test "configure_cursor rc: $rc"
    log_test "CURSOR_STATUS: $CURSOR_STATUS"
    log_test "CURSOR_FAILURE_REASON: ${CURSOR_FAILURE_REASON:-}"
    log_test "hooks.json: $(cat "$CURSOR_HOOKS_JSON")"

    [ "$rc" -eq 0 ]
    [ "$CURSOR_STATUS" = "failed" ]
    [[ "$CURSOR_FAILURE_REASON" == *"invalid"* ]]
    [ -z "$CURSOR_BACKUP" ]
    [ "$(cat "$CURSOR_HOOKS_JSON")" = "$before" ]
}

@test "configure_cursor: malformed hooks object is preserved and reports failed" {
    log_test "Testing Cursor malformed hooks preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_cursor
    mkdir -p "$HOME/.cursor"
    cat > "$CURSOR_HOOKS_JSON" <<'EOF'
{
  "version": 1,
  "hooks": ["bad-shape"]
}
EOF
    local before
    before=$(cat "$CURSOR_HOOKS_JSON")

    configure_cursor
    local rc=$?

    log_test "configure_cursor rc: $rc"
    log_test "CURSOR_STATUS: $CURSOR_STATUS"
    log_test "CURSOR_FAILURE_REASON: ${CURSOR_FAILURE_REASON:-}"
    log_test "hooks.json: $(cat "$CURSOR_HOOKS_JSON")"

    [ "$rc" -eq 0 ]
    [ "$CURSOR_STATUS" = "failed" ]
    [[ "$CURSOR_FAILURE_REASON" == *"malformed"* ]]
    [ -z "$CURSOR_BACKUP" ]
    [ "$(cat "$CURSOR_HOOKS_JSON")" = "$before" ]
}

@test "configure_cursor: non-list beforeShellExecution is preserved and reports failed" {
    log_test "Testing Cursor non-list beforeShellExecution preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_cursor
    mkdir -p "$HOME/.cursor"
    cat > "$CURSOR_HOOKS_JSON" <<'EOF'
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": "bad-shape"
  }
}
EOF
    local before
    before=$(cat "$CURSOR_HOOKS_JSON")

    configure_cursor
    local rc=$?

    log_test "configure_cursor rc: $rc"
    log_test "CURSOR_STATUS: $CURSOR_STATUS"
    log_test "CURSOR_FAILURE_REASON: ${CURSOR_FAILURE_REASON:-}"
    log_test "hooks.json: $(cat "$CURSOR_HOOKS_JSON")"

    [ "$rc" -eq 0 ]
    [ "$CURSOR_STATUS" = "failed" ]
    [[ "$CURSOR_FAILURE_REASON" == *"malformed"* ]]
    [ -z "$CURSOR_BACKUP" ]
    [ "$(cat "$CURSOR_HOOKS_JSON")" = "$before" ]
}

# ============================================================================
# GitHub Copilot CLI Configuration Tests
# ============================================================================

setup_mock_copilot_repo() {
    mkdir -p "$HOME/.copilot"

    COPILOT_REPO="$TEST_TMPDIR/copilot-repo"
    mkdir -p "$COPILOT_REPO"
    git init -q -b main "$COPILOT_REPO"
    cd "$COPILOT_REPO"
}

assert_copilot_first_hook() {
    command -v python3 &>/dev/null || skip "python3 not available"

    python3 - "$COPILOT_HOOK_FILE" "$1" <<'PYEOF'
import json
import sys

hook_file, expected = sys.argv[1:3]
with open(hook_file, "r") as f:
    config = json.load(f)

actual = config["hooks"]["preToolUse"][0]["bash"]
if actual != expected:
    raise SystemExit(f"first Copilot hook was {actual!r}, expected {expected!r}")
PYEOF
}

assert_copilot_dcg_hook_count() {
    command -v python3 &>/dev/null || skip "python3 not available"

    python3 - "$COPILOT_HOOK_FILE" "$DEST/dcg" "$1" <<'PYEOF'
import json
import os
import shlex
import sys

hook_file, dcg_path, expected_raw = sys.argv[1:4]
expected = int(expected_raw)

def command_invokes_dcg(cmd):
    if not isinstance(cmd, str) or not cmd:
        return False
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return False
    if not tokens:
        return False
    name = os.path.basename(tokens[0])
    if name.endswith(".exe"):
        name = name[:-4]
    return name == "dcg"

with open(hook_file, "r") as f:
    config = json.load(f)

count = 0
for entry in config["hooks"]["preToolUse"]:
    if command_invokes_dcg(entry.get("bash")) or command_invokes_dcg(entry.get("powershell")):
        count += 1

if count != expected:
    raise SystemExit(f"Copilot dcg hook count was {count}, expected {expected}")

first = config["hooks"]["preToolUse"][0]
if first.get("bash") != dcg_path or first.get("powershell") != dcg_path:
    raise SystemExit(f"first Copilot hook is not the current dcg hook: {first!r}")
PYEOF
}

@test "configure_copilot: adds hook in git repository" {
    log_test "Testing Copilot hook creation..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_copilot_repo

    configure_copilot

    log_test "COPILOT_STATUS: $COPILOT_STATUS"
    log_test "Hook file: ${COPILOT_HOOK_FILE:-}"
    log_test "Hook content: $(cat "$COPILOT_HOOK_FILE" 2>/dev/null || echo 'missing')"

    [ "$COPILOT_STATUS" = "created" ]
    [ -f "$COPILOT_HOOK_FILE" ]
    assert_copilot_first_hook "$DEST/dcg"
    assert_copilot_dcg_hook_count 1
}

@test "configure_copilot: does not treat dcg substring commands as installed" {
    log_test "Testing Copilot exact dcg hook detection..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_copilot_repo
    mkdir -p .github/hooks
    cat > .github/hooks/dcg.json <<'EOF'
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "type": "command",
        "bash": "/opt/dcgrep/bin/scan",
        "powershell": "pwsh-dcg-helper",
        "cwd": ".",
        "timeoutSec": 30
      }
    ]
  }
}
EOF

    configure_copilot

    log_test "COPILOT_STATUS: $COPILOT_STATUS"
    log_test "Hook content: $(cat "$COPILOT_HOOK_FILE")"

    [ "$COPILOT_STATUS" = "merged" ]
    assert_copilot_first_hook "$DEST/dcg"
    assert_copilot_dcg_hook_count 1
    grep -qF "/opt/dcgrep/bin/scan" "$COPILOT_HOOK_FILE"
    grep -qF "pwsh-dcg-helper" "$COPILOT_HOOK_FILE"
}

@test "configure_copilot: reorders current dcg hook to first and removes duplicates" {
    log_test "Testing Copilot dcg hook reorder and duplicate cleanup..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_copilot_repo
    mkdir -p .github/hooks
    cat > .github/hooks/dcg.json << EOF
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "type": "command",
        "bash": "atuin history start",
        "powershell": "atuin history start",
        "cwd": ".",
        "timeoutSec": 30
      },
      {
        "type": "command",
        "bash": "$DEST/dcg",
        "powershell": "$DEST/dcg",
        "cwd": ".",
        "timeoutSec": 30
      },
      {
        "type": "command",
        "bash": "/old/bin/dcg",
        "powershell": "/old/bin/dcg",
        "cwd": ".",
        "timeoutSec": 30
      }
    ]
  }
}
EOF

    configure_copilot

    log_test "COPILOT_STATUS: $COPILOT_STATUS"
    log_test "Hook content: $(cat "$COPILOT_HOOK_FILE")"

    [ "$COPILOT_STATUS" = "merged" ]
    assert_copilot_first_hook "$DEST/dcg"
    assert_copilot_dcg_hook_count 1
    grep -qF "atuin history start" "$COPILOT_HOOK_FILE"
}

@test "configure_copilot: preserves mixed hook entries when refreshing a dcg platform command" {
    log_test "Testing Copilot mixed platform hook preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_copilot_repo
    mkdir -p .github/hooks
    cat > .github/hooks/dcg.json << EOF
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "type": "command",
        "bash": "audit-pretool",
        "powershell": "$DEST/dcg",
        "cwd": ".",
        "timeoutSec": 30
      }
    ]
  }
}
EOF

    configure_copilot

    log_test "COPILOT_STATUS: $COPILOT_STATUS"
    log_test "Hook content: $(cat "$COPILOT_HOOK_FILE")"

    [ "$COPILOT_STATUS" = "merged" ]
    assert_copilot_first_hook "$DEST/dcg"
    assert_copilot_dcg_hook_count 1
    python3 - "$COPILOT_HOOK_FILE" <<'PYEOF'
import json
import sys

with open(sys.argv[1], "r") as f:
    config = json.load(f)

pre_tool = config["hooks"]["preToolUse"]
if len(pre_tool) != 2:
    raise SystemExit(f"expected two Copilot hooks after merge, found {len(pre_tool)}")

residual = pre_tool[1]
if residual.get("bash") != "audit-pretool":
    raise SystemExit(f"mixed hook bash command was not preserved: {residual!r}")
if "powershell" in residual:
    raise SystemExit(f"dcg powershell command was not stripped from mixed hook: {residual!r}")
PYEOF
}

@test "configure_copilot: adds preToolUse when hooks object exists without it" {
    log_test "Testing Copilot hook file extension without preToolUse..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_copilot_repo
    mkdir -p .github/hooks
    cat > .github/hooks/dcg.json <<'EOF'
{
  "version": 1,
  "hooks": {
    "postToolUse": [
      {
        "type": "command",
        "bash": "atuin history end",
        "powershell": "atuin history end"
      }
    ]
  }
}
EOF

    configure_copilot

    log_test "COPILOT_STATUS: $COPILOT_STATUS"
    log_test "Hook content: $(cat "$COPILOT_HOOK_FILE")"

    [ "$COPILOT_STATUS" = "merged" ]
    assert_copilot_first_hook "$DEST/dcg"
    assert_copilot_dcg_hook_count 1
    grep -qF "postToolUse" "$COPILOT_HOOK_FILE"
    grep -qF "atuin history end" "$COPILOT_HOOK_FILE"
}

@test "configure_copilot: invalid hook file is preserved and reports failed" {
    log_test "Testing Copilot invalid hook file preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_copilot_repo
    mkdir -p .github/hooks
    printf '%s\n' '{"hooks":{"preToolUse":[' > .github/hooks/dcg.json
    local before
    before=$(cat .github/hooks/dcg.json)

    configure_copilot
    local rc=$?

    log_test "configure_copilot rc: $rc"
    log_test "COPILOT_STATUS: $COPILOT_STATUS"
    log_test "COPILOT_FAILURE_REASON: ${COPILOT_FAILURE_REASON:-}"
    log_test "Hook content: $(cat .github/hooks/dcg.json)"

    [ "$rc" -eq 1 ]
    [ "$COPILOT_STATUS" = "failed" ]
    [[ "$COPILOT_FAILURE_REASON" == *"invalid"* ]]
    [ -z "$COPILOT_BACKUP" ]
    [ "$(cat .github/hooks/dcg.json)" = "$before" ]
}

@test "configure_copilot: malformed hooks object is preserved and reports failed" {
    log_test "Testing Copilot malformed hooks preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_copilot_repo
    mkdir -p .github/hooks
    cat > .github/hooks/dcg.json <<'EOF'
{
  "version": 1,
  "hooks": ["bad-shape"]
}
EOF
    local before
    before=$(cat .github/hooks/dcg.json)

    configure_copilot
    local rc=$?

    log_test "configure_copilot rc: $rc"
    log_test "COPILOT_STATUS: $COPILOT_STATUS"
    log_test "COPILOT_FAILURE_REASON: ${COPILOT_FAILURE_REASON:-}"
    log_test "Hook content: $(cat .github/hooks/dcg.json)"

    [ "$rc" -eq 1 ]
    [ "$COPILOT_STATUS" = "failed" ]
    [[ "$COPILOT_FAILURE_REASON" == *"invalid"* ]]
    [ -z "$COPILOT_BACKUP" ]
    [ "$(cat .github/hooks/dcg.json)" = "$before" ]
}

# ============================================================================
# Codex CLI Detection Tests
# ============================================================================

assert_codex_hooks_has_current_dcg() {
    [ -f "$CODEX_SETTINGS" ]
    grep -q '"PreToolUse"' "$CODEX_SETTINGS"
    grep -q '"matcher": "Bash"' "$CODEX_SETTINGS"
    grep -q "\"command\": \"$DEST/dcg\"" "$CODEX_SETTINGS"
}

assert_codex_first_bash_hook_command() {
    command -v python3 &>/dev/null || skip "python3 not available"

    python3 - "$CODEX_SETTINGS" "$1" <<'PYEOF'
import json
import sys

hooks_file = sys.argv[1]
expected = sys.argv[2]

with open(hooks_file, "r") as f:
    config = json.load(f)

for entry in config["hooks"]["PreToolUse"]:
    if entry.get("matcher") == "Bash":
        actual = entry["hooks"][0]["command"]
        if actual != expected:
            raise SystemExit(f"first Bash hook was {actual!r}, expected {expected!r}")
        raise SystemExit(0)

raise SystemExit("no Bash PreToolUse matcher found")
PYEOF
}

assert_codex_dcg_hook_count() {
    command -v python3 &>/dev/null || skip "python3 not available"

    python3 - "$CODEX_SETTINGS" "$1" <<'PYEOF'
import json
import os
import shlex
import sys

hooks_file = sys.argv[1]
expected = int(sys.argv[2])

with open(hooks_file, "r") as f:
    config = json.load(f)

count = 0
for entry in config.get("hooks", {}).get("PreToolUse", []):
    if not isinstance(entry, dict):
        continue
    for hook in entry.get("hooks", []):
        if not isinstance(hook, dict):
            continue
        command = hook.get("command")
        if not isinstance(command, str):
            continue
        try:
            parts = shlex.split(command)
        except ValueError:
            continue
        if parts:
            name = os.path.basename(parts[0])
            if name.endswith(".exe"):
                name = name[:-4]
            if name == "dcg":
                count += 1

if count != expected:
    raise SystemExit(f"dcg hook count was {count}, expected {expected}")
PYEOF
}

create_no_python_path() {
    local no_python_path="$TEST_TMPDIR/no-python-path"
    mkdir -p "$no_python_path"

    local tool
    for tool in dirname cp mv rm mkdir date grep; do
        ln -s "$(command -v "$tool")" "$no_python_path/$tool"
    done

    echo "$no_python_path"
}

log_codex_hooks_transition() {
    log_test "Codex hooks after: $(cat "$CODEX_SETTINGS" 2>/dev/null || echo 'missing')"
}

codex_post_tool_use_json() {
    command -v python3 &>/dev/null || skip "python3 not available"

    python3 - "$CODEX_SETTINGS" <<'PYEOF'
import json
import sys

with open(sys.argv[1], "r") as f:
    config = json.load(f)

post_tool_use = config.get("hooks", {}).get("PostToolUse")
print(json.dumps(post_tool_use, sort_keys=True, separators=(",", ":")))
PYEOF
}

@test "configure_codex: skips when not installed" {
    log_test "Testing Codex detection when not installed..."

    # Make sure .codex doesn't exist
    rm -rf "$HOME/.codex"

    configure_codex

    log_test "CODEX_STATUS: $CODEX_STATUS"

    # Should be skipped when not installed
    [ "$CODEX_STATUS" = "skipped" ]
}

@test "configure_codex: detects via .codex directory" {
    log_test "Testing Codex detection via .codex directory..."

    setup_mock_codex

    configure_codex

    log_test "CODEX_STATUS: $CODEX_STATUS"
    log_test "hooks.json: $(cat "$CODEX_SETTINGS" 2>/dev/null || echo 'missing')"

    [ "$CODEX_STATUS" = "created" ]
    assert_codex_hooks_has_current_dcg
    assert_codex_first_bash_hook_command "$DEST/dcg"
}

@test "configure_codex: detects via codex command" {
    log_test "Testing Codex detection via codex command..."

    # Create mock codex binary
    mkdir -p "$TEST_TMPDIR/bin"
    cat > "$TEST_TMPDIR/bin/codex" << 'EOF'
#!/bin/bash
echo "Codex CLI v1.0.0"
EOF
    chmod +x "$TEST_TMPDIR/bin/codex"
    export PATH="$TEST_TMPDIR/bin:$PATH"

    configure_codex

    log_test "CODEX_STATUS: $CODEX_STATUS"
    log_test "hooks.json: $(cat "$CODEX_SETTINGS" 2>/dev/null || echo 'missing')"

    [ "$CODEX_STATUS" = "created" ]
    assert_codex_hooks_has_current_dcg
    assert_codex_first_bash_hook_command "$DEST/dcg"
}

@test "configure_codex: is idempotent when current hook already exists" {
    log_test "Testing Codex idempotent already status..."

    setup_mock_codex

    configure_codex

    log_test "First CODEX_STATUS: $CODEX_STATUS"
    log_test "First hooks.json: $(cat "$CODEX_SETTINGS" 2>/dev/null || echo 'missing')"

    [ "$CODEX_STATUS" = "created" ]

    configure_codex

    log_test "Second CODEX_STATUS: $CODEX_STATUS"
    log_test "Second hooks.json: $(cat "$CODEX_SETTINGS" 2>/dev/null || echo 'missing')"

    [ "$CODEX_STATUS" = "already" ]
    assert_codex_hooks_has_current_dcg
    assert_codex_dcg_hook_count 1
}

@test "configure_codex: reorders current dcg hook to first" {
    log_test "Testing Codex reorders existing dcg hook to first..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_codex
    cat > "$CODEX_SETTINGS" << EOF
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "atuin history start"},
          {"type": "command", "command": "$DEST/dcg"}
        ]
      }
    ]
  }
}
EOF

    configure_codex

    log_test "CODEX_STATUS: $CODEX_STATUS"
    log_test "After hooks.json: $(cat "$CODEX_SETTINGS")"

    [ "$CODEX_STATUS" = "merged" ]
    assert_codex_hooks_has_current_dcg
    assert_codex_first_bash_hook_command "$DEST/dcg"
    assert_codex_dcg_hook_count 1
    grep -q "atuin history start" "$CODEX_SETTINGS"
}

@test "configure_codex: merges existing hooks and keeps dcg first" {
    log_test "Testing Codex merge with existing hooks..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_codex
    cat > "$CODEX_SETTINGS" <<'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "atuin history start"}
        ]
      },
      {
        "matcher": "Read",
        "hooks": [
          {"type": "command", "command": "echo read-hook"}
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "echo post-hook"}
        ]
      }
    ]
  },
  "theme": "dark"
}
EOF

    log_test "Before hooks.json: $(cat "$CODEX_SETTINGS")"

    configure_codex

    log_test "CODEX_STATUS: $CODEX_STATUS"
    log_test "After hooks.json: $(cat "$CODEX_SETTINGS")"

    [ "$CODEX_STATUS" = "merged" ]
    assert_codex_hooks_has_current_dcg
    assert_codex_first_bash_hook_command "$DEST/dcg"
    grep -q "atuin history start" "$CODEX_SETTINGS"
    grep -q "echo read-hook" "$CODEX_SETTINGS"
    grep -q "echo post-hook" "$CODEX_SETTINGS"
    grep -q '"theme": "dark"' "$CODEX_SETTINGS"
}

@test "configure_codex: updates stale dcg hook path" {
    log_test "Testing Codex stale dcg path update..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_codex
    cat > "$CODEX_SETTINGS" <<'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/old/bin/dcg"}
        ]
      }
    ]
  }
}
EOF

    log_test "Before hooks.json: $(cat "$CODEX_SETTINGS")"

    configure_codex

    log_test "CODEX_STATUS: $CODEX_STATUS"
    log_test "After hooks.json: $(cat "$CODEX_SETTINGS")"

    [ "$CODEX_STATUS" = "merged" ]
    assert_codex_hooks_has_current_dcg
    assert_codex_first_bash_hook_command "$DEST/dcg"
    if grep -q "/old/bin/dcg" "$CODEX_SETTINGS"; then
        return 1
    fi
    assert_codex_dcg_hook_count 1
}

@test "configure_codex: collapses duplicate and stale dcg hooks" {
    log_test "Testing Codex duplicate dcg hook cleanup..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_codex
    cat > "$CODEX_SETTINGS" <<EOF
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "$DEST/dcg"},
          {"type": "command", "command": "/old/bin/dcg"},
          {"type": "command", "command": "atuin history start"}
        ]
      }
    ]
  }
}
EOF

    log_test "Before hooks.json: $(cat "$CODEX_SETTINGS")"

    configure_codex

    log_test "CODEX_STATUS: $CODEX_STATUS"
    log_test "After hooks.json: $(cat "$CODEX_SETTINGS")"

    [ "$CODEX_STATUS" = "merged" ]
    assert_codex_hooks_has_current_dcg
    assert_codex_first_bash_hook_command "$DEST/dcg"
    assert_codex_dcg_hook_count 1
    grep -q "atuin history start" "$CODEX_SETTINGS"
    if grep -q "/old/bin/dcg" "$CODEX_SETTINGS"; then
        return 1
    fi
}

@test "configure_codex: Bash matcher with non-list hooks is preserved and reports failed" {
    log_test "Testing Codex malformed Bash hooks preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_codex
    seed_codex_hooks_json '{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": {"bad": "shape"}
      },
      {
        "matcher": "Read",
        "hooks": [
          {"type": "command", "command": "echo read-hook"}
        ]
      }
    ]
  }
}'

    configure_codex
    local rc=$?

    log_test "CODEX_STATUS: $CODEX_STATUS"
    log_test "CODEX_FAILURE_REASON: ${CODEX_FAILURE_REASON:-}"
    log_codex_hooks_transition

    [ "$rc" -eq 0 ]
    [ "$CODEX_STATUS" = "failed" ]
    [[ "$CODEX_FAILURE_REASON" == *"invalid"* ]]
    [ -z "$CODEX_BACKUP" ]
    assert_codex_hooks_unchanged
}

@test "install.ps1: malformed Codex Bash hooks is preserved and reports failed" {
    log_test "Testing PowerShell Codex installer malformed Bash hooks preservation..."
    local pwsh_bin
    pwsh_bin="$(PATH="${ORIGINAL_PATH:-$PATH}" command -v pwsh || true)"
    [ -n "$pwsh_bin" ] || skip "pwsh not available"

    setup_mock_codex
    seed_codex_hooks_json '{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": {"bad": "shape"}
      },
      {
        "matcher": "Read",
        "hooks": [
          {"type": "command", "command": "echo read-hook"}
        ]
      }
    ]
  }
}'

    run env DCG_INSTALL_PS1="$PROJECT_ROOT/install.ps1" DCG_DCG_PATH="$DEST/dcg.exe" "$pwsh_bin" -NoProfile -Command '
$ScriptPath = $env:DCG_INSTALL_PS1
$errors = $null
$tokens = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) {
  $errors | ForEach-Object { Write-Error $_ }
  exit 1
}
$ast.EndBlock.Statements |
  Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] } |
  ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }

try {
  Configure-CodexHook -DcgPath $env:DCG_DCG_PATH
  Write-Error "expected malformed Bash hooks to be rejected"
  exit 2
} catch {
  if ($_.Exception.Message -notlike "*Bash matcher hooks must contain a list*") {
    Write-Error "unexpected error: $($_.Exception.Message)"
    exit 3
  }
}
'

    log_test "pwsh install.ps1 status: $status"
    log_test "pwsh install.ps1 output: $output"

    [ "$status" -eq 0 ]
    assert_codex_hooks_unchanged
}

@test "configure_codex: invalid hooks.json is preserved and reports failed" {
    log_test "Testing Codex invalid hooks.json preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_codex
    printf '%s\n' '{"hooks":{"PreToolUse":[' > "$CODEX_SETTINGS"
    save_codex_hooks_snapshot

    configure_codex
    local rc=$?

    log_test "CODEX_STATUS: $CODEX_STATUS"
    log_test "CODEX_FAILURE_REASON: ${CODEX_FAILURE_REASON:-}"
    log_codex_hooks_transition

    [ "$rc" -eq 0 ]
    [ "$CODEX_STATUS" = "failed" ]
    [[ "$CODEX_FAILURE_REASON" == *"invalid"* ]]
    [ -z "$CODEX_BACKUP" ]
    assert_codex_hooks_unchanged
}

@test "configure_codex: non-object hooks is preserved and reports failed" {
    log_test "Testing Codex non-object hooks preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_codex
    seed_codex_hooks_json '{"hooks":["bad-shape"]}'

    configure_codex
    local rc=$?

    log_test "CODEX_STATUS: $CODEX_STATUS"
    log_test "CODEX_FAILURE_REASON: ${CODEX_FAILURE_REASON:-}"
    log_codex_hooks_transition

    [ "$rc" -eq 0 ]
    [ "$CODEX_STATUS" = "failed" ]
    [[ "$CODEX_FAILURE_REASON" == *"invalid"* ]]
    [ -z "$CODEX_BACKUP" ]
    assert_codex_hooks_unchanged
}

@test "configure_codex: non-list PreToolUse is preserved and reports failed" {
    log_test "Testing Codex non-list PreToolUse preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_codex
    seed_codex_hooks_json '{
  "hooks": {
    "PreToolUse": {"bad": "shape"},
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "atuin history end"}
        ]
      }
    ]
  }
}'

    configure_codex
    local rc=$?

    log_test "CODEX_STATUS: $CODEX_STATUS"
    log_test "CODEX_FAILURE_REASON: ${CODEX_FAILURE_REASON:-}"
    log_codex_hooks_transition

    [ "$rc" -eq 0 ]
    [ "$CODEX_STATUS" = "failed" ]
    [[ "$CODEX_FAILURE_REASON" == *"invalid"* ]]
    [ -z "$CODEX_BACKUP" ]
    assert_codex_hooks_unchanged
}

@test "configure_codex: fails without python3 and preserves existing hooks.json" {
    log_test "Testing Codex merge failure when python3 is unavailable..."

    setup_mock_codex
    cat > "$CODEX_SETTINGS" <<'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "atuin history start"}
        ]
      }
    ]
  }
}
EOF

    local before
    before=$(cat "$CODEX_SETTINGS")
    log_test "Before hooks.json: $before"

    # shellcheck disable=SC2031 # Bats runs each test in an isolated subshell.
    local saved_path="$PATH"
    PATH="$(create_no_python_path)"

    configure_codex
    local rc=$?

    PATH="$saved_path"

    local after
    after=$(cat "$CODEX_SETTINGS")
    log_test "CODEX_STATUS: $CODEX_STATUS"
    log_test "Return code: $rc"
    log_test "After hooks.json: $after"

    [ "$rc" -eq 0 ]
    [ "$CODEX_STATUS" = "failed" ]
    [[ "$CODEX_FAILURE_REASON" == *"python3"* ]]
    [ "$after" = "$before" ]
    [ -z "$CODEX_BACKUP" ]
    if grep -q "$DEST/dcg" "$CODEX_SETTINGS"; then
        return 1
    fi
}

@test "configure_codex + unconfigure_codex: clean setup round-trips idempotently" {
    log_test "Testing Codex clean install/uninstall repeated round trip..."

    setup_mock_codex

    configure_codex
    log_test "First CODEX_STATUS: $CODEX_STATUS"
    log_codex_hooks_transition

    [ "$CODEX_STATUS" = "created" ]
    assert_codex_hooks_has_current_dcg
    assert_codex_first_bash_hook_command "$DEST/dcg"

    run unconfigure_codex
    log_test "First unconfigure status: $status"
    log_test "First unconfigure output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    [[ "$output" == *"removed"* ]]
    assert_codex_hooks_deleted

    configure_codex
    log_test "Second CODEX_STATUS: $CODEX_STATUS"
    log_codex_hooks_transition

    [ "$CODEX_STATUS" = "created" ]
    assert_codex_hooks_has_current_dcg
    assert_codex_first_bash_hook_command "$DEST/dcg"

    configure_codex
    log_test "Third CODEX_STATUS: $CODEX_STATUS"
    log_codex_hooks_transition

    [ "$CODEX_STATUS" = "already" ]
    assert_codex_hooks_has_current_dcg

    local dcg_count
    dcg_count=$(grep -oF "$DEST/dcg" "$CODEX_SETTINGS" | wc -l)
    [ "$dcg_count" -eq 1 ]

    run unconfigure_codex
    log_test "Second unconfigure status: $status"
    log_test "Second unconfigure output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    [[ "$output" == *"removed"* ]]
    assert_codex_hooks_deleted

    run unconfigure_codex
    log_test "Extra unconfigure status: $status"
    log_test "Extra unconfigure output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    [ -z "$output" ]
    assert_codex_hooks_deleted
}

@test "configure_codex + unconfigure_codex: preserves atuin PostToolUse" {
    log_test "Testing Codex install/uninstall preserves atuin PostToolUse..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_codex
    cat > "$CODEX_SETTINGS" <<'EOF'
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "atuin history end"}
        ]
      }
    ]
  }
}
EOF

    local before_post
    before_post="$(codex_post_tool_use_json)"
    log_test "Before PostToolUse: $before_post"

    configure_codex
    log_test "CODEX_STATUS: $CODEX_STATUS"
    log_codex_hooks_transition

    [ "$CODEX_STATUS" = "merged" ]
    assert_codex_hooks_has_current_dcg
    assert_codex_first_bash_hook_command "$DEST/dcg"

    local after_install_post
    after_install_post="$(codex_post_tool_use_json)"
    log_test "After install PostToolUse: $after_install_post"
    [ "$after_install_post" = "$before_post" ]

    run unconfigure_codex
    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    [[ "$output" == *"removed"* ]]
    assert_codex_hooks_not_contains "$DEST/dcg"
    assert_codex_hooks_contains "PostToolUse"
    assert_codex_hooks_contains "atuin history end"

    local after_uninstall_post
    after_uninstall_post="$(codex_post_tool_use_json)"
    log_test "After uninstall PostToolUse: $after_uninstall_post"
    [ "$after_uninstall_post" = "$before_post" ]
}

@test "configure_codex + unconfigure_codex: replaces stale dcg path then removes it" {
    log_test "Testing Codex stale path update followed by uninstall..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_codex
    cat > "$CODEX_SETTINGS" <<'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/old/bin/dcg"}
        ]
      }
    ]
  }
}
EOF

    configure_codex
    log_test "CODEX_STATUS: $CODEX_STATUS"
    log_codex_hooks_transition

    [ "$CODEX_STATUS" = "merged" ]
    assert_codex_hooks_has_current_dcg
    assert_codex_first_bash_hook_command "$DEST/dcg"
    assert_codex_hooks_not_contains "/old/bin/dcg"

    run unconfigure_codex
    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    [[ "$output" == *"removed"* ]]
    assert_codex_hooks_deleted
}

@test "configure_codex + unconfigure_codex: malformed installed hooks do not panic" {
    log_test "Testing Codex uninstall after installed hooks become malformed..."

    setup_mock_codex

    configure_codex
    log_test "CODEX_STATUS: $CODEX_STATUS"
    log_codex_hooks_transition

    [ "$CODEX_STATUS" = "created" ]
    assert_codex_hooks_has_current_dcg

    printf '%s\n' '{"command": "dcg",' > "$CODEX_SETTINGS"
    save_codex_hooks_snapshot

    run unconfigure_codex
    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    [ -z "$output" ]
    [[ "$output" != *"Traceback"* ]]
    assert_codex_hooks_unchanged
}

@test "unconfigure_codex: deletes hooks.json when only dcg is present" {
    log_test "Testing Codex uninstall deletes dcg-only hooks.json..."
    command -v python3 &>/dev/null || skip "python3 not available"

    seed_codex_hooks_json '{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/usr/local/bin/dcg"}
        ]
      }
    ]
  }
}'

    run unconfigure_codex
    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    [[ "$output" == *"removed"* ]]
    assert_codex_hooks_deleted
}

@test "unconfigure_codex: preserves coexisting atuin hook in same Bash matcher" {
    log_test "Testing Codex uninstall preserves same-matcher non-dcg hook..."
    command -v python3 &>/dev/null || skip "python3 not available"

    seed_codex_hooks_json '{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/usr/local/bin/dcg"},
          {"type": "command", "command": "atuin history start"}
        ]
      }
    ]
  }
}'

    run unconfigure_codex
    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    assert_codex_hooks_contains "atuin history start"
    assert_codex_hooks_not_contains "/usr/local/bin/dcg"
}

@test "unconfigure_codex: preserves separate matcher block for atuin" {
    log_test "Testing Codex uninstall preserves separate matcher block..."
    command -v python3 &>/dev/null || skip "python3 not available"

    seed_codex_hooks_json '{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/usr/local/bin/dcg"}
        ]
      },
      {
        "matcher": "^Bash$",
        "hooks": [
          {"type": "command", "command": "atuin history start"}
        ]
      }
    ]
  }
}'

    run unconfigure_codex
    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    assert_codex_hooks_contains '"matcher": "^Bash$"'
    assert_codex_hooks_contains "atuin history start"
    assert_codex_hooks_not_contains "/usr/local/bin/dcg"
}

@test "unconfigure_codex: preserves non-Bash dcg command hook" {
    log_test "Testing Codex uninstall only removes Bash-owned dcg hooks..."
    command -v python3 &>/dev/null || skip "python3 not available"

    seed_codex_hooks_json '{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read",
        "hooks": [
          {"type": "command", "command": "/opt/read-hook/dcg"}
        ]
      },
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/usr/local/bin/dcg"},
          {"type": "command", "command": "atuin history start"}
        ]
      }
    ]
  }
}'

    run unconfigure_codex
    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    assert_codex_hooks_contains '"matcher": "Read"'
    assert_codex_hooks_contains "/opt/read-hook/dcg"
    assert_codex_hooks_contains "atuin history start"
    assert_codex_hooks_not_contains "/usr/local/bin/dcg\""
}

@test "unconfigure_codex: preserves PostToolUse when only PreToolUse had dcg" {
    log_test "Testing Codex uninstall preserves PostToolUse hooks..."
    command -v python3 &>/dev/null || skip "python3 not available"

    seed_codex_hooks_json '{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/usr/local/bin/dcg"}
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "atuin history end"}
        ]
      }
    ]
  }
}'

    run unconfigure_codex
    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    assert_codex_hooks_contains "PostToolUse"
    assert_codex_hooks_contains "atuin history end"
    assert_codex_hooks_not_contains "/usr/local/bin/dcg"
}

@test "unconfigure_codex: no-op when file has no dcg entries" {
    log_test "Testing Codex uninstall no-op without dcg entries..."
    command -v python3 &>/dev/null || skip "python3 not available"

    seed_codex_hooks_json '{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "atuin history start"}
        ]
      }
    ]
  }
}'

    run unconfigure_codex
    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    [ -z "$output" ]
    assert_codex_hooks_unchanged
}

@test "unconfigure_codex: no-op when file does not exist" {
    log_test "Testing Codex uninstall no-op without hooks.json..."

    mkdir -p "$HOME/.codex"
    [ ! -e "$CODEX_SETTINGS" ]

    run unconfigure_codex
    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    [ -z "$output" ]
    assert_codex_hooks_unchanged
}

@test "unconfigure_codex: malformed JSON leaves hooks.json unchanged" {
    log_test "Testing Codex uninstall leaves malformed JSON unchanged..."
    command -v python3 &>/dev/null || skip "python3 not available"

    mkdir -p "$HOME/.codex"
    printf '%s\n' '{"command": "dcg",' > "$CODEX_SETTINGS"
    save_codex_hooks_snapshot

    run unconfigure_codex
    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    [ -z "$output" ]
    assert_codex_hooks_unchanged
}

@test "unconfigure_codex: PreToolUse is not a list leaves hooks.json unchanged" {
    log_test "Testing Codex uninstall leaves non-list PreToolUse unchanged..."
    command -v python3 &>/dev/null || skip "python3 not available"

    seed_codex_hooks_json '{
  "hooks": {
    "PreToolUse": {
      "matcher": "Bash",
      "hooks": [
        {"type": "command", "command": "/usr/local/bin/dcg"}
      ]
    }
  }
}'

    run unconfigure_codex
    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    [ -z "$output" ]
    assert_codex_hooks_unchanged
}

@test "unconfigure_codex: hooks key is not a dict leaves hooks.json unchanged" {
    log_test "Testing Codex uninstall leaves non-dict hooks unchanged..."
    command -v python3 &>/dev/null || skip "python3 not available"

    seed_codex_hooks_json '{
  "hooks": [
    {"type": "command", "command": "/usr/local/bin/dcg"}
  ]
}'

    run unconfigure_codex
    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    [ -z "$output" ]
    assert_codex_hooks_unchanged
}

@test "unconfigure_codex: python3 unavailable returns 1 and preserves hooks.json" {
    log_test "Testing Codex uninstall failure without python3..."

    seed_codex_hooks_json '{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/usr/local/bin/dcg"}
        ]
      }
    ]
  }
}'

    local saved_path="$PATH"
    PATH="$(create_no_python_path)"

    run unconfigure_codex

    PATH="$saved_path"

    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 1 ]
    [[ "$output" == *"python3 not available"* ]]
    assert_codex_hooks_unchanged
}

@test "unconfigure_codex: read-only directory returns 1 and preserves hooks.json" {
    log_test "Testing Codex uninstall failure with read-only hooks directory..."
    command -v python3 &>/dev/null || skip "python3 not available"

    seed_codex_hooks_json '{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/usr/local/bin/dcg"}
        ]
      }
    ]
  }
}'

    chmod 500 "$HOME/.codex"
    run unconfigure_codex
    chmod 700 "$HOME/.codex"

    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 1 ]
    [[ "$output" == *"failed to update"* ]]
    assert_codex_hooks_unchanged
}

@test "unconfigure_codex: preserves dcg-helper while removing dcg" {
    log_test "Testing Codex uninstall preserves commands whose basename is not dcg..."
    command -v python3 &>/dev/null || skip "python3 not available"

    seed_codex_hooks_json '{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/usr/local/bin/dcg"},
          {"type": "command", "command": "/usr/local/bin/dcg-helper"}
        ]
      }
    ]
  }
}'

    run unconfigure_codex
    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    assert_codex_hooks_contains "dcg-helper"
    assert_codex_hooks_not_contains "/usr/local/bin/dcg\""
}

# ============================================================================
# Hermes Agent Configuration Tests (issue #110)
# ============================================================================

@test "configure_hermes: skips when not installed" {
    log_test "Testing Hermes skip when not installed..."
    HERMES_CONFIG="$HOME/.hermes/config.yaml"

    [ ! -d "$HOME/.hermes" ]
    ! command -v hermes >/dev/null 2>&1

    configure_hermes

    log_test "HERMES_STATUS: $HERMES_STATUS"
    [ "$HERMES_STATUS" = "skipped" ]
    [ ! -f "$HERMES_CONFIG" ]
}

@test "configure_hermes: creates config.yaml when ~/.hermes exists" {
    log_test "Testing Hermes config creation..."
    command -v python3 &>/dev/null || skip "python3 not available"
    python3 -c 'import yaml' &>/dev/null || skip "PyYAML not available"

    setup_mock_hermes

    configure_hermes

    log_test "HERMES_STATUS: $HERMES_STATUS"
    log_test "config.yaml: $(cat "$HERMES_CONFIG" 2>/dev/null || echo 'missing')"

    [ "$HERMES_STATUS" = "created" ]
    [ -f "$HERMES_CONFIG" ]
    assert_hermes_config_contains "pre_tool_call"
    assert_hermes_config_contains "matcher: \"terminal\""
    assert_hermes_config_contains "$DEST/dcg"
    # Auto-accept must be set so the hook fires in non-TTY runs.
    assert_hermes_config_contains "hooks_auto_accept: true"
}

@test "configure_hermes: is idempotent" {
    log_test "Testing Hermes install idempotency..."
    command -v python3 &>/dev/null || skip "python3 not available"
    python3 -c 'import yaml' &>/dev/null || skip "PyYAML not available"

    setup_mock_hermes

    configure_hermes
    [ "$HERMES_STATUS" = "created" ]

    local first_count
    first_count="$(hermes_dcg_pre_tool_call_count)"
    [ "$first_count" = "1" ]

    # Second run: must not produce any change.
    configure_hermes
    log_test "Second-run HERMES_STATUS: $HERMES_STATUS"
    [ "$HERMES_STATUS" = "already" ]

    local second_count
    second_count="$(hermes_dcg_pre_tool_call_count)"
    [ "$second_count" = "1" ]
}

@test "configure_hermes: merges into existing config without dropping user keys" {
    log_test "Testing Hermes merge preserves coexisting config..."
    command -v python3 &>/dev/null || skip "python3 not available"
    python3 -c 'import yaml' &>/dev/null || skip "PyYAML not available"

    setup_mock_hermes
    seed_hermes_config 'model:
  provider: openrouter
  name: NousResearch/Hermes-3-405B
hooks:
  post_tool_call:
    - matcher: "write_file"
      command: "/usr/local/bin/auto-format.sh"
hooks_auto_accept: false
'

    configure_hermes
    log_test "HERMES_STATUS: $HERMES_STATUS"
    log_test "config.yaml after merge: $(cat "$HERMES_CONFIG")"

    [ "$HERMES_STATUS" = "merged" ]

    # User's pre-existing entries must survive.
    assert_hermes_config_contains "post_tool_call"
    assert_hermes_config_contains "auto-format.sh"
    assert_hermes_config_contains "openrouter"
    assert_hermes_config_contains "Hermes-3-405B"

    # User's explicit hooks_auto_accept: false MUST be preserved (we only
    # set when not already set).
    assert_hermes_config_contains "hooks_auto_accept: false"

    # dcg's hook must be present and unique.
    assert_hermes_config_contains "$DEST/dcg"
    [ "$(hermes_dcg_pre_tool_call_count)" = "1" ]
}

@test "configure_hermes: replaces stale dcg path and dedupes duplicates" {
    log_test "Testing Hermes stale path rewrite..."
    command -v python3 &>/dev/null || skip "python3 not available"
    python3 -c 'import yaml' &>/dev/null || skip "PyYAML not available"

    setup_mock_hermes
    seed_hermes_config "hooks:
  pre_tool_call:
    - matcher: \"terminal\"
      command: \"/old/stale/path/dcg\"
      timeout: 10
    - matcher: \"terminal\"
      command: \"/another/dcg\"
      timeout: 5
    - matcher: \"web_search\"
      command: \"/usr/local/bin/log-search.sh\"
"

    configure_hermes
    log_test "HERMES_STATUS: $HERMES_STATUS"
    log_test "config.yaml after rewrite: $(cat "$HERMES_CONFIG")"

    [ "$HERMES_STATUS" = "merged" ]

    # New dcg path inserted.
    assert_hermes_config_contains "$DEST/dcg"
    # Both stale dcg entries removed.
    assert_hermes_config_not_contains "/old/stale/path/dcg"
    assert_hermes_config_not_contains "/another/dcg"
    # Coexisting non-dcg hook preserved.
    assert_hermes_config_contains "log-search.sh"
    [ "$(hermes_dcg_pre_tool_call_count)" = "1" ]
}

@test "configure_hermes: refuses to clobber malformed YAML" {
    log_test "Testing Hermes invalid YAML preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"
    python3 -c 'import yaml' &>/dev/null || skip "PyYAML not available"

    setup_mock_hermes
    # Deliberately broken YAML (unbalanced quotes / colons).
    seed_hermes_config 'hooks:
  pre_tool_call:
    - matcher: "missing-close
      command: /usr/local/bin/something
'

    configure_hermes

    log_test "HERMES_STATUS: $HERMES_STATUS"
    log_test "HERMES_FAILURE_REASON: $HERMES_FAILURE_REASON"

    [ "$HERMES_STATUS" = "failed" ]
    [[ "$HERMES_FAILURE_REASON" == *"invalid"* ]]
    # File must be unchanged.
    grep -qF "missing-close" "$HERMES_CONFIG"
}

@test "configure_hermes: rejects non-mapping hooks block" {
    log_test "Testing Hermes non-mapping hooks rejection..."
    command -v python3 &>/dev/null || skip "python3 not available"
    python3 -c 'import yaml' &>/dev/null || skip "PyYAML not available"

    setup_mock_hermes
    seed_hermes_config 'hooks:
  - this should be a mapping not a list
'

    configure_hermes

    log_test "HERMES_STATUS: $HERMES_STATUS"
    [ "$HERMES_STATUS" = "failed" ]
    # Original file preserved verbatim.
    grep -qF "this should be a mapping not a list" "$HERMES_CONFIG"
}

@test "configure_hermes: does not treat non-dcg hooks as installed" {
    log_test "Testing Hermes substring rejection..."
    command -v python3 &>/dev/null || skip "python3 not available"
    python3 -c 'import yaml' &>/dev/null || skip "PyYAML not available"

    setup_mock_hermes
    # `dcg-tools` is NOT dcg even though the substring matches.
    seed_hermes_config 'hooks:
  pre_tool_call:
    - matcher: "terminal"
      command: "/usr/local/bin/dcg-tools"
'

    configure_hermes
    log_test "HERMES_STATUS: $HERMES_STATUS"
    log_test "config.yaml: $(cat "$HERMES_CONFIG")"

    [ "$HERMES_STATUS" = "merged" ]
    # The fake `dcg-tools` entry is NOT a dcg command, so it must be preserved.
    assert_hermes_config_contains "dcg-tools"
    # Real dcg added.
    assert_hermes_config_contains "$DEST/dcg"
    # Exactly one real dcg entry (basename match, not substring).
    [ "$(hermes_dcg_pre_tool_call_count)" = "1" ]
}

@test "unconfigure_hermes: removes only dcg entries and leaves siblings intact" {
    log_test "Testing Hermes uninstall..."
    command -v python3 &>/dev/null || skip "python3 not available"
    python3 -c 'import yaml' &>/dev/null || skip "PyYAML not available"

    setup_mock_hermes
    # Seed a config with dcg PLUS a sibling hook the user wants to keep.
    seed_hermes_config "hooks:
  pre_tool_call:
    - matcher: \"terminal\"
      command: \"$DEST/dcg\"
      timeout: 30
    - matcher: \"web_search\"
      command: \"/usr/local/bin/log-search.sh\"
hooks_auto_accept: true
"

    run unconfigure_hermes
    log_test "unconfigure_hermes status: $status"
    log_test "config.yaml after uninstall: $(cat "$HERMES_CONFIG" 2>/dev/null || echo 'missing')"

    [ "$status" -eq 0 ]
    [ -f "$HERMES_CONFIG" ]

    # dcg gone.
    assert_hermes_config_not_contains "$DEST/dcg"
    # Sibling preserved.
    assert_hermes_config_contains "log-search.sh"
    # We deliberately do NOT touch hooks_auto_accept on uninstall.
    assert_hermes_config_contains "hooks_auto_accept: true"
}

@test "unconfigure_hermes: noop on missing config" {
    log_test "Testing Hermes uninstall with no config..."

    HERMES_CONFIG="$HOME/.hermes/config.yaml"
    [ ! -f "$HERMES_CONFIG" ]

    run unconfigure_hermes
    log_test "unconfigure_hermes status: $status"
    [ "$status" -eq 0 ]
}

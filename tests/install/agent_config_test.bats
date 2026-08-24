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

    # Create settings with dcg hook already present under the canonical matcher
    cat > "$CLAUDE_SETTINGS" << EOF
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell",
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

@test "configure_claude_code: migrates a legacy Bash-only dcg hook (#226)" {
    log_test "Testing Claude Code legacy Bash matcher migration..."
    command -v python3 &>/dev/null || skip "python3 not available"

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"

    # Pre-#226 registration: the matcher covers only Bash, so Claude Code's
    # native-Windows PowerShell tool ran completely unguarded.
    cat > "$CLAUDE_SETTINGS" << EOF
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "$DEST/dcg"},
          {"type": "command", "command": "atuin history start"}
        ]
      }
    ]
  }
}
EOF

    configure_claude_code "$CLAUDE_SETTINGS" "0"

    log_test "CLAUDE_STATUS: $CLAUDE_STATUS"
    log_test "After: $(cat "$CLAUDE_SETTINGS")"

    # A legacy entry must be migrated, never reported as already current.
    [ "$CLAUDE_STATUS" = "merged" ]

    python3 - "$CLAUDE_SETTINGS" "$DEST/dcg" <<'PY'
import json
import sys

settings_file, dcg_path = sys.argv[1:3]
with open(settings_file, "r") as f:
    settings = json.load(f)

entries = settings["hooks"]["PreToolUse"]
commands = [
    hook.get("command")
    for entry in entries
    for hook in entry.get("hooks", [])
    if isinstance(hook, dict)
]

# Exactly one dcg hook, hoisted first, under a matcher that covers PowerShell.
assert commands.count(dcg_path) == 1, commands
assert entries[0]["matcher"] == "Bash|PowerShell", entries
assert entries[0]["hooks"][0]["command"] == dcg_path, entries
# The user's own hook keeps its original, unwidened Bash matcher.
bash_entries = [e for e in entries if e.get("matcher") == "Bash"]
assert len(bash_entries) == 1, entries
assert [h["command"] for h in bash_entries[0]["hooks"]] == ["atuin history start"], entries
PY

    # Re-running settles: the migrated shape is now current.
    configure_claude_code "$CLAUDE_SETTINGS" "0"
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

commands = [
    hook.get("command")
    for entry in settings["hooks"]["PreToolUse"]
    for hook in entry.get("hooks", [])
    if isinstance(hook, dict)
]

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

commands = [
    hook.get("command")
    for entry in settings["hooks"]["PreToolUse"]
    for hook in entry.get("hooks", [])
    if isinstance(hook, dict)
]

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
    for tool in dirname mkdir cp date grep sed tr rm mv cat; do
        ln -s "$(command -v "$tool")" "$no_python_path/$tool"
    done

    local old_path="$PATH"
    PATH="$no_python_path"
    local rc=0
    configure_claude_code "$CLAUDE_SETTINGS" "0" || rc=$?
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
        "matcher": "Bash|PowerShell",
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
    for tool in dirname mkdir cp date grep sed tr rm mv cat; do
        ln -s "$(command -v "$tool")" "$no_python_path/$tool"
    done

    local old_path="$PATH"
    PATH="$no_python_path"
    local rc=0
    configure_claude_code "$CLAUDE_SETTINGS" "0" || rc=$?
    PATH="$old_path"

    log_test "CLAUDE_STATUS: $CLAUDE_STATUS rc=$rc"

    [ "$rc" -eq 0 ]
    [ "$CLAUDE_STATUS" = "already" ]
}

@test "configure_claude_code: no-python fallback recognizes minified dcg hook" {
    log_test "Testing Claude Code no-python fallback with minified JSON..."

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"
    printf '{"hooks":{"PreToolUse":[{"matcher":"Bash|PowerShell","hooks":[{"type":"command","command":"%s"}]}]}}\n' "$DEST/dcg" > "$CLAUDE_SETTINGS"

    local no_python_path="$TEST_TMPDIR/no-python-bin"
    mkdir -p "$no_python_path"
    local tool
    for tool in dirname mkdir cp date grep sed tr rm mv cat; do
        ln -s "$(command -v "$tool")" "$no_python_path/$tool"
    done

    local old_path="$PATH"
    PATH="$no_python_path"
    local rc=0
    configure_claude_code "$CLAUDE_SETTINGS" "0" || rc=$?
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
    for tool in dirname mkdir cp date grep sed tr rm mv cat; do
        ln -s "$(command -v "$tool")" "$no_python_path/$tool"
    done

    local old_path="$PATH"
    PATH="$no_python_path"
    local rc=0
    configure_claude_code "$CLAUDE_SETTINGS" "0" || rc=$?
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
    for tool in dirname mkdir cp date grep sed tr rm mv cat; do
        ln -s "$(command -v "$tool")" "$no_python_path/$tool"
    done

    local old_path="$PATH"
    PATH="$no_python_path"
    local rc=0
    configure_gemini "$GEMINI_SETTINGS" || rc=$?
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

    local rc=0
    configure_gemini "$GEMINI_SETTINGS" || rc=$?

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

    local rc=0
    configure_gemini "$GEMINI_SETTINGS" || rc=$?

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

    local rc=0
    configure_gemini "$GEMINI_SETTINGS" || rc=$?

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

    local rc=0
    configure_gemini "$GEMINI_SETTINGS" || rc=$?

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

    local rc=0
    configure_cursor || rc=$?

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

    local rc=0
    configure_cursor || rc=$?

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

    local rc=0
    configure_cursor || rc=$?

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
    export COPILOT_HOME="$HOME/.copilot"

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

    # The canonical stored form is the double-quoted binary path (survives a
    # DEST containing spaces), matching configure_posit_assistant.
    python3 - "$COPILOT_HOOK_FILE" "\"$DEST/dcg\"" "$1" <<'PYEOF'
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

@test "configure_copilot: adds user-level hook" {
    log_test "Testing Copilot hook creation..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_copilot_repo

    configure_copilot

    log_test "COPILOT_STATUS: $COPILOT_STATUS"
    log_test "Hook file: ${COPILOT_HOOK_FILE:-}"
    log_test "Hook content: $(cat "$COPILOT_HOOK_FILE" 2>/dev/null || echo 'missing')"

    [ "$COPILOT_STATUS" = "created" ]
    [ -f "$COPILOT_HOOK_FILE" ]
    assert_copilot_first_hook "\"$DEST/dcg\""
    assert_copilot_dcg_hook_count 1
}

@test "configure_copilot: does not treat dcg substring commands as installed" {
    log_test "Testing Copilot exact dcg hook detection..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_copilot_repo
    mkdir -p "$COPILOT_HOME/hooks"
    cat > "$COPILOT_HOME/hooks/dcg.json" <<'EOF'
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
    assert_copilot_first_hook "\"$DEST/dcg\""
    assert_copilot_dcg_hook_count 1
    grep -qF "/opt/dcgrep/bin/scan" "$COPILOT_HOOK_FILE"
    grep -qF "pwsh-dcg-helper" "$COPILOT_HOOK_FILE"
}

@test "configure_copilot: reorders current dcg hook to first and removes duplicates" {
    log_test "Testing Copilot dcg hook reorder and duplicate cleanup..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_copilot_repo
    mkdir -p "$COPILOT_HOME/hooks"
    cat > "$COPILOT_HOME/hooks/dcg.json" << EOF
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
    assert_copilot_first_hook "\"$DEST/dcg\""
    assert_copilot_dcg_hook_count 1
    grep -qF "atuin history start" "$COPILOT_HOOK_FILE"
}

@test "configure_copilot: preserves mixed hook entries when refreshing a dcg platform command" {
    log_test "Testing Copilot mixed platform hook preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_copilot_repo
    mkdir -p "$COPILOT_HOME/hooks"
    cat > "$COPILOT_HOME/hooks/dcg.json" << EOF
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
    assert_copilot_first_hook "\"$DEST/dcg\""
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
    mkdir -p "$COPILOT_HOME/hooks"
    cat > "$COPILOT_HOME/hooks/dcg.json" <<'EOF'
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
    assert_copilot_first_hook "\"$DEST/dcg\""
    assert_copilot_dcg_hook_count 1
    grep -qF "postToolUse" "$COPILOT_HOOK_FILE"
    grep -qF "atuin history end" "$COPILOT_HOOK_FILE"
}

@test "configure_copilot: invalid hook file is preserved and reports failed" {
    log_test "Testing Copilot invalid hook file preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_copilot_repo
    mkdir -p "$COPILOT_HOME/hooks"
    printf '%s\n' '{"hooks":{"preToolUse":[' > "$COPILOT_HOME/hooks/dcg.json"
    local before
    before=$(cat "$COPILOT_HOME/hooks/dcg.json")

    local rc=0
    configure_copilot || rc=$?

    log_test "configure_copilot rc: $rc"
    log_test "COPILOT_STATUS: $COPILOT_STATUS"
    log_test "COPILOT_FAILURE_REASON: ${COPILOT_FAILURE_REASON:-}"
    log_test "Hook content: $(cat "$COPILOT_HOME/hooks/dcg.json")"

    [ "$rc" -eq 1 ]
    [ "$COPILOT_STATUS" = "failed" ]
    [[ "$COPILOT_FAILURE_REASON" == *"invalid"* ]]
    [ -z "$COPILOT_BACKUP" ]
    [ "$(cat "$COPILOT_HOME/hooks/dcg.json")" = "$before" ]
}

@test "configure_copilot: malformed hooks object is preserved and reports failed" {
    log_test "Testing Copilot malformed hooks preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_copilot_repo
    mkdir -p "$COPILOT_HOME/hooks"
    cat > "$COPILOT_HOME/hooks/dcg.json" <<'EOF'
{
  "version": 1,
  "hooks": ["bad-shape"]
}
EOF
    local before
    before=$(cat "$COPILOT_HOME/hooks/dcg.json")

    local rc=0
    configure_copilot || rc=$?

    log_test "configure_copilot rc: $rc"
    log_test "COPILOT_STATUS: $COPILOT_STATUS"
    log_test "COPILOT_FAILURE_REASON: ${COPILOT_FAILURE_REASON:-}"
    log_test "Hook content: $(cat "$COPILOT_HOME/hooks/dcg.json")"

    [ "$rc" -eq 1 ]
    [ "$COPILOT_STATUS" = "failed" ]
    [[ "$COPILOT_FAILURE_REASON" == *"invalid"* ]]
    [ -z "$COPILOT_BACKUP" ]
    [ "$(cat "$COPILOT_HOME/hooks/dcg.json")" = "$before" ]
}

@test "configure_copilot: adopts existing PascalCase PreToolUse key without duplicating it" {
    log_test "Testing Copilot PascalCase key adoption (#253)..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_copilot_repo
    mkdir -p "$COPILOT_HOME/hooks"
    cat > "$COPILOT_HOME/hooks/dcg.json" <<'EOF'
{
  "version": 1,
  "hooks": {
    "PreToolUse": [
      {
        "type": "command",
        "bash": "audit-pretool",
        "powershell": "audit-pretool.exe",
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
    python3 - "$COPILOT_HOOK_FILE" "\"$DEST/dcg\"" <<'PYEOF'
import json
import sys

hook_file, dcg_path = sys.argv[1:3]
with open(hook_file, "r") as f:
    config = json.load(f)

keys = [k for k in config["hooks"] if k.lower() == "pretooluse"]
if keys != ["PreToolUse"]:
    raise SystemExit(
        f"expected exactly one hooks key adopting the file's PascalCase spelling, found {keys!r}"
    )

pre_tool = config["hooks"]["PreToolUse"]
if pre_tool[0].get("bash") != dcg_path or pre_tool[0].get("powershell") != dcg_path:
    raise SystemExit(f"first hook is not the current dcg entry: {pre_tool[0]!r}")
if len(pre_tool) != 2 or pre_tool[1].get("bash") != "audit-pretool":
    raise SystemExit(f"non-dcg entry was not preserved intact: {pre_tool!r}")
PYEOF
}

@test "configure_copilot: repairs duplicated casing keys into one canonical key" {
    log_test "Testing Copilot duplicate-casing repair (#253)..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_copilot_repo
    mkdir -p "$COPILOT_HOME/hooks"
    cat > "$COPILOT_HOME/hooks/dcg.json" <<'EOF'
{
  "version": 1,
  "hooks": {
    "PreToolUse": [
      {
        "type": "command",
        "bash": "/old/bin/dcg",
        "powershell": "/old/bin/dcg",
        "cwd": ".",
        "timeoutSec": 30
      },
      {
        "type": "command",
        "bash": "audit-pretool",
        "powershell": "audit-pretool.exe"
      }
    ],
    "preToolUse": [
      {
        "type": "command",
        "bash": "/stale/bin/dcg",
        "powershell": "/stale/bin/dcg",
        "cwd": ".",
        "timeoutSec": 30
      },
      {
        "type": "command",
        "bash": "atuin history start",
        "powershell": "atuin history start"
      }
    ]
  }
}
EOF

    configure_copilot

    log_test "COPILOT_STATUS: $COPILOT_STATUS"
    log_test "Hook content: $(cat "$COPILOT_HOOK_FILE")"

    [ "$COPILOT_STATUS" = "merged" ]
    assert_copilot_first_hook "\"$DEST/dcg\""
    assert_copilot_dcg_hook_count 1
    python3 - "$COPILOT_HOOK_FILE" <<'PYEOF'
import json
import sys

with open(sys.argv[1], "r") as f:
    config = json.load(f)

keys = [k for k in config["hooks"] if k.lower() == "pretooluse"]
if keys != ["preToolUse"]:
    raise SystemExit(
        f"expected the single canonical camelCase key after repair, found {keys!r}"
    )

bashes = [e.get("bash") for e in config["hooks"]["preToolUse"]]
for expected in ("audit-pretool", "atuin history start"):
    if expected not in bashes:
        raise SystemExit(f"non-dcg entry {expected!r} was dropped: {bashes!r}")
PYEOF
}

@test "configure_copilot: spaced DEST is quoted, idempotent, and uninstallable" {
    log_test "Testing Copilot hook with a DEST containing spaces (#253-adjacent)..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_copilot_repo

    # Reinstall the mock dcg under a destination directory containing a space.
    DEST="$TEST_TMPDIR/spaced bin"
    mkdir -p "$DEST"
    cat > "$DEST/dcg" << 'MOCKEOF'
#!/bin/bash
echo "dcg 1.0.0"
MOCKEOF
    chmod +x "$DEST/dcg"

    configure_copilot
    log_test "First run status: $COPILOT_STATUS"
    log_test "Hook content: $(cat "$COPILOT_HOOK_FILE")"
    [ "$COPILOT_STATUS" = "created" ]
    assert_copilot_first_hook "\"$DEST/dcg\""
    assert_copilot_dcg_hook_count 1

    # Re-run: the quoted command must round-trip through the shlex-based
    # dedupe as the current dcg entry — not get duplicated.
    configure_copilot
    log_test "Second run status: $COPILOT_STATUS"
    log_test "Hook content: $(cat "$COPILOT_HOOK_FILE")"
    [ "$COPILOT_STATUS" = "already" ]
    assert_copilot_dcg_hook_count 1

    # Uninstall must recognize the quoted spaced path too; the dcg-dedicated
    # hook file empties out and is removed entirely.
    run unconfigure_copilot
    log_test "unconfigure_copilot status: $status output: $output"
    [ "$status" -eq 0 ]
    [ ! -e "$COPILOT_HOME/hooks/dcg.json" ]
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

    local rc=0
    configure_codex || rc=$?

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

    local rc=0
    configure_codex || rc=$?

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

    local rc=0
    configure_codex || rc=$?

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

    local rc=0
    configure_codex || rc=$?

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

    local rc=0
    configure_codex || rc=$?

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

@test "unconfigure_codex: removes wrong-matcher dcg command hook" {
    log_test "Testing Codex uninstall repairs wrong-matcher dcg hooks..."
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
    assert_codex_hooks_not_contains '"matcher": "Read"'
    assert_codex_hooks_not_contains "/opt/read-hook/dcg"
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

# ============================================================================
# Posit Assistant Configuration Tests
#
# Posit Assistant reads Claude-Code-compatible PreToolUse hooks from
# ~/.posit/assistant/settings.json. Three wire details are asserted on purpose
# because getting any of them wrong yields a hook that sits in the file but
# never fires (or breaks on a path with spaces):
#   - the matcher is lowercase "bash|powershell" (a simple matcher is an exact
#     match against the tool name; both shell-tool names are covered);
#   - only documented handler fields are emitted (type/command/timeout, no
#     `shell` field) and the command path is quoted for shell-form execution;
#   - `timeout` is in seconds.
# ============================================================================

@test "configure_posit_assistant: skips when not installed" {
    log_test "Testing Posit Assistant skip when not installed..."

    POSIT_ASSISTANT_SETTINGS="$HOME/.posit/assistant/settings.json"
    [ ! -d "$HOME/.posit" ]
    ! command -v pa >/dev/null 2>&1

    configure_posit_assistant

    log_test "POSIT_ASSISTANT_STATUS: $POSIT_ASSISTANT_STATUS"
    [ "$POSIT_ASSISTANT_STATUS" = "skipped" ]
    [ ! -e "$POSIT_ASSISTANT_SETTINGS" ]
    # A skip must not create the config directory either.
    [ ! -d "$HOME/.posit" ]
}

@test "configure_posit_assistant: creates settings.json when ~/.posit/assistant exists" {
    log_test "Testing Posit Assistant settings creation..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_posit_assistant

    configure_posit_assistant

    log_test "POSIT_ASSISTANT_STATUS: $POSIT_ASSISTANT_STATUS"
    log_test "settings.json: $(cat "$POSIT_ASSISTANT_SETTINGS" 2>/dev/null || echo 'missing')"

    [ "$POSIT_ASSISTANT_STATUS" = "created" ]
    [ -f "$POSIT_ASSISTANT_SETTINGS" ]
    assert_posit_assistant_settings_valid_json
    assert_posit_assistant_settings_contains '"PreToolUse"'
    # Lowercase matcher covering both shell-tool names.
    assert_posit_assistant_settings_contains '"matcher": "bash|powershell"'
    # The command path is stored quoted so spaces survive shell-form execution.
    assert_posit_assistant_settings_contains "$DEST/dcg"
    [ "$(posit_assistant_first_group_first_command)" = "\"$DEST/dcg\"" ]
    assert_posit_assistant_settings_contains '"timeout": 10'
    # Only documented handler fields; `shell` is not one of them.
    assert_posit_assistant_settings_not_contains '"shell"'
    [ "$AUTO_CONFIGURED" = "1" ]
}

@test "configure_posit_assistant: treats an existing empty settings.json as create-fresh" {
    log_test "Testing Posit Assistant empty settings.json handling..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_posit_assistant
    # An existing 0-byte file (e.g. left behind by a crashed editor or a
    # `touch`) must configure like a fresh install, not fail as invalid.
    : > "$POSIT_ASSISTANT_SETTINGS"

    configure_posit_assistant

    log_test "POSIT_ASSISTANT_STATUS: $POSIT_ASSISTANT_STATUS"
    log_test "settings.json: $(cat "$POSIT_ASSISTANT_SETTINGS" 2>/dev/null || echo 'missing')"

    [ "$POSIT_ASSISTANT_STATUS" = "created" ]
    assert_posit_assistant_settings_valid_json
    [ "$(posit_assistant_first_group_first_command)" = "\"$DEST/dcg\"" ]

    # Whitespace-only content is the same case.
    printf '  \n\t\n' > "$POSIT_ASSISTANT_SETTINGS"
    configure_posit_assistant
    log_test "Whitespace-only rerun status: $POSIT_ASSISTANT_STATUS"
    [ "$POSIT_ASSISTANT_STATUS" = "created" ]
    assert_posit_assistant_settings_valid_json
    [ "$(posit_assistant_first_group_first_command)" = "\"$DEST/dcg\"" ]
}

@test "configure_posit_assistant: detects a bare pa client on PATH" {
    log_test "Testing Posit Assistant detection via the pa client..."
    command -v python3 &>/dev/null || skip "python3 not available"

    POSIT_ASSISTANT_SETTINGS="$HOME/.posit/assistant/settings.json"
    printf '#!/bin/bash\necho "pa 1.2.3"\n' > "$TEST_TMPDIR/bin/pa"
    chmod +x "$TEST_TMPDIR/bin/pa"

    configure_posit_assistant

    log_test "POSIT_ASSISTANT_STATUS: $POSIT_ASSISTANT_STATUS"
    [ "$POSIT_ASSISTANT_STATUS" = "created" ]
    [ -f "$POSIT_ASSISTANT_SETTINGS" ]
}

@test "configure_posit_assistant: detects the legacy ~/.positai config dir" {
    log_test "Testing Posit Assistant detection via the legacy config dir..."
    command -v python3 &>/dev/null || skip "python3 not available"

    POSIT_ASSISTANT_SETTINGS="$HOME/.posit/assistant/settings.json"
    mkdir -p "$HOME/.positai"

    configure_posit_assistant

    log_test "POSIT_ASSISTANT_STATUS: $POSIT_ASSISTANT_STATUS"
    [ "$POSIT_ASSISTANT_STATUS" = "created" ]
    # The hook still lands in the CURRENT location, not the legacy one.
    [ -f "$POSIT_ASSISTANT_SETTINGS" ]
    [ ! -e "$HOME/.positai/settings.json" ]
}

@test "configure_posit_assistant: is idempotent" {
    log_test "Testing Posit Assistant install idempotency..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_posit_assistant

    configure_posit_assistant
    [ "$POSIT_ASSISTANT_STATUS" = "created" ]
    local first
    first="$(cat "$POSIT_ASSISTANT_SETTINGS")"

    POSIT_ASSISTANT_STATUS=""
    POSIT_ASSISTANT_BACKUP=""
    configure_posit_assistant

    log_test "Second-run POSIT_ASSISTANT_STATUS: $POSIT_ASSISTANT_STATUS"
    [ "$POSIT_ASSISTANT_STATUS" = "already" ]
    [ "$first" = "$(cat "$POSIT_ASSISTANT_SETTINGS")" ]
    # An unchanged reinstall must not litter the directory with backups.
    [ -z "$POSIT_ASSISTANT_BACKUP" ]
    [ "$(posit_assistant_dcg_hook_count)" = "1" ]
}

@test "configure_posit_assistant: preserves unrelated settings, groups, and events" {
    log_test "Testing Posit Assistant merge preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_posit_assistant
    seed_posit_assistant_settings '{
  "model": "keep-me",
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "bash,edit",
        "hooks": [
          { "type": "command", "command": "/usr/local/bin/audit-log" }
        ]
      }
    ],
    "SessionStart": [
      { "hooks": [ { "type": "command", "command": "/usr/local/bin/greet" } ] }
    ]
  }
}'

    configure_posit_assistant
    log_test "POSIT_ASSISTANT_STATUS: $POSIT_ASSISTANT_STATUS"
    log_test "settings.json: $(cat "$POSIT_ASSISTANT_SETTINGS")"

    [ "$POSIT_ASSISTANT_STATUS" = "merged" ]
    [ -f "$POSIT_ASSISTANT_BACKUP" ]
    assert_posit_assistant_settings_contains '"model"'
    assert_posit_assistant_settings_contains 'keep-me'
    # The user's comma-separated matcher group is preserved verbatim rather
    # than consolidated into ours (hook config is additive).
    assert_posit_assistant_settings_contains '"bash,edit"'
    assert_posit_assistant_settings_contains 'audit-log'
    assert_posit_assistant_settings_contains 'greet'
    [ "$(posit_assistant_dcg_hook_count)" = "1" ]
    # dcg's group sits first so a denial fires before other hooks.
    [ "$(posit_assistant_first_group_matcher)" = "bash|powershell" ]
    [ "$(posit_assistant_first_group_first_command)" = "\"$DEST/dcg\"" ]
    [ "$(posit_assistant_group_count)" = "2" ]
}

@test "configure_posit_assistant: replaces stale dcg paths without duplicating" {
    log_test "Testing Posit Assistant stale-path repair..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_posit_assistant
    seed_posit_assistant_settings '{
  "hooks": {
    "PreToolUse": [
      { "matcher": "bash", "hooks": [ { "type": "command", "command": "/old/path/dcg" } ] },
      { "matcher": "bash|powershell", "hooks": [ { "type": "command", "command": "\"/another/dcg\"", "timeout": 10 } ] }
    ]
  }
}'

    configure_posit_assistant
    log_test "POSIT_ASSISTANT_STATUS: $POSIT_ASSISTANT_STATUS"
    log_test "settings.json: $(cat "$POSIT_ASSISTANT_SETTINGS")"

    [ "$POSIT_ASSISTANT_STATUS" = "merged" ]
    assert_posit_assistant_settings_not_contains '/old/path/dcg'
    assert_posit_assistant_settings_not_contains '/another/dcg'
    assert_posit_assistant_settings_contains "$DEST/dcg"
    [ "$(posit_assistant_dcg_hook_count)" = "1" ]
    # Groups that existed only to run dcg are pruned, not left empty.
    [ "$(posit_assistant_group_count)" = "1" ]
}

@test "configure_posit_assistant: preserves a lookalike tool whose name contains dcg" {
    log_test "Testing Posit Assistant basename matching..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_posit_assistant
    seed_posit_assistant_settings '{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "bash",
        "hooks": [
          { "type": "command", "command": "/opt/dcgrep/bin/dcgworkflow --scan" }
        ]
      }
    ]
  }
}'

    configure_posit_assistant
    log_test "settings.json: $(cat "$POSIT_ASSISTANT_SETTINGS")"

    [ "$POSIT_ASSISTANT_STATUS" = "merged" ]
    assert_posit_assistant_settings_contains 'dcgworkflow'
    # Only the real dcg counts.
    [ "$(posit_assistant_dcg_hook_count)" = "1" ]
    [ "$(posit_assistant_group_count)" = "2" ]
}

@test "configure_posit_assistant: leaves invalid JSON untouched" {
    log_test "Testing Posit Assistant invalid-JSON refusal..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_posit_assistant
    seed_posit_assistant_settings '{ this is not json'

    configure_posit_assistant
    log_test "POSIT_ASSISTANT_STATUS: $POSIT_ASSISTANT_STATUS"

    [ "$POSIT_ASSISTANT_STATUS" = "failed" ]
    [[ "$POSIT_ASSISTANT_FAILURE_REASON" == *"invalid"* ]]
    assert_posit_assistant_settings_unchanged
    # A refusal must not leave a backup file behind.
    [ -z "$POSIT_ASSISTANT_BACKUP" ]
}

@test "configure_posit_assistant: leaves a malformed PreToolUse shape untouched" {
    log_test "Testing Posit Assistant malformed-shape refusal..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_posit_assistant
    seed_posit_assistant_settings '{"hooks": {"PreToolUse": "not-a-list"}}'

    configure_posit_assistant
    log_test "POSIT_ASSISTANT_STATUS: $POSIT_ASSISTANT_STATUS"

    [ "$POSIT_ASSISTANT_STATUS" = "failed" ]
    assert_posit_assistant_settings_unchanged
}

@test "detect_agents: reports posit-assistant when the config dir exists" {
    log_test "Testing Posit Assistant agent detection..."

    setup_mock_posit_assistant

    detect_agents
    log_test "DETECTED_AGENTS: ${DETECTED_AGENTS[*]}"

    is_agent_detected posit-assistant
}

@test "detect_agents: a bare ~/.posit directory is not enough" {
    log_test "Testing that ~/.posit alone does not count as Posit Assistant..."

    mkdir -p "$HOME/.posit"

    detect_agents
    log_test "DETECTED_AGENTS: ${DETECTED_AGENTS[*]}"

    ! is_agent_detected posit-assistant
}

@test "unconfigure_posit_assistant: removes only dcg and leaves siblings intact" {
    log_test "Testing Posit Assistant uninstall..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_posit_assistant
    # Install through the real code path so the seeded shape cannot drift from
    # what the installer actually writes, then add siblings to preserve.
    configure_posit_assistant
    [ "$POSIT_ASSISTANT_STATUS" = "created" ]
    posit_assistant_add_sibling_hooks

    run unconfigure_posit_assistant
    log_test "unconfigure_posit_assistant status: $status"
    log_test "settings.json after uninstall: $(cat "$POSIT_ASSISTANT_SETTINGS" 2>/dev/null || echo 'missing')"

    [ "$status" -eq 0 ]
    [ -f "$POSIT_ASSISTANT_SETTINGS" ]
    assert_posit_assistant_settings_not_contains "$DEST/dcg"
    assert_posit_assistant_settings_contains 'audit-log'
    assert_posit_assistant_settings_contains 'greet'
    [ "$(posit_assistant_dcg_hook_count)" = "0" ]
}

@test "unconfigure_posit_assistant: keeps the file when dcg was the only hook" {
    log_test "Testing Posit Assistant uninstall of a dcg-only config..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_posit_assistant
    configure_posit_assistant
    [ "$POSIT_ASSISTANT_STATUS" = "created" ]

    run unconfigure_posit_assistant
    log_test "unconfigure_posit_assistant status: $status"

    [ "$status" -eq 0 ]
    # Posit Assistant keeps unrelated settings in this file, so it is never
    # deleted — only the emptied PreToolUse key is dropped.
    [ -f "$POSIT_ASSISTANT_SETTINGS" ]
    assert_posit_assistant_settings_valid_json
    assert_posit_assistant_settings_not_contains '"PreToolUse"'
}

@test "unconfigure_posit_assistant: does not touch a config without dcg" {
    log_test "Testing Posit Assistant uninstall no-op..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_posit_assistant
    seed_posit_assistant_settings '{"hooks":{"PreToolUse":[{"matcher":"bash","hooks":[{"type":"command","command":"/opt/dcgrep/bin/dcgworkflow"}]}]}}'

    run unconfigure_posit_assistant
    log_test "unconfigure_posit_assistant status: $status"

    [ "$status" -eq 0 ]
    assert_posit_assistant_settings_unchanged
}

@test "unconfigure_posit_assistant: noop on missing settings" {
    log_test "Testing Posit Assistant uninstall with no settings file..."

    POSIT_ASSISTANT_SETTINGS="$HOME/.posit/assistant/settings.json"
    [ ! -f "$POSIT_ASSISTANT_SETTINGS" ]

    run unconfigure_posit_assistant
    log_test "unconfigure_posit_assistant status: $status"
    [ "$status" -eq 0 ]
}

# ============================================================================
# OpenCode Configuration Tests (#318)
# ============================================================================

# The real plugin-generation behavior (marker, embedded path, refusal to
# overwrite user-owned files) is covered by Rust tests against the real
# binary (tests/cli_e2e.rs). These tests cover configure_opencode's own
# logic: detection gating, delegation to `dcg install --opencode --force`,
# and status mapping of the binary's outcomes.

make_opencode_mock_dcg() {
    # $1 = behavior: "ok" writes the plugin and exits 0; "conflict" emits the
    # ownership-refusal message and exits 1; "fail" exits 1 with a generic
    # error.
    #
    # Pin XDG_CONFIG_HOME inside the isolated HOME so a host value cannot
    # leak into path assertions.
    export XDG_CONFIG_HOME="$HOME/.config"
    local behavior="$1"
    cat > "$DEST/dcg" << MOCKEOF
#!/bin/bash
if [ "\$1" = "install" ] && [ "\$2" = "--opencode" ]; then
    case "$behavior" in
        ok)
            plugin_dir="\${XDG_CONFIG_HOME:-\$HOME/.config}/opencode/plugins"
            mkdir -p "\$plugin_dir"
            printf '// dcg-opencode-plugin: generated by dcg installer (mock)\n' > "\$plugin_dir/dcg-guard.js"
            echo "OpenCode plugin installed successfully!"
            exit 0
            ;;
        conflict)
            echo "dcg-guard.js exists but was not generated by dcg (missing the marker)." >&2
            exit 1
            ;;
        fail)
            echo "some unexpected failure" >&2
            exit 1
            ;;
    esac
fi
echo "dcg 1.0.0"
MOCKEOF
    chmod +x "$DEST/dcg"
}

@test "configure_opencode: skipped when OpenCode not detected" {
    export XDG_CONFIG_HOME="$HOME/.config"
    DETECTED_AGENTS=()
    OPENCODE_STATUS=""

    configure_opencode

    [ "$OPENCODE_STATUS" = "skipped" ]
    [ ! -f "$HOME/.config/opencode/plugins/dcg-guard.js" ]
}

@test "configure_opencode: delegates to dcg install --opencode and reports created" {
    DETECTED_AGENTS=("opencode")
    OPENCODE_STATUS=""
    AUTO_CONFIGURED=0
    make_opencode_mock_dcg ok

    configure_opencode

    log_test "OPENCODE_STATUS=$OPENCODE_STATUS"
    [ "$OPENCODE_STATUS" = "created" ]
    [ "$AUTO_CONFIGURED" -eq 1 ]
    [ -f "$HOME/.config/opencode/plugins/dcg-guard.js" ]
    grep -q 'dcg-opencode-plugin' "$HOME/.config/opencode/plugins/dcg-guard.js"
}

@test "configure_opencode: reports merged when a plugin already existed" {
    DETECTED_AGENTS=("opencode")
    OPENCODE_STATUS=""
    make_opencode_mock_dcg ok
    mkdir -p "$HOME/.config/opencode/plugins"
    printf '// dcg-opencode-plugin: older install\n' > "$HOME/.config/opencode/plugins/dcg-guard.js"

    configure_opencode

    [ "$OPENCODE_STATUS" = "merged" ]
}

@test "configure_opencode: maps ownership refusal to conflict" {
    DETECTED_AGENTS=("opencode")
    OPENCODE_STATUS=""
    make_opencode_mock_dcg conflict
    mkdir -p "$HOME/.config/opencode/plugins"
    printf 'export const Mine = async () => ({});\n' > "$HOME/.config/opencode/plugins/dcg-guard.js"

    run configure_opencode
    # Re-run in the current shell to capture the status variable (bats `run`
    # executes in a subshell).
    configure_opencode || true

    log_test "OPENCODE_STATUS=$OPENCODE_STATUS"
    [ "$OPENCODE_STATUS" = "conflict" ]
    grep -q 'Mine' "$HOME/.config/opencode/plugins/dcg-guard.js"
}

@test "configure_opencode: maps other failures to failed with reason" {
    DETECTED_AGENTS=("opencode")
    OPENCODE_STATUS=""
    make_opencode_mock_dcg fail

    configure_opencode || true

    [ "$OPENCODE_STATUS" = "failed" ]
    [ -n "$OPENCODE_FAILURE_REASON" ]
}

# ============================================================================
# OpenCode Uninstall Tests (#318)
# ============================================================================

@test "unconfigure_opencode: removes dcg-owned plugin only" {
    export XDG_CONFIG_HOME="$HOME/.config"
    mkdir -p "$HOME/.config/opencode/plugins"
    printf '// dcg-opencode-plugin: generated\n' > "$HOME/.config/opencode/plugins/dcg-guard.js"

    run unconfigure_opencode
    [ "$status" -eq 0 ]
    [ ! -f "$HOME/.config/opencode/plugins/dcg-guard.js" ]
}

@test "unconfigure_opencode: preserves user-owned plugin without marker" {
    export XDG_CONFIG_HOME="$HOME/.config"
    mkdir -p "$HOME/.config/opencode/plugins"
    printf 'export const Mine = async () => ({});\n' > "$HOME/.config/opencode/plugins/dcg-guard.js"

    run unconfigure_opencode
    [ "$status" -eq 0 ]
    [ -f "$HOME/.config/opencode/plugins/dcg-guard.js" ]
    grep -q 'Mine' "$HOME/.config/opencode/plugins/dcg-guard.js"
}

@test "unconfigure_opencode: noop when plugin missing" {
    export XDG_CONFIG_HOME="$HOME/.config"
    run unconfigure_opencode
    [ "$status" -eq 0 ]
}

# ============================================================================
# Oh My Pi Configuration and Uninstall Tests
# ============================================================================

make_omp_mock_dcg() {
    local behavior="$1"
    cat > "$DEST/dcg" << MOCKEOF
#!/bin/bash
if [ "\$1" = "install" ] && [ "\$2" = "--omp" ]; then
    case "$behavior" in
        ok)
            extension_dir="\${PI_CODING_AGENT_DIR:-\$HOME/.omp/agent}/extensions"
            mkdir -p "\$extension_dir"
            printf '// dcg-omp-extension: generated by dcg installer (mock)\n' > "\$extension_dir/dcg-guard.ts"
            echo "OMP extension installed successfully!"
            exit 0
            ;;
        conflict)
            echo "dcg-guard.ts exists but was not generated by dcg (missing the marker)." >&2
            exit 1
            ;;
        fail)
            echo "some unexpected failure" >&2
            exit 1
            ;;
    esac
fi
echo "dcg 1.0.0"
MOCKEOF
    chmod +x "$DEST/dcg"
}

@test "configure_omp: skipped when OMP not detected" {
    DETECTED_AGENTS=()
    OMP_STATUS=""

    configure_omp

    [ "$OMP_STATUS" = "skipped" ]
    [ ! -f "$HOME/.omp/agent/extensions/dcg-guard.ts" ]
}

@test "configure_omp: delegates to dcg install --omp and reports created" {
    DETECTED_AGENTS=("omp")
    OMP_STATUS=""
    AUTO_CONFIGURED=0
    make_omp_mock_dcg ok

    configure_omp

    [ "$OMP_STATUS" = "created" ]
    [ "$AUTO_CONFIGURED" -eq 1 ]
    grep -q 'dcg-omp-extension' "$HOME/.omp/agent/extensions/dcg-guard.ts"
}

@test "configure_omp: reports a refresh for an existing named-profile extension" {
    DETECTED_AGENTS=("omp")
    OMP_STATUS=""
    AUTO_CONFIGURED=0
    export OMP_PROFILE="work"
    local extension="$HOME/.omp/profiles/work/agent/extensions/dcg-guard.ts"
    mkdir -p "$(dirname "$extension")"
    printf '// dcg-omp-extension: generated\n' > "$extension"
    make_omp_mock_dcg ok

    configure_omp

    [ "$OMP_STATUS" = "merged" ]
    [ "$AUTO_CONFIGURED" -eq 1 ]
}

@test "configure_omp: maps ownership refusal to conflict" {
    DETECTED_AGENTS=("omp")
    OMP_STATUS=""
    make_omp_mock_dcg conflict
    mkdir -p "$HOME/.omp/agent/extensions"
    printf 'export default function mine() {}\n' > "$HOME/.omp/agent/extensions/dcg-guard.ts"

    configure_omp || true

    [ "$OMP_STATUS" = "conflict" ]
    grep -q 'mine' "$HOME/.omp/agent/extensions/dcg-guard.ts"
}

@test "unconfigure_omp: removes marker-owned extension only" {
    extract_uninstall_functions
    mkdir -p "$HOME/.omp/agent/extensions"
    printf '// dcg-omp-extension: generated\n' > "$HOME/.omp/agent/extensions/dcg-guard.ts"

    run unconfigure_omp

    [ "$status" -eq 0 ]
    [ ! -f "$HOME/.omp/agent/extensions/dcg-guard.ts" ]
}

@test "unconfigure_omp: resolves the active named profile" {
    extract_uninstall_functions
    export OMP_PROFILE="work"
    local extension="$HOME/.omp/profiles/work/agent/extensions/dcg-guard.ts"
    mkdir -p "$(dirname "$extension")"
    printf '// dcg-omp-extension: generated\n' > "$extension"

    run unconfigure_omp

    [ "$status" -eq 0 ]
    [ ! -f "$extension" ]
}

@test "unconfigure_omp: removes marker-owned extensions from inactive profiles" {
    extract_uninstall_functions
    local default_extension="$HOME/.omp/agent/extensions/dcg-guard.ts"
    local work_extension="$HOME/.omp/profiles/work/agent/extensions/dcg-guard.ts"
    local team_extension="$HOME/.omp/profiles/team/agent/extensions/dcg-guard.ts"
    local user_extension="$HOME/.omp/profiles/personal/agent/extensions/dcg-guard.ts"
    mkdir -p "$(dirname "$default_extension")" "$(dirname "$work_extension")" \
        "$(dirname "$team_extension")" "$(dirname "$user_extension")"
    printf '// dcg-omp-extension: generated\n' > "$default_extension"
    printf '// dcg-omp-extension: generated\n' > "$work_extension"
    printf '// dcg-omp-extension: generated\n' > "$team_extension"
    printf 'export default function mine() {}\n' > "$user_extension"

    run unconfigure_omp

    [ "$status" -eq 0 ]
    [ ! -f "$default_extension" ]
    [ ! -f "$work_extension" ]
    [ ! -f "$team_extension" ]
    grep -q 'mine' "$user_extension"
}

@test "unconfigure_omp: finds a project extension from a nested directory" {
    extract_uninstall_functions
    local repo="$BATS_TEST_TMPDIR/omp-project"
    local nested="$repo/a/b"
    local extension="$repo/.omp/extensions/dcg-guard.ts"
    mkdir -p "$repo/.git" "$nested" "$(dirname "$extension")"
    printf '// dcg-omp-extension: generated\n' > "$extension"

    cd "$nested"
    run unconfigure_omp

    [ "$status" -eq 0 ]
    [ ! -f "$extension" ]
}

@test "unconfigure_omp: invalid profile safely uses the default agent override" {
    extract_uninstall_functions
    export OMP_PROFILE="con"
    export PI_CODING_AGENT_DIR="$HOME/custom-omp-agent"
    local extension="$PI_CODING_AGENT_DIR/extensions/dcg-guard.ts"
    mkdir -p "$(dirname "$extension")"
    printf '// dcg-omp-extension: generated\n' > "$extension"

    run unconfigure_omp

    [ "$status" -eq 0 ]
    [ ! -f "$extension" ]
}

@test "unconfigure_omp: preserves a user-owned extension" {
    extract_uninstall_functions
    mkdir -p "$HOME/.omp/agent/extensions"
    printf 'export default function mine() {}\n' > "$HOME/.omp/agent/extensions/dcg-guard.ts"

    run unconfigure_omp

    [ "$status" -eq 0 ]
    grep -q 'mine' "$HOME/.omp/agent/extensions/dcg-guard.ts"
}

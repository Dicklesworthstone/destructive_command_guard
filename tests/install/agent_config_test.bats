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

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"

    # Create malformed JSON
    echo "not valid json {{{" > "$CLAUDE_SETTINGS"

    log_test "Malformed content: $(cat "$CLAUDE_SETTINGS")"

    # This might fail or succeed depending on implementation
    # The key is it shouldn't crash
    configure_claude_code "$CLAUDE_SETTINGS" "0" || true

    log_test "CLAUDE_STATUS: $CLAUDE_STATUS"
    log_test "After: $(cat "$CLAUDE_SETTINGS" 2>/dev/null || echo 'N/A')"

    # Either status should be set
    [ -n "$CLAUDE_STATUS" ]
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

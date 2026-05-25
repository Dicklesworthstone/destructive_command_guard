#!/usr/bin/env bats
# Unit tests for uninstall.sh
#
# Tests:
# - Agent hook removal (Claude Code, Gemini CLI, Aider)
# - Binary removal
# - Configuration and data removal
# - Confirmation prompt behavior

load test_helper

setup() {
    setup_isolated_home
    setup_test_log "$BATS_TEST_NAME"

    # Source uninstall.sh functions
    UNINSTALL_SCRIPT="$PROJECT_ROOT/uninstall.sh"

    # Create mock dcg binary
    mkdir -p "$HOME/.local/bin"
    cat > "$HOME/.local/bin/dcg" << 'MOCKEOF'
#!/bin/bash
echo "dcg 1.0.0"
MOCKEOF
    chmod +x "$HOME/.local/bin/dcg"
    export PATH="$HOME/.local/bin:$PATH"
}

teardown() {
    log_test "=== Test completed: $BATS_TEST_NAME (status: $status) ==="
    teardown_isolated_home
}

# ============================================================================
# Claude Code Uninstall Tests
# ============================================================================

@test "uninstall: removes dcg hook from Claude Code settings" {
    log_test "Testing Claude Code hook removal..."

    # Skip if python3 not available
    command -v python3 &>/dev/null || skip "python3 not available"

    mkdir -p "$HOME/.claude"
    cat > "$HOME/.claude/settings.json" << 'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/path/to/dcg"}
        ]
      }
    ]
  }
}
EOF

    log_test "Before: $(cat "$HOME/.claude/settings.json")"

    # Run uninstall with --yes to skip confirmation
    "$UNINSTALL_SCRIPT" --yes --quiet

    log_test "After: $(cat "$HOME/.claude/settings.json" 2>/dev/null || echo 'N/A')"

    # dcg hook should be removed
    ! grep -q '"command".*dcg' "$HOME/.claude/settings.json"
}

@test "uninstall: preserves other hooks in Claude Code settings" {
    log_test "Testing preservation of other Claude Code hooks..."

    # Skip if python3 not available
    command -v python3 &>/dev/null || skip "python3 not available"

    mkdir -p "$HOME/.claude"
    cat > "$HOME/.claude/settings.json" << 'EOF'
{
  "theme": "dark",
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/path/to/dcg"},
          {"type": "command", "command": "/path/to/other-hook"}
        ]
      },
      {
        "matcher": "Read",
        "hooks": [{"type": "command", "command": "/path/to/read-hook"}]
      }
    ]
  }
}
EOF

    "$UNINSTALL_SCRIPT" --yes --quiet

    log_test "After: $(cat "$HOME/.claude/settings.json")"

    # Other hooks should remain
    grep -q "other-hook" "$HOME/.claude/settings.json"
    grep -q "read-hook" "$HOME/.claude/settings.json"
    grep -q "theme" "$HOME/.claude/settings.json"
}

@test "unconfigure_claude_code: ignores commands that only contain dcg as a substring" {
    log_test "Testing Claude Code substring-only hook preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"
    extract_uninstall_functions

    mkdir -p "$HOME/.claude"
    cat > "$HOME/.claude/settings.json" << 'EOF'
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
    local before
    before=$(cat "$HOME/.claude/settings.json")

    run unconfigure_claude_code

    log_test "unconfigure_claude_code status: $status"
    log_test "unconfigure_claude_code output: $output"
    log_test "After: $(cat "$HOME/.claude/settings.json")"

    [ "$status" -eq 0 ]
    [ -z "$output" ]
    [ "$(cat "$HOME/.claude/settings.json")" = "$before" ]
}

@test "unconfigure_claude_code: preserves malformed Bash hook containers" {
    log_test "Testing Claude Code malformed Bash hook preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"
    extract_uninstall_functions

    mkdir -p "$HOME/.claude"
    cat > "$HOME/.claude/settings.json" << 'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": {
          "command": "/opt/dcgrep/bin/scan"
        }
      }
    ]
  }
}
EOF
    local before
    before=$(cat "$HOME/.claude/settings.json")

    run unconfigure_claude_code

    log_test "unconfigure_claude_code status: $status"
    log_test "unconfigure_claude_code output: $output"
    log_test "After: $(cat "$HOME/.claude/settings.json")"

    [ "$status" -eq 0 ]
    [ -z "$output" ]
    [ "$(cat "$HOME/.claude/settings.json")" = "$before" ]
}

# ============================================================================
# Gemini CLI Uninstall Tests
# ============================================================================

@test "uninstall: removes dcg hook from Gemini CLI settings" {
    log_test "Testing Gemini CLI hook removal..."

    # Skip if python3 not available
    command -v python3 &>/dev/null || skip "python3 not available"

    mkdir -p "$HOME/.gemini"
    cat > "$HOME/.gemini/settings.json" << 'EOF'
{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "run_shell_command",
        "hooks": [
          {"name": "dcg", "type": "command", "command": "/path/to/dcg"}
        ]
      }
    ]
  }
}
EOF

    "$UNINSTALL_SCRIPT" --yes --quiet

    log_test "After: $(cat "$HOME/.gemini/settings.json" 2>/dev/null || echo 'N/A')"

    # dcg hook should be removed
    ! grep -q '"command".*dcg' "$HOME/.gemini/settings.json"
}

@test "unconfigure_gemini: ignores commands that only contain dcg as a substring" {
    log_test "Testing Gemini CLI substring-only hook preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"
    extract_uninstall_functions

    mkdir -p "$HOME/.gemini"
    cat > "$HOME/.gemini/settings.json" << 'EOF'
{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "run_shell_command",
        "hooks": [
          {"name": "dcgrep", "type": "command", "command": "/opt/dcgrep/bin/scan"}
        ]
      }
    ]
  }
}
EOF
    local before
    before=$(cat "$HOME/.gemini/settings.json")

    run unconfigure_gemini

    log_test "unconfigure_gemini status: $status"
    log_test "unconfigure_gemini output: $output"
    log_test "After: $(cat "$HOME/.gemini/settings.json")"

    [ "$status" -eq 0 ]
    [ -z "$output" ]
    [ "$(cat "$HOME/.gemini/settings.json")" = "$before" ]
}

@test "unconfigure_gemini: preserves malformed hook containers" {
    log_test "Testing Gemini CLI malformed hook preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"
    extract_uninstall_functions

    mkdir -p "$HOME/.gemini"
    cat > "$HOME/.gemini/settings.json" << 'EOF'
{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "run_shell_command",
        "hooks": {
          "command": "/opt/dcgrep/bin/scan"
        }
      }
    ]
  }
}
EOF
    local before
    before=$(cat "$HOME/.gemini/settings.json")

    run unconfigure_gemini

    log_test "unconfigure_gemini status: $status"
    log_test "unconfigure_gemini output: $output"
    log_test "After: $(cat "$HOME/.gemini/settings.json")"

    [ "$status" -eq 0 ]
    [ -z "$output" ]
    [ "$(cat "$HOME/.gemini/settings.json")" = "$before" ]
}

# ============================================================================
# GitHub Copilot CLI Uninstall Tests
# ============================================================================

@test "unconfigure_copilot: ignores commands that only contain dcg as a substring" {
    log_test "Testing GitHub Copilot CLI substring-only hook preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"
    command -v git &>/dev/null || skip "git not available"
    extract_uninstall_functions

    mkdir -p "$TEST_TMPDIR/repo"
    cd "$TEST_TMPDIR/repo"
    git init -q
    mkdir -p .github/hooks
    cat > .github/hooks/dcg.json << 'EOF'
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "type": "command",
        "bash": "/opt/dcgrep/bin/scan",
        "powershell": "/opt/dcgrep/bin/scan",
        "cwd": ".",
        "timeoutSec": 30
      }
    ]
  }
}
EOF
    local before
    before=$(cat .github/hooks/dcg.json)

    run unconfigure_copilot

    log_test "unconfigure_copilot status: $status"
    log_test "unconfigure_copilot output: $output"
    log_test "After: $(cat .github/hooks/dcg.json)"

    [ "$status" -eq 0 ]
    [ -z "$output" ]
    [ "$(cat .github/hooks/dcg.json)" = "$before" ]
}

@test "unconfigure_copilot: removes exact dcg command and preserves other entries" {
    log_test "Testing GitHub Copilot CLI exact dcg hook removal..."
    command -v python3 &>/dev/null || skip "python3 not available"
    command -v git &>/dev/null || skip "git not available"
    extract_uninstall_functions

    mkdir -p "$TEST_TMPDIR/repo"
    cd "$TEST_TMPDIR/repo"
    git init -q
    mkdir -p .github/hooks
    cat > .github/hooks/dcg.json << 'EOF'
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "type": "command",
        "bash": "/usr/local/bin/dcg",
        "powershell": "/usr/local/bin/dcg",
        "cwd": ".",
        "timeoutSec": 30
      },
      {
        "type": "command",
        "bash": "/opt/dcgrep/bin/scan",
        "powershell": "/opt/dcgrep/bin/scan",
        "cwd": ".",
        "timeoutSec": 30
      }
    ]
  }
}
EOF

    run unconfigure_copilot

    log_test "unconfigure_copilot status: $status"
    log_test "unconfigure_copilot output: $output"
    log_test "After: $(cat .github/hooks/dcg.json)"

    [ "$status" -eq 0 ]
    [[ "$output" == *"removed"* ]]
    if grep -qF '/usr/local/bin/dcg' .github/hooks/dcg.json; then
        return 1
    fi
    grep -qF '/opt/dcgrep/bin/scan' .github/hooks/dcg.json
}

@test "unconfigure_copilot: preserves mixed hook entries after removing dcg platform command" {
    log_test "Testing GitHub Copilot CLI mixed platform hook preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"
    command -v git &>/dev/null || skip "git not available"
    extract_uninstall_functions

    mkdir -p "$TEST_TMPDIR/repo"
    cd "$TEST_TMPDIR/repo"
    git init -q
    mkdir -p .github/hooks
    cat > .github/hooks/dcg.json << 'EOF'
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "type": "command",
        "bash": "audit-pretool",
        "powershell": "/usr/local/bin/dcg",
        "cwd": ".",
        "timeoutSec": 30
      }
    ]
  }
}
EOF

    run unconfigure_copilot

    log_test "unconfigure_copilot status: $status"
    log_test "unconfigure_copilot output: $output"
    log_test "After: $(cat .github/hooks/dcg.json)"

    [ "$status" -eq 0 ]
    [[ "$output" == *"removed"* ]]
    python3 - .github/hooks/dcg.json <<'PYEOF'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    config = json.load(f)

pre_tool = config["hooks"]["preToolUse"]
if len(pre_tool) != 1:
    raise SystemExit(f"expected one preserved Copilot hook, found {len(pre_tool)}")

residual = pre_tool[0]
if residual.get("bash") != "audit-pretool":
    raise SystemExit(f"mixed hook bash command was not preserved: {residual!r}")
if "powershell" in residual:
    raise SystemExit(f"dcg powershell command was not stripped from mixed hook: {residual!r}")
PYEOF
}

# ============================================================================
# Cursor IDE Uninstall Tests
# ============================================================================

@test "unconfigure_cursor: ignores commands that only contain dcg as a substring" {
    log_test "Testing Cursor IDE substring-only hook preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"
    extract_uninstall_functions

    mkdir -p "$HOME/.cursor"
    cat > "$HOME/.cursor/hooks.json" << 'EOF'
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [
      {
        "command": "/opt/dcgrep/bin/scan"
      }
    ]
  }
}
EOF
    local before
    before=$(cat "$HOME/.cursor/hooks.json")

    run unconfigure_cursor

    log_test "unconfigure_cursor status: $status"
    log_test "unconfigure_cursor output: $output"
    log_test "After: $(cat "$HOME/.cursor/hooks.json")"

    [ "$status" -eq 0 ]
    [ -z "$output" ]
    [ "$(cat "$HOME/.cursor/hooks.json")" = "$before" ]
}

@test "unconfigure_cursor: preserves same-basename hook outside generated path" {
    log_test "Testing Cursor IDE same-basename hook preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"
    extract_uninstall_functions

    mkdir -p "$HOME/.cursor" "$TEST_TMPDIR/other-hooks"
    local other_hook="$TEST_TMPDIR/other-hooks/dcg-pre-shell.py"
    cat > "$HOME/.cursor/hooks.json" << EOF
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [
      {
        "command": "$other_hook"
      }
    ]
  }
}
EOF
    local before
    before=$(cat "$HOME/.cursor/hooks.json")

    run unconfigure_cursor

    log_test "unconfigure_cursor status: $status"
    log_test "unconfigure_cursor output: $output"
    log_test "After: $(cat "$HOME/.cursor/hooks.json")"

    [ "$status" -eq 0 ]
    [ -z "$output" ]
    [ "$(cat "$HOME/.cursor/hooks.json")" = "$before" ]
}

@test "unconfigure_cursor: removes generated hook script entry and preserves other entries" {
    log_test "Testing Cursor IDE generated hook removal..."
    command -v python3 &>/dev/null || skip "python3 not available"
    extract_uninstall_functions

    mkdir -p "$HOME/.cursor/hooks"
    cat > "$HOME/.cursor/hooks/dcg-pre-shell.py" << 'EOF'
#!/usr/bin/env python3
# dcg-cursor-hook: generated by dcg installer
EOF
    chmod +x "$HOME/.cursor/hooks/dcg-pre-shell.py"
    cat > "$HOME/.cursor/hooks.json" << EOF
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [
      {
        "command": "$HOME/.cursor/hooks/dcg-pre-shell.py"
      },
      {
        "command": "/opt/dcgrep/bin/scan"
      }
    ]
  }
}
EOF

    run unconfigure_cursor

    log_test "unconfigure_cursor status: $status"
    log_test "unconfigure_cursor output: $output"
    log_test "After: $(cat "$HOME/.cursor/hooks.json")"

    [ "$status" -eq 0 ]
    [[ "$output" == *"removed"* ]]
    [ ! -f "$HOME/.cursor/hooks/dcg-pre-shell.py" ]
    if grep -qF 'dcg-pre-shell.py' "$HOME/.cursor/hooks.json"; then
        return 1
    fi
    grep -qF '/opt/dcgrep/bin/scan' "$HOME/.cursor/hooks.json"
}

@test "unconfigure_cursor: removes generated-only hooks json" {
    log_test "Testing Cursor IDE generated-only hook file removal..."
    command -v python3 &>/dev/null || skip "python3 not available"
    extract_uninstall_functions

    mkdir -p "$HOME/.cursor/hooks"
    cat > "$HOME/.cursor/hooks/dcg-pre-shell.py" << 'EOF'
#!/usr/bin/env python3
# dcg-cursor-hook: generated by dcg installer
EOF
    chmod +x "$HOME/.cursor/hooks/dcg-pre-shell.py"
    cat > "$HOME/.cursor/hooks.json" << EOF
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [
      {
        "command": "$HOME/.cursor/hooks/dcg-pre-shell.py"
      }
    ]
  }
}
EOF

    run unconfigure_cursor

    log_test "unconfigure_cursor status: $status"
    log_test "unconfigure_cursor output: $output"

    [ "$status" -eq 0 ]
    [[ "$output" == *"removed"* ]]
    [ ! -f "$HOME/.cursor/hooks/dcg-pre-shell.py" ]
    [ ! -f "$HOME/.cursor/hooks.json" ]
}

@test "uninstall: preflight ignores substring-only agent hook configs" {
    log_test "Testing uninstall preflight exact hook detection..."
    command -v python3 &>/dev/null || skip "python3 not available"
    command -v git &>/dev/null || skip "git not available"

    mv "$HOME/.local/bin/dcg" "$HOME/.local/bin/dcg.disabled"

    mkdir -p "$HOME/.claude"
    cat > "$HOME/.claude/settings.json" << 'EOF'
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

    mkdir -p "$HOME/.gemini"
    cat > "$HOME/.gemini/settings.json" << 'EOF'
{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "run_shell_command",
        "hooks": [
          {"name": "dcgrep", "type": "command", "command": "/opt/dcgrep/bin/scan"}
        ]
      }
    ]
  }
}
EOF

    mkdir -p "$HOME/.codex"
    cat > "$HOME/.codex/hooks.json" << 'EOF'
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

    mkdir -p "$HOME/.cursor"
    cat > "$HOME/.cursor/hooks.json" << 'EOF'
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [
      {
        "command": "/opt/dcgrep/bin/scan"
      }
    ]
  }
}
EOF

    mkdir -p "$TEST_TMPDIR/repo"
    cd "$TEST_TMPDIR/repo"
    git init -q
    mkdir -p .github/hooks
    cat > .github/hooks/dcg.json << 'EOF'
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "type": "command",
        "bash": "/opt/dcgrep/bin/scan",
        "powershell": "/opt/dcgrep/bin/scan",
        "cwd": ".",
        "timeoutSec": 30
      }
    ]
  }
}
EOF

    run "$UNINSTALL_SCRIPT" --yes

    log_test "uninstall status: $status"
    log_test "uninstall output: $output"

    [ "$status" -eq 0 ]
    [[ "$output" == *"Nothing to remove"* ]]
    [[ "$output" != *"Claude Code hook"* ]]
    [[ "$output" != *"Gemini CLI hook"* ]]
    [[ "$output" != *"Codex CLI hook"* ]]
    [[ "$output" != *"GitHub Copilot CLI hook"* ]]
    [[ "$output" != *"Cursor IDE hook"* ]]
}

@test "uninstall.ps1: preserves non-Bash PreToolUse dcg hooks" {
    log_test "Testing PowerShell Codex uninstall only removes Bash-owned dcg hooks..."
    local pwsh_bin
    pwsh_bin="$(PATH="${ORIGINAL_PATH:-$PATH}" command -v pwsh || true)"
    [ -n "$pwsh_bin" ] || skip "pwsh not available"

    mkdir -p "$HOME/.codex"
    cat > "$HOME/.codex/hooks.json" << 'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read",
        "hooks": [
          {"type": "command", "command": "C:\\tools\\dcg.exe"}
        ]
      },
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "C:\\tools\\dcg.exe"},
          {"type": "command", "command": "other-tool"}
        ]
      }
    ]
  }
}
EOF

    run env DCG_UNINSTALL_PS1="$PROJECT_ROOT/uninstall.ps1" DCG_HOOKS_JSON="$HOME/.codex/hooks.json" "$pwsh_bin" -NoProfile -Command '
$ScriptPath = $env:DCG_UNINSTALL_PS1
$HooksPath = $env:DCG_HOOKS_JSON
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

$result = Remove-DcgHooksFromJsonFile -Path $HooksPath -DeleteEmptyFile
if (-not $result) {
  Write-Error "expected Bash dcg hook removal"
  exit 2
}

$config = Get-Content -Raw -Path $HooksPath | ConvertFrom-Json
$entries = @($config.hooks.PreToolUse)
$readEntry = @($entries | Where-Object { $_.matcher -eq "Read" })[0]
if ($readEntry.hooks[0].command -ne "C:\tools\dcg.exe") {
  Write-Error "Read dcg hook was not preserved"
  exit 3
}

$bashEntry = @($entries | Where-Object { $_.matcher -eq "Bash" })[0]
$bashCommands = @($bashEntry.hooks | ForEach-Object { $_.command })
if ($bashCommands -contains "C:\tools\dcg.exe") {
  Write-Error "Bash dcg hook was not removed"
  exit 4
}
if ($bashCommands -notcontains "other-tool") {
  Write-Error "coexisting Bash hook was not preserved"
  exit 5
}
'

    log_test "pwsh uninstall.ps1 status: $status"
    log_test "pwsh uninstall.ps1 output: $output"

    [ "$status" -eq 0 ]
}

@test "uninstall.ps1: preserves malformed PreToolUse shape" {
    log_test "Testing PowerShell Codex uninstall preserves non-list PreToolUse..."
    local pwsh_bin
    pwsh_bin="$(PATH="${ORIGINAL_PATH:-$PATH}" command -v pwsh || true)"
    [ -n "$pwsh_bin" ] || skip "pwsh not available"

    mkdir -p "$HOME/.codex"
    cat > "$HOME/.codex/hooks.json" << 'EOF'
{
  "hooks": {
    "PreToolUse": {
      "matcher": "Bash",
      "hooks": [
        {"type": "command", "command": "C:\\tools\\dcg.exe"}
      ]
    }
  }
}
EOF
    local before
    before="$(cat "$HOME/.codex/hooks.json")"

    run env DCG_UNINSTALL_PS1="$PROJECT_ROOT/uninstall.ps1" DCG_HOOKS_JSON="$HOME/.codex/hooks.json" "$pwsh_bin" -NoProfile -Command '
$ScriptPath = $env:DCG_UNINSTALL_PS1
$HooksPath = $env:DCG_HOOKS_JSON
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

$result = Remove-DcgHooksFromJsonFile -Path $HooksPath -DeleteEmptyFile
if ($result) {
  Write-Error "malformed PreToolUse should have been left unchanged"
  exit 2
}
'

    log_test "pwsh uninstall.ps1 status: $status"
    log_test "pwsh uninstall.ps1 output: $output"

    [ "$status" -eq 0 ]
    [ "$(cat "$HOME/.codex/hooks.json")" = "$before" ]
}

@test "uninstall.ps1: preserves malformed Bash hooks shape" {
    log_test "Testing PowerShell Codex uninstall preserves non-list Bash hooks..."
    local pwsh_bin
    pwsh_bin="$(PATH="${ORIGINAL_PATH:-$PATH}" command -v pwsh || true)"
    [ -n "$pwsh_bin" ] || skip "pwsh not available"

    mkdir -p "$HOME/.codex"
    cat > "$HOME/.codex/hooks.json" << 'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": {
          "type": "command",
          "command": "C:\\tools\\dcg.exe"
        }
      },
      {
        "matcher": "Read",
        "hooks": [
          {"type": "command", "command": "echo read-hook"}
        ]
      }
    ]
  }
}
EOF
    local before
    before="$(cat "$HOME/.codex/hooks.json")"

    run env DCG_UNINSTALL_PS1="$PROJECT_ROOT/uninstall.ps1" DCG_HOOKS_JSON="$HOME/.codex/hooks.json" "$pwsh_bin" -NoProfile -Command '
$ScriptPath = $env:DCG_UNINSTALL_PS1
$HooksPath = $env:DCG_HOOKS_JSON
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

$result = Remove-DcgHooksFromJsonFile -Path $HooksPath -DeleteEmptyFile
if ($result) {
  Write-Error "malformed Bash hooks should have been left unchanged"
  exit 2
}
'

    log_test "pwsh uninstall.ps1 status: $status"
    log_test "pwsh uninstall.ps1 output: $output"

    [ "$status" -eq 0 ]
    [ "$(cat "$HOME/.codex/hooks.json")" = "$before" ]
}

# ============================================================================
# Aider Uninstall Tests
# ============================================================================

@test "uninstall: removes dcg settings from Aider config" {
    log_test "Testing Aider config removal..."

    cat > "$HOME/.aider.conf.yml" << 'EOF'
# Aider config
model: gpt-4

# Added by dcg installer - enables git hooks so dcg pre-commit can run
git-commit-verify: true
EOF

    "$UNINSTALL_SCRIPT" --yes --quiet

    log_test "After: $(cat "$HOME/.aider.conf.yml" 2>/dev/null || echo 'N/A')"

    # dcg-added lines should be removed
    if grep -q "Added by dcg installer" "$HOME/.aider.conf.yml"; then
        return 1
    fi
    # Other settings should remain
    grep -q "model: gpt-4" "$HOME/.aider.conf.yml"
}

@test "uninstall: removes empty Aider config file" {
    log_test "Testing Aider config removal when file becomes empty..."

    cat > "$HOME/.aider.conf.yml" << 'EOF'
# Added by dcg installer - enables git hooks so dcg pre-commit can run
git-commit-verify: true
EOF

    "$UNINSTALL_SCRIPT" --yes --quiet

    # File should be removed if it's now empty
    [ ! -f "$HOME/.aider.conf.yml" ]
}

@test "uninstall: does not report Aider removal when Aider config is absent" {
    log_test "Testing Aider removal output is not emitted for absent config..."

    run "$UNINSTALL_SCRIPT" --yes

    log_test "uninstall status: $status"
    log_test "uninstall output: $output"

    [ "$status" -eq 0 ]
    [[ "$output" == *"Removed binary"* ]]
    [[ "$output" != *"Removed Aider configuration"* ]]
}

# ============================================================================
# Binary Removal Tests
# ============================================================================

@test "uninstall: removes dcg binary" {
    log_test "Testing binary removal..."

    # Verify binary exists
    [ -f "$HOME/.local/bin/dcg" ]

    "$UNINSTALL_SCRIPT" --yes --quiet

    # Binary should be removed
    [ ! -f "$HOME/.local/bin/dcg" ]
}

# ============================================================================
# Configuration/Data Removal Tests
# ============================================================================

@test "uninstall: removes config directory by default" {
    log_test "Testing config directory removal..."

    mkdir -p "$HOME/.config/dcg"
    echo "test" > "$HOME/.config/dcg/config.toml"

    "$UNINSTALL_SCRIPT" --yes --quiet

    # Config directory should be removed
    [ ! -d "$HOME/.config/dcg" ]
}

@test "uninstall: keeps config directory with --keep-config" {
    log_test "Testing --keep-config flag..."

    mkdir -p "$HOME/.config/dcg"
    echo "test" > "$HOME/.config/dcg/config.toml"

    "$UNINSTALL_SCRIPT" --yes --quiet --keep-config

    # Config directory should still exist
    [ -d "$HOME/.config/dcg" ]
    [ -f "$HOME/.config/dcg/config.toml" ]
}

@test "uninstall: removes data directory by default" {
    log_test "Testing data directory removal..."

    mkdir -p "$HOME/.local/share/dcg"
    echo "test" > "$HOME/.local/share/dcg/history.db"

    "$UNINSTALL_SCRIPT" --yes --quiet

    # Data directory should be removed
    [ ! -d "$HOME/.local/share/dcg" ]
}

@test "uninstall: keeps data directory with --keep-history" {
    log_test "Testing --keep-history flag..."

    mkdir -p "$HOME/.local/share/dcg"
    echo "test" > "$HOME/.local/share/dcg/history.db"

    "$UNINSTALL_SCRIPT" --yes --quiet --keep-history

    # Data directory should still exist
    [ -d "$HOME/.local/share/dcg" ]
}

# ============================================================================
# Edge Cases
# ============================================================================

@test "uninstall: handles missing installations gracefully" {
    log_test "Testing graceful handling of missing installation..."

    # Remove everything
    rm -rf "$HOME/.claude" "$HOME/.gemini" "$HOME/.config/dcg" "$HOME/.local/share/dcg"
    rm -f "$HOME/.local/bin/dcg" "$HOME/.aider.conf.yml"

    # Should exit cleanly
    "$UNINSTALL_SCRIPT" --yes --quiet
}

@test "uninstall: syntax check passes" {
    log_test "Testing script syntax..."

    bash -n "$UNINSTALL_SCRIPT"
}

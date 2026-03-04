# Agent-Specific Profiles

dcg can detect which AI coding agent is invoking it and apply agent-specific
trust levels and configuration overrides. This allows you to grant higher
trust to well-behaved agents while maintaining strict controls for unknown ones.

## Supported Agents

| Agent | Detection Method | Environment Variable |
|-------|------------------|---------------------|
| Claude Code | Environment | `CLAUDE_CODE=1` or `CLAUDE_SESSION_ID` |
| Aider | Environment | `AIDER_SESSION=1` |
| Continue | Environment | `CONTINUE_SESSION_ID` |
| Codex CLI | Environment | `CODEX_CLI=1` |
| Gemini CLI | Environment | `GEMINI_CLI=1` |
| GitHub Copilot CLI | Environment | `COPILOT_CLI=1`, `TERM_PROGRAM=vscode`, or `COPILOT_AGENT_START_TIME_SEC` |

## Detection Priority

Agent detection follows this priority order:

1. **Explicit `--agent` flag**: Manual override via CLI
2. **Environment variables**: Most agents set identifying env vars
3. **Parent process inspection**: Fallback check of process tree
4. **Unknown**: Default when no agent is detected

## Trust Levels

Three trust levels control how strictly dcg evaluates commands:

| Level | Description |
|-------|-------------|
| `high` | Relaxed evaluation; agent has proven reliable |
| `medium` | Default; standard evaluation rules apply |
| `low` | Strict evaluation; extra caution for unknown agents |

## Configuration

Configure agent profiles in your `config.toml`:

```toml
# Trust Claude Code more (it sets CLAUDE_CODE=1)
[agents.claude-code]
trust_level = "high"
additional_allowlist = ["npm run build", "cargo test"]

[agents.copilot]
trust_level = "medium"
additional_allowlist = ["npm test"]

# Restrict unknown agents
[agents.unknown]
trust_level = "low"
extra_packs = ["paranoid"]

# Default profile for unspecified agents
[agents.default]
trust_level = "medium"
```

### Profile Options

| Option | Type | Description |
|--------|------|-------------|
| `trust_level` | string | `"high"`, `"medium"`, or `"low"` |
| `disabled_packs` | array | Packs to disable for this agent |
| `extra_packs` | array | Additional packs to enable |
| `additional_allowlist` | array | Commands to allowlist for this agent |
| `disabled_allowlist` | bool | If true, ignore base allowlist for this agent |

### Example: Restrictive Config for CI

```toml
# In .dcg.toml (project-level)
[agents.unknown]
trust_level = "low"
disabled_allowlist = true
extra_packs = ["core", "database", "filesystem"]

[agents.claude-code]
trust_level = "medium"
additional_allowlist = ["npm test", "npm run lint"]
```

## Custom Agents

Define profiles for custom agents by setting an environment variable:

```bash
# Set a custom agent identifier
export MY_BUILD_BOT=1
```

Then configure in `config.toml`:

```toml
[agents.my-build-bot]
trust_level = "high"
additional_allowlist = ["make deploy"]
```

## Profile Resolution

When resolving which profile to use:

1. Look for exact match: `agents.<agent-config-key>`
2. Fall back to `agents.unknown` if agent is unrecognized
3. Fall back to `agents.default` if no specific profile exists

## Verbose Output

Use `--verbose` or `-v` to see agent detection info:

```bash
$ dcg test "git push --force" --verbose
Command: git push --force
...
Elapsed: 21.14ms
Agent: Claude Code
Trust level: medium
Severity: critical
```

Use `-vv` for detailed debug output:

```bash
$ dcg test "git push --force" -vv
...
Agent detection:
  Detected: Claude Code (claude-code)
  Method: environment_variable
  Matched: CLAUDE_CODE
  Profile: agents.claude-code
  Trust level: medium
```

## JSON Output

The `--format json` output includes agent information:

```json
{
  "command": "git push --force",
  "decision": "deny",
  "agent": {
    "detected": "claude-code",
    "trust_level": "medium",
    "detection_method": "environment_variable"
  }
}
```

## Robot Mode

Robot mode provides a unified, machine-friendly interface for AI agents. When
enabled, dcg optimizes its output for programmatic consumption.

### Enabling Robot Mode

```bash
# Via flag
dcg --robot test "rm -rf /"

# Via environment variable
DCG_ROBOT=1 dcg test "rm -rf /"
```

### Robot Mode Behavior

| Aspect | Normal Mode | Robot Mode |
|--------|-------------|------------|
| stdout | JSON or pretty | Always JSON |
| stderr | Rich colored output | Silent |
| Exit codes | Varies | Standardized |
| ANSI codes | If TTY | Never |
| Progress | Shown | Hidden |
| Suggestions | Shown | In JSON only |

### Standardized Exit Codes

In robot mode, dcg uses consistent exit codes across all commands:

| Code | Constant | Meaning |
|------|----------|---------|
| 0 | `EXIT_SUCCESS` | Success / Allow |
| 1 | `EXIT_DENIED` | Command denied/blocked |
| 2 | `EXIT_WARNING` | Warning (with --fail-on warn) |
| 3 | `EXIT_CONFIG_ERROR` | Configuration error |
| 4 | `EXIT_PARSE_ERROR` | Parse/input error |
| 5 | `EXIT_IO_ERROR` | IO error |

### Robot Mode JSON Output

All robot-mode responses are pure JSON on stdout:

```json
{
  "command": "rm -rf /",
  "decision": "deny",
  "rule_id": "core.filesystem:rm-rf-root",
  "pack_id": "core.filesystem",
  "severity": "critical",
  "reason": "rm -rf / would delete the entire filesystem",
  "agent": {
    "detected": "claude-code",
    "trust_level": "medium",
    "detection_method": "environment_variable"
  }
}
```

### Hook Mode vs Robot Mode

**Hook mode** (default when no subcommand) follows the Claude Code protocol:
- Always exits 0 (hook protocol requirement)
- JSON on stdout for denials, empty for allows
- Rich output on stderr for human visibility

**Robot mode** with subcommands uses standardized exit codes:
- Exit 1 for denials (allows scripting with `$?`)
- Pure JSON on stdout
- Silent stderr

### Example: Agent Integration

```bash
#!/bin/bash
# Script for AI agent to check commands before execution

check_command() {
    local cmd="$1"
    local result

    # Use robot mode for predictable output
    result=$(dcg --robot test "$cmd" 2>/dev/null)
    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        echo "Command allowed: $cmd"
        return 0
    elif [ $exit_code -eq 1 ]; then
        echo "Command BLOCKED: $cmd"
        echo "Reason: $(echo "$result" | jq -r '.reason')"
        return 1
    else
        echo "Error checking command (exit code: $exit_code)"
        return $exit_code
    fi
}

# Usage
check_command "git status"      # Allowed
check_command "rm -rf /"        # Blocked
```

### Unified Output Format

Robot mode uses the unified `OutputFormat` enum:

```bash
# These are equivalent in robot mode
dcg --robot test "cmd"
dcg --robot --format json test "cmd"
```

Available formats:
- `pretty` / `text` / `human` - Human-readable (default without --robot)
- `json` / `sarif` / `structured` - JSON output (default with --robot)
- `jsonl` - JSON Lines (one object per line, for streaming)
- `compact` - Compact single-line output

## Best Practices

1. **Start with defaults**: The default `medium` trust level is safe for most
   use cases.

2. **Grant trust incrementally**: Only increase trust for agents after
   observing their behavior.

3. **Use project-level configs**: Put agent profiles in `.dcg.toml` so they're
   version-controlled with your project.

4. **Restrict unknown agents**: Always configure `agents.unknown` with lower
   trust in production environments.

5. **Review the JSON output**: Use `--format json` in CI to audit which agents
   are accessing your codebase.

6. **Use robot mode for scripting**: When integrating dcg into automated
   workflows, use `--robot` for consistent, parseable output.

7. **Check exit codes**: In robot mode, use exit codes to make decisions
   without parsing JSON for simple allow/deny checks.

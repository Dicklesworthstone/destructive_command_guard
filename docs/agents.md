# Agent-Specific Profiles

dcg can detect which AI coding agent is invoking it and apply agent-specific
trust levels and configuration overrides. This allows you to grant higher
trust to well-behaved agents while maintaining strict controls for unknown ones.

## Supported Agents

| Agent | Detection Method | Environment Variable |
|-------|------------------|---------------------|
| Claude Code | Environment | `CLAUDE_CODE=1` or `CLAUDE_SESSION_ID` |
| Augment Code | Environment | `AUGMENT_AGENT=1` or `AUGMENT_CONVERSATION_ID` |
| Aider | Environment | `AIDER_SESSION=1` |
| Continue | Environment | `CONTINUE_SESSION_ID` |
| Codex CLI | Environment | `CODEX_CLI=1` |
| Gemini CLI | Environment | `GEMINI_CLI=1` |
| GitHub Copilot CLI | Environment | `COPILOT_CLI=1` or `COPILOT_AGENT_START_TIME_SEC` |
| VS Code Copilot Chat | Hook payload | `tool_name` is `runTerminalCommand`, `run_in_terminal`, or `runInTerminal` |
| Cursor IDE | Environment | `CURSOR_IDE=1` (set by dcg's hook script) |
| Hermes Agent | Environment | `HERMES_AGENT=1` or `HERMES_SESSION_ID` |
| Grok (xAI) | Environment | `GROK_SESSION_ID`, `GROK_HOOK_EVENT`, or `GROK_WORKSPACE_ROOT` |
| Pi | Environment | `PI_CODING_AGENT=true` |

## Detection Priority

Agent detection follows this priority order:

1. **Explicit `--agent` flag**: Manual override via CLI
2. **Environment variables**: Most agents set identifying env vars
3. **Parent process inspection**: Fallback check of process tree
4. **Unknown**: Default when no agent is detected

## Trust Levels

Three trust levels label how much you trust a given agent:

| Level | Description |
|-------|-------------|
| `high` | Agent has proven reliable; typically paired with a broader allowlist and fewer packs |
| `medium` | Default; standard configuration |
| `low` | Extra caution; typically paired with more packs and a restricted allowlist |

### How trust levels work

The `trust_level` field is an **advisory label**. It is recorded in JSON output
and shown in verbose/debug logs so you (and downstream tooling) can see what
trust tier was in effect for a given evaluation. It does **not**, by itself,
change which rules fire or how confidence scores are computed.

All behavioral differences between agents come from the other profile options
that you configure alongside the trust level:

| Option | What it does | Typical usage |
|--------|-------------|---------------|
| `disabled_packs` | Removes packs (and their sub-packs) from evaluation | High-trust agents that don't need certain rule sets |
| `extra_packs` | Adds packs to evaluation | Low-trust agents that should be checked against more rules |
| `additional_allowlist` | Adds command patterns that bypass deny rules | High-trust agents with known-safe build commands |
| `disabled_allowlist` | When `true`, ignores *all* allowlist entries (base + additional) | Low-trust agents that should never get a free pass |

In other words: setting `trust_level = "high"` alone does not relax any rules.
You must also adjust `disabled_packs`, `extra_packs`, `additional_allowlist`,
or `disabled_allowlist` to change evaluation behavior.

### Why the separation?

This design is intentional. Trust is not a magic knob -- different environments
need different trade-offs. A "high trust" agent in one project might need strict
database rules but relaxed filesystem rules, while in another project the
opposite applies. By keeping the label separate from the behavioral knobs, dcg
gives you full control without hidden side effects.

### Practical examples

**High-trust agent** -- a well-tested agent that runs routine build/test
commands. You widen the allowlist and disable packs that produce false positives
for its workflow:

```toml
[agents.claude-code]
trust_level = "high"
additional_allowlist = ["npm run build", "cargo test", "make lint"]
disabled_packs = ["kubernetes"]
```

**Medium-trust agent (default)** -- standard rules, no overrides:

```toml
[agents.default]
trust_level = "medium"
```

**Low-trust agent** -- an unknown or new agent. You add extra packs and disable
the allowlist so every command is evaluated against the full rule set:

```toml
[agents.unknown]
trust_level = "low"
disabled_allowlist = true
# Real pack / category IDs (see `dcg packs` / docs/packs/README.md). A category
# ID like "database" expands to every database.* sub-pack. "paranoid" is a
# graduation mode, not a pack — use the real `strict_git` pack for stricter git
# rules, and `core.filesystem` (not "filesystem") for the filesystem pack.
extra_packs = ["strict_git", "database", "system"]
```

## Configuration

Configure agent profiles in your `config.toml`:

```toml
# Trust Claude Code more (it sets CLAUDE_CODE=1)
[agents.claude-code]
trust_level = "high"
additional_allowlist = ["npm run build", "cargo test"]

# Restrict unknown agents
[agents.unknown]
trust_level = "low"
disabled_allowlist = true
extra_packs = ["strict_git", "database"]

# Default profile for unspecified agents
[agents.default]
trust_level = "medium"
```

### Profile Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `trust_level` | string | `"medium"` | Advisory label: `"high"`, `"medium"`, or `"low"`. Included in JSON/verbose output but does not change rule evaluation by itself. |
| `disabled_packs` | array | `[]` | Pack or category IDs to remove from evaluation for this agent (a category ID drops every matching sub-pack). |
| `extra_packs` | array | `[]` | Additional pack or category IDs to enable for this agent (a category ID expands to all its sub-packs). |
| `additional_allowlist` | array | `[]` | Command patterns to allowlist for this agent (added on top of the base allowlist). |
| `disabled_allowlist` | bool | `false` | If `true`, ignore all allowlist entries for this agent (more restrictive). |

### Example: Restrictive Config for CI

```toml
# In .dcg.toml (project-level)
[agents.unknown]
trust_level = "low"
disabled_allowlist = true
extra_packs = ["strict_git", "database", "system"]

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

**Hook mode** (default when no subcommand) follows the active hook protocol:
- Claude Code, Gemini CLI, Copilot CLI, VS Code Copilot Chat, and compatible JSON-hook protocols emit
  JSON on stdout for denials and empty stdout for allows.
- Codex CLI uses strict hook parsing, so dcg emits a minimal
  `hookSpecificOutput` denial on stdout and exits 0.
- Rich output always goes to stderr for human visibility.

**Robot mode** with subcommands uses standardized exit codes:
- Exit 1 for denials (allows scripting with `$?`)
- Pure JSON on stdout
- Silent stderr

## Rich Output and Agent Compatibility

dcg keeps agent-facing output and human-facing output on separate streams. This
is the compatibility contract for rich terminal formatting.

| Stream | Purpose | Hook-mode content | Robot-mode content |
|--------|---------|-------------------|--------------------|
| stdout | Agent and script parsing | Protocol JSON for denials, empty for allows | JSON only |
| stderr | Human-visible diagnostics | Rich or plain text warning boxes | Silent |

Rich output is display-only. It must never be parsed by agents and must never be
written to stdout. When dcg prints Unicode boxes, colors, highlighted commands,
or suggestion panels, that output belongs on stderr.

### Rich Output Selection

dcg uses rich terminal formatting only when the runtime is suitable. It falls
back to plain output when any of these controls are active:

| Control | Effect |
|---------|--------|
| `DCG_NO_RICH=1` | Disable rich formatting while keeping normal command behavior |
| `--legacy-output` or `DCG_LEGACY_OUTPUT=1` | Force legacy/plain rendering paths |
| `NO_COLOR=1` or `DCG_NO_COLOR=1` | Disable colorized output |
| `TERM=dumb` | Use dumb-terminal-safe output |
| `CI=1` | Suppress rich interactive formatting in CI |
| non-TTY stdout | Prefer plain output for pipeline-friendly behavior |
| `--robot` or `DCG_ROBOT=1` | Emit machine-readable stdout and keep stderr silent |

### Wrapper Guidance

Agent wrappers should choose the interface that matches their parser:

```bash
# Hook integration: preserve both streams.
dcg < hook-input.json >hook-stdout.json 2>human-warning.txt

# Scripting integration: use robot mode and parse stdout only.
dcg --robot test "rm -rf /" >decision.json 2>/dev/null
```

For Codex and Claude-compatible hook integrations, parse stdout when it is
non-empty and treat empty stdout with exit 0 as allow. Codex's denial payload is
minimal and intentionally omits dcg-only metadata.

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

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
| VS Code Copilot Chat | Hook payload | `tool_name` is `runTerminalCommand`, `run_in_terminal`, or `runInTerminal`; the Agent Host's batched `toolCalls` envelope is also recognized, with every shell entry evaluated independently |
| Cursor IDE | Environment | `CURSOR_IDE=1` (set by dcg's hook script) |
| Hermes Agent | Environment | `HERMES_AGENT=1` or `HERMES_SESSION_ID` |
| Grok (xAI) | Environment | `GROK_SESSION_ID`, `GROK_HOOK_EVENT`, or `GROK_WORKSPACE_ROOT` |
| Oh My Pi (`omp`) | Explicit bridge / process | Generated extension passes `--agent omp`; exact `omp` and `oh-my-pi` process names are fallback matches |
| Pi | Environment | `PI_CODING_AGENT=true` |
| Posit Assistant | Environment | `PA_PROJECT_DIR` (set in hook subprocesses; checked last among environment markers so agents with their own markers win — environment detection still precedes parent-process detection) |

## Detection Priority

Agent detection follows this priority order:

1. **Explicit `--agent` flag**: Manual override via CLI
2. **Environment variables**: Most agents set identifying env vars
3. **Parent process inspection**: Fallback check of process tree
4. **Unknown**: Default when no agent is detected

### Oh My Pi (`omp`)

Install dcg's native OMP ExtensionAPI module with:

```bash
dcg install --omp
```

The default user path is `~/.omp/agent/extensions/dcg-guard.ts`. OMP named
profiles use `~/.omp/profiles/<name>/agent/extensions/dcg-guard.ts`; dcg follows
OMP's `OMP_PROFILE`-before-`PI_PROFILE` precedence and honors
`PI_CONFIG_DIR` for a config directory name relative to the user's home plus
`PI_CODING_AGENT_DIR` for the default profile. Drive-qualified
`PI_CONFIG_DIR` values are rejected on Windows because Rust would otherwise
resolve them differently from OMP's home-relative `path.join` behavior. Use
`dcg install --omp --project` to install `<cwd>/.omp/extensions/dcg-guard.ts`
instead. OMP checks only the current working directory for native project
extensions; it neither requires Git nor walks to an ancestor, so launch OMP
from that same directory.

The extension uses OMP's pre-execution `tool_call` event and sends each `bash`
command to `dcg --robot test --stdin --agent omp --format json` with the dialect
selected by OMP's execution route. Pinning the private bridge format prevents
ambient `DCG_FORMAT` from redirecting or invalidating its compact protocol
without removing that variable from supported environment-conditioned policy.
The embedded install-time absolute dcg path is
authoritative: ambient `DCG_BIN` cannot redirect the marker-owned guard; rerun
`dcg install --omp --force` after moving the binary. Ordinary and managed-async
calls use OMP's embedded Brush shell and pass `--dialect posix`, including on
native Windows. An eligible local `pty: true` call instead maps OMP's
configured external shell to `--dialect posix`, `cmd`, or `ps`; `PI_NO_PTY=1`
disables that PTY route. A dcg deny, ask, or indeterminate result returns
`{ block: true, reason }` to OMP.
Because the bridge supplies `--agent omp` explicitly, OMP remains distinct from
legacy Pi even when OMP exposes Pi-family compatibility variables. The
canonical profile key is `agents.omp`; `oh-my-pi` is accepted as an alias.
When `[history] enabled = true`, these robot-boundary evaluations are persisted
with the canonical `agent_type = "omp"`; ordinary human `dcg test` diagnostics
remain outside command history.

The bridge spawns dcg directly, without a shell, and gives Bun a 30-second
parent-side timeout with a hard kill signal. This is a pathological-hang
backstop above dcg's ordinary 1-second evaluator default and the broad Windows
preset's 3-second default, not a replacement for those configurable budgets.
An explicit evaluator budget above 30 seconds is nevertheless capped by this
OMP-specific outer ceiling; direct hook and diagnostic invocations retain their
configured budget.
If the backstop terminates a child before it returns a safety verdict, the
bridge reads Bun's post-exit `signalCode`, reports the exact signal as an
infrastructure failure, and follows the established visible fail-open policy.
This keeps an ordinary numeric exit 137 distinct from a timeout or other
`SIGKILL`. A complete deny, ask, or indeterminate verdict already written to
stdout remains authoritative and blocks regardless of the signal; dcg's
independent blocking exit 1 remains authoritative if status observation is
otherwise contradictory or faulty. Other abnormal exit statuses remain
visible even when a deny-like stdout verdict is authoritative.

OMP's public ExtensionAPI does not expose its ACP client-terminal capability or
selected backend, and both ACP and JSON-RPC surface as `mode: "rpc"`. The bridge
therefore does not infer a Windows dialect from mode: non-PTY RPC calls remain
POSIX-scoped so ordinary JSON-RPC execution does not gain Cmd/PowerShell false
positives. As a result, an ACP client-terminal call does not yet receive exact
Cmd/PowerShell-specific coverage; closing that residual requires OMP to expose
the actual BashTool route before the `tool_call` handler runs.

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

[agents.omp]
trust_level = "medium"
extra_packs = ["strict_git"]

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

### Example: Agent Profiles for a Trusted Config

```toml
# In ~/.config/dcg/config.toml, or in a reviewed file selected with DCG_CONFIG
[agents.unknown]
trust_level = "low"
disabled_allowlist = true
extra_packs = ["strict_git", "database", "system"]

[agents.claude-code]
trust_level = "medium"
additional_allowlist = ["npm test", "npm run lint"]
```

Automatically discovered repository `.dcg.toml` files cannot define agent
profiles. Profiles can disable packs or add allowlist entries, so accepting
them from a newly cloned repository would cross dcg's security boundary. To
use a reviewed repository-owned profile deliberately, invoke dcg with
`DCG_CONFIG=.dcg.toml` (or copy the profile into the user config).

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

3. **Version reviewed profiles carefully**: A repository can keep a reviewed
   profile in `.dcg.toml`, but it only takes effect when explicitly selected
   with `DCG_CONFIG=.dcg.toml`; automatic discovery ignores agent profiles.

4. **Restrict unknown agents**: Always configure `agents.unknown` with lower
   trust in production environments.

5. **Review the JSON output**: Use `--format json` in CI to audit which agents
   are accessing your codebase.

6. **Use robot mode for scripting**: When integrating dcg into automated
   workflows, use `--robot` for consistent, parseable output.

7. **Check exit codes**: In robot mode, use exit codes to make decisions
   without parsing JSON for simple allow/deny checks.

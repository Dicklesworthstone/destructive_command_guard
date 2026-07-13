# Configuration Guide

This guide explains how dcg loads configuration and how to enable packs,
allowlists, and hooks.

## Configuration Precedence (Highest → Lowest)

1. **CLI flags**
2. **Environment variables**
3. **Explicit config path**: `DCG_CONFIG=/path/to/config.toml`
4. **Project config**: `.dcg.toml` at repo root
5. **User config**: `~/.config/dcg/config.toml`
6. **System config**: `/etc/dcg/config.toml`

## Pack Configuration

Enable or disable packs in config files:

```toml
[packs]
enabled = [
  "database.postgresql",
  "containers.docker",
  "kubernetes", # category ID — enables all kubernetes.* sub-packs
]

disabled = [
  # "database.redis",  # optional: keep a category enabled but drop one sub-pack
]
```

Category IDs in `enabled` / `disabled` (and in agent-profile `extra_packs` /
`disabled_packs`) expand to every matching sub-pack. Use IDs listed by
`dcg packs` or in `docs/packs/README.md`. Names such as `"paranoid"` are
[graduation modes](graduated-response.md), not packs — enable the real
`strict_git` pack for stricter git rules.

### Environment Overrides

- `DCG_PACKS="containers.docker,kubernetes"`
- `DCG_DISABLE="kubernetes.helm"`
- `DCG_VERBOSE=1`
- `DCG_COLOR=auto|always|never`
- `DCG_NO_RICH=1`
- `DCG_BYPASS=1` (escape hatch; use sparingly)

## Output Configuration

dcg separates machine-readable output from human-facing terminal output. Hook and
robot-mode integrations must read protocol responses from stdout and treat stderr
as advisory human output only. Human warnings, rich formatting, and progress
output are never required for automation.

### Rich Terminal Output

Rich output is enabled only when the current output mode is human-facing, stdout
is a TTY, and no plain-output control is active. These controls force plain,
automation-friendly output:

| Control | Default | Effect |
|---------|---------|--------|
| `--legacy-output` or `DCG_LEGACY_OUTPUT=1` | unset | Use the legacy/plain renderer. |
| `DCG_NO_RICH=1` | unset | Disable rich formatting while keeping normal command output. |
| `--no-color`, `DCG_NO_COLOR=1`, or `NO_COLOR=1` | unset | Disable colors and rich terminal styling. |
| `DCG_COLOR=never` | `auto` | Disable colors through the general configuration override. |
| `TERM=dumb` | terminal-defined | Use a plain fallback for minimal terminals. |
| `CI=1` | unset | Use a plain fallback in CI and other non-interactive runners. |
| Piped stdout or non-TTY stdout | TTY-detected | Disable rich output automatically. |

Examples:

```bash
DCG_NO_RICH=1 dcg scan .
NO_COLOR=1 dcg doctor
dcg scan . | head
```

### Theme Configuration

High-contrast output can be enabled with `DCG_HIGH_CONTRAST=1` or config:

```toml
[output]
high_contrast = true

[theme]
palette = "high-contrast"
use_unicode = false
```

### Robot and Hook Modes

Use robot mode for agent and script integrations:

```bash
DCG_ROBOT=1 dcg test --format json "git reset --hard HEAD~1"
dcg --robot packs
```

Robot mode forces JSON output on stdout, suppresses stderr, disables rich output,
and uses standardized machine-readable exit codes.

In hook mode, keep stdout reserved for the hook protocol. Human-facing denial or
warning text is written to stderr so agents can parse stdout without terminal
decorations. Codex hook protocol denials use the stricter Codex-compatible path:
exit code `2` with the denial reason on stderr instead of stdout JSON.

Related references:

- [README.md](../README.md) for the user-facing overview.
- [AGENTS.md](../AGENTS.md) for the hook protocol contract.
- [docs/agents.md](agents.md) for agent detection and profile configuration.

## External Packs (YAML)

External packs let you define custom rules without modifying the binary. The
authoritative schema is `docs/pack.schema.yaml`. The schema is versioned via
`schema_version` for forward compatibility.

### Example Pack File

```yaml
schema_version: 1
id: mycompany.deploy
name: MyCompany Deployment Policies
version: 1.0.0
description: Prevents accidental production deployments

keywords:
  - deploy
  - release
  - publish

destructive_patterns:
  - name: prod-direct
    pattern: deploy\\s+--env\\s*=?\\s*prod
    severity: critical
    description: Direct production deployment
    explanation: |
      Production deployments must go through the release pipeline.
      Direct deploys bypass approval workflows and audit logging.
      Use https://deploy.mycompany.com instead.

safe_patterns:
  - name: staging-deploy
    pattern: deploy\\s+--env\\s*=?\\s*(staging|dev)
    description: Non-production deployments are allowed
```

### Rust Struct Mapping (for the pack loader)

```rust
#[derive(Debug, Deserialize)]
pub struct ExternalPack {
    pub schema_version: u32,
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub destructive_patterns: Vec<ExternalDestructivePattern>,
    #[serde(default)]
    pub safe_patterns: Vec<ExternalSafePattern>,
}

#[derive(Debug, Deserialize)]
pub struct ExternalDestructivePattern {
    pub name: String,
    pub pattern: String,
    #[serde(default)]
    pub severity: Option<String>,
    pub description: Option<String>,
    pub explanation: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ExternalSafePattern {
    pub name: String,
    pub pattern: String,
    pub description: Option<String>,
}
```

## Allowlists

Allowlists are layered in this order:

1. **Project**: `.dcg/allowlist.toml`
2. **User**: `~/.config/dcg/allowlist.toml`
3. **System**: `/etc/dcg/allowlist.toml`

Use project allowlists for repo-specific exceptions and user allowlists for
personal workflows.

## Hook Configuration

Scan hooks are loaded from `.dcg/hooks.toml` when present. See
`docs/scan-precommit-guide.md` for hook configuration and pre-commit examples.

## Heredoc Scanning

Heredoc scanning can be enabled or configured with:

```toml
[heredoc]
enabled = true
timeout_ms = 50
max_body_bytes = 1048576
max_body_lines = 10000
max_heredocs = 10
fallback_on_parse_error = true
fallback_on_timeout = true
```

CLI overrides:
- `--heredoc-scan` / `--no-heredoc-scan`
- `--heredoc-timeout <ms>`
- `--heredoc-languages <lang1,lang2,...>`

## Agent-Specific Profiles

dcg can detect which AI coding agent is invoking it and apply agent-specific
trust levels and configuration overrides.

```toml
[agents.claude-code]
trust_level = "high"
additional_allowlist = ["npm run build"]

[agents.unknown]
trust_level = "low"
extra_packs = ["paranoid"]
```

See [agents.md](agents.md) for full documentation on agent detection, trust
levels, and profile configuration.

## Editor Autocomplete & Validation (JSON Schema)

dcg publishes a JSON Schema for `config.toml` so editors can offer field
autocomplete, inline docs, and validation. The schema is committed at the repo
root as [`config.schema.json`](../config.schema.json) and is generated directly
from dcg's Rust config types, so it always matches the running binary.

### Even Better TOML (VS Code)

Install the **Even Better TOML** extension, then either add a schema directive
comment at the top of your `config.toml`:

```toml
#:schema https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/config.schema.json

[packs]
enabled = ["kubernetes"]
```

or associate the schema in your VS Code `settings.json`:

```json
{
  "evenBetterToml.schema.associations": {
    "**/dcg/config.toml": "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/config.schema.json",
    "**/.dcg.toml": "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/config.schema.json"
  }
}
```

### taplo (CLI / LSP)

Point taplo at the schema in a `.taplo.toml` at your repo root:

```toml
[[rule]]
include = ["**/dcg/config.toml", "**/.dcg.toml"]

[rule.schema]
path = "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/config.schema.json"
```

### Regenerating the schema

Print the schema to stdout or write it to a file with the `config schema`
subcommand:

```bash
# Print to stdout
dcg config schema

# Write (or overwrite) the committed schema
dcg config schema --output config.schema.json
```

A test (`tests/config_schema_drift.rs`) asserts the committed
`config.schema.json` matches what the current config types generate, so CI fails
if a config struct changes without the schema being regenerated. To bless an
intentional change, run `DCG_BLESS_SCHEMA=1 cargo test --test config_schema_drift`
(or just re-run the `--output` command above).

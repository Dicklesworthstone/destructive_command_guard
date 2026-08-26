# Configuration Guide

This guide explains how dcg loads configuration and how to enable packs,
allowlists, and hooks.

## Configuration Precedence (Highest → Lowest)

1. **CLI flags**
2. **Environment variables**
3. **Explicit config path**: `DCG_CONFIG=/path/to/config.toml`
4. **User config**: `~/.config/dcg/config.toml`
5. **System config**: `/etc/dcg/config.toml`

### Repository config trust boundary

The automatically discovered `.dcg.toml` at a repository root is not a normal
precedence layer. Opening a newly cloned repository must not give that
repository authority over the user's security policy. Automatic discovery
therefore accepts only settings that monotonically add enforcement:

- `[packs].enabled`
- `[policy].default_mode = "deny"` and per-pack/per-rule entries equal to `"deny"`
- `[general].fail_closed = true`
- `[general].unverified_decision = "deny"`
- `[heredoc].enabled = true`
- `[heredoc].fallback_on_parse_error = false`
- `[heredoc].fallback_on_timeout = false`

Every other project setting is ignored by automatic discovery. In particular,
a repository cannot add allow rules, disable packs, load repository-controlled
custom pack files, inject custom regex overrides (including block regexes),
reduce resource limits, restrict scanned languages, relax agent profiles, or
alter global logging/history/output paths.

After reviewing a repository's config, a user can deliberately give the whole
file normal config authority for an invocation:

```bash
DCG_CONFIG=.dcg.toml dcg test "git reset --hard"
```

Because `DCG_CONFIG` is an explicit user-controlled selection, that file is
loaded in full rather than through the enforcement-only project filter.

On Unix, automatic discovery additionally requires `.dcg.toml` to be a direct
regular file and binds the pathname to the same descriptor used for the
bounded read. Native Windows currently ignores automatic project config until
dcg has equivalent reparse-point-safe open and file-identity checks. A reviewed
file remains available there through explicit `DCG_CONFIG` selection.

Implicit system config is likewise accepted only on Unix, from a direct
root-owned path whose file and ancestor directories are not group/world
writable (`/private/etc/dcg` is used on macOS to avoid the `/etc` symlink).
Native Windows should use user or explicitly selected config until native ACL
validation is available.

## Decision Policy

Matched rules use severity defaults unless `[policy]` overrides them:

```toml
[policy]
default_mode = "ask"

[policy.packs]
"database.snowflake" = "deny"

[policy.rules]
"core.git:push-force-long" = "warn"
```

- `deny` blocks the command.
- `ask` requires explicit operator approval on Claude-compatible and Copilot
  hooks. Protocols without a native review decision fail closed with their
  normal deny/block response.
- `warn` prints a warning but allows the command.
- `log` allows silently while retaining configured audit logging.

`ask` is opt-in and may be selected globally, per pack, or per rule. Broad
`warn`/`log` policy cannot relax Critical rules; that still requires an
explicit per-rule override. `DCG_POLICY_DEFAULT_MODE=ask` is the equivalent
environment override.

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

### Curated Windows company preset

`careful_company_running_windows` is a curated preset for bypass-enabled agents
on Windows. It enables its six outbound-communication and guardrail packs plus
an explicitly reviewed set of the existing Windows, database, storage, remote,
backup, secrets, and cloud packs. The membership is pinned in the binary:
future packs in those reused categories do not silently join an organization's
deployed policy.

```toml
[packs]
enabled = ["careful_company_running_windows"]

# Exclusions are applied after preset/category expansion.
disabled = [
  # "careful_company_running_windows.tunnel",
  # "database.mongodb",
]
```

The preset includes `database.snowflake` and all four `windows.*` packs. The
always-on `core.*` protections and default-on `system.disk` remain independent.
Disabling `careful_company_running_windows` removes the contribution made by
the preset. Independently enabled leaves and native-Windows packs that are
default-on remain enabled through those separate sources.
See [Careful company policy for Windows agents](careful-company-windows.md) for
the channel inventory, staged rollout, `hfdt` trust boundary, and native-Windows
configuration limitations.

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
decorations. Warning-only decisions leave stdout empty. Codex hook protocol
denials use a minimal `hookSpecificOutput` denial on stdout and exit code `0`,
which is the contract Codex's hook parser accepts.

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

Effective allowlists are layered in this order:

1. **Explicitly trusted project**: `.dcg/allowlist.toml`
2. **User**: `~/.config/dcg/allowlist.toml`
3. **System**: `/etc/dcg/allowlist.toml`

Repository contents are not a trust grant. The project layer is inactive unless
`DCG_CONFIG` canonically selects the regular repo-root `.dcg.toml` for that
invocation. `dcg allowlist add`, `add-command`, `remove`, and `prune` therefore
default to the user layer and reject `--project` while repository policy is
untrusted. For a repository-scoped user exception, pass both the repository root
and `<repo-root>/**` with repeatable `--path` flags. `list --project`, `validate
--project`, and `prune --project --dry-run` may inspect the raw inactive file and
label it `INACTIVE`; default reads operate on effective layers only.

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

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
  "kubernetes", # enables all kubernetes sub-packs
]

disabled = [

]
```

### Environment Overrides

- `DCG_PACKS="containers.docker,kubernetes"`
- `DCG_DISABLE="kubernetes.helm"`
- `DCG_VERBOSE=1`
- `DCG_COLOR=auto|always|never`
- `DCG_BYPASS=1` (escape hatch; use sparingly)

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

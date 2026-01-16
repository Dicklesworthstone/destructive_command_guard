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

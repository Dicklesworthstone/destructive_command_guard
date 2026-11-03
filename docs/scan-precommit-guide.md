# dcg scan: Pre-Commit Integration Guide

> Protect your repositories from destructive commands **before** they're committed.

This guide covers how to integrate `dcg scan` into your pre-commit workflow safely, with a focus on gradual rollout and minimizing false positive friction.

---

## What dcg scan Is (and Is Not)

### What it is

**dcg scan** analyzes files for destructive commands in *executable contexts*:

- GitHub Actions workflows (`.github/workflows/*.yml`)
- Dockerfiles (`RUN` commands)
- Shell scripts (`*.sh`, `*.bash`)
- Makefiles (recipe lines)
- GitLab CI (`.gitlab-ci.yml`)
- Docker Compose (`command:` fields)
- Terraform (`local-exec` provisioners)

The key difference from the real-time hook (`dcg` on its own):

| Mode | Protects | When |
|------|----------|------|
| **Hook** (`dcg`) | Interactive agent commands | At execution time |
| **Scan** (`dcg scan`) | Commands in committed files | At commit/CI time |

### What it is NOT

- **Not a full static analysis engine.** It does not understand your shell logic, variable expansion, or conditional branches.
- **Not a naive grep.** It uses extractors that understand file formats and only matches commands in executable contexts (not comments, documentation, or string literals).
- **Not a replacement for the hook.** Use both: the hook protects interactive execution; scan protects your repository.

---

## Quick Start

### One-command installation

```bash
# Navigate to your git repository
cd /path/to/your/repo

# Install the pre-commit hook
dcg scan install-pre-commit
```

This creates `.git/hooks/pre-commit` with a dcg-managed hook that runs `dcg scan --staged` before each commit.

### Manual integration

If you already have a pre-commit hook or use a hook manager:

```bash
# Add this line to your existing hook
dcg scan --staged
```

For hook managers like Husky, Lefthook, or pre-commit.com, see [Hook Manager Examples](#hook-manager-examples) below.

### Uninstallation

```bash
dcg scan uninstall-pre-commit
```

---

## Recommended Rollout Plan (Warn-First)

> **TL;DR:** Start conservative, expand gradually. Don't turn on warning-as-fail on day one.

### Phase 1: Observe (1-2 weeks)

Enable scanning with defaults - only catastrophic rules (`fail_on = error`) block commits.

```toml
# .dcg/hooks.toml
[scan]
fail_on = "error"      # Only block on high-confidence catastrophic rules
format = "pretty"      # Human-readable output
```

During this phase:
- Collect feedback from the team on false positives
- Use `dcg explain "<command>"` to understand why something was flagged
- Build up your allowlist for legitimate use cases

### Phase 2: Expand scope

After the team is comfortable:

1. **Add more file types** to scanning:
   ```toml
   [scan.paths]
   include = [
     ".github/workflows/**",
     "Dockerfile*",
     "Makefile",
     "scripts/**/*.sh",
   ]
   ```

2. **Consider enabling warning-as-fail** for specific high-risk patterns:
   ```bash
   # Test locally before enforcing
   dcg scan --staged --fail-on warning
   ```

### Phase 3: Enforce in CI

Once local pre-commit is stable, add CI enforcement. Provision `dcg` on the
runner or in its image with the [verified release installation recipe](../README.md#quick-install-verified-release)
before this job; the scan job does not download and execute an installer:

```yaml
# .github/workflows/dcg-scan.yml
name: DCG Scan
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - run: dcg --version
      - run: dcg scan --git-diff origin/${{ github.base_ref }}...HEAD --fail-on error
```

---

## How to Interpret Findings

### Output format

```
[ERROR] .github/workflows/ci.yml:42
  Rule:     core.git:reset-hard
  Severity: critical
  Reason:   git reset --hard destroys uncommitted changes

  → dcg allow core.git:reset-hard -r "CI cleanup" --user
```

### Field meanings

| Field | Description |
|-------|-------------|
| `[ERROR]`/`[WARN]`/`[INFO]` | Severity level - ERROR blocks by default |
| File path + line | Where the command was extracted from |
| `Rule:` | Stable rule ID (`pack_id:pattern_name`) for allowlisting |
| `Severity:` | `critical`, `high`, `medium`, `low` - how dangerous |
| `Reason:` | Why this command is flagged |
| `→` suggestion | How to fix or allowlist |

### Severity levels

| Severity | Default action | Examples |
|----------|---------------|----------|
| `critical` | Block (`error`) | `git reset --hard`, `rm -rf /`, `DROP DATABASE` |
| `high` | Block (`error`) | `git push --force`, `docker system prune -a` |
| `medium` | Warn | Context-dependent patterns |
| `low` | Inform | Advisory patterns, low confidence |

---

## How to Fix a Finding

### Option 1: Change the code (preferred)

Many destructive commands have safer alternatives:

| Instead of | Use |
|------------|-----|
| `git reset --hard` | `git stash` or targeted `git checkout` |
| `git push --force` | `git push --force-with-lease` |
| `rm -rf ./build` | Use build tool's clean (e.g., `cargo clean`, `make clean`) |
| `docker system prune -af` | `docker image prune --filter "until=24h"` |

### Option 2: Investigate with explain

```bash
# See why a command is flagged
dcg explain "git reset --hard HEAD~1"
```

This shows the full decision trace: which pack matched, what pattern triggered, and whether any allowlists applied.

### Option 3: Allowlist (if it's a false positive)

If the command is safe in your context (e.g., a CI cleanup step), allowlist it:

```bash
repo_root=$(git rev-parse --show-toplevel)

# Allowlist by rule ID (recommended - most stable)
dcg allow core.git:reset-hard -r "Used for CI cleanup after tests" \
  --user --path "$repo_root" --path "$repo_root/**"

# Or allowlist a specific command (exact match)
dcg allowlist add-command "git reset --hard HEAD" -r "CI cleanup" \
  --user --path "$repo_root" --path "$repo_root/**"
```

**Important safety notes:**

1. **Always provide a reason** (`-r "..."`) - document why this is safe
2. **Use user-owned path scopes** for project-specific exceptions. A checked-in
   `.dcg/allowlist.toml` is inactive until the user reviews and explicitly
   selects the repo-root `.dcg.toml` through `DCG_CONFIG`.
3. **Use expiration** for temporary overrides:
   ```bash
   dcg allow core.git:reset-hard -r "Migration" \
     --expires "2026-02-01T00:00:00Z" --user \
     --path "$repo_root" --path "$repo_root/**"
   ```

### Viewing and managing allowlists

```bash
# List effective allowlist entries
dcg allowlist list

# Inspect raw project policy (marked INACTIVE unless explicitly trusted)
dcg allowlist list --project

# Remove the user-owned entry
dcg allowlist remove core.git:reset-hard --user

# Validate allowlist files
dcg allowlist validate
```

---

## Privacy and Secrets

### Command redaction

By default, scan output shows full commands. In CI, this could expose secrets.

```toml
# .dcg/hooks.toml
[scan]
redact = "quoted"   # Redact quoted strings: rm -rf "[REDACTED]"
# redact = "aggressive"  # Redact more aggressively
# redact = "none"        # Show full commands (default, for local use)
```

### CI best practices

1. **Use `redact = "quoted"` in CI** to avoid printing secrets in logs
2. **Limit output** with `truncate` and `max_findings`:
   ```toml
   [scan]
   truncate = 100       # Truncate long command output
   max_findings = 50    # Limit total findings per scan
   ```
3. **Use JSON format** for machine parsing in CI:
   ```toml
   [scan]
   format = "json"
   ```

---

## Configuration Reference

### .dcg/hooks.toml

Create this file in your repository root to configure scan behavior:

```toml
[scan]
# Output format: "pretty" (human-readable) or "json"
format = "pretty"

# When to fail: "error", "warning", or "none"
fail_on = "error"

# Maximum file size to scan (bytes) - larger files are skipped
max_file_size = 1048576  # 1MB

# Maximum findings to report per run
max_findings = 100

# Command redaction: "none", "quoted", or "aggressive"
redact = "none"

# Truncate long command output (0 = no truncation)
truncate = 200

[scan.paths]
# Glob patterns to include (default: all supported file types)
include = [
  ".github/workflows/**",
  "Dockerfile*",
  "**/Makefile",
  "scripts/**/*.sh",
]

# Glob patterns to exclude
exclude = [
  "vendor/**",
  "node_modules/**",
  "**/testdata/**",
]
```

### CLI flags (override config)

```bash
dcg scan --staged \
  --format json \
  --fail-on warning \
  --max-file-size 2097152 \
  --exclude "tests/**" \
  --include "*.sh"
```

CLI flags always take precedence over `.dcg/hooks.toml`.

---

## Hook Manager Examples

### Husky (npm, v8+)

```bash
# .husky/pre-commit
dcg scan --staged
```

Create with: `npx husky add .husky/pre-commit "dcg scan --staged"`

### Lefthook

```yaml
# lefthook.yml
pre-commit:
  commands:
    dcg-scan:
      run: dcg scan --staged
```

### pre-commit.com

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: dcg-scan
        name: dcg scan
        entry: dcg scan --staged
        language: system
        pass_filenames: false
```

---

## Troubleshooting

### "dcg not found in PATH"

The pre-commit hook cannot find `dcg`. Either:

1. Install dcg globally: `cargo install destructive_command_guard`
2. Add dcg's location to PATH before running git commands
3. Use an absolute path in your hook configuration

### "Refusing to overwrite existing pre-commit hook"

You already have a pre-commit hook not installed by dcg. Options:

1. **Add dcg to your existing hook**: Add `dcg scan --staged` to your hook script
2. **Replace the hook**: Delete it manually, then re-run `dcg scan install-pre-commit`

### False positives

If dcg flags a command that's safe:

1. **Investigate**: `dcg explain "the-command"` to understand why
2. **Allowlist if needed**: add a user-owned entry with repository-root and
   descendant `--path` scopes.
3. **Report**: If it's a pattern bug, file an issue

### Hook is too slow

Scan performance depends on:

1. **Number of staged files** - only changed files are scanned
2. **File sizes** - use `max_file_size` to skip large files
3. **Pattern count** - enable only needed packs in your config

---

## Summary

1. **Install**: `dcg scan install-pre-commit`
2. **Configure**: Create `.dcg/hooks.toml` with your settings
3. **Start conservative**: `fail_on = "error"` initially
4. **Expand gradually**: Add more file types, consider warning-as-fail
5. **Allowlist false positives**: use a user-owned, repository-path-scoped entry
6. **Add CI enforcement**: Scan PR diffs in GitHub Actions/GitLab CI

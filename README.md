# dcg (Destructive Command Guard)

<div align="center">
  <img src="illustration.webp" alt="Destructive Command Guard - Protecting your code from accidental destruction">
</div>

A high-performance Claude Code hook that blocks destructive commands before they execute, protecting your work from accidental deletion by AI coding agents.

<div align="center">
<h3>Quick Install</h3>

```bash
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/master/install.sh?$(date +%s)" | bash
```

<p><em>Works on Linux, macOS, and Windows (WSL). Auto-detects your platform and downloads the right binary.</em></p>
</div>

---

## Origins & Authors

This project began as a Python script by Jeffrey Emanuel, who recognized that AI coding agents, while incredibly useful, occasionally run catastrophic commands that destroy hours of uncommitted work. The original implementation was a simple but effective hook that intercepted dangerous git and filesystem commands before execution.

- **[Jeffrey Emanuel](https://github.com/Dicklesworthstone)** - Original concept and Python implementation ([source](https://github.com/Dicklesworthstone/misc_coding_agent_tips_and_scripts/blob/main/DESTRUCTIVE_GIT_COMMAND_CLAUDE_HOOKS_SETUP.md))
- **[Darin Gordon](https://github.com/Dowwie)** - Rust port with performance optimizations

The Rust port maintains 100% pattern compatibility with the original Python implementation while adding sub-millisecond execution through SIMD-accelerated filtering and lazy-compiled regex patterns.

## Why This Exists

AI coding agents are powerful but fallible. They can accidentally run destructive commands that wipe out hours of uncommitted work, drop database tables, or delete critical files. Common scenarios include:

- **"Let me clean up the build artifacts"** → `rm -rf ./src` (typo)
- **"I'll reset to the last commit"** → `git reset --hard` (destroys uncommitted changes)
- **"Let me fix the merge conflict"** → `git checkout -- .` (discards all modifications)
- **"I'll clean up untracked files"** → `git clean -fd` (permanently deletes untracked files)

This hook intercepts dangerous commands *before* execution and blocks them with a clear explanation, giving you a chance to stash your changes first, or to consciously proceed by running the command manually.

## What It Blocks

**Git commands that destroy uncommitted work:**
- `git reset --hard` / `git reset --merge` - destroys uncommitted changes
- `git checkout -- <file>` - discards file modifications
- `git restore <file>` (without `--staged`) - discards uncommitted changes
- `git clean -f` - permanently deletes untracked files

**Git commands that can destroy remote history:**
- `git push --force` / `git push -f` - overwrites remote commits
- `git branch -D` - force-deletes branches without merge check

**Git commands that destroy stashed work:**
- `git stash drop` / `git stash clear` - permanently deletes stashes

**Filesystem commands:**
- `rm -rf` on any path outside `/tmp`, `/var/tmp`, or `$TMPDIR`

**Heredoc and inline-script scanning (AST-based):**
- Blocks destructive operations embedded inside heredocs, here-strings, and inline scripts
  (e.g., `python -c`, `bash -c`, `node -e`)
- Supported languages: bash, python, javascript, typescript, ruby, perl, go
- Fail-open on parse errors/timeouts to avoid breaking workflows

## What It Allows

**Safe git operations pass through silently:**
- `git status`, `git log`, `git diff`, `git add`, `git commit`, `git push`, `git pull`, `git fetch`
- `git branch -d` (safe delete with merge check)
- `git stash`, `git stash pop`, `git stash list`

**Explicitly safe patterns:**
- `git checkout -b <branch>` - creating new branches
- `git checkout --orphan <branch>` - creating orphan branches
- `git restore --staged <file>` - unstaging (safe, doesn't touch working tree)
- `git clean -n` / `git clean --dry-run` - preview mode
- `rm -rf /tmp/*`, `rm -rf /var/tmp/*`, `rm -rf $TMPDIR/*` - temp directory cleanup

## Modular Pack System

dcg uses a modular "pack" system to organize destructive command patterns by category. Packs can be enabled or disabled in the configuration file. Available packs include:

### Core Packs (Always Enabled)
- **core.git** - Blocks destructive git commands (reset --hard, checkout --, push --force, etc.)
- **core.filesystem** - Blocks dangerous rm -rf outside temp directories

### Database Packs
- **database.postgresql** - Blocks DROP/TRUNCATE in PostgreSQL
- **database.mysql** - Blocks DROP/TRUNCATE in MySQL/MariaDB
- **database.mongodb** - Blocks dropDatabase, drop() in MongoDB
- **database.redis** - Blocks FLUSHALL/FLUSHDB commands
- **database.sqlite** - Blocks DROP in SQLite

### Container Packs
- **containers.docker** - Blocks docker system prune, docker rm -f, etc.
- **containers.compose** - Blocks docker-compose down --volumes
- **containers.podman** - Blocks podman system prune, etc.

### Kubernetes Packs
- **kubernetes.kubectl** - Blocks kubectl delete namespace, etc.
- **kubernetes.helm** - Blocks helm uninstall, etc.
- **kubernetes.kustomize** - Blocks kustomize delete patterns

### Cloud Provider Packs

Cloud resources are often expensive, time-consuming to rebuild, and may contain irreplaceable data. These packs provide broad protection across major cloud providers, with particular attention to container registries (which store deployment-critical images) and logging infrastructure (which captures audit trails and debugging data).

- **cloud.aws** - Blocks destructive AWS CLI commands including EC2 instance termination, RDS deletion, S3 recursive removal, EKS cluster deletion, and **container registry operations** (ECR `delete-repository`, `batch-delete-image`, `delete-lifecycle-policy`) and **CloudWatch Logs** (`delete-log-group`, `delete-log-stream`)
- **cloud.gcp** - Blocks destructive gcloud commands including Compute Engine deletion, Cloud SQL instance deletion, GCS recursive removal, GKE cluster deletion, Firestore deletion, and **Artifact Registry / Container Registry** (`container images delete`, `artifacts docker images delete`, `artifacts repositories delete`)
- **cloud.azure** - Blocks destructive az commands including VM deletion, storage account deletion, resource group deletion, AKS cluster deletion, and **Azure Container Registry** (`acr delete`, `acr repository delete`, `acr repository untag`)

### Infrastructure Packs
- **infrastructure.terraform** - Blocks terraform destroy
- **infrastructure.ansible** - Blocks dangerous ansible patterns
- **infrastructure.pulumi** - Blocks pulumi destroy

### System Packs
- **system.disk** - Blocks dd, mkfs, fdisk operations
- **system.permissions** - Blocks dangerous chmod/chown patterns
- **system.services** - Blocks systemctl stop/disable patterns

### CI/CD Packs
- **cicd.github_actions** - Blocks destructive GitHub Actions operations via `gh` CLI (secret/variable deletion, workflow disable, `gh api DELETE /actions/*`)
- **cicd.gitlab_ci** - Blocks destructive GitLab CI/CD operations via `glab` CLI (pipeline deletion, variable deletion, release deletion, project deletion)
- **cicd.jenkins** - Blocks destructive Jenkins CLI and API operations (delete-job, delete-node, delete-credentials, wipe-out-workspace, clear-queue, Groovy `doDelete` calls)

### Secrets Management Packs

Secrets are among the most sensitive resources in any infrastructure. Accidental deletion or modification of secrets can cause authentication failures across entire systems, break deployments, and potentially expose sensitive data during recovery. These packs protect secrets management systems with a defense-in-depth approach: safe read operations are explicitly allowlisted, while mutations and deletions require deliberate manual execution.

- **secrets.vault** - Blocks destructive HashiCorp Vault operations (delete, destroy, metadata delete)
- **secrets.aws_secrets** - Blocks destructive AWS Secrets Manager and SSM Parameter Store operations. AWS secrets often contain database credentials, API keys, and service account tokens that applications depend on at runtime. Deleting these can cause cascading failures across dependent services. Protects: `delete-secret`, `delete-parameter`, `delete-parameters`, `remove-regions-from-replication`
- **secrets.onepassword** - Blocks destructive 1Password CLI (`op`) operations. 1Password vaults often contain shared team credentials and sensitive documents. Protects: `item delete`, `vault delete`, `document delete`
- **secrets.doppler** - Blocks destructive Doppler secrets management operations. Doppler centralizes environment variables and secrets across development, staging, and production. Protects: `secrets delete`, `configs delete`, `projects delete`, `environments delete`

### Monitoring Packs

Monitoring and observability data is often irreplaceable - logs and metrics capture point-in-time system state that cannot be reconstructed after deletion. These packs protect against accidental destruction of monitoring infrastructure.

- **monitoring.splunk** - Blocks destructive Splunk CLI operations. Splunk indexes can contain years of log data critical for security investigations, compliance audits, and debugging production issues. Protects: `remove index`, `clean eventdata`

### Heredoc Packs
- **heredoc.bash** - Destructive bash operations inside heredocs/inline scripts
- **heredoc.python** - Destructive Python operations inside heredocs/inline scripts
- **heredoc.javascript** - Destructive JavaScript operations inside heredocs/inline scripts
- **heredoc.typescript** - Destructive TypeScript operations inside heredocs/inline scripts
- **heredoc.ruby** - Destructive Ruby operations inside heredocs/inline scripts
- **heredoc.perl** - Destructive Perl operations inside heredocs/inline scripts
- **heredoc.go** - Destructive Go operations inside heredocs/inline scripts

### Other Packs
- **strict_git** - Extra paranoid git protections for teams requiring additional safety margins
- **package_managers** - Blocks dangerous package manager operations across ecosystems. Publishing a package is often irreversible (npm, PyPI, Maven Central have strict policies on unpublishing), and removing dependencies can break builds. Protects:
  - **npm/yarn/pnpm**: `unpublish` (removes published packages)
  - **pip**: `uninstall` (removes installed packages), `install` from raw URLs (security risk)
  - **cargo**: `yank` (marks crate versions as yanked)
  - **gem**: `yank` (removes gem versions)
  - **poetry**: `publish` (publishes to PyPI), `remove` (removes dependencies)
  - **maven**: `deploy` (publishes to repository), `release:perform` (performs release)
  - **gradle**: `publish` (uploads artifacts)
  - **apt/yum/dnf**: removal of critical system packages
  - **brew**: `uninstall` (removes packages)

Enable packs in `~/.config/dcg/config.toml`:

```toml
[packs]
enabled = [
    "database.postgresql",
    "containers.docker",
    "kubernetes",  # Enables all kubernetes sub-packs
    "secrets.aws_secrets",
    "cicd.jenkins",
    "monitoring.splunk",
]
```

Heredoc scanning configuration:

```toml
[heredoc]
# Enable scanning for heredocs and inline scripts (python -c, bash -c, etc.).
enabled = true

# Extraction timeout budget (milliseconds).
timeout_ms = 50

# Resource limits for extracted bodies.
max_body_bytes = 1048576
max_body_lines = 10000
max_heredocs = 10

# Optional language filter (scan only these languages). Omit for "all".
# languages = ["python", "bash", "javascript", "typescript", "ruby", "perl", "go"]

# Graceful degradation (hook defaults are fail-open).
fallback_on_parse_error = true
fallback_on_timeout = true
```

CLI overrides for heredoc scanning:

- `--heredoc-scan` / `--no-heredoc-scan`
- `--heredoc-timeout <ms>`
- `--heredoc-languages <lang1,lang2,...>`

Heredoc documentation:

- `docs/adr-001-heredoc-scanning.md` (architecture and rationale)
- `docs/patterns.md` (pattern authoring + inventory)
- `docs/security.md` (threat model and incident response)

If you encounter commands that should be blocked, please file an issue.

### Environment Variables

Environment variables override config files (highest priority):

- `DCG_PACKS="containers.docker,kubernetes"`: enable packs (comma-separated)
- `DCG_DISABLE="kubernetes.helm"`: disable packs/sub-packs (comma-separated)
- `DCG_VERBOSE=1`: verbose output
- `DCG_COLOR=auto|always|never`: color mode
- `DCG_BYPASS=1`: bypass dcg entirely (escape hatch; use sparingly)

## Installation

### Quick Install (Recommended)

The easiest way to install is using the install script, which downloads a prebuilt binary for your platform:

```bash
# With cache buster (recommended - ensures latest version)
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/master/install.sh?$(date +%s)" | bash

# Without cache buster
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/master/install.sh | bash
```

**With options:**

```bash
# Easy mode: auto-update PATH in shell rc files
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/master/install.sh?$(date +%s)" | bash -s -- --easy-mode

# Install specific version
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/master/install.sh?$(date +%s)" | bash -s -- --version v0.1.0

# Install to /usr/local/bin (system-wide, requires sudo)
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/master/install.sh?$(date +%s)" | sudo bash -s -- --system

# Build from source instead of downloading binary
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/master/install.sh?$(date +%s)" | bash -s -- --from-source
```

> **Note:** If you have [gum](https://github.com/charmbracelet/gum) installed, the installer will use it for fancy terminal formatting.

The install script:
- Automatically detects your OS and architecture
- Downloads the appropriate prebuilt binary
- Verifies SHA256 checksums for security
- Falls back to building from source if no prebuilt is available
- Offers to update your PATH

### From source (requires Rust nightly)

This project uses Rust Edition 2024 features and requires the nightly toolchain. The repository includes a `rust-toolchain.toml` that automatically selects the correct toolchain.

```bash
# Install Rust nightly if you don't have it
rustup install nightly

# Install directly from GitHub
cargo +nightly install --git https://github.com/Dicklesworthstone/destructive_command_guard
```

### Manual build

```bash
git clone https://github.com/Dicklesworthstone/destructive_command_guard
cd destructive_command_guard
# rust-toolchain.toml automatically selects nightly
cargo build --release
cp target/release/dcg ~/.local/bin/
```

## Updating

Run the built-in updater to re-run the installer for your platform:

```bash
dcg update
```

Optional flags mirror the installer scripts (examples):

```bash
dcg update --version v0.2.0
dcg update --system
dcg update --verify
```

You can always re-run `install.sh` / `install.ps1` directly if preferred.

### Prebuilt Binaries

Prebuilt binaries are available for:
- Linux x86_64 (`x86_64-unknown-linux-gnu`)
- Linux ARM64 (`aarch64-unknown-linux-gnu`)
- macOS Intel (`x86_64-apple-darwin`)
- macOS Apple Silicon (`aarch64-apple-darwin`)
- Windows (`x86_64-pc-windows-msvc`)

Download from [GitHub Releases](https://github.com/Dicklesworthstone/destructive_command_guard/releases) and verify the SHA256 checksum.

## Claude Code Configuration

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "dcg"
          }
        ]
      }
    ]
  }
}
```

**Important:** Restart Claude Code after adding the hook configuration.

## CLI Usage

While primarily designed as a hook, the binary supports direct invocation for testing and debugging:

```bash
# Show version with build metadata
dcg --version

# Show help with blocked command categories
dcg --help

# Test a command manually (pipe JSON to stdin)
echo '{"tool_name":"Bash","tool_input":{"command":"git reset --hard"}}' | dcg
```

The `--version` output includes build metadata for debugging:

```
dcg 0.1.0
  Built: 2026-01-07T22:13:10.413872881Z
  Rustc: 1.94.0-nightly
  Target: x86_64-unknown-linux-gnu
```

This metadata is embedded at compile time via [vergen](https://github.com/rustyhorde/vergen), making it easy to identify exactly which build is running when troubleshooting.

## Repository Scanning

While the hook protects **interactive** command execution, teams also need protection against destructive commands that get **committed into repositories**. The `dcg scan` command extracts executable command contexts from files and evaluates them using the same pattern engine.

### What Scan Is (and Is Not)

**What it is:**
- An extractor-based scanner that understands executable contexts
- Uses the same evaluator as hook mode for consistency
- Supports CI integration and pre-commit hooks

**What it is NOT:**
- A naive grep that matches strings everywhere
- A replacement for code review
- A static analysis tool for arbitrary languages

The key difference from grep: `dcg scan` understands that `"rm -rf /"` in a comment is data, not code. It uses extractors that understand file structure (shell scripts, Dockerfiles, GitHub Actions, Makefiles) to find only actually-executed commands.

### Quick Start

```bash
# Install the pre-commit hook
dcg scan install-pre-commit

# Or manually run on staged files
dcg scan --staged

# Scan specific paths
dcg scan --paths scripts/ .github/workflows/
```

### Recommended Rollout Plan

**Start conservative to avoid developer friction:**

```bash
# Week 1-2: Warn-first with narrow scope
dcg scan --staged --fail-on error  # Only fail on catastrophic rules
```

Create `.dcg/hooks.toml` with conservative defaults:

```toml
[scan]
fail_on = "error"          # Only fail on high-confidence catastrophic rules
format = "pretty"          # Human-readable output
redact = "quoted"          # Hide sensitive strings
truncate = 120             # Shorten long commands

[scan.paths]
include = [
    ".github/workflows/**",  # Start with CI configs
    "Dockerfile",            # Container builds
    "Makefile",              # Build scripts
]
exclude = [
    "target/**",
    "node_modules/**",
    "vendor/**",
]
```

**Gradual expansion:**

1. **Week 1-2**: Start with workflows/Dockerfiles only, `--fail-on error`
2. **Week 3-4**: Add Makefiles and shell scripts in `scripts/`
3. **Month 2**: Add `--fail-on warning` after reviewing findings
4. **Ongoing**: Add new extractors as team confidence grows

### Pre-Commit Integration

#### One-Command Install

```bash
dcg scan install-pre-commit
```

This creates a `.git/hooks/pre-commit` that runs `dcg scan --staged`.

#### Manual Setup

If you prefer manual control or use a hook manager:

```bash
#!/bin/bash
# .git/hooks/pre-commit (or equivalent for your hook manager)

set -e

# Run dcg scan on staged files
dcg scan --staged --fail-on error

# Add other hooks below...
```

#### Uninstall

```bash
dcg scan uninstall-pre-commit
```

This only removes hooks installed by dcg (detected via sentinel comment).

### Interpreting Findings

The output includes:

```
scripts/deploy.sh:42:5: [ERROR] core.git:reset-hard
  Command: git reset --hard HEAD
  Reason: git reset --hard destroys uncommitted changes
  Suggestion: Consider using 'git stash' first to save changes.
```

- **File:Line:Col**: Location in the source file
- **Severity**: `ERROR` (catastrophic) or `WARNING` (concerning)
- **Rule ID**: Stable identifier like `core.git:reset-hard`
- **Command**: The extracted command (may be redacted/truncated)
- **Reason**: Why this command is flagged
- **Suggestion**: How to make it safer

### Fixing Findings

#### Option 1: Change the Code (Preferred)

Replace the dangerous command with a safer alternative:

```bash
# Instead of:
git reset --hard

# Use:
git stash push -m "before reset"
git reset --hard
```

#### Option 2: Understand with Explain

Get detailed analysis:

```bash
dcg explain "git reset --hard HEAD"
```

#### Option 3: Allowlist (When Intentional)

If the command is genuinely needed:

```bash
# Project-level allowlist (committed, code-reviewed)
dcg allowlist add core.git:reset-hard --reason "Required for CI cleanup" --project

# Or for a specific command
dcg allowlist add-command "rm -rf ./build" --reason "Build cleanup" --project
```

The finding output includes a copy-paste allowlist command for convenience.
Heredoc rules use stable IDs like `heredoc.python.shutil_rmtree`.

### Privacy and Redaction

Scan supports redaction of potentially sensitive content in output. Use `--redact quoted` to hide quoted strings that may contain secrets:

```
# Original command:
curl -H "Authorization: Bearer $TOKEN" https://api.example.com

# With --redact quoted:
curl -H "..." https://api.example.com
```

Options:
- `--redact none`: Show full commands (default)
- `--redact quoted`: Hide quoted strings (recommended for CI logs)
- `--redact aggressive`: Hide more potential secrets

### Configuration Reference

`.dcg/hooks.toml` (project-level, committed):

```toml
[scan]
# Exit non-zero when findings meet this threshold
fail_on = "error"      # Options: none, warning, error

# Output format
format = "pretty"      # Options: pretty, json, markdown

# Maximum file size to scan (bytes)
max_file_size = 1000000

# Stop after this many findings
max_findings = 50

# Redaction level for sensitive content
redact = "quoted"      # Options: none, quoted, aggressive

# Truncate long commands (chars; 0 = no truncation)
truncate = 120

[scan.paths]
# Only scan files matching these patterns
include = [
    "scripts/**",
    ".github/workflows/**",
    "Dockerfile*",
    "Makefile",
]

# Skip files matching these patterns
exclude = [
    "target/**",
    "node_modules/**",
    "*.md",
]
```

CLI flags override config file values.

### CI Integration

#### GitHub Actions

```yaml
name: Security Scan
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Install dcg
        run: |
          curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/master/install.sh" | bash
          echo "$HOME/.local/bin" >> $GITHUB_PATH

      - name: Scan changed files
        run: |
          dcg scan --git-diff origin/${{ github.base_ref }}..HEAD \
            --format markdown \
            --fail-on error
```

#### GitLab CI

```yaml
scan:
  stage: test
  script:
    - curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/master/install.sh" | bash
    - ~/.local/bin/dcg scan --git-diff origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME..HEAD --fail-on error
  rules:
    - if: $CI_MERGE_REQUEST_ID
```

### Bypass for Emergencies

If you need to bypass the pre-commit hook temporarily:

```bash
git commit --no-verify -m "Emergency fix"
```

This is logged and visible in git history. For permanent exceptions, use allowlists instead.

## How It Works

1. Claude Code invokes the hook before executing any Bash command
2. The hook receives the command as JSON on stdin
3. Commands are normalized (e.g., `/usr/bin/git` becomes `git`)
4. Safe patterns are checked first (whitelist approach)
5. Destructive patterns are checked second (blacklist approach)
6. If destructive: outputs JSON denial with explanation
7. If safe: exits silently (no output = allow)

The hook is designed for minimal latency with sub-millisecond execution on typical commands.

### Output Behavior

The hook uses two separate output channels:

- **stdout (JSON)**: The Claude Code hook protocol response. On denial, outputs JSON with `permissionDecision: "deny"`. On allow, outputs nothing.
- **stderr (colorful text)**: A human-readable warning when commands are blocked. Colors are automatically disabled when stderr is not a TTY (e.g., when piped to a file).

This dual-output design ensures the hook protocol works correctly while still providing immediate visual feedback to users watching the terminal.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Claude Code                               │
│                                                                  │
│  User: "delete the build artifacts"                             │
│  Agent: executes `rm -rf ./build`                               │
│                                                                  │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼ PreToolUse hook (stdin: JSON)
┌─────────────────────────────────────────────────────────────────┐
│                     dcg                             │
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │    Parse     │───▶│  Normalize   │───▶│ Quick Reject │       │
│  │    JSON      │    │   Command    │    │   Filter     │       │
│  └──────────────┘    └──────────────┘    └──────┬───────┘       │
│                                                  │               │
│                      ┌───────────────────────────┘               │
│                      ▼                                           │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   Pattern Matching                        │   │
│  │                                                           │   │
│  │   1. Check SAFE_PATTERNS (whitelist) ──▶ Allow if match  │   │
│  │   2. Check DESTRUCTIVE_PATTERNS ──────▶ Deny if match    │   │
│  │   3. No match ────────────────────────▶ Allow (default)  │   │
│  │                                                           │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼ stdout: JSON (deny) or empty (allow)
┌─────────────────────────────────────────────────────────────────┐
│                        Claude Code                               │
│                                                                  │
│  If denied: Shows block message, does NOT execute command       │
│  If allowed: Proceeds with command execution                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Processing Pipeline

**Stage 1: JSON Parsing**
- Reads the hook input from stdin
- Validates the structure matches Claude Code's `PreToolUse` format
- Extracts the command string from `tool_input.command`
- Non-Bash tools are immediately allowed (no output)

**Stage 2: Command Normalization**
- Strips absolute paths from `git` and `rm` binaries
- `/usr/bin/git status` → `git status`
- `/bin/rm -rf /tmp/foo` → `rm -rf /tmp/foo`
- Uses regex with lookahead to preserve arguments containing paths

**Stage 3: Quick Rejection Filter**
- O(n) substring search for "git" or "rm" in the command
- Commands without these substrings bypass regex matching entirely
- Handles 99%+ of non-destructive commands (ls, cat, cargo, npm, etc.)

**Stage 4: Pattern Matching**
- Safe patterns checked first (short-circuit on match → allow)
- Destructive patterns checked second (match → deny with reason)
- No match on either → default allow

## Design Principles

### 1. Whitelist-First Architecture

Safe patterns are checked *before* destructive patterns. This design ensures that explicitly safe commands (like `git checkout -b`) are never accidentally blocked, even if they partially match a destructive pattern (like `git checkout`).

```
git checkout -b feature    →  Matches SAFE "checkout-new-branch"  →  ALLOW
git checkout -- file.txt   →  No safe match, matches DESTRUCTIVE  →  DENY
```

### 2. Fail-Safe Defaults

The hook uses a **default-allow** policy for unrecognized commands. This ensures:
- The hook never breaks legitimate workflows
- Only *known* dangerous patterns are blocked
- New git commands are allowed until explicitly categorized

### 3. Zero False Negatives Philosophy

The pattern set prioritizes **never allowing dangerous commands** over avoiding false positives. A few extra prompts for manual confirmation are acceptable; lost work is not.

### 4. Defense in Depth

This hook is one layer of protection. It complements (not replaces):
- Regular commits and pushes
- Git stash before risky operations
- Proper backup strategies
- Code review processes

### 5. Minimal Latency

Every Bash command passes through this hook. Performance is critical:
- Lazy-initialized static regex patterns (compiled once, reused)
- Quick rejection filter eliminates 99%+ of commands before regex
- No heap allocations on the hot path for safe commands
- Sub-millisecond execution for typical commands

## Pattern Matching System

### Safe Patterns (Whitelist)

The safe pattern list contains 34 patterns covering:

| Category | Patterns | Purpose |
|----------|----------|---------|
| Branch creation | `checkout -b`, `checkout --orphan` | Creating branches is safe |
| Staged-only | `restore --staged`, `restore -S` | Unstaging doesn't touch working tree |
| Dry run | `clean -n`, `clean --dry-run` | Preview mode, no actual deletion |
| Temp cleanup | `rm -rf /tmp/*`, `rm -rf /var/tmp/*` | Ephemeral directories are safe |
| Variable expansion | `rm -rf $TMPDIR/*`, `rm -rf ${TMPDIR}/*` | Shell variable forms |
| Quoted paths | `rm -rf "$TMPDIR/*"` | Quoted variable forms |
| Separate flags | `rm -r -f /tmp/*`, `rm -r -f $TMPDIR/*` | Flag ordering variants |
| Long flags | `rm --recursive --force /tmp/*`, `$TMPDIR/*` | GNU-style long options |

### Destructive Patterns (Blacklist)

The destructive pattern list contains 16 patterns covering:

| Category | Pattern | Reason |
|----------|---------|--------|
| Work destruction | `reset --hard`, `reset --merge` | Destroys uncommitted changes |
| File reversion | `checkout -- <path>` | Discards file modifications |
| Worktree restore | `restore` (without --staged) | Discards uncommitted changes |
| Untracked deletion | `clean -f` | Permanently removes untracked files |
| History rewrite | `push --force`, `push -f` | Can destroy remote commits |
| Unsafe branch delete | `branch -D` | Force-deletes without merge check |
| Stash destruction | `stash drop`, `stash clear` | Permanently deletes stashed work |
| Filesystem nuke | `rm -rf` (non-temp paths) | Recursive deletion outside temp |

### Pattern Syntax

Patterns use [fancy-regex](https://github.com/fancy-regex/fancy-regex) for advanced features:

```rust
// Negative lookahead: block restore UNLESS --staged is present
r"git\s+restore\s+(?!--staged\b)(?!-S\b)"

// Negative lookahead: don't match --force-with-lease
r"git\s+push\s+.*--force(?![-a-z])"

// Character class: match any flag ordering
r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*"
```

## Edge Cases Handled

### Path Normalization

Commands may use absolute paths to binaries:

```bash
/usr/bin/git reset --hard          # Blocked ✓
/usr/local/bin/git checkout -- .   # Blocked ✓
/bin/rm -rf /home/user             # Blocked ✓
```

The normalizer uses regex to strip paths while preserving arguments:

```bash
git add /usr/bin/something         # "/usr/bin/something" is an argument, preserved
```

### Flag Ordering Variants

The `rm` command accepts flags in many forms:

```bash
rm -rf /path          # Combined flags
rm -fr /path          # Reversed order
rm -r -f /path        # Separate flags
rm -f -r /path        # Separate, reversed
rm --recursive --force /path    # Long flags
rm --force --recursive /path    # Long flags, reversed
rm -rf --no-preserve-root /     # Additional flags
```

All variants are handled by flexible regex patterns.

### Shell Variable Expansion

Temp directory variables come in multiple forms:

```bash
rm -rf $TMPDIR/build           # Unquoted, simple
rm -rf ${TMPDIR}/build         # Unquoted, braced
rm -rf "$TMPDIR/build"         # Quoted, simple
rm -rf "${TMPDIR}/build"       # Quoted, braced
rm -rf "${TMPDIR:-/tmp}/build" # With default value
```

### Git Flag Combinations

Git commands can have flags in various positions:

```bash
git push --force                  # Blocked ✓
git push origin main --force      # Blocked ✓
git push --force origin main      # Blocked ✓
git push -f                       # Blocked ✓
git push --force-with-lease       # Allowed ✓ (safe alternative)
```

### Staged vs Worktree Restore

The restore command has nuanced safety:

```bash
git restore --staged file.txt           # Allowed ✓ (unstaging only)
git restore -S file.txt                 # Allowed ✓ (short flag)
git restore file.txt                    # Blocked (discards changes)
git restore --worktree file.txt         # Blocked (explicit worktree)
git restore --staged --worktree file    # Blocked (includes worktree)
git restore -S -W file.txt              # Blocked (includes worktree)
```

## Performance Optimizations

### 1. Lazy Static Initialization

Regex patterns are compiled once on first use via `LazyLock`:

```rust
static SAFE_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    vec![
        pattern!("checkout-new-branch", r"git\s+checkout\s+-b\s+"),
        // ... 33 more patterns
    ]
});
```

Subsequent invocations reuse the compiled patterns with zero compilation overhead.

### 2. SIMD-Accelerated Quick Rejection

Before any regex matching, a SIMD-accelerated substring search filters out irrelevant commands. The [memchr](https://github.com/BurntSushi/memchr) crate uses CPU vector instructions (SSE2, AVX2, NEON) when available:

```rust
use memchr::memmem;

static GIT_FINDER: LazyLock<memmem::Finder<'static>> = LazyLock::new(|| memmem::Finder::new("git"));
static RM_FINDER: LazyLock<memmem::Finder<'static>> = LazyLock::new(|| memmem::Finder::new("rm"));

fn quick_reject(cmd: &str) -> bool {
    let bytes = cmd.as_bytes();
    GIT_FINDER.find(bytes).is_none() && RM_FINDER.find(bytes).is_none()
}
```

For commands like `ls -la`, `cargo build`, or `npm install`, this check short-circuits the entire matching pipeline. The `memmem::Finder` is pre-compiled once and reused, avoiding repeated setup costs.

### 3. Early Exit on Safe Match

Safe patterns are checked first. On match, the function returns immediately without checking destructive patterns:

```rust
for pattern in SAFE_PATTERNS.iter() {
    if pattern.regex.is_match(&normalized).unwrap_or(false) {
        return;  // Allow immediately
    }
}
```

### 4. Compile-Time Pattern Validation

The `pattern!` and `destructive!` macros include the pattern name in panic messages, making invalid patterns fail at first execution with clear diagnostics:

```rust
macro_rules! pattern {
    ($name:literal, $re:literal) => {
        Pattern {
            regex: Regex::new($re).expect(concat!("pattern '", $name, "' should compile")),
            name: $name,
        }
    };
}
```

### 5. Zero-Copy JSON Parsing

The `serde_json` parser operates on the input buffer without unnecessary copies. The command string is extracted directly from the parsed JSON value.

### 6. Zero-Allocation Path Normalization

Command normalization uses `Cow<str>` (copy-on-write) to avoid heap allocations in the common case:

```rust
fn normalize_command(cmd: &str) -> Cow<'_, str> {
    // Fast path: if command doesn't start with '/', no normalization needed
    if !cmd.starts_with('/') {
        return Cow::Borrowed(cmd);  // Zero allocation
    }
    PATH_NORMALIZER.replace(cmd, "$1")  // Allocation only when path is stripped
}
```

Most commands don't use absolute paths to `git` or `rm`, so this fast path avoids allocation entirely for 99%+ of inputs.

### 7. Release Profile Optimization

The release build uses aggressive optimization settings:

```toml
[profile.release]
opt-level = "z"     # Optimize for size (lean binary)
lto = true          # Link-time optimization across crates
codegen-units = 1   # Single codegen unit for better optimization
panic = "abort"     # Smaller binary, no unwinding overhead
strip = true        # Remove debug symbols
```

## Example Block Message

When a destructive command is intercepted, the hook outputs a colorful warning to stderr (shown below without ANSI codes):

```
════════════════════════════════════════════════════════════════════════
BLOCKED  dcg
────────────────────────────────────────────────────────────────────────
Reason:  git reset --hard destroys uncommitted changes. Use 'git stash' first.

Command:  git reset --hard HEAD~1

Tip: If you need to run this command, execute it manually in a terminal.
     Consider using 'git stash' first to save your changes.
════════════════════════════════════════════════════════════════════════
```

The hook provides **contextual suggestions** based on the command type:

| Command Type | Suggestion |
|-------------|------------|
| `git reset`, `git checkout --` | "Consider using 'git stash' first to save your changes." |
| `git clean` | "Use 'git clean -n' first to preview what would be deleted." |
| `git push --force` | "Consider using '--force-with-lease' for safer force pushing." |
| `rm -rf` | "Verify the path carefully before running rm -rf manually." |

Simultaneously, the hook outputs JSON to stdout for the Claude Code protocol:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "BLOCKED by dcg\n\nReason: ..."
  }
}
```

## Security Considerations

### What This Protects Against

- **Accidental data loss**: AI agents running `git checkout --` or `git reset --hard` on files with uncommitted changes
- **Remote history destruction**: Force pushes that overwrite shared branch history
- **Stash loss**: Dropping or clearing stashes containing important work-in-progress
- **Filesystem accidents**: Recursive deletion outside designated temp directories

### Inherent Limitations

While dcg provides comprehensive protection across many tools and platforms, some attack vectors are inherently difficult or impossible to protect against:
- **Malicious actors**: A determined attacker can bypass this hook
- **Non-Bash commands**: Direct file writes via Python/JavaScript, API calls, etc. are not intercepted
- **Committed but unpushed work**: The hook doesn't prevent loss of local-only commits
- **Bugs in allowed commands**: A `git commit` that accidentally includes wrong files
- **Commands in scripts**: If an agent runs `./deploy.sh`, we don't inspect what's inside the script

### Threat Model

This hook assumes the AI agent is **well-intentioned but fallible**. It's designed to catch honest mistakes, not adversarial attacks. The hook runs with the same permissions as the Claude Code process.

## Troubleshooting

### Hook not blocking commands

1. **Check hook registration**: Verify `~/.claude/settings.json` contains the hook configuration
2. **Restart Claude Code**: Configuration changes require a restart
3. **Check binary location**: Ensure `dcg` is in your PATH
4. **Test manually**: Run `echo '{"tool_name":"Bash","tool_input":{"command":"git reset --hard"}}' | dcg`

### Hook blocking safe commands

1. **Check for false positives**: Some edge cases may not be covered by safe patterns
2. **File an issue**: Report the command that was incorrectly blocked
3. **Temporary bypass**: Have the user run the command manually in a separate terminal
4. **Add to allowlist**: Use the allowlist feature below for persistent overrides

### Resolving False Positives with Allowlists

If dcg blocks a command that is safe in your specific context, you can add it to an allowlist. Allowlists support three layers (checked in order):

1. **Project** (`.dcg/allowlist.toml`): Applies only to the current project
2. **User** (`~/.config/dcg/allowlist.toml`): Applies to all your projects
3. **System** (`/etc/dcg/allowlist.toml`): Applies system-wide

**Adding a rule to the allowlist:**

```bash
# Allow a specific rule by ID (recommended)
dcg allowlist add core.git:reset-hard -r "Used for CI cleanup"

# Allow at project level (default if in a git repo)
dcg allowlist add core.git:reset-hard -r "CI cleanup" --project

# Add to user-level allowlist instead
dcg allowlist add core.git:reset-hard -r "Personal workflow" --user

# Allow with expiration (ISO 8601 format)
dcg allowlist add core.git:clean-force -r "Migration" --expires "2026-02-01T00:00:00Z"

# Allow a specific command (exact match) using add-command
dcg allowlist add-command "rm -rf ./build" -r "Build cleanup"
```

**Listing allowlist entries:**

```bash
# List all entries from all layers
dcg allowlist list

# List project allowlist only
dcg allowlist list --project

# List user allowlist only
dcg allowlist list --user

# Output as JSON
dcg allowlist list --format json
```

**Removing entries:**

```bash
# Remove a rule by ID
dcg allowlist remove core.git:reset-hard

# Remove from project allowlist specifically
dcg allowlist remove core.git:reset-hard --project
```

**Validating allowlist files:**

```bash
# Check for issues (expired entries, invalid patterns)
dcg allowlist validate

# Strict mode: treat warnings as errors
dcg allowlist validate --strict
```

**Example allowlist.toml:**

```toml
[[allow]]
rule = "core.git:reset-hard"
reason = "Used for CI pipeline cleanup"
added_at = "2026-01-08T12:00:00Z"

[[allow]]
exact_command = "rm -rf ./build"
reason = "Safe build directory cleanup"
added_at = "2026-01-08T12:00:00Z"
expires_at = "2026-02-08T12:00:00Z"  # Optional expiration

[[allow]]
pattern = "rm -rf .*/build"
reason = "Build directories across projects"
risk_acknowledged = true  # Required for pattern-based entries
added_at = "2026-01-08T12:00:00Z"
```

### Performance issues

1. **Check pattern count**: Excessive custom patterns can slow matching
2. **Profile with `--release`**: Debug builds are significantly slower
3. **Check stdin buffering**: Slow JSON input can delay processing

## Running Tests

### Unit Tests

```bash
cargo test
```

The test suite includes 80+ tests covering:

- **normalize_command_tests**: Path stripping for git and rm binaries
- **quick_reject_tests**: Fast-path filtering for non-git/rm commands
- **safe_pattern_tests**: Whitelist accuracy for all safe pattern variants
- **destructive_pattern_tests**: Blacklist coverage for all dangerous commands
- **input_parsing_tests**: JSON parsing robustness and edge cases
- **deny_output_tests**: Output format validation
- **integration_tests**: End-to-end pipeline verification

### Test with Coverage

```bash
cargo install cargo-tarpaulin
cargo tarpaulin --out Html
```

### End-to-End Testing

The repository includes a comprehensive E2E test script with 120 test cases:

```bash
# Run full E2E test suite
./scripts/e2e_test.sh

# With verbose output
./scripts/e2e_test.sh --verbose

# With specific binary path
./scripts/e2e_test.sh --binary ./target/release/dcg
```

The E2E suite covers:
- All destructive git commands (reset, checkout, restore, clean, push, branch, stash)
- All safe git commands (status, log, diff, add, commit, push, branch -d)
- Filesystem commands (rm -rf with various paths and flag orderings)
- Absolute path handling (`/usr/bin/git`, `/bin/rm`)
- Non-Bash tools (Read, Write, Edit, Grep, Glob)
- Malformed JSON input (empty, missing fields, invalid syntax)
- Edge cases (sudo prefixes, quoted paths, variable expansion)

## Continuous Integration

The project uses GitHub Actions for CI/CD:

### CI Workflow (`.github/workflows/ci.yml`)

Runs on every push and pull request:

- **Formatting check**: `cargo fmt --check`
- **Clippy lints**: `cargo clippy --all-targets -- -D warnings` (pedantic + nursery enabled)
- **Compilation check**: `cargo check --all-targets`
- **Unit tests**: `cargo nextest run` with JUnit XML reports
- **Coverage**: `cargo llvm-cov` with LCOV output

### Release Workflow (`.github/workflows/dist.yml`)

Triggered on version tags (`v*`):

- Builds optimized binaries for 5 platforms:
  - Linux x86_64 (`x86_64-unknown-linux-gnu`)
  - Linux ARM64 (`aarch64-unknown-linux-gnu`)
  - macOS Intel (`x86_64-apple-darwin`)
  - macOS Apple Silicon (`aarch64-apple-darwin`)
  - Windows (`x86_64-pc-windows-msvc`)
- Creates `.tar.xz` archives (Unix) or `.zip` (Windows)
- Generates SHA256 checksums for verification
- Publishes to GitHub Releases with auto-generated release notes

To create a release:

```bash
git tag v0.1.0
git push origin v0.1.0
```

## FAQ

**Q: Why block `git branch -D` but allow `git branch -d`?**

The lowercase `-d` only deletes branches that have been fully merged. The uppercase `-D` force-deletes regardless of merge status, potentially losing commits that exist only on that branch.

**Q: Why is `git push --force-with-lease` allowed?**

Force-with-lease is a safer alternative that refuses to push if the remote has commits you haven't seen. It prevents accidentally overwriting someone else's work.

**Q: Why block all `rm -rf` outside temp directories?**

Recursive forced deletion is one of the most dangerous filesystem operations. Even with good intentions, a typo or wrong variable expansion can delete critical files. Temp directories are designed to be ephemeral.

**Q: Can I add custom patterns?**

Currently, patterns are compiled into the binary. For custom patterns, fork the repository and modify `SAFE_PATTERNS` or `DESTRUCTIVE_PATTERNS` in `src/main.rs`.

**Q: What if I really need to run a blocked command?**

The block message instructs the AI to ask you for explicit permission. You can then run the command manually in a separate terminal, ensuring you've made a conscious decision.

**Q: Does this work with other AI coding tools?**

The hook is designed for Claude Code's `PreToolUse` hook protocol. Other tools would need adapters to match the expected JSON input/output format.

**Q: What about database, Docker, Kubernetes, and cloud commands?**

dcg already includes comprehensive packs for all of these! The modular pack system covers databases (PostgreSQL, MySQL, MongoDB, Redis, SQLite), containers (Docker, Podman, docker-compose), Kubernetes (kubectl, Helm, Kustomize), and all major cloud providers (AWS, GCP, Azure) including their container registries, secrets management services, and logging infrastructure. Enable the packs you need in your config. If you encounter a destructive command that should be blocked, please file an issue.

## Contributing

*About Contributions:* Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

## License

MIT

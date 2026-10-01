---
name: dcg
description: "Destructive Command Guard - High-performance Rust hook for Claude Code that blocks dangerous commands before execution. SIMD-accelerated, modular pack system, whitelist-first architecture. Essential safety layer for agent workflows."
---

# DCG — Destructive Command Guard

A high-performance Claude Code hook that intercepts and blocks destructive commands before they execute. Written in Rust with SIMD-accelerated filtering for sub-millisecond latency.

## Why This Exists

AI coding agents are powerful but fallible. They can accidentally run destructive commands:

- **"Let me clean up the build artifacts"** → `rm -rf ./src` (typo)
- **"I'll reset to the last commit"** → `git reset --hard` (destroys uncommitted changes)
- **"Let me fix the merge conflict"** → `git checkout -- .` (discards all modifications)
- **"I'll clean up untracked files"** → `git clean -fd` (permanently deletes untracked files)

DCG intercepts dangerous commands *before* execution and blocks them with a clear explanation, giving you a chance to stash your changes first.

## Critical Design Principles

### 1. Whitelist-First Architecture

Safe patterns are checked *before* destructive patterns. This ensures explicitly safe commands are never accidentally blocked:

```
git checkout -b feature    →  Matches SAFE "checkout-new-branch"  →  ALLOW
git checkout -- file.txt   →  No safe match, matches DESTRUCTIVE  →  DENY
```

### 2. Fail-Safe Defaults (Default-Allow)

Unrecognized commands are **allowed by default**. This ensures:
- The hook never breaks legitimate workflows
- Only *known* dangerous patterns are blocked
- New git commands work until explicitly categorized

### 3. Zero False Negatives Philosophy

The pattern set prioritizes **never allowing dangerous commands** over avoiding false positives. A few extra prompts for manual confirmation are acceptable; lost work is not.

## What It Blocks

### Git Commands That Destroy Uncommitted Work

| Command | Reason |
|---------|--------|
| `git reset --hard` | Destroys uncommitted changes |
| `git reset --merge` | Destroys uncommitted changes |
| `git checkout -- <file>` | Discards file modifications |
| `git restore <file>` (without `--staged`) | Discards uncommitted changes |
| `git clean -f` | Permanently deletes untracked files |

### Git Commands That Destroy Remote History

| Command | Reason |
|---------|--------|
| `git push --force` / `-f` | Overwrites remote commits |
| `git branch -d`, `--delete`, `-D`, `-f`, `-M`, `-C` | Deletes or force-overwrites a user-owned branch ref |

### Git Commands That Destroy Stashed Work

| Command | Reason |
|---------|--------|
| `git stash drop` | Permanently deletes a stash |
| `git stash clear` | Permanently deletes all stashes |

### Filesystem Commands

| Command | Reason |
|---------|--------|
| `rm -rf` (outside `/tmp`, `/var/tmp`, `$TMPDIR`) | Recursive deletion is dangerous |

## What It ALLOWS

Safe operations pass through silently:

### Always Safe Git Operations

`git status`, `git log`, `git diff`, `git add`, `git commit`, `git push`, `git pull`, `git fetch`, read-only branch listings, `git stash`, `git stash pop`, `git stash list`

### Explicitly Safe Patterns

| Pattern | Why Safe |
|---------|----------|
| `git checkout -b <branch>` | Creating new branches |
| `git checkout --orphan <branch>` | Creating orphan branches |
| `git restore --staged <file>` | Unstaging only, doesn't touch working tree |
| `git restore -S <file>` | Short flag for staged |
| `git clean -n` / `--dry-run` | Preview mode, no actual deletion |
| `rm -rf /tmp/*` | Temp directories are ephemeral |
| `rm -rf $TMPDIR/*` | Shell variable forms |

### Safe Alternative: `--force-with-lease`

```bash
git push --force-with-lease   # ALLOWED - refuses if remote has unseen commits
git push --force              # BLOCKED - can overwrite others' work
```

## Modular Pack System

DCG uses a modular "pack" system to organize patterns by category:

### Core Packs (Always Enabled)

| Pack | Description |
|------|-------------|
| `core.git` | Destructive git commands |
| `core.filesystem` | Dangerous rm -rf outside temp |

### Database Packs

| Pack | Description |
|------|-------------|
| `database.postgresql` | DROP/TRUNCATE in PostgreSQL |
| `database.mysql` | DROP/TRUNCATE in MySQL/MariaDB |
| `database.mongodb` | dropDatabase, drop() |
| `database.redis` | FLUSHALL/FLUSHDB |
| `database.sqlite` | DROP in SQLite |

### Container Packs

| Pack | Description |
|------|-------------|
| `containers.docker` | docker system prune, docker rm -f |
| `containers.compose` | docker-compose down --volumes |
| `containers.podman` | podman system prune |

### Kubernetes Packs

| Pack | Description |
|------|-------------|
| `kubernetes.kubectl` | kubectl delete namespace |
| `kubernetes.helm` | helm uninstall |
| `kubernetes.kustomize` | kustomize delete patterns |

### Cloud Provider Packs

| Pack | Description |
|------|-------------|
| `cloud.aws` | Destructive AWS CLI commands |
| `cloud.gcp` | Destructive gcloud commands |
| `cloud.azure` | Destructive az commands |

### Infrastructure Packs

| Pack | Description |
|------|-------------|
| `infrastructure.terraform` | terraform destroy |
| `infrastructure.ansible` | Dangerous ansible patterns |
| `infrastructure.pulumi` | pulumi destroy |

### System Packs

| Pack | Description |
|------|-------------|
| `system.disk` | dd, mkfs, fdisk operations |
| `system.permissions` | Dangerous chmod/chown patterns |
| `system.services` | systemctl stop/disable patterns |

### Other Packs

| Pack | Description |
|------|-------------|
| `strict_git` | Extra paranoid git protections |
| `package_managers` | npm unpublish, cargo yank |

### Configuring Packs

```toml
# ~/.config/dcg/config.toml
[packs]
enabled = [
    "database.postgresql",
    "containers.docker",
    "kubernetes",  # Enables all kubernetes sub-packs
]
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `DCG_PACKS="containers.docker,kubernetes"` | Enable packs (comma-separated) |
| `DCG_DISABLE="kubernetes.helm"` | Disable packs/sub-packs |
| `DCG_VERBOSE=1` | Verbose output |
| `DCG_COLOR=auto\|always\|never` | Color mode |
| `DCG_BYPASS=1` | Bypass DCG entirely (escape hatch) |

## Installation

### Quick Install (Recommended)

```bash
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/install.sh?$(date +%s)" | bash

# Easy mode: auto-update PATH
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/install.sh?$(date +%s)" | bash -s -- --easy-mode

# System-wide (requires sudo)
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/install.sh?$(date +%s)" | sudo bash -s -- --system
```

### From Source (Requires Rust Nightly)

```bash
cargo +nightly install --git https://github.com/Dicklesworthstone/destructive_command_guard
```

### Prebuilt Binaries

Available for: Linux x86_64, Linux ARM64, macOS Intel, macOS Apple Silicon, Windows

## Claude Code Configuration

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell",
        "hooks": [
          {
            "type": "command",
            "command": "/absolute/path/to/dcg"
          }
        ]
      }
    ]
  }
}
```

Replace `/absolute/path/to/dcg` with the exact resolved binary path. Do not use
bare `dcg`: non-interactive hook shells may not inherit the interactive
`PATH`. On native Windows, use `install.ps1` so the hook receives the
PowerShell-safe absolute command and explicit shell selection.

**Important:** Restart Claude Code after adding the hook.

## How It Works

### Processing Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                        Claude Code                               │
│  Agent executes `rm -rf ./build`                                │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼ PreToolUse hook (stdin: JSON)
┌─────────────────────────────────────────────────────────────────┐
│                          dcg                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │    Parse     │───▶│  Normalize   │───▶│ Quick Reject │       │
│  │    JSON      │    │   Command    │    │   Filter     │       │
│  └──────────────┘    └──────────────┘    └──────┬───────┘       │
│                                                  │               │
│                      ┌───────────────────────────┘               │
│                      ▼                                           │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   Pattern Matching                        │   │
│  │   1. Check SAFE_PATTERNS (whitelist) ──▶ Allow if match  │   │
│  │   2. Check DESTRUCTIVE_PATTERNS ──────▶ Deny if match    │   │
│  │   3. No match ────────────────────────▶ Allow (default)  │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼ stdout: JSON (deny) or empty (allow)
```

### Stage 1: JSON Parsing
- Reads hook input from stdin
- Validates Claude Code's `PreToolUse` format
- Non-Bash tools immediately allowed

### Stage 2: Command Normalization
- Strips absolute paths: `/usr/bin/git status` → `git status`
- Preserves argument paths

### Stage 3: Quick Rejection Filter
- SIMD-accelerated substring search for "git" or "rm"
- Commands without these bypass regex entirely (99%+ of commands)

### Stage 4: Pattern Matching
- Safe patterns checked first (short-circuit on match → allow)
- Destructive patterns checked second (match → deny)
- No match → default allow

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Command is safe, proceed |
| `2` | Command is blocked, do not execute |

## CLI Usage

Test commands manually:

```bash
# Show version with build metadata
dcg --version

# Test a command
echo '{"tool_name":"Bash","tool_input":{"command":"git reset --hard"}}' | dcg
```

## Example Block Message

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

### Contextual Suggestions

| Command Type | Suggestion |
|-------------|------------|
| `git reset`, `git checkout --` | "Consider using 'git stash' first" |
| `git clean` | "Use 'git clean -n' first to preview" |
| `git push --force` | "Consider using '--force-with-lease'" |
| `rm -rf` | "Verify the path carefully before running manually" |

## Edge Cases Handled

### Path Normalization

```bash
/usr/bin/git reset --hard          # Blocked
/usr/local/bin/git checkout -- .   # Blocked
/bin/rm -rf /home/user             # Blocked
```

### Flag Ordering Variants

```bash
rm -rf /path          # Combined flags
rm -fr /path          # Reversed order
rm -r -f /path        # Separate flags
rm --recursive --force /path    # Long flags
```

All variants are handled.

### Shell Variable Expansion

```bash
rm -rf $TMPDIR/build           # Allowed (temp)
rm -rf ${TMPDIR}/build         # Allowed
rm -rf "$TMPDIR/build"         # Allowed
rm -rf "${TMPDIR:-/tmp}/build" # Allowed
```

### Staged vs Worktree Restore

```bash
git restore --staged file.txt    # Allowed (unstaging only)
git restore -S file.txt          # Allowed (short flag)
git restore file.txt             # BLOCKED (discards changes)
git restore --worktree file.txt  # BLOCKED (explicit worktree)
git restore -S -W file.txt       # BLOCKED (includes worktree)
```

## Performance Optimizations

DCG is designed for zero perceived latency:

| Optimization | Technique |
|--------------|-----------|
| **Lazy Static** | Regex patterns compiled once via `LazyLock` |
| **SIMD Quick Reject** | `memchr` crate for CPU vector instructions |
| **Early Exit** | Safe match returns immediately |
| **Zero-Copy JSON** | `serde_json` operates on input buffer |
| **Zero-Allocation** | `Cow<str>` for path normalization |
| **Release Profile** | `opt-level="z"`, LTO, single codegen unit |

**Result:** Sub-millisecond execution for typical commands.

## Pattern Counts

| Type | Count |
|------|-------|
| Safe patterns (whitelist) | 34 |
| Destructive patterns (blacklist) | 16 |

## Security Considerations

### What DCG Protects Against

- Accidental data loss from `git checkout --` or `git reset --hard`
- Remote history destruction from force pushes
- Stash loss from `git stash drop/clear`
- Filesystem accidents from `rm -rf` outside temp directories

### What DCG Does NOT Protect Against

- Malicious actors (can bypass the hook)
- Non-Bash commands (Python/JavaScript file writes, API calls)
- Committed but unpushed work
- Commands inside scripts (`./deploy.sh` contents not inspected)

### Threat Model

DCG assumes the AI agent is **well-intentioned but fallible**. It catches honest mistakes, not adversarial attacks.

## Troubleshooting

### Hook not blocking commands

1. Verify `~/.claude/settings.json` has hook configuration
2. Restart Claude Code
3. Test manually: `echo '{"tool_name":"Bash","tool_input":{"command":"git reset --hard"}}' | dcg`

### Hook blocking safe commands

1. Check if there's an edge case not covered
2. File a GitHub issue
3. Temporary bypass: `DCG_BYPASS=1` or run command manually

## FAQ

**Q: Why block both `git branch -d` and `git branch -D`?**

Lowercase `-d` checks merge state, but still removes the branch name, upstream-tracking configuration, and convenient reflog reference. Those are user-owned state, so every delete form requires explicit approval. Review first with `git branch -vv`, `git branch --merged`, and `git branch --no-merged`. The merge-checked form is its own rule, `core.git:branch-delete`, so `[policy.rules] "core.git:branch-delete" = "ask"` turns it into an approval prompt while `-D` (`core.git:branch-force-delete`) stays denied.

**Q: Why is `git push --force-with-lease` allowed?**

Force-with-lease refuses to push if the remote has commits you haven't seen, preventing accidental overwrites.

**Q: Why block all `rm -rf` outside temp directories?**

Recursive forced deletion is extremely dangerous. A typo or wrong variable can delete critical files. Temp directories are designed to be ephemeral.

**Q: What if I really need to run a blocked command?**

DCG instructs the agent to ask for permission. Run the command manually in a separate terminal after making a conscious decision.

## Integration with Flywheel

| Tool | Integration |
|------|-------------|
| **Claude Code** | Native PreToolUse hook |
| **Agent Mail** | Agents can report blocked commands to coordinator |
| **BV** | Flag tasks that repeatedly trigger DCG |
| **CASS** | Search DCG block patterns across sessions |
| **RU** | DCG protects agent-sweep from destructive commits |

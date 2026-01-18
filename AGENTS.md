# AGENTS.md — dcg (Destructive Command Guard)

> Guidelines for AI coding agents working in this Rust codebase.

---

## RULE NUMBER 1: NO FILE DELETION

**YOU ARE NEVER ALLOWED TO DELETE A FILE WITHOUT EXPRESS PERMISSION.** Even a new file that you yourself created, such as a test code file. You have a horrible track record of deleting critically important files or otherwise throwing away tons of expensive work. As a result, you have permanently lost any and all rights to determine that a file or folder should be deleted.

**YOU MUST ALWAYS ASK AND RECEIVE CLEAR, WRITTEN PERMISSION BEFORE EVER DELETING A FILE OR FOLDER OF ANY KIND.**

---

## Irreversible Git & Filesystem Actions — DO NOT EVER BREAK GLASS

> **Note:** This project exists specifically to block these dangerous commands for AI agents. Practice what we preach.

1. **Absolutely forbidden commands:** `git reset --hard`, `git clean -fd`, `rm -rf`, or any command that can delete or overwrite code/data must never be run unless the user explicitly provides the exact command and states, in the same message, that they understand and want the irreversible consequences.
2. **No guessing:** If there is any uncertainty about what a command might delete or overwrite, stop immediately and ask the user for specific approval. "I think it's safe" is never acceptable.
3. **Safer alternatives first:** When cleanup or rollbacks are needed, request permission to use non-destructive options (`git status`, `git diff`, `git stash`, copying to backups) before ever considering a destructive command.
4. **Mandatory explicit plan:** Even after explicit user authorization, restate the command verbatim, list exactly what will be affected, and wait for a confirmation that your understanding is correct. Only then may you execute it—if anything remains ambiguous, refuse and escalate.
5. **Document the confirmation:** When running any approved destructive command, record (in the session notes / final response) the exact user text that authorized it, the command actually run, and the execution time. If that record is absent, the operation did not happen.

---

## Toolchain: Rust & Cargo

We only use **Cargo** in this project, NEVER any other package manager.

- **Edition:** Rust 2024 (nightly required — see `rust-toolchain.toml`)
- **Dependency versions:** Explicit versions for stability
- **Configuration:** Cargo.toml only
- **Unsafe code:** Forbidden (`#![forbid(unsafe_code)]`)

### Key Dependencies

| Crate | Purpose |
|-------|---------|
| `serde` + `serde_json` | JSON parsing for Claude Code hook protocol |
| `fancy-regex` | Advanced regex with lookahead/lookbehind |
| `memchr` | SIMD-accelerated substring search |
| `colored` | Terminal colors with TTY detection |
| `vergen-gix` | Build metadata embedding (build.rs) |

### Release Profile

The release build optimizes for binary size:

```toml
[profile.release]
opt-level = "z"     # Optimize for size (lean binary for distribution)
lto = true          # Link-time optimization
codegen-units = 1   # Single codegen unit for better optimization
panic = "abort"     # Smaller binary, no unwinding overhead
strip = true        # Remove debug symbols
```

---

## Code Editing Discipline

### No Script-Based Changes

**NEVER** run a script that processes/changes code files in this repo. Brittle regex-based transformations create far more problems than they solve.

- **Always make code changes manually**, even when there are many instances
- For many simple changes: use parallel subagents
- For subtle/complex changes: do them methodically yourself

### No File Proliferation

If you want to change something or add a feature, **revise existing code files in place**.

**NEVER** create variations like:
- `mainV2.rs`
- `main_improved.rs`
- `main_enhanced.rs`

New files are reserved for **genuinely new functionality** that makes zero sense to include in any existing file. The bar for creating new files is **incredibly high**.

---

## Backwards Compatibility

We do not care about backwards compatibility—we're in early development with no users. We want to do things the **RIGHT** way with **NO TECH DEBT**.

- Never create "compatibility shims"
- Never create wrapper functions for deprecated APIs
- Just fix the code directly

---

## Output Style

This tool has two output modes:

- **JSON to stdout:** For Claude Code hook protocol (`hookSpecificOutput` with `permissionDecision: "deny"`)
- **Colorful warning to stderr:** For human visibility when commands are blocked

Output behavior:
- **Deny:** Colorful warning to stderr + JSON to stdout
- **Allow:** No output (silent exit)
- **--version/-V:** Version info with build metadata to stderr
- **--help/-h:** Usage information to stderr

Colors are automatically disabled when stderr is not a TTY (e.g., piped to file).

---

## Compiler Checks (CRITICAL)

**After any substantive code changes, you MUST verify no errors were introduced:**

```bash
# Check for compiler errors and warnings
cargo check --all-targets

# Check for clippy lints (pedantic + nursery are enabled)
cargo clippy --all-targets -- -D warnings

# Verify formatting
cargo fmt --check
```

If you see errors, **carefully understand and resolve each issue**. Read sufficient context to fix them the RIGHT way.

---

## Testing

### Unit Tests

The test suite includes 80+ tests covering all functionality:

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test module
cargo test normalize_command_tests
cargo test safe_pattern_tests
cargo test destructive_pattern_tests
```

### End-to-End Testing

```bash
# Run the E2E test script
./scripts/e2e_test.sh

# Or test manually
echo '{"tool_name":"Bash","tool_input":{"command":"git reset --hard"}}' | cargo run --release
# Should output JSON denial

echo '{"tool_name":"Bash","tool_input":{"command":"git status"}}' | cargo run --release
# Should output nothing (allowed)
```

### Test Categories

| Module | Tests | Purpose |
|--------|-------|---------|
| `normalize_command_tests` | 8 | Path stripping for git/rm binaries |
| `quick_reject_tests` | 5 | Fast-path filtering for non-git/rm commands |
| `safe_pattern_tests` | 16 | Whitelist accuracy |
| `destructive_pattern_tests` | 20 | Blacklist coverage |
| `input_parsing_tests` | 8 | JSON parsing robustness |
| `deny_output_tests` | 2 | Output format validation |
| `integration_tests` | 4 | End-to-end pipeline |
| `optimization_tests` | 9 | Performance paths |
| `edge_case_tests` | 24 | Real-world edge cases |

---

## CI/CD Pipeline

### Jobs Overview

| Job | Trigger | Purpose | Blocking |
|-----|---------|---------|----------|
| `check` | PR, push | Format, clippy, UBS, tests | Yes |
| `coverage` | PR, push | Coverage thresholds | Yes |
| `memory-tests` | PR, push | Memory leak detection | Yes |
| `benchmarks` | push to master | Performance budgets | Warn only |
| `e2e` | PR, push | End-to-end shell tests | Yes |
| `scan-regression` | PR, push | Scan output stability | Yes |
| `perf-regression` | PR, push | Process-per-invocation perf | Yes |

### Check Job

Runs format, clippy, UBS static analysis, and unit tests. Includes:
- `cargo fmt --check` - Code formatting
- `cargo clippy --all-targets -- -D warnings` - Lints (pedantic + nursery enabled)
- UBS analysis on changed Rust files (warning-only, non-blocking)
- `cargo nextest run` - Full test suite with JUnit XML report

### Coverage Job

Runs `cargo llvm-cov` and enforces thresholds:
- **Overall:** ≥ 70%
- **src/evaluator.rs:** ≥ 80%
- **src/hook.rs:** ≥ 80%

Coverage is uploaded to Codecov for trend tracking. Dashboard: https://codecov.io/gh/Dicklesworthstone/destructive_command_guard

### Memory Tests Job

Runs dedicated memory leak tests with:
- `--test-threads=1` for accurate measurements
- Release mode for realistic performance
- 1-2MB growth budgets per test

Tests include: hook input parsing, pattern evaluation, heredoc extraction, file extractors, full pipeline, and a self-test that verifies the framework catches leaks.

### Benchmarks Job

Runs on push to master only (benchmarks are noisy on PRs). Checks performance budgets from `src/perf.rs`:
- Quick reject: < 50μs panic
- Fast path: < 500μs panic
- Pattern match: < 1ms panic
- Heredoc extract: < 2ms panic
- Full pipeline: < 50ms panic

### UBS Static Analysis

Ultimate Bug Scanner runs on changed Rust files. Currently warning-only (non-blocking) to tune for false positives. Configuration in `.ubsignore` excludes test/bench/fuzz directories.

### Dependabot

Automated dependency updates configured in `.github/dependabot.yml`:
- **Cargo dependencies:** Weekly (Monday 9am EST), 5 PR limit
- **GitHub Actions:** Weekly (Monday 9am EST), 3 PR limit
- **Grouping:** Minor/patch updates grouped; serde updates separate (more careful review)

### Debugging CI Failures

#### Coverage Threshold Failure
1. Check which file(s) dropped below threshold in CI output
2. Run `cargo llvm-cov --html` locally to see uncovered lines
3. Add tests for uncovered code paths
4. Download `coverage-report` artifact for full details

#### Memory Test Failure
1. Download `memory-test-output` artifact
2. Check which test failed and growth amount
3. Run locally: `cargo test --test memory_tests --release -- --nocapture --test-threads=1`
4. Profile with valgrind if needed

#### UBS Warnings
1. Check ubs-output.log in CI summary
2. Review flagged issues - may be false positives
3. If valid issues, fix them; if false positives, add to `.ubsignore`

#### E2E Test Failure
1. Download `e2e-artifacts` artifact
2. Check `e2e_output.json` for failing test details
3. Run locally: `./scripts/e2e_test.sh --verbose`
4. The step summary shows the first failure with output

#### Benchmark Regression
1. Download `benchmark-results` artifact
2. Compare against budgets in `src/perf.rs`
3. Profile locally with `cargo bench --bench heredoc_perf`
4. Check for algorithmic regressions in hot path

---

## Heredoc Detection Notes (for contributors)

- **Rule IDs**: Heredoc patterns use stable IDs like `heredoc.python.shutil_rmtree` for allowlisting.
- **Fail-open**: In hook mode, heredoc parse errors/timeouts must allow (do not block).
- **Tests**: Prefer targeted tests in `src/ast_matcher.rs` and `src/heredoc.rs`.
  - `cargo test ast_matcher`
  - `cargo test heredoc`
  - Add positive and negative fixtures for each new pattern.

---

## Third-Party Library Usage

If you aren't 100% sure how to use a third-party library, **SEARCH ONLINE** to find the latest documentation and mid-2025 best practices.

---

## dcg (Destructive Command Guard) — This Project

**This is the project you're working on.** dcg is a high-performance Claude Code hook that blocks destructive commands before they execute. It protects against dangerous git commands, filesystem operations, database queries, container commands, and more through a modular pack system.

### Architecture

```
JSON Input → Parse → Quick Reject (memchr) → Normalize → Safe Patterns → Destructive Patterns → Default Allow
```

### Key Files

| File | Purpose |
|------|---------|
| `src/main.rs` | Complete implementation (~40KB) + 80 tests |
| `Cargo.toml` | Dependencies and release optimizations |
| `build.rs` | Build script for version metadata (vergen) |
| `rust-toolchain.toml` | Nightly toolchain requirement |
| `scripts/e2e_test.sh` | End-to-end test script (120 tests) |

### Pattern System

- **34 safe patterns** (whitelist, checked first)
- **16 destructive patterns** (blacklist, checked second)
- **Default allow** for unmatched commands

### Adding New Patterns

1. Identify the command to block/allow
2. Write a regex using `fancy-regex` syntax (supports lookahead/lookbehind)
3. Add to `SAFE_PATTERNS` or `DESTRUCTIVE_PATTERNS` using the macros:

```rust
// Safe pattern (whitelist)
pattern!("pattern-name", r"regex-here")

// Destructive pattern (blacklist)
destructive!(
    r"regex-here",
    "Human-readable reason for blocking"
)
```

4. Add tests for all variants
5. Run `cargo test` and `./scripts/e2e_test.sh`

### Performance Requirements

Every Bash command passes through this hook. Performance is critical:

- Quick rejection filter eliminates 99%+ of commands before regex
- Lazy-initialized static regex patterns (compiled once, reused)
- Sub-millisecond execution for typical commands
- Zero allocations on the hot path for safe commands

---

<!-- dcg-machine-readable-v1 -->

## DCG Hook Protocol (Machine-Readable Reference)

> This section provides structured documentation for AI agents integrating with dcg.

### JSON Input Format

dcg reads from stdin in Claude Code's `PreToolUse` hook format:

```json
{
  "tool_name": "Bash",
  "tool_input": {
    "command": "git reset --hard HEAD~5"
  }
}
```

**Required fields:**
- `tool_name`: Must be `"Bash"` for dcg to process (other tools are ignored)
- `tool_input.command`: The shell command string to evaluate

### JSON Output Format (Denial)

When a command is blocked, dcg outputs JSON to stdout:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "BLOCKED by dcg\n\nTip: dcg explain \"git reset --hard HEAD~5\"\n\nReason: git reset --hard destroys uncommitted changes\n\nExplanation: Rewrites history and discards uncommitted changes.\n\nRule: core.git:reset-hard\n\nCommand: git reset --hard HEAD~5\n\nIf this operation is truly needed, ask the user for explicit permission and have them run the command manually.",
    "ruleId": "core.git:reset-hard",
    "packId": "core.git",
    "severity": "critical",
    "confidence": 0.95,
    "allowOnceCode": "a1b2c3",
    "allowOnceFullHash": "sha256:abc123...",
    "remediation": {
      "safeAlternative": "git stash",
      "explanation": "Use git stash to save your changes first.",
      "allowOnceCommand": "dcg allow-once a1b2c3"
    }
  }
}
```

**Key fields for agent parsing:**
| Field | Type | Description |
|-------|------|-------------|
| `permissionDecision` | `"allow"` \| `"deny"` | The decision |
| `ruleId` | `string` | Stable pattern ID (e.g., `"core.git:reset-hard"`) for allowlisting |
| `packId` | `string` | Pack that matched (e.g., `"core.git"`) |
| `severity` | `string` | `"critical"`, `"high"`, `"medium"`, or `"low"` |
| `confidence` | `number` | Match confidence 0.0-1.0 |
| `allowOnceCode` | `string` | Short code for `dcg allow-once` |
| `remediation.safeAlternative` | `string?` | Suggested safe command |

### JSON Output Format (Allow)

When a command is allowed: **no output** (silent exit 0).

---

## Exit Codes Reference

| Code | Meaning | Agent Action |
|------|---------|--------------|
| `0` | Command allowed OR denied (check stdout for JSON) | Parse stdout; if empty, command was allowed |
| `1` | Parse error or invalid input | Retry with corrected input |
| `2` | Configuration error | Check config file syntax |

**Detection logic for agents:**
```bash
output=$(echo "$hook_input" | dcg 2>/dev/null)
if [ -z "$output" ]; then
  echo "ALLOWED"
else
  echo "DENIED: $output"
fi
```

---

## Error Codes Reference

DCG uses standardized error codes in the format `DCG-XXXX` for machine-parseable error handling.

### Error Categories

| Range | Category | Description |
|-------|----------|-------------|
| DCG-1xxx | `pattern_match` | Pattern matching and evaluation errors |
| DCG-2xxx | `configuration` | Configuration loading and parsing errors |
| DCG-3xxx | `runtime` | Runtime and execution errors |
| DCG-4xxx | `external` | External integration errors |

### Common Error Codes

| Code | Description | Typical Cause |
|------|-------------|---------------|
| `DCG-1001` | Pattern compilation failed | Invalid regex syntax in pattern |
| `DCG-1002` | Pattern match timeout | Complex pattern taking too long |
| `DCG-2001` | Config file not found | Missing configuration file |
| `DCG-2002` | Config parse error | Invalid TOML/JSON syntax |
| `DCG-2004` | Allowlist load error | Invalid allowlist file |
| `DCG-3001` | JSON parse error | Malformed JSON input |
| `DCG-3002` | IO error | File read/write failure |
| `DCG-4001` | External pack load failed | Invalid external pack YAML |

### Error JSON Structure

When errors are returned in JSON format, they follow this structure:

```json
{
  "error": {
    "code": "DCG-3001",
    "category": "runtime",
    "message": "JSON parse error: unexpected token at position 15",
    "context": {
      "position": 15,
      "input_preview": "{ \"tool_name\": ..."
    }
  }
}
```

**Fields:**
- `code`: Stable error code for programmatic handling
- `category`: Error category (`pattern_match`, `configuration`, `runtime`, `external`)
- `message`: Human-readable error description
- `context`: Additional details (optional, varies by error type)

---

## Allowlist & Bypass Instructions

### Temporary Bypass (24-hour allow-once)

When a command is blocked, the output includes an `allowOnceCode`. Use it:

```bash
dcg allow-once <code>
```

This allows the specific command for 24 hours in the current directory scope.

### Permanent Allowlist (by rule ID)

Add a rule to the project allowlist:

```bash
dcg allowlist add <ruleId> --project
# Example: dcg allowlist add core.git:reset-hard --project
```

Allowlist files (in priority order):
1. `.dcg/allowlist.toml` (project)
2. `~/.config/dcg/allowlist.toml` (user)
3. `/etc/dcg/allowlist.toml` (system)

### Bypass Environment Variable

For emergency bypass (use sparingly):

```bash
DCG_BYPASS=1 <command>
```

**Warning:** This disables all protection. Log and justify any usage.

---

## Pattern Quick Reference

### Core Git Patterns (Always Enabled)

| Pattern ID | Blocks | Severity |
|------------|--------|----------|
| `core.git:reset-hard` | `git reset --hard` | Critical |
| `core.git:reset-merge` | `git reset --merge` | High |
| `core.git:checkout-discard` | `git checkout -- <file>` | High |
| `core.git:restore-discard` | `git restore <file>` (without `--staged`) | High |
| `core.git:clean-force` | `git clean -f`, `git clean -fd` | High |
| `core.git:force-push` | `git push --force`, `git push -f` | High |
| `core.git:branch-force-delete` | `git branch -D` | High |
| `core.git:stash-drop` | `git stash drop`, `git stash clear` | High |

### Core Filesystem Patterns (Always Enabled)

| Pattern ID | Blocks | Severity |
|------------|--------|----------|
| `core.filesystem:rm-rf-root` | `rm -rf /`, `rm -rf ~` | Critical |
| `core.filesystem:rm-rf-general` | `rm -rf` outside temp dirs | High |

### Safe Patterns (Whitelist - Always Allowed)

| Pattern | Command | Why Safe |
|---------|---------|----------|
| `git-checkout-branch` | `git checkout -b <branch>` | Creates new branch |
| `git-checkout-orphan` | `git checkout --orphan <branch>` | Creates orphan branch |
| `git-restore-staged` | `git restore --staged <file>` | Only unstages, doesn't discard |
| `git-clean-dry-run` | `git clean -n`, `git clean --dry-run` | Preview only |
| `rm-tmp` | `rm -rf /tmp/*`, `/var/tmp/*` | Temp directory cleanup |

### Pack Enable/Disable Examples

```toml
# ~/.config/dcg/config.toml
[packs]
enabled = [
    "database.postgresql",    # Blocks DROP TABLE, TRUNCATE
    "kubernetes.kubectl",     # Blocks kubectl delete namespace
    "cloud.aws",              # Blocks aws ec2 terminate-instances
]

disabled = [
    "containers.docker",      # Disable Docker protection
]
```

List all packs: `dcg packs --verbose`

---

## CLI Quick Reference for Agents

| Command | Purpose |
|---------|---------|
| `dcg explain "<command>"` | Detailed trace of why command is blocked/allowed |
| `dcg allow-once <code>` | Allow a blocked command for 24 hours |
| `dcg allowlist add <ruleId> --project` | Permanently allow a rule |
| `dcg packs` | List enabled packs |
| `dcg packs --verbose` | List all packs with pattern counts |
| `dcg scan .` | Scan codebase for destructive patterns |
| `dcg --version` | Show version and build info |

---

## Agent Integration Checklist

When integrating with dcg, ensure your agent:

- [ ] Parses stdout for JSON denial responses
- [ ] Handles empty stdout as "command allowed"
- [ ] Uses `ruleId` for stable allowlisting (not pattern text)
- [ ] Displays `remediation.safeAlternative` to users when available
- [ ] Respects `severity` for prioritization (critical > high > medium > low)
- [ ] Uses `dcg explain` before asking users to bypass

---

## JSON Schema Reference

Formal JSON Schema definitions (Draft 2020-12) for all dcg output formats are available in `docs/json-schema/`:

| Schema | Purpose |
|--------|---------|
| [`hook-output.json`](docs/json-schema/hook-output.json) | PreToolUse hook denial response format |
| [`scan-results.json`](docs/json-schema/scan-results.json) | `dcg scan` command output format |
| [`stats-output.json`](docs/json-schema/stats-output.json) | `dcg stats` command output format |
| [`error.json`](docs/json-schema/error.json) | Error response formats for various commands |

Use these schemas for:
- Validating dcg output in automated pipelines
- Generating type-safe client code
- Understanding the complete output contract

<!-- end-dcg-machine-readable -->

---

## MCP Agent Mail — Multi-Agent Coordination

A mail-like layer that lets coding agents coordinate asynchronously via MCP tools and resources. Provides identities, inbox/outbox, searchable threads, and advisory file reservations with human-auditable artifacts in Git.

### Why It's Useful

- **Prevents conflicts:** Explicit file reservations (leases) for files/globs
- **Token-efficient:** Messages stored in per-project archive, not in context
- **Quick reads:** `resource://inbox/...`, `resource://thread/...`

### Same Repository Workflow

1. **Register identity:**
   ```
   ensure_project(project_key=<abs-path>)
   register_agent(project_key, program, model)
   ```

2. **Reserve files before editing:**
   ```
   file_reservation_paths(project_key, agent_name, ["src/**"], ttl_seconds=3600, exclusive=true)
   ```

3. **Communicate with threads:**
   ```
   send_message(..., thread_id="FEAT-123")
   fetch_inbox(project_key, agent_name)
   acknowledge_message(project_key, agent_name, message_id)
   ```

4. **Quick reads:**
   ```
   resource://inbox/{Agent}?project=<abs-path>&limit=20
   resource://thread/{id}?project=<abs-path>&include_bodies=true
   ```

### Macros vs Granular Tools

- **Prefer macros for speed:** `macro_start_session`, `macro_prepare_thread`, `macro_file_reservation_cycle`, `macro_contact_handshake`
- **Use granular tools for control:** `register_agent`, `file_reservation_paths`, `send_message`, `fetch_inbox`, `acknowledge_message`

### Common Pitfalls

- `"from_agent not registered"`: Always `register_agent` in the correct `project_key` first
- `"FILE_RESERVATION_CONFLICT"`: Adjust patterns, wait for expiry, or use non-exclusive reservation
- **Auth errors:** If JWT+JWKS enabled, include bearer token with matching `kid`

---

## Beads (bd) — Dependency-Aware Issue Tracking

Beads provides a lightweight, dependency-aware issue database and CLI (`bd`) for selecting "ready work," setting priorities, and tracking status. It complements MCP Agent Mail's messaging and file reservations.

### Conventions

- **Single source of truth:** Beads for task status/priority/dependencies; Agent Mail for conversation and audit
- **Shared identifiers:** Use Beads issue ID (e.g., `bd-123`) as Mail `thread_id` and prefix subjects with `[bd-123]`
- **Reservations:** When starting a task, call `file_reservation_paths()` with the issue ID in `reason`

### Typical Agent Flow

1. **Pick ready work (Beads):**
   ```bash
   bd ready --json  # Choose highest priority, no blockers
   ```

2. **Reserve edit surface (Mail):**
   ```
   file_reservation_paths(project_key, agent_name, ["src/**"], ttl_seconds=3600, exclusive=true, reason="bd-123")
   ```

3. **Announce start (Mail):**
   ```
   send_message(..., thread_id="bd-123", subject="[bd-123] Start: <title>", ack_required=true)
   ```

4. **Work and update:** Reply in-thread with progress

5. **Complete and release:**
   ```bash
   bd close bd-123 --reason "Completed"
   ```
   ```
   release_file_reservations(project_key, agent_name, paths=["src/**"])
   ```
   Final Mail reply: `[bd-123] Completed` with summary

### Mapping Cheat Sheet

| Concept | Value |
|---------|-------|
| Mail `thread_id` | `bd-###` |
| Mail subject | `[bd-###] ...` |
| File reservation `reason` | `bd-###` |
| Commit messages | Include `bd-###` for traceability |

---

## bv — Graph-Aware Triage Engine

bv is a graph-aware triage engine for Beads projects (`.beads/beads.jsonl`). It computes PageRank, betweenness, critical path, cycles, HITS, eigenvector, and k-core metrics deterministically.

**Scope boundary:** bv handles *what to work on* (triage, priority, planning). For agent-to-agent coordination (messaging, work claiming, file reservations), use MCP Agent Mail.

**CRITICAL: Use ONLY `--robot-*` flags. Bare `bv` launches an interactive TUI that blocks your session.**

### The Workflow: Start With Triage

**`bv --robot-triage` is your single entry point.** It returns:
- `quick_ref`: at-a-glance counts + top 3 picks
- `recommendations`: ranked actionable items with scores, reasons, unblock info
- `quick_wins`: low-effort high-impact items
- `blockers_to_clear`: items that unblock the most downstream work
- `project_health`: status/type/priority distributions, graph metrics
- `commands`: copy-paste shell commands for next steps

```bash
bv --robot-triage        # THE MEGA-COMMAND: start here
bv --robot-next          # Minimal: just the single top pick + claim command
```

### Command Reference

**Planning:**
| Command | Returns |
|---------|---------|
| `--robot-plan` | Parallel execution tracks with `unblocks` lists |
| `--robot-priority` | Priority misalignment detection with confidence |

**Graph Analysis:**
| Command | Returns |
|---------|---------|
| `--robot-insights` | Full metrics: PageRank, betweenness, HITS, eigenvector, critical path, cycles, k-core, articulation points, slack |
| `--robot-label-health` | Per-label health: `health_level`, `velocity_score`, `staleness`, `blocked_count` |
| `--robot-label-flow` | Cross-label dependency: `flow_matrix`, `dependencies`, `bottleneck_labels` |
| `--robot-label-attention [--attention-limit=N]` | Attention-ranked labels |

**History & Change Tracking:**
| Command | Returns |
|---------|---------|
| `--robot-history` | Bead-to-commit correlations |
| `--robot-diff --diff-since <ref>` | Changes since ref: new/closed/modified issues, cycles |

**Other:**
| Command | Returns |
|---------|---------|
| `--robot-burndown <sprint>` | Sprint burndown, scope changes, at-risk items |
| `--robot-forecast <id\|all>` | ETA predictions with dependency-aware scheduling |
| `--robot-alerts` | Stale issues, blocking cascades, priority mismatches |
| `--robot-suggest` | Hygiene: duplicates, missing deps, label suggestions |
| `--robot-graph [--graph-format=json\|dot\|mermaid]` | Dependency graph export |
| `--export-graph <file.html>` | Interactive HTML visualization |

### Scoping & Filtering

```bash
bv --robot-plan --label backend              # Scope to label's subgraph
bv --robot-insights --as-of HEAD~30          # Historical point-in-time
bv --recipe actionable --robot-plan          # Pre-filter: ready to work
bv --recipe high-impact --robot-triage       # Pre-filter: top PageRank
bv --robot-triage --robot-triage-by-track    # Group by parallel work streams
bv --robot-triage --robot-triage-by-label    # Group by domain
```

### Understanding Robot Output

**All robot JSON includes:**
- `data_hash` — Fingerprint of source beads.jsonl
- `status` — Per-metric state: `computed|approx|timeout|skipped` + elapsed ms
- `as_of` / `as_of_commit` — Present when using `--as-of`

**Two-phase analysis:**
- **Phase 1 (instant):** degree, topo sort, density
- **Phase 2 (async, 500ms timeout):** PageRank, betweenness, HITS, eigenvector, cycles

### jq Quick Reference

```bash
bv --robot-triage | jq '.quick_ref'                        # At-a-glance summary
bv --robot-triage | jq '.recommendations[0]'               # Top recommendation
bv --robot-plan | jq '.plan.summary.highest_impact'        # Best unblock target
bv --robot-insights | jq '.status'                         # Check metric readiness
bv --robot-insights | jq '.Cycles'                         # Circular deps (must fix!)
```

---

## UBS — Ultimate Bug Scanner

**Golden Rule:** `ubs <changed-files>` before every commit. Exit 0 = safe. Exit >0 = fix & re-run.

### Commands

```bash
ubs file.rs file2.rs                    # Specific files (< 1s) — USE THIS
ubs $(git diff --name-only --cached)    # Staged files — before commit
ubs --only=rust,toml src/               # Language filter (3-5x faster)
ubs --ci --fail-on-warning .            # CI mode — before PR
ubs .                                   # Whole project (ignores target/, Cargo.lock)
```

### Output Format

```
⚠️  Category (N errors)
    file.rs:42:5 – Issue description
    💡 Suggested fix
Exit code: 1
```

Parse: `file:line:col` → location | 💡 → how to fix | Exit 0/1 → pass/fail

### Fix Workflow

1. Read finding → category + fix suggestion
2. Navigate `file:line:col` → view context
3. Verify real issue (not false positive)
4. Fix root cause (not symptom)
5. Re-run `ubs <file>` → exit 0
6. Commit

### Bug Severity

- **Critical (always fix):** Memory safety, use-after-free, data races, SQL injection
- **Important (production):** Unwrap panics, resource leaks, overflow checks
- **Contextual (judgment):** TODO/FIXME, println! debugging

---

## ast-grep vs ripgrep

**Use `ast-grep` when structure matters.** It parses code and matches AST nodes, ignoring comments/strings, and can **safely rewrite** code.

- Refactors/codemods: rename APIs, change import forms
- Policy checks: enforce patterns across a repo
- Editor/automation: LSP mode, `--json` output

**Use `ripgrep` when text is enough.** Fastest way to grep literals/regex.

- Recon: find strings, TODOs, log lines, config values
- Pre-filter: narrow candidate files before ast-grep

### Rule of Thumb

- Need correctness or **applying changes** → `ast-grep`
- Need raw speed or **hunting text** → `rg`
- Often combine: `rg` to shortlist files, then `ast-grep` to match/modify

### Rust Examples

```bash
# Find structured code (ignores comments)
ast-grep run -l Rust -p 'fn $NAME($$$ARGS) -> $RET { $$$BODY }'

# Find all unwrap() calls
ast-grep run -l Rust -p '$EXPR.unwrap()'

# Quick textual hunt
rg -n 'println!' -t rust

# Combine speed + precision
rg -l -t rust 'unwrap\(' | xargs ast-grep run -l Rust -p '$X.unwrap()' --json
```

---

## Morph Warp Grep — AI-Powered Code Search

**Use `mcp__morph-mcp__warp_grep` for exploratory "how does X work?" questions.** An AI agent expands your query, greps the codebase, reads relevant files, and returns precise line ranges with full context.

**Use `ripgrep` for targeted searches.** When you know exactly what you're looking for.

**Use `ast-grep` for structural patterns.** When you need AST precision for matching/rewriting.

### When to Use What

| Scenario | Tool | Why |
|----------|------|-----|
| "How is pattern matching implemented?" | `warp_grep` | Exploratory; don't know where to start |
| "Where is the quick reject filter?" | `warp_grep` | Need to understand architecture |
| "Find all uses of `Regex::new`" | `ripgrep` | Targeted literal search |
| "Find files with `println!`" | `ripgrep` | Simple pattern |
| "Replace all `unwrap()` with `expect()`" | `ast-grep` | Structural refactor |

### warp_grep Usage

```
mcp__morph-mcp__warp_grep(
  repoPath: "/path/to/dcg",
  query: "How does the safe pattern whitelist work?"
)
```

Returns structured results with file paths, line ranges, and extracted code snippets.

### Anti-Patterns

- **Don't** use `warp_grep` to find a specific function name → use `ripgrep`
- **Don't** use `ripgrep` to understand "how does X work" → wastes time with manual reads
- **Don't** use `ripgrep` for codemods → risks collateral edits

<!-- bv-agent-instructions-v1 -->

---

## Beads Workflow Integration

This project uses [beads_viewer](https://github.com/Dicklesworthstone/beads_viewer) for issue tracking. Issues are stored in `.beads/` and tracked in git.

### Essential Commands

```bash
# View issues (launches TUI - avoid in automated sessions)
bv

# CLI commands for agents (use these instead)
bd ready              # Show issues ready to work (no blockers)
bd list --status=open # All open issues
bd show <id>          # Full issue details with dependencies
bd create --title="..." --type=task --priority=2
bd update <id> --status=in_progress
bd close <id> --reason="Completed"
bd close <id1> <id2>  # Close multiple issues at once
bd sync               # Commit and push changes
```

### Workflow Pattern

1. **Start**: Run `bd ready` to find actionable work
2. **Claim**: Use `bd update <id> --status=in_progress`
3. **Work**: Implement the task
4. **Complete**: Use `bd close <id>`
5. **Sync**: Always run `bd sync` at session end

### Key Concepts

- **Dependencies**: Issues can block other issues. `bd ready` shows only unblocked work.
- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (use numbers, not words)
- **Types**: task, bug, feature, epic, question, docs
- **Blocking**: `bd dep add <issue> <depends-on>` to add dependencies

### Session Protocol

**Before ending any session, run this checklist:**

```bash
git status              # Check what changed
git add <files>         # Stage code changes
bd sync                 # Commit beads changes
git commit -m "..."     # Commit code
bd sync                 # Commit any new beads changes
git push                # Push to remote
```

### Best Practices

- Check `bd ready` at session start to find available work
- Update status as you work (in_progress → closed)
- Create new issues with `bd create` when you discover tasks
- Use descriptive titles and set appropriate priority/type
- Always `bd sync` before ending session

<!-- end-bv-agent-instructions -->

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd sync
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds

# AGENTS.md — dcg (Destructive Command Guard)

> Guidelines for AI coding agents working in this Rust codebase.

---

## RULE 0 - THE FUNDAMENTAL OVERRIDE PREROGATIVE

If I tell you to do something, even if it goes against what follows below, YOU MUST LISTEN TO ME. I AM IN CHARGE, NOT YOU.

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

## Git Branch: ONLY Use `main`, NEVER `master`

**The default branch is `main`. The `master` branch exists only for legacy URL compatibility.**

- **All work happens on `main`** — commits, PRs, feature branches all merge to `main`
- **Never reference `master` in code or docs** — if you see `master` anywhere, it's a bug that needs fixing
- **The `master` branch must stay synchronized with `main`** — after pushing to `main`, also push to `master`:
  ```bash
  git push origin main:master
  ```

**Why this matters:** The `dcg update` command and install URLs historically referenced `master`. If `master` falls behind `main`, users get stale code. We had a bug where `master` was **497 commits behind**, causing users to see old installer behavior.

**If you see `master` referenced anywhere:**
1. Update it to `main`
2. Ensure `master` is synchronized: `git push origin main:master`

---

## Toolchain: Rust & Cargo

We only use **Cargo** in this project, NEVER any other package manager.

- **Edition:** Rust 2024 (nightly required — see `rust-toolchain.toml`)
- **Dependency versions:** Explicit versions for stability
- **Configuration:** Cargo.toml only (single crate, not a workspace)
- **Unsafe code:** Forbidden (`#![forbid(unsafe_code)]`)

### Key Dependencies

| Crate | Purpose |
|-------|---------|
| `serde` + `serde_json` | JSON parsing for Claude Code hook protocol |
| `serde_yaml` | External pack YAML parsing |
| `toml` + `toml_edit` | TOML config parsing with formatting preservation |
| `fancy-regex` | Advanced regex with lookahead/lookbehind |
| `regex` | `RegexSet` for heredoc detection |
| `memchr` | SIMD-accelerated substring search |
| `aho-corasick` | Multi-pattern string matching for keyword quick-reject |
| `colored` | Terminal colors with TTY detection |
| `clap` + `clap_complete` | CLI argument parsing with shell completions |
| `chrono` | RFC 3339 timestamps |
| `ast-grep-core` + `ast-grep-language` | AST-based pattern matching for heredoc/inline-script content |
| `rusqlite` | Bundled upstream SQLite for best-effort telemetry history |
| `rust-mcp-sdk` | MCP server integration (stdio transport) |
| `tokio` | Async runtime for MCP server mode |
| `ratatui` + `comfy-table` + `indicatif` + `console` | TUI/CLI visual polish |
| `self_update` | Binary self-update from GitHub Releases |
| `vergen-gix` | Build metadata embedding (build.rs) |
| `tracing` + `tracing-subscriber` | Structured logging and diagnostics |
| `sha2` + `hmac` | Hashing and HMAC for allow-once short codes |
| `flate2` | Gzip compression for history export |

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

### Feature Flags

```toml
[features]
rayon = ["dep:rayon"]           # Rayon data parallelism (optional)
rich-output = ["dep:rich_rust"] # Enable rich_rust for premium terminal output
legacy-output = []              # Keep old rendering (placeholder for gradual migration)
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

## Windows Support (native, `x86_64-pc-windows-msvc`)

dcg ships a **native Windows** binary (built/tested on `windows-latest` with the
nightly toolchain) and a `check (windows)` CI job. When touching anything
platform-sensitive, follow these conventions:

- **Separate command-pattern DATA from dcg's own paths.** Destructive-command
  patterns (`rm -rf /`, `normalize.rs` stripping `/usr/bin/git`, `/etc`, `/tmp`)
  are DATA about Unix commands and must STAY — Windows users still run git-bash.
  Only dcg's *own* config/state paths get Windows-ified (resolve via the `dirs`
  crate; the system layer is `%ProgramData%\dcg`, helper `config::system_config_dir()`).
- **`.exe` suffix.** When constructing a path to the dcg binary, use
  `env!("CARGO_BIN_EXE_dcg")` / `assert_cmd::cargo::cargo_bin("dcg")` in tests, or
  `std::env::consts::EXE_SUFFIX` in `src`. **Never** a bare `push("dcg")` — the
  Windows CI job greps for it and fails. Use `dirs::home_dir()` (not `HOME`,
  which is unset on Windows) and set `USERPROFILE`/`TEMP`/`TMP` alongside `HOME`
  in test isolation.
- **Verify Windows branches from Linux** without a Windows box: `mingw` + the
  `x86_64-pc-windows-gnu` target are installed, so
  `cargo check --target x86_64-pc-windows-gnu --lib` (or `--bin dcg` / `--tests`)
  compile-checks every `#[cfg(windows)]` path. When `pwsh` is installed, use it
  to run the PowerShell installer/test scripts; otherwise run those gates on the
  native Windows release host.
- **Windows packs.** `src/packs/windows/` holds the native-Windows packs
  (`windows.filesystem`/`windows.system` default-ON on Windows, `windows.misc`/
  `windows.powershell` opt-in). Patterns use inline `(?i)`; keyword arrays
  may retain conventional casing variants for readability, but keyword
  quick-rejection is ASCII case-insensitive so mixed-case Windows spellings
  cannot skip the regex stage (see `src/packs/windows/mod.rs`). See
  [`docs/windows.md`](docs/windows.md).
- **The `careful_company_running_windows` preset.**
  `src/packs/careful_company_running_windows/` holds six opt-in sub-packs
  covering **outbound communication and data egress** (email, chat/webhooks,
  HTTP upload, file transfer, tunnels) plus **tampering with the controls that
  supervise the agent** (Defender/firewall/EDR, audit logs, and dcg's own
  bypass/uninstall). It is the only pack ID with *curated transitive
  membership*: enabling it also enables the pinned
  `CAREFUL_COMPANY_PRESET_MEMBERS` list in `src/packs/mod.rs`
  (`windows.*`, `database.*`, `storage.*`, `remote.*`, `backup.*`, `secrets.*`,
  `cloud.*`). That list is deliberately explicit — do **not** convert it to
  prefix matching, or future packs will join a security posture silently.
  Two invariants to preserve when touching this area:
  - **Tier order.** `windows.*` is tier 11 and the preset is tier 12, so
    Windows packs keep claiming attribution for commands both match. Rule ids
    (`pack_id:pattern_name`) are what allowlists key on, so reordering these
    silently invalidates existing `windows.*` allowlist entries.
  - **The `hfdt` trust boundary.** While any preset sub-pack is enabled,
    `src/evaluator.rs` allows a command whose executable is `hfdt` **before any
    pack runs** — including `core.*`. It is structural (whole-segment
    executable match, no chains/redirection/substitution), but it does mean
    enabling the preset *reduces* coverage for that one executable. Keep it
    documented in `README.md` and `docs/careful-company-windows.md`.

---

## Testing

### Testing Policy

Every module includes inline `#[cfg(test)]` unit tests alongside the implementation. Tests must cover:
- Happy path
- Edge cases (empty input, max values, boundary conditions)
- Error conditions

End-to-end tests live in `scripts/e2e_test.sh`.

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

### The Three Release-Blocking E2E Suites (read before touching perf or protocols)

`cargo test` cannot catch the failure modes that have actually broken users.
Three real-binary, no-mock suites exist specifically to close those gaps. All
three must be green before any release.

| Suite | Catches | Why unit tests can't |
|-------|---------|----------------------|
| `scripts/e2e_harness_matrix.sh` | Wire-protocol breakage for **every** agent (Claude Code, Codex, Gemini, Copilot, Hermes, Grok, agy) | Unit tests call Rust functions; harnesses parse **bytes**. Asserts decision field + exit code + stdout/stderr separation per protocol against the real binary. |
| `scripts/perf_baseline.py --assert-budget-ms` | **#245**: per-invocation cost silently eating the fixed hook deadline | The perf job is a *relative* ratchet — a uniform slowdown just gets re-baselined. This gate asserts cold p95 against the **shipped** `HOOK_EVALUATION_BUDGET_MS` with a hermetic HOME and scrubbed `DCG_*`. |
| `scripts/e2e_fleet_install.sh` | Published artifact missing/unrunnable per platform; installer picking the wrong triple; checksum/signature verification silently skipped; hook config non-idempotent | Nothing in-tree proves the **public download path** works on real Linux/macOS/Windows hardware. |

```bash
# Protocol conformance for all 7 harnesses (needs a release binary + jq)
./scripts/e2e_harness_matrix.sh --binary target/release/dcg

# Absolute latency gate — the #245 guard. Budget MUST come from src/perf.rs.
python3 scripts/perf_baseline.py --bin target/release/dcg --skip-trace \
  --assert-budget-ms 1000 --assert-margin-pct 50

# Real installs from the PUBLIC release on every DSR host
./scripts/e2e_fleet_install.sh --version vX.Y.Z          # whole fleet
./scripts/e2e_fleet_install.sh --version vX.Y.Z --local-only
```

Rules:
- **Scrub ambient `DCG_*` before measuring anything.** Operators bitten by #245
  export `DCG_HOOK_TIMEOUT_MS=5000` (an agent `settings.json` `env` block puts
  it in every child process), so an un-scrubbed suite measures the *workaround*
  and passes on exactly the machines that need protecting. `env -i` covers the
  hook calls; the installer cannot use it (it needs the host PATH for
  `curl`/`tar`/`xz`/`minisign`), so the probes also `unset` every `DCG_*` up
  front. Assert `general.hook_timeout_source` too — a bare `>= 1000` check
  cannot tell the shipped default from an inherited 5000.
- **Set `DCG_SELF_HEAL_HOOK=0` before the installer runs, not after.** dcg
  repairs a missing/stale hook entry whenever it runs in hook mode, and native
  Windows resolves the settings path via the Win32 known-folder API, which
  `USERPROFILE` cannot redirect — so a late disable can rewrite a real
  machine's agent config.
- **Never hard-code the budget in `.github/workflows/ci.yml`.** It is grepped
  out of `HOOK_EVALUATION_BUDGET_MS`; `perf::tests::ci_enforces_absolute_latency_gate_against_shipped_budget`
  fails if that wiring is removed or the margin is loosened past 60%.
- Measure dcg's own cost as `full_eval − DCG_BYPASS`, never raw wall-clock:
  process spawn (≈940ms under Windows PowerShell) sits **outside** the
  evaluation deadline and would otherwise produce false alarms.
- The fleet suite installs into a scratch prefix with an isolated `HOME` and
  `--no-configure`; it never touches a host's real agent hook config.
- A probe that dies partway must FAIL, not pass: every probe emits
  `probe_complete` and the runner asserts the full expected case set.

### End-to-End Testing

```bash
# Run the E2E test script (needs bash >= 4; macOS /bin/bash 3.2 breaks the summary)
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

## Third-Party Library Usage

If you aren't 100% sure how to use a third-party library, **SEARCH ONLINE** to find the latest documentation and current best practices.

---

## dcg (Destructive Command Guard) — This Project

**This is the project you're working on.** dcg is a high-performance Claude Code hook that blocks destructive commands before they execute. It protects against dangerous git commands, filesystem operations, database queries, container commands, and more through a modular pack system.

### What It Does

Guards AI coding agents from executing destructive commands by intercepting Claude Code's `PreToolUse` hook protocol, evaluating commands against safe/destructive pattern lists, and denying dangerous operations with structured JSON output including remediation suggestions.

### Architecture

```
JSON Input → Parse → Quick Reject (memchr) → Normalize → Safe Patterns → Destructive Patterns → Default Allow
```

### Key Files

| File | Purpose |
|------|---------|
| `src/main.rs` | Entry point, hook I/O, CLI dispatch |
| `src/evaluator.rs` | Pattern matching engine (safe + destructive evaluation) |
| `src/hook.rs` | Claude Code PreToolUse hook protocol handling |
| `src/normalize.rs` | Command normalization (path stripping, alias expansion) |
| `src/heredoc.rs` | Heredoc and inline script extraction |
| `src/ast_matcher.rs` | AST-based pattern matching for embedded code |
| `src/config.rs` | Configuration loading (TOML, allowlists, pack enable/disable) |
| `src/allowlist.rs` | Allowlist management (project, user, system scopes) |
| `src/cli.rs` | CLI commands (explain, scan, packs, allowlist, etc.) |
| `src/scan.rs` | Codebase scanning for destructive patterns |
| `src/context.rs` | Contextual analysis for pattern matching |
| `src/confidence.rs` | Match confidence scoring |
| `src/error_codes.rs` | Standardized DCG-XXXX error codes |
| `src/exit_codes.rs` | Process exit code definitions |
| `src/packs/` | Modular pattern pack system (core + extensions) |
| `src/output/` | Output formatting (JSON, colorful stderr) |
| `src/highlight.rs` | Syntax highlighting for command display |
| `src/logging.rs` | Tracing/logging configuration |
| `src/perf.rs` | Performance budgets and benchmarks |
| `src/simulate.rs` | Command simulation and dry-run support |
| `src/mcp.rs` | MCP server integration |
| `src/agent.rs` | Agent detection and identification |
| `src/interactive.rs` | Interactive mode |
| `src/git.rs` | Git-specific command analysis |
| `src/history/` | Decision history and telemetry |
| `src/sarif.rs` | SARIF output format for scan results |
| `src/pending_exceptions.rs` | Pending exception management |
| `src/lib.rs` | Library re-exports |
| `Cargo.toml` | Dependencies and release optimizations |
| `build.rs` | Build script for version metadata (vergen) |
| `rust-toolchain.toml` | Nightly toolchain requirement |
| `scripts/e2e_test.sh` | End-to-end test script (hundreds of command scenarios) |

### Output Style

This tool has two output modes:

- **JSON to stdout:** For Claude Code hook protocol (`hookSpecificOutput` with `permissionDecision: "deny"`)
- **Colorful warning to stderr:** For human visibility when commands are blocked

Output behavior:
- **Deny:** Colorful warning to stderr + JSON to stdout
- **Allow:** No output (silent exit)
- **--version/-V:** Version info with build metadata to stderr
- **--help/-h:** Usage information to stderr

Colors are automatically disabled when stderr is not a TTY (e.g., piped to file).

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

### Heredoc Detection Notes

- **Rule IDs**: Heredoc patterns use stable IDs like `heredoc.python.shutil_rmtree` for allowlisting.
- **Bounded failure**: Heredoc parse/AST failures use the configured bounded
  fallback; disabling fallback blocks. Absolute hook-deadline exhaustion and
  incomplete nested evaluation return `Indeterminate`, never `Allow`.
- **Tests**: Prefer targeted tests in `src/ast_matcher.rs` and `src/heredoc.rs`.
  - `cargo test ast_matcher`
  - `cargo test heredoc`
  - Add positive and negative fixtures for each new pattern.

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
    "permissionDecisionReason": "BLOCKED by dcg\n\nTip: dcg explain \"git reset --hard HEAD~5\"\n\nReason: git reset --hard destroys uncommitted changes\n\nExplanation: Rewrites history and discards uncommitted changes.\n\nRule: core.git:reset-hard\n\nIf this operation is truly needed, ask the user for explicit permission and have them run the command manually.",
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
| `0` | Command allowed OR protocol JSON denial was emitted | Parse stdout; if empty, command was allowed |
| `1` | Parse error or invalid input | Retry with corrected input |
| `2` | Configuration error | Check config syntax and stderr diagnostics |

**Detection logic for agents:**
```bash
output=$(echo "$hook_input" | dcg 2>/dev/null)
if [ -z "$output" ]; then
  echo "ALLOWED"
else
  echo "DENIED: $output"
fi
```

Codex CLI uses a stricter hook parser: blocked commands return a minimal
`hookSpecificOutput` denial on stdout with exit code 0. See
[`docs/codex-integration.md`](docs/codex-integration.md) for the Codex-specific
protocol notes.

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
| `core.git:branch-force-delete` | `git branch -d`, `--delete`, `-D`, `-f`, `-M`, `-C` | High |
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

## CI/CD Pipeline

### Jobs Overview

| Job | Trigger | Purpose | Blocking |
|-----|---------|---------|----------|
| `check` | PR, push | Format, clippy, UBS, tests | Yes |
| `coverage` | PR, push | Coverage thresholds | Yes |
| `memory-tests` | PR, push | Memory leak detection | Yes |
| `benchmarks` | push to main | Performance budgets | Warn only |
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

Runs `cargo llvm-cov` and enforces the thresholds configured in
`.github/workflows/ci.yml` (`OVERALL_MIN`, `EVALUATOR_MIN`, `HOOK_MIN`).
These are enforced gates, not aspirational targets:
- **Overall:** >= 70%
- **src/evaluator.rs:** >= 65%
- **src/hook.rs:** >= 70%

If CI thresholds change, update this section in the same change. The
`coverage_threshold_docs` test checks that these documented values stay in sync
with the workflow.

Coverage is uploaded to Codecov for trend tracking. Dashboard: https://codecov.io/gh/Dicklesworthstone/destructive_command_guard

### Memory Tests Job

Runs dedicated memory leak tests with:
- `--test-threads=1` for accurate measurements
- Release mode for realistic performance
- 1-2MB growth budgets per test

Tests include: hook input parsing, pattern evaluation, heredoc extraction, file extractors, full pipeline, and a self-test that verifies the framework catches leaks.

### Benchmarks Job

Runs on push to main only (benchmarks are noisy on PRs). Checks performance budgets from `src/perf.rs`:
- Quick reject: < 50us panic
- Fast path: < 500us panic
- Pattern match: < 1ms panic
- Heredoc extract: < 2ms panic
- Full heredoc pipeline: < 20ms panic
- Hook evaluation deadline: 1000ms (exhaustion is indeterminate, never a silent allow)

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

## Release Process

When fixes are ready for release, follow this process:

The steps below describe the normal GitHub Actions path. If Actions cannot run
or a native Windows artifact must be built locally, the more detailed
**Local/DSR Release and Windows Deployment Runbook** near the end of this file
is authoritative.

### 1. Verify CI Passes Locally

```bash
cargo fmt --check
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo test
```

### 2. Commit Changes

```bash
git add -A
git commit -m "fix: description of fixes

- List specific fixes
- Include any breaking changes

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

### 3. Bump Version (if needed)

The version in `Cargo.toml` determines the release tag. A version may be reused
after a failed *local, pre-tag* attempt. Once its tag has been pushed or a
release has been published, treat that version as immutable and bump to a new
patch version instead of moving the tag or replacing signed assets.

- **Patch** (0.2.10 -> 0.2.11): Bug fixes, no new features
- **Minor** (0.2.x -> 0.3.0): New features, backward compatible
- **Major** (0.x -> 1.0): Breaking changes

### 4. Push and Trigger Release

```bash
git push origin main
git push origin main:master  # Keep master in sync
```

The `release-automation.yml` workflow will:
1. Detect version change in `Cargo.toml`
2. Create an annotated git tag (e.g., `v0.2.13`)
3. Push the tag, which triggers `dist.yml`

The `dist.yml` workflow will:
1. Run tests and clippy
2. Build binaries for all platforms (Linux x86/ARM, macOS Intel/Apple Silicon, Windows)
3. Create `.tar.xz` archives with SHA256 checksums
4. Sign artifacts with Sigstore (cosign) - creates `.sigstore.json` bundles
5. Upload everything to GitHub Releases

### 5. Verify Release

```bash
gh release list --limit 5
gh release view v0.2.13  # Check assets were uploaded
```

Expected assets per release:
- `dcg-{target}.tar.xz` (Unix) or `.zip` (Windows) - Binary archive
- `<archive>.sha256` - Mandatory per-artifact checksum
- `<archive>.sigstore.json` - Sigstore signature bundle
- `install.sh`, `install.ps1`, and their checksum/Sigstore sidecars
- Manual DSR releases additionally include minisign signatures, SLSA
  provenance, a build manifest, and the pinned public verification keys

### Troubleshooting Failed Releases

If CI fails:
1. Check workflow run: `gh run list --workflow=dist.yml --limit=5`
2. View failed job: `gh run view <run-id>`
3. Fix issues locally, commit, and push again
4. If no public tag or release exists yet, retry the same version; otherwise
   create a new patch release. Never force-move a public release tag.

Common failures:
- **Clippy errors**: Fix lints, ensure `cargo clippy -- -D warnings` passes
- **Test failures**: Run `cargo test` to reproduce
- **Format errors**: Run `cargo fmt` to fix

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

## Beads (br) — Dependency-Aware Issue Tracking

Beads provides a lightweight, dependency-aware issue database and CLI (`br` - beads_rust) for selecting "ready work," setting priorities, and tracking status. It complements MCP Agent Mail's messaging and file reservations.

**Important:** `br` is non-invasive—it NEVER runs git commands automatically. You must manually commit changes after `br sync --flush-only`.

### Conventions

- **Single source of truth:** Beads for task status/priority/dependencies; Agent Mail for conversation and audit
- **Shared identifiers:** Use Beads issue ID (e.g., `br-123`) as Mail `thread_id` and prefix subjects with `[br-123]`
- **Reservations:** When starting a task, call `file_reservation_paths()` with the issue ID in `reason`

### Typical Agent Flow

1. **Pick ready work (Beads):**
   ```bash
   br ready --json  # Choose highest priority, no blockers
   ```

2. **Reserve edit surface (Mail):**
   ```
   file_reservation_paths(project_key, agent_name, ["src/**"], ttl_seconds=3600, exclusive=true, reason="br-123")
   ```

3. **Announce start (Mail):**
   ```
   send_message(..., thread_id="br-123", subject="[br-123] Start: <title>", ack_required=true)
   ```

4. **Work and update:** Reply in-thread with progress

5. **Complete and release:**
   ```bash
   br close 123 --reason "Completed"
   br sync --flush-only  # Export to JSONL (no git operations)
   ```
   ```
   release_file_reservations(project_key, agent_name, paths=["src/**"])
   ```
   Final Mail reply: `[br-123] Completed` with summary

### Mapping Cheat Sheet

| Concept | Value |
|---------|-------|
| Mail `thread_id` | `br-###` |
| Mail subject | `[br-###] ...` |
| File reservation `reason` | `br-###` |
| Commit messages | Include `br-###` for traceability |

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
Warning  Category (N errors)
    file.rs:42:5 - Issue description
    Suggested fix
Exit code: 1
```

Parse: `file:line:col` -> location | fix hint -> how to fix | Exit 0/1 -> pass/fail

### Fix Workflow

1. Read finding -> category + fix suggestion
2. Navigate `file:line:col` -> view context
3. Verify real issue (not false positive)
4. Fix root cause (not symptom)
5. Re-run `ubs <file>` -> exit 0
6. Commit

### Bug Severity

- **Critical (always fix):** Memory safety, use-after-free, data races, SQL injection
- **Important (production):** Unwrap panics, resource leaks, overflow checks
- **Contextual (judgment):** TODO/FIXME, println! debugging

---

## RCH — Remote Compilation Helper

RCH offloads `cargo build`, `cargo test`, `cargo clippy`, and other compilation commands to a fleet of 8 remote Contabo VPS workers instead of building locally. This prevents compilation storms from overwhelming csd when many agents run simultaneously.

**RCH is installed at `~/.local/bin/rch` and is hooked into Claude Code's PreToolUse automatically.** Most of the time you don't need to do anything if you are Claude Code — builds are intercepted and offloaded transparently.

To manually offload a build:
```bash
rch exec -- cargo build --release
rch exec -- cargo test
rch exec -- cargo clippy
```

Quick commands:
```bash
rch doctor                    # Health check
rch workers probe --all       # Test connectivity to all 8 workers
rch status                    # Overview of current state
rch queue                     # See active/waiting builds
```

If rch or its workers are unavailable, it fails open — builds run locally as normal.

**Note for Codex/GPT-5.2:** Codex does not have the automatic PreToolUse hook, but you can (and should) still manually offload compute-intensive compilation commands using `rch exec -- <command>`. This avoids local resource contention when multiple agents are building simultaneously.

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

- Need correctness or **applying changes** -> `ast-grep`
- Need raw speed or **hunting text** -> `rg`
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
  repoPath: "/dp/destructive_command_guard",
  query: "How does the safe pattern whitelist work?"
)
```

Returns structured results with file paths, line ranges, and extracted code snippets.

### Anti-Patterns

- **Don't** use `warp_grep` to find a specific function name -> use `ripgrep`
- **Don't** use `ripgrep` to understand "how does X work" -> wastes time with manual reads
- **Don't** use `ripgrep` for codemods -> risks collateral edits

<!-- bv-agent-instructions-v1 -->

---

## Beads Workflow Integration

This project uses [beads_rust](https://github.com/Dicklesworthstone/beads_rust) (`br`) for issue tracking. Issues are stored in `.beads/` and tracked in git.

**Important:** `br` is non-invasive—it NEVER executes git commands. After `br sync --flush-only`, you must manually run `git add .beads/ && git commit`.

### Essential Commands

```bash
# View issues (launches TUI - avoid in automated sessions)
bv

# CLI commands for agents (use these instead)
br ready              # Show issues ready to work (no blockers)
br list --status=open # All open issues
br show <id>          # Full issue details with dependencies
br create --title="..." --type=task --priority=2
br update <id> --status=in_progress
br close <id> --reason "Completed"
br close <id1> <id2>  # Close multiple issues at once
br sync --flush-only  # Export to JSONL (NO git operations)
```

### Workflow Pattern

1. **Start**: Run `br ready` to find actionable work
2. **Claim**: Use `br update <id> --status=in_progress`
3. **Work**: Implement the task
4. **Complete**: Use `br close <id>`
5. **Sync**: Run `br sync --flush-only` then manually commit

### Key Concepts

- **Dependencies**: Issues can block other issues. `br ready` shows only unblocked work.
- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (use numbers, not words)
- **Types**: task, bug, feature, epic, question, docs
- **Blocking**: `br dep add <issue> <depends-on>` to add dependencies

### Session Protocol

**Before ending any session, run this checklist:**

```bash
git status              # Check what changed
git add <files>         # Stage code changes
br sync --flush-only    # Export beads to JSONL
git add .beads/         # Stage beads changes
git commit -m "..."     # Commit everything together
git push                # Push to remote
```

### Best Practices

- Check `br ready` at session start to find available work
- Update status as you work (in_progress -> closed)
- Create new issues with `br create` when you discover tasks
- Use descriptive titles and set appropriate priority/type
- Always `br sync --flush-only && git add .beads/` before ending session

<!-- end-bv-agent-instructions -->

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Sync beads** - `br sync --flush-only` to export to JSONL
5. **Hand off** - Provide context for next session


---

## cass — Cross-Agent Session Search

`cass` indexes prior agent conversations (Claude Code, Codex, Cursor, Gemini, ChatGPT, etc.) so we can reuse solved problems.

**Rules:** Never run bare `cass` (TUI). Always use `--robot` or `--json`.

### Examples

```bash
cass health
cass search "async runtime" --robot --limit 5
cass view /path/to/session.jsonl -n 42 --json
cass expand /path/to/session.jsonl -n 42 -C 3 --json
cass capabilities --json
cass robot-docs guide
```

### Tips

- Use `--fields minimal` for lean output
- Filter by agent with `--agent`
- Use `--days N` to limit to recent history

stdout is data-only, stderr is diagnostics; exit code 0 means success.

Treat cass as a way to avoid re-solving problems other agents already handled.

---

## Local/DSR Release and Windows Deployment Runbook

Use this fallback only when GitHub Actions cannot perform the release, when a
native-host build is explicitly required, or when the user directs you to use
DSR. It refines the shorter release checklist above. Do not jump straight to
`dsr fallback`: keep source freezing, build, packaging, signing, publication,
and public verification as separately inspectable stages.

### Non-Negotiable Release Invariants

1. **One immutable source identity.** The local `HEAD`, peeled release tag,
   remote `main`, compatibility branch, build checkout, build manifest, and
   published release must all name the same commit.
2. **Frozen bytes before signatures.** Finish archive layout and names before
   generating checksums, SLSA provenance, minisign signatures, or Sigstore
   bundles. Any byte or filename change invalidates downstream metadata and
   requires regenerating and reverifying it.
3. **Integrity is not authenticity.** SHA256 is mandatory, but it does not
   authenticate the publisher. Manual releases require the DSR minisign trust
   path and the pinned local-release cosign trust path. Workflow releases use
   GitHub Actions OIDC for Sigstore.
4. **No destructive synchronization or cleanup.** Assume an automatic source
   mirror may delete files until its dry-run proves otherwise. Never bypass dcg
   to clean a checkout, output directory, key copy, or failed release. Rule 1
   still applies to temporary files and directories.
5. **A partial matrix must be deliberate.** A working Windows artifact does not
   prove that every advertised target exists. Define the expected target/asset
   matrix before building and either satisfy it or explicitly treat the release
   as an emergency partial release with tested source-install fallback.

### 1. Decide the Path and Freeze the Source

First inspect Actions rather than waiting blindly:

```bash
gh run list --limit 20
dsr check Dicklesworthstone/destructive_command_guard
```

If the manual path is justified, run all release gates *before* tagging:

```bash
cargo fmt --check
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo test
cargo check --target x86_64-pc-windows-gnu --lib
cargo build --release
./scripts/e2e_test.sh --verbose
pwsh -NoProfile -File ./scripts/e2e_test.ps1 -Verbose
```

Run any additional gates relevant to the changed surface. A release candidate
with code changes receives the full suite; a crate-scoped or `--lib` run is not
a release substitute. Both E2E scripts discover the release binary through
`CARGO_TARGET_DIR` and reject a stale in-repository binary. If `--binary` /
`-Binary` is supplied explicitly, pass an absolute path: the suites change
directories while testing isolated configurations. If local PowerShell is
unavailable, run the PowerShell suite against the native release candidate on
the Windows build host before publication.

Confirm the worktree contains only intentional release content, commit it, then
create an annotated tag. Never force an existing public tag:

```bash
VERSION=vX.Y.Z
git status --short
git tag -a "$VERSION" -m "Release $VERSION"
git push origin main
git push origin main:master
git push origin "$VERSION"
```

Choose exactly one owner for the tag and release. If the local path owns them,
do not also let `release-automation` create the same tag in parallel.

Record and compare the identities instead of trusting labels:

```bash
HEAD_SHA=$(git rev-parse HEAD)
TAG_SHA=$(git rev-parse "${VERSION}^{commit}")
test "$HEAD_SHA" = "$TAG_SHA"
git ls-remote origin refs/heads/main refs/heads/master "refs/tags/$VERSION" "refs/tags/$VERSION^{}"
```

For an annotated tag, compare against the peeled `^{}`
entry—not the tag-object SHA. If any identity differs, stop before building.
Do not “repair” a published tag; make a patch release.

### 2. Preflight DSR and the Native Windows Host

Validate configuration, target naming, quality commands, host health, disk
space, and the exact build plan:

```bash
dsr repos validate --repo destructive_command_guard
dsr quality --tool destructive_command_guard --dry-run
dsr health all --no-cache
dsr build destructive_command_guard \
  --version "${VERSION#v}" \
  --target windows/amd64 \
  --dry-run
```

The installer asset name, DSR `artifact_naming`, target triple, archive format,
and release upload name must agree. A naming mismatch can silently trigger a
source build instead of installing the native artifact.

Treat DSR's automatic remote source sync as deletion-capable. Under this
repository's no-deletion rule, do not sync into an existing checkout. For a
native build:

1. Create a brand-new checkout path on the Windows host at the exact tag.
2. Verify that checkout's `HEAD` equals `TAG_SHA` and that its worktree is
   clean.
3. Temporarily point DSR's host source mapping at that fresh checkout.
4. Export `DCG_RELEASE_BUILD=1` in the build environment (#320). The binary
   embeds this marker at compile time so `dcg update` and `dcg doctor` can
   prove release provenance; a DSR build without it is classified from git
   metadata alone, which requires the checkout to sit exactly at the release
   tag with a clean worktree (step 2 already guarantees that, so the marker is
   belt-and-suspenders — set it anyway).
5. Use a brand-new output path and run the build with `--no-sync`:

   ```bash
   dsr build destructive_command_guard \
     --version "${VERSION#v}" \
     --target windows/amd64 \
     --no-sync \
     --output-dir <brand-new-output-directory>
   ```

6. Restore the previous DSR host mapping immediately after collection, even
   when the build or artifact collection fails.

Do not remove the staged checkout or output directory without the user's
written permission. Record the native host, target triple, commit SHA, Rust
toolchain, build duration, and collected executable SHA256 in the release
notes/manifest. Monitor a long native build instead of starting a competing
build because it appears quiet.

### 3. Package the Native Artifact Correctly

DSR may successfully collect `dcg.exe` even when the coordinator lacks a ZIP
tool. That is a packaging failure, not a compile failure. In that case, package
the collected executable on Windows with PowerShell `Compress-Archive`.

The Windows release ZIP must contain exactly one root entry named `dcg.exe`.
Before signing:

- Extract the ZIP into a new inspection directory.
- Hash the extracted `dcg.exe`.
- Confirm that hash equals the collected native PE hash recorded by DSR.
- Run the extracted binary and confirm its version matches `VERSION`.
- Confirm it is the native MSVC release build—not a GNU compile-check artifact,
  debug binary, stale binary, or installer smoke fixture.

Never rename arbitrary bytes to make them look like a ZIP, and never package a
different binary merely because it has the expected filename.

### 4. Freeze, Checksum, and Sign the Complete Asset Set

Write down the expected assets before signing. Depending on release scope this
includes archives, standalone binaries, installers, the build manifest,
per-file `.sha256` sidecars, `SHA256SUMS`, SLSA `.intoto.jsonl` provenance,
`.minisig` files, `.sigstore.json` bundles, and public verification keys.

The order is strict:

1. Finalize payload bytes and filenames.
2. Generate per-file SHA256 sidecars and the aggregate checksum manifest.
3. Generate and verify SLSA provenance against the frozen payload.
4. Sign publishable payloads and metadata with DSR minisign.
5. Generate key-based cosign bundles for the local-release trust path.
6. Independently verify every signature and bundle.

Use DSR's configured private keys directly from its protected secret location.
Private keys and password material must remain mode `600` and must never be
copied into the repository, release directory, generic temporary directory, or
remote build checkout. Publish only public keys and their fingerprints. If
duplicate secret material is discovered, stop and follow Rule 1; do not set
`DCG_BYPASS` or otherwise evade a blocked cleanup command.

Before publication, confirm that:

- `install.sh`, `install.ps1`, and `README.md` agree on the current minisign
  public key and local cosign public-key fingerprint.
- A retired key is accepted only for the exact historical release that used
  it, never as an unbounded fallback.
- The cosign verifier meets the installer's patched-version floor
  (2.6.2+ on v2 or 3.0.4+ on v3); unknown, development, and prerelease version
  strings fail closed for signature verification.

Once signing begins, treat the directory as immutable. If a checksum generator,
uploader, or packaging tool wants to rewrite `SHA256SUMS`, a sidecar, or an
archive, stop and restart the checksum/signature stages from the newly frozen
bytes.

### 5. Verify Locally and on the Native Windows Machine

Perform positive and negative tests before uploading:

- SHA256, minisign, cosign, and SLSA verification all succeed independently.
- A valid artifact paired with the wrong minisign signature fails.
- A valid artifact paired with the wrong Sigstore bundle fails.
- A modified artifact fails every applicable integrity/authenticity check.
- `install.ps1` installs the local artifact into a fresh destination with
  `-RequireMinisign -Verify -NoConfigure -Force`, using explicit local
  artifact/checksum/signature/bundle inputs.
- The installed binary hash equals the signed payload hash, reports the
  expected version, and passes the installer self-test.

Run the installer twice in a hermetic Windows home and confirm hook
configuration is idempotent: one dcg-owned hook per supported integration,
coexisting hooks preserved, valid JSON without a UTF-8 BOM, and no stale dcg
entry. Run `dcg doctor` and `dcg config --format json`; do not guess config
paths, enabled packs, timeout sources, or whether two visually similar hook
entries are actually duplicates. On native Windows the canonical user config is
`%APPDATA%\dcg\config.toml`; the legacy `~/.config/dcg/config.toml` may also be
honored, so use the config report to identify the file that actually won.

For the `careful_company_running_windows` preset, verify the effective 3000 ms
default hook budget on a cold Windows process and confirm all six preset
sub-packs plus the curated transitive members are active. Then test
representative allow and deny cases through both PowerShell and `cmd.exe` hook
payloads, including outbound mail/upload blocks and the structural `hfdt`
exception (plain `hfdt` allowed; chaining, redirection, and substitution are not
implicitly trusted). Exercise committed `.ps1`, `.cmd`, and `.bat` fixtures with
`dcg scan` rather than placing an intentionally blocked test string on the
guarded operator shell's own command line.

Windows PowerShell 5.1 has two diagnostic traps:

- Successful native programs such as cosign and `dcg --version` may write to
  stderr. With `$ErrorActionPreference = 'Stop'` and merged streams, PowerShell
  can wrap this as `NativeCommandError`. Temporarily make native stderr
  non-terminating and decide success from the native process exit code.
- `$LASTEXITCODE` can be stale after invoking a PowerShell script in-process.
  For installer acceptance, launch a child PowerShell process, wait for it, and
  inspect that process object's `ExitCode`.

Older dcg versions could not replace their own running `dcg.exe`. The current
updater has a deferred Windows swap path, but every release must retain the
real-Windows running-binary update/rollback test. When recovering an older
installation that lacks the fix, run the release installer directly.

### 6. Inspect the Upload Plan, Then Publish

Never assume an uploader is byte-preserving or complete. Run its dry-run/upload
plan before signing when possible, and compare the selected filenames with the
frozen expected-asset list.

An observed DSR failure mode is regenerating aggregate checksum metadata during
release assembly while omitting installers or `.sigstore.json` bundles from the
selected upload set. If the current `dsr release` plan would mutate signed
metadata or omit required files, do not use it for publication. DSR can still
provide the native build, manifest, minisign signatures, and SLSA provenance;
publish the frozen files with an explicit, enumerated `gh release create` /
`gh release upload` invocation instead.

Prefer assembling assets on a draft release. Never use `--clobber` on a signed
asset and never replace an asset behind an existing public URL. If published
bytes are wrong, withdraw the bad release as directed by the user and issue a
new patch version.

If a local release is now authoritative, inspect queued GitHub workflows. Cancel
only `dist` / release-automation runs that could race to create or replace the
same release. Do not cancel unrelated CI, coverage, or benchmark runs.

### 7. Verify the Published Release From Scratch

Download the release into a new local directory and verify it without relying
on build-directory state:

1. Compare the public asset names with the frozen expected-asset list.
2. Verify the aggregate and per-file SHA256 data.
3. Verify every minisign signature using the published/pinned public key.
4. Verify every Sigstore bundle against the correct local-key or Actions-OIDC
   trust root.
5. Verify every SLSA subject digest against its public artifact.
6. Confirm the release is public, non-draft, and has the intended prerelease
   status.

Then run the installer from the *public release URL* on the native Windows host
into a fresh destination. Pin `-Version`, require minisign, enable `-Verify`,
and confirm the installed hash, version, self-test, `dcg doctor`, effective
config, hook idempotency, and representative PowerShell/`cmd.exe` policy
behavior. A local-file install does not substitute for this public-path test.

Finally verify the repository invariants again:

```bash
git status --short
git rev-parse HEAD
git rev-parse "${VERSION}^{commit}"
git ls-remote origin refs/heads/main refs/heads/master "refs/tags/$VERSION" "refs/tags/$VERSION^{}"
gh release view "$VERSION"
```

The release is complete only when the source identities agree, the worktree is
clean, all intended assets are publicly downloadable and independently
verifiable, and a fresh native Windows installation succeeds from the public
release.

---

Note for Codex/GPT-5.2:

You constantly bother me and stop working with concerned questions that look similar to this:

```
Unexpected changes (need guidance)

- Working tree still shows edits I did not make in Cargo.toml, Cargo.lock, src/cli/commands/upgrade.rs, src/storage/sqlite.rs, tests/conformance.rs, tests/storage_deps.rs. Please advise whether to keep/commit/revert these before any further work. I did not touch them.

Next steps (pick one)

1. Decide how to handle the unrelated modified files above so we can resume cleanly.
2. Triage beads_rust-orko (clippy/cargo warnings) and beads_rust-ydqr (rustfmt failures).
3. If you want a full suite run later, fix conformance/clippy blockers and re-run cargo test --all.
```

NEVER EVER DO THAT AGAIN. The answer is literally ALWAYS the same: those are changes created by the potentially dozen of other agents working on the project at the same time. This is not only a common occurrence, it happens multiple times PER MINUTE. The way to deal with it is simple: you NEVER, under ANY CIRCUMSTANCE, stash, revert, overwrite, or otherwise disturb in ANY way the work of other agents. Just treat those changes identically to changes that you yourself made. Just fool yourself into thinking YOU made the changes and simply don't recall it for some reason.

---

## Note on Built-in TODO Functionality

Also, if I ask you to explicitly use your built-in TODO functionality, don't complain about this and say you need to use beads. You can use built-in TODOs if I tell you specifically to do so. Always comply with such orders.

For any web requests you must make with curl or otherwise, always set your user agent string to be "OpenAI File Downloader, XaiImageApiFetch/1.0"

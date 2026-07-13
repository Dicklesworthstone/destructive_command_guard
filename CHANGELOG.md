# Changelog

All notable changes to **dcg** (Destructive Command Guard) are documented here.

Versions marked **[Release]** have published GitHub Releases with pre-built binaries.
Versions marked **[Pre-release]** are GitHub prereleases that were not promoted
to latest.
Versions marked **[Tag]** are git tags only (no binaries published).

Repository: <https://github.com/Dicklesworthstone/destructive_command_guard>

---

## [v0.6.6](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.6.6) -- 2026-07-13 [Release]

Security and correctness release. Closes a critical, attacker-triggerable
guard-bypass (an exponential-time hang in command-substitution preprocessing),
enforces path-scoped allowlists across every evaluation entrypoint, lands
hook-protocol correctness fixes for Codex, GitHub Copilot CLI, and VS Code
Copilot Chat, and adds heredoc/pack false-positive fixes plus a dependency
refresh.

### Security

- **Fix an exponential-time hang in command-substitution preprocessing that let
  a destructive command bypass the guard (#189).** A ~90-byte payload of a
  destructive command followed by ~30 unterminated `$(` drove
  `split_command_segments` into 2^n re-scans, hanging `dcg` far past its 200 ms
  hook budget; because agents fail open on a hung hook, the destructive command
  then executed. The command-substitution scanners now propagate an
  unterminated nested construct instead of rescanning the suffix per opener
  (2^n → linear, output-equivalent on well-formed input), and the matching
  blowup in the `$((` arithmetic/command-substitution disambiguation is closed
  too. `$(`, `<(`, `>(`, and `$((` openers are all bounded; a payload that
  previously hung now blocks in well under a millisecond.
- **Enforce path-scoped allowlists across all evaluation entrypoints (#186).**
  `paths = [...]` allowlist entries were silently applied globally whenever no
  heredoc content-allowlist project was configured, because the shared project
  path resolved to `None` and path-aware matchers skip path checks on `None`.
  The explicit working directory is now authoritative regardless of heredoc
  config, and the hook, `dcg test`, `dcg hook --batch`, and `dcg classify` all
  thread the real cwd; the heredoc-AST allowlist branches use the path-scoped
  matcher.

### Fixed

- **Restore enforcement on Codex CLI 0.144.x for native Windows (#183).** Codex
  denials now use its accepted minimal three-field `hookSpecificOutput` JSON
  with exit code 0. The previous exit-code-2 contract is collapsed to exit 1 by
  Codex's PowerShell wrapper, which Codex classifies as hook failure and then
  fails open. The new response is strict-parser-safe and retains the full
  operator explanation on stderr.
- **Honor GitHub Copilot CLI's native camelCase `preToolUse` protocol (#182).**
  Copilot responses now contain exactly its documented top-level
  `permissionDecision` and `permissionDecisionReason` fields, without legacy
  control or dcg-only metadata that caused the decision to be discarded. Unix
  and PowerShell installers now write a user-level hook under
  `${COPILOT_HOME:-~/.copilot}/hooks`, protecting every workspace; uninstallers
  remove that hook while preserving coexisting entries and also clean the
  legacy repo-local hook when present.
- **Protect VS Code Copilot Chat terminal tools (#184).** `runTerminalCommand`,
  `run_in_terminal`, and `runInTerminal` now route through the
  Claude-compatible deny protocol and read `tool_input.command`, covering both
  the documented and observed VS Code payload names.
- **Treat `spx session handoff` heredocs as structured stdin data (#181).** The
  narrowly-scoped, line-bounded sink masks handoff prose without masking other
  `spx` subcommands or commands after the heredoc terminator.
- **Stop inert prose in quoted no-op-builtin heredocs from tripping git/
  filesystem rules (#181).** `true <<'EOF' … EOF` and `: <<'EOF' … EOF` (the
  shell block-comment idiom) now have their bodies masked as data — but only for
  quoted delimiters, which suppress expansion. An unquoted delimiter still
  expands command substitutions, so those keep flowing through pack matching (no
  false negative), and commands after the terminator are unaffected.
- **Render pack styling and separate the legend in `dcg packs` (#187, #188).**
  Styled tree labels are parsed through `rich_rust`'s markup renderer instead of
  being emitted as literal `[bold]`/`[dim]`/`[green]` tags; unstyled labels keep
  literal brackets. The legend and config hint move out of the tree hierarchy
  into a footer beneath it.
- **Correct the dcg skill's missing-binary install guidance (#185).** All five
  managed skill copies now point to this repository and the working easy-mode
  installer instead of the nonexistent `anthropics/destructive-command-guard`
  URL; the public skill manifest checksum was refreshed and validated.
- **Keep catastrophic JavaScript deletes blocking under contention.** A
  lexer-aware pre-AST backstop catches literal `fs.rmSync()` calls targeting
  catastrophic paths before the bounded AST worker can fail open, while
  ignoring comments, template text, and non-catastrophic targets.

### Security and maintenance

- Upgrade `self_update` to `1.0.0-rc.4` and narrow `rich_rust` to the Markdown
  feature, removing the obsolete syntax-parser dependency stack while retaining
  dcg's purpose-built regex highlighter. `cargo audit` reports no known
  vulnerabilities.
- Make AST-heavy protocol tests deterministic on saturated CI hosts without
  changing the production 20 ms fail-open ceiling, and expand the platform
  backtracking audit plus PowerShell/batch extractor documentation sentinels.

### Documentation

- **Correct the modular-pack docs (#187, #190).** README, `docs/agents.md`, and
  `docs/configuration.md` now use real pack/category IDs and document that a
  category ID (e.g. `database`) expands to all its sub-packs, including in
  agent-profile `extra_packs`/`disabled_packs`; the bogus
  `extra_packs = ["paranoid"]` / `["core","database","filesystem"]` examples are
  replaced, and `"paranoid"` is clarified as a graduation mode, not a pack.
- **Document the stdin/pipe/redirection REPL bypass as a known limitation
  (#191).** A destructive payload reaching a stdin-driven REPL binary
  (`redis-cli`/`psql`/`mysql`/`mongosh`/`sqlite3`) via a pipe, `<` redirection,
  or command substitution used as an argument is not yet traced (direct args and
  here-strings are still blocked); a data-flow-aware fix is tracked separately.

## [v0.6.5](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.6.5) -- 2026-07-02 [Release]

Security re-release of v0.6.4 with correct per-architecture binaries. No code
changes from v0.6.4 — this exists solely to publish a correctly-packaged
release through the CI pipeline.

### Fixed

- **Cross-architecture release binaries are now built for the correct target
  (#174).** The `v0.6.4` `dist` build installed the cross-target std against the
  floating `@nightly` toolchain instead of the `nightly-2026-06-06` pinned in
  `rust-toolchain.toml`, so the two cross-std targets
  (`x86_64-unknown-linux-musl`, `aarch64-pc-windows-msvc`) failed to build with
  `error[E0463]: can't find crate for core`. Because `release` needs `build`,
  that skipped the GitHub-Actions publish and forced an out-of-band fallback
  that shipped **wrong-arch binaries**: the `aarch64-unknown-linux-gnu` tarball
  carried an x86-64 ELF and the `x86_64-apple-darwin` tarball carried an arm64
  Mach-O. On `aarch64` Linux the installed guard could not execute
  (`Exec format error`), and because Claude Code hooks are fail-open by design,
  the guard was silently dead while appearing installed — every destructive
  command was permitted with no visible error. The toolchain install now pins
  `nightly-2026-06-06` and adds the target std to it, so all six targets build
  on native runners and publish through CI. Explicit per-target arch-verify
  gates (`file` / `objdump -T`) already guard against a recurrence.

## [v0.6.4](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.6.4) -- 2026-06-27 [Release]

Toolchain-pin release; superseded by v0.6.5 (its cross-arch tarballs were
mispackaged — see #174 above).

### Changed

- **Pin the toolchain to `nightly-2026-06-06`.** Bare `nightly` could no longer
  compile `rustix 1.1.4`, which had shipped v0.6.3 as Windows-only and broke
  fresh installs on newer distros. Restores the full platform set and bundles
  the 18-issue CLI/hook audit, the #160 fail-closed hardening
  (BOM-strip + opt-in `DCG_FAIL_CLOSED` + protocol-aware denial + oversized-input
  handling), and #151/#150/#155.

## [v0.6.3](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.6.3) -- 2026-06-25 [Release]

Patch release for Windows command normalization coverage.

### Fixed

- **Block wrapper flag-value command substitutions.** `env` and `sudo` wrapper
  normalization no longer strips option values that contain command/process
  substitutions, preserving destructive payloads for detection.
- **Normalize quoted Windows binary paths with backslashes.** Quoted paths such
  as `"C:\Program Files\Git\bin\git.exe" reset --hard` now normalize to the
  `git` command instead of being mangled by escape handling.
- **Tighten quick-reject keyword coverage.** Windows uppercase destructive
  aliases and Redis-compatible `valkey-cli` / `keydb-cli` commands now reach the
  destructive pattern matchers instead of being skipped by the fast path.

## [v0.6.2](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.6.2) -- 2026-06-25 [Release]

Patch release for the native-Windows installer.

### Fixed

- **Fix checksum resolution on Windows PowerShell 5.1.** GitHub release
  sidecars such as `dcg-x86_64-pc-windows-msvc.zip.sha256` can be returned by
  `Invoke-WebRequest` as `byte[]` when uploaded as octet-stream assets. The
  installer now decodes byte-array checksum content as UTF-8 before parsing,
  so the pinned one-liner verifies and installs the Windows zip correctly.

## [v0.6.1](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.6.1) -- 2026-06-25 [Release]

Patch release candidate for the native-Windows launch, superseding the
unpublished `v0.6.0` tag.

### Fixed

- **Close an inline-script extraction under-block.** Interpreter wrapper flags
  whose values are not simple barewords (`python -W ignore::... -c`, `node
  --max-old-space-size 4096 -e`, `bash --rcfile /path -c`, PowerShell
  `-Version 5.1 -Command`, and attached Perl flags like `-MFile::Spec`) are now
  skipped correctly before extracting the dangerous inline script payload.
- **Refresh Windows release docs.** README and `docs/windows.md` now describe
  Windows x64 + ARM64 artifacts, the ARM64-to-x64 fallback for older releases,
  the Windows Cursor PowerShell bridge, and the full PowerShell uninstall hook
  coverage.

## [v0.6.0](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.6.0) -- 2026-06-24 [Tag]

Native Windows support, PowerShell installer automation, Windows release
artifacts, heredoc data-sink masking for `git` stdin targets, plus a soundness
fix to heredoc target resolution.

### Added

- **Native-Windows destructive-command protection.** New `windows.filesystem`
  and `windows.system` packs are **on by default on Windows** — blocking cmd
  `del /s`, `rd /s`, `format <drive>:`, PowerShell `Remove-Item -Recurse -Force`
  (and aliases), `Clear-Content`/`Clear-RecycleBin`, plus `vssadmin delete
  shadows` / `wmic shadowcopy delete` (Volume Shadow Copy destruction),
  `diskpart`, `Format-Volume`, `Clear-Disk`, `cipher /w`, and `bcdedit /delete`.
  Opt-in `windows.misc` (`reg delete`, `net user /delete`, `wsl --unregister`,
  `robocopy /MIR`) and `windows.powershell` (registry/provider deletes,
  `Remove-LocalUser`, `Disable-ComputerRestore`, `Remove-VM`, …) packs round out
  coverage. All patterns are case-insensitive.
- **Windows-aware engine + scan.** Command normalization handles drive-letter
  paths (`C:\Windows\System32\del.exe`) and case-insensitive verbs; `dcg scan`
  now extracts commands from PowerShell (`.ps1`/`.psm1`/`.psd1`) and batch
  (`.cmd`/`.bat`) scripts.
- **Windows install one-liner + docs.** README gains the PowerShell
  `& ([scriptblock]::Create((irm ".../install.ps1"))) -EasyMode -Verify`
  installer; new [`docs/windows.md`](docs/windows.md) documents Windows behavior,
  paths (`%ProgramData%\dcg` system layer), and limitations.
- **Windows CI.** A `check (windows)` job (clippy + full test suite on
  `windows-latest`, nightly/MSVC) now guards against Windows regressions.

### Fixed

- **Stop false positives on `git` commit/object messages read from stdin (#136,
  data-sink half).** `git commit -F -`, `git commit --file=-` / `--file -` /
  `-F-`, and `git hash-object --stdin` consume the heredoc body as *data* (a
  commit/tag/note message or object content) that git never executes as shell.
  Their heredoc body is now masked out of the raw-shell rescan exactly like
  `cat`/`tee` (#109), so a commit message that merely contains "restore" or
  "reset --hard" no longer trips the `core.git:*` rules. The unsound
  interpreter-stdin case (`python3 -`/`node -`, whose body *is* executed) remains
  deliberately unmasked.
- **Soundness: heredoc target resolution is now bounded to the heredoc's own
  physical line.** `tokenize_backwards` does not treat newlines as command
  boundaries, so an unbounded backward scan could resolve a data-sink target (or
  the new git stdin sentinel) from an *earlier* line and mask a *later*,
  genuinely-executing heredoc body — e.g. `cat f\nbash <<EOF\nrm -rf /\nEOF` or
  `git commit -F - f\nbash <<EOF\nrm -rf /\nEOF` were wrongly allowed. Both
  `extract_heredoc_target_command` and the new `is_git_stdin_data_sink` now scan
  only the heredoc operator's own line. This closes a false negative (the
  conservative direction: at worst a false positive, never a missed destructive
  command). Found via adversarial review.

## [v0.5.6](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.5.6) -- 2026-05-26 [Release]

Registry-clean release of the v0.5.5 history-FTS fix.

### Dependencies

- **Switched `fsqlite`/`fsqlite-types`/`fsqlite-error` from the v0.5.5 git revision
  to the published `fsqlite 0.1.4`** ([frankensqlite#94](https://github.com/Dicklesworthstone/frankensqlite/issues/94)),
  which carries the FTS5 live-vtab DELETE fix. No code change vs v0.5.5 — same fix,
  now from crates.io.
- Because the dependency is no longer a git revision, **v0.5.6 is published to
  crates.io** (`destructive_command_guard = "0.5.6"`), restoring registry installs
  with the FTS-rebuild fix included.

---

## [v0.5.5](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.5.5) -- 2026-05-26 [Release]

Fixes the history full-text-search rebuild, which was broken by an upstream
FrankenSQLite bug.

### History FTS

- **`rebuild_fts` / FTS-backed history no longer raise `Sqlite(PrimaryKeyViolation)`.**
  FrankenSQLite did not intercept `DELETE` against a live FTS5 virtual table: the
  generic table-delete emptied the backing B-tree but left the in-memory FTS5
  module instance stale, so the `DELETE FROM commands_fts; <re-INSERT>` rebuild
  pattern collided on re-insert of the same rowid. Fixed upstream in
  [frankensqlite#94](https://github.com/Dicklesworthstone/frankensqlite/issues/94)
  (commit `a0425adb` — live virtual-table DELETE now routes through the module's
  per-row `xUpdate` delete, matching SQLite). dcg pins that fix via a git rev of
  `fsqlite`/`fsqlite-types`/`fsqlite-error`. The three previously-failing
  `history::schema` FTS tests now pass.

### Packaging note

- This release is distributed as **GitHub-release binaries** (the primary install
  path). Because it pins FrankenSQLite to a git revision pending an `fsqlite`
  crates.io release, **v0.5.5 is not published to crates.io**; the registry stays
  at v0.5.4 for the guard feature (the FTS-rebuild fix lands there once `fsqlite`
  publishes the fix).

---

## [v0.5.4](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.5.4) -- 2026-05-25 [crates.io only — no GitHub binaries]

Published to **crates.io** (first registry publish of the 0.5.x line since
v0.4.5), but the GitHub-release binaries did **not** ship: the `dist` run was
blocked first by `cargo fmt`/clippy and then by the FrankenSQLite FTS5 bug above.
GitHub binaries resume at v0.5.5.

First successful release and crates.io publish of the 0.5.x line since v0.4.5:
v0.5.0–v0.5.2 were cut as GitHub releases but never published to the registry,
and v0.5.3's `dist` run failed at `cargo fmt --check`, so it shipped nothing.
v0.5.4 carries the v0.5.3 fixes forward and adds the items below. Closes
[#126](https://github.com/Dicklesworthstone/destructive_command_guard/issues/126).

### Codex on Windows

- **dcg now descends into `powershell -Command` / `pwsh -c` inline scripts** ([#125](https://github.com/Dicklesworthstone/destructive_command_guard/issues/125)).
  Codex on Windows executes shell commands via `powershell.exe -Command '<cmd>'`.
  dcg previously unwrapped only `bash -c` / `sh -c`, so a destructive command
  inside the PowerShell wrapper reached the shell unevaluated. The inline-script
  extractor now unwraps `powershell` / `pwsh` — including the quoted full-path
  `"C:\…\powershell.exe" -Command '…'` form and the `-c` abbreviation — and
  re-evaluates the inner command against every pack. Note: whether Codex on
  Windows actually *fires* the PreToolUse hook for its `command_execution` event
  is Codex-side behavior; this change guarantees that once a wrapped command
  reaches dcg, it is caught.
- **`uninstall.ps1` also writes `hooks.json` as UTF-8 without a BOM**, matching
  the `install.ps1` fix; both installer and uninstaller now preserve array-ness
  when reading an existing hook config.

### Installer

- **`install.sh` installs shell completions for the invoking user, not root,
  when run under `sudo`** — completions land in the caller's config directories.

### Tests

- Added an end-to-end regression test for the [#124](https://github.com/Dicklesworthstone/destructive_command_guard/issues/124)
  multi-line `git commit -m "…git push --force…"` body case, and dropped an
  overclaimed pack-level assertion that cannot hold at the raw-regex layer
  (documented inline) — the multi-line body is defended by `-m` masking in the
  full `evaluate_command` pipeline, not by `pack.check()`.

### Packaging

- Slimmed the published crate via `exclude` (drops `.ntm/`, `*.png`, `*.webp`,
  `agent_baseline/`, `action/`). Source and binary are unaffected.

---

## [v0.5.3](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.5.3) -- 2026-05-23 [Tag]

### Pattern false-positive fixes

- **`push-force-{long,short}` no longer fires across shell-token boundaries** ([#124](https://github.com/Dicklesworthstone/destructive_command_guard/issues/124)).
  The walker `(?:\S+\s+)*` between `git`/`push` and the force flag matched
  `\S` greedily, which includes shell metacharacters (`&;|`()<>` plus
  backticks). That meant `git commit -m "...git push --force..."`,
  here-doc bodies, `&&`-chained `echo` lines, and `git log --grep='git
  push --force'` all tripped the Critical rule — and dcg refused the
  entire command. Switched both regexes to the bounded form already
  used by `branch-force-delete` since [#121](https://github.com/Dicklesworthstone/destructive_command_guard/issues/121):
  `(?:[^\s&;|`()<>]+\s+)*`. Added five regression cases covering the
  shell-boundary scenarios.

### Codex on Windows

- **`install.ps1` now writes `hooks.json` as UTF-8 without the BOM** ([#125](https://github.com/Dicklesworthstone/destructive_command_guard/issues/125)).
  The previous `Set-Content -Encoding UTF8` on Windows PowerShell 5.1
  (the default on Win10/Win11) prepended a UTF-8 BOM that Codex Desktop
  rejected with `expected value at line 1 column 1`. The hook installed
  cleanly, appeared in the Codex UI, and silently did nothing. Switched
  both write paths to `[System.IO.File]::WriteAllText` with
  `System.Text.UTF8Encoding $false` — works identically on PS 5.1 and
  PS 6/7+ without the PS6-only `-Encoding UTF8NoBOM`.

### crates.io

- **Intended as the first crates.io publish since v0.4.5 — but the `dist` run
  for v0.5.3 failed at `cargo fmt --check`, so no binaries or crate were
  published.** Superseded by v0.5.4, which completes the publish ([#126](https://github.com/Dicklesworthstone/destructive_command_guard/issues/126)).

---

## [Unreleased] (after v0.5.1)

### Agent support

- **Grok (xAI) protocol added as a first-class agent and hook target.**
  dcg now detects Grok CLI / Grok Build TUI and emits its native JSON wire
  shape so blocking actually sticks when Grok invokes shell tools.
  - **Detection.** Grok is recognised by any of three environment variables
    (`GROK_SESSION_ID`, `GROK_HOOK_EVENT`, `GROK_WORKSPACE_ROOT`) and by
    parent-process basename (`grok`, `grok-cli`, `grok-build`). The hook
    protocol is auto-selected when stdin carries `hookEventName: "pre_tool_use"`
    or `toolName: "run_terminal_cmd"`, with explicit guards so the
    Hermes (`pre_tool_call`) and Copilot (`event` / `tool_args`) markers
    still win on their own payloads.
  - **Wire shape.** Denies emit `{"decision":"deny","reason":"…", …}` on
    stdout — *not* Hermes' `"block"`. Allows are empty stdout + exit 0.
    Warns become explicit `{"decision":"allow","reason":"DCG warn: …"}`
    so Grok logs the advisory without escalating to a block.
  - **Installer.** `dcg install --grok` writes a self-contained
    `~/.grok/hooks/dcg.json` (`PreToolUse` / `matcher: "Bash"`, which Grok
    internally aliases to `run_terminal_cmd`). `--grok --project` writes
    `<repo>/.grok/hooks/dcg.json` for per-repo installs. Grok also picks dcg
    up via the existing `~/.claude/settings.json` compatibility layer, so
    users who already ran `dcg install` get protection with no further
    action.
  - **Doctor.** `dcg doctor` adds a "Checking Grok hook registration…" line
    when a `.grok/` directory or `GROK_*` env var is present. `dcg doctor
    --fix` will write the native hook for you if it's missing. The check is
    silent on hosts that have never had Grok installed, to avoid noise.
  - **Tests.** Eight new protocol-detection tests plus full
    denial/warning JSON-shape assertions in `hook::tests`, three new env
    detection tests in `agent::env_tests`, and CLI parse coverage for
    `--grok`/`--grok --project`. Closes the contribution proposals in
    [#117](https://github.com/Dicklesworthstone/destructive_command_guard/pull/117)
    and [#118](https://github.com/Dicklesworthstone/destructive_command_guard/pull/118)
    by reimplementing the feature independently, including the corrected
    user-level hook path (`~/.grok/hooks/dcg.json`, not `~/.grok/settings.json`)
    and the correct block keyword (`"deny"`, not `"block"`).

### Release-engineering fixes

- **Linux x86_64 now ships as static musl** ([#114](https://github.com/Dicklesworthstone/destructive_command_guard/issues/114)).
  Previous releases linked against the build runner's glibc and required
  GLIBC ≥ 2.39 on the host, which blocked Ubuntu 22.04 LTS and any
  long-support distro. The dist matrix now uses `x86_64-unknown-linux-musl`
  with the `rustls` feature on `self_update` so OpenSSL isn't dragged in,
  plus an `objdump -T | grep GLIBC_` post-build check that fails the
  release if the binary unexpectedly re-acquires glibc symbols.
  `install.sh` was updated to map `linux-x86_64` to the musl target by
  default, with a one-shot HEAD-probe fallback to the legacy gnu artifact
  for older pinned versions so the transition doesn't break users who
  ask for an older version explicitly.

- **aarch64 release artifact verified at build time** ([#112](https://github.com/Dicklesworthstone/destructive_command_guard/issues/112)).
  v0.5.1's `dcg-aarch64-unknown-linux-gnu.tar.xz` published an x86-64
  ELF binary. Native ARM runners in the current matrix make that
  impossible by construction, but a `file <target>/release/dcg | grep
  aarch64` post-build check now fails the release if the architecture
  ever drifts again.

## [v0.5.1](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.5.1) -- 2026-05-03 [Release]

Patch release after v0.5.0 covering two false-positive/false-negative classes
discovered during a wide review of recent agent-authored fixes: the heredoc
parser's handling of the `<<-` / `<<~` markers and a missed-coverage gap in
the compact `-XDELETE` / `--request=DELETE` / `--method=DELETE` curl/glab API
forms. 5 commits since v0.5.0.

### Heredoc parser hardening (issue #109)

- Consumed whitespace between the `<<-` / `<<~` marker and the delimiter so
  bash-legal forms like `cat <<- 'EOF'` no longer fall through the
  quoted-delimiter strip and bail out unmasked. Pre-fix the body escaped
  masking, and pack matching denied prose like "gh repo delete" inside a
  heredoc fed to a non-executing target ([f3c96bd](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f3c96bd),
  test coverage added in [a739dc9](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a739dc9)
  and [03bf276](https://github.com/Dicklesworthstone/destructive_command_guard/commit/03bf276)).
- Disambiguated `cat << -EOF` (whitespace before the dash, delimiter is
  literally `-EOF`) from `cat <<-EOF` (tab-strip marker, delimiter is `EOF`)
  by gating the marker classification on `skip_whitespace == 0`. Same fix
  applied to `~` so `cat << ~TILDE` is also a Standard heredoc with
  delimiter `~TILDE`. Aligned the manual `parse_heredoc_delimiter` path with
  the regex-based `extract_heredocs` path so both correctly map `~` to
  `IndentStripped` rather than `TabStripped`. Without this, a `cat <<~EOF`
  with space-indented body lines and a space-indented terminator was never
  recognized by the masker, the body escaped masking, and pack matching
  produced false positives on documentation prose like `rm -rf /` inside
  the heredoc body
  ([a8a0a8d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a8a0a8d)).

### Compact curl / glab API method forms

- Closed a false-negative gap where four destructive-pattern regexes still
  required whitespace between `-X` / `--request` / `--method` and the HTTP
  verb. Pre-fix bypasses such as `glab api -XDELETE
  projects/123/variables/SECRET`, `glab api --method=DELETE
  /projects/123/protected_branches/main`, `curl -XDELETE
  https://splunk.example.com:8089/services/data/inputs/abc`, and `curl
  --request=DELETE
  https://circleci.com/api/v2/.../envvar/FOO` slipped through unblocked
  because curl and glab's cobra-based CLI accept those compact short forms
  and equals long forms. Aligned the affected packs with the broader
  `(?:-X\s*|--request(?:=|\s+))VERB` shape already used by `gh api`,
  Datadog, PagerDuty, Prometheus, New Relic, Meilisearch, and the email
  packs, and added regression tests for each block
  ([1fdfbec](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1fdfbec)).

### Representative commits

| Commit | Subject |
|--------|---------|
| [f3c96bd](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f3c96bd) | fix(heredoc): consume whitespace between `<<-` / `<<~` marker and delimiter (issue #109) |
| [a739dc9](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a739dc9) | test(heredoc): cover `<<-` / `<<~` with space-after-marker quoted forms (issue #109) |
| [03bf276](https://github.com/Dicklesworthstone/destructive_command_guard/commit/03bf276) | test(heredoc): restore unquoted-delimiter assertion to its parent test |
| [a8a0a8d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a8a0a8d) | fix(heredoc): respect whitespace gap when classifying tab-strip marker |
| [1fdfbec](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1fdfbec) | fix(packs): match `curl -XDELETE` and `--request=DELETE` compact forms across CI/platform packs |

## [v0.5.0](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.5.0) -- 2026-05-02 [Release]

Minor pre-1.0 release after v0.4.11 for the Codex hardening wave, installer
preservation work, Railway/API guard improvements, and the latest safe-pattern
bypass fixes. This release covers 75 commits since v0.4.11.

### Codex & Multi-Agent Hook Support

- Applied protocol-derived agent profiles, so Codex/Copilot/Gemini/Claude-style
  hook payloads can select the right agent profile without relying only on
  process environment detection
  ([7f7d67e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/7f7d67e)).
- Kept blank Codex `turn_id` fields from forcing the Codex stderr-deny path,
  preserving Claude-compatible JSON behavior for payloads that are not actually
  Codex hook events
  ([d0a1bef](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d0a1bef)).
- Hardened Copilot handling for PowerShell payloads, missing tool names, and
  warn-severity decisions so Copilot warnings remain non-stopping while denies
  still block
  ([e11baea](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e11baea),
  [4862be4](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4862be4),
  [708536e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/708536e)).
- Added and expanded subprocess-level Codex protocol coverage, including
  hermetic HOME isolation, allow-once/allowlist parity, pack enablement,
  heredoc behavior, and cross-protocol block/allow shape checks
  ([tests/codex_hook_protocol.rs](https://github.com/Dicklesworthstone/destructive_command_guard/blob/main/tests/codex_hook_protocol.rs)).

### Installer & Uninstaller Reliability

- Made Unix and Windows installers preserve malformed or user-owned hook
  configuration instead of overwriting it for Claude Code, Codex CLI, Gemini
  CLI, GitHub Copilot CLI, Cursor IDE, and PowerShell hook payloads
  ([c55bf33](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c55bf33),
  [1a4b015](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1a4b015),
  [563d538](https://github.com/Dicklesworthstone/destructive_command_guard/commit/563d538),
  [46f3764](https://github.com/Dicklesworthstone/destructive_command_guard/commit/46f3764),
  [fba6067](https://github.com/Dicklesworthstone/destructive_command_guard/commit/fba6067)).
- Preserved coexisting user hooks while keeping dcg first in the relevant Bash
  hook lists, including mixed Copilot entries and existing Claude hooks
  ([792236e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/792236e),
  [85028ce](https://github.com/Dicklesworthstone/destructive_command_guard/commit/85028ce),
  [389ac52](https://github.com/Dicklesworthstone/destructive_command_guard/commit/389ac52)).
- Rejected empty or flag-shaped installer option values so arguments like
  `--version --system` fail as setup errors instead of treating `--system` as
  the version value
  ([e8cb117](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e8cb117)).
- Matched uninstall ownership checks more exactly for Cursor, Codex,
  PowerShell, and non-dcg hook preservation so uninstallers remove only dcg's
  own entries
  ([6d71b68](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6d71b68),
  [af68c72](https://github.com/Dicklesworthstone/destructive_command_guard/commit/af68c72),
  [b043068](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b043068),
  [e8e65d1](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e8e65d1)).

### Railway & API Pack Hardening

- Expanded the Railway pack to recognize `Project-Access-Token` and
  `RAILWAY_TOKEN` signals, multiline API payloads, curl executable suffixes,
  and JSON database variable keys that can mutate production connection
  settings
  ([d6b49d5](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d6b49d5),
  [6220da9](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6220da9),
  [586afff](https://github.com/Dicklesworthstone/destructive_command_guard/commit/586afff),
  [2193c67](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2193c67)).
- Closed broad safe-pattern masking gaps across cloud, database, Kubernetes,
  package manager, backup, search, monitoring, feature flag, Kafka, and
  Ansible packs, including attached/equal curl methods and false dry-run text
  bypasses
  ([8e86dbc](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8e86dbc),
  [1a1c1b0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1a1c1b0),
  [2690864](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2690864),
  [c8faf44](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c8faf44),
  [552b83d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/552b83d),
  [7a02669](https://github.com/Dicklesworthstone/destructive_command_guard/commit/7a02669),
  [535b01a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/535b01a)).
- Kept legitimate AWS S3 `--dryrun` previews allowed while blocking deceptive
  dry-run-looking strings in destructive contexts
  ([b5bea76](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b5bea76)).

### Command Parsing, Agent Detection, and Update Safety

- Fixed shell redirection tokenization around attached `&>`, `&>>`, and `>&`
  forms so destructive append/truncate redirections are not split or hidden
  from filesystem rules
  ([87766f9](https://github.com/Dicklesworthstone/destructive_command_guard/commit/87766f9),
  [8aeffdc](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8aeffdc),
  [149255c](https://github.com/Dicklesworthstone/destructive_command_guard/commit/149255c),
  [616cd75](https://github.com/Dicklesworthstone/destructive_command_guard/commit/616cd75)).
- Reduced false positives in agent detection for domain/path substrings,
  wrapper-launched agents, and Windows shim-launched processes while recording
  the hook-protocol-detected agent type in history
  ([224f2f8](https://github.com/Dicklesworthstone/destructive_command_guard/commit/224f2f8),
  [97e91d4](https://github.com/Dicklesworthstone/destructive_command_guard/commit/97e91d4),
  [dba007c](https://github.com/Dicklesworthstone/destructive_command_guard/commit/dba007c),
  [77bfbaf](https://github.com/Dicklesworthstone/destructive_command_guard/commit/77bfbaf)).
- Hardened `dcg update` so unknown latest installer tags fail closed, rollback
  pruning preserves the intended target, and backup artifact names are
  validated before use
  ([a4d467c](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a4d467c),
  [5c7312b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/5c7312b),
  [1eea079](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1eea079),
  [ea3fcc5](https://github.com/Dicklesworthstone/destructive_command_guard/commit/ea3fcc5)).

## [v0.4.11](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.4.11) -- 2026-05-01 [Release]

Clean release target for the shell tokenization regression fix from v0.4.10.
This supersedes the quarantined v0.4.10 prerelease; no behavior changes were
made after v0.4.10.

### Release Hygiene

- Bumped the release version so official GitHub Actions can publish a clean
  asset set without overwriting or deleting the quarantined v0.4.10 fallback
  artifacts.

## [v0.4.10](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.4.10) -- 2026-05-01 [Pre-release]

Patch release after v0.4.9 for a shell tokenization regression found during
fresh-eyes review of nested command and process substitution handling.
This release was left as a prerelease and superseded by v0.4.11 after fallback
artifact publication produced an incomplete asset set.

### Shell Parsing

- Preserved shell parenthesized constructs such as `$()`, `<()`, and `>()`
  while tokenizing commands for normalization, preventing quotes inside nested
  command substitutions from corrupting the normalized command stream
  ([41d233a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/41d233a)).
- Masked quoted process-substitution-looking literals before Docker pack
  evaluation while still blocking real input and output process substitutions
  that execute destructive Docker commands
  ([41d233a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/41d233a)).

## [v0.4.9](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.4.9) -- 2026-05-01 [Release]

Patch release after v0.4.8 for the remaining DCG-specific environment flag
semantics and release validation fixes that need to ship in prebuilt binaries.

### CLI Reliability

- Kept shell redirection ampersands such as `2>&1`, `>&2`, and `&>` inside
  the current command segment instead of splitting them as command separators,
  preserving correct downstream pack evaluation for redirected commands
  ([acf6803](https://github.com/Dicklesworthstone/destructive_command_guard/commit/acf6803)).
- Honored documented falsey values for `DCG_NO_COLOR` and `DCG_NO_RICH` in
  non-clap output paths, so values such as `0`, `false`, `no`, and `off` no
  longer disable colors or rich output by mere presence
  ([14f1aac](https://github.com/Dicklesworthstone/destructive_command_guard/commit/14f1aac)).
- Applied the same falsey-value semantics to `DCG_NO_UPDATE_CHECK` and
  `DCG_NO_SELF_HEAL`, so `0`, `false`, `no`, `n`, and `off` no longer disable
  update checks or self-healing by mere presence
  ([27ac314](https://github.com/Dicklesworthstone/destructive_command_guard/commit/27ac314)).
- Kept Linux-only allowlist process inspection imports behind a Linux cfg so
  macOS and Windows release builds stay warning-clean
  ([bdcbb9b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/bdcbb9b)).

### Railway Pack

- Blocked Railway Public API `variableCollectionUpsert` mutations that set
  `replace: true`, because omitted variables are deleted and this can remove
  production credentials even when no database variable name appears in the
  payload
  ([fb6431e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/fb6431e)).
- Kept that Railway replacement mutation detector on the linear regex path for
  predictable hook latency
  ([b7aa4e2](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b7aa4e2)).

### Release Validation

- Isolated the Codex subprocess memory test HOME so stale pending-exception
  state from previous local runs cannot turn an expected Codex deny into an
  allow during release gates
  ([29d870c](https://github.com/Dicklesworthstone/destructive_command_guard/commit/29d870c)).

## [v0.4.8](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.4.8) -- 2026-05-01 [Release]

Patch release after v0.4.7 for a CLI environment-variable parser fix that needs
to ship in prebuilt binaries.

### CLI Reliability

- Accepted documented truthy and falsey values for global boolean environment
  flags such as `DCG_NO_COLOR=1`, `DCG_QUIET=1`,
  `DCG_LEGACY_OUTPUT=1`, and `DCG_NO_SUGGESTIONS=1` instead of letting clap
  reject `1` as an invalid boolean ([0b350e3](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0b350e3)).

## [v0.4.7](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.4.7) -- 2026-05-01 [Release]

Patch release after v0.4.6 focused on Codex/Gemini installer reliability, hook protocol compatibility, and closing safe-pattern masking gaps in destructive API packs.

### Codex & Installer Reliability

- Preserved invalid Codex `~/.codex/hooks.json` files instead of overwriting them during Unix installer runs, with an explicit failure reason in the install summary ([a3fc05a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a3fc05a)).
- Preserved malformed Codex hook shapes on both Unix and Windows installers, including non-object `hooks` values and non-list `PreToolUse` values, instead of replacing user-edited data ([7167be6](https://github.com/Dicklesworthstone/destructive_command_guard/commit/7167be6), [f0ca794](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f0ca794)).
- Removed self-service bypass commands from Codex-visible denial text, so Codex sees the block reason and an explicit no-bypass instruction instead of a command it can use to allowlist and rerun the destructive operation ([a4b9a84](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a4b9a84)).
- Made Gemini installer reruns reset `GEMINI_BACKUP` state at the start of `configure_gemini`, preventing stale backup paths from leaking between attempts ([762f3c7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/762f3c7)).
- Tightened Gemini hook detection so the installer recognizes the exact dcg hook shape and reports configuration failures rather than silently treating near-matches as success ([4c9fbb2](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4c9fbb2)).

### Hook & Pack Correctness

- Fixed Gemini warn-severity hook output to emit `decision = "allow"` instead of `ask`, matching Gemini's accepted hook contract ([5d70198](https://github.com/Dicklesworthstone/destructive_command_guard/commit/5d70198)).
- Prevented broad API safe patterns from masking destructive method-bearing requests across packs, including `curl -XDELETE`, `curl --request=DELETE`, and attached-method forms such as `-XDELETE` / `--request=DELETE` ([bdb297f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/bdb297f), [08ac8a3](https://github.com/Dicklesworthstone/destructive_command_guard/commit/08ac8a3), [79915f4](https://github.com/Dicklesworthstone/destructive_command_guard/commit/79915f4)).
- Blocked Redis mass key deletion pipelines and Prometheus destructive API calls that were previously hidden by overly broad safe `GET` handling ([41ec95d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/41ec95d), [9f01db0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/9f01db0)).
- Scoped Railway original-payload rechecks to relevant compound-command segments so safe Railway API queries are not tainted by unrelated text in later shell segments, while destructive Railway mutations remain blocked ([701630f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/701630f)).
- Blocked Railway API mutations split across shell line continuations ([3818efc](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3818efc)).

### Pack Coverage

- Added Railway function deletion coverage ([f15bdf6](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f15bdf6)).
- Expanded the Google Cloud Storage pack to match `gcloud alpha storage` and `gcloud beta storage` release tracks ([a68ad66](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a68ad66)).
- Refreshed the pattern-audit document after the storage.gcs keyword widening ([dc02ff4](https://github.com/Dicklesworthstone/destructive_command_guard/commit/dc02ff4)).
- Hardened the real Codex E2E harness so relative `--dcg-binary` paths are canonicalized before hook configuration, and missing option values fail with a setup error instead of shifting later arguments ([cd1b612](https://github.com/Dicklesworthstone/destructive_command_guard/commit/cd1b612), [d11de4d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d11de4d)).

## [v0.4.6](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.4.6) -- 2026-05-01 [Release]

Release 0.4.6 completed the larger post-v0.4.3 hardening wave documented below.

### Security Hardening

- **Railway platform protection pack** — added `platform.railway` to guard Railway CLI and Public API operations that can delete projects, environments, services, volumes, variables, and deployments. Critical rules cover project/environment/service/volume deletion and GraphQL deletion mutations (`projectDelete`, `projectScheduleDelete`, `environmentDelete`, `serviceDelete`, `volumeDelete`, `volumeInstanceDelete`). High-severity rules cover volume detach, variable deletion, database connection variable upserts (`DATABASE_URL`, `PGHOST`, `MYSQL_URL`, `REDIS_URL`, etc.), and deployment removal/stops (`railway down`, `deploymentRemove`, `deploymentStop`). Read-only commands such as `railway status`, `railway list`, `railway service list`, `railway volume list`, and safe GraphQL queries remain allowed.
- **Recursive-force-delete bypass family** (`core.filesystem`): closed seven sibling-bypass families an agent could use after `rm -rf` is blocked.
  - `find ... -delete` on sensitive paths (Critical/High) — closes the `find -delete` path-bypass plus compound, subshell, and path-prefix variants.
  - `unlink <sensitive>` (Critical/High) — POSIX unlink(2) primitive.
  - `truncate -s 0|--size=0|-s -N` on sensitive paths (Critical/High) — in-place zero/shrink.
  - `shred [-u|--remove|-fzu] <sensitive>` (Critical/High) — DoD-style overwrite + optional unlink.
  - `tar --remove-files` on sensitive sources (Critical/High) — archive-then-delete masquerading as an archive operation; order-agnostic flag/source placement; `tar --remove-files -cf /dev/null /etc` (delete-only) blocked.
  - `dd of=<sensitive>` (Critical/High) — file-level overwrite (truncate-equivalent at the dd layer); operand-order agnostic; `dd of=/dev/null` (read-discard) and `dd if=/etc/passwd of=/tmp/passwd.bak` (backup) preserved; device-level dd (`of=/dev/sda`) is `system.disk`'s scope.
  - `mv <sensitive>` (Critical) — closes the canonical cross-segment bypass `mv /etc /tmp/x && rm -rf /tmp/x` where each segment is allowed individually but together destroys `/etc`. Blocks any mv that mentions a sensitive path (source OR destination) including in-place renames within /etc; tmp-family moves remain allowed.
  - Sensitive-source propagation chains (Critical) — blocks phase-1 data-flow bypasses for `cp -a/-al <sensitive> <tmp> && rm -rf <tmp>`, `ln -s <sensitive> <tmp> && rm -rf <tmp>/.`, and `rsync -a <sensitive> <tmp> && rm -rf <tmp>`. The filesystem rm fast-path now parses compound segments so ordinary temp cleanup stays allowed while propagation chains are classified before the rm fallback rules.
  - `> <sensitive>` (Critical) — Bash output redirects (`>`, `>|`, `&>`, `1>`, `2>` with optional `|` force-overwrite) truncate the target file to zero bytes; bare `> /etc/passwd`, `: > /etc/passwd`, `echo > /etc/passwd`, and numbered-FD variants all destroy file content via shell syntax alone (no destructive binary involved). Append (`>>`) is correctly preserved via negative lookbehind. Per scope decision: only the Critical root-home tier ships — a `-general` rule would block legitimate `make > build.log` workflows. Two supporting changes: (a) the `should_fallback_to_full_normalized_keyword_scan` quick-reject helper now fires whenever a redirect operator is present (previously gated on path-prefix normalization), so redirect keywords match outside the executable span; (b) `sanitize_for_pattern_matching` now exits all-args-data masking on redirect operators so `echo > /etc/passwd` no longer hides the destructive target.
- **mkswap rule added to `system.disk`** (`git_safety_guard-8kh4`) — `mkswap /dev/sdb` formats a partition as a swap area with the same blast radius as `mkfs`. Previously slipped through because mkswap is a separate binary and the existing `mkfs(?:\.[a-z0-9]+)?` regex only matched `mkfs.*` variants. Ships with the `mkswap` keyword in PACK_ENTRIES, a destructive `mkswap` rule (High), and a safe `mkswap-check` carve-out for read-only `mkswap --check` inspection.
- **`dcg update` verifies install.sh / install.ps1 before exec** (`git_safety_guard-ythp`) — `self_update_unix` previously did `curl -fsSL <script> | bash -s -- ...`: a tag-pinned but unverified pipe, so a GitHub account compromise that planted a malicious installer at the tag would run unchecked. New flow downloads the script to a tempfile, best-effort fetches `install.sh.sha256` from the matching GitHub Release (`releases/download/<tag>/install.sh.sha256`), verifies via `shasum -a 256 -c`, aborts on mismatch, and only then `bash`-execs the script. Tags published before this change have no `.sha256` artifact: the verifier emits a warning and proceeds (preserving the update path for stale binaries). PowerShell path mirrors the same flow with `Get-FileHash`. CI side: `dist.yml` now publishes `install.sh.sha256` / `install.ps1.sha256` plus matching cosign sigstore bundles for every release.
- **Cross-session graduated-response wiring** (`git_safety_guard-n9j1`) — `history_soft_block` / `history_hard_block` / `history_window` config fields were parsed and merged but never consulted by `determine_graduated_response`. For shell hooks (one process per `Bash` call) the in-process `session_count` never grows past 1, so Standard/Lenient modes never escalated across invocations. Added `determine_graduated_response_with_history` and `EvaluationResult::apply_graduation_with_history_db` that query `HistoryDb::count_command_blocks_in_window(command_hash, history_window_duration)` and escalate Standard/Lenient to SoftBlock/HardBlock when the cross-session count crosses the configured thresholds. Hot-path stays fail-open: any history query error falls back to session-only graduation. New `ResponseConfig::parse_history_window` helper accepts `s` / `m` / `h` / `d` suffixes. 7 new tests including legacy-signature equivalence and unit-parsing coverage.
- **History `inline_params` SQL substitution corruption fix** (`git_safety_guard-tovy`) — `history/schema.rs::inline_params` previously substituted `?N` placeholders via reverse-order `String::replace`. Reversal solved the `?10` vs `?1` ambiguity but did NOT prevent corruption when a substituted value contained text matching an earlier placeholder index (e.g. `params[4] = "?1"` would inject `'?1'` into the SQL, then the subsequent pass would re-substitute it into the value of `?1`). Replaced with a single-pass left-to-right walk that recognizes `?N` only outside single-quoted string literals, parses full digit runs, and writes substituted values to the output without rescanning. 7 new tests including the exact regression case (`params[1] = "?1"`) and SQLite's doubled-quote escape handling.
- **Unified SIGINT shutdown registry** (`git_safety_guard-i5gd`) — `main.rs` previously registered an ad-hoc ctrlc handler that flushed only the `HistoryWriter`. Refactored to a process-wide `SHUTDOWN_ACTIONS` registry: each subsystem with cross-call buffered state registers a flush closure at startup, and the SIGINT handler invokes them in order before `std::process::exit(130)`. Future stores plug in by calling `register_shutdown_action(...)` rather than adding ad-hoc logic to the signal handler.
- **Pending-exceptions JSONL bounded with rotation** (`git_safety_guard-f81d`) — `record_block` previously appended unbounded; long-running automations issuing many allow-once codes turned every `record_block` call into O(N) under an exclusive lock. New `MAX_PENDING_LINES` (10,000) cap triggers archival to `pending.jsonl.1` of the oldest half (with `OpenOptions::append` so prior archives accumulate, not overwrite). Hard `MAX_PENDING_BYTES` (10 MiB) refusal: if the live file is somehow still over that cap, `record_block` returns an error rather than continuing to grow. The hot path is now O(MAX_PENDING_LINES / 2) under the exclusive lock.
- **Bounded config-file reads + system-layer symlink rejection** (`git_safety_guard-tck0`) — `config::load_layer_from_file` and `allowlist::load_allowlist_file` previously called `fs::read_to_string` directly, so a 2 GiB symlinked file would be loaded entirely into memory before parsing failed. New `read_config_file_bounded` helper caps reads at `MAX_CONFIG_BYTES` (1 MiB, well above any sane TOML config) using `Read::take`. The system layer (`/etc/dcg/config.toml` and `AllowlistLayer::System`) additionally refuses to follow symlinks pointing at user-writable targets — a non-root user could otherwise influence privileged config by symlinking it into their home directory. Per-layer trust class is encoded as `ConfigSource::System` vs `Untrusted`.
- **Scan reporting: structured skip detail and missing-path warnings** (`git_safety_guard-jvkm` + `-eug4`) — `ScanReport.summary` now includes two new arrays in addition to the existing `files_skipped` total. `paths_skipped[]` lists top-level user-supplied target paths that didn't exist or were unreadable, with `reason: "path_not_found"` — surfaced via `tracing::warn!` so misconfigured CI invocations no longer silently exit zero with `files_scanned=0`. `skipped[]` records per-file skip detail with a `reason` enum (`metadata_error`, `not_a_regular_file`, `too_large`, `no_extractor`, `read_error`) so operators can distinguish `max-file-size` configuration issues from genuinely-non-script files.
- **Scan-mode heredoc-extraction timeout floor** (`git_safety_guard-s67a`) — `ScanEvalContext::from_config` now floors `heredoc_settings.limits.timeout_ms` at 200ms (`SCAN_HEREDOC_MIN_TIMEOUT_MS`). The hook hot path is a per-Bash-call budget where every microsecond matters; the scan path is offline (`dcg scan .` runs once, deliberately, and doesn't gate command execution). Inheriting the hot-path budget silently dropped matches whose extraction merely brushed the budget. User config values larger than the floor are still honored.
- **Pending-exception short codes are now 6 digits** (`git_safety_guard-suap`) — `short_code_from_hash` was a 5-digit decimal modulo of the trailing 32 bits, giving 100,000 codes and a birthday-paradox 50% collision threshold at ~370 active records. Bumped to 6 digits (1,000,000 codespace) which raises the threshold to ~1,175 active records — well above realistic per-day volume in a 24-hour TTL. `dcg allow-once <code>` and `dcg allowlist revoke <code>` accept legacy 5-digit codes from already-written `pending.jsonl` files.
- **`detached_head_strictness` config knob** (`git_safety_guard-6skk`) — `apply_branch_strictness` previously collapsed `BranchInfo::DetachedHead(_)` to `branch_name=None` and applied `default_strictness`. Detached HEAD typically signals rebase / bisect / checkout-of-tag — exactly the contexts where uncommitted work is most exposed. New `git_awareness.detached_head_strictness` field defaults to `All` (strictest); also configurable via `DCG_GIT_DETACHED_HEAD_STRICTNESS`. Set it to `default_strictness` for the previous loose behavior.
- **Agent detection no longer false-positives on substrings** (`git_safety_guard-bui6`) — `agent_from_process_name` previously used `executable.contains("claude")` / `"aider"` / `"continue"` / `"cursor"` etc., misclassifying any tool whose binary name merely contained an agent name (`claude-explorer`, `myproject-continue`, `cursor-ext`). The new implementation tokenizes the parent-process string on whitespace, takes each token's basename (lower-case, `\` → `/`, last path segment, strip `.exe`), and matches it against an explicit name/alias table. Wrapper invocations like `node /usr/local/bin/codex` continue to detect correctly because each argv token is checked independently.
- **Interactive prompt sanitizes attacker-controlled command** (`git_safety_guard-m1ic`) — `display_prompt` in `src/interactive.rs` now passes the blocked command and reason through `sanitize_for_display` before any styling. The helper strips CSI/OSC/2-byte ESC escapes (preventing terminal-title spoofing, fake prompt boundaries, color injection) and visualizes remaining C0/C1 control bytes as `\xNN` / `\n` / `\r` / `\t` so the human verifier sees the original bytes without the terminal acting on them.
- **system.disk pack promoted to default-on** (`PacksConfig::enabled_pack_ids`) — first-time users with empty config now get `mkfs`/`dd-to-/dev`/`fdisk`/`parted`/`mdadm`/`lvm`/`wipefs` protection without manual enablement. Opt-out via `disabled = ["system.disk"]` (or `disabled = ["system"]`).
- **Strict git pack**: expanded dangerous-command detection for additional destructive git patterns ([6d950f3](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6d950f3), [031e84a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/031e84a))
- Removed safe patterns in strict git pack that created a compound-command bypass ([d6ce202](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d6ce202))
- Podman `rm`/`rmi` combined-flag bypass (e.g. `podman rm -af`) ([d9d23b5](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d9d23b5))

### Hook & Agent Detection

- **Codex CLI PreToolUse hook support**: Codex CLI 0.125.0+ is supported via stable `~/.codex/hooks.json` PreToolUse hooks. dcg detects Codex hook input from the `turn_id` field and uses the strict stderr-deny contract with exit code 2 required by Codex, not the Claude/Gemini JSON-deny payload. The Unix installer writes `~/.codex/hooks.json` when Codex CLI is detected; Windows installs document the manual hook path while PowerShell parity is tracked separately. Closes [#84](https://github.com/Dicklesworthstone/destructive_command_guard/issues/84).
- Hook system expansion with additional interception patterns and strict git pack hardening ([031e84a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/031e84a))
- Disambiguate Claude Code from Gemini in `detect_protocol()` -- closes [#77](https://github.com/Dicklesworthstone/destructive_command_guard/issues/77) ([8815b54](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8815b54))

### Output

- **Rich output is now enabled by default** (`bd-15p0`) — default Cargo builds include the `rich-output` feature and the `rich_rust` renderer, while `cargo build --no-default-features` remains the lean/plain fallback. The unused `legacy-output` Cargo feature placeholder was removed; runtime plain output is still available through `DCG_NO_RICH=1`, `NO_COLOR=1`, CI/non-TTY detection, or `--legacy-output`.

### Maintenance

- Clippy and rustfmt cleanup across CLI, hook, and pack modules ([c26f22d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c26f22d))
- Test infrastructure: `large_dataset_insertion` test updated to use in-memory DB with manual seeding ([784e356](https://github.com/Dicklesworthstone/destructive_command_guard/commit/784e356))

---

## [v0.4.3](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.4.3) -- 2026-03-14 [Tag]

A large release adding new agent detections, new protection packs, self-healing settings monitoring, and a session-scoped interactive allowlist system.

### Self-Healing & Resilience

- **Real-time `settings.json` overwrite detection and self-healing** -- DCG now watches for external processes silently removing its hook registration and restores it automatically ([708d202](https://github.com/Dicklesworthstone/destructive_command_guard/commit/708d202))
- `dcg setup` command with shell startup hook-removal detection -- closes [#56](https://github.com/Dicklesworthstone/destructive_command_guard/issues/56) ([45db4b7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/45db4b7))
- Shell startup check to detect silently removed DCG hook ([eb06112](https://github.com/Dicklesworthstone/destructive_command_guard/commit/eb06112))
- Prevent duplicate shell check injection on re-runs ([8b70cab](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8b70cab))

### New Protection Packs

- **Supabase database protection pack** -- full CLI coverage including `db push`, `db reset`, `migration repair`, `functions delete`, `secrets unset`, `storage rm`, `projects delete`, and more; `--dry-run` whitelisted as safe ([003a429](https://github.com/Dicklesworthstone/destructive_command_guard/commit/003a429), [3e3ed19](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3e3ed19))

### Agent Detection & Protocol Support

- **Gemini CLI hook protocol support** with improved detection for minimal payloads ([ac6e6ad](https://github.com/Dicklesworthstone/destructive_command_guard/commit/ac6e6ad), [0629a5d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0629a5d))
- **Augment Code** agent detection ([5917125](https://github.com/Dicklesworthstone/destructive_command_guard/commit/5917125))
- **GitHub Copilot CLI** agent detection ([84bb1a0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/84bb1a0))

### Interactive Allowlist & Session Management

- **Session-scoped allowlist** binding with `session_id` and testable interactive checks ([3533533](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3533533))
- **Interactive allowlist audit system** with collision-resistant backup naming and SQLite schema v6 migration ([c948240](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c948240))
- Project-level hook install and `--no-configure` update flag ([1397a8b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1397a8b))

### Output & History

- **TOON output format** support, hardened history storage, and improved test infrastructure ([69f60c8](https://github.com/Dicklesworthstone/destructive_command_guard/commit/69f60c8))

### Bug Fixes

- Emit JSON `"ask"` decision for warn-severity matches in hook mode -- closes [#70](https://github.com/Dicklesworthstone/destructive_command_guard/issues/70) ([91f09db](https://github.com/Dicklesworthstone/destructive_command_guard/commit/91f09db))
- Display `custom_paths` packs in `dcg packs` listing -- closes [#57](https://github.com/Dicklesworthstone/destructive_command_guard/issues/57) ([045cfc0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/045cfc0))
- Redis `maxmemory` regex no longer matches `maxmemory-policy` ([1c3c94a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1c3c94a))
- Missing Redis CONFIG SET rules for `maxmemory`, persistence, and rewrite ([4f0a21a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4f0a21a))
- ARM64 compilation fix for `uring-fs` (`*const i8` to `*const libc::c_char`) ([7b9bf96](https://github.com/Dicklesworthstone/destructive_command_guard/commit/7b9bf96))
- Installer and CI aligned on `gnu` targets to match existing release binaries ([5e81603](https://github.com/Dicklesworthstone/destructive_command_guard/commit/5e81603))

---

## [v0.4.2](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.4.2) -- 2026-02-23 [Tag]

Stabilization release that resolved 91+ pre-existing test failures.

### Test Suite

- Resolved 91+ pre-existing test failures across the entire test suite ([faf7e0e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/faf7e0e))

### License

- License updated to MIT with OpenAI/Anthropic Rider ([c1200c7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c1200c7))

---

## [v0.4.1](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.4.1) -- 2026-02-22 [Tag]

First `musl`-based statically linked Linux binary release, plus dependency modernization and publish to crates.io.

### Distribution & Portability

- Switch Linux x86_64 distribution to **musl** for portable, statically linked binaries ([e066687](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e066687))
- Static linking verification for musl builds in CI ([6cdbfc1](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6cdbfc1), [0a6850c](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0a6850c))
- `fsqlite` dependencies switched from local paths to crates.io v0.1.0 ([9dc695b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/9dc695b))
- `rich_rust` dependency updated from pre-release/git ref to crates.io v0.2.0 ([83d4abf](https://github.com/Dicklesworthstone/destructive_command_guard/commit/83d4abf))
- crates.io keyword limit compliance (max 5) ([0a46ef7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0a46ef7))

### CLI Improvements

- `dcg pack-info` shows patterns by default; new `--json` and `--no-patterns` flags ([48e303e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/48e303e))

### Bug Fixes

- Binary content detection for Unicode; FTS rowid sync; regex engine fallback ([acc2f2c](https://github.com/Dicklesworthstone/destructive_command_guard/commit/acc2f2c))
- macOS `CursorUIViewService` filtered from Cursor IDE detection ([970f62f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/970f62f))
- Migrate all branch references from `master` to `main`; fix quote-stripping in normalizer ([920d785](https://github.com/Dicklesworthstone/destructive_command_guard/commit/920d785))
- History writer migrated to thread-local DB; updated `rand` API ([4d1b3c7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4d1b3c7))

### Testing

- Comprehensive unit tests for output modules ([b97f50a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b97f50a))

---

## [v0.4.0](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.4.0) -- 2026-02-10 [Release]

Major release adding GitHub Copilot CLI hook support, installer improvements, and automated packaging triggers.

### Agent Integration

- **GitHub Copilot CLI hook support** and installer integration ([7385931](https://github.com/Dicklesworthstone/destructive_command_guard/commit/7385931))
- Timeout protection and user feedback for agent scanning during install ([37c9123](https://github.com/Dicklesworthstone/destructive_command_guard/commit/37c9123))

### Distribution

- `repository_dispatch` triggers for homebrew-tap and scoop-bucket automated packaging ([b5482b4](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b5482b4))

### Evaluator

- Evaluator refactored to consolidate external pack checking into core evaluation ([fea7d6a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/fea7d6a))
- Build ordered pack list and keyword index after external packs are loaded ([314e591](https://github.com/Dicklesworthstone/destructive_command_guard/commit/314e591))

### Bug Fixes

- All available subcommands now appear in `dcg --help` output ([23f3301](https://github.com/Dicklesworthstone/destructive_command_guard/commit/23f3301))

---

## [v0.3.0](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.3.0) -- 2026-02-02 [Release]

Large feature release introducing robot mode, rich terminal output via `rich_rust`, golden testing, expanded packs, and agent-specific profiles.

### Robot Mode & Machine-Readable Output

- **Robot mode** with structured JSON output and machine-readable exit codes (`dcg test --robot`) ([e576883](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e576883))
- Robot mode API documentation ([34506dd](https://github.com/Dicklesworthstone/destructive_command_guard/commit/34506dd))
- Schema versioning and metadata in `TestOutput` JSON ([b7a6d6d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b7a6d6d))

### Rich Terminal Output (`rich_rust` Integration)

- `rich_rust` dependency with DcgConsole wrapper and rich theme bridge ([ae39947](https://github.com/Dicklesworthstone/destructive_command_guard/commit/ae39947), [c881a75](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c881a75))
- Tables migrated to `rich_rust` ([328107a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/328107a))
- Enhanced `doctor`, `packs`, and `stats` commands with rich terminal output ([02b5086](https://github.com/Dicklesworthstone/destructive_command_guard/commit/02b5086), [ea39323](https://github.com/Dicklesworthstone/destructive_command_guard/commit/ea39323))
- Tree visualization for `dcg explain` ([e538399](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e538399), [2b8780d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2b8780d))
- CLI output control flags for legacy and color modes ([fdda44f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/fdda44f))

### Golden Testing

- Golden JSON tests framework for deterministic output validation ([0b0ca97](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0b0ca97))
- Robot framework test fixtures ([cbf74da](https://github.com/Dicklesworthstone/destructive_command_guard/commit/cbf74da))

### Pack System Expansion

- Detailed explanations added to all destructive patterns ([e775c2b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e775c2b))
- Expanded allowlist rules for safe command patterns ([db272dc](https://github.com/Dicklesworthstone/destructive_command_guard/commit/db272dc))
- External pack loading from `custom_paths` wired into the evaluator ([bea17d0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/bea17d0), [a2cabc5](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a2cabc5))
- Expanded `system.disk` pack with mdadm, btrfs, LVM, and dmsetup patterns ([56df75a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/56df75a))

### Agent Profiles

- **Agent-specific profiles and trust levels** (Epic 9) -- auto-detect AI coding agent and apply tailored settings ([77571ba](https://github.com/Dicklesworthstone/destructive_command_guard/commit/77571ba))

### Misc

- Configurable verification methods for interactive prompts ([23618ac](https://github.com/Dicklesworthstone/destructive_command_guard/commit/23618ac))
- OpenCode added to supported tools list ([4473419](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4473419))

### Bug Fixes

- macOS config path: check XDG-style `~/.config/dcg` first ([ceffdf5](https://github.com/Dicklesworthstone/destructive_command_guard/commit/ceffdf5))
- External packs marked as always-enabled in listing ([7821773](https://github.com/Dicklesworthstone/destructive_command_guard/commit/7821773))
- Iteration limit added to prevent unbounded wrapper stripping in normalizer ([d342171](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d342171))
- CI/TERM=dumb detection for plain text fallback output ([47b4ddd](https://github.com/Dicklesworthstone/destructive_command_guard/commit/47b4ddd))

---

## [v0.2.15](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.15) -- 2026-01-20 [Release]

CI fix release.

### Bug Fixes

- Run only lib tests in dist workflow to avoid missing binary errors ([6489d2b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6489d2b))

---

## [v0.2.14](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.14) -- 2026-01-20 [Tag]

Version bump and formatting for release pipeline.

### Maintenance

- Bump version to 0.2.14 and apply `cargo fmt` ([6d67502](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6d67502))

---

## [v0.2.13](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.13) -- 2026-01-20 [Tag]

Massive feature batch covering the MCP server, CI scan extractors, self-update mechanism, SARIF output, rich TUI, custom packs, and dozens of new security pack enrichments.

### MCP Server & Agent Integration

- **MCP server mode** (`dcg mcp`) for direct agent integration via the Model Context Protocol ([b372d99](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b372d99))
- Hook output enriched with `ruleId`, `severity`, and `remediation` fields ([b439cd4](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b439cd4))
- Agent ergonomics test suite ([0ebc72f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0ebc72f))
- Machine-readable DCG documentation added to AGENTS.md ([871f929](https://github.com/Dicklesworthstone/destructive_command_guard/commit/871f929))

### Structured Output Formats

- **SARIF 2.1.0 output format** for security tool and CI integration ([4a4c09e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4a4c09e), [17f2040](https://github.com/Dicklesworthstone/destructive_command_guard/commit/17f2040))
- Standardized error code system (DCG-XXXX) ([4f87561](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4f87561))
- JSON Schema (Draft 2020-12) for all DCG output formats ([8c7601c](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8c7601c))
- `--format json` support for `test` and `packs` commands ([f9db962](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f9db962))

### Rich Terminal Rendering

- **Rich terminal rendering** -- denial boxes, progress bars, tables, and TUI denial integration ([a0aaf42](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a0aaf42), [f9986e0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f9986e0))
- Span highlighting with caret-style terminal formatter for denial output ([32aaa18](https://github.com/Dicklesworthstone/destructive_command_guard/commit/32aaa18), [ad2ac66](https://github.com/Dicklesworthstone/destructive_command_guard/commit/ad2ac66))

### Self-Update & Installer

- **Native Rust self-update mechanism** with version rollback and background notification ([f8a8a15](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f8a8a15), [d0e1066](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d0e1066))
- `--check` flag for version checking ([c4f4f64](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c4f4f64))
- **Sigstore cosign signing** added to release workflow ([45c8109](https://github.com/Dicklesworthstone/destructive_command_guard/commit/45c8109))
- Installer: sigstore verification, Cursor detection, preflight checks, version-check idempotency ([2a597b6](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2a597b6), [1ab0b5b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1ab0b5b))
- Installer: checksum verification with `--no-verify` flag ([616db4a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/616db4a))
- Installer: `uninstall.sh` script with agent hook removal ([c3d3eff](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c3d3eff))
- Installer: Aider auto-configuration, Continue detection (unsupported status), Codex CLI detection (unsupported status) ([0a06a82](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0a06a82), [8d07940](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8d07940), [067b28a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/067b28a))

### Custom Pack System

- **Custom pack system** with external YAML loading (`custom_paths` in config) ([0e4bc64](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0e4bc64), [f87aade](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f87aade))
- Regex engine analysis and pack validation utilities ([fa9400f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/fa9400f))

### Scan Mode Extractors

- CircleCI extractor (`.circleci/config.yml`) ([1a3b232](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1a3b232))
- Azure Pipelines extractor ([80d4cda](https://github.com/Dicklesworthstone/destructive_command_guard/commit/80d4cda))
- Dockerfile extractor improvements ([302e35f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/302e35f))
- GitLab CI extractor tests ([3316733](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3316733))

### Pack Enrichment

- Comprehensive severity levels and extended explanations across all packs ([86b6b9a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/86b6b9a), [8dafbe3](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8dafbe3))
- Explanations added to DNS, Payment, database, infrastructure, Kubernetes, container, CI/CD, backup, and API gateway packs ([82064d4](https://github.com/Dicklesworthstone/destructive_command_guard/commit/82064d4), [42ed80b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/42ed80b), [c07e4f9](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c07e4f9))
- **MySQL pack** with comprehensive destructive patterns ([81b0ca8](https://github.com/Dicklesworthstone/destructive_command_guard/commit/81b0ca8))
- Suggestions added for Docker, Kubernetes, MySQL, and system permissions packs ([26dcc3b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/26dcc3b), [1b16ef0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1b16ef0), [5f76ba0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/5f76ba0))

### CLI Enhancements

- Verbosity controls, shell completions, and `DCG_FORMAT` env var ([f545d4d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f545d4d))
- Rule-level analytics queries and suggestion audit tracking ([0a1b7e5](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0a1b7e5), [017a94b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/017a94b))
- Git branch detection module ([6bb91f9](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6bb91f9))
- `DetailedEvaluationResult` and `evaluate_detailed()` API ([bb93259](https://github.com/Dicklesworthstone/destructive_command_guard/commit/bb93259))
- Config parser for new allowlist schema ([876beff](https://github.com/Dicklesworthstone/destructive_command_guard/commit/876beff))

### Security

- Backslash and quote obfuscation bypass detection ([8eaeaaa](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8eaeaaa))
- Safe pattern bypass prevention for compound commands ([e85a495](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e85a495))
- Heredoc scanning: skip non-executing targets (cat, tee, etc.) ([4be0358](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4be0358))
- Here-string (`<<<`) masking for non-executing commands ([831d637](https://github.com/Dicklesworthstone/destructive_command_guard/commit/831d637))

### Bug Fixes

- Docker-compose extractor quote handling for embedded commands ([90c01a0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/90c01a0))
- UTF-8 safe string handling in update and denial modules ([c62ec3e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c62ec3e))
- History FTS rebuild wrapped in transaction for atomicity ([82ee415](https://github.com/Dicklesworthstone/destructive_command_guard/commit/82ee415))
- CI blockers resolved for release builds ([999b9b1](https://github.com/Dicklesworthstone/destructive_command_guard/commit/999b9b1))

---

## [v0.2.12](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.12) -- 2026-01-15 [Tag]

Internal rename of the `telemetry` module to `history`.

### Refactoring

- Complete `telemetry` to `history` module rename across the codebase ([ddfc15d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/ddfc15d))

---

## [v0.2.11](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.11) -- 2026-01-15 [Tag]

Introduces the full command history system and auto-configuration of agent hooks.

### Command History System

- **Command history system** with stats, export, and per-pack analysis (`dcg history stats`, `dcg history export`) ([59a33b1](https://github.com/Dicklesworthstone/destructive_command_guard/commit/59a33b1))
- Comprehensive history module integration tests ([c7802cc](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c7802cc))

### Installer & Agent Configuration

- Installer auto-configures Claude Code and Gemini CLI hooks with detailed feedback ([512c2d3](https://github.com/Dicklesworthstone/destructive_command_guard/commit/512c2d3))

### Performance

- Aho-Corasick quick-reject in `sanitize_for_pattern_matching` for faster false-positive elimination ([6c8afc6](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6c8afc6))

### Testing

- Security regression tests for normalization, safe pattern, and Windows bypasses ([f7324e2](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f7324e2))

---

## [v0.2.10](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.10) -- 2026-01-15 [Release]

Security hardening, performance improvements, and the history pruning command.

### Command History

- **History pruning** command ([06c6ea7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/06c6ea7))
- `DCG_TELEMETRY_*` env vars renamed to `DCG_HISTORY_*` ([d44bde6](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d44bde6))

### Security & Correctness

- Tier 1 bypass fixed for inline scripts with attached quotes (e.g. `bash -c"..."`) ([2890891](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2890891))
- Inline interpreter detection improved to avoid false positives on echoed commands ([3b426b0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3b426b0))
- Potential stack overflow in recursive heredoc scanning limited to depth 50 ([a8f24b0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a8f24b0))
- Quoted secrets with spaces now handled in redaction ([a04f570](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a04f570))

### Bug Fixes

- `xargs` regex robustness, simulated limits, and OOM protection ([77fa5fb](https://github.com/Dicklesworthstone/destructive_command_guard/commit/77fa5fb))
- Inline code detection improved for context module ([8d1ce05](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8d1ce05))

---

## [v0.2.9](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.9) -- 2026-01-14 [Release]

Codebase-wide rename from `telemetry` to `history` and Redis secret redaction.

### Refactoring

- Complete `telemetry` to `history` rename throughout codebase ([d0b2976](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d0b2976))

### Bug Fixes

- Redis `user:password` URL pattern added to secret redaction ([0d61117](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0d61117))

---

## [v0.2.8](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.8) -- 2026-01-14 [Tag]

Introduces the telemetry/history subsystem with persistent SQLite storage, CLI subcommands, secret redaction, and extensive normalizer hardening.

### Telemetry / History Subsystem

- **Telemetry CLI** subcommands for querying persistent command history ([fc2a7a8](https://github.com/Dicklesworthstone/destructive_command_guard/commit/fc2a7a8), [2e4ea76](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2e4ea76))
- **Secret redaction patterns** for telemetry storage ([dbe7159](https://github.com/Dicklesworthstone/destructive_command_guard/commit/dbe7159))
- Telemetry database migrations and config options ([15e3587](https://github.com/Dicklesworthstone/destructive_command_guard/commit/15e3587), [bb95341](https://github.com/Dicklesworthstone/destructive_command_guard/commit/bb95341))
- Comprehensive E2E test framework for telemetry ([13d1701](https://github.com/Dicklesworthstone/destructive_command_guard/commit/13d1701))

### Installer & Agent Configuration

- Claude Code `SKILL.md` for automatic capability discovery ([6f44dc7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6f44dc7))
- Installer auto-configures Claude Code and Gemini CLI idempotently ([3b8fc5f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3b8fc5f))

### Normalizer & Context Hardening

- Sanitize `git grep`/`ag`/`ack` search patterns to prevent false positives ([cf0565a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/cf0565a), [299df4b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/299df4b))
- Harden allowlist/pending exception parsing ([49fda98](https://github.com/Dicklesworthstone/destructive_command_guard/commit/49fda98))
- Avoid panics in production paths ([3e678b5](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3e678b5))
- Apply scan globs after directory expansion ([82a7639](https://github.com/Dicklesworthstone/destructive_command_guard/commit/82a7639))
- Honor project pack overrides ([bcc9a20](https://github.com/Dicklesworthstone/destructive_command_guard/commit/bcc9a20))
- Handle path-prefixed wrappers, env quoted assignments, Dockerfile exec continuations, HCL block comments, inline YAML commas ([326ab3a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/326ab3a), [81fcc2e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/81fcc2e), [65d0fa6](https://github.com/Dicklesworthstone/destructive_command_guard/commit/65d0fa6), [3880cf3](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3880cf3), [c4ba22f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c4ba22f))
- Skip GitHub Actions `env`/`with` blocks during scan extraction ([9f6eab9](https://github.com/Dicklesworthstone/destructive_command_guard/commit/9f6eab9))

### Bug Fixes

- TMPDIR shell default value syntax in safe path detection ([4a970b8](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4a970b8))
- `is_expired` made fail-closed on invalid timestamps ([84e607c](https://github.com/Dicklesworthstone/destructive_command_guard/commit/84e607c))
- CI failures in E2E, scan-regression, and coverage jobs ([f7a4d53](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f7a4d53), [dc82f6a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/dc82f6a))

---

## [v0.2.7](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.7) -- 2026-01-12 [Release]

Memory leak fix and version alignment.

### Bug Fixes

- Full pipeline memory test constrained to core packs to prevent leaks ([d8b1376](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d8b1376))

---

## [v0.2.6](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.6) -- 2026-01-12 [Release]

CI fix for macOS Intel builds.

### CI / Distribution

- macOS Intel builds moved to `macos-15-intel` runner (deprecation of `macos-13`) ([46c20d7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/46c20d7))

---

## [v0.2.5](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.5) -- 2026-01-12 [Release]

Memory test stabilization.

### Bug Fixes

- Warm up pipeline before leak check to avoid false positives ([02c0169](https://github.com/Dicklesworthstone/destructive_command_guard/commit/02c0169))

---

## [v0.2.4](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.4) -- 2026-01-12 [Release]

Lockfile pin for CI stability.

### Bug Fixes

- Pin `ciborium` to 0.2.2 in lockfile ([9f454c6](https://github.com/Dicklesworthstone/destructive_command_guard/commit/9f454c6))

---

## [v0.2.3](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.3) -- 2026-01-12 [Release]

Default config fix.

### Bug Fixes

- Enable common packs on default config load ([23fd149](https://github.com/Dicklesworthstone/destructive_command_guard/commit/23fd149))

---

## [v0.2.2](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.2) -- 2026-01-12 [Release]

Formatting fix.

### Maintenance

- Align confidence tests with rustfmt ([534d1ef](https://github.com/Dicklesworthstone/destructive_command_guard/commit/534d1ef))

---

## [v0.2.1](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.1) -- 2026-01-12 [Release]

Installer improvements with Gemini CLI support, binary size reduction, and portability fixes.

### Installer & Agent Support

- **Gemini CLI** support in installer with proper tool name and error handling ([3769dab](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3769dab))
- Auto-configure Claude Code/Codex and detect predecessor tools ([9929f7d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/9929f7d))
- `--easy-mode` promoted as the recommended install method ([75de506](https://github.com/Dicklesworthstone/destructive_command_guard/commit/75de506))

### Performance

- Binary size reduced 69% by trimming tree-sitter parsers ([d11670e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d11670e))

### Scanning & Detection

- Confidence tiering for warn-by-default patterns ([b31b4010](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b31b4010))
- Quote-aware heredoc operator detection ([4d20d9e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4d20d9e))
- Docker-compose extraction allowed without keywords ([c90a56b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c90a56b))
- Per-pack reference documentation generator ([56db566](https://github.com/Dicklesworthstone/destructive_command_guard/commit/56db566))

### Bug Fixes

- Installer portability improvements for BSD/macOS systems ([9f89544](https://github.com/Dicklesworthstone/destructive_command_guard/commit/9f89544))
- UTF-8 boundary panic prevented in confidence/operator detection ([44389a3](https://github.com/Dicklesworthstone/destructive_command_guard/commit/44389a3))
- Heredoc error message line numbers corrected ([d4b98b5](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d4b98b5))
- Explain hint added to block messages ([156de92](https://github.com/Dicklesworthstone/destructive_command_guard/commit/156de92))
- Inline code context detection for attached `-c` flags ([b10c480](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b10c480))

---

## [v0.2.0](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.0) -- 2026-01-09 [Tag]

Foundational release representing the first tagged version of DCG with a mature feature set. Built over 300+ commits in two days of intensive multi-agent development.

### Core Detection Engine

- **Modular pack system** with 49+ security packs covering: core git/filesystem, databases (PostgreSQL, MySQL, Redis, MongoDB, SQLite), Kubernetes (kubectl, Helm, Kustomize), Docker/Podman/Compose, cloud providers (AWS, GCP, Azure), Terraform/Pulumi/Ansible, CI/CD (GitHub Actions, Jenkins, CircleCI, GitLab CI), CDN (CloudFront, Cloudflare Workers, Fastly), DNS (Route53, Cloudflare), backup tools (restic, rclone, borg, Velero), load balancers (ELB, nginx, HAProxy, Traefik), secrets management (Vault, AWS Secrets, Doppler, 1Password), monitoring (Datadog, Prometheus, Splunk, PagerDuty), email services (SES, SendGrid, Mailgun, Postmark), API gateways (Kong, Apigee, AWS API Gateway), search engines (Elasticsearch, Algolia, Meilisearch, OpenSearch), messaging (Kafka, RabbitMQ, NATS, SQS/SNS), storage (S3, GCS, MinIO, Azure Blob), feature flags (LaunchDarkly, Split, Unleash, Flipt), and payments (Stripe, Braintree, Square) ([f04ae36](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f04ae36aaecc027b7666504cd5aa7e0c2d922dda))
- **Aho-Corasick keyword prefilter** + per-pack `RegexSet` fast path for O(n) matching
- **Lazy regex compilation** with `LazyFancyRegex` -- patterns compiled on first use only
- **Pack-aware quick reject** -- skip entire packs when no keywords match ([635bb97](https://github.com/Dicklesworthstone/destructive_command_guard/commit/635bb97))
- **CompiledOverrides** for precompiled config regexes in the evaluator hot path ([2f2a979](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2f2a979))

### Heredoc & Inline Script Scanning

- **Two-tier heredoc detection** -- Tier 1 fast path for common patterns, Tier 2 AST-based content extraction ([1ca7745](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1ca7745), [891722e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/891722e))
- **AST pattern matching layer** for destructive operations in Python, Ruby, JavaScript, TypeScript, Perl, Go, Bash ([2ae7517](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2ae7517))
- Language detection with priority-based signals ([f9f1228](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f9f1228))
- Configurable heredoc scanning behavior ([81d9bde](https://github.com/Dicklesworthstone/destructive_command_guard/commit/81d9bde))
- Go language support for heredoc AST scanning ([a0a89bd](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a0a89bd))

### Smart Context Detection

- **Execution-context classification** -- distinguishes data contexts (strings, comments, grep patterns) from execution contexts ([14cb23a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/14cb23a), [e829144](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e829144))
- **Safe String-Argument Registry** v1 for reducing false positives on non-executing patterns ([341f24b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/341f24b))
- `sanitize_for_pattern_matching` integration for false-positive immunity ([55561a1](https://github.com/Dicklesworthstone/destructive_command_guard/commit/55561a1))

### CLI & User Interface

- **Explain mode** -- `dcg explain "command"` shows matching rules, packs, severity, and trace info ([4b01e6d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4b01e6d), [7d5a8fb](https://github.com/Dicklesworthstone/destructive_command_guard/commit/7d5a8fb))
- **Scan mode** for CI/CD -- extract and evaluate commands from GitHub Actions, Dockerfiles, Makefiles, shell scripts, docker-compose, and `package.json` ([1d915d5](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1d915d5), [89ef9cd](https://github.com/Dicklesworthstone/destructive_command_guard/commit/89ef9cd))
- **Simulate mode** with output formats and redaction/truncation ([183862b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/183862b))
- Pre-commit hook install/uninstall for scan mode ([c8174c9](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c8174c9))
- Markdown output format for PR comments ([c3428ff](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c3428ff))
- `--explain` and `--format` flags for the test command ([e032fd9](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e032fd9))

### Policy & Allowlist System

- **Decision modes** (deny/warn/log) per rule ([d3e5499](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d3e5499))
- **Severity tagging** for core pack rules ([aeacc38](https://github.com/Dicklesworthstone/destructive_command_guard/commit/aeacc38))
- **Allowlist system** with expiration, conditions, risk acknowledgement, and wildcard pack matching ([0eff234](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0eff234), [58d683e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/58d683e), [78d0eee](https://github.com/Dicklesworthstone/destructive_command_guard/commit/78d0eee))
- **Observe mode** with `observe_until` warn-first rollout window ([d67fe7b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d67fe7b))
- Allowlist CLI commands ([600549d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/600549d))
- Allow-once audit logging ([d25f44f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d25f44f))

### Suggestions Engine

- **Suggestions engine** with safer alternative recommendations for all core patterns ([4948d6a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4948d6a), [53b48e7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/53b48e7))
- Docker, Kubernetes, and database suggestions ([dd525d0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/dd525d0))

### Performance & Resilience

- **Fail-open deadline enforcement** -- configurable timeout budget prevents DCG from blocking workflows ([ef9bb4a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/ef9bb4a))
- **Performance benchmarks** for heredoc detection and core pipeline ([8456045](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8456045), [4ac432e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4ac432e))
- Performance budget constants and CI enforcement ([2a2b3b1](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2a2b3b1))
- Wrapper prefix stripping module for sudo/env/command normalization ([b2f02b8](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b2f02b8))

### Testing

- **E2E test framework** with comprehensive coverage of CLI flows, hook mode, scan mode, and security regressions ([3d4c216](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3d4c216), [39ee901](https://github.com/Dicklesworthstone/destructive_command_guard/commit/39ee901))
- **Cargo-fuzz harness** with 4 fuzz targets ([530e05f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/530e05f))
- **Property-based tests** for evaluator invariants ([b3b33a4](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b3b33a4))
- Layered allowlist E2E tests ([42c4adb](https://github.com/Dicklesworthstone/destructive_command_guard/commit/42c4adb))
- Hook/CLI evaluator parity tests ([d08105e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d08105e))
- Coverage threshold enforcement in CI ([d40217a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d40217a))

### Infrastructure

- **Release automation** and self-updater foundation ([cb9f6b4](https://github.com/Dicklesworthstone/destructive_command_guard/commit/cb9f6b4))
- Cross-platform CI: Linux (x86_64, aarch64), macOS (Intel, Apple Silicon), Windows
- Codecov integration for coverage tracking
- Dependabot configuration for automated dependency updates
- `install.sh` with `--easy-mode` flag, platform auto-detection, and predecessor tool migration

### Bug Fixes

- Regex backtracking panic in `normalize_command` ([4c5be16](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4c5be16))
- Stdin hang on clap parse errors ([17889ce](https://github.com/Dicklesworthstone/destructive_command_guard/commit/17889ce))
- UTF-8 safe preview truncation in AST matcher ([961bc8f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/961bc8f))
- Quoted command-word bypass ([1647112](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1647112))
- Temp-dir path traversal treated as catastrophic in AST matcher ([893887a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/893887a))
- Shell function declaration with spaced parens in scanner ([c19dc2a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c19dc2a))

---

## Initial Development -- 2026-01-07

The project began as `git_safety_guard`, a focused tool for blocking destructive git commands. It was renamed to **destructive_command_guard** (`dcg`) and expanded into a general-purpose destructive-command interceptor with the modular pack system.

- Initial commit ([1640612](https://github.com/Dicklesworthstone/destructive_command_guard/commit/16406128fc967a305b97f4cd8da1b537a4be7b6f))
- Comprehensive enhancements with colorful output, CI/CD, and tooling ([c686775](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c686775b745b5b81644323eb35df3a8920136f74))
- Rename to `destructive_command_guard` with modular pack system ([f04ae36](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f04ae36aaecc027b7666504cd5aa7e0c2d922dda))

---

## Release Matrix

| Version | Date | Type | Binaries |
|---------|------|------|----------|
| v0.4.3 | 2026-03-14 | Tag only | No |
| v0.4.2 | 2026-02-23 | Tag only | No |
| v0.4.1 | 2026-02-22 | Tag only | No |
| v0.4.0 | 2026-02-10 | **GitHub Release** | Yes |
| v0.3.0 | 2026-02-02 | **GitHub Release** | Yes |
| v0.2.15 | 2026-01-20 | **GitHub Release** | Yes |
| v0.2.14 | 2026-01-20 | Tag only | No |
| v0.2.13 | 2026-01-20 | Tag only | No |
| v0.2.12 | 2026-01-15 | Tag only | No |
| v0.2.11 | 2026-01-15 | Tag only | No |
| v0.2.10 | 2026-01-15 | **GitHub Release** | Yes |
| v0.2.9 | 2026-01-14 | **GitHub Release** | Yes |
| v0.2.8 | 2026-01-14 | Tag only | No |
| v0.2.7 | 2026-01-12 | **GitHub Release** | Yes |
| v0.2.6 | 2026-01-12 | **GitHub Release** | Yes |
| v0.2.5 | 2026-01-12 | **GitHub Release** | Yes |
| v0.2.4 | 2026-01-12 | **GitHub Release** | Yes |
| v0.2.3 | 2026-01-12 | **GitHub Release** | Yes |
| v0.2.2 | 2026-01-12 | **GitHub Release** | Yes |
| v0.2.1 | 2026-01-12 | **GitHub Release** | Yes |
| v0.2.0 | 2026-01-09 | Tag only | No |

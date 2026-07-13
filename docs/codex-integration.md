# Codex Integration

Last updated: 2026-07-11

This document is the maintainer reference for dcg's Codex CLI hook path. It
explains how dcg distinguishes Codex from Claude-compatible hook payloads, why
Codex denials use a minimal stdout JSON contract, and how to debug a hook run
that Codex reports as failed instead of blocked.

## Protocol Detection

Codex CLI 0.125.0+ sends the same basic hook payload shape as Claude Code for
shell commands: `tool_name`, `tool_input.command`, hook event metadata, and a
tool-use identifier. dcg must therefore avoid treating every Bash hook as
Codex. The discriminator is Codex's `turn_id` field.

The rule in `src/hook.rs:detect_protocol` is intentionally narrow:

- A shell tool (`Bash`, `bash`, or `launch-process`) with a non-empty `turn_id`
  is treated as `HookProtocol::Codex`.
- A shell tool with `tool_use_id` but no `turn_id` stays on the
  Claude-compatible JSON path.
- Non-shell tools do not become Codex just because a `turn_id` field is present.
- Copilot and Gemini envelope detection runs before the Codex check so their
  protocol-specific handling still wins.

The important regression is the Claude-shaped payload that includes
`tool_use_id` but not `turn_id`. If that ever flips to the Codex path, Claude
Code would stop receiving the structured JSON denial it expects.

Coverage lives in two layers:

- `src/hook.rs` unit tests cover protocol detection and output dispatch.
- `tests/codex_hook_protocol.rs` runs the compiled dcg binary against
  Codex-shaped hook payloads and verifies process exit codes, stdout, stderr,
  allowlists, allow-once codes, pack enablement, history writes, and heredoc
  behavior.

## Deny Contract

Claude-compatible hooks receive a structured JSON denial on stdout. That JSON
contains fields dcg users and agents rely on, including `hookSpecificOutput`,
`ruleId`, `packId`, `severity`, `confidence`, `allowOnceCode`, and
`remediation`.

Codex's hook output parser is stricter. The Codex deny parser can reject unknown
fields, so sending dcg's extended Claude-compatible payload can turn a policy
decision into a `PreToolUse Failed` event instead of a blocked command. dcg
therefore emits only Codex's documented fields:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Destructive command blocked by dcg."
  }
}
```

The process exits 0. stderr still contains the human-readable warning for an
operator, but Codex's blocking decision comes from the JSON on stdout. This is
important on Codex 0.144.x for Windows: a verified report showed the legacy
exit-2 path being classified as `PreToolUse Failed` and then failing open,
whereas the minimal JSON denial blocks correctly (#183).

The implementation points are:

- `src/hook.rs:output_denial_for_protocol` selects the minimal Codex JSON shape.
- The deny branch in `src/main.rs` returns normally, so pending history writes
  flush through `HistoryWriter::Drop`.
- `src/hook.rs` keeps each other agent's established protocol-specific output
  path unchanged.

The exit-code split is intentional:

| Case | stdout | stderr | exit |
|------|--------|--------|------|
| Allow under any protocol | empty | empty | 0 |
| Claude-compatible deny | JSON denial | warning text | 0 |
| Codex deny | minimal JSON denial | warning text | 0 |
| Parse/config/runtime error | optional error output | error details | 1 or 2 |

For Codex hook integrations, parse the minimal stdout JSON. Empty stdout with
exit 0 still means allow.

## Manual Protocol Probe

Use a throwaway repository when testing real destructive commands through an
agent. For a cheap protocol-shape probe, you can pipe a Codex-shaped hook
payload directly into a dcg binary without asking Codex to run anything:

```bash
printf '%s\n' \
  '{"session_id":"s","turn_id":"turn-1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git reset --hard HEAD~1"},"tool_use_id":"call-1"}' \
  | ./target/release/dcg >/tmp/dcg-codex-stdout.txt 2>/tmp/dcg-codex-stderr.txt
echo "exit=$?"
wc -c /tmp/dcg-codex-stdout.txt /tmp/dcg-codex-stderr.txt
```

Expected result:

- exit code is 0;
- stdout contains a three-field `hookSpecificOutput` denial;
- stderr is non-empty and mentions the blocked command plus the matching rule.

For a Claude-compatible negative control, remove `turn_id` from the same payload.
The denial should return exit code 0 with a JSON object on stdout.

## Troubleshooting

### Codex Reports `PreToolUse Failed`

This usually means Codex could not interpret the hook result as a valid Codex
block. Check these in order:

1. Confirm the hook command in `~/.codex/hooks.json` points to the intended dcg
   binary and that the binary exists.
2. Confirm the binary is executable and runs from the same shell environment
   Codex uses.
3. Confirm `codex --version` reports 0.125.0 or newer.
4. Run the manual protocol probe above. The Codex payload must contain only
   `hookEventName`, `permissionDecision`, and `permissionDecisionReason` inside
   `hookSpecificOutput`; dcg-only metadata belongs only on tolerant protocols.
5. If stderr is empty on a destructive command, inspect `src/hook.rs` output
   dispatch and `src/main.rs` deny handling before looking at installer code.

### Codex Runs The Command After A Denial

Look for a failed-hook symptom first. A failed hook is not the same as a blocked
hook. The common causes are an old dcg binary, stale hook configuration, or a
hook output shape that no longer matches Codex's parser.

Also open `/hooks` once in Codex and trust the installed hook. Current Codex can
silently skip an untrusted user hook, which is observationally similar to a
failed-open hook.

The real-Codex harness checks the smoking-gun condition directly: after Codex is
asked to run a destructive command, the test verifies the repository state is
unchanged and the Codex log includes `hook: PreToolUse Blocked`.

### Safe Commands Emit dcg Text

Allowed commands must be silent. Under Codex, `git status` and other safe
commands should return exit code 0 with empty stdout and empty stderr from dcg.
If Codex displays dcg text for an allowed command, inspect warning-mode routing
and any environment variables that force diagnostic output.

### Allow-Once Or Allowlists Do Not Apply

Codex uses the same evaluation, allowlist, pack, and allow-once logic as the
Claude-compatible path. Only the final hook output contract changes. Check:

- `DCG_CONFIG`, `DCG_PACKS`, and `DCG_DISABLE` are visible to the hook process;
- the project/user/system allowlist file being edited is the one dcg loads;
- the pending exception store is under the same home/project context that the
  hook process sees;
- `tests/codex_hook_protocol.rs` still passes the allowlist and allow-once
  round-trip tests.

## Installer And CI Surfaces

Installer support is split by platform:

- `install.sh:configure_codex` merges a dcg `PreToolUse` Bash hook into
  `~/.codex/hooks.json` when Codex is detected.
- `uninstall.sh:unconfigure_codex` removes only dcg-owned Codex hooks and
  preserves unrelated user hooks.
- `install.ps1` and `uninstall.ps1` provide the same ownership-preserving
  behavior for `%USERPROFILE%\.codex\hooks.json` on Windows.

CI covers Codex without making every pull request depend on a live Codex account:

- The normal `check` job runs `cargo nextest run`, which includes
  `tests/codex_hook_protocol.rs`.
- The coverage job enforces the project thresholds and keeps `src/hook.rs`
  coverage visible.
- The push-only `codex-e2e` job builds dcg, installs Codex when
  `CODEX_API_KEY` is configured, authenticates, and runs
  `scripts/e2e_codex.sh`.
- The real-Codex job exits cleanly with a clear skip when Codex is unavailable,
  unauthenticated, quota-limited, or temporarily unable to reach the API.

Do not make PR CI require live Codex network access. Subprocess protocol tests
are the PR gate; the real-Codex harness is a push-to-main smoke layer.

## Performance Notes

Codex does not get a separate matching engine. The hot path remains the same:
parse, quick reject, normalize, safe patterns, destructive patterns, then output
formatting. The Codex-specific work happens after the decision, where dcg chooses
minimal JSON output for denials.

Performance-sensitive changes should keep these properties:

- allowed commands stay silent and fast;
- protocol detection stays O(1) over parsed hook metadata;
- Codex serialization stays minimal and excludes dcg-only fields;
- history writes flush through normal scope teardown rather than a special
  process-exit path.

The `codex_deny` benchmark exists to catch regressions in the Codex denial path.

## Migration Notes

For existing users upgrading from older dcg versions:

1. Upgrade the dcg binary first.
2. Re-run the installer so `~/.codex/hooks.json` points to the upgraded binary.
3. Confirm Codex is 0.125.0 or newer.
4. Run `codex login status` if you plan to use the real-Codex e2e harness.
5. Run the manual protocol probe above before testing against a real repository.

If Codex has stale hooks that still point to an old binary, the safest fix is to
run dcg's installer or uninstaller. They update only dcg-owned hook entries and
preserve coexisting hooks.

## Known Limitation: Codex `unified_exec` Path (Windows Desktop / CLI)

Codex's `PreToolUse` hook dispatch does **not** intercept every shell call. Per
OpenAI's hook docs: PreToolUse "doesn't intercept all shell calls yet, only the
simple ones. The newer `unified_exec` mechanism allows richer streaming
stdin/stdout handling of shell, but interception is incomplete."
(https://developers.openai.com/codex/hooks)

This is the root cause behind the unresolved part of issue #125 (Windows Codex
Desktop / `codex exec`). On that path Codex routes the command through
`unified_exec` and may emit a `command_execution` event with a wrapped PowerShell
invocation, e.g.:

```json
{
  "type": "command_execution",
  "command": "\"C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -Command 'git reset --hard HEAD~1'"
}
```

`command_execution` is **not** a tool-use event, so `PreToolUse` never fires for
it — regardless of the `matcher` value. This was confirmed empirically: a reporter
tested `matcher: "Bash"`, `matcher: "command_execution"`, and `matcher: "*"`
(wildcard) and none fired for the `command_execution` path. The hook command is
never invoked, so dcg never sees the payload.

### Why the matcher is `Bash` and stays `Bash`

The `matcher` field is a **regex applied to `tool_name`**, and Codex's canonical
shell `tool_name` is `Bash` — there is no `shell_command` alias. (Codex's docs:
"Currently, the tool name is always `\"Bash\"` in Codex CLI"; matcher "is applied
to `tool_name`".) When Codex *does* dispatch a shell call through `PreToolUse`
(the "simple" path), the payload reports `tool_name: "Bash"`, so the installer's
`matcher: "Bash"` is correct. The Desktop runtime log line `tool_name="shell_command"`
the reporter observed comes from the `unified_exec`/`command_execution` runtime
internals — not from a `PreToolUse` payload that dcg would ever receive, and not a
matcher dcg can usefully target (the hook isn't dispatched at all on that path).

Changing the installed matcher to `shell_command` would therefore be a regression:
it would fail to match the canonical `Bash` payload on the path where hooks *do*
fire, while still not helping the `unified_exec` path (where no hook fires under
any matcher). The fix has to land upstream in Codex (extend `PreToolUse` dispatch
to cover `unified_exec`/`command_execution`).

Upstream tracking:
- https://github.com/openai/codex/issues/16246 — PostToolUse missing for the
  exec-session / polling path.
- https://github.com/openai/codex/issues/21639 — hooks stopped firing after a
  Codex Desktop update (regression in the alpha line the reporter is on).
- https://github.com/openai/codex/pull/18888 — work to emit Bash hook events when
  `exec_command` completes via the `write_stdin` polling mechanism.

dcg behavior under this gap is **fail-open by construction**: when Codex routes a
command through `unified_exec`/`command_execution`, *no* `PreToolUse` hook fires, so
dcg is simply never invoked — it cannot block what it never sees, and it neither
crashes nor interferes. The simple per-tool shell path (Codex's `Bash` /
PowerShell-named payload) **is** intercepted (it dispatches as `HookProtocol::Codex`,
the minimal-JSON deny path). See also the Windows limitations summary in
[docs/windows.md](windows.md#limitations-honest).

### dcg-side state (already correct)

The dcg engine and its installed hook config are correct for every path Codex
*does* route through `PreToolUse`:

- The PowerShell-wrapped command form (`powershell.exe -Command '...'`,
  `pwsh -c`, quoted-full-path variants, `cmd /c`) is unwrapped and re-evaluated by
  the inline-script extractor (commit `57ec7ec`), so a wrapped destructive command
  that **reaches** dcg is blocked (verified by direct payload).
- `~/.codex/hooks.json` is written as UTF-8 without a BOM on Windows (commits
  `17746e8`, `5703a8a`), so Codex's strict JSON parser accepts it.
- The matcher is `Bash` (the canonical shell `tool_name`).

No further dcg-side change can make the `unified_exec` path block until Codex
fires `PreToolUse` for it. Until then, treat Codex hooks as a guardrail that
covers the simple-shell path, not a complete enforcement boundary on Windows
Desktop / `codex exec` — consistent with the existing "the model can still write
scripts to disk to bypass hook-based blocking" caveat.

## Verifying It Works

Before closing Codex hook work, collect evidence for the relevant layer:

- `cargo test --test codex_hook_protocol` passes.
- `cargo test --lib hook::` passes when protocol detection or output dispatch
  changes.
- `cargo check --all-targets` passes.
- `cargo clippy --all-targets -- -D warnings` passes.
- The manual protocol probe returns exit code 0, minimal denial JSON on stdout,
  and non-empty stderr for a destructive Codex-shaped payload.
- `scripts/e2e_codex.sh --verbose --json --artifacts <dir> --dcg-binary <path>`
  either passes against an authenticated Codex CLI or exits successfully with an
  explicit skip reason.
- README's Codex CLI note links back to this document.
- AGENTS.md states that a Codex deny uses the minimal JSON contract and that
  empty stdout with exit 0 remains the allow signal.

# Troubleshooting Guide

Common issues and how to resolve them.

## dcg is not blocking anything

1. Confirm the hook is installed correctly.
2. Ensure the dcg binary is on PATH.
3. Verify trusted config loading (explicit/user/system) and pack enablement.
   Automatically discovered `.dcg.toml` files may enable packs and add other
   enforcement, but cannot disable protection or add allow rules.

If available, run:
- `dcg doctor` for a structured diagnostics report.

## Packs are not enabled

Check your config sources in order:
- `DCG_CONFIG=/path/to/config.toml` (explicit, fully trusted)
- `~/.config/dcg/config.toml` (user)
- `/etc/dcg/config.toml` (system)

An automatically discovered project `.dcg.toml` may add `[packs].enabled`, but
its `[packs].disabled` and `custom_paths` entries are ignored. Select a reviewed
project file explicitly with `DCG_CONFIG=.dcg.toml` if it needs full authority.

Also verify environment overrides:
- `DCG_PACKS`
- `DCG_DISABLE`

## False positives (safe command blocked)

1. Add a safe allowlist entry (project or user).
2. If recurring, file a bug report with the exact command.
3. Add a test case to prevent regressions.

## False negatives (dangerous command allowed)

1. File a bug report with the exact command and context.
2. Add a destructive pattern + test case.
3. Update the pack’s safe pattern list to avoid over-broad allow rules.

## Hook errors or timeouts

First identify the budget or analysis step named in the diagnostic:

- **Regex backtracking limit:** the reason names the responsible pack and
  pattern, when known, and the operation such as `find_from`. The default is
  100,000 backtracking steps per regex operation. Review that rule using
  [Diagnosing incomplete rule evaluation](custom-packs.md#diagnosing-incomplete-rule-evaluation);
  a larger hook deadline does not change this work limit.
- **`interpreter_literal_recovery`:** a separate bounded analysis of literals
  inside interpreter source did not finish. Possible causes include syntax or
  structural limits, its own time budget, or an unavailable worker. This stage
  does not identify a custom regex failure or establish hook-deadline
  exhaustion. [Issue #643](https://github.com/Dicklesworthstone/destructive_command_guard/issues/643)
  did not include the exact short Python inputs; the reported shape alone is
  insufficient to identify or reproduce their specific failure. A minimal
  sanitized example should preserve the interpreter options, quoting, escapes,
  and heredoc delimiter.
- **Hook deadline:** the reason reports that safety evaluation could not
  complete within the configured hook time. The wall/CPU timing and phase help
  distinguish expensive evaluation from a host that did not schedule dcg.

`dcg config` separates `Regex evaluation` from `Heredoc scanning`. In
particular, the default 50 ms extraction timeout belongs to heredoc extraction,
not to regex matching. JSON exposes `regex.backtrack_limit_steps`,
`heredoc.timeout_ms`, and `general.hook_timeout_ms` separately. Incomplete
analysis retains the configured ask/deny behavior; it never proves a command
safe.

For heredoc or large script parsing:
- Lower `max_body_bytes` or `max_body_lines`.
- Increase `[heredoc].timeout_ms` if heredoc extraction itself is timing out.
- Ensure `fallback_on_parse_error` is true for hook mode.

When the diagnostic establishes genuine hook-deadline exhaustion on a slower
workstation or modest VPS, tune the separate absolute hook budget. For example:

```toml
[general]
hook_timeout_ms = 1500
```

The equivalent one-process override is `DCG_HOOK_TIMEOUT_MS=1500`. Reproduce
the live evaluator budget with
`dcg test --enforce-budget --format json "<command>"`; deadline exhaustion must
appear as `indeterminate`, never `allow` or a destructive-pattern match. Use
`--stdin` when the candidate should not appear on dcg's own command line. Do
not reduce the budget below the measured full-evaluation latency for the host.

When the exact `careful_company_running_windows` preset ID is enabled, dcg uses
3000 ms automatically unless config or the environment supplies a value. Check
`dcg config --format json` for `hook_timeout_ms` and
`hook_timeout_source`. An existing User-scope `DCG_HOOK_TIMEOUT_MS=3000` is safe
to leave in place; it produces the same enforcement budget and is reported as
`configured`.

## Windows update staged but the version did not change

`dcg update` appends worker progress to
`%LOCALAPPDATA%\dcg\update.log`. The worker must wait for the initiating
`dcg.exe` process to exit before Windows permits replacement. AppLocker,
disabled WMI/CIM, or Constrained Language Mode can prevent the resilient worker
launch; dcg reports that condition before trying its detached compatibility
fallback.

Use `dcg update --verify --no-configure` when only the binary should change.
This keeps existing Claude, Codex, Gemini, Cursor, and other hook files exactly
as they are. Re-running the installer or updater without `--no-configure` is
idempotent for dcg hooks and preserves unrelated hooks; `dcg doctor` should
report exactly one dcg hook plus the count of unrelated hooks.

## A known PowerShell mailer still runs

`dcg scan` inspects source, while the runtime hook ordinarily sees only the
script-launch command. Add a narrow trusted `[overrides].block` entry for the
known filename, and separately disable any Task Scheduler entry that launches
it outside the agent. See
[Stop a known mailer immediately](careful-company-windows.md#stop-a-known-mailer-immediately).

Use `dcg test --stdin` with a candidate file when testing a denial through an
already-guarded shell; otherwise the parent hook can correctly block the
dangerous fixture before the test subprocess starts.

## Performance concerns

If hook latency is high:
- Reduce enabled pack count.
- Disable expensive packs temporarily.
- Capture performance logs and open an issue.

## Reporting issues

When filing a report, include:
- The exact command
- Expected vs actual decision
- Your enabled packs list
- Relevant config snippets (redact secrets)

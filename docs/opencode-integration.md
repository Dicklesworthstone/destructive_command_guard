# OpenCode Integration

> Last updated: 2026-08-19 (first-party plugin, issue #318)

[OpenCode](https://opencode.ai) does not expose PreToolUse-style hook config
files the way Claude Code, Codex, or Gemini do. Its interception surface is a
**plugin system**: JavaScript/TypeScript modules loaded by OpenCode's Bun
runtime from `~/.config/opencode/plugins/` (global) or `.opencode/plugins/`
(per-project). A plugin that implements the `"tool.execute.before"` hook can
inspect every tool call before it runs and veto it by throwing an `Error`.

dcg ships a first-party plugin generator:

```bash
dcg install --opencode              # user-level: ~/.config/opencode/plugins/dcg-guard.js
dcg install --opencode --project    # repo-level: <repo>/.opencode/plugins/dcg-guard.js
dcg install --opencode --force      # refresh a dcg-owned plugin in place
```

Restart OpenCode (start a new session) after installing — plugins are loaded
at startup.

## How the plugin works

The generated `dcg-guard.js`:

1. Registers a `"tool.execute.before"` handler and ignores every tool except
   `bash`.
2. Spawns the dcg binary (absolute path embedded at install time — never a
   bare `PATH` lookup, since agent-spawned processes often run with a reduced
   `PATH`) with the Claude-compatible hook envelope on stdin:
   `{"tool_name":"Bash","tool_input":{"command":"…"}}`, and `OPENCODE=1` in
   the environment so dcg identifies the calling agent.
3. Interprets dcg's stdout exactly like the other harnesses: **empty stdout
   means allow**; a `hookSpecificOutput.permissionDecision` of `"deny"` — or
   `"ask"`, since OpenCode has no operator-review state, so review requests
   fail closed — aborts the tool call by throwing an `Error` carrying dcg's
   full block message (reason, rule id, allow-once code, suggestions).
4. Fails **open** only on infrastructure errors (dcg binary missing or
   unrunnable), with a `[dcg]` notice on OpenCode's stderr. The safety
   *evaluation* itself keeps dcg's bounded fail-closed semantics.

## Ownership and uninstall

The file carries a `dcg-opencode-plugin` marker comment. The installer refuses
to overwrite a `dcg-guard.js` that lacks the marker (it belongs to you, not
dcg), and `uninstall.sh` deletes only marker-carrying files.

`install.sh` configures OpenCode automatically when
`${XDG_CONFIG_HOME:-~/.config}/opencode` exists or `opencode` is on `PATH`
(status appears in the install summary). `uninstall.sh` removes the plugin
symmetrically.

## Verifying coverage

`dcg doctor` includes an `opencode_plugin` check whenever OpenCode appears to
be in use (config directory present or an `OPENCODE*` environment variable
set). A missing plugin is an **error** — unlike Grok, OpenCode has no Claude
compatibility layer, so without the plugin its shell commands never reach dcg
at all. `dcg doctor --fix` installs it.

A green doctor proves *wiring* only. The end-to-end proof is a live refusal:
ask an OpenCode session to run a harmless guarded command (for example
`git reset --hard` in a scratch repository) and confirm the tool call aborts
with `BLOCKED by dcg` and the expected rule id.

## Manual test of the plugin contract

```bash
# What the plugin sends and receives:
echo '{"tool_name":"Bash","tool_input":{"command":"git reset --hard"}}' | dcg
# → denial JSON on stdout (plugin throws)

echo '{"tool_name":"Bash","tool_input":{"command":"git status"}}' | dcg
# → empty stdout, exit 0 (plugin allows)
```

## Limitations

- Plugins run inside OpenCode's own runtime; a model that writes a script to
  disk and executes it in a later `bash` call is still evaluated (dcg sees the
  invocation), but content dcg cannot statically trace falls back to its
  bounded fail-closed rules like every other harness.
- Project-level installs (`--project`) require the repository to be trusted by
  OpenCode before plugins load, mirroring Grok's `/hooks-trust` flow.

# Crush Integration

> Last updated: 2026-09-06 (first-party support, issue #388)

[Crush](https://github.com/charmbracelet/crush) (Charm's terminal coding
agent) runs Claude-Code-style `PreToolUse` hooks that it reads from the
`hooks` object of its `crush.json`. dcg speaks Crush's hook protocol
natively: Crush pipes every `bash` tool call to dcg's stdin, and dcg answers
in the envelope Crush parses.

```bash
dcg install --crush              # user-level: ~/.config/crush/crush.json
dcg install --crush --project    # repo-level: <repo>/crush.json (or an existing .crush.json)
dcg install --crush --force      # refresh a stale binary path in place
dcg uninstall --crush            # remove dcg's entry from ~/.config/crush/crush.json
```

Start a new Crush session after installing.

## What gets written

dcg merges one flat entry into `hooks.PreToolUse` and leaves everything else
in the file alone (Crush's own `$schema`, `options`, providers, MCP servers,
and any other hooks you have):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "name": "dcg",
        "matcher": "^bash$",
        "command": "/absolute/path/to/dcg",
        "timeout": 5
      }
    ]
  }
}
```

- `matcher` is a regex Crush tests against the tool name. Crush's shell tool
  is called `bash` on every platform (it runs an embedded POSIX shell), so
  there is no PowerShell variant to match.
- `command` is the absolute path of the dcg binary that ran the installer,
  POSIX-quoted. Crush executes hook commands through its embedded POSIX
  shell on Windows too, so the PowerShell `& '…'` form Claude's installer
  uses there is never used here.
- `name` and `timeout` are host-owned: if you rename the entry or change the
  timeout, a reinstall keeps your values and only refreshes `command` and
  `matcher`.
- Reinstalling sweeps stale dcg entries under any spelling of the event key
  Crush accepts (`PreToolUse`, `pretooluse`, `pre_tool_use`, …) and inserts
  the fresh entry first. Crush runs hooks in parallel but resolves them in
  config order, and the first deny wins.

### Which file

Crush deep-merges its config files and **concatenates** `hooks` arrays, so a
user-level entry coexists with project hooks. The user-level path is resolved
exactly as Crush resolves it:

1. `$CRUSH_GLOBAL_CONFIG/crush.json` when that directory override is set;
2. else `$XDG_CONFIG_HOME/crush/crush.json`;
3. else `~/.config/crush/crush.json` — including on Windows.

`~/.local/share/crush/crush.json` is Crush's machine-written *data* file and
is never touched. With `--project`, dcg edits the repo root's `crush.json`
(or `.crush.json` if only that exists) and creates `crush.json` when neither
exists. Crush looks for project configs from the working directory up to the
Git root.

## How the hook protocol works

Crush pipes this JSON to the hook's stdin (the envelope is
`hooks.BuildPayload` in Crush's source):

```json
{"event":"PreToolUse","session_id":"313909e","cwd":"/home/user/project","tool_name":"bash","tool_input":{"command":"rm -rf /"}}
```

dcg recognizes the envelope on its own — no `--agent` flag is needed — by the
PascalCase `event` together with `tool_input`. (GitHub Copilot CLI is the
only other agent that sends a top-level `event`; its value is the hyphenated
`pre-tool-use` and it ships `tool_args`, so the two never collide.)

dcg always exits 0 and answers on stdout:

| dcg verdict | stdout | What Crush does |
|---|---|---|
| allow | *(empty)* | "No opinion": the call goes through Crush's ordinary permission prompt, exactly as if no hook were installed. |
| deny | `{"version":1,"decision":"deny","reason":"…", "ruleId":…, "allowOnceCode":…}` | Blocks the tool call; the model sees `reason`. |
| ask / indeterminate | same `deny` envelope | Crush has no `ask` decision, and an omitted decision could be waved through by a permission allowlist or an auto-approver, so review requests fail closed. |
| warn | `{"version":1,"context":"DCG warn: …"}` | No decision (the call proceeds through the normal permission flow); `context` is appended to what the model sees. |

dcg never emits `"decision":"allow"`. In Crush that is an *affirmative*
pre-approval that skips the user's permission prompt entirely, and a guard
has no business vouching for a command it merely found nothing wrong with.

Crush's parser ignores fields it does not know, so dcg's ergonomics fields
(`ruleId`, `packId`, `severity`, `allowOnceCode`, `remediation`, …) ride
along for any tooling that wants them. The human-readable denial box still
goes to stderr; Crush only reads stderr as the reason when a hook exits 2,
which dcg does not do (exit 0 + JSON is the path that keeps the structured
fields intact; any other non-zero exit is a non-blocking error in Crush).

## Agent detection

Crush sets `CRUSH=1` (plus `AGENT=crush` and `AI_AGENT=crush`) in the
environment of every hook it runs and every command its `bash` tool
executes. dcg detects Crush from `CRUSH` — the generic `AGENT`/`AI_AGENT`
names are deliberately not consulted — so `[agents.profiles.crush]` in dcg's
config applies both to hook evaluations and to `dcg` invoked from inside a
Crush shell. History entries record `agent_type = "crush"`. The `crush`
parent-process name is a fallback.

## Installers and doctor

`install.sh` and `install.ps1` configure Crush automatically when its config
directory exists or `crush` is on `PATH` (both delegate to
`dcg install --crush --force`). `uninstall.sh` and `uninstall.ps1` strip
dcg's entries from the user-level and repo-root configs. `dcg doctor` reports
a `crush_hook` check when Crush appears to be in use; it is an error (and
`--fix`able) when the hook is missing, because Crush reads only its own
`crush.json` — there is no Claude-settings compatibility layer to fall back
on.

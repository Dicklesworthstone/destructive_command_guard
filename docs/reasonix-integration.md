# Reasonix Integration

> Last updated: 2026-09-24 (first-party support, issue #358)

[Reasonix](https://github.com/esengine/DeepSeek-Reasonix) (DeepSeek's
terminal coding agent) runs native `PreToolUse` hooks declared in its
`settings.json`. dcg speaks that protocol directly: Reasonix pipes each shell
tool call to dcg's stdin, and dcg blocks with exit status 2.

```bash
dcg install --reasonix              # user-level: <Reasonix home>/settings.json
dcg install --reasonix --project    # repo-level: <repo>/.reasonix/settings.json
dcg install --reasonix --force      # refresh a stale binary path in place
dcg uninstall --reasonix            # remove dcg's entry from the user-level file
```

Restart Reasonix after installing; it loads hooks when a session is built.
`install.sh` and `install.ps1` run `dcg install --reasonix --force` when
they detect Reasonix, and `uninstall.sh` / `uninstall.ps1` remove the entry
from the user-level and repo-level settings files.

## What gets written

dcg merges one entry into `hooks.PreToolUse` and leaves everything else in
the file alone:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "match": "bash|pwsh",
        "command": "/absolute/path/to/dcg",
        "description": "dcg: block destructive shell commands",
        "timeout": 5000
      }
    ]
  }
}
```

- `match` is an anchored regex that Reasonix tests against the tool name.
  Hooks see the canonical name of Reasonix's one shell tool: `bash`, or `pwsh`
  when Reasonix rebinds that tool to PowerShell.
- `command` is the absolute path of the dcg binary that ran the installer.
  Reasonix runs it with `sh -c` on macOS/Linux, so the path is POSIX-quoted.
  On Windows it runs `cmd /c`, so the path is double-quoted.
- `timeout` is in milliseconds. If you change `timeout` or `description`,
  a reinstall keeps your values and refreshes only `command` and `match`.
- A reinstall removes old dcg entries and puts the new one first.

The user-level file is `<Reasonix home>/settings.json`. The Reasonix home is
`$REASONIX_HOME` if set, else `~/.reasonix` on macOS/Linux and
`%APPDATA%\reasonix` on Windows. dcg reads `$REASONIX_HOME` as Reasonix
does: trimmed, with `${VAR}` references and a leading `~` expanded. On
Windows, when that file does not exist,
Reasonix still reads a legacy `~\.reasonix\settings.json`. dcg then edits
the legacy file, because creating the new one would make Reasonix silently
stop loading every hook in it.

If the file uses the bare shorthand that Reasonix's JSON editor accepts
(`{"PreToolUse": [...]}` with no `hooks` key), dcg refuses to edit it. The
Reasonix runtime ignores that shape too. Save it once from Reasonix's hook
editor, which writes `{"hooks": ...}`, then rerun the install.

## The protocol

Reasonix writes this to the hook's stdin:

```json
{"event":"PreToolUse","cwd":"/repo","toolName":"bash","toolArgs":{"command":"git reset --hard"}}
```

dcg recognizes this payload without an `--agent` flag. Reasonix reads only
the exit status:

| dcg verdict | exit | what Reasonix does |
|---|---|---|
| allow | 0 | runs the command |
| deny, or an indeterminate result that fails closed | 2 | blocks it and shows dcg's stderr to you and the model |
| warn | 1 | runs the command and shows you the warning (not the model) |

Reasonix has no "ask" answer. dcg rules that ask for review therefore block
here, and the stderr message says how to allow the command, e.g. with
`dcg allow-once`. A hook timeout also blocks, so a slow dcg fails closed.

Reasonix sets no environment variable that identifies it, and dcg's
process-ancestry detection works only on macOS/Linux. A payload dcg cannot
parse (larger than `max_hook_input_bytes`, or not valid UTF-8) therefore
often arrives with no agent identified. dcg still blocks it with exit 2 when
the salvaged command is destructive (or under `DCG_FAIL_CLOSED`), because
the Reasonix envelope markers, a `PreToolUse` `event` and a `toolArgs`
object, remain readable in the raw bytes. Those markers are consulted only
when no agent was identified.

On Windows, Reasonix's shell tool runs PowerShell when no bash is installed,
and it can still be named `bash` then. A `bash`-labeled Reasonix command on a
Windows host is therefore judged by its text, as dcg does for Codex. A
command that cannot parse as POSIX is evaluated as PowerShell. Any other is
evaluated under every dialect, and a deny in any of them blocks. A `pwsh`
payload is always evaluated as PowerShell, with the `windows.*` packs
enabled.

Before #358, dcg treated this payload as a Copilot one. It answered with a
JSON deny on exit 0, which Reasonix ignores, so every command ran.

## Checking it

Once Reasonix appears to be installed, `dcg doctor` reports whether dcg is
registered in the user-level settings, as the `reasonix_hook` check in
`--format json`. `dcg doctor --fix` registers it. For a
manual test:

```bash
echo '{"event":"PreToolUse","cwd":"'"$PWD"'","toolName":"bash","toolArgs":{"command":"git reset --hard"}}' | dcg; echo "exit=$?"
```

This should print `BLOCKED by dcg …` on stderr and `exit=2`.

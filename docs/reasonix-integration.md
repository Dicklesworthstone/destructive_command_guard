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

Start a new Reasonix session after installing.

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
  `bash` is its POSIX shell tool and `pwsh` is its Windows PowerShell tool.
- `command` is the absolute path of the dcg binary that ran the installer.
  Reasonix runs it with `sh -c` on macOS/Linux, so the path is POSIX-quoted.
  On Windows it runs `cmd /c`, so the path is double-quoted.
- `timeout` is in milliseconds. If you change `timeout` or `description`,
  a reinstall keeps your values and refreshes only `command` and `match`.
- A reinstall removes old dcg entries and puts the new one first.

The user-level file is `<Reasonix home>/settings.json`. The Reasonix home is
`$REASONIX_HOME` if set, else `~/.reasonix` on macOS/Linux and
`%APPDATA%\reasonix` on Windows.

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
| warn | 1 | runs the command and shows the warning |

Reasonix has no "ask" answer. dcg rules that ask for review therefore block
here, and the stderr message says how to allow the command, e.g. with
`dcg allow-once`. A hook timeout also blocks, so a slow dcg fails closed.

Before #358, dcg treated this payload as a Copilot one. It answered with a
JSON deny on exit 0, which Reasonix ignores, so every command ran.

## Checking it

`dcg doctor` reports whether dcg is registered in the Reasonix settings once
Reasonix appears to be installed, and `dcg doctor --fix` registers it. For a
manual test:

```bash
echo '{"event":"PreToolUse","cwd":"'"$PWD"'","toolName":"bash","toolArgs":{"command":"git reset --hard"}}' | dcg; echo "exit=$?"
```

This should print `BLOCKED by dcg …` on stderr and `exit=2`.

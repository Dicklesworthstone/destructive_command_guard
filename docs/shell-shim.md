# PATH shell shims

`dcg`'s agent integrations guard commands that pass through a supported hook
(Claude Code, OpenCode, Codex, ...). A plain shell started by a custom agent
runtime, a cron job, or a script does not pass through any hook: it finds
`rm` on `PATH` and runs it. That gap is real even when `dcg install --opencode`
is installed and working.

`dcg install --shell-shim` closes the common case by writing small wrappers
for destructive commands into a bin directory:

```bash
dcg install --shell-shim
# Put the directory ahead of the system bin directories in PATH.
export PATH="$HOME/.local/bin:$PATH"
```

The destination is `$XDG_BIN_HOME` when set, otherwise `~/.local/bin`. Each
wrapper reconstructs the command line, asks `dcg test --dialect posix --robot
-f json --stdin` for a verdict, and only then execs the real binary found
further along `PATH`:

- verdict `allow` (exit 0): run the command;
- verdict `deny` (exit 1): refuse it with a stderr message and exit 126;
- verdict `warning` (exit 2): print the warning and run it;
- anything else: fail closed with exit 125, since dcg could not evaluate it.

Allowlist rules and pack configuration are honoured: the wrapper calls the
same verdict engine as the hooks, with the same config.

Remove the wrappers with:

```bash
dcg uninstall --shell-shim
```

The installer refuses to overwrite a file without the `dcg-shell-shim` marker
(move it aside first, or pass `--force`). The uninstaller removes only
marker-carrying files and leaves everything else at those names untouched.

## What this does not cover

Be precise about the remaining gaps; a shim is a safety rail, not a sandbox:

- Absolute paths (`/bin/rm`, `/usr/bin/rm`) bypass `PATH` shims entirely.
- Shell functions, aliases and builtins take precedence over shims.
- A runtime that replaces `PATH`, or runs with a different `HOME`, can sidestep
  the wrappers. The shim directory must come before the system bin directories
  for the shell in question.
- `dcg test` sees the flattened command line, not heredoc bodies. Use a hooked
  agent when heredoc scanning matters; the hook path remains the stronger one.
- The wrappers are bash scripts, so this install mode is for Unix-like systems.
- `dcg doctor` does not report shim state yet. Check the directory directly.

Install shims **and** the agent hook when both are relevant: they cover
different execution paths.

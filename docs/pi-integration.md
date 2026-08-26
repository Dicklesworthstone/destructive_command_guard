# Pi Integration

Last updated: 2026-08-26

This document shows how to connect dcg to the [Pi coding agent](https://github.com/earendil-works/pi)
(`earendil-works/pi`). Pi is not auto-configured by dcg's installer — Pi's
guardrails are deliberately user-authored as small TypeScript *extensions* — so
this is the official "directed implementation" recipe requested in
[issue #133](https://github.com/Dicklesworthstone/destructive_command_guard/issues/133).
Drop in the extension below and Pi will route every shell command through dcg
before it runs.

## How Pi interception works

Pi extensions register handlers with `pi.on("tool_call", …)`. The handler runs
*before* the tool executes, receives the tool name and (mutable) input, and can
veto execution by returning `{ block: true, reason }`:

```ts
export default function (pi: ExtensionAPI) {
  pi.on("tool_call", async (event, ctx) => {
    // event.toolName === "bash", event.input.command === "<the command>"
    // return { block: true, reason } to deny
  });
}
```

Extensions auto-load from `~/.pi/agent/extensions/*.ts` (global) or
`.pi/extensions/*.ts` (project-local). See Pi's
[extensions docs](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/extensions.md).

## Which dcg entrypoint to call

dcg exposes a stable, agent-friendly decision API via **robot mode**, which is
the right fit for an extension because the decision is carried by the **exit
code** and a machine-readable JSON payload — no hook-protocol envelope to
construct:

```bash
dcg --robot test "<command>"
```

- **exit 0** → allowed
- **exit 1** → denied (JSON on stdout carries `reason`, `rule_id`, `pack_id`,
  `explanation`, `remediation`, …)
- **exit ≥ 3** → a dcg error (config/parse/IO). Treat these as *fail-open* (let
  the command proceed) or *fail-closed* (block) per your risk tolerance; the
  example below fails open so a broken dcg install never wedges Pi, matching the
  default posture of the other dcg integrations.

(See [`docs/adr-002-robot-mode-api.md`](adr-002-robot-mode-api.md) for the full
exit-code contract.)

> Why not pipe a hook JSON payload to bare `dcg`? You can — `printf
> '{"tool_name":"Bash","tool_input":{"command":"…"}}' | dcg` works too — but in
> that mode dcg always exits 0 and puts the decision inside
> `hookSpecificOutput.permissionDecision`, so the extension would have to parse
> JSON just to learn allow vs. deny. `--robot test` makes the exit code
> authoritative, which is simpler and less error-prone.

## The extension

Save this as `~/.pi/agent/extensions/dcg-guard.ts` (global) or
`<repo>/.pi/extensions/dcg-guard.ts` (per project):

```ts
// dcg-guard.ts — block destructive shell commands with dcg
// https://github.com/Dicklesworthstone/destructive_command_guard
import { spawn } from "node:child_process";

const DCG_BIN = process.env.DCG_BIN ?? "dcg";

// Fail open when dcg itself cannot run (not installed, fd exhaustion, ...),
// so a broken install never wedges Pi. Flip this to { deny: true, ... } to
// fail closed instead.
const UNAVAILABLE = { deny: false, reason: "" };

function dcgDecision(command: string): Promise<{ deny: boolean; reason: string }> {
  return new Promise((resolve) => {
    // Resolve exactly once: "error" and "close" can both fire, and a
    // synchronous spawn failure must not race a later event.
    let settled = false;
    const settle = (decision: { deny: boolean; reason: string }) => {
      if (settled) return;
      settled = true;
      resolve(decision);
    };

    // Pi runs on Bun, and Bun's spawn() differs from Node in two ways that
    // matter here: a failed posix_spawn (ENOENT, ENFILE, EAGAIN, ...) is
    // thrown synchronously from spawn() rather than delivered as an "error"
    // event, and when the stdio pipes cannot be set up the returned child can
    // have no `stdout` at all. Handle both, or the extension crashes and the
    // host aborts the tool call instead of failing open.
    let child;
    try {
      child = spawn(DCG_BIN, ["--robot", "test", command], {
        stdio: ["ignore", "pipe", "ignore"],
      });
    } catch {
      settle(UNAVAILABLE);
      return;
    }

    let stdout = "";
    child.stdout?.on("data", (chunk) => {
      stdout += chunk.toString();
    });

    child.on("error", () => settle(UNAVAILABLE));

    child.on("close", (code) => {
      if (code === 1) {
        // Denied. The reason lives in the robot-mode JSON; if the stdout
        // pipe was missing the exit code is still authoritative.
        let reason = "Blocked by dcg (destructive command).";
        try {
          const parsed = JSON.parse(stdout);
          if (parsed?.reason) reason = parsed.reason;
          if (parsed?.rule_id) reason += ` [${parsed.rule_id}]`;
        } catch {
          /* keep the default reason */
        }
        settle({ deny: true, reason });
      } else {
        // 0 = allowed; >=3 = dcg error -> fail open.
        settle(UNAVAILABLE);
      }
    });
  });
}

export default function (pi: ExtensionAPI) {
  pi.on("tool_call", async (event) => {
    if (event.toolName !== "bash") return;
    const command = String(event.input?.command ?? "");
    if (!command.trim()) return;

    let decision;
    try {
      decision = await dcgDecision(command);
    } catch {
      // Anything unexpected inside the guard is a guard failure, not a
      // reason to abort the tool call.
      decision = UNAVAILABLE;
    }
    if (decision.deny) {
      return { block: true, reason: decision.reason };
    }
  });
}
```

> **Oh My Pi users:** since v0.13.0, `dcg install --omp` writes a generated
> `tool_call` extension for OMP that already covers the Bun failure modes
> above; prefer it over hand-maintaining this recipe. The recipe remains the
> path for Pi proper, which also runs on Bun.

Adjust the tool-name check (`event.toolName !== "bash"`) if your Pi build names
its shell tool differently, and set `DCG_BIN` if `dcg` is not on Pi's `PATH`
(e.g. `~/.local/bin/dcg`).

## Verifying it works

1. Install dcg (`curl … | bash`) and confirm `dcg --version` works in the same
   shell environment Pi runs in.
2. Drop `dcg-guard.ts` into one of the discovery paths above (or pass it
   explicitly: `pi -e ./dcg-guard.ts`).
3. Ask Pi to run a known-destructive command, e.g. `git reset --hard HEAD~1`.
   Pi should refuse with the dcg reason instead of executing it.
4. Sanity-check the underlying decision directly:

   ```bash
   dcg --robot test "git reset --hard HEAD~1"; echo "exit=$?"   # exit=1 (denied)
   dcg --robot test "ls -la"; echo "exit=$?"                    # exit=0 (allowed)
   ```

## Limitations

Like every PreToolUse-style guardrail (Claude Code, Codex, Gemini, …), this
gates the *tool call*. A sufficiently determined model can still write a script
to disk and execute that, or use a tool other than `bash`. For a hard boundary,
run Pi inside a container or sandbox. dcg's pre-commit `scan` mode
([`docs/scan-precommit-guide.md`](scan-precommit-guide.md)) is a useful
second layer for the git path.

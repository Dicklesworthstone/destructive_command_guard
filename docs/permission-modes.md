# Permission Modes (v0.6)

> **Status:** Introduced in `dcg-core` 0.6.0-rc.1.

This document describes the permission-modes API added in dcg v0.6.
The API lets consumer applications (jcode, Codex, Hermes, Grok, agent
SDKs, …) link `dcg-core` directly and obtain a three-state decision
(`Allow` / `Prompt` / `Deny`) for each tool call, evaluated under a
configurable [`Mode`](#mode-enum).

The design closely follows [Claude Code's permission modes][cc-modes].

[cc-modes]: https://docs.anthropic.com/en/docs/claude-code/sdk/sdk-permissions

---

## Why this exists

dcg v0.5 was a binary hook: stdin JSON in, allow-or-deny verdict out.
That's enough for shell-level guardrails but doesn't compose with
agent frameworks that already have rich tool taxonomies, plan vs.
auto-edit modes, and per-session approval state.

v0.6 turns dcg into a Rust library (`dcg-core`) with a small,
stable public API:

```rust
use dcg_core::{Engine, EngineConfig, Mode, Session, ToolCall, Effect, Decision};

let engine = Engine::new(
    EngineConfig::builder()
        .working_dir("/work/project")
        .protected_paths(vec!["~/.ssh".into(), "~/.aws".into(), ".git".into()])
        .build(),
);
let mut session = Session::new();

let call = ToolCall::bash("git status");
let decision = engine.evaluate(&mut session, &call, Mode::Plan, &[Effect::Read]);

assert!(matches!(decision, Decision::Allow));
```

Consumers no longer shell out to a `dcg` binary — they call
`engine.evaluate()` directly, in-process, with no allocation or
serialization overhead beyond the call itself.

---

## Core types

### `Mode` enum

```rust
pub enum Mode {
    Default,
    AcceptEdits,
    Plan,
    DontAsk,
    BypassPermissions,
    Auto,
}
```

| Mode                | Behavior                                                                                          |
|---------------------|---------------------------------------------------------------------------------------------------|
| `Default`           | Standard rule-based evaluation. Unmatched commands fall through to `Allow`.                       |
| `AcceptEdits`       | Auto-approve `Read`/`Fs`/`Write` effects within the working dir. Network/Spawn/Irreversible → `Prompt`. Protected paths → `Prompt`. |
| `Plan`              | Read-only enforcement. Allow only `effects ⊆ {Read, Fs}`. Everything else → `Deny`.               |
| `DontAsk`           | Restricted-surface mode. Only explicit allow rules pass; everything else → `Deny`. Never `Prompt`. |
| `BypassPermissions` | Skip evaluation entirely and return `Allow`. **Use with caution.** Deny rules upstream still apply. |
| `Auto`              | **Phase C placeholder.** For v0.6 routes identically to `Default`.                                |

`Mode` parses both `camelCase` (Claude Code wire format) and
`snake_case`:

```rust
assert_eq!(Mode::parse("acceptEdits"), Some(Mode::AcceptEdits));
assert_eq!(Mode::parse("accept_edits"), Some(Mode::AcceptEdits));
```

### `ToolCall` enum

```rust
pub enum ToolCall {
    Bash    { cmd: String },
    Edit    { path: PathBuf },
    Write   { path: PathBuf },
    Read    { path: PathBuf },
    Network { url: String, method: String },
}
```

Consumers map their native tool taxonomy onto these five variants
(see [Integration guide](integration-guide.md)).

### `Effect` enum

Effects are the unit of analysis used by [`Mode`] policies.

| Effect           | Meaning                                                          |
|------------------|------------------------------------------------------------------|
| `Read`           | Reads filesystem, command output, or network responses.          |
| `Write`          | Writes data anywhere.                                             |
| `Network`        | Performs network I/O.                                             |
| `Spawn`          | Spawns a long-running process / background daemon.                |
| `Irreversible`   | Cannot be undone (`rm -rf`, `git push --force`, `DROP TABLE`, …). |
| `MutateVcs`      | Mutates VCS state (commits, branches, refs).                      |
| `Fs`             | Touches filesystem layout (`mkdir`, `mv`, `rm`).                  |

A tool call carries a *set* of effects; the mode policy checks subset
relationships (e.g. `Plan` allows iff `effects ⊆ {Read, Fs}`).

### `Decision` enum

```rust
pub enum Decision {
    Allow,
    Prompt {
        reason: String,
        allow_once_code: String,
        alternatives: Vec<String>,
    },
    Deny {
        reason: String,
        alternatives: Vec<String>,
    },
}
```

`allow_once_code` is a 6-hex-char short code that the consumer can
present to the user. On approval, the consumer calls
`session.consume_allow_once(code)` to record the exception. Codes are
single-use and expire after 24 hours.

### `Session`

Per-agent-run state: working directory, allow-once cache, per-command
deny counter. Replaces the v0.5 global `SessionTracker` `Mutex`.

```rust
let mut session = Session::with_working_dir("/work".into());

// Generate an allow-once code (called inside Engine::evaluate when it
// produces a Prompt decision):
let code = session.generate_allow_once_code("git push --force");

// Consume on user approval:
assert!(session.consume_allow_once(&code));
assert!(!session.consume_allow_once(&code), "single-use");
```

---

## Decision flow

```
┌─────────────────────────────────────────────┐
│  Engine::evaluate(session, tool, mode, fx)  │
└────────────────────┬────────────────────────┘
                     │
                     ▼
            Resolve protected path?
                     │
                     ▼
         ┌───────────────────────┐
         │  Mode::pre_check(…)   │
         └───┬───┬───┬───────────┘
             │   │   │
        Allow│   │Deny└── Prompt ────┐
             │   │                   ▼
             │   │           generate allow-once code
             │   │                   │
             │   │                   ▼
             │   │              return Prompt
             │   │
             │   └── return Deny
             │
             ▼
        return Allow
                     │
                     ▼
              Continue → fallthrough
                     │
       ┌─────────────┼──────────────┐
       │ Default/    │ DontAsk      │
       │ Auto        │              │
       │ AcceptEdits │              │
       │ → Allow     │ → Deny       │
       │             │ + bump_deny  │
       └─────────────┴──────────────┘
```

### Mode × ToolCall × Effect matrix (selected)

| Mode               | Tool                  | Effects                                  | Decision  |
|--------------------|-----------------------|------------------------------------------|-----------|
| `Default`          | `Bash("git status")`  | `[Read]`                                 | `Allow`   |
| `Plan`             | `Bash("git status")`  | `[Read]`                                 | `Allow`   |
| `Plan`             | `Bash("git push")`    | `[MutateVcs, Network]`                   | `Deny`    |
| `Plan`             | `Write(/work/foo)`    | `[Write, Fs]`                            | `Deny`    |
| `AcceptEdits`      | `Edit(/work/foo.rs)`  | `[Write, Fs]`                            | `Allow`   |
| `AcceptEdits`      | `Write(~/.ssh/id_rsa)`| `[Write, Fs]`                            | `Prompt`  |
| `AcceptEdits`      | `Bash("rm -rf x")`    | `[Write, Fs, Irreversible]`              | `Prompt`  |
| `BypassPermissions`| any                   | any                                      | `Allow`   |
| `DontAsk`          | `Bash("ls")`          | `[Read]`                                 | `Deny`    |

---

## Effect taxonomy & tagging

### Tier-A explicit (per-rule)

About 30-50 high-impact rules in core packs (`core.git`,
`core.filesystem`) carry explicit `effects` tags. Examples:

| Rule                       | Effects                                       |
|----------------------------|-----------------------------------------------|
| `core.git:reset-hard`      | `[MutateVcs, Irreversible]`                   |
| `core.git:push-force-long` | `[MutateVcs, Network, Irreversible]`          |
| `core.git:clean-force`     | `[Write, Fs, Irreversible]`                   |
| `core.git:stash-drop`      | `[MutateVcs, Irreversible]`                   |
| `core.fs:rm-rf-general`    | `[Write, Fs, Irreversible]`                   |
| `core.fs:dd-overwrite-general` | `[Write, Fs, Irreversible]`               |

### Tier-B pack default

Each pack declares a `default_effects` slice used as fallback for
rules without explicit tags.

| Pack              | `default_effects`              |
|-------------------|--------------------------------|
| `core.git`        | `[MutateVcs, Write]`           |
| `core.filesystem` | `[Write, Fs]`                  |
| any other pack    | `[Write, Irreversible]` (DEFAULT_PACK_EFFECTS) |

The conservative `[Write, Irreversible]` default ensures that an
unrecognized rule cannot silently auto-allow under `Mode::Plan` — it
will not match the `{Read, Fs}` allowed set and thus deny in Plan,
prompt in AcceptEdits.

### YAML schema (custom packs)

External (YAML) packs may declare both fields:

```yaml
schema_version: 1
id: example.deployment
name: Example Deployment Policies
version: 1.0.0

# Pack-level Tier-B fallback (optional)
default_effects:
  - mutate_vcs
  - write

destructive_patterns:
  - name: prod-direct-deploy
    pattern: \bdeploy\s+--env\s*=?\s*prod\b
    severity: critical
    description: Direct production deployment blocked
    # Per-rule Tier-A override (optional)
    effects:
      - network
      - irreversible
```

Both fields are optional. v0.5 packs (no `effects` / `default_effects`)
load unchanged and inherit `DEFAULT_PACK_EFFECTS = [Write, Irreversible]`.

---

## Protected paths

`Engine::new` takes a `protected_paths` list. Paths starting with `~/`
expand using [`dirs::home_dir`]; other relative paths are anchored to
the engine's `working_dir`.

```rust
EngineConfig::builder()
    .working_dir("/work/project")
    .protected_paths(vec![
        "~/.ssh".into(),
        "~/.aws".into(),
        ".git".into(),
        "/etc".into(),
    ])
    .build()
```

When a `ToolCall::Edit/Write/Read` targets a path inside any protected
prefix, `Mode::AcceptEdits` upgrades the decision to `Prompt`. Other
modes treat protected paths as informational (the prefix list is
exposed via `Engine::protected_paths().contains(p)` for consumer use).

---

## Backward compatibility

- **v0.5 binary clients** (CLI shell-out) keep working. The `dcg`
  binary still emits the same JSON deny output by default. A `--mode
  <NAME>` flag can opt into v0.6 mode evaluation.
- **v0.5 YAML packs** load against the v0.6 loader. Missing `effects`
  → `None` (per-rule); missing `default_effects` → `DEFAULT_PACK_EFFECTS`.
- **Decision verdicts** for existing rules are unchanged. The v0.6
  effects field is purely additive — it changes how `Mode::Plan` /
  `Mode::AcceptEdits` interpret a rule, not whether the rule fires.

`tests/backward_compat_v06.rs` enforces these invariants in CI.

---

## Out of scope (Phase C / future)

- **`Mode::Auto`** — model-classifier approvals. Variant is reserved
  but currently routes as `Default`.
- **Boundary API** — separate work for sandbox-style auto modes.
- **Streaming audit / programmatic approve** — Tier 3 of the original
  plan, deferred.
- **Daemon mode** — library link covers the v0.6 use case.

[`dirs::home_dir`]: https://docs.rs/dirs/latest/dirs/fn.home_dir.html

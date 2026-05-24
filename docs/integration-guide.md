# Integration Guide (v0.6)

> **Audience:** authors of agent frameworks (jcode, Codex, Hermes, Grok,
> custom in-house systems) embedding dcg as a Rust library.

For the binary hook protocol used by Claude Code / Codex CLI / Gemini
CLI / Cursor / etc., see the [main README](../README.md). This guide
covers the new `dcg-core` library API introduced in v0.6.

---

## Add the dependency

`dcg-core` is published on crates.io:

```toml
# Cargo.toml of the consumer crate
[dependencies]
dcg-core = "0.6"
```

For the full pack-rule library (50+ packs, heredoc scanning,
allowlists, history) link the higher-level `destructive_command_guard`
crate instead:

```toml
[dependencies]
destructive_command_guard = "0.6"
# Re-exports dcg-core types as well, so you only need one dep.
```

The `dcg-core` crate has minimal deps (`serde`, `regex`, `memchr`,
`aho-corasick`, `fancy-regex`, `sha2`, `chrono`, `dirs`). The
`destructive_command_guard` crate pulls in everything else (TUI,
self-update, MCP, history DB, …).

---

## Quick start

```rust
use std::path::PathBuf;
use dcg_core::{Engine, EngineConfig, Mode, Session, ToolCall, Effect, Decision};

fn main() {
    // 1. Build the engine once at startup.
    let engine = Engine::new(
        EngineConfig::builder()
            .working_dir(PathBuf::from("/work/project"))
            .protected_paths(vec![
                "~/.ssh".into(),
                "~/.aws".into(),
                ".git".into(),
                "/etc".into(),
            ])
            .build(),
    );

    // 2. One Session per agent run / conversation.
    let mut session = Session::with_working_dir(PathBuf::from("/work/project"));

    // 3. For each tool call, decide what to do.
    let call = ToolCall::bash("git status");
    let decision = engine.evaluate(&mut session, &call, Mode::Plan, &[Effect::Read]);

    match decision {
        Decision::Allow => {
            // Run the tool.
        }
        Decision::Prompt { reason, allow_once_code, alternatives } => {
            // Show the reason to the user. If approved, call:
            //   session.consume_allow_once(&allow_once_code);
            // and proceed with the tool call.
            eprintln!("Confirm? {reason} (code: {allow_once_code})");
            for alt in alternatives {
                eprintln!("  alternative: {alt}");
            }
        }
        Decision::Deny { reason, alternatives } => {
            // Block the tool.
            eprintln!("Blocked: {reason}");
            for alt in alternatives {
                eprintln!("  try: {alt}");
            }
        }
    }
}
```

---

## Mapping your tool taxonomy

`dcg-core::ToolCall` has five variants: `Bash`, `Edit`, `Write`,
`Read`, `Network`. Map your native tool catalog onto these:

```rust
fn classify(tool: &MyTool) -> dcg_core::ToolCall {
    match tool {
        // Shell execution
        MyTool::Bash(cmd)               => ToolCall::bash(cmd),
        MyTool::RunTerminalCmd(cmd)     => ToolCall::bash(cmd),
        MyTool::Terminal(cmd)           => ToolCall::bash(cmd),

        // Read-only file ops
        MyTool::Read(p) | MyTool::Glob(p) | MyTool::Ls(p) => ToolCall::read(p),
        MyTool::Grep { path, .. }       => ToolCall::read(path),

        // Edit / write
        MyTool::Edit(p) | MyTool::MultiEdit(p) | MyTool::ApplyPatch(p)
            => ToolCall::edit(p),
        MyTool::Write(p)                => ToolCall::write(p),

        // Network
        MyTool::WebSearch(url)          => ToolCall::network(url, "GET"),
        MyTool::WebFetch(url, method)   => ToolCall::network(url, method),
        MyTool::Browser(url)            => ToolCall::network(url, "GET"),
    }
}
```

The five variants are intentionally narrow. If your taxonomy needs
finer distinctions (e.g. `Memory` operations that aren't quite `Read`
nor `Write`), use the closest match and add your own pre-check if
needed. The engine doesn't see your full type — it only consumes the
five variants.

---

## Resolving effects

`Engine::evaluate` takes an `effects: &[Effect]` slice. This is the
**caller's** estimate of what the tool call will do. For pure shell
calls (`ToolCall::Bash`), you can compute effects from your own rule
tables, or use the `destructive_command_guard` crate's pack registry:

```rust
use destructive_command_guard::{Pack, packs::PackRegistry};

fn effects_for_command(cmd: &str, registry: &PackRegistry) -> Vec<Effect> {
    // Walk enabled packs; return the first matching rule's resolved
    // effects (Tier-A override, falling back to pack default_effects).
    for pack in registry.iter_enabled() {
        if !pack.might_match(cmd) {
            continue;
        }
        if let Some(matched) = pack.find_destructive_match(cmd) {
            return pack.resolve_effects(matched).to_vec();
        }
    }
    Vec::new()
}
```

For typed tools (`Read`, `Write`, `Edit`, `Network`), you can hard-code
sensible effects:

```rust
fn typed_effects(tool: &ToolCall) -> Vec<Effect> {
    match tool {
        ToolCall::Read { .. }    => vec![Effect::Read, Effect::Fs],
        ToolCall::Edit { .. }    => vec![Effect::Write, Effect::Fs],
        ToolCall::Write { .. }   => vec![Effect::Write, Effect::Fs],
        ToolCall::Network { method, .. } => {
            if method.eq_ignore_ascii_case("GET") {
                vec![Effect::Network, Effect::Read]
            } else {
                vec![Effect::Network, Effect::Write]
            }
        }
        ToolCall::Bash { cmd } => effects_for_command(cmd, &registry),
    }
}
```

---

## Allow-once approval flow

When `Engine::evaluate` returns `Decision::Prompt`, the caller is
responsible for asking the user. The decision carries a 6-hex-char
`allow_once_code` which the caller can show in the prompt:

```rust
let decision = engine.evaluate(&mut session, &call, mode, &effects);
if let Decision::Prompt { reason, allow_once_code, alternatives } = decision {
    println!("{reason}");
    println!("Approve? (Y/n) [code: {allow_once_code}]");

    if user_approves() {
        // Mark the code consumed in the session. After this, the
        // same code cannot be reused.
        let ok = session.consume_allow_once(&allow_once_code);
        assert!(ok, "code should still be valid");
        run_tool(call);
    }
}
```

`Session::approve_with_code` is a convenience helper that does the
match-and-consume in one call:

```rust
let decided = session.approve_with_code(&user_supplied_code, decision);
if let Decision::Allow = decided {
    run_tool(call);
}
```

---

## Bridging with the legacy hook protocol

If your consumer needs both:

1. The new `Mode`-aware library API (for in-process tool calls)
2. The legacy stdin-JSON hook protocol (for shelling out to existing
   `dcg` binaries)

…use `destructive_command_guard::permission_modes::evaluate_with_mode`
which combines pack rule evaluation with mode policy in one call:

```rust
use destructive_command_guard::{
    config::Config, allowlist::LayeredAllowlist, evaluate_with_mode,
    Engine, EngineConfig, Mode, Session,
};

let cfg = Config::load();
let allowlists = LayeredAllowlist::load_default();
let overrides = cfg.overrides.compile();
let engine = Engine::new(EngineConfig::default());
let mut session = Session::new();

let decision = evaluate_with_mode(
    "git push --force",
    &cfg,
    &enabled_keywords,
    &overrides,
    &allowlists,
    &engine,
    &mut session,
    Mode::Default,
);
```

This is the easiest migration path for existing dcg shell-out
consumers — drop the subprocess call, link the library, get the same
verdict plus mode awareness.

---

## Performance

- `Engine::evaluate` is non-allocating on the fast path (allow without
  pre-check). The `Decision::Allow` variant is a unit construct.
- `Session` is `Clone`, so consumers can hand it to subagent threads
  by value if needed.
- The compiled protected-path list is shared via `Engine`, not
  rebuilt per call.
- Allow-once code generation is O(1) SHA-256 of (session_id ||
  command_hash). No I/O.

---

## Versioning

`dcg-core` follows semver. The 0.6.x line will not break the public
API surface. Major changes (`0.7`, `1.0`) will be signaled by
deprecations one minor version in advance.

The `destructive_command_guard` crate (the higher-level library +
binary) follows its own version line; both crates are kept in sync at
release time.

---

## See also

- [`docs/permission-modes.md`](permission-modes.md) — Mode/Effect
  reference, decision flow.
- [`docs/custom-packs.md`](custom-packs.md) — authoring custom YAML
  packs, including v0.6 `effects` schema.
- [`CHANGELOG.md`](../CHANGELOG.md) — v0.6 release notes.

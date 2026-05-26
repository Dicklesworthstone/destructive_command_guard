# dcg-core

Core library for [Destructive Command Guard][dcg] (dcg) v0.6.

This crate provides the permission-modes API that consumer applications
(`dcg` CLI, jcode, Codex, Hermes, Grok, …) can link against directly without
pulling in CLI/TUI/MCP dependencies.

## Status

`0.6.0-rc.1` — work in progress. API may still change before `0.6.0` final.

## Features

- `Engine::evaluate(&Session, &ToolCall, Mode) -> Decision` — tool-aware command guard
- `Mode { Default, AcceptEdits, Plan, DontAsk, BypassPermissions, Auto }` — permission modes (Claude Code-aligned)
- `Effect { Read, Write, Network, Spawn, Irreversible, MutateVcs, Fs }` — effect taxonomy for plan/auto modes
- `Decision { Allow, Prompt, Deny }` — three-state decision with allow-once codes and alternatives
- `Session` — in-memory state for allow-once cache and deny counters

## Design goals

- Minimal dep footprint (no tokio, no async, no TUI deps)
- Stable, semver-compatible API
- Suitable for embedding in any Rust agent framework

[dcg]: https://github.com/Dicklesworthstone/destructive_command_guard

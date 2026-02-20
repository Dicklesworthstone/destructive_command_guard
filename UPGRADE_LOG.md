# Dependency Upgrade Log

**Date:** 2026-02-19  |  **Project:** destructive_command_guard (dcg)  |  **Language:** Rust

## Summary
- **Updated:** 12 (Cargo.toml version bumps) + 82 semver-compatible lockfile updates
- **Skipped:** 3  |  **Failed:** 0  |  **Needs attention:** 1

## Phase 1: Semver-Compatible Updates (cargo update)

82 transitive packages updated within existing version ranges. All 1935 tests passed.

Key updates: clap 4.5.54 → 4.5.60, regex 1.12.2 → 1.12.3, memchr 2.7.6 → 2.8.0,
rust-mcp-sdk 0.8.2 → 0.8.3, tokio (transitive deps), tree-sitter 0.26.3 → 0.26.5.

## Phase 2: Breaking Version Bumps

### rust-mcp-sdk: 0.8.1 → 0.8.3
- **Breaking:** None (patch bump, already resolved by cargo update)
- **Tests:** Passed

### fancy-regex: 0.14 → 0.17
- **Breaking:** None (new features only: split(), splitn(), RegexBuilder options)
- **Tests:** Passed

### colored: 2.1 → 3.1
- **Breaking:** MSRV bump to 1.80+ (we use nightly, no issue). lazy_static removed internally.
- **Code changes:** None
- **Tests:** Passed

### dirs: 5.0 → 6.0
- **Breaking:** None (dependency maintenance release, full API compat)
- **Tests:** Passed

### console: 0.15 → 0.16
- **Breaking:** `std` feature flag introduced (enabled by default)
- **Code changes:** None
- **Tests:** Passed

### indicatif: 0.17 → 0.18
- **Breaking:** Depends on console 0.16, switched number_prefix to unit-prefix
- **Code changes:** None
- **Tests:** Passed

### inquire: 0.7 → 0.9
- **Breaking:** RenderConfig now Copy, bitflags v2, MSRV 1.82+
- **Code changes:** None (our usage doesn't touch RenderConfig directly)
- **Tests:** Passed

### toml: 0.8 → 1.0
- **Breaking:** Deserializer::new() returns Result, FromStr for Value changed
- **Code changes:** None (our usage is all toml::from_str/to_string_pretty which are unchanged)
- **Tests:** Passed

### toml_edit: 0.22 → 0.25
- **Breaking:** InternalString removed, Time fields wrapped in Option, table position changes
- **Code changes:** None (our usage is DocumentMut, Table, value(), ArrayOfTables)
- **Tests:** Passed

### rusqlite: 0.35 → 0.38
- **Breaking:** u64/usize ToSql/FromSql changes, statement caching optional, SQLite 3.34.1 min
- **Code changes:** None (we use bundled SQLite and don't use u64/usize conversions)
- **Tests:** Passed

### rand: 0.8 → 0.10
- **Breaking:** thread_rng() → rng(), gen_range() → random_range(), Rng → RngExt, features renamed
- **Code changes:**
  - `src/interactive.rs`: `use rand::Rng` → `use rand::RngExt`
  - `src/interactive.rs`: `rand::thread_rng()` → `rand::rng()`
  - `src/interactive.rs`: `.gen_range()` → `.random_range()`
  - `Cargo.toml`: features changed from `["std", "std_rng"]` to `["std", "thread_rng"]`
- **Tests:** Passed

### criterion: 0.5 → 0.8 (dev-dependency)
- **Breaking:** `criterion::black_box` deprecated in favor of `std::hint::black_box`
- **Code changes:**
  - `benches/heredoc_perf.rs`: Switched to `use std::hint::black_box`
  - `benches/regex_automata_comparison.rs`: Switched to `use std::hint::black_box`
- **Tests:** Passed

### which: 7.0 → 8.0 (dev-dependency)
- **Breaking:** Minor API changes
- **Code changes:** None
- **Tests:** Passed

## Skipped

### serde_yaml: 0.9 (deprecated)
- **Reason:** Crate is deprecated; successor is `serde_yml` or `serde_yaml_ng`. Migration requires evaluating replacements. Logged for future work.

### vergen-gix: 10.0.0-beta.5 (pre-release)
- **Reason:** Already on latest pre-release. Stable max is 9.1.0. Staying on beta track.

### rich_rust: 0.2.0
- **Reason:** Already on latest stable version.

## Needs Attention

### serde_yaml deprecation
- The `serde_yaml` crate (0.9.x) is officially deprecated. Consider migrating to `serde_yml` or `serde_yaml_ng` in a future session.

## Validation
- `cargo fmt --check`: Passed
- `cargo clippy --all-targets -- -D warnings`: Passed
- `cargo test --lib`: 1935/1935 passed

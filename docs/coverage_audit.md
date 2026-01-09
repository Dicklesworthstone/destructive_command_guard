# DCG Coverage Audit & Mock Inventory

**Date**: 2026-01-09
**Bead**: git_safety_guard-xqv

## Executive Summary

This audit establishes a baseline coverage map, inventories mock/fake usage in tests, and provides concrete replacement strategies.

## Test Summary

| Category | Count | Status |
|----------|-------|--------|
| Unit tests (main binary) | 105 | PASS |
| Integration tests (regression_corpus) | 5 | PASS |
| Doc tests | 1 passed, 9 ignored | PASS |
| **Total** | **111** | **PASS** |

### Tests Under Coverage Instrumentation

When running with `cargo llvm-cov`, 28 tests fail due to timeout/performance issues:

| Module | Failures | Root Cause |
|--------|----------|------------|
| `heredoc::tests::tier2_extraction` | 13 | 50ms timeout budget exceeded under instrumentation |
| `ast_matcher::tests::javascript_*` | 7 | AST parsing timeout with coverage overhead |
| `ast_matcher::tests::typescript_*` | 4 | AST parsing timeout with coverage overhead |
| `ast_matcher::tests::perl_*` | 2 | AST parsing timeout with coverage overhead |
| `ast_matcher::tests::ruby_*` | 2 | AST parsing timeout with coverage overhead |

**Recommendation**: Increase timeout budgets when running under coverage, or use `#[cfg(not(coverage))]` conditional compilation for strict timing tests.

## Coverage by Module (Estimated)

Based on test distribution and code review:

| Module | Estimated Coverage | Notable Gaps |
|--------|-------------------|--------------|
| `main.rs` | ~80% | Input size limits (new code), edge cases |
| `evaluator.rs` | ~85% | Allowlist override edge cases |
| `hook.rs` | ~75% | Error paths, colorful output truncation |
| `config.rs` | ~90% | Policy merge edge cases |
| `packs/*.rs` | ~85% | Some pattern edge cases |
| `heredoc.rs` | ~60% | Tier 2/3 extraction (timeout-sensitive) |
| `ast_matcher.rs` | ~50% | JS/TS/Perl/Ruby patterns (timeout issues) |
| `context.rs` | ~80% | Complex tokenization cases |
| `allowlist.rs` | ~85% | Layer precedence edge cases |
| `trace.rs` | ~40% | Explain mode output formatting |
| `scan.rs` | ~30% | Repository scanning (minimal tests) |
| `simulate.rs` | ~20% | New module, minimal test coverage |

### Proposed Coverage Thresholds for CI

| Threshold | Initial Target | Stretch Goal |
|-----------|----------------|--------------|
| Overall | 70% | 85% |
| Critical modules (evaluator, hook) | 80% | 90% |
| Non-critical (trace, scan) | 50% | 70% |

## Mock/Fake Inventory

### 1. MockSafePattern / MockDestructivePattern (evaluator.rs)

**Location**: `src/evaluator.rs:1460-1493`

```rust
struct MockSafePattern {
    regex: Regex,
}

impl LegacySafePattern for MockSafePattern { ... }

struct MockDestructivePattern {
    regex: Regex,
    reason: String,
}

impl LegacyDestructivePattern for MockDestructivePattern { ... }
```

**Usage**: Tests at lines 1492, 1542, 1595, 1637, 1677, 1727

**Purpose**: Allows testing the `run_evaluation_pipeline` function without loading actual pack patterns.

**Replacement Strategy**:
1. **Option A (Recommended)**: Replace with real pack fixtures from `REGISTRY`
   - Use `REGISTRY.get_pack("core.git")` to get actual patterns
   - Tests become integration-level but verify real behavior
2. **Option B**: Create a test fixture module with pre-compiled patterns
   - Move mock definitions to `src/test_fixtures.rs`
   - Share across test modules

**Effort**: Medium (3-5 hours)
**Priority**: P2

### 2. Dummy Paths in Allowlist Tests (allowlist.rs)

**Location**: `src/allowlist.rs:632, 645, 659, 675, 689`

```rust
let file = parse_allowlist_toml(AllowlistLayer::Project, Path::new("dummy"), toml);
```

**Purpose**: Tests parsing logic without needing real files.

**Replacement Strategy**:
- Keep as-is - these are appropriate test doubles for parsing logic
- The `Path::new("dummy")` is used only for error messages/debugging
- No behavioral coupling to actual filesystem

**Effort**: N/A (acceptable pattern)
**Priority**: P4 (no action needed)

### 3. Fake Pack IDs in CLI Tests (cli.rs)

**Location**: `src/cli.rs:4870, 4876-4877`

```rust
assert!(!is_valid_pack_id("fake.pack"));
assert!(!is_valid_pack_id("containers.fake"));
```

**Purpose**: Tests validation of invalid pack identifiers.

**Replacement Strategy**:
- Keep as-is - these test negative cases correctly
- Using obviously-fake IDs like "fake.pack" is the right approach

**Effort**: N/A (acceptable pattern)
**Priority**: P4 (no action needed)

## Replacement Plan Summary

| Mock/Fake | Location | Action | Priority | Effort |
|-----------|----------|--------|----------|--------|
| MockSafePattern | evaluator.rs:1460 | Replace with real pack fixtures | P2 | 3-5h |
| MockDestructivePattern | evaluator.rs:1471 | Replace with real pack fixtures | P2 | (included above) |
| Path::new("dummy") | allowlist.rs | Keep (appropriate) | P4 | N/A |
| "fake.pack" test data | cli.rs | Keep (appropriate) | P4 | N/A |

## Compilation Issues Fixed

During this audit, the following issues were identified and fixed:

1. **Missing `Read` import** (`src/main.rs:40`)
   - Changed: `use std::io::{self, BufRead, IsTerminal}` → `use std::io::{self, IsTerminal, Read}`
   - Reason: `take()` method requires `Read` trait in scope

2. **Private `merge` method** (`src/config.rs:752`)
   - Changed: `fn merge` → `pub(crate) fn merge`
   - Reason: Tests in main.rs need to access this method

## Clippy Warnings

The following clippy warnings exist (all pedantic/nursery, not blocking):

| File | Warning | Category |
|------|---------|----------|
| simulate.rs:481 | must_use_candidate | pedantic |
| simulate.rs:507 | doc_markdown | pedantic |
| simulate.rs:555 | doc_markdown | pedantic |
| simulate.rs:557 | doc_markdown | pedantic |
| simulate.rs:595 | doc_markdown | pedantic |
| simulate.rs:657 | must_use_candidate | pedantic |
| simulate.rs:735 | must_use_candidate | pedantic |
| simulate.rs:823 | missing_errors_doc | pedantic |
| main.rs:467 | significant_drop_tightening | nursery |

## Recommendations

1. **Immediate**: Run `cargo clippy --fix` to resolve doc formatting warnings
2. **Short-term**: Replace evaluator mock structs with real pack fixtures (blocks git_safety_guard-1g6)
3. **Medium-term**: Increase heredoc/AST timeout budgets for coverage runs
4. **Long-term**: Add tests for scan.rs and simulate.rs modules

## Next Steps (Downstream Beads)

This audit unblocks:
- `git_safety_guard-1g6`: Replace evaluator mock tests with real pack fixtures
- `git_safety_guard-484`: Coverage: no-mock unit tests + gating
- `git_safety_guard-64n`: Replace remaining mocks/fakes with real integration fixtures
- `git_safety_guard-rl8`: Enforce coverage thresholds in CI (llvm-cov)

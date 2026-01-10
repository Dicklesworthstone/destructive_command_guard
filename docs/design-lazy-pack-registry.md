# Design: Lazy Pack Registry + Lazy Regex Compilation

Goal: eliminate eager regex compilation from the hot path while preserving
behavior and attribution exactly (isomorphism).

## Goals

- List packs/keywords without compiling regex.
- Allow-path quick-reject without compiling regex.
- Compile regex only for enabled packs actually evaluated.
- Preserve ordering, attribution, and fail-open behavior.

## Non-Goals

- Changing patterns, policy, or allow/deny semantics.
- Altering pack ordering or safe-before-destructive logic.
- Introducing a daemon or persistent service.

## Proposed Types (metadata-only packs)

### PackSpec

```rust
pub struct PackSpec {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub keywords: &'static [&'static str],
    pub safe_patterns: &'static [SafePatternSpec],
    pub destructive_patterns: &'static [DestructivePatternSpec],
}
```

### SafePatternSpec

```rust
pub struct SafePatternSpec {
    pub name: &'static str,
    pub pattern: &'static str,
    pub compiled: std::sync::OnceLock<CompiledRegex>,
}
```

### DestructivePatternSpec

```rust
pub struct DestructivePatternSpec {
    pub name: Option<&'static str>,
    pub pattern: &'static str,
    pub reason: &'static str,
    pub severity: Severity,
    pub compiled: std::sync::OnceLock<CompiledRegex>,
}
```

### Lazy Compile API

```rust
impl SafePatternSpec {
    pub fn is_match(&self, haystack: &str) -> bool;
    pub fn find_span(&self, haystack: &str) -> Option<(usize, usize)>;
}

impl DestructivePatternSpec {
    pub fn is_match(&self, haystack: &str) -> bool;
    pub fn find_span(&self, haystack: &str) -> Option<(usize, usize)>;
}
```

- `CompiledRegex` comes from `src/packs/regex_engine.rs` and auto-selects
  linear vs backtracking engine.
- `OnceLock::get_or_init` is used on first match attempt only.

## Registry Structure

`PackRegistry` stores only `PackSpec` (no compiled regex).

Derived data:
- `keywords` list is computed from `PackSpec.keywords`.
- `expand_enabled_ordered` uses pack IDs only.

Evaluation:
- **Safe pass:** iterate safe patterns across enabled packs; on first match
  return allow.
- **Destructive pass:** iterate destructive patterns across enabled packs;
  return the first match (respecting severity/mode).

Compilation happens only when a pattern is actually evaluated.

## Isomorphism Guarantees

1) **Ordering unchanged**
   - Same `expand_enabled_ordered` tier + lexicographic sort.
2) **Safe-before-destructive unchanged**
   - Two-pass evaluation preserved.
3) **Attribution unchanged**
   - Pack ID and pattern name sourced from the same specs; no renaming.
4) **Allowlist scope unchanged**
   - Allowlisting still bypasses only the matched rule, not the pack.
5) **Fail-open unchanged**
   - Regex execution errors still treated as non-match.
6) **Decision parity**
   - For any command, the first matching rule (by order) and its reason are
     identical to the eager-compile version.

## Handling Compile Errors (Parity)

Current behavior panics early on invalid patterns due to `Regex::new(...).expect`.

With lazy compilation, compile errors would shift to first use. To preserve
"invalid patterns are caught immediately" in dev/test without penalizing
production:

- Add a test `all_pack_patterns_compile` that explicitly compiles every
  pattern under `#[cfg(test)]`.
- Optional CLI: `dcg packs --validate` to force compile all patterns.

## Migration Plan (Phased)

1) **Introduce specs + lazy regex primitive**
   - Add `SafePatternSpec` / `DestructivePatternSpec` with `OnceLock`.
   - Reuse `CompiledRegex` (no behavior change yet).

2) **Refactor pack definitions**
   - Replace `Vec<SafePattern>` with static arrays of `SafePatternSpec`.
   - Replace `Vec<DestructivePattern>` with static arrays of `DestructivePatternSpec`.

3) **Registry metadata-only**
   - `PackRegistry::new` builds only `PackSpec` and keywords.
   - No regex compilation on init.

4) **Evaluator wiring**
   - Safe/destructive passes call `spec.is_match()` which compiles lazily.

5) **Parity guardrails**
   - Add `all_pack_patterns_compile` test.
   - Add regression corpus parity test: eager vs lazy output identical.

## Integration Points

- `src/packs/mod.rs`: Pack/Pattern type refactor and registry construction.
- `src/packs/regex_engine.rs`: Lazy compile backing type (`CompiledRegex`).
- `src/evaluator.rs`: Pattern match calls use lazy spec API.
- `src/main.rs`: Pack keyword gating remains metadata-only.

## Success Criteria

- `dcg packs --enabled` is metadata-only (no regex compile).
- Hook allow path performs no regex compilation.
- Golden/e2e parity unchanged for allow/deny outcomes and reasons.

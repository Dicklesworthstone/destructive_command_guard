# ADR-001: Heredoc Scanning Architecture

## Status

**Accepted** (2026-01-08)

## Context

### Problem Statement

dcg currently blocks destructive commands via regex pattern matching on the raw command string. However, attackers or accidental misuse can embed destructive code inside heredocs, here-strings, or inline interpreter flags (`python -c`, `bash -c`), bypassing pattern detection.

Example bypass:
```bash
cat <<EOF | bash
rm -rf /important
EOF
```

The outer command (`cat <<EOF | bash`) doesn't match any destructive pattern, but the embedded code is dangerous.

### Constraints

1. **Performance**: dcg runs on EVERY bash command. Total latency budget: <10ms typical, <50ms worst-case
2. **False Positives**: Must not block legitimate heredocs (deployment scripts, SQL migrations, config generation)
3. **Dependencies**: Minimize binary size impact; avoid external process dependencies
4. **Maintenance**: Pattern library must be extensible without core code changes
5. **Fail-Open**: In hook mode, timeouts/parse errors must ALLOW (not block) to avoid breaking user workflows

### Options Considered

| Option | Latency | Binary Size | Maintenance | FP Control |
|--------|---------|-------------|-------------|------------|
| A. External ast-grep CLI | 10-50ms | 0 | Low | High |
| B. ast-grep-core (embedded) | <5ms | +2-4MB | Medium | High |
| C. tree-sitter direct | <5ms | +1-2MB/grammar | High | Medium |
| D. Regex-only | <1ms | 0 | Low | Low |

## Decision

**Use ast-grep-core (embedded) with a tiered detection architecture.**

### Architecture: Three-Tier Detection

```
Command Input
     │
     ▼
┌─────────────────────┐
│ Tier 0: Pack Gate   │ ─── No keywords ──► ALLOW (fast path, <10μs)
│ (pack_aware_quick_  │
│  reject)            │
└─────────┬───────────┘
          │ Keywords found
          ▼
┌─────────────────────┐
│ Tier 1: Trigger     │ ─── No match ──► Continue to pack patterns
│ (RegexSet, <100μs)  │
└─────────┬───────────┘
          │ Heredoc/inline detected
          ▼
┌─────────────────────┐
│ Tier 2: Extract     │ ─── Error/Timeout ──► ALLOW + diagnostic
│ (<1ms, bounded)     │
└─────────┬───────────┘
          │ Content + language
          ▼
┌─────────────────────┐
│ Tier 3: AST Scan    │ ─── No match ──► ALLOW
│ (ast-grep-core,     │ ─── Match ──► BLOCK
│  <5ms, timeout 20ms)│
└─────────────────────┘
```

### Tier Details

#### Tier 0: Pack-Aware Quick Reject (existing)

- Uses `pack_aware_quick_reject()` with SIMD-accelerated keyword search
- If no enabled pack keywords found → early return
- Budget: <10μs

#### Tier 1: Heredoc/Inline Trigger Detection

Triggers (RegexSet):
- `<<-?\s*['\"]?\w+['\"]?` (heredoc operators)
- `<<<` (here-strings)
- `\b(python3?|ruby|perl|node)\s+-[ce]\s` (inline scripts)
- `\b(sh|bash|zsh)\s+-c\s` (shell inline)
- `\|\s*(python3?|ruby|perl|node|sh|bash)\b` (pipe to interpreter)

Budget: <100μs
Guarantees: ZERO false negatives for supported forms

#### Tier 2: Content Extraction

Bounded extraction with hard limits:
- `max_body_bytes`: 1MB per heredoc
- `max_body_lines`: 10,000 per heredoc
- `max_heredocs`: 10 per command
- `timeout_ms`: 50ms total

Language detection priority (from git_safety_guard-jfj):
1. Inline interpreter flag (`python -c` → Python, High confidence)
2. Receiving command (`python <<EOF` → Python, High confidence)
3. Delimiter hints (`<<SQL`, `<<PY` → SQL/Python, Medium)
4. Content heuristics (shebang, imports → Medium/Low)

Budget: <1ms typical

#### Tier 3: AST Pattern Matching

Uses ast-grep-core for structural pattern matching:
- Language-specific patterns from pattern library
- Composite matchers: regex trigger + AST validation
- Timeout protection: 20ms hard limit

Budget: <5ms typical, 20ms max

### Pattern Library

Format defined in `docs/pattern-library-design.md`:

```rust
pub struct HeredocPattern {
    pub id: &'static str,        // Stable rule ID
    pub language: Language,
    pub matcher: PatternMatcher,
    pub reason: &'static str,
    pub suggestion: Option<&'static str>,  // Safe alternative
    pub severity: Severity,
    pub fp_notes: Option<&'static str>,    // FP risk documentation
}
```

Severity taxonomy:
- **Critical**: Always block (e.g., `shutil.rmtree`, `fs.rmSync({recursive:true})`)
- **High**: Block by default, allowlistable
- **Medium**: Warn by default
- **Low**: Log only

Pack integration:
- New `heredoc.*` category (heredoc.python, heredoc.bash, heredoc.javascript, etc.)
- Patterns only evaluated when Tier 1/2 trigger
- Stable rule IDs for allowlisting: `heredoc.{language}.{operation}`

### Integration Points

#### With Existing Pack System

Heredoc detection runs AFTER pack-aware quick reject but BEFORE regular pack pattern matching:

```
Command → Quick Reject → Heredoc Detection → Pack Patterns → Default Allow
```

If heredoc detection blocks, skip pack patterns (already decided).

#### With Execution Context Classification (git_safety_guard-t8x)

Heredoc patterns should respect execution context:
- Code in comments → Lower severity
- Code in strings → Lower severity
- Code being echoed → Lower severity

#### With Config Overrides

Users can allowlist by stable rule ID:
```toml
[allow]
rules = ["heredoc.python.subprocess_rm_rf"]
```

### Performance Budgets

| Component | Target | Panic Threshold |
|-----------|--------|-----------------|
| Quick reject | <10μs | >100μs |
| Tier 1 trigger | <10μs match, <100μs total | >500μs |
| Tier 2 extract | <500μs | >2ms |
| Tier 3 AST | <5ms | >20ms |
| **Total heredoc path** | <10ms | >50ms |

### Error Handling

**All tiers follow fail-open semantics in hook mode:**

| Error | Behavior | Diagnostic |
|-------|----------|------------|
| Tier 1 regex error | ALLOW | Log + mark for review |
| Tier 2 extraction timeout | ALLOW | Emit `heredoc_extraction_timeout` marker |
| Tier 2 malformed heredoc | ALLOW | Emit `heredoc_parse_error` marker |
| Tier 3 AST parse error | ALLOW | Emit `ast_parse_error` marker |
| Tier 3 timeout | ALLOW | Emit `ast_timeout` marker |
| Unknown language | ALLOW | Emit `unknown_language` marker |

Rationale: A hung or crashed hook is worse than a missed detection. Diagnostics enable `dcg explain` to surface issues for review.

## Consequences

### Benefits

1. **No process spawn overhead**: ast-grep-core is embedded, avoiding 10-50ms CLI latency
2. **Structural matching**: AST patterns avoid false positives from comments/strings
3. **Extensible**: Pattern library can grow without core code changes
4. **Fail-safe**: Fail-open design prevents blocking legitimate workflows
5. **Explainable**: Stable rule IDs enable precise allowlisting

### Drawbacks

1. **Binary size increase**: +2-4MB for ast-grep-core + grammars
2. **Compile time increase**: +20-30s for grammar compilation
3. **Maintenance burden**: Pattern library requires ongoing curation
4. **Complexity**: Three-tier architecture is more complex than regex-only

### Mitigations

- Feature flags for language grammars (compile only what's needed)
- Pattern library validation in CI
- Comprehensive test fixtures for each pattern
- Documentation of all supported heredoc forms

## Technical Details

### Cargo.toml Changes

```toml
[dependencies]
ast-grep-core = { version = "0.40", optional = true }

[features]
default = ["heredoc"]
heredoc = ["ast-grep-core"]
```

### New Modules

- `src/heredoc/mod.rs` - Tier orchestration
- `src/heredoc/trigger.rs` - Tier 1 RegexSet triggers
- `src/heredoc/extract.rs` - Tier 2 content extraction
- `src/heredoc/language.rs` - Language detection
- `src/heredoc/patterns/` - Per-language pattern definitions

### Data Flow

```
HookInput {command}
    ↓
pack_aware_quick_reject(command, keywords) == false?
    ↓ (if false = keywords present, proceed)
HeredocTrigger::check(command)
    ↓ (if triggered)
HeredocExtractor::extract(command)
    ↓
LanguageDetector::detect(payload, context)
    ↓
AstMatcher::find_matches(content, language)
    ↓
CheckResult {blocked, reason, rule_id}
```

Note: `pack_aware_quick_reject()` returns `true` if safe to skip (no keywords),
`false` if keywords present and further checking is needed.

## References

- `docs/pattern-library-design.md` - Pattern metadata schema
- `git_safety_guard-o15` - Heredoc detection strategy (GreenHarbor)
- `git_safety_guard-jfj` - Language detection heuristics (GreenHarbor)
- `git_safety_guard-2j3` - Tree-sitter research (SilverCreek)
- `git_safety_guard-boy` - Embedded vs external evaluation (SilverCreek)
- `git_safety_guard-6sg` - Pattern library design (SilverCreek)

## Decision Record

| Date | Author | Change |
|------|--------|--------|
| 2026-01-08 | SilverCreek | Initial ADR created |

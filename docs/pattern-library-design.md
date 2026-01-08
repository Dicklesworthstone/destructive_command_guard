# Pattern Library Design Specification

## Decision: Hybrid Approach (Rust + TOML extensions)

**Rationale:** Core patterns hardcoded in Rust for performance and type safety. Optional user extensions via TOML for flexibility.

---

## 1. Pattern Metadata Schema

### HeredocPattern struct (Rust)

```rust
/// A destructive pattern for heredoc/inline script scanning.
pub struct HeredocPattern {
    /// Stable rule ID: "{pack_id}.{pattern_name}"
    /// Example: "heredoc.python.shutil_rmtree"
    pub id: &'static str,

    /// Target language for this pattern.
    pub language: Language,

    /// Pattern matcher (regex or AST).
    pub matcher: PatternMatcher,

    /// Human-readable explanation.
    pub reason: &'static str,

    /// Suggestion for safe alternative.
    pub suggestion: Option<&'static str>,

    /// Severity level (affects default mode).
    pub severity: Severity,

    /// False positive risk notes (for maintainers).
    pub fp_notes: Option<&'static str>,
}

pub enum Language {
    Python,
    Bash,
    JavaScript,
    TypeScript,
    Ruby,
    Perl,
    Go,
    Php,
    Unknown,
}

pub enum PatternMatcher {
    /// Simple regex (Tier 1 compatible).
    Regex(Regex),

    /// AST pattern for ast-grep-core.
    Ast(String),

    /// Composite: regex trigger + AST validation.
    Composite {
        trigger: Regex,
        validator: String,
    },
}

pub enum Severity {
    /// Always block (irreversible + high confidence).
    Critical,

    /// Block by default, allowlistable.
    High,

    /// Warn by default, blockable via config.
    Medium,

    /// Log only (for telemetry/learning).
    Low,
}
```

---

## 2. Stable Rule ID Format

Pattern: `{category}.{language}.{operation}[.{variant}]`

Examples:
- `heredoc.python.shutil_rmtree`
- `heredoc.python.subprocess_rm_rf`
- `heredoc.bash.rm_rf_recursive`
- `heredoc.javascript.fs_rmsync_recursive`
- `heredoc.ruby.fileutils_rm_rf`

### ID Stability Rules

1. **Never rename** an existing pattern ID
2. **Deprecate** instead of remove (add `.deprecated` suffix)
3. **New variants** get new ID (don't modify existing)
4. **ID = allowlist key** (users reference by ID)

---

## 3. Pack Integration

### New pack category: `heredoc`

```
heredoc.python    - Python heredoc patterns
heredoc.bash      - Bash heredoc patterns
heredoc.javascript - JavaScript heredoc patterns
heredoc.ruby      - Ruby heredoc patterns
heredoc.perl      - Perl heredoc patterns
heredoc.go        - Go heredoc patterns
heredoc.php       - PHP heredoc patterns
```

### Integration with existing packs

Heredoc patterns are a NEW category alongside existing packs.
They're only evaluated when:
1. Tier 1 regex triggers heredoc detection
2. Tier 2 extracts content + detects language
3. Tier 3 runs language-specific patterns

---

## 4. Initial Pattern Inventory

### Python (heredoc.python)

| ID | Pattern | Severity | FP Risk |
|----|---------|----------|---------|
| shutil_rmtree | `shutil.rmtree($PATH)` | Critical | Low |
| os_remove_system | `os.remove("/")`, `os.remove("/etc")` | Critical | Low |
| subprocess_rm_rf | `subprocess.*(["rm", "-rf", ...])` | Critical | Medium |
| os_system_rm | `os.system("rm ...")` | Critical | Medium |

### Bash (heredoc.bash)

| ID | Pattern | Severity | FP Risk |
|----|---------|----------|---------|
| rm_rf | `rm -rf $PATH` (non-temp) | Critical | Medium |
| git_destructive | destructive git commands | Critical | Low |
| destructive_pipe | `| sh`, `| bash` | High | Medium |

### JavaScript (heredoc.javascript)

| ID | Pattern | Severity | FP Risk |
|----|---------|----------|---------|
| fs_rmsync_recursive | `fs.rmSync($, {recursive: true})` | Critical | Low |
| execsync_rm | `execSync("rm ...")` | Critical | Medium |
| spawn_rm | `spawn("rm", [...])` | Critical | Medium |

### Ruby (heredoc.ruby)

| ID | Pattern | Severity | FP Risk |
|----|---------|----------|---------|
| fileutils_rm_rf | `FileUtils.rm_rf($PATH)` | Critical | Low |
| system_rm | `system("rm ...")` | Critical | Medium |
| backtick_rm | backtick with rm | Critical | Medium |

---

## 5. Contextual Pattern Strategy

### Problem: Low-signal patterns

`subprocess.run(cmd)` - too broad (cmd could be anything)

### Solution: Composite matchers

1. Regex trigger: detects subprocess/exec call
2. AST extraction: gets the command argument
3. Secondary check: validates command is destructive

```rust
PatternMatcher::Composite {
    trigger: regex!(r"subprocess\.\w+\("),
    validator: "$EXPR.run($CMD)" // AST pattern
    // Then check $CMD contains destructive content
}
```

---

## 6. Pattern Authoring Checklist

Every new pattern MUST have:

- [ ] Unique stable ID following naming convention
- [ ] Severity level with justification
- [ ] Human-readable reason (<100 chars)
- [ ] At least 1 positive fixture (should match)
- [ ] At least 1 negative fixture (should NOT match)
- [ ] FP notes documenting known false positive scenarios
- [ ] Optional suggestion for safe alternative

### Test Fixture Format

```rust
#[test]
fn test_heredoc_python_shutil_rmtree() {
    let pattern = patterns::get("heredoc.python.shutil_rmtree");

    // Positive fixtures (should match)
    assert!(pattern.matches("shutil.rmtree('/home/user')"));
    assert!(pattern.matches("shutil.rmtree(path)"));

    // Negative fixtures (should NOT match)
    assert!(!pattern.matches("# shutil.rmtree('/tmp')"));  // Comment
    assert!(!pattern.matches("'shutil.rmtree(x)'"));       // String literal
    assert!(!pattern.matches("shutil.copy(path)"));        // Different function
}
```

---

## 7. Default Mode by Severity

| Severity | Default Mode | User Override |
|----------|--------------|---------------|
| Critical | Block | Allowlist only |
| High | Block | Allowlist by ID |
| Medium | Warn | Block via config |
| Low | Log | Warn/Block via config |

---

## 8. Allowlisting Integration

Users allowlist by stable rule ID:

```toml
# dcg.toml
[allow]
rules = [
    "heredoc.python.subprocess_rm_rf",  # We review these manually
    "heredoc.bash.rm_rf",               # Our CI needs this
]
```

Allowlists are scoped by:
- Rule ID (required)
- Optional: file pattern, expiration, reason

---

## Acceptance Criteria Met

- Clear pattern metadata schema
- Stable rule IDs for hook output / allowlisting
- Severity taxonomy tied to default modes
- FP controls via test fixtures requirement
- Integration plan with pack system
- Contextual patterns via composite matchers

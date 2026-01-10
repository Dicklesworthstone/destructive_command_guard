# Pack Testing Guide

This guide covers how to write comprehensive tests for dcg packs. Well-tested packs ensure reliable protection against destructive commands while avoiding false positives.

## Quick Start

```rust
use crate::packs::test_helpers::*;
use crate::packs::Severity;
use super::*;

#[test]
fn test_my_pattern_blocks() {
    let pack = create_pack();
    assert_blocks(&pack, "dangerous-command", "expected reason");
}

#[test]
fn test_safe_command_allowed() {
    let pack = create_pack();
    assert_allows(&pack, "safe-command");
}
```

## Test Structure

Every pack should have tests covering these categories:

### 1. Pack Creation Tests

Verify the pack initializes correctly:

```rust
#[test]
fn test_pack_creation() {
    let pack = create_pack();

    // Verify metadata
    assert!(!pack.id.is_empty());
    assert!(!pack.keywords.is_empty());

    // Verify patterns are valid
    assert_patterns_compile(&pack);
    assert_all_patterns_have_reasons(&pack);
    assert_unique_pattern_names(&pack);
}
```

### 2. Destructive Pattern Tests

For each destructive pattern, test:

- **Canonical form**: The most common usage
- **Variations**: Different flags, arguments, paths
- **Severity**: Correct classification (Critical/High/Medium/Low)
- **Pattern name**: For allowlisting

```rust
#[test]
fn test_destructive_reset_hard() {
    let pack = create_pack();

    // Canonical form
    assert_blocks(&pack, "git reset --hard", "destroys uncommitted");

    // Variations
    assert_blocks(&pack, "git reset --hard HEAD", "destroys uncommitted");
    assert_blocks(&pack, "git reset --hard HEAD~1", "destroys uncommitted");

    // Verify severity
    assert_blocks_with_severity(&pack, "git reset --hard", Severity::Critical);

    // Verify pattern name
    assert_blocks_with_pattern(&pack, "git reset --hard", "reset-hard");
}
```

### 3. Safe Pattern Tests

Verify that safe patterns correctly allow commands:

```rust
#[test]
fn test_safe_checkout_new_branch() {
    let pack = create_pack();

    // Explicitly matched by safe pattern
    assert_safe_pattern_matches(&pack, "git checkout -b feature");

    // Should be allowed (not blocked)
    assert_allows(&pack, "git checkout -b feature");
}
```

### 4. Edge Case Tests

Test unusual but valid command forms:

```rust
#[test]
fn test_edge_cases() {
    let pack = create_pack();

    // Extra whitespace
    assert_blocks(&pack, "git  reset  --hard", "destroys uncommitted");

    // Quoted arguments
    assert_blocks(&pack, "git reset --hard \"HEAD\"", "destroys uncommitted");

    // Empty/minimal
    assert_no_match(&pack, "");
    assert_no_match(&pack, "git");
}
```

### 5. Specificity Tests (False Positive Prevention)

**Critical**: Verify patterns don't over-match:

```rust
#[test]
fn test_specificity_unrelated_not_matched() {
    let pack = create_pack();

    // Unrelated commands
    assert_no_match(&pack, "ls -la");
    assert_no_match(&pack, "cargo build");

    // Substring matches (should NOT trigger)
    assert_no_match(&pack, "cat .gitignore");
    assert_no_match(&pack, "echo digit");

    // Safe git commands
    assert_allows(&pack, "git status");
    assert_allows(&pack, "git log");
}
```

### 6. Severity Tests

Verify correct severity classification:

```rust
#[test]
fn test_severity_classification() {
    let pack = create_pack();

    // Critical: Most dangerous, always block
    assert_blocks_with_severity(&pack, "git reset --hard", Severity::Critical);

    // High: Dangerous, block by default
    assert_blocks_with_severity(&pack, "git stash drop", Severity::High);

    // Medium: Warn by default
    // assert_blocks_with_severity(&pack, "...", Severity::Medium);

    // Low: Log only
    // assert_blocks_with_severity(&pack, "...", Severity::Low);
}
```

### 7. Performance Tests

Verify patterns don't have catastrophic backtracking:

```rust
#[test]
fn test_performance() {
    let pack = create_pack();

    // Normal commands
    assert_matches_within_budget(&pack, "git reset --hard");

    // Pathological inputs
    let long_input = format!("git {}", "-".repeat(1000));
    assert_matches_within_budget(&pack, &long_input);
}
```

## Test Helpers Reference

### Assertion Functions

| Function | Purpose |
|----------|---------|
| `assert_blocks(&pack, cmd, reason)` | Verify command is blocked with expected reason |
| `assert_blocks_with_pattern(&pack, cmd, name)` | Verify specific pattern matches |
| `assert_blocks_with_severity(&pack, cmd, severity)` | Verify severity classification |
| `assert_allows(&pack, cmd)` | Verify command is not blocked |
| `assert_safe_pattern_matches(&pack, cmd)` | Verify safe pattern explicitly matches |
| `assert_no_match(&pack, cmd)` | Verify no patterns match (specificity) |
| `assert_matches_within_budget(&pack, cmd)` | Verify performance is acceptable |

### Batch Test Functions

```rust
// Test multiple commands should be blocked
test_batch_blocks(&pack, &[
    "git reset --hard",
    "git reset --hard HEAD",
    "git reset --hard HEAD~1",
], "reset");

// Test multiple commands should be allowed
test_batch_allows(&pack, &[
    "git status",
    "git log",
    "git diff",
]);
```

### Validation Functions

```rust
// Verify all patterns compile
assert_patterns_compile(&pack);

// Verify all destructive patterns have reasons
assert_all_patterns_have_reasons(&pack);

// Verify no duplicate pattern names
assert_unique_pattern_names(&pack);
```

### Debugging

```rust
// Get detailed match information
let info = debug_match_info(&pack, "git reset --hard");
println!("{}", info);
// Output:
// Match info for 'git reset --hard' in pack 'core.git':
//   Keywords (["git"]): MAY match
//   Safe patterns:
//     - checkout-new-branch: no match
//     ...
//   Destructive patterns:
//     - reset-hard: MATCH (severity: Critical)
```

## Minimum Coverage Requirements

Every pack MUST have tests for:

1. **Pack creation** - Verify metadata and pattern validity
2. **Every destructive pattern** - At least the canonical form
3. **Every safe pattern** - Verify it actually allows intended commands
4. **Specificity** - At least 5 unrelated commands that should NOT match
5. **Edge cases** - Empty string, extra whitespace, quoted arguments

## Common Patterns to Test

### Flag Variations

```rust
// Combined flags
assert_blocks(&pack, "rm -rf dir/", "...");

// Separate flags
assert_blocks(&pack, "rm -r -f dir/", "...");

// Long flags
assert_blocks(&pack, "rm --recursive --force dir/", "...");

// Mixed flags
assert_blocks(&pack, "rm -r --force dir/", "...");
```

### Path Variations

```rust
// Relative paths
assert_blocks(&pack, "rm -rf ./dir", "...");
assert_blocks(&pack, "rm -rf dir/", "...");

// With trailing slash
assert_blocks(&pack, "rm -rf dir/", "...");

// Without trailing slash
assert_blocks(&pack, "rm -rf dir", "...");

// Absolute paths
assert_blocks(&pack, "rm -rf /home/user/dir", "...");

// Path with spaces (quoted)
assert_blocks(&pack, "rm -rf \"my dir\"", "...");
```

### Command Prefixes

```rust
// With sudo
assert_blocks(&pack, "sudo rm -rf dir/", "...");

// With env
assert_blocks(&pack, "env VAR=val rm -rf dir/", "...");

// With command
assert_blocks(&pack, "command rm -rf dir/", "...");
```

## Logging Test Information

When tests fail, the helpers provide detailed information:

```
Expected pack 'core.git' to block command 'git xyz' but it was allowed.
Pack has 6 safe patterns and 12 destructive patterns.
Keywords: ["git"]
```

For debugging, use `debug_match_info()`:

```rust
#[test]
fn debug_why_not_matching() {
    let pack = create_pack();
    eprintln!("{}", debug_match_info(&pack, "my command"));
}
```

## Test File Organization

### Option 1: Inline Tests (Recommended for Small Packs)

```rust
// src/packs/database/postgresql.rs

pub fn create_pack() -> Pack {
    // ...
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::test_helpers::*;

    #[test]
    fn test_pack_creation() { ... }

    #[test]
    fn test_drop_table() { ... }
}
```

### Option 2: Separate Test File (For Large Packs)

```rust
// src/packs/database/postgresql.rs
pub fn create_pack() -> Pack { ... }

#[cfg(test)]
#[path = "postgresql_tests.rs"]
mod tests;

// src/packs/database/postgresql_tests.rs
use super::*;
use crate::packs::test_helpers::*;

#[test]
fn test_pack_creation() { ... }
```

## Running Tests

```bash
# Run all pack tests
cargo test packs

# Run tests for specific pack
cargo test packs::database::postgresql

# Run with output (for debugging)
cargo test packs::database::postgresql -- --nocapture

# Run specific test
cargo test test_destructive_drop_table
```

## Checklist for New Pack Tests

- [ ] Pack creation test with validation
- [ ] Test for each destructive pattern (canonical + variations)
- [ ] Test for each safe pattern
- [ ] Severity tests for Critical/High patterns
- [ ] Pattern name tests (for allowlisting)
- [ ] Edge cases (whitespace, quotes, empty)
- [ ] Specificity tests (5+ unrelated commands)
- [ ] Performance test with pathological input
- [ ] All tests pass with `cargo test`

## Pack Testing Logging

The pack testing framework includes structured logging for debugging and CI/CD integration.

### Using LoggedPackTestRunner

For detailed debugging output, use `LoggedPackTestRunner`:

```rust
use crate::packs::test_helpers::{LoggedPackTestRunner, create_debug_runner};
use crate::logging::PackTestLogConfig;

#[test]
fn test_with_logging() {
    let pack = create_pack();

    // Create a debug runner for verbose output
    let mut runner = LoggedPackTestRunner::debug(&pack);

    // Or use custom configuration
    let config = PackTestLogConfig {
        level: PackTestLogLevel::Debug,
        json_mode: true,  // Output structured JSON
        show_timing: true,
        show_patterns: true,
    };
    let mut runner = LoggedPackTestRunner::new(&pack, config);

    // Run assertions (automatically logged)
    runner.assert_blocks("dangerous-command", "expected reason");
    runner.assert_allows("safe-command");

    // Get JSON report at the end
    let report = runner.finish();
    println!("{}", report);
}
```

### JSON Report Format

The `LoggedPackTestRunner` produces structured JSON reports:

```json
{
  "pack": "secrets.vault",
  "timestamp": "2024-01-15T10:30:00Z",
  "tests": [
    {
      "timestamp": "2024-01-15T10:30:00Z",
      "pack": "secrets.vault",
      "test_name": "assert_blocks",
      "passed": true,
      "duration_ms": 1.2,
      "pattern_matched": "vault-delete",
      "input": "vault secrets disable my-secret"
    }
  ],
  "summary": {
    "total": 25,
    "passed": 25,
    "failed": 0
  },
  "pattern_matches": [
    {
      "timestamp": "2024-01-15T10:30:00Z",
      "pack": "secrets.vault",
      "pattern": "vault-delete",
      "input": "vault secrets disable my-secret",
      "matched": true,
      "duration_us": 45,
      "severity": "Critical",
      "reason": "Disabling secrets engine destroys all secrets"
    }
  ]
}
```

### Log Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| Error | Only failures | CI/CD pipelines |
| Warn  | Warnings and errors | Normal testing |
| Info  | Test results (default) | Standard output |
| Debug | Pattern match details | Debugging patterns |
| Trace | All internal details | Deep debugging |

### Interpreting Debug Output

When running with `--nocapture` and debug mode enabled:

```
[DEBUG] core.git | reset-hard | MATCH | git reset --hard (45us)
[DEBUG] core.git | checkout-discard | no-match | git reset --hard (12us)
[PASS] test_reset_hard_blocks (1.23ms)
```

Format: `[LEVEL] pack_id | pattern_name | match_status | input (timing)`

### CI/CD Integration

For CI pipelines, use JSON mode and parse the summary:

```bash
cargo test packs --no-fail-fast 2>&1 | grep '"summary"' | jq '.failed'
```

The `PackTestLogger` can also be used programmatically for custom reporting.

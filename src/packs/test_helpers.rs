//! Test helper utilities for pack unit testing.
//!
//! This module provides reusable assertion functions and utilities for testing
//! pack patterns. Use these helpers to ensure consistent test structure and
//! informative failure messages across all pack tests.
//!
//! # Usage
//!
//! ```rust,ignore
//! use crate::packs::test_helpers::*;
//!
//! #[test]
//! fn test_my_pack() {
//!     let pack = my_pack::create_pack();
//!
//!     // Test destructive patterns block with expected reasons
//!     assert_blocks(&pack, "dangerous-command", "expected reason substring");
//!
//!     // Test safe patterns allow commands
//!     assert_allows(&pack, "safe-command");
//!
//!     // Test unrelated commands are not matched
//!     assert_no_match(&pack, "unrelated-command");
//! }
//! ```

use crate::packs::{Pack, Severity};
use std::fmt::Write;
use std::time::{Duration, Instant};

/// Maximum time allowed for a single pattern match operation.
/// Pattern matching should be sub-millisecond for typical commands.
pub const PATTERN_MATCH_TIMEOUT: Duration = Duration::from_millis(5);

/// Assert that a pack blocks a command with a reason containing the expected substring.
///
/// # Panics
///
/// Panics if:
/// - The pack does not block the command
/// - The block reason does not contain `expected_reason_substring`
///
/// # Example
///
/// ```rust,ignore
/// assert_blocks(&pack, "git reset --hard", "destroys uncommitted changes");
/// ```
#[track_caller]
pub fn assert_blocks(pack: &Pack, command: &str, expected_reason_substring: &str) {
    let result = pack.check(command);

    match result {
        Some(matched) => {
            assert!(
                matched.reason.contains(expected_reason_substring),
                "Command '{}' was blocked but with unexpected reason.\n\
                 Expected reason to contain: '{}'\n\
                 Actual reason: '{}'",
                command,
                expected_reason_substring,
                matched.reason
            );
        }
        None => {
            panic!(
                "Expected pack '{}' to block command '{}' but it was allowed.\n\
                 Pack has {} safe patterns and {} destructive patterns.\n\
                 Keywords: {:?}",
                pack.id,
                command,
                pack.safe_patterns.len(),
                pack.destructive_patterns.len(),
                pack.keywords
            );
        }
    }
}

/// Assert that a pack blocks a command with the specified pattern name.
///
/// This is useful for testing that a specific pattern matches rather than
/// just any pattern. Pattern names are used for allowlisting.
///
/// # Panics
///
/// Panics if:
/// - The pack does not block the command
/// - The pattern that matched does not have the expected name
#[track_caller]
pub fn assert_blocks_with_pattern(pack: &Pack, command: &str, expected_pattern_name: &str) {
    let result = pack.check(command);

    match result {
        Some(matched) => {
            match matched.name {
                Some(name) => {
                    assert_eq!(
                        name, expected_pattern_name,
                        "Command '{command}' was blocked by pattern '{name}' but expected '{expected_pattern_name}'"
                    );
                }
                None => {
                    panic!(
                        "Command '{}' was blocked but by an unnamed pattern.\n\
                         Expected pattern name: '{}'\n\
                         Reason: '{}'",
                        command, expected_pattern_name, matched.reason
                    );
                }
            }
        }
        None => {
            panic!(
                "Expected pack '{}' to block command '{}' with pattern '{}' but it was allowed",
                pack.id, command, expected_pattern_name
            );
        }
    }
}

/// Assert that a pack blocks a command with the specified severity level.
///
/// Use this to verify that Critical, High, Medium, and Low severity patterns
/// are correctly classified.
///
/// # Panics
///
/// Panics if:
/// - The pack does not block the command
/// - The matched pattern does not have the expected severity
#[track_caller]
pub fn assert_blocks_with_severity(pack: &Pack, command: &str, expected_severity: Severity) {
    let result = pack.check(command);

    match result {
        Some(matched) => {
            assert_eq!(
                matched.severity, expected_severity,
                "Command '{}' was blocked with severity {:?} but expected {:?}.\n\
                 Pattern: {:?}\n\
                 Reason: '{}'",
                command,
                matched.severity,
                expected_severity,
                matched.name,
                matched.reason
            );
        }
        None => {
            panic!(
                "Expected pack '{}' to block command '{}' with severity {:?} but it was allowed",
                pack.id, command, expected_severity
            );
        }
    }
}

/// Assert that a pack allows a command (no destructive pattern matches).
///
/// This can mean either:
/// - A safe pattern explicitly allows the command, OR
/// - No patterns match at all
///
/// # Panics
///
/// Panics if the pack blocks the command.
#[track_caller]
pub fn assert_allows(pack: &Pack, command: &str) {
    let result = pack.check(command);

    if let Some(matched) = result {
        panic!(
            "Expected pack '{}' to allow command '{}' but it was blocked.\n\
             Pattern: {:?}\n\
             Reason: '{}'\n\
             Severity: {:?}",
            pack.id,
            command,
            matched.name,
            matched.reason,
            matched.severity
        );
    }
}

/// Assert that a safe pattern explicitly matches a command.
///
/// This is stricter than `assert_allows` - it verifies that a safe pattern
/// actually matches, not just that no destructive pattern matched.
///
/// # Panics
///
/// Panics if no safe pattern matches the command.
#[track_caller]
pub fn assert_safe_pattern_matches(pack: &Pack, command: &str) {
    assert!(
        pack.matches_safe(command),
        "Expected a safe pattern in pack '{}' to match command '{}' but none did.\n\
         Safe patterns ({}):\n{}",
        pack.id,
        command,
        pack.safe_patterns.len(),
        pack.safe_patterns
            .iter()
            .map(|p| format!("  - {}", p.name))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Assert that no pattern in the pack matches the command.
///
/// Use this to verify specificity - that patterns don't accidentally match
/// unrelated commands due to overly broad regexes.
///
/// # Panics
///
/// Panics if any pattern (safe or destructive) matches the command.
#[track_caller]
pub fn assert_no_match(pack: &Pack, command: &str) {
    // Check safe patterns
    if pack.matches_safe(command) {
        let matched_safe = pack
            .safe_patterns
            .iter()
            .find(|p| p.regex.is_match(command).unwrap_or(false));

        panic!(
            "Expected no patterns in pack '{}' to match command '{}' but safe pattern matched.\n\
             Matched safe pattern: {:?}",
            pack.id,
            command,
            matched_safe.map(|p| p.name)
        );
    }

    // Check destructive patterns
    if let Some(matched) = pack.matches_destructive(command) {
        panic!(
            "Expected no patterns in pack '{}' to match command '{}' but destructive pattern matched.\n\
             Pattern: {:?}\n\
             Reason: '{}'",
            pack.id,
            command,
            matched.name,
            matched.reason
        );
    }
}

/// Assert that a pattern matches within the allowed time budget.
///
/// Pattern matching should be fast. This helper ensures regex patterns
/// don't have catastrophic backtracking or performance issues.
///
/// # Panics
///
/// Panics if pattern matching takes longer than `PATTERN_MATCH_TIMEOUT`.
#[track_caller]
pub fn assert_matches_within_budget(pack: &Pack, command: &str) {
    let start = Instant::now();
    let _ = pack.check(command);
    let elapsed = start.elapsed();

    assert!(
        elapsed < PATTERN_MATCH_TIMEOUT,
        "Pattern matching for command '{}' in pack '{}' took {:?}, exceeding budget of {:?}.\n\
         This may indicate catastrophic regex backtracking.",
        command,
        pack.id,
        elapsed,
        PATTERN_MATCH_TIMEOUT
    );
}

/// Test a batch of commands that should all be blocked.
///
/// Returns a summary of results for debugging.
///
/// # Panics
///
/// Panics if any command in the batch is not blocked or has an unexpected reason.
///
/// # Example
///
/// ```rust,ignore
/// let commands = vec![
///     "git reset --hard",
///     "git reset --hard HEAD",
///     "git reset --hard HEAD~1",
/// ];
/// test_batch_blocks(&pack, &commands, "reset");
/// ```
#[track_caller]
pub fn test_batch_blocks(pack: &Pack, commands: &[&str], reason_substring: &str) {
    let mut failures = Vec::new();

    for cmd in commands {
        let result = pack.check(cmd);
        match result {
            Some(matched) => {
                if !matched.reason.contains(reason_substring) {
                    failures.push(format!(
                        "  '{cmd}': blocked but reason '{}' doesn't contain '{reason_substring}'",
                        matched.reason
                    ));
                }
            }
            None => {
                failures.push(format!("  '{cmd}': allowed (should be blocked)"));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "Batch block test failed for pack '{}':\n{}",
        pack.id,
        failures.join("\n")
    );
}

/// Test a batch of commands that should all be allowed.
///
/// # Panics
///
/// Panics if any command in the batch is blocked.
///
/// # Example
///
/// ```rust,ignore
/// let commands = vec![
///     "git status",
///     "git log",
///     "git diff",
/// ];
/// test_batch_allows(&pack, &commands);
/// ```
#[track_caller]
pub fn test_batch_allows(pack: &Pack, commands: &[&str]) {
    let mut failures = Vec::new();

    for cmd in commands {
        if let Some(matched) = pack.check(cmd) {
            failures.push(format!(
                "  '{cmd}': blocked by {:?} - '{}'",
                matched.name,
                matched.reason
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "Batch allow test failed for pack '{}':\n{}",
        pack.id,
        failures.join("\n")
    );
}

/// Get detailed match information for debugging.
///
/// This is useful when writing tests to understand why a pattern did or
/// didn't match.
#[must_use]
pub fn debug_match_info(pack: &Pack, command: &str) -> String {
    let mut info = format!("Match info for '{command}' in pack '{}':\n", pack.id);

    // Check keyword matching
    let might_match = pack.might_match(command);
    let _ = writeln!(
        info,
        "  Keywords ({:?}): {}",
        pack.keywords,
        if might_match { "MAY match" } else { "quick-rejected" }
    );

    if !might_match {
        return info;
    }

    // Check safe patterns
    info.push_str("  Safe patterns:\n");
    for pattern in &pack.safe_patterns {
        let matches = pattern.regex.is_match(command).unwrap_or(false);
        let _ = writeln!(
            info,
            "    - {}: {}",
            pattern.name,
            if matches { "MATCH" } else { "no match" }
        );
    }

    // Check destructive patterns
    info.push_str("  Destructive patterns:\n");
    for pattern in &pack.destructive_patterns {
        let matches = pattern.regex.is_match(command).unwrap_or(false);
        let _ = writeln!(
            info,
            "    - {:?}: {} (severity: {:?})",
            pattern.name,
            if matches { "MATCH" } else { "no match" },
            pattern.severity
        );
    }

    info
}

/// Verify that all patterns in a pack compile successfully.
///
/// This is a sanity check to ensure no regex syntax errors exist.
#[track_caller]
pub fn assert_patterns_compile(pack: &Pack) {
    // Safe patterns
    for pattern in &pack.safe_patterns {
        // Just accessing the regex is enough - it's compiled at pack creation
        let _ = pattern.regex.as_str();
    }

    // Destructive patterns
    for pattern in &pack.destructive_patterns {
        let _ = pattern.regex.as_str();
    }
}

/// Verify that all destructive patterns have non-empty reasons.
///
/// # Panics
///
/// Panics if any destructive pattern has an empty reason string.
#[track_caller]
pub fn assert_all_patterns_have_reasons(pack: &Pack) {
    for pattern in &pack.destructive_patterns {
        assert!(
            !pattern.reason.is_empty(),
            "Destructive pattern {:?} in pack '{}' has empty reason",
            pattern.name,
            pack.id
        );
    }
}

/// Verify that all named patterns have unique names within the pack.
///
/// # Panics
///
/// Panics if any two patterns (safe or destructive) share the same name.
#[track_caller]
pub fn assert_unique_pattern_names(pack: &Pack) {
    let mut names = std::collections::HashSet::new();

    // Check safe patterns
    for pattern in &pack.safe_patterns {
        assert!(
            names.insert(pattern.name),
            "Duplicate safe pattern name '{}' in pack '{}'",
            pattern.name,
            pack.id
        );
    }

    // Check destructive patterns
    for pattern in &pack.destructive_patterns {
        if let Some(name) = pattern.name {
            assert!(
                names.insert(name),
                "Duplicate destructive pattern name '{}' in pack '{}'",
                name,
                pack.id
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::core;

    #[test]
    fn test_assert_blocks_works() {
        let pack = core::git::create_pack();
        assert_blocks(&pack, "git reset --hard", "destroys uncommitted");
    }

    #[test]
    fn test_assert_allows_works() {
        let pack = core::git::create_pack();
        assert_allows(&pack, "git status");
        assert_allows(&pack, "git log");
    }

    #[test]
    fn test_assert_safe_pattern_matches_works() {
        let pack = core::git::create_pack();
        assert_safe_pattern_matches(&pack, "git checkout -b feature");
    }

    #[test]
    fn test_assert_no_match_works() {
        let pack = core::git::create_pack();
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "cargo build");
    }

    #[test]
    fn test_batch_blocks_works() {
        let pack = core::git::create_pack();
        let commands = vec![
            "git reset --hard",
            "git reset --hard HEAD",
            "git reset --hard HEAD~1",
        ];
        test_batch_blocks(&pack, &commands, "reset");
    }

    #[test]
    fn test_batch_allows_works() {
        let pack = core::git::create_pack();
        let commands = vec!["git status", "git log", "git diff"];
        test_batch_allows(&pack, &commands);
    }

    #[test]
    fn test_debug_match_info_provides_useful_output() {
        let pack = core::git::create_pack();
        let info = debug_match_info(&pack, "git reset --hard");
        assert!(info.contains("core.git"));
        assert!(info.contains("reset-hard"));
        assert!(info.contains("MATCH"));
    }

    #[test]
    fn test_patterns_compile_and_validate() {
        let pack = core::git::create_pack();
        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn test_assert_blocks_with_pattern_works() {
        let pack = core::git::create_pack();
        assert_blocks_with_pattern(&pack, "git reset --hard", "reset-hard");
    }

    #[test]
    fn test_assert_blocks_with_severity_works() {
        let pack = core::git::create_pack();
        assert_blocks_with_severity(&pack, "git reset --hard", Severity::Critical);
    }
}

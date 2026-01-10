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

// ============================================================================
// Logging Integration
// ============================================================================

use crate::logging::{PackTestLogConfig, PackTestLogger};

/// A test runner that integrates with `PackTestLogger` for structured output.
///
/// This allows running pack tests with detailed logging and generating
/// JSON reports for CI/CD integration.
///
/// # Example
///
/// ```rust,ignore
/// let mut runner = LoggedPackTestRunner::new(&pack, PackTestLogConfig::default());
/// runner.assert_blocks("git reset --hard", "destroys uncommitted");
/// runner.assert_allows("git status");
/// let report = runner.finish();
/// println!("{}", report);
/// ```
pub struct LoggedPackTestRunner<'a> {
    pack: &'a Pack,
    logger: PackTestLogger,
}

impl<'a> LoggedPackTestRunner<'a> {
    /// Create a new test runner for a pack.
    #[must_use]
    pub fn new(pack: &'a Pack, config: PackTestLogConfig) -> Self {
        Self {
            pack,
            logger: PackTestLogger::new(&pack.id, &config),
        }
    }

    /// Create a test runner with debug-mode logging.
    #[must_use]
    pub fn debug(pack: &'a Pack) -> Self {
        Self {
            pack,
            logger: PackTestLogger::debug_mode(&pack.id),
        }
    }

    /// Assert that a command is blocked and log the result.
    ///
    /// # Panics
    ///
    /// Panics if the command is not blocked or reason doesn't match.
    #[track_caller]
    pub fn assert_blocks(&mut self, command: &str, expected_reason_substring: &str) {
        let start = Instant::now();
        let result = self.pack.check(command);
        #[allow(clippy::cast_possible_truncation)]
        let duration_us = start.elapsed().as_micros() as u64; // Safe: test durations won't exceed u64

        if let Some(matched) = &result {
            let passed = matched.reason.contains(expected_reason_substring);
            self.logger.log_pattern_match_detailed(
                matched.name.unwrap_or("unnamed"),
                command,
                true,
                duration_us,
                Some(&format!("{:?}", matched.severity)),
                Some(matched.reason),
            );
            self.logger.log_test_result_detailed(
                "assert_blocks",
                passed,
                if passed { "" } else { "reason mismatch" },
                matched.name,
                Some(command),
            );
            assert!(passed, 
                "Command '{}' blocked but with unexpected reason.\n\
                 Expected: '{}'\n\
                 Actual: '{}'",
                command, expected_reason_substring, matched.reason
            );
        } else {
            self.logger.log_test_result_detailed(
                "assert_blocks",
                false,
                "command was allowed",
                None,
                Some(command),
            );
            panic!(
                "Expected pack '{}' to block command '{}' but it was allowed",
                self.pack.id, command
            );
        }
    }

    /// Assert that a command is allowed and log the result.
    ///
    /// # Panics
    ///
    /// Panics if the command is blocked.
    #[track_caller]
    pub fn assert_allows(&mut self, command: &str) {
        let start = Instant::now();
        let result = self.pack.check(command);
        #[allow(clippy::cast_possible_truncation)]
        let duration_us = start.elapsed().as_micros() as u64; // Safe: test durations won't exceed u64

        if let Some(matched) = result {
            self.logger.log_pattern_match_detailed(
                matched.name.unwrap_or("unnamed"),
                command,
                true,
                duration_us,
                Some(&format!("{:?}", matched.severity)),
                Some(matched.reason),
            );
            self.logger.log_test_result_detailed(
                "assert_allows",
                false,
                &format!("blocked by {:?}", matched.name),
                matched.name,
                Some(command),
            );
            panic!(
                "Expected pack '{}' to allow command '{}' but it was blocked",
                self.pack.id, command
            );
        } else {
            self.logger.log_pattern_match(
                "none",
                command,
                false,
                duration_us,
            );
            self.logger.log_test_result_detailed(
                "assert_allows",
                true,
                "",
                None,
                Some(command),
            );
        }
    }

    /// Run a batch of blocking assertions.
    ///
    /// # Panics
    ///
    /// Panics if any command is not blocked or has unexpected reason.
    #[track_caller]
    pub fn test_batch_blocks(&mut self, commands: &[&str], reason_substring: &str) {
        for cmd in commands {
            self.assert_blocks(cmd, reason_substring);
        }
    }

    /// Run a batch of allowing assertions.
    ///
    /// # Panics
    ///
    /// Panics if any command is blocked.
    #[track_caller]
    pub fn test_batch_allows(&mut self, commands: &[&str]) {
        for cmd in commands {
            self.assert_allows(cmd);
        }
    }

    /// Log a summary and get the JSON report.
    #[must_use]
    pub fn finish(&self) -> String {
        let total = self.logger.test_result_count();
        // All tests passed if we got here without panic
        self.logger.log_summary(total, total, 0);
        self.logger.report_json()
    }

    /// Get the underlying logger for additional customization.
    #[must_use]
    pub const fn logger(&self) -> &PackTestLogger {
        &self.logger
    }
}

/// Create a debug-mode test runner for a pack.
///
/// This is a convenience function for quick debugging.
#[must_use]
pub fn create_debug_runner(pack: &Pack) -> LoggedPackTestRunner<'_> {
    LoggedPackTestRunner::debug(pack)
}

// ============================================================================
// Isomorphism Test Infrastructure
// ============================================================================
//
// This section provides utilities for golden/snapshot testing of the evaluator.
// Use these helpers to verify that refactors preserve exact behavior.

use crate::allowlist::AllowlistLayer;
use crate::evaluator::{
    evaluate_command_with_pack_order, EvaluationDecision, EvaluationResult, MatchSource,
};
use crate::packs::{DecisionMode, REGISTRY};
use crate::Config;
use std::path::Path;

/// A stable, comparable snapshot of an evaluation result for golden testing.
///
/// This struct captures all meaningful aspects of an evaluation that tests
/// should verify remain unchanged across refactors.
///
/// # Example
///
/// ```rust,ignore
/// let snapshot = eval_snapshot("git reset --hard", &config);
/// assert_eq!(snapshot.decision, "deny");
/// assert_eq!(snapshot.rule_id, Some("core.git:reset-hard".into()));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EvalSnapshot {
    /// The command that was evaluated.
    pub command: String,
    /// Decision: "allow" or "deny".
    pub decision: String,
    /// Effective mode: "deny", "warn", "log", or None if allowed cleanly.
    pub effective_mode: Option<String>,
    /// Combined pack:pattern ID (e.g., "core.git:reset-hard").
    pub rule_id: Option<String>,
    /// Pack that matched (e.g., "core.git").
    pub pack_id: Option<String>,
    /// Pattern name within the pack (e.g., "reset-hard").
    pub pattern_name: Option<String>,
    /// Match source: "pack", "config", "heredoc", or "legacy".
    pub match_source: Option<String>,
    /// Reason substring (first 100 chars).
    pub reason_preview: Option<String>,
    /// Whether evaluation was truncated due to time budget.
    pub skipped_due_to_budget: bool,
    /// Allowlist layer if overridden: "project", "user", or "system".
    pub allowlist_layer: Option<String>,
    /// Preview of matched text (if available).
    pub matched_text_preview: Option<String>,
}

impl EvalSnapshot {
    /// Create a snapshot from an evaluation result.
    #[must_use]
    pub fn from_result(command: &str, result: &EvaluationResult) -> Self {
        let decision = match result.decision {
            EvaluationDecision::Allow => "allow",
            EvaluationDecision::Deny => "deny",
        };

        let effective_mode = result.effective_mode.map(|m| match m {
            DecisionMode::Deny => "deny".to_string(),
            DecisionMode::Warn => "warn".to_string(),
            DecisionMode::Log => "log".to_string(),
        });

        let (pack_id, pattern_name, rule_id, match_source, reason_preview, matched_text_preview) =
            result.pattern_info.as_ref().map_or(
                (None, None, None, None, None, None),
                |info| {
                    let pack = info.pack_id.clone();
                    let pattern = info.pattern_name.clone();
                    let rule = pack
                        .as_ref()
                        .zip(pattern.as_ref())
                        .map(|(p, n)| format!("{p}:{n}"));
                    let source = Some(match info.source {
                        MatchSource::Pack => "pack".to_string(),
                        MatchSource::ConfigOverride => "config".to_string(),
                        MatchSource::HeredocAst => "heredoc".to_string(),
                        MatchSource::LegacyPattern => "legacy".to_string(),
                    });
                    let reason = if info.reason.len() > 100 {
                        Some(info.reason[..100].to_string())
                    } else {
                        Some(info.reason.clone())
                    };
                    (pack, pattern, rule, source, reason, info.matched_text_preview.clone())
                },
            );

        let allowlist_layer = result.allowlist_override.as_ref().map(|ao| match ao.layer {
            AllowlistLayer::Project => "project".to_string(),
            AllowlistLayer::User => "user".to_string(),
            AllowlistLayer::System => "system".to_string(),
        });

        Self {
            command: command.to_string(),
            decision: decision.to_string(),
            effective_mode,
            rule_id,
            pack_id,
            pattern_name,
            match_source,
            reason_preview,
            skipped_due_to_budget: result.skipped_due_to_budget,
            allowlist_layer,
            matched_text_preview,
        }
    }
}

/// Expected log fields from a corpus test case.
///
/// These are the fields specified in `[case.log]` sections of corpus TOML files.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ExpectedLog {
    /// Expected decision: "allow" or "deny".
    pub decision: Option<String>,
    /// Expected effective mode: "deny", "warn", or "log".
    pub mode: Option<String>,
    /// Expected pack ID.
    pub pack_id: Option<String>,
    /// Expected pattern name.
    pub pattern_name: Option<String>,
    /// Expected rule ID (pack:pattern).
    pub rule_id: Option<String>,
    /// Substring that reason must contain.
    pub reason_contains: Option<String>,
    /// Expected allowlist layer.
    pub allowlist_layer: Option<String>,
}

/// A corpus test case loaded from TOML.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CorpusTestCase {
    /// Human-readable description.
    pub description: String,
    /// The command to evaluate.
    pub command: String,
    /// Expected outcome: "allow" or "deny".
    pub expected: String,
    /// Optional rule ID that should match (for deny cases).
    #[serde(default)]
    pub rule_id: Option<String>,
    /// Optional expected log fields for detailed verification.
    #[serde(default)]
    pub log: Option<ExpectedLog>,
}

/// A corpus file containing multiple test cases.
#[derive(Debug, serde::Deserialize)]
struct CorpusFile {
    #[serde(rename = "case")]
    cases: Vec<CorpusTestCase>,
}

/// Category of corpus test based on directory name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorpusCategory {
    /// Commands that should be denied (true positives).
    TruePositives,
    /// Commands that should be allowed (false positive prevention).
    FalsePositives,
    /// Bypass attempts that should still be denied.
    BypassAttempts,
    /// Edge cases where any outcome is acceptable (tests parsing/stability).
    EdgeCases,
}

impl CorpusCategory {
    /// Parse category from directory name.
    #[must_use]
    pub fn from_dir_name(name: &str) -> Option<Self> {
        match name {
            "true_positives" => Some(Self::TruePositives),
            "false_positives" => Some(Self::FalsePositives),
            "bypass_attempts" => Some(Self::BypassAttempts),
            "edge_cases" => Some(Self::EdgeCases),
            _ => None,
        }
    }

    /// Get the expected decision for this category.
    #[must_use]
    pub const fn expected_decision(&self) -> Option<&'static str> {
        match self {
            Self::TruePositives | Self::BypassAttempts => Some("deny"),
            Self::FalsePositives => Some("allow"),
            Self::EdgeCases => None, // Any outcome OK
        }
    }
}

/// Load corpus test cases from a TOML file.
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed.
#[allow(clippy::missing_errors_doc)]
pub fn load_corpus_file(path: &Path) -> Result<Vec<CorpusTestCase>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    let corpus: CorpusFile = toml::from_str(&content)
        .map_err(|e| format!("Failed to parse {}: {e}", path.display()))?;
    Ok(corpus.cases)
}

/// Load all corpus test cases from a directory.
///
/// Recursively loads all `.toml` files from the given directory.
///
/// # Errors
///
/// Returns an error if any file cannot be read or parsed.
#[allow(clippy::missing_errors_doc)]
pub fn load_corpus_dir(dir: &Path) -> Result<Vec<(CorpusCategory, String, CorpusTestCase)>, String> {
    let mut cases = Vec::new();
    let categories = ["true_positives", "false_positives", "bypass_attempts", "edge_cases"];

    for category_name in &categories {
        let category_dir = dir.join(category_name);
        if !category_dir.exists() {
            continue;
        }

        let Some(category) = CorpusCategory::from_dir_name(category_name) else {
            continue;
        };

        let entries = std::fs::read_dir(&category_dir)
            .map_err(|e| format!("Failed to read {}: {e}", category_dir.display()))?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "toml") {
                let file_cases = load_corpus_file(&path)?;
                let file_name = path.file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                for case in file_cases {
                    cases.push((category, file_name.clone(), case));
                }
            }
        }
    }

    Ok(cases)
}

/// Evaluate a command and return a snapshot for comparison.
///
/// Uses the default configuration with all core packs enabled.
///
/// # Example
///
/// ```rust,ignore
/// let snapshot = eval_snapshot("git reset --hard");
/// assert_eq!(snapshot.decision, "deny");
/// ```
#[must_use]
pub fn eval_snapshot(command: &str) -> EvalSnapshot {
    eval_snapshot_with_config(command, &Config::default())
}

/// Evaluate a command with a specific configuration and return a snapshot.
#[must_use]
pub fn eval_snapshot_with_config(command: &str, config: &Config) -> EvalSnapshot {
    let enabled_packs = config.enabled_pack_ids();
    let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    let compiled_overrides = config.overrides.compile();
    let allowlists = crate::LayeredAllowlist::default();
    let heredoc_settings = config.heredoc_settings();

    let result = evaluate_command_with_pack_order(
        command,
        &enabled_keywords,
        &ordered_packs,
        &compiled_overrides,
        &allowlists,
        &heredoc_settings,
    );

    EvalSnapshot::from_result(command, &result)
}

/// Diff two evaluation snapshots and return human-readable differences.
///
/// Returns `None` if the snapshots are identical.
#[must_use]
pub fn diff_snapshots(expected: &EvalSnapshot, actual: &EvalSnapshot) -> Option<String> {
    let mut diffs = Vec::new();

    if expected.decision != actual.decision {
        diffs.push(format!(
            "  decision: expected '{}', got '{}'",
            expected.decision, actual.decision
        ));
    }

    if expected.effective_mode != actual.effective_mode {
        diffs.push(format!(
            "  effective_mode: expected {:?}, got {:?}",
            expected.effective_mode, actual.effective_mode
        ));
    }

    if expected.rule_id != actual.rule_id {
        diffs.push(format!(
            "  rule_id: expected {:?}, got {:?}",
            expected.rule_id, actual.rule_id
        ));
    }

    if expected.pack_id != actual.pack_id {
        diffs.push(format!(
            "  pack_id: expected {:?}, got {:?}",
            expected.pack_id, actual.pack_id
        ));
    }

    if expected.pattern_name != actual.pattern_name {
        diffs.push(format!(
            "  pattern_name: expected {:?}, got {:?}",
            expected.pattern_name, actual.pattern_name
        ));
    }

    if expected.match_source != actual.match_source {
        diffs.push(format!(
            "  match_source: expected {:?}, got {:?}",
            expected.match_source, actual.match_source
        ));
    }

    if expected.skipped_due_to_budget != actual.skipped_due_to_budget {
        diffs.push(format!(
            "  skipped_due_to_budget: expected {}, got {}",
            expected.skipped_due_to_budget, actual.skipped_due_to_budget
        ));
    }

    if expected.allowlist_layer != actual.allowlist_layer {
        diffs.push(format!(
            "  allowlist_layer: expected {:?}, got {:?}",
            expected.allowlist_layer, actual.allowlist_layer
        ));
    }

    if diffs.is_empty() {
        None
    } else {
        Some(format!(
            "Snapshot mismatch for command: {}\n{}\n\nReproduce:\n  cargo test -- --nocapture 'test_name' && dcg explain '{}'",
            expected.command,
            diffs.join("\n"),
            expected.command.replace('\'', "'\\''")
        ))
    }
}

/// Verify a corpus test case passes.
///
/// Returns `Ok(())` if the test passes, or `Err(message)` with details on failure.
#[allow(clippy::missing_errors_doc, clippy::too_many_lines)]
pub fn verify_corpus_case(case: &CorpusTestCase, category: CorpusCategory) -> Result<(), String> {
    let snapshot = eval_snapshot(&case.command);

    // Check basic decision
    let expected_decision = case.expected.as_str();
    if snapshot.decision != expected_decision {
        return Err(format!(
            "Decision mismatch:\n\
             Description: {}\n\
             Command: {}\n\
             Expected: {}\n\
             Actual: {}\n\
             Rule ID: {:?}\n\
             Reproduce: dcg explain '{}'",
            case.description,
            case.command,
            expected_decision,
            snapshot.decision,
            snapshot.rule_id,
            case.command.replace('\'', "'\\''")
        ));
    }

    // Check rule_id if specified
    if let Some(ref expected_rule_id) = case.rule_id {
        if snapshot.rule_id.as_deref() != Some(expected_rule_id) {
            return Err(format!(
                "Rule ID mismatch:\n\
                 Description: {}\n\
                 Command: {}\n\
                 Expected rule_id: {}\n\
                 Actual rule_id: {:?}\n\
                 Reproduce: dcg explain '{}'",
                case.description,
                case.command,
                expected_rule_id,
                snapshot.rule_id,
                case.command.replace('\'', "'\\''")
            ));
        }
    }

    // Check detailed log expectations if present
    if let Some(ref log) = case.log {
        if let Some(ref expected_decision) = log.decision {
            if snapshot.decision != *expected_decision {
                return Err(format!(
                    "Log decision mismatch: expected {expected_decision}, got {}",
                    snapshot.decision
                ));
            }
        }

        if let Some(ref expected_mode) = log.mode {
            if snapshot.effective_mode.as_deref() != Some(expected_mode.as_str()) {
                return Err(format!(
                    "Log mode mismatch: expected {expected_mode}, got {:?}",
                    snapshot.effective_mode
                ));
            }
        }

        if let Some(ref expected_pack_id) = log.pack_id {
            if snapshot.pack_id.as_deref() != Some(expected_pack_id.as_str()) {
                return Err(format!(
                    "Log pack_id mismatch: expected {expected_pack_id}, got {:?}",
                    snapshot.pack_id
                ));
            }
        }

        if let Some(ref expected_pattern_name) = log.pattern_name {
            if snapshot.pattern_name.as_deref() != Some(expected_pattern_name.as_str()) {
                return Err(format!(
                    "Log pattern_name mismatch: expected {expected_pattern_name}, got {:?}",
                    snapshot.pattern_name
                ));
            }
        }

        if let Some(ref expected_rule_id) = log.rule_id {
            if snapshot.rule_id.as_deref() != Some(expected_rule_id.as_str()) {
                return Err(format!(
                    "Log rule_id mismatch: expected {expected_rule_id}, got {:?}",
                    snapshot.rule_id
                ));
            }
        }

        if let Some(ref reason_contains) = log.reason_contains {
            let contains = snapshot
                .reason_preview
                .as_ref()
                .is_some_and(|r| r.contains(reason_contains));
            if !contains {
                return Err(format!(
                    "Log reason_contains mismatch: expected to contain '{}', got {:?}",
                    reason_contains, snapshot.reason_preview
                ));
            }
        }
    }

    // Category-based validation (for cases without explicit log expectations)
    if case.log.is_none() {
        if let Some(cat_decision) = category.expected_decision() {
            if snapshot.decision != cat_decision {
                return Err(format!(
                    "Category-based decision mismatch:\n\
                     Description: {}\n\
                     Command: {}\n\
                     Category: {:?} (expects {})\n\
                     Actual: {}",
                    case.description, case.command, category, cat_decision, snapshot.decision
                ));
            }
        }
    }

    Ok(())
}

/// Assert a command produces the expected snapshot.
///
/// Panics with a detailed diff if the snapshots don't match.
///
/// # Panics
///
/// Panics if the actual evaluation result doesn't match the expected snapshot.
#[track_caller]
pub fn assert_eval_snapshot(command: &str, expected: &EvalSnapshot) {
    let actual = eval_snapshot(command);
    if let Some(diff) = diff_snapshots(expected, &actual) {
        panic!("Evaluation snapshot mismatch:\n{diff}");
    }
}

/// Assert a command produces a specific decision.
///
/// This is a simpler helper for basic decision verification.
///
/// # Panics
///
/// Panics if the decision doesn't match.
#[track_caller]
pub fn assert_decision(command: &str, expected_decision: &str) {
    let snapshot = eval_snapshot(command);
    assert_eq!(
        snapshot.decision, expected_decision,
        "Decision mismatch for command: {}\nExpected: {}\nActual: {}\nRule ID: {:?}\n\nReproduce: dcg explain '{}'",
        command, expected_decision, snapshot.decision, snapshot.rule_id,
        command.replace('\'', "'\\''")
    );
}

/// Assert a command is denied with a specific rule.
///
/// # Panics
///
/// Panics if the command is not denied or the rule doesn't match.
#[track_caller]
pub fn assert_denies_with_rule(command: &str, expected_rule_id: &str) {
    let snapshot = eval_snapshot(command);
    assert_eq!(
        snapshot.decision, "deny",
        "Expected deny for command: {}\nActual: {}\nRule ID: {:?}",
        command, snapshot.decision, snapshot.rule_id
    );
    assert_eq!(
        snapshot.rule_id.as_deref(),
        Some(expected_rule_id),
        "Rule mismatch for command: {}\nExpected: {}\nActual: {:?}",
        command, expected_rule_id, snapshot.rule_id
    );
}

/// Assert a command is allowed (not blocked).
///
/// # Panics
///
/// Panics if the command is denied.
#[track_caller]
pub fn assert_allows_command(command: &str) {
    let snapshot = eval_snapshot(command);
    assert_eq!(
        snapshot.decision, "allow",
        "Expected allow for command: {}\nActual: {}\nBlocked by: {:?}",
        command, snapshot.decision, snapshot.rule_id
    );
}

/// Batch verify corpus test cases.
///
/// Returns a summary of pass/fail counts and details of failures.
#[must_use]
pub fn verify_corpus_batch(
    cases: &[(CorpusCategory, String, CorpusTestCase)],
) -> (usize, usize, Vec<String>) {
    let mut passed = 0;
    let mut failed = 0;
    let mut failures = Vec::new();

    for (category, file, case) in cases {
        match verify_corpus_case(case, *category) {
            Ok(()) => passed += 1,
            Err(msg) => {
                failed += 1;
                failures.push(format!("[{file}] {msg}"));
            }
        }
    }

    (passed, failed, failures)
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

    // =========================================================================
    // LoggedPackTestRunner Tests
    // =========================================================================

    #[test]
    fn test_logged_runner_creation() {
        let pack = core::git::create_pack();
        let runner = LoggedPackTestRunner::debug(&pack);
        assert_eq!(runner.logger().test_result_count(), 0);
    }

    #[test]
    fn test_logged_runner_assert_blocks() {
        let pack = core::git::create_pack();
        let mut runner = LoggedPackTestRunner::debug(&pack);
        runner.assert_blocks("git reset --hard", "destroys uncommitted");
        assert_eq!(runner.logger().test_result_count(), 1);
    }

    #[test]
    fn test_logged_runner_assert_allows() {
        let pack = core::git::create_pack();
        let mut runner = LoggedPackTestRunner::debug(&pack);
        runner.assert_allows("git status");
        assert_eq!(runner.logger().test_result_count(), 1);
    }

    #[test]
    fn test_logged_runner_batch_operations() {
        let pack = core::git::create_pack();
        let mut runner = LoggedPackTestRunner::debug(&pack);
        runner.test_batch_allows(&["git status", "git log"]);
        assert_eq!(runner.logger().test_result_count(), 2);
    }

    #[test]
    fn test_logged_runner_finish_produces_json() {
        let pack = core::git::create_pack();
        let mut runner = LoggedPackTestRunner::debug(&pack);
        runner.assert_allows("git status");
        let report = runner.finish();
        assert!(report.contains("\"pack\""));
        assert!(report.contains("core.git"));
    }

    #[test]
    fn test_create_debug_runner_helper() {
        let pack = core::git::create_pack();
        let runner = create_debug_runner(&pack);
        assert_eq!(runner.logger().test_result_count(), 0);
    }

    // =========================================================================
    // Isomorphism Test Infrastructure Tests
    // =========================================================================

    #[test]
    fn test_eval_snapshot_deny() {
        let snapshot = eval_snapshot("git reset --hard");
        assert_eq!(snapshot.decision, "deny");
        assert_eq!(snapshot.rule_id, Some("core.git:reset-hard".to_string()));
        assert_eq!(snapshot.pack_id, Some("core.git".to_string()));
        assert_eq!(snapshot.pattern_name, Some("reset-hard".to_string()));
        assert_eq!(snapshot.match_source, Some("pack".to_string()));
        assert!(snapshot.reason_preview.is_some());
        assert!(!snapshot.skipped_due_to_budget);
    }

    #[test]
    fn test_eval_snapshot_allow() {
        let snapshot = eval_snapshot("git status");
        assert_eq!(snapshot.decision, "allow");
        assert!(snapshot.rule_id.is_none());
        assert!(snapshot.pack_id.is_none());
    }

    #[test]
    fn test_assert_decision_works() {
        assert_decision("git reset --hard", "deny");
        assert_decision("git status", "allow");
    }

    #[test]
    fn test_assert_denies_with_rule_works() {
        assert_denies_with_rule("git reset --hard", "core.git:reset-hard");
        assert_denies_with_rule("git clean -fd", "core.git:clean-force");
    }

    #[test]
    fn test_assert_allows_command_works() {
        assert_allows_command("git status");
        assert_allows_command("ls -la");
    }

    #[test]
    fn test_diff_snapshots_identical() {
        let s1 = eval_snapshot("git reset --hard");
        let s2 = eval_snapshot("git reset --hard");
        assert!(diff_snapshots(&s1, &s2).is_none());
    }

    #[test]
    fn test_diff_snapshots_different() {
        let s1 = eval_snapshot("git reset --hard");
        let s2 = eval_snapshot("git status");
        let diff = diff_snapshots(&s1, &s2);
        assert!(diff.is_some());
        let diff_text = diff.unwrap();
        assert!(diff_text.contains("decision"));
        assert!(diff_text.contains("Reproduce"));
    }

    #[test]
    fn test_corpus_category_from_dir_name() {
        assert_eq!(
            CorpusCategory::from_dir_name("true_positives"),
            Some(CorpusCategory::TruePositives)
        );
        assert_eq!(
            CorpusCategory::from_dir_name("false_positives"),
            Some(CorpusCategory::FalsePositives)
        );
        assert_eq!(
            CorpusCategory::from_dir_name("bypass_attempts"),
            Some(CorpusCategory::BypassAttempts)
        );
        assert_eq!(
            CorpusCategory::from_dir_name("edge_cases"),
            Some(CorpusCategory::EdgeCases)
        );
        assert!(CorpusCategory::from_dir_name("unknown").is_none());
    }

    #[test]
    fn test_corpus_category_expected_decision() {
        assert_eq!(CorpusCategory::TruePositives.expected_decision(), Some("deny"));
        assert_eq!(CorpusCategory::BypassAttempts.expected_decision(), Some("deny"));
        assert_eq!(CorpusCategory::FalsePositives.expected_decision(), Some("allow"));
        assert_eq!(CorpusCategory::EdgeCases.expected_decision(), None);
    }

    #[test]
    fn test_verify_corpus_case_pass() {
        let case = CorpusTestCase {
            description: "git reset --hard should be blocked".to_string(),
            command: "git reset --hard".to_string(),
            expected: "deny".to_string(),
            rule_id: Some("core.git:reset-hard".to_string()),
            log: None,
        };
        let result = verify_corpus_case(&case, CorpusCategory::TruePositives);
        assert!(result.is_ok(), "Expected pass: {result:?}");
    }

    #[test]
    fn test_verify_corpus_case_fail_wrong_decision() {
        let case = CorpusTestCase {
            description: "git status should NOT be blocked".to_string(),
            command: "git status".to_string(),
            expected: "deny".to_string(), // Wrong: git status is allowed
            rule_id: None,
            log: None,
        };
        let result = verify_corpus_case(&case, CorpusCategory::TruePositives);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("Decision mismatch"));
    }

    #[test]
    fn test_verify_corpus_case_with_log_expectations() {
        let case = CorpusTestCase {
            description: "git reset --hard with log checks".to_string(),
            command: "git reset --hard".to_string(),
            expected: "deny".to_string(),
            rule_id: Some("core.git:reset-hard".to_string()),
            log: Some(ExpectedLog {
                decision: Some("deny".to_string()),
                mode: Some("deny".to_string()),
                pack_id: Some("core.git".to_string()),
                pattern_name: Some("reset-hard".to_string()),
                rule_id: Some("core.git:reset-hard".to_string()),
                reason_contains: Some("uncommitted".to_string()),
                allowlist_layer: None,
            }),
        };
        let result = verify_corpus_case(&case, CorpusCategory::TruePositives);
        assert!(result.is_ok(), "Expected pass: {result:?}");
    }

    #[test]
    fn test_load_corpus_file() {
        // Test loading a real corpus file
        let path = std::path::Path::new("tests/corpus/true_positives/git_destructive.toml");
        if path.exists() {
            let cases = load_corpus_file(path);
            assert!(cases.is_ok(), "Failed to load: {cases:?}");
            let cases = cases.unwrap();
            assert!(!cases.is_empty());
            // First case should be git reset --hard
            assert!(cases[0].command.contains("git reset"));
        }
    }

    #[test]
    fn test_eval_snapshot_serialization() {
        let snapshot = eval_snapshot("git reset --hard");
        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(json.contains("deny"));
        assert!(json.contains("core.git:reset-hard"));

        // Round-trip
        let deserialized: EvalSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snapshot, deserialized);
    }
}

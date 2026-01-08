//! AST-based pattern matching for heredoc and inline script content.
//!
//! This module implements Tier 3 of the heredoc detection architecture,
//! using ast-grep-core for structural pattern matching.
//!
//! # Architecture
//!
//! ```text
//! Content + Language
//!      │
//!      ▼
//! ┌─────────────────┐
//! │   AstMatcher    │ ─── Parse error ──► ALLOW + diagnostic
//! │   (ast-grep)    │ ─── Timeout ──► ALLOW + diagnostic
//! │   <5ms typical  │ ─── No match ──► ALLOW
//! │   20ms max      │ ─── Match ──► BLOCK
//! └─────────────────┘
//! ```
//!
//! # Error Handling
//!
//! All errors result in fail-open behavior (ALLOW) with diagnostics:
//! - Parse errors: Language syntax not recognized
//! - Timeouts: Pattern matching exceeded time budget
//! - Unknown language: No grammar available
//!
//! # Performance
//!
//! - Pattern compilation: One-time at startup
//! - Parse: <2ms for typical heredoc sizes
//! - Match: <1ms typical
//! - Hard timeout: 20ms

use crate::heredoc::ScriptLanguage;
use ast_grep_core::{AstGrep, Pattern};
use ast_grep_language::SupportLang;
use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

/// Hard timeout for AST operations (20ms as per ADR).
const AST_TIMEOUT_MS: u64 = 20;

/// Severity level for pattern matches.
///
/// Determines the default action taken when a pattern matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    /// Always block - no allowlist override without explicit config.
    Critical,
    /// Block by default, can be allowlisted.
    High,
    /// Warn by default (log but don't block).
    Medium,
    /// Log only - informational.
    Low,
}

impl Severity {
    /// Human-readable label for this severity.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }

    /// Whether this severity should block by default.
    #[must_use]
    pub const fn blocks_by_default(&self) -> bool {
        matches!(self, Self::Critical | Self::High)
    }
}

/// Result of a pattern match.
#[derive(Debug, Clone)]
pub struct PatternMatch {
    /// Stable rule ID for allowlisting (e.g., `heredoc.python.subprocess_rm`).
    pub rule_id: String,
    /// Human-readable reason for the match.
    pub reason: String,
    /// Preview of the matched text (truncated if too long).
    pub matched_text_preview: String,
    /// Byte offset of match start in the content.
    pub start: usize,
    /// Byte offset of match end in the content.
    pub end: usize,
    /// 1-based line number where match starts.
    pub line_number: usize,
    /// Severity level of this match.
    pub severity: Severity,
    /// Optional suggestion for safe alternative.
    pub suggestion: Option<String>,
}

/// Error during AST matching (all errors are non-fatal, fail-open).
#[derive(Debug, Clone)]
pub enum MatchError {
    /// Language not supported by ast-grep.
    UnsupportedLanguage(ScriptLanguage),
    /// Failed to parse content as the specified language.
    ParseError { language: ScriptLanguage, detail: String },
    /// Pattern matching exceeded timeout.
    Timeout { elapsed_ms: u64, budget_ms: u64 },
    /// Pattern compilation failed (should not happen with static patterns).
    PatternError { pattern: String, detail: String },
}

impl std::fmt::Display for MatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedLanguage(lang) => {
                write!(f, "unsupported language for AST matching: {lang:?}")
            }
            Self::ParseError { language, detail } => {
                write!(f, "AST parse error for {language:?}: {detail}")
            }
            Self::Timeout { elapsed_ms, budget_ms } => {
                write!(f, "AST matching timeout: {elapsed_ms}ms > {budget_ms}ms budget")
            }
            Self::PatternError { pattern, detail } => {
                write!(f, "pattern compilation error for '{pattern}': {detail}")
            }
        }
    }
}

/// A compiled AST pattern with metadata.
#[derive(Debug, Clone)]
pub struct CompiledPattern {
    /// The pattern string (for debugging/logging).
    pub pattern_str: String,
    /// Stable rule ID.
    pub rule_id: String,
    /// Human-readable reason.
    pub reason: String,
    /// Match severity.
    pub severity: Severity,
    /// Optional safe alternative suggestion.
    pub suggestion: Option<String>,
}

impl CompiledPattern {
    /// Create a new compiled pattern.
    #[must_use]
    pub const fn new(
        pattern_str: String,
        rule_id: String,
        reason: String,
        severity: Severity,
        suggestion: Option<String>,
    ) -> Self {
        Self {
            pattern_str,
            rule_id,
            reason,
            severity,
            suggestion,
        }
    }
}

/// AST pattern matcher using ast-grep-core.
///
/// Holds pre-compiled patterns for each supported language.
pub struct AstMatcher {
    /// Patterns organized by language.
    patterns: HashMap<ScriptLanguage, Vec<CompiledPattern>>,
    /// Timeout for matching operations.
    timeout: Duration,
}

impl Default for AstMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl AstMatcher {
    /// Create a new matcher with default destructive patterns.
    #[must_use]
    pub fn new() -> Self {
        Self {
            patterns: default_patterns(),
            timeout: Duration::from_millis(AST_TIMEOUT_MS),
        }
    }

    /// Create a matcher with custom patterns.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // HashMap is not const-constructible
    pub fn with_patterns(patterns: HashMap<ScriptLanguage, Vec<CompiledPattern>>) -> Self {
        Self {
            patterns,
            timeout: Duration::from_millis(AST_TIMEOUT_MS),
        }
    }

    /// Create a matcher with custom timeout.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Builder pattern, not suitable for const
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Find pattern matches in the given code.
    ///
    /// # Errors
    ///
    /// Returns `MatchError` on:
    /// - Unsupported language
    /// - Parse failure
    /// - Timeout
    ///
    /// All errors are non-fatal; callers should fail-open (allow the command).
    #[allow(clippy::cast_possible_truncation)] // Timeout values are always small
    pub fn find_matches(
        &self,
        code: &str,
        language: ScriptLanguage,
    ) -> Result<Vec<PatternMatch>, MatchError> {
        let start_time = Instant::now();
        let budget_ms = self.timeout.as_millis() as u64;

        // Helper to create timeout error
        let timeout_err = |start: Instant| MatchError::Timeout {
            elapsed_ms: start.elapsed().as_millis() as u64,
            budget_ms,
        };

        // Check language support FIRST (before patterns, so we report unsupported properly)
        let Some(ast_lang) = script_language_to_ast_lang(language) else {
            return Err(MatchError::UnsupportedLanguage(language));
        };

        // Get patterns for this language (after language support check)
        let patterns = match self.patterns.get(&language) {
            Some(p) if !p.is_empty() => p,
            _ => return Ok(Vec::new()), // No patterns = no matches
        };

        // Parse the code
        let ast = AstGrep::new(code, ast_lang);
        let root = ast.root();

        // Check timeout after parsing
        if start_time.elapsed() > self.timeout {
            return Err(timeout_err(start_time));
        }

        let mut matches = Vec::new();

        // Match each pattern
        for compiled in patterns {
            // Check timeout before each pattern
            if start_time.elapsed() > self.timeout {
                return Err(timeout_err(start_time));
            }

            // Try to compile the pattern
            let pattern = match Pattern::try_new(&compiled.pattern_str, ast_lang) {
                Ok(p) => p,
                Err(e) => {
                    // Log but continue - pattern error shouldn't block all matching
                    eprintln!(
                        "Warning: failed to compile pattern '{}': {}",
                        compiled.pattern_str, e
                    );
                    continue;
                }
            };

            // Find all matches for this pattern
            for node in root.find_all(&pattern) {
                let matched_text = node.text();
                let range = node.range();

                // Calculate line number (1-based)
                let line_number = code[..range.start].matches('\n').count() + 1;

                // Create preview (truncate if too long, UTF-8 safe)
                let preview = truncate_preview(&matched_text, 60);

                matches.push(PatternMatch {
                    rule_id: compiled.rule_id.clone(),
                    reason: compiled.reason.clone(),
                    matched_text_preview: preview,
                    start: range.start,
                    end: range.end,
                    line_number,
                    severity: compiled.severity,
                    suggestion: compiled.suggestion.clone(),
                });
            }
        }

        Ok(matches)
    }

    /// Check if any blocking patterns match (convenience method).
    ///
    /// Returns the first blocking match, or None if no blocking patterns match.
    #[must_use]
    pub fn has_blocking_match(
        &self,
        code: &str,
        language: ScriptLanguage,
    ) -> Option<PatternMatch> {
        self.find_matches(code, language)
            .ok()
            .and_then(|matches| matches.into_iter().find(|m| m.severity.blocks_by_default()))
    }
}

/// Truncate a string to at most `max_chars` characters, UTF-8 safe.
///
/// If truncation occurs, appends "..." to indicate more content exists.
fn truncate_preview(text: &str, max_chars: usize) -> String {
    let char_count = text.chars().count();
    if char_count <= max_chars {
        text.to_string()
    } else {
        // Leave room for "..."
        let truncate_at = max_chars.saturating_sub(3);
        let truncated: String = text.chars().take(truncate_at).collect();
        format!("{truncated}...")
    }
}

/// Convert `ScriptLanguage` to ast-grep's `SupportLang`.
const fn script_language_to_ast_lang(lang: ScriptLanguage) -> Option<SupportLang> {
    match lang {
        ScriptLanguage::Python => Some(SupportLang::Python),
        ScriptLanguage::JavaScript => Some(SupportLang::JavaScript),
        ScriptLanguage::TypeScript => Some(SupportLang::TypeScript),
        ScriptLanguage::Ruby => Some(SupportLang::Ruby),
        ScriptLanguage::Bash => Some(SupportLang::Bash),
        ScriptLanguage::Perl | ScriptLanguage::Unknown => None,
    }
}

/// Default patterns for heredoc scanning.
///
/// These patterns detect destructive operations in embedded scripts.
/// Each pattern has a stable rule ID for allowlisting.
#[allow(clippy::too_many_lines)]
fn default_patterns() -> HashMap<ScriptLanguage, Vec<CompiledPattern>> {
    let mut patterns = HashMap::new();

    // Python patterns
    patterns.insert(
        ScriptLanguage::Python,
        vec![
            CompiledPattern::new(
                "shutil.rmtree($$$)".to_string(),
                "heredoc.python.shutil_rmtree".to_string(),
                "shutil.rmtree() recursively deletes directories".to_string(),
                Severity::Critical,
                Some("Use shutil.rmtree with explicit path validation".to_string()),
            ),
            CompiledPattern::new(
                "os.remove($$$)".to_string(),
                "heredoc.python.os_remove".to_string(),
                "os.remove() deletes files".to_string(),
                Severity::High,
                None,
            ),
            CompiledPattern::new(
                "os.rmdir($$$)".to_string(),
                "heredoc.python.os_rmdir".to_string(),
                "os.rmdir() deletes directories".to_string(),
                Severity::High,
                None,
            ),
            CompiledPattern::new(
                "os.unlink($$$)".to_string(),
                "heredoc.python.os_unlink".to_string(),
                "os.unlink() deletes files".to_string(),
                Severity::High,
                None,
            ),
            CompiledPattern::new(
                "pathlib.Path($$$).unlink($$$)".to_string(),
                "heredoc.python.pathlib_unlink".to_string(),
                "Path.unlink() deletes files".to_string(),
                Severity::High,
                None,
            ),
            CompiledPattern::new(
                "subprocess.run($$$)".to_string(),
                "heredoc.python.subprocess_run".to_string(),
                "subprocess.run() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "os.system($$$)".to_string(),
                "heredoc.python.os_system".to_string(),
                "os.system() executes shell commands".to_string(),
                Severity::High,
                Some("Use subprocess with explicit arguments instead".to_string()),
            ),
        ],
    );

    // JavaScript/Node patterns
    patterns.insert(
        ScriptLanguage::JavaScript,
        vec![
            CompiledPattern::new(
                "fs.rmSync($$$)".to_string(),
                "heredoc.javascript.fs_rmsync".to_string(),
                "fs.rmSync() deletes files/directories".to_string(),
                Severity::Critical,
                None,
            ),
            CompiledPattern::new(
                "fs.rmdirSync($$$)".to_string(),
                "heredoc.javascript.fs_rmdirsync".to_string(),
                "fs.rmdirSync() deletes directories".to_string(),
                Severity::High,
                None,
            ),
            CompiledPattern::new(
                "fs.unlinkSync($$$)".to_string(),
                "heredoc.javascript.fs_unlinksync".to_string(),
                "fs.unlinkSync() deletes files".to_string(),
                Severity::High,
                None,
            ),
            CompiledPattern::new(
                "child_process.execSync($$$)".to_string(),
                "heredoc.javascript.execsync".to_string(),
                "execSync() executes shell commands".to_string(),
                Severity::High,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "require('child_process').execSync($$$)".to_string(),
                "heredoc.javascript.require_execsync".to_string(),
                "execSync() executes shell commands".to_string(),
                Severity::High,
                None,
            ),
        ],
    );

    // TypeScript patterns (similar to JavaScript)
    patterns.insert(
        ScriptLanguage::TypeScript,
        vec![
            CompiledPattern::new(
                "fs.rmSync($$$)".to_string(),
                "heredoc.typescript.fs_rmsync".to_string(),
                "fs.rmSync() deletes files/directories".to_string(),
                Severity::Critical,
                None,
            ),
            CompiledPattern::new(
                "fs.unlinkSync($$$)".to_string(),
                "heredoc.typescript.fs_unlinksync".to_string(),
                "fs.unlinkSync() deletes files".to_string(),
                Severity::High,
                None,
            ),
            CompiledPattern::new(
                "Deno.remove($$$)".to_string(),
                "heredoc.typescript.deno_remove".to_string(),
                "Deno.remove() deletes files/directories".to_string(),
                Severity::High,
                None,
            ),
        ],
    );

    // Ruby patterns
    patterns.insert(
        ScriptLanguage::Ruby,
        vec![
            CompiledPattern::new(
                "FileUtils.rm_rf($$$)".to_string(),
                "heredoc.ruby.fileutils_rm_rf".to_string(),
                "FileUtils.rm_rf() recursively deletes directories".to_string(),
                Severity::Critical,
                None,
            ),
            CompiledPattern::new(
                "FileUtils.rm($$$)".to_string(),
                "heredoc.ruby.fileutils_rm".to_string(),
                "FileUtils.rm() deletes files".to_string(),
                Severity::High,
                None,
            ),
            CompiledPattern::new(
                "File.delete($$$)".to_string(),
                "heredoc.ruby.file_delete".to_string(),
                "File.delete() removes files".to_string(),
                Severity::High,
                None,
            ),
            CompiledPattern::new(
                "Dir.rmdir($$$)".to_string(),
                "heredoc.ruby.dir_rmdir".to_string(),
                "Dir.rmdir() removes directories".to_string(),
                Severity::High,
                None,
            ),
            CompiledPattern::new(
                "system($$$)".to_string(),
                "heredoc.ruby.system".to_string(),
                "system() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
        ],
    );

    // Bash patterns
    patterns.insert(
        ScriptLanguage::Bash,
        vec![
            CompiledPattern::new(
                "rm -rf $$$".to_string(),
                "heredoc.bash.rm_rf".to_string(),
                "rm -rf recursively deletes files/directories".to_string(),
                Severity::Critical,
                Some("Verify the target path carefully before running".to_string()),
            ),
            CompiledPattern::new(
                "rm -r $$$".to_string(),
                "heredoc.bash.rm_r".to_string(),
                "rm -r recursively deletes".to_string(),
                Severity::High,
                None,
            ),
            CompiledPattern::new(
                "git reset --hard".to_string(),
                "heredoc.bash.git_reset_hard".to_string(),
                "git reset --hard discards uncommitted changes".to_string(),
                Severity::Critical,
                Some("Use 'git stash' to save changes first".to_string()),
            ),
            CompiledPattern::new(
                "git clean -fd".to_string(),
                "heredoc.bash.git_clean_fd".to_string(),
                "git clean -fd deletes untracked files".to_string(),
                Severity::High,
                Some("Use 'git clean -n' to preview first".to_string()),
            ),
        ],
    );

    patterns
}

/// Global default matcher instance (lazy-initialized).
pub static DEFAULT_MATCHER: LazyLock<AstMatcher> = LazyLock::new(AstMatcher::new);

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::similar_names)] // `matcher` vs `matches` is readable in test code
mod tests {
    use super::*;

    #[test]
    fn severity_labels() {
        assert_eq!(Severity::Critical.label(), "critical");
        assert_eq!(Severity::High.label(), "high");
        assert_eq!(Severity::Medium.label(), "medium");
        assert_eq!(Severity::Low.label(), "low");
    }

    #[test]
    fn severity_blocking() {
        assert!(Severity::Critical.blocks_by_default());
        assert!(Severity::High.blocks_by_default());
        assert!(!Severity::Medium.blocks_by_default());
        assert!(!Severity::Low.blocks_by_default());
    }

    #[test]
    fn match_error_display() {
        let errors = vec![
            MatchError::UnsupportedLanguage(ScriptLanguage::Perl),
            MatchError::ParseError {
                language: ScriptLanguage::Python,
                detail: "syntax error".to_string(),
            },
            MatchError::Timeout {
                elapsed_ms: 25,
                budget_ms: 20,
            },
            MatchError::PatternError {
                pattern: "bad pattern".to_string(),
                detail: "invalid syntax".to_string(),
            },
        ];

        for err in errors {
            let display = format!("{err}");
            assert!(!display.is_empty());
        }
    }

    #[test]
    fn matcher_default_has_patterns() {
        let matcher = AstMatcher::new();
        assert!(!matcher.patterns.is_empty());
        assert!(matcher.patterns.contains_key(&ScriptLanguage::Python));
        assert!(matcher.patterns.contains_key(&ScriptLanguage::JavaScript));
        assert!(matcher.patterns.contains_key(&ScriptLanguage::Ruby));
        assert!(matcher.patterns.contains_key(&ScriptLanguage::Bash));
    }

    #[test]
    fn python_positive_match() {
        let matcher = AstMatcher::new();
        let code = "import shutil\nshutil.rmtree('/tmp/test')";

        let matches = matcher.find_matches(code, ScriptLanguage::Python);
        match matches {
            Ok(m) => {
                assert!(!m.is_empty(), "should match shutil.rmtree");
                assert_eq!(m[0].rule_id, "heredoc.python.shutil_rmtree");
                assert!(m[0].severity.blocks_by_default());
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn python_negative_match() {
        let matcher = AstMatcher::new();
        let code = "import os\nprint('hello world')";

        let matches = matcher.find_matches(code, ScriptLanguage::Python);
        match matches {
            Ok(m) => assert!(m.is_empty(), "should not match safe code"),
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn javascript_positive_match() {
        let matcher = AstMatcher::new();
        let code = "const fs = require('fs');\nfs.rmSync('/tmp/test', {recursive: true});";

        let matches = matcher.find_matches(code, ScriptLanguage::JavaScript);
        match matches {
            Ok(m) => {
                assert!(!m.is_empty(), "should match fs.rmSync");
                assert!(m[0].rule_id.contains("rmsync"));
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn javascript_negative_match() {
        let matcher = AstMatcher::new();
        let code = "console.log('hello');";

        let matches = matcher.find_matches(code, ScriptLanguage::JavaScript);
        match matches {
            Ok(m) => assert!(m.is_empty(), "should not match safe code"),
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn unsupported_language_returns_error() {
        let matcher = AstMatcher::new();
        let code = "print 'hello perl';";

        let result = matcher.find_matches(code, ScriptLanguage::Perl);
        assert!(matches!(result, Err(MatchError::UnsupportedLanguage(_))));
    }

    #[test]
    fn unknown_language_returns_error() {
        let matcher = AstMatcher::new();
        let code = "some code";

        let result = matcher.find_matches(code, ScriptLanguage::Unknown);
        assert!(matches!(result, Err(MatchError::UnsupportedLanguage(_))));
    }

    #[test]
    fn has_blocking_match_returns_first_blocker() {
        let matcher = AstMatcher::new();
        let code = "import shutil\nshutil.rmtree('/danger')";

        let result = matcher.has_blocking_match(code, ScriptLanguage::Python);
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_id, "heredoc.python.shutil_rmtree");
    }

    #[test]
    fn has_blocking_match_returns_none_for_safe_code() {
        let matcher = AstMatcher::new();
        let code = "x = 1 + 2";

        let result = matcher.has_blocking_match(code, ScriptLanguage::Python);
        assert!(result.is_none());
    }

    #[test]
    fn has_blocking_match_fails_open_on_error() {
        let matcher = AstMatcher::new();
        let code = "some perl code";

        // Perl is unsupported - should fail open (return None, not panic)
        let result = matcher.has_blocking_match(code, ScriptLanguage::Perl);
        assert!(result.is_none());
    }

    #[test]
    fn match_includes_line_number() {
        let matcher = AstMatcher::new();
        let code = "x = 1\ny = 2\nshutil.rmtree('/test')";

        let matches = matcher
            .find_matches(code, ScriptLanguage::Python)
            .expect("should parse");
        assert!(!matches.is_empty());
        assert_eq!(matches[0].line_number, 3); // shutil.rmtree is on line 3
    }

    #[test]
    fn match_preview_truncates_long_text() {
        let ast_matcher = AstMatcher::new();
        // Create code with a very long argument
        let long_path = "/very/long/path/".repeat(10);
        let code = format!("import shutil\nshutil.rmtree('{long_path}')");

        let results = ast_matcher
            .find_matches(&code, ScriptLanguage::Python)
            .expect("should parse");
        assert!(!results.is_empty());
        // Preview should be truncated
        assert!(results[0].matched_text_preview.len() <= 63);
        assert!(results[0].matched_text_preview.ends_with("..."));
    }

    #[test]
    fn empty_code_returns_no_matches() {
        let ast_matcher = AstMatcher::new();

        let results = ast_matcher
            .find_matches("", ScriptLanguage::Python)
            .expect("should parse empty code");
        assert!(results.is_empty());
    }

    #[test]
    fn default_matcher_is_lazy_initialized() {
        // Just verify it can be accessed without panic
        let _ = &*DEFAULT_MATCHER;
        assert!(!DEFAULT_MATCHER.patterns.is_empty());
    }

    #[test]
    fn truncate_preview_handles_utf8_safely() {
        // Test with ASCII
        assert_eq!(truncate_preview("hello", 10), "hello");
        assert_eq!(truncate_preview("hello world!", 8), "hello...");

        // Test with multi-byte UTF-8 (emojis are 4 bytes each)
        let emojis = "🎉🎊🎁🎄🎅";
        assert_eq!(truncate_preview(emojis, 10), emojis); // 5 chars, fits
        assert_eq!(truncate_preview(emojis, 4), "🎉..."); // truncates to 1 emoji + ...

        // Test with CJK characters (3 bytes each)
        let cjk = "你好世界";
        assert_eq!(truncate_preview(cjk, 10), cjk); // 4 chars, fits
        assert_eq!(truncate_preview(cjk, 4), "你..."); // truncates to 1 char + ...

        // Edge cases
        assert_eq!(truncate_preview("", 10), "");
        assert_eq!(truncate_preview("ab", 3), "ab");
        assert_eq!(truncate_preview("abc", 3), "abc");
        assert_eq!(truncate_preview("abcd", 3), "...");
    }

    #[test]
    fn ruby_positive_match() {
        let matcher = AstMatcher::new();
        let code = "require 'fileutils'\nFileUtils.rm_rf('/tmp/danger')";

        let matches = matcher.find_matches(code, ScriptLanguage::Ruby);
        match matches {
            Ok(m) => {
                assert!(!m.is_empty(), "should match FileUtils.rm_rf");
                assert!(m[0].rule_id.contains("ruby"));
                assert!(m[0].severity.blocks_by_default());
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn ruby_negative_match() {
        let matcher = AstMatcher::new();
        let code = "puts 'hello world'";

        let matches = matcher.find_matches(code, ScriptLanguage::Ruby);
        match matches {
            Ok(m) => assert!(m.is_empty(), "should not match safe code"),
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn typescript_positive_match() {
        let matcher = AstMatcher::new();
        let code = "import * as fs from 'fs';\nfs.rmSync('/tmp/test');";

        let matches = matcher.find_matches(code, ScriptLanguage::TypeScript);
        match matches {
            Ok(m) => {
                assert!(!m.is_empty(), "should match fs.rmSync");
                assert!(m[0].rule_id.contains("typescript"));
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
}

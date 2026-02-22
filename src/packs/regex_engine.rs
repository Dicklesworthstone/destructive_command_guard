//! Dual regex engine abstraction for safe and fast pattern matching.
//!
//! The regex safety audit (git_safety_guard-99e.11) found:
//! - ~85% of pack patterns can use the linear-time `regex` crate
//! - ~15% require lookahead/lookbehind (needs `fancy_regex`)
//!
//! This module provides:
//! - [`CompiledRegex`]: Eagerly compiled abstraction that auto-selects engine
//! - [`LazyCompiledRegex`]: Lazily compiled regex using `CompiledRegex` (for pack patterns)
//!
//! The lazy variant avoids regex compilation during pack registry initialization,
//! improving startup latency for the common allow-path case.

use std::borrow::Cow;
use std::sync::OnceLock;

/// A compiled regex that auto-selects between linear-time and backtracking engines.
///
/// Use this instead of `fancy_regex::Regex` directly when the pattern may not
/// require backtracking features. The `regex` crate provides O(n) guarantees
/// but doesn't support lookahead/lookbehind.
///
/// # Example
///
/// ```ignore
/// use destructive_command_guard::packs::regex_engine::CompiledRegex;
///
/// // Auto-selects linear-time engine (no lookahead)
/// let simple = CompiledRegex::new(r"rm\s+-rf").unwrap();
/// assert!(!simple.uses_backtracking());
///
/// // Auto-selects backtracking engine (has lookahead)
/// let lookahead = CompiledRegex::new(r"git\s+push(?=.*--force)").unwrap();
/// assert!(lookahead.uses_backtracking());
/// ```
#[derive(Debug)]
pub enum CompiledRegex {
    /// Linear-time regex (O(n) guaranteed, no backtracking).
    Linear(regex::Regex),
    /// Backtracking regex (supports lookahead/lookbehind).
    Backtracking(fancy_regex::Regex),
}

impl CompiledRegex {
    /// Compile a pattern, auto-selecting the appropriate engine.
    ///
    /// Uses linear-time `regex` crate unless the pattern contains features
    /// that require backtracking:
    /// - Lookahead: `(?=...)`, `(?!...)`
    /// - Lookbehind: `(?<=...)`, `(?<!...)`
    /// - Backreferences: `\1`, `\2`, etc.
    ///
    /// # Errors
    /// Returns an error if the pattern fails to compile.
    pub fn new(pattern: &str) -> Result<Self, String> {
        if needs_backtracking_engine(pattern) {
            fancy_regex::Regex::new(pattern)
                .map(Self::Backtracking)
                .map_err(|e| format!("fancy_regex compile error: {e}"))
        } else {
            match regex::Regex::new(pattern) {
                Ok(re) => Ok(Self::Linear(re)),
                Err(e) => {
                    // Fall back to backtracking engine if linear engine fails
                    // This handles any advanced features that needs_backtracking_engine() missed
                    fancy_regex::Regex::new(pattern)
                        .map(Self::Backtracking)
                        .map_err(|fancy_err| {
                            format!(
                                "regex compile error: {e}, fancy_regex compile error: {fancy_err}"
                            )
                        })
                }
            }
        }
    }

    /// Compile a pattern using the linear-time engine only.
    ///
    /// # Errors
    /// Returns an error if the pattern uses features not supported by the
    /// linear-time engine (lookahead, lookbehind, backreferences).
    pub fn new_linear(pattern: &str) -> Result<Self, String> {
        regex::Regex::new(pattern)
            .map(Self::Linear)
            .map_err(|e| format!("regex compile error: {e}"))
    }

    /// Compile a pattern using the backtracking engine.
    ///
    /// # Errors
    /// Returns an error if the pattern fails to compile.
    pub fn new_backtracking(pattern: &str) -> Result<Self, String> {
        fancy_regex::Regex::new(pattern)
            .map(Self::Backtracking)
            .map_err(|e| format!("fancy_regex compile error: {e}"))
    }

    /// Check if the pattern matches the text.
    ///
    /// For backtracking engine, returns `false` on regex execution errors.
    #[must_use]
    pub fn is_match(&self, text: &str) -> bool {
        match self {
            Self::Linear(re) => re.is_match(text),
            Self::Backtracking(re) => re.is_match(text).unwrap_or(false),
        }
    }

    /// Find the first match in the text.
    ///
    /// Returns the start and end byte offsets of the match.
    #[must_use]
    pub fn find(&self, text: &str) -> Option<(usize, usize)> {
        match self {
            Self::Linear(re) => re.find(text).map(|m| (m.start(), m.end())),
            Self::Backtracking(re) => re.find(text).ok().flatten().map(|m| (m.start(), m.end())),
        }
    }

    /// Get the pattern string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Linear(re) => re.as_str(),
            Self::Backtracking(re) => re.as_str(),
        }
    }

    /// Check if this regex uses the backtracking engine.
    #[must_use]
    pub const fn uses_backtracking(&self) -> bool {
        matches!(self, Self::Backtracking(_))
    }

    /// Replace up to `limit` matches with the replacement string.
    ///
    /// Returns a `Cow::Borrowed` if no replacements were made.
    /// For backtracking engine, falls back to original text on execution errors.
    #[must_use]
    pub fn replacen<'t>(&self, text: &'t str, limit: usize, rep: &str) -> Cow<'t, str> {
        match self {
            Self::Linear(re) => re.replacen(text, limit, rep),
            // Use try_replacen to handle errors gracefully (returns Result)
            Self::Backtracking(re) => re
                .try_replacen(text, limit, rep)
                .unwrap_or(Cow::Borrowed(text)),
        }
    }
}

/// Check if a pattern requires the backtracking engine.
///
/// Returns `true` if the pattern contains features not supported by the
/// linear-time `regex` crate:
/// - Lookahead: `(?=...)`, `(?!...)`
/// - Lookbehind: `(?<=...)`, `(?<!...)`
/// - Backreferences: `\1`, `\2`, etc.
///
/// Note: This is a heuristic based on syntax. Some edge cases (like `\1` in a
/// character class or escaped in a string literal) may produce false positives,
/// but false positives are safe (just use the slower engine unnecessarily).
#[must_use]
pub fn needs_backtracking_engine(pattern: &str) -> bool {
    // Lookahead: (?= positive, (?! negative
    // Lookbehind: (?<= positive, (?<! negative
    // Atomic groups: (?>
    if pattern.contains("(?=")
        || pattern.contains("(?!")
        || pattern.contains("(?<=")
        || pattern.contains("(?<!")
        || pattern.contains("(?>")
    {
        return true;
    }

    // Possessive quantifiers: *+, ++, ?+, {n,m}+
    // Note: This is a heuristic. + can also be a literal or part of character class.
    // However, *+, ++, ?+ are almost always possessive quantifiers in this context.
    if pattern.contains("*+")
        || pattern.contains("++")
        || pattern.contains("?+")
        || pattern.contains("}+")
    {
        return true;
    }

    // Backreferences: \1 through \9 (and \10+ for 10+ capture groups)
    // Check for \1-\9 which covers the vast majority of backreference usage
    let bytes = pattern.as_bytes();
    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i] == b'\\' {
            let next = bytes[i + 1];
            // \1 through \9 are backreferences
            if next.is_ascii_digit() && next != b'0' {
                return true;
            }
        }
    }

    false
}

// ============================================================================
// Lazy Regex Primitive
// ============================================================================

/// A lazily-compiled regex pattern using `CompiledRegex`.
///
/// This primitive stores the pattern text and defers regex compilation until
/// first use. This is critical for pack registry performance: we can initialize
/// pack metadata (keywords, pattern names) without paying the compilation cost
/// for patterns that may never be evaluated (e.g., on the quick-reject allow path).
///
/// # Performance Characteristics
///
/// - **Construction**: O(1) - just stores the pattern string
/// - **First match**: O(pattern) - compiles the regex once
/// - **Subsequent matches**: Varies (backtracking engine may be super-linear)
///
/// # Thread Safety
///
/// Uses `OnceLock` for thread-safe lazy initialization. Multiple threads may
/// race to compile the pattern, but only one compilation occurs.
///
/// # Example
///
/// ```ignore
/// use destructive_command_guard::packs::regex_engine::LazyCompiledRegex;
///
/// // No compilation happens here
/// static PATTERN: LazyCompiledRegex = LazyCompiledRegex::new(r"git\s+reset\s+--hard");
///
/// // Compilation happens on first use
/// assert!(PATTERN.is_match("git reset --hard HEAD"));
/// ```
#[derive(Debug)]
pub struct LazyCompiledRegex {
    pattern: PatternText,
    compiled: OnceLock<Result<CompiledRegex, String>>,
}

#[derive(Debug)]
enum PatternText {
    Static(&'static str),
    Owned(String),
}

impl PatternText {
    fn as_str(&self) -> &str {
        match self {
            Self::Static(pattern) => pattern,
            Self::Owned(pattern) => pattern.as_str(),
        }
    }
}

impl LazyCompiledRegex {
    /// Create a new lazy regex pattern from a static string.
    ///
    /// This is a `const fn` and performs no regex compilation.
    /// The pattern will be compiled on first use.
    #[must_use]
    pub const fn new(pattern: &'static str) -> Self {
        Self {
            pattern: PatternText::Static(pattern),
            compiled: OnceLock::new(),
        }
    }

    /// Create a new lazy regex pattern from an owned string.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new_owned(pattern: String) -> Self {
        Self {
            pattern: PatternText::Owned(pattern),
            compiled: OnceLock::new(),
        }
    }

    /// Get or compile the regex.
    ///
    /// Returns `None` if compilation fails (fail-open).
    fn get_compiled(&self) -> Option<&CompiledRegex> {
        self.compiled
            .get_or_init(|| CompiledRegex::new(self.pattern.as_str()))
            .as_ref()
            .ok()
    }

    /// Check if the pattern matches the text.
    ///
    /// On first call, this compiles the regex. Subsequent calls reuse the
    /// compiled pattern.
    ///
    /// Returns `false` on regex execution or compile errors.
    #[must_use]
    pub fn is_match(&self, haystack: &str) -> bool {
        self.get_compiled()
            .is_some_and(|compiled| compiled.is_match(haystack))
    }

    /// Find the span (start, end) of the first match.
    ///
    /// Returns `None` if no match or on execution/compile error.
    #[must_use]
    pub fn find(&self, haystack: &str) -> Option<(usize, usize)> {
        self.get_compiled()
            .and_then(|compiled| compiled.find(haystack))
    }

    /// Get the pattern string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.pattern.as_str()
    }

    /// Check if the regex has been compiled.
    ///
    /// Useful for testing to verify lazy compilation behavior.
    #[must_use]
    pub fn is_compiled(&self) -> bool {
        matches!(self.compiled.get(), Some(Ok(_)))
    }
}

impl std::fmt::Display for LazyCompiledRegex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linear_engine_selection() {
        // Simple patterns should use linear engine
        let re = CompiledRegex::new(r"rm\s+-rf").unwrap();
        assert!(!re.uses_backtracking());
        assert!(re.is_match("rm -rf /"));
    }

    #[test]
    fn test_backtracking_engine_selection() {
        // Lookahead patterns should use backtracking engine
        let re = CompiledRegex::new(r"git\s+push(?=.*--force)").unwrap();
        assert!(re.uses_backtracking());
        assert!(re.is_match("git push --force"));
        assert!(!re.is_match("git push"));
    }

    #[test]
    fn test_lookbehind() {
        let re = CompiledRegex::new(r"(?<=drop\s)database").unwrap();
        assert!(re.uses_backtracking());
        assert!(re.is_match("drop database"));
    }

    #[test]
    fn test_negative_lookahead() {
        let re = CompiledRegex::new(r"rm(?!\s+--dry-run)").unwrap();
        assert!(re.uses_backtracking());
        assert!(re.is_match("rm -rf"));
        assert!(!re.is_match("rm --dry-run"));
    }

    #[test]
    fn test_needs_backtracking_detection() {
        // Simple patterns - linear engine
        assert!(!needs_backtracking_engine(r"simple"));
        assert!(!needs_backtracking_engine(r"git\s+status"));
        assert!(!needs_backtracking_engine(r"\d+\.\d+")); // \d is NOT a backreference
        assert!(!needs_backtracking_engine(r"foo\0bar")); // \0 is NOT a backreference

        // Lookahead/lookbehind - backtracking needed
        assert!(needs_backtracking_engine(r"(?=lookahead)"));
        assert!(needs_backtracking_engine(r"(?!negative)"));
        assert!(needs_backtracking_engine(r"(?<=lookbehind)"));
        assert!(needs_backtracking_engine(r"(?<!negative-behind)"));

        // Backreferences - backtracking needed
        assert!(needs_backtracking_engine(r"(foo)\1"));
        assert!(needs_backtracking_engine(r"(\w+)\s+\1"));
        assert!(needs_backtracking_engine(r"(a)(b)\2\1"));

        // Two-digit backreferences (detected by first digit)
        // \10 starts with \1 which triggers detection
        assert!(needs_backtracking_engine(
            r"(.)(.)(.)(.)(.)(.)(.)(.)(.)(.).\10"
        ));
    }

    #[test]
    fn test_backreference_pattern() {
        // Backreferences should use backtracking engine
        let re = CompiledRegex::new(r"(\w+)\s+\1").unwrap();
        assert!(re.uses_backtracking());

        // Should match repeated words
        assert!(re.is_match("hello hello"));
        assert!(re.is_match("the the"));
        assert!(!re.is_match("hello world"));
    }

    #[test]
    fn test_find_linear() {
        let re = CompiledRegex::new(r"rm").unwrap();
        assert!(!re.uses_backtracking());
        assert_eq!(re.find("test rm command"), Some((5, 7)));
        assert_eq!(re.find("no match"), None);
    }

    #[test]
    fn test_find_backtracking() {
        // Use lookahead pattern to force backtracking engine
        let re = CompiledRegex::new(r"git(?=\s+push)").unwrap();
        assert!(re.uses_backtracking());
        assert_eq!(re.find("run git push"), Some((4, 7)));
        assert_eq!(re.find("git status"), None); // lookahead fails
    }

    #[test]
    fn test_replacen_linear() {
        let re = CompiledRegex::new(r"foo").unwrap();
        assert!(!re.uses_backtracking());
        assert_eq!(re.replacen("foo bar foo", 1, "baz"), "baz bar foo");
        assert_eq!(re.replacen("foo bar foo", 0, "baz"), "baz bar baz"); // 0 = all
    }

    #[test]
    fn test_replacen_backtracking() {
        // Use backreference pattern to force backtracking engine
        let re = CompiledRegex::new(r"(\w+)\s+\1").unwrap();
        assert!(re.uses_backtracking());
        // Replace duplicate words with "DUPE"
        assert_eq!(re.replacen("the the cat", 1, "DUPE"), "DUPE cat");
    }

    // ==========================================================================
    // Worst-case regex input tests
    // ==========================================================================
    // These tests verify the linear-time engine handles inputs that would cause
    // exponential blowup in backtracking engines (classic ReDoS patterns).

    #[test]
    fn test_worst_case_alternation() {
        // Pattern: (a|a)+ on input "aaaa..." is O(2^n) for backtracking
        // Linear engine handles this in O(n)
        let re = CompiledRegex::new(r"(a|a)+").unwrap();
        assert!(!re.uses_backtracking()); // Should use linear engine

        // This would hang a backtracking engine but linear handles it fine
        let input = "a".repeat(100);
        assert!(re.is_match(&input));
    }

    #[test]
    fn test_worst_case_nested_quantifiers() {
        // Pattern: (a+)+ on input "aaa...!" is classic ReDoS
        // Linear engine guarantees O(n)
        let re = CompiledRegex::new(r"(a+)+$").unwrap();
        assert!(!re.uses_backtracking());

        // Input that would cause catastrophic backtracking
        let mut input = "a".repeat(50);
        input.push('!'); // Force non-match after lots of 'a's
        assert!(!re.is_match(&input)); // Should complete quickly
    }

    #[test]
    fn test_worst_case_star_quantifier() {
        // Pattern: a*a*a*...a*b on input "aaaa...a" (no b)
        let re = CompiledRegex::new(r"a*a*a*a*a*b").unwrap();
        assert!(!re.uses_backtracking());

        let input = "a".repeat(100);
        assert!(!re.is_match(&input)); // No 'b', should be quick
    }

    #[test]
    fn test_worst_case_dot_star() {
        // Pattern: .*.*.*= with non-matching long input
        let re = CompiledRegex::new(r".*.*.*=").unwrap();
        assert!(!re.uses_backtracking());

        let input = "x".repeat(100);
        assert!(!re.is_match(&input)); // No '=', should complete quickly
    }

    #[test]
    fn test_linear_engine_long_input() {
        // Verify linear engine handles long inputs efficiently
        let re = CompiledRegex::new(r"rm\s+-rf\s+/").unwrap();
        assert!(!re.uses_backtracking());

        // Embed the pattern in a very long command
        let mut cmd = "echo ".to_string();
        cmd.push_str(&"x".repeat(10_000));
        cmd.push_str(" && rm -rf / && ");
        cmd.push_str(&"y".repeat(10_000));

        assert!(re.is_match(&cmd));
    }

    #[test]
    fn test_backtracking_safety() {
        // Patterns with lookahead still need backtracking, but should be bounded
        // This test ensures we don't hang on reasonable inputs
        let re = CompiledRegex::new(r"git\s+push(?=.*--force)").unwrap();
        assert!(re.uses_backtracking());

        // Reasonable size input - should complete quickly
        let cmd = format!("git push {} --force", "branch".repeat(100));
        assert!(re.is_match(&cmd));
    }

    #[test]
    fn test_as_str_preserves_pattern() {
        let pattern = r"test\s+pattern";
        let re = CompiledRegex::new(pattern).unwrap();
        assert_eq!(re.as_str(), pattern);
    }

    #[test]
    fn test_as_str_backtracking() {
        // Verify as_str works with backtracking engine too
        let pattern = r"foo(?=bar)";
        let re = CompiledRegex::new(pattern).unwrap();
        assert!(re.uses_backtracking());
        assert_eq!(re.as_str(), pattern);
    }

    #[test]
    fn test_empty_pattern() {
        // Empty pattern should work (matches empty string at every position)
        let re = CompiledRegex::new("").unwrap();
        assert!(!re.uses_backtracking()); // No backtracking features
        assert!(re.is_match("")); // Matches empty string
        assert!(re.is_match("anything")); // Matches at start of any string
        assert_eq!(re.find("test"), Some((0, 0))); // Zero-width match at position 0
    }

    #[test]
    fn test_compile_error_linear() {
        // Invalid regex should return error
        let result = CompiledRegex::new_linear(r"(unclosed");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("regex compile error"));
    }

    #[test]
    fn test_compile_error_backtracking() {
        // Invalid regex should return error
        let result = CompiledRegex::new_backtracking(r"(unclosed");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("fancy_regex compile error"));
    }

    // =========================================================================
    // LazyCompiledRegex Tests
    // =========================================================================

    #[test]
    fn test_lazy_regex_not_compiled_initially() {
        let lazy = LazyCompiledRegex::new(r"test\s+pattern");
        assert!(!lazy.is_compiled());
    }

    #[test]
    fn test_lazy_regex_compiles_on_first_use() {
        let lazy = LazyCompiledRegex::new(r"test\s+pattern");
        assert!(!lazy.is_compiled());

        // First use triggers compilation
        let _ = lazy.is_match("test pattern");
        assert!(lazy.is_compiled());
    }

    #[test]
    fn test_lazy_regex_is_match_same_as_eager() {
        let pattern = r"git\s+reset\s+--hard";
        let lazy = LazyCompiledRegex::new(pattern);
        let eager = CompiledRegex::new(pattern).unwrap();

        // Test matching inputs
        let inputs = [
            "git reset --hard",
            "git reset --hard HEAD",
            "  git reset --hard  ",
            "git status",   // No match
            "reset --hard", // No match
            "",
        ];

        for input in inputs {
            assert_eq!(
                lazy.is_match(input),
                eager.is_match(input),
                "Mismatch for input: {input:?}"
            );
        }
    }

    #[test]
    fn test_lazy_regex_find_span_same_as_eager() {
        let pattern = r"rm\s+-rf";
        let lazy = LazyCompiledRegex::new(pattern);
        let eager = CompiledRegex::new(pattern).unwrap();

        let inputs = [
            "rm -rf /",
            "sudo rm -rf /tmp",
            "echo rm -rf",
            "rm command",
            "",
        ];

        for input in inputs {
            let lazy_span = lazy.find(input);
            let eager_span = eager.find(input);
            assert_eq!(lazy_span, eager_span, "Span mismatch for input: {input:?}");
        }
    }

    #[test]
    fn test_lazy_regex_as_str() {
        let pattern = r"test\s+pattern";
        let lazy = LazyCompiledRegex::new(pattern);
        assert_eq!(lazy.as_str(), pattern);
    }

    #[test]
    fn test_lazy_regex_lookahead() {
        // Test with lookahead pattern (requires fancy_regex)
        let lazy = LazyCompiledRegex::new(r"git\s+push(?=.*--force)");

        assert!(lazy.is_match("git push --force"));
        assert!(lazy.is_match("git push origin main --force"));
        assert!(!lazy.is_match("git push"));
        assert!(!lazy.is_match("git push origin main"));
    }

    #[test]
    fn test_lazy_regex_lookbehind() {
        // Test with lookbehind pattern
        let lazy = LazyCompiledRegex::new(r"(?<=drop\s)database");

        assert!(lazy.is_match("drop database"));
        assert!(!lazy.is_match("database"));
    }

    #[test]
    fn test_lazy_regex_span_with_lookahead() {
        let lazy = LazyCompiledRegex::new(r"git(?=\s+push)");

        // Lookahead is zero-width, so span should be just "git"
        assert_eq!(lazy.find("git push"), Some((0, 3)));
        assert_eq!(lazy.find("run git push now"), Some((4, 7)));
        assert_eq!(lazy.find("git status"), None);
    }

    #[test]
    fn test_lazy_regex_static_usage() {
        // Verify it works as a static (the primary use case)
        static PATTERN: LazyCompiledRegex = LazyCompiledRegex::new(r"hello\s+world");

        assert!(PATTERN.is_match("hello world"));
        assert!(!PATTERN.is_match("hello"));
    }

    #[test]
    fn test_lazy_regex_empty_pattern() {
        let lazy = LazyCompiledRegex::new("");

        // Empty pattern matches at position 0
        assert!(lazy.is_match(""));
        assert!(lazy.is_match("anything"));
        assert_eq!(lazy.find("test"), Some((0, 0)));
    }

    #[test]
    fn test_lazy_regex_reuses_compiled() {
        let lazy = LazyCompiledRegex::new(r"test");

        // Multiple calls should reuse the same compiled regex
        assert!(lazy.is_match("test"));
        assert!(lazy.is_match("test again"));
        assert!(lazy.is_match("another test"));

        // All calls after first should still show as compiled
        assert!(lazy.is_compiled());
    }
}

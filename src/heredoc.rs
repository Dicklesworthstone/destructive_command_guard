//! Two-tier heredoc and inline script detection.
//!
//! This module implements a tiered detection architecture for heredoc and inline
//! script analysis, balancing performance with detection accuracy.
//!
//! # Architecture
//!
//! ```text
//! Command Input
//!      │
//!      ▼
//! ┌─────────────────┐
//! │ Tier 1: Trigger │ ─── No match ──► ALLOW (fast path)
//! │   (<100μs)      │
//! └────────┬────────┘
//!          │ Match
//!          ▼
//! ┌─────────────────┐
//! │ Tier 2: Extract │ ─── Error/Timeout ──► ALLOW + warn
//! │   (<1ms)        │
//! └────────┬────────┘
//!          │ Success
//!          ▼
//! ┌─────────────────┐
//! │ Tier 3: AST     │ ─── No match ──► ALLOW
//! │   (<5ms)        │ ─── Match ──► BLOCK
//! └─────────────────┘
//! ```
//!
//! # Tier 1: Trigger Detection
//!
//! Ultra-fast detection using [`RegexSet`] for parallel matching.
//! Zero allocations on non-match path. MUST have zero false negatives.
//!
//! # Tier 2: Content Extraction
//!
//! Extracts heredoc/inline script content with bounded memory and time.
//! Graceful degradation on malformed input.
//!
//! # Tier 3: AST Pattern Matching (future)
//!
//! Uses ast-grep-core for structural pattern matching.
//! Language-specific patterns for destructive operations.

use memchr::memchr;
use regex::RegexSet;
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tracing::{debug, instrument, trace, warn};

/// Tier 1 trigger patterns for heredoc and inline script detection.
///
/// These patterns are designed for maximum recall (zero false negatives).
/// False positives are acceptable - they just trigger Tier 2 analysis.
///
/// # Performance
///
/// Uses [`RegexSet`] for parallel matching in a single pass over the input.
/// Target latency: <10μs for non-matching, <100μs for matching.
///
/// Note: heredoc operators (e.g. `<<EOF`, `<<< "..."`) are detected via a small,
/// quote-aware scanner so we can suppress obvious false positives inside quoted
/// literals (commit messages, search patterns, etc.) without introducing false
/// negatives for real shell syntax (including `$()`/backtick substitutions).
const HEREDOC_TRIGGER_PATTERNS: [&str; 12] = [
    // Inline interpreter execution. These patterns intentionally allow:
    // - interleaved flags (python -I -c, bash --norc -c)
    // - combined short-flag clusters (bash -lc, node -pe, perl -pi -e)
    // - Windows .exe extensions (python.exe, python3.11.exe, etc.)
    //
    // Tier 1 MUST have zero false negatives for Tier 2 extraction.
    //
    // Python inline execution (matches python, python3, python3.11, python.exe, python3.11.exe, etc.)
    r"\bpython[0-9.]*(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+))*\s+-[A-Za-z]*[ce][A-Za-z]*\s",
    // Ruby inline execution (matches ruby, ruby3, ruby3.0, ruby.exe, etc.)
    r"\bruby[0-9.]*(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+))*\s+-[A-Za-z]*e[A-Za-z]*\s",
    r"\birb[0-9.]*(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+))*\s+-[A-Za-z]*e[A-Za-z]*\s",
    // Perl inline execution (matches perl, perl5, perl5.36, perl.exe, etc.)
    r"\bperl[0-9.]*(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+))*\s+-[A-Za-z]*[eE][A-Za-z]*\s",
    // Node.js inline execution (matches node, node18, nodejs, node.exe, etc.)
    r"\bnode(?:js)?[0-9.]*(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+))*\s+-[A-Za-z]*[ep][A-Za-z]*\s",
    // PHP inline execution
    r"\bphp[0-9.]*(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+))*\s+-[A-Za-z]*r[A-Za-z]*\s",
    // Lua inline execution
    r"\blua[0-9.]*(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+))*\s+-[A-Za-z]*e[A-Za-z]*\s",
    // Shell inline execution (sh -c, bash -c, zsh -c, fish -c, bash -lc, etc.)
    r"\b(?:sh|bash|zsh|fish)(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+))*\s+-[A-Za-z]*c[A-Za-z]*\s",
    // Piped execution to interpreters (versioned, with optional .exe)
    r"\|\s*(?:python[0-9.]*|ruby[0-9.]*|perl[0-9.]*|node(?:js)?[0-9.]*|php[0-9.]*|lua[0-9.]*|sh|bash)(?:\.exe)?\b",
    // Piped to xargs (can execute arbitrary commands)
    r"\|\s*xargs\s",
    // exec/eval in various contexts
    r#"\beval\s+['"]"#,
    r#"\bexec\s+['"]"#,
];

const MANUAL_HEREDOC_TRIGGER_INDEX: usize = HEREDOC_TRIGGER_PATTERNS.len();

static HEREDOC_TRIGGERS: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new(HEREDOC_TRIGGER_PATTERNS).expect("heredoc trigger patterns should compile")
});

#[inline]
#[must_use]
fn contains_active_heredoc_operator(command: &str) -> bool {
    if memchr(b'<', command.as_bytes()).is_none() {
        return false;
    }
    contains_active_heredoc_operator_recursive(command, 0, 0)
}

#[must_use]
fn contains_active_heredoc_operator_recursive(
    command: &str,
    start: usize,
    recursion_depth: usize,
) -> bool {
    // Prevent stack overflow on pathological input.
    //
    // Tier 1 must have zero false negatives; on recursion exhaustion we conservatively
    // trigger (false positives are acceptable here).
    if recursion_depth > 500 {
        return true;
    }

    let bytes = command.as_bytes();
    let len = bytes.len();
    let mut i = start.min(len);

    while i < len {
        match bytes[i] {
            b'<' if i + 1 < len && bytes[i + 1] == b'<' => {
                // Active shell heredoc/here-string operator.
                return true;
            }
            b'\\' => {
                // Handle CRLF escape (consumes 3 bytes: \, \r, \n)
                if i + 2 < len && bytes[i + 1] == b'\r' && bytes[i + 2] == b'\n' {
                    i += 3;
                } else {
                    // Skip escaped byte. Conservative for UTF-8 (see context.rs notes).
                    i = (i + 2).min(len);
                }
            }
            b'\'' => {
                // Single-quoted segment (no escapes, no substitutions).
                i += 1;
                while i < len && bytes[i] != b'\'' {
                    i += 1;
                }
                if i < len {
                    i += 1;
                }
            }
            b'"' => {
                // Double-quoted segment: ignore literal `<<` inside, but scan nested `$()`/backticks.
                let (found, next) = scan_double_quotes_for_heredoc(command, i + 1, recursion_depth);
                if found {
                    return true;
                }
                i = next;
            }
            b'$' if i + 1 < len && bytes[i + 1] == b'(' => {
                let (found, next) =
                    scan_dollar_paren_for_heredoc_recursive(command, i, recursion_depth + 1);
                if found {
                    return true;
                }
                i = next;
            }
            b'`' => {
                let (found, next) =
                    scan_backticks_for_heredoc_recursive(command, i, recursion_depth + 1);
                if found {
                    return true;
                }
                i = next;
            }
            _ => {
                i += 1;
            }
        }
    }

    false
}

#[must_use]
fn scan_double_quotes_for_heredoc(
    command: &str,
    start: usize,
    recursion_depth: usize,
) -> (bool, usize) {
    if recursion_depth > 500 {
        return (true, command.len());
    }

    let bytes = command.as_bytes();
    let len = bytes.len();
    let mut i = start.min(len);

    while i < len {
        match bytes[i] {
            b'"' => return (false, i + 1),
            b'\\' => {
                i = (i + 2).min(len);
            }
            b'$' if i + 1 < len && bytes[i + 1] == b'(' => {
                let (found, next) =
                    scan_dollar_paren_for_heredoc_recursive(command, i, recursion_depth + 1);
                if found {
                    return (true, next);
                }
                i = next;
            }
            b'`' => {
                let (found, next) =
                    scan_backticks_for_heredoc_recursive(command, i, recursion_depth + 1);
                if found {
                    return (true, next);
                }
                i = next;
            }
            _ => {
                i += 1;
            }
        }
    }

    (false, len)
}

#[must_use]
fn scan_dollar_paren_for_heredoc_recursive(
    command: &str,
    start: usize,
    recursion_depth: usize,
) -> (bool, usize) {
    // Prevent stack overflow on pathological input.
    if recursion_depth > 500 {
        return (true, command.len());
    }

    let bytes = command.as_bytes();
    let len = bytes.len();

    debug_assert!(bytes.get(start) == Some(&b'$'));
    debug_assert!(bytes.get(start + 1) == Some(&b'('));

    let mut i = start + 2;
    let mut depth: u32 = 1;

    while i < len {
        match bytes[i] {
            b'<' if i + 1 < len && bytes[i + 1] == b'<' => {
                return (true, i + 2);
            }
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                if depth == 1 {
                    // End of command substitution.
                    return (false, i + 1);
                }
                depth = depth.saturating_sub(1);
                i += 1;
            }
            b'\\' => {
                i = (i + 2).min(len);
            }
            b'\'' => {
                // Single quotes inside: consume until closing.
                i += 1;
                while i < len && bytes[i] != b'\'' {
                    i += 1;
                }
                if i < len {
                    i += 1;
                }
            }
            b'"' => {
                let (found, next) = scan_double_quotes_for_heredoc(command, i + 1, recursion_depth);
                if found {
                    return (true, next);
                }
                i = next;
            }
            b'$' if i + 1 < len && bytes[i + 1] == b'(' => {
                let (found, next) =
                    scan_dollar_paren_for_heredoc_recursive(command, i, recursion_depth + 1);
                if found {
                    return (true, next);
                }
                i = next;
            }
            b'`' => {
                let (found, next) =
                    scan_backticks_for_heredoc_recursive(command, i, recursion_depth + 1);
                if found {
                    return (true, next);
                }
                i = next;
            }
            _ => {
                i += 1;
            }
        }
    }

    (false, len)
}

#[must_use]
fn scan_backticks_for_heredoc_recursive(
    command: &str,
    start: usize,
    recursion_depth: usize,
) -> (bool, usize) {
    if recursion_depth > 500 {
        return (true, command.len());
    }

    let bytes = command.as_bytes();
    let len = bytes.len();

    debug_assert!(bytes.get(start) == Some(&b'`'));

    let mut i = start + 1;
    while i < len {
        match bytes[i] {
            b'<' if i + 1 < len && bytes[i + 1] == b'<' => {
                return (true, i + 2);
            }
            b'\\' => {
                i = (i + 2).min(len);
            }
            b'\'' => {
                i += 1;
                while i < len && bytes[i] != b'\'' {
                    i += 1;
                }
                if i < len {
                    i += 1;
                }
            }
            b'"' => {
                let (found, next) = scan_double_quotes_for_heredoc(command, i + 1, recursion_depth);
                if found {
                    return (true, next);
                }
                i = next;
            }
            b'$' if i + 1 < len && bytes[i + 1] == b'(' => {
                let (found, next) =
                    scan_dollar_paren_for_heredoc_recursive(command, i, recursion_depth + 1);
                if found {
                    return (true, next);
                }
                i = next;
            }
            b'`' => {
                return (false, i + 1);
            }
            _ => {
                i += 1;
            }
        }
    }

    (false, len)
}

/// Result of Tier 1 trigger detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerResult {
    /// No heredoc/inline script indicators found - fast path to ALLOW.
    NoTrigger,
    /// Trigger detected - proceed to Tier 2 extraction.
    Triggered,
}

/// Check if a command contains heredoc or inline script indicators.
///
/// This is Tier 1 of the detection pipeline - ultra-fast screening.
///
/// # Guarantees
///
/// - Zero false negatives: if Tier 2 would find a heredoc, this MUST trigger
/// - Zero allocations on non-match path
/// - Target latency: <10μs for non-matching commands
///
/// # Examples
///
/// ```ignore
/// use destructive_command_guard::heredoc::{check_triggers, TriggerResult};
///
/// // No trigger - fast path
/// assert_eq!(check_triggers("git status"), TriggerResult::NoTrigger);
///
/// // Heredoc trigger
/// assert_eq!(check_triggers("cat << EOF"), TriggerResult::Triggered);
///
/// // Python inline execution
/// assert_eq!(check_triggers("python -c 'import os'"), TriggerResult::Triggered);
/// ```
#[inline]
#[must_use]
#[instrument(skip(command), fields(cmd_len = command.len()))]
pub fn check_triggers(command: &str) -> TriggerResult {
    if contains_active_heredoc_operator(command) || HEREDOC_TRIGGERS.is_match(command) {
        debug!("tier1_trigger: heredoc/inline script indicator detected");
        TriggerResult::Triggered
    } else {
        trace!("tier1_no_trigger: fast path allow");
        TriggerResult::NoTrigger
    }
}

/// Returns the list of trigger pattern indices that matched.
///
/// Useful for debugging and logging which patterns triggered.
#[must_use]
pub fn matched_triggers(command: &str) -> Vec<usize> {
    let mut matches: Vec<usize> = HEREDOC_TRIGGERS.matches(command).into_iter().collect();
    if contains_active_heredoc_operator(command) {
        matches.push(MANUAL_HEREDOC_TRIGGER_INDEX);
    }
    matches
}

// ============================================================================
// Tier 2: Content Extraction
// ============================================================================

use regex::Regex;

/// Limits for content extraction to prevent resource exhaustion.
#[derive(Debug, Clone, Copy)]
pub struct ExtractionLimits {
    /// Maximum bytes to extract from heredoc body (default: 1MB)
    pub max_body_bytes: usize,
    /// Maximum lines to extract from heredoc body (default: 10,000)
    pub max_body_lines: usize,
    /// Maximum number of heredocs to process per command (default: 10)
    pub max_heredocs: usize,
    /// Timeout for extraction in milliseconds (default: 50ms)
    pub timeout_ms: u64,
}

impl Default for ExtractionLimits {
    fn default() -> Self {
        Self {
            max_body_bytes: 1024 * 1024, // 1MB
            max_body_lines: 10_000,
            max_heredocs: 10,
            timeout_ms: 50,
        }
    }
}

/// Detected language for embedded script content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScriptLanguage {
    Bash,
    Go,
    Php,
    Python,
    Ruby,
    Perl,
    JavaScript,
    TypeScript,
    Unknown,
}

impl ScriptLanguage {
    /// Infer language from a command prefix (e.g., "python", "python3", "python3.11").
    ///
    /// Matches exact command names or names with version suffixes (e.g., "python3.11").
    /// Also handles Windows .exe extensions (e.g., "python.exe", "python3.11.exe").
    /// Does NOT match arbitrary words that start with a command name (e.g., "shebang" ≠ "sh").
    #[must_use]
    pub fn from_command(cmd: &str) -> Self {
        let cmd_lower = cmd.to_lowercase();
        // Strip Windows .exe extension if present
        let cmd_base = cmd_lower.strip_suffix(".exe").unwrap_or(&cmd_lower);

        // Helper: check if cmd matches base name, optionally followed by version digits/dots
        // e.g., "python" matches "python", "python3", "python3.11"
        // but "python" does NOT match "pythonic" or "python_helper"
        let matches_interpreter = |base: &str| -> bool {
            if cmd_base == base {
                return true;
            }
            // Allow version suffixes: digits and dots (e.g., "3", "3.11", "3.11.4")
            cmd_base.strip_prefix(base).is_some_and(|suffix| {
                !suffix.is_empty()
                    && suffix.chars().all(|c| c.is_ascii_digit() || c == '.')
                    && suffix.chars().next().is_some_and(|c| c.is_ascii_digit())
            })
        };

        if matches_interpreter("python") {
            Self::Python
        } else if matches_interpreter("ruby") || matches_interpreter("irb") {
            Self::Ruby
        } else if matches_interpreter("perl") {
            Self::Perl
        } else if matches_interpreter("node") || matches_interpreter("nodejs") {
            Self::JavaScript
        } else if matches_interpreter("deno") || matches_interpreter("bun") {
            Self::TypeScript
        } else if matches_interpreter("php") {
            Self::Php
        } else if matches_interpreter("go") {
            // Note: Go doesn't typically use version suffixes in command names
            Self::Go
        } else if matches_interpreter("sh")
            || matches_interpreter("bash")
            || matches_interpreter("zsh")
            || matches_interpreter("fish")
        {
            Self::Bash
        } else {
            Self::Unknown
        }
    }

    /// Infer language from a shebang line (e.g., `#!/usr/bin/env python3`).
    ///
    /// Parses both direct interpreter paths (`#!/bin/bash`) and env-based shebangs
    /// (`#!/usr/bin/env python3`).
    ///
    /// Returns `None` if no valid shebang is found.
    #[must_use]
    pub fn from_shebang(content: &str) -> Option<Self> {
        let first_line = content.lines().next()?;

        // Shebang must start with #!
        let shebang = first_line.strip_prefix("#!")?;
        let shebang = shebang.trim();

        if shebang.is_empty() {
            return None;
        }

        // Extract interpreter: handle both direct paths and env-style shebangs
        // Examples:
        //   #!/bin/bash              -> bash
        //   #!/bin/bash -e           -> bash (ignores flags)
        //   #!/usr/bin/env python3   -> python3
        //   #!/usr/bin/env python3 -u -> python3 (ignores flags)
        //   #!/usr/bin/env -S python3 -u -> python3 (skips env flags)
        //   #!/usr/bin/python        -> python
        let mut parts = shebang.split_whitespace();
        let first = parts.next()?;
        let basename = first.rsplit('/').next().unwrap_or(first);

        // If it's "env", skip any flags (starting with -) to find the interpreter
        let interpreter = if basename == "env" {
            // Skip env flags like -S, -i, -u, etc.
            loop {
                let next = parts.next()?;
                if !next.starts_with('-') {
                    break next.rsplit('/').next().unwrap_or(next);
                }
            }
        } else {
            basename
        };

        // Use existing from_command logic to map interpreter to language
        let lang = Self::from_command(interpreter);
        if lang == Self::Unknown {
            None
        } else {
            Some(lang)
        }
    }

    /// Infer language from content heuristics (fallback detection).
    ///
    /// Examines the first few lines for language-specific patterns like
    /// import statements, requires, or function definitions.
    ///
    /// This is a low-confidence detection method used only when command
    /// prefix and shebang detection fail.
    ///
    /// Returns `None` if no recognizable patterns are found.
    #[must_use]
    pub fn from_content(content: &str) -> Option<Self> {
        // Only examine first 20 lines to bound heuristic cost
        let lines: Vec<&str> = content.lines().take(20).collect();

        // Python indicators (high confidence)
        let has_python_import = lines.iter().any(|l| {
            let trimmed = l.trim();
            trimmed.starts_with("import ") || trimmed.starts_with("from ")
        });
        if has_python_import {
            return Some(Self::Python);
        }

        // TypeScript indicators (check BEFORE JavaScript since TS is a superset)
        // TypeScript-specific patterns that distinguish it from plain JS
        let has_typescript_patterns = lines.iter().any(|l| {
            let trimmed = l.trim();
            trimmed.contains(": string")
                || trimmed.contains(": number")
                || trimmed.contains(": boolean")
                || trimmed.contains("interface ")
                || trimmed.starts_with("type ")
        });
        if has_typescript_patterns {
            return Some(Self::TypeScript);
        }

        // JavaScript/Node indicators
        let has_js_patterns = lines.iter().any(|l| {
            let trimmed = l.trim();
            trimmed.contains("require(")
                || trimmed.starts_with("const ")
                || trimmed.starts_with("let ")
                || trimmed.starts_with("var ")
                || trimmed.contains("module.exports")
        });
        if has_js_patterns {
            return Some(Self::JavaScript);
        }

        // Ruby indicators
        let has_ruby_patterns = lines.iter().any(|l| {
            let trimmed = l.trim();
            trimmed.starts_with("def ")
                || trimmed.starts_with("class ")
                || trimmed.starts_with("require ")
                || trimmed.starts_with("require_relative ")
                || trimmed.contains(".each do")
                || trimmed.contains(" do |")
        });
        // Ruby also needs "end" somewhere to reduce false positives
        let has_end = content.contains("\nend") || content.ends_with("end");
        if has_ruby_patterns && has_end {
            return Some(Self::Ruby);
        }

        // Go indicators (high confidence)
        // Go has distinctive patterns: package declaration, func, :=, import with quotes
        let has_go_patterns = lines.iter().any(|l| {
            let trimmed = l.trim();
            trimmed.starts_with("package ")
                || trimmed.starts_with("func ")
                || trimmed.contains(":=")
                || (trimmed.starts_with("import ") && trimmed.contains('"'))
                || trimmed == "import ("
        });
        if has_go_patterns {
            return Some(Self::Go);
        }

        // Perl indicators
        let has_perl_patterns = lines.iter().any(|l| {
            let trimmed = l.trim();
            trimmed.starts_with("use strict")
                || trimmed.starts_with("use warnings")
                || trimmed.starts_with("my $")
                || trimmed.starts_with("my @")
                || trimmed.starts_with("my %")
                || trimmed.contains("=~ /")
                || trimmed.contains("=~ s/")
        });
        if has_perl_patterns {
            return Some(Self::Perl);
        }

        // Bash indicators (low priority - many scripts look like bash)
        let has_bash_patterns = lines.iter().any(|l| {
            let trimmed = l.trim();
            trimmed.starts_with("if [")
                || trimmed.starts_with("for ")
                || trimmed.starts_with("while ")
                || trimmed.starts_with("case ")
                || trimmed.contains("$((")
                || trimmed.contains("${")
                || trimmed.starts_with("function ")
                || (trimmed.contains("()") && trimmed.contains('{'))
        });
        if has_bash_patterns {
            return Some(Self::Bash);
        }

        None
    }

    /// Detect language using all available signals with priority order.
    ///
    /// Priority:
    /// 1. Command prefix (highest confidence - e.g., `python -c`)
    /// 2. Shebang line (high confidence - e.g., `#!/usr/bin/env python3`)
    /// 3. Content heuristics (lower confidence - imports, patterns)
    /// 4. Unknown (fallback)
    ///
    /// Returns a tuple of (language, confidence) for explainability.
    #[must_use]
    pub fn detect(cmd: &str, content: &str) -> (Self, DetectionConfidence) {
        // Priority 1: Extract interpreter from command prefix
        if let Some(interpreter) = Self::extract_head_interpreter(cmd) {
            let lang = Self::from_command(&interpreter);
            if lang != Self::Unknown {
                return (lang, DetectionConfidence::CommandPrefix);
            }
        }

        // Priority 1b: Check pipe destinations (e.g. "cat <<EOF | python")
        // This handles cases where the heredoc consumer is later in the pipeline
        if cmd.contains('|') {
            for segment in cmd.split('|') {
                let segment = segment.trim();
                if segment.is_empty() {
                    continue;
                }
                if let Some(interpreter) = Self::extract_head_interpreter(segment) {
                    let lang = Self::from_command(&interpreter);
                    if lang != Self::Unknown {
                        return (lang, DetectionConfidence::CommandPrefix);
                    }
                }
            }
        }

        // Priority 2: Shebang detection
        if let Some(lang) = Self::from_shebang(content) {
            return (lang, DetectionConfidence::Shebang);
        }

        // Priority 3: Content heuristics
        if let Some(lang) = Self::from_content(content) {
            return (lang, DetectionConfidence::ContentHeuristics);
        }

        // Priority 4: Unknown
        (Self::Unknown, DetectionConfidence::Unknown)
    }

    /// Extract the interpreter name from the head of a command string.
    ///
    /// Handles various formats:
    /// - `python3 -c "code"` → "python3"
    /// - `/usr/bin/python -c "code"` → "python"
    /// - `env python3 -c "code"` → "python3"
    /// - `env -S python3 -c "code"` → "python3" (skips env flags)
    /// - `env VAR=val python3 -c "code"` → "python3" (skips env vars)
    /// - `bash -c "code"` → "bash"
    fn extract_head_interpreter(cmd: &str) -> Option<String> {
        // Use robust wrapper stripping to handle env flags (e.g. -u, -C) correctly.
        let normalized = crate::normalize::strip_wrapper_prefixes(cmd);
        let cmd_to_check = normalized.normalized;

        let mut parts = cmd_to_check.split_whitespace();
        let first = parts.next()?;

        // Get basename (strip path)
        let basename = first.rsplit('/').next().unwrap_or(first);
        Some(basename.to_string())
    }
}

/// Confidence level of language detection.
///
/// Used by `dcg explain` to show why a particular language was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DetectionConfidence {
    /// Detected from command prefix (e.g., `python -c`).
    /// Highest confidence - the command explicitly names the interpreter.
    CommandPrefix,

    /// Detected from shebang line (e.g., `#!/usr/bin/env python3`).
    /// High confidence - explicit interpreter declaration in the script.
    Shebang,

    /// Detected from content patterns (imports, syntax patterns).
    /// Lower confidence - heuristic-based detection.
    ContentHeuristics,

    /// Could not determine language.
    /// Lowest "confidence" - effectively no detection.
    Unknown,
}

impl DetectionConfidence {
    /// Human-readable label for this confidence level.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::CommandPrefix => "command-prefix",
            Self::Shebang => "shebang",
            Self::ContentHeuristics => "content-heuristics",
            Self::Unknown => "unknown",
        }
    }

    /// Descriptive reason for this confidence level.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::CommandPrefix => "detected from command interpreter (highest confidence)",
            Self::Shebang => "detected from shebang line (high confidence)",
            Self::ContentHeuristics => "inferred from content patterns (lower confidence)",
            Self::Unknown => "could not determine language",
        }
    }
}

/// Type of heredoc extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeredocType {
    /// Standard heredoc (<<)
    Standard,
    /// Tab-stripping heredoc (<<-)
    TabStripped,
    /// Here-string (<<<)
    HereString,
    /// Indentation-stripping heredoc (<<~, Ruby-style)
    IndentStripped,
}

/// Extracted content from a heredoc or inline script.
#[derive(Debug, Clone)]
pub struct ExtractedContent {
    /// The script content (body of heredoc or inline argument).
    pub content: String,
    /// Detected or inferred language.
    pub language: ScriptLanguage,
    /// Heredoc delimiter (e.g., "EOF"), if applicable.
    pub delimiter: Option<String>,
    /// Byte range in the original command.
    pub byte_range: std::ops::Range<usize>,
    /// Byte range of the extracted content inside the original command, if known.
    ///
    /// For inline scripts and here-strings this is the exact content span.
    /// For heredoc bodies, this represents the raw body range (may not map
    /// cleanly if indentation or CRLF normalization occurred).
    pub content_range: Option<std::ops::Range<usize>>,
    /// Whether the delimiter was quoted (suppresses expansion).
    pub quoted: bool,
    /// Type of heredoc (if applicable).
    pub heredoc_type: Option<HeredocType>,
    /// The command that receives this heredoc (e.g., "cat", "bash").
    /// Used to determine if content should be evaluated as executable.
    pub target_command: Option<String>,
}

/// Reason why extraction was skipped (for observability/logging).
#[derive(Debug, Clone, PartialEq)]
pub enum SkipReason {
    /// Input exceeded maximum size limit.
    ExceededSizeLimit { actual: usize, limit: usize },
    /// Input exceeded maximum line count.
    ExceededLineLimit { actual: usize, limit: usize },
    /// Maximum heredoc count reached.
    ExceededHeredocLimit { limit: usize },
    /// Binary-like content detected (contains null bytes or high non-printable ratio).
    BinaryContent {
        null_bytes: usize,
        non_printable_ratio: f32,
    },
    /// Tier 2 extraction exceeded the time budget (fail-open).
    Timeout { elapsed_ms: u64, budget_ms: u64 },
    /// Heredoc delimiter not found (unterminated).
    UnterminatedHeredoc { delimiter: String },
    /// Malformed input that couldn't be parsed.
    MalformedInput { reason: String },
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExceededSizeLimit { actual, limit } => {
                write!(f, "exceeded size limit: {actual} bytes > {limit} bytes")
            }
            Self::ExceededLineLimit { actual, limit } => {
                write!(f, "exceeded line limit: {actual} lines > {limit} lines")
            }
            Self::ExceededHeredocLimit { limit } => {
                write!(f, "exceeded heredoc limit: max {limit} heredocs")
            }
            Self::BinaryContent {
                null_bytes,
                non_printable_ratio,
            } => {
                write!(
                    f,
                    "binary content detected: {null_bytes} null bytes, {:.1}% non-printable",
                    non_printable_ratio * 100.0
                )
            }
            Self::Timeout {
                elapsed_ms,
                budget_ms,
            } => write!(
                f,
                "extraction timeout: {elapsed_ms}ms > {budget_ms}ms budget"
            ),
            Self::UnterminatedHeredoc { delimiter } => {
                write!(f, "unterminated heredoc: delimiter '{delimiter}' not found")
            }
            Self::MalformedInput { reason } => {
                write!(f, "malformed input: {reason}")
            }
        }
    }
}

/// Result of Tier 2 content extraction.
#[derive(Debug)]
pub enum ExtractionResult {
    /// No extractable content found after trigger.
    NoContent,
    /// Successfully extracted content.
    Extracted(Vec<ExtractedContent>),
    /// Extraction was skipped (fail-open with reason for observability).
    Skipped(Vec<SkipReason>),
    Partial {
        extracted: Vec<ExtractedContent>,
        skipped: Vec<SkipReason>,
    },
    /// Extraction failed (timeout, malformed, etc.) - fail open with warning.
    Failed(String),
}

/// Regex patterns for heredoc extraction (compiled once).
static HEREDOC_EXTRACTOR: LazyLock<Regex> = LazyLock::new(|| {
    // Matches: <<[-~]? followed by:
    // 1. Single-quoted delimiter: 'delim' (Group 2)
    // 2. Double-quoted delimiter: "delim" (Group 3)
    // 3. Unquoted delimiter: delim (Group 4)
    // Group 1 is the operator variant (-/~/empty).
    // Note: * instead of + allows empty delimiters (valid in bash).
    Regex::new(r#"<<([-~])?\s*(?:'([^']*)'|"([^"]*)"|([\w.-]+))"#).expect("heredoc regex compiles")
});

/// Regex for here-string extraction with single quotes (<<<).
static HERESTRING_SINGLE_QUOTE: LazyLock<Regex> = LazyLock::new(|| {
    // Matches: <<< 'content' - content can contain double quotes
    // Group 1: content
    Regex::new(r"<<<\s*'([^']*)'").expect("herestring single-quote regex compiles")
});

/// Regex for here-string extraction with double quotes (<<<).
static HERESTRING_DOUBLE_QUOTE: LazyLock<Regex> = LazyLock::new(|| {
    // Matches: <<< "content" - content can contain single quotes
    // Group 1: content
    Regex::new(r#"<<<\s*"([^"]*)""#).expect("herestring double-quote regex compiles")
});

/// Regex for here-string extraction without quotes (<<<).
static HERESTRING_UNQUOTED: LazyLock<Regex> = LazyLock::new(|| {
    // Matches: <<< word - unquoted single word (NOT starting with quote)
    // Group 1: content
    // [^'\x22\s] ensures we don't match quoted forms
    Regex::new(r"<<<\s*([^'\x22\s]\S*)").expect("herestring unquoted regex compiles")
});

/// Regex for inline script flag extraction with single quotes.
static INLINE_SCRIPT_SINGLE_QUOTE: LazyLock<Regex> = LazyLock::new(|| {
    // Matches: command -c/-e/-p/-E/-r followed by single-quoted content
    // Groups: (1) interpreter, (2) optional "js" suffix for node, (3) flag, (4) content
    // Supports versioned interpreters: python3.11, ruby3.0, perl5.36, node18, nodejs20, etc.
    // Supports Windows .exe extensions: python.exe, python3.11.exe, etc.
    Regex::new(r"\b(python[0-9.]*(?:\.exe)?|ruby[0-9.]*(?:\.exe)?|irb[0-9.]*(?:\.exe)?|perl[0-9.]*(?:\.exe)?|node(js)?[0-9.]*(?:\.exe)?|php[0-9.]*(?:\.exe)?|lua[0-9.]*(?:\.exe)?|sh(?:\.exe)?|bash(?:\.exe)?|zsh(?:\.exe)?|fish(?:\.exe)?)\b(?:\s+(?:--\S+|-[A-Za-z]+))*\s+(-[A-Za-z]*[ceEpr][A-Za-z]*)\s*'([^']*)'")
        .expect("inline script single-quote regex compiles")
});

/// Regex for inline script flag extraction with double quotes.
static INLINE_SCRIPT_DOUBLE_QUOTE: LazyLock<Regex> = LazyLock::new(|| {
    // Matches: command -c/-e/-p/-E/-r followed by double-quoted content
    // Groups: (1) interpreter, (2) optional "js" suffix for node, (3) flag, (4) content
    // Supports versioned interpreters: python3.11, ruby3.0, perl5.36, node18, nodejs20, etc.
    // Supports Windows .exe extensions: python.exe, python3.11.exe, etc.
    Regex::new(r#"\b(python[0-9.]*(?:\.exe)?|ruby[0-9.]*(?:\.exe)?|irb[0-9.]*(?:\.exe)?|perl[0-9.]*(?:\.exe)?|node(js)?[0-9.]*(?:\.exe)?|php[0-9.]*(?:\.exe)?|lua[0-9.]*(?:\.exe)?|sh(?:\.exe)?|bash(?:\.exe)?|zsh(?:\.exe)?|fish(?:\.exe)?)\b(?:\s+(?:--\S+|-[A-Za-z]+))*\s+(-[A-Za-z]*[ceEpr][A-Za-z]*)\s*"([^"]*)""#)
        .expect("inline script double-quote regex compiles")
});

// ============================================================================
// Robustness: Binary Content Detection
// ============================================================================

/// Threshold for non-printable character ratio to consider content binary.
const BINARY_THRESHOLD: f32 = 0.30; // 30% non-printable characters

/// Check if content appears to be binary (contains null bytes or high non-printable ratio).
///
/// # Returns
///
/// `Some(SkipReason::BinaryContent)` if the content appears binary, `None` otherwise.
#[must_use]
#[allow(clippy::cast_precision_loss)] // Precision loss acceptable
#[allow(clippy::naive_bytecount)] // Acceptable for bounded content
pub fn check_binary_content(content: &str) -> Option<SkipReason> {
    let bytes = content.as_bytes();
    if bytes.is_empty() {
        return None;
    }

    // Count null bytes (definite binary indicator)
    let null_bytes = bytes.iter().filter(|&&b| b == 0).count();
    if null_bytes > 0 {
        return Some(SkipReason::BinaryContent {
            null_bytes,
            non_printable_ratio: null_bytes as f32 / bytes.len() as f32,
        });
    }

    // Count non-printable characters (excluding common whitespace)
    let non_printable = bytes
        .iter()
        .filter(|&&b| {
            // Non-printable if not in printable ASCII range and not common whitespace
            !(b == b'\n' || b == b'\r' || b == b'\t' || (0x20..=0x7E).contains(&b))
        })
        .count();

    let ratio = non_printable as f32 / bytes.len() as f32;
    if ratio > BINARY_THRESHOLD {
        return Some(SkipReason::BinaryContent {
            null_bytes: 0,
            non_printable_ratio: ratio,
        });
    }

    None
}

#[inline]
fn record_timeout_if_needed(
    start_time: Instant,
    timeout: Duration,
    budget_ms: u64,
    skip_reasons: &mut Vec<SkipReason>,
) -> bool {
    let elapsed = start_time.elapsed();
    if elapsed < timeout {
        return false;
    }

    if !skip_reasons
        .iter()
        .any(|r| matches!(r, SkipReason::Timeout { .. }))
    {
        let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        skip_reasons.push(SkipReason::Timeout {
            elapsed_ms,
            budget_ms,
        });
    }

    true
}

/// Extract heredoc and inline script content from a command.
///
/// This is Tier 2 of the detection pipeline - content extraction with safety bounds.
///
/// # Guarantees
///
/// - Bounded memory usage (never allocate >`max_body_bytes` per heredoc)
/// - Graceful degradation on malformed input (fail-open with warning)
///
/// # Examples
///
/// ```ignore
/// use destructive_command_guard::heredoc::{extract_content, ExtractionLimits, ExtractionResult};
///
/// let result = extract_content(
///     "python3 -c 'import os; os.system(\"rm -rf /\")'",
///     &ExtractionLimits::default()
/// );
///
/// if let ExtractionResult::Extracted(contents) = result {
///     assert_eq!(contents.len(), 1);
///     assert!(contents[0].content.contains("os.system"));
/// }
/// ```
#[must_use]
#[instrument(skip(command, limits), fields(cmd_len = command.len(), timeout_ms = limits.timeout_ms))]
pub fn extract_content(command: &str, limits: &ExtractionLimits) -> ExtractionResult {
    let start_time = Instant::now();
    let timeout = Duration::from_millis(limits.timeout_ms);
    let mut skip_reasons: Vec<SkipReason> = Vec::new();

    // Enforce input size limit
    if command.len() > limits.max_body_bytes {
        warn!(
            actual = command.len(),
            limit = limits.max_body_bytes,
            "tier2_skip: input exceeds size limit"
        );
        skip_reasons.push(SkipReason::ExceededSizeLimit {
            actual: command.len(),
            limit: limits.max_body_bytes,
        });
        return ExtractionResult::Skipped(skip_reasons);
    }

    // Check for binary content (null bytes or high non-printable ratio)
    if let Some(reason) = check_binary_content(command) {
        warn!(?reason, "tier2_skip: binary content detected");
        skip_reasons.push(reason);
        return ExtractionResult::Skipped(skip_reasons);
    }

    let mut extracted: Vec<ExtractedContent> = Vec::new();

    // Enforce time budget (fail open) before doing any further work.
    if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, &mut skip_reasons) {
        return ExtractionResult::Skipped(skip_reasons);
    }

    // Extract inline scripts (-c/-e flags)
    extract_inline_scripts(
        command,
        limits,
        start_time,
        timeout,
        &mut extracted,
        &mut skip_reasons,
    );
    if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, &mut skip_reasons) {
        return if extracted.is_empty() {
            ExtractionResult::Skipped(skip_reasons)
        } else {
            ExtractionResult::Extracted(extracted)
        };
    }

    // Extract here-strings (<<<)
    extract_herestrings(
        command,
        limits,
        start_time,
        timeout,
        &mut extracted,
        &mut skip_reasons,
    );
    if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, &mut skip_reasons) {
        return if extracted.is_empty() {
            ExtractionResult::Skipped(skip_reasons)
        } else {
            ExtractionResult::Extracted(extracted)
        };
    }

    // Extract heredocs (<<, <<-, <<~)
    extract_heredocs(
        command,
        limits,
        start_time,
        timeout,
        &mut extracted,
        &mut skip_reasons,
    );

    // Return based on what we found
    let elapsed_us = start_time.elapsed().as_micros();
    match (extracted.is_empty(), skip_reasons.is_empty()) {
        (true, true) => {
            trace!(elapsed_us, "tier2_complete: no content found");
            ExtractionResult::NoContent
        }
        (true, false) => {
            warn!(
                elapsed_us,
                skip_count = skip_reasons.len(),
                "tier2_complete: skipped"
            );
            ExtractionResult::Skipped(skip_reasons)
        }
        (false, true) => {
            debug!(
                elapsed_us,
                count = extracted.len(),
                "tier2_complete: content extracted"
            );
            ExtractionResult::Extracted(extracted)
        }
        (false, false) => {
            // Partial extraction with some skips - return what we got
            debug!(
                elapsed_us,
                count = extracted.len(),
                skip_count = skip_reasons.len(),
                "tier2_complete: partial extraction with skips"
            );
            ExtractionResult::Extracted(extracted)
        }
    }
}

/// Extract inline scripts from -c/-e flags.
fn extract_inline_scripts(
    command: &str,
    limits: &ExtractionLimits,
    start_time: Instant,
    timeout: Duration,
    extracted: &mut Vec<ExtractedContent>,
    skip_reasons: &mut Vec<SkipReason>,
) {
    if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons) {
        return;
    }
    if extracted.len() >= limits.max_heredocs {
        skip_reasons.push(SkipReason::ExceededHeredocLimit {
            limit: limits.max_heredocs,
        });
        return;
    }

    // Helper to extract from a given regex pattern
    let mut hit_limit = false;
    let mut extract_from_pattern = |pattern: &Regex| {
        for cap in pattern.captures_iter(command) {
            if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons) {
                return;
            }
            if extracted.len() >= limits.max_heredocs {
                hit_limit = true;
                break;
            }

            let cmd_name = cap.get(1).map_or("", |m| m.as_str());
            let flag = cap.get(3).map_or("", |m| m.as_str());
            // Content is in group 4: (1) interpreter, (2) optional "js", (3) flag, (4) content
            let content_match = cap.get(4);
            let content = content_match.map_or("", |m| m.as_str());

            // The regex covers multiple interpreters; validate that the matched flag actually
            // implies inline code for this interpreter (e.g. bash needs -c, perl needs -e/-E).
            let is_inline_flag = if cmd_name.starts_with("python") {
                flag.contains('c') || flag.contains('e')
            } else if cmd_name.starts_with("ruby") || cmd_name.starts_with("irb") {
                flag.contains('e')
            } else if cmd_name.starts_with("perl") {
                flag.contains('e') || flag.contains('E')
            } else if cmd_name.starts_with("node") {
                flag.contains('e') || flag.contains('p')
            } else if cmd_name.starts_with("php") {
                flag.contains('r')
            } else if cmd_name.starts_with("lua") {
                flag.contains('e')
            } else {
                // sh/bash/zsh/fish
                flag.contains('c')
            };

            if !is_inline_flag {
                continue;
            }

            // Enforce content size limit
            if content.len() > limits.max_body_bytes {
                // Skip but don't add to skip_reasons (would be too noisy)
                continue;
            }

            let full_match = cap.get(0).unwrap();
            extracted.push(ExtractedContent {
                content: content.to_string(),
                language: ScriptLanguage::from_command(cmd_name),
                delimiter: None,
                byte_range: full_match.start()..full_match.end(),
                content_range: content_match.map(|m| m.start()..m.end()),
                quoted: true, // -c/-e content is always in quotes
                heredoc_type: None,
                target_command: Some(cmd_name.to_string()), // -c/-e content is executed by the interpreter
            });
        }
    };

    // Extract from both single-quoted and double-quoted patterns
    extract_from_pattern(&INLINE_SCRIPT_SINGLE_QUOTE);
    extract_from_pattern(&INLINE_SCRIPT_DOUBLE_QUOTE);

    if hit_limit {
        skip_reasons.push(SkipReason::ExceededHeredocLimit {
            limit: limits.max_heredocs,
        });
    }
}

/// Extract here-strings (<<<).
fn extract_herestrings(
    command: &str,
    limits: &ExtractionLimits,
    start_time: Instant,
    timeout: Duration,
    extracted: &mut Vec<ExtractedContent>,
    skip_reasons: &mut Vec<SkipReason>,
) {
    if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons) {
        return;
    }
    if extracted.len() >= limits.max_heredocs {
        return; // Already hit limit, don't add another skip reason
    }

    let mut hit_limit = false;

    // Helper to extract from a given pattern (quoted patterns have content in group 1)
    let mut extract_quoted = |pattern: &Regex, is_quoted: bool| {
        for cap in pattern.captures_iter(command) {
            if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons) {
                return;
            }
            if extracted.len() >= limits.max_heredocs {
                hit_limit = true;
                break;
            }

            // Content is in group 1 for all our here-string patterns
            let content_match = cap.get(1);
            let content = content_match.map_or("", |m| m.as_str());

            if content.len() > limits.max_body_bytes {
                continue;
            }

            let full_match = cap.get(0).unwrap();

            // Extract the command that receives the here-string
            let target_cmd = extract_heredoc_target_command(command, full_match.start());

            extracted.push(ExtractedContent {
                content: content.to_string(),
                language: ScriptLanguage::Bash, // Here-strings are bash-specific
                delimiter: None,
                byte_range: full_match.start()..full_match.end(),
                content_range: content_match.map(|m| m.start()..m.end()),
                quoted: is_quoted,
                heredoc_type: Some(HeredocType::HereString),
                target_command: target_cmd,
            });
        }
    };

    // Extract from single-quoted, double-quoted, then unquoted patterns
    // Quoted patterns first to avoid unquoted matching the outer quotes
    extract_quoted(&HERESTRING_SINGLE_QUOTE, true);
    extract_quoted(&HERESTRING_DOUBLE_QUOTE, true);
    extract_quoted(&HERESTRING_UNQUOTED, false);

    if hit_limit {
        skip_reasons.push(SkipReason::ExceededHeredocLimit {
            limit: limits.max_heredocs,
        });
    }
}

/// Extract heredocs (<<, <<-, <<~).
fn extract_heredocs(
    command: &str,
    limits: &ExtractionLimits,
    start_time: Instant,
    timeout: Duration,
    extracted: &mut Vec<ExtractedContent>,
    skip_reasons: &mut Vec<SkipReason>,
) {
    if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons) {
        return;
    }
    if extracted.len() >= limits.max_heredocs {
        return; // Already hit limit
    }

    let mut hit_limit = false;
    for cap in HEREDOC_EXTRACTOR.captures_iter(command) {
        if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons) {
            return;
        }
        if extracted.len() >= limits.max_heredocs {
            hit_limit = true;
            break;
        }

        let operator_variant = cap.get(1).map(|m| m.as_str());

        let (delimiter, quoted) = if let Some(m) = cap.get(2) {
            (m.as_str(), true)
        } else if let Some(m) = cap.get(3) {
            (m.as_str(), true)
        } else if let Some(m) = cap.get(4) {
            (m.as_str(), false)
        } else {
            // Should be unreachable if regex matched
            continue;
        };

        // Determine heredoc type
        let heredoc_type = match operator_variant {
            Some("-") => HeredocType::TabStripped,
            Some("~") => HeredocType::IndentStripped,
            _ => HeredocType::Standard,
        };

        let full_match = cap.get(0).unwrap();
        let mut start_pos = full_match.end();

        // Heredoc bodies start on the next line. If there are trailing tokens after the delimiter
        // on the same line (pipelines, redirects, etc.), skip them so we don't corrupt the
        // extracted body (which can otherwise cause AST parse failures and false negatives).
        start_pos = command[start_pos..]
            .find('\n')
            .map_or(command.len(), |rel| start_pos.saturating_add(rel));

        // Find the terminating delimiter
        match extract_heredoc_body(
            command,
            start_pos,
            delimiter,
            heredoc_type,
            limits,
            start_time,
            timeout,
        ) {
            Ok((content, end_pos, body_start_abs, body_end_abs)) => {
                let (language, _confidence) = ScriptLanguage::detect(command, &content);
                // Extract the command that receives the heredoc
                let target_cmd = extract_heredoc_target_command(command, full_match.start());
                extracted.push(ExtractedContent {
                    content,
                    language,
                    delimiter: Some(delimiter.to_string()),
                    byte_range: full_match.start()..end_pos.min(command.len()),
                    content_range: Some(body_start_abs..body_end_abs),
                    quoted,
                    heredoc_type: Some(heredoc_type),
                    target_command: target_cmd,
                });
            }
            Err(reason) => {
                skip_reasons.push(reason);
                if matches!(skip_reasons.last(), Some(SkipReason::Timeout { .. })) {
                    return;
                }
            }
        }
    }

    if hit_limit {
        skip_reasons.push(SkipReason::ExceededHeredocLimit {
            limit: limits.max_heredocs,
        });
    }
}

/// Extract the command that receives a heredoc or here-string.
///
/// Looks backwards from the heredoc operator position to find the command word.
/// Returns `Some(command_name)` if found, `None` otherwise.
///
/// Examples:
/// - `cat <<EOF` -> Some("cat")
/// - `bash <<EOF` -> Some("bash")
/// - `cat file.txt | tee <<EOF` -> Some("tee")
/// - `$(cat <<EOF)` -> Some("cat")
fn extract_heredoc_target_command(command: &str, heredoc_start: usize) -> Option<String> {
    if heredoc_start == 0 {
        return None;
    }

    let before = &command[..heredoc_start];

    // Trim trailing whitespace before the heredoc operator
    let trimmed = before.trim_end();
    if trimmed.is_empty() {
        return None;
    }

    // Parse tokens backwards to find the command
    // This handles quoted strings, flags, and file arguments properly
    let tokens = tokenize_backwards(trimmed);

    for token in tokens {
        // Skip flags
        if token.starts_with('-') {
            continue;
        }

        // Skip quoted strings (arguments like '{print $1}' or "hello world")
        if (token.starts_with('\'') && token.ends_with('\''))
            || (token.starts_with('"') && token.ends_with('"'))
        {
            continue;
        }

        // Skip if this looks like a file path argument
        if token.contains('/') {
            let basename = token.rsplit('/').next().unwrap_or(&token);

            // Check if this looks like a command path (/bin/cat, /usr/bin/bash)
            // vs a file argument (/tmp/file, /path/to/data)
            let is_known_command = NON_EXECUTING_HEREDOC_COMMANDS.contains(&basename)
                || [
                    "bash", "sh", "zsh", "fish", "ksh", "dash", "python", "perl", "ruby", "node",
                ]
                .contains(&basename);

            // Command paths are typically in standard locations
            let looks_like_command_path = token.starts_with("/bin/")
                || token.starts_with("/usr/bin/")
                || token.starts_with("/usr/local/bin/")
                || token.starts_with("/sbin/")
                || token.starts_with("/usr/sbin/")
                || is_known_command;

            if !looks_like_command_path {
                // Doesn't look like a command path, skip it
                continue;
            }

            return Some(basename.to_string());
        }

        // Skip if this looks like a file with extension
        let has_extension = token.contains('.') && !token.starts_with('.');
        let is_known_command = NON_EXECUTING_HEREDOC_COMMANDS.contains(&token.as_str())
            || [
                "bash", "sh", "zsh", "fish", "ksh", "dash", "python", "perl", "ruby", "node",
            ]
            .contains(&token.as_str());
        if has_extension && !is_known_command {
            continue;
        }

        return Some(token);
    }

    None
}

/// Tokenize a command string backwards, respecting quotes.
/// Returns tokens in reverse order (last token first).
///
/// Note: This function does not handle escaped quotes inside double-quoted strings
/// (e.g., `"foo\"bar"`). In such cases, tokenization may be incorrect. This is acceptable
/// because the failure mode is safe - we won't find the target command and thus won't
/// mask the heredoc content, which is the conservative choice for security.
fn tokenize_backwards(s: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let bytes = s.as_bytes();
    let mut i = s.len();

    while i > 0 {
        // Skip trailing whitespace
        while i > 0 && bytes[i - 1].is_ascii_whitespace() {
            i -= 1;
        }
        if i == 0 {
            break;
        }

        let end = i;

        // Check for quoted string
        if bytes[i - 1] == b'\'' || bytes[i - 1] == b'"' {
            let quote = bytes[i - 1];
            i -= 1;
            // Find matching opening quote
            while i > 0 && bytes[i - 1] != quote {
                i -= 1;
            }
            i = i.saturating_sub(1); // Skip opening quote if present
            tokens.push(s[i..end].to_string());
            continue;
        }

        // Check for command separator (|, ;, &, $, ()
        if matches!(bytes[i - 1], b'|' | b';' | b'&' | b'$' | b'(' | b')') {
            // Stop parsing - we've reached a command boundary
            break;
        }

        // Regular word - scan backwards to whitespace or separator
        while i > 0 {
            let c = bytes[i - 1];
            if c.is_ascii_whitespace() || matches!(c, b'|' | b';' | b'&' | b'$' | b'(' | b')') {
                break;
            }
            i -= 1;
        }

        if i < end {
            tokens.push(s[i..end].to_string());
        }
    }

    tokens
}

/// Commands that do NOT execute their stdin/heredoc content as code.
/// Heredocs passed to these commands are DATA, not executable scripts.
const NON_EXECUTING_HEREDOC_COMMANDS: &[&str] = &[
    // Text output commands
    "cat",
    "tee",
    "echo",
    "printf",
    // File writing/appending
    "dd",
    // Text processing (read stdin, output transformed text)
    "head",
    "tail",
    "grep",
    "egrep",
    "fgrep",
    "sed",
    "awk",
    "cut",
    "sort",
    "uniq",
    "tr",
    "wc",
    "rev",
    "nl",
    "fold",
    "fmt",
    "expand",
    "unexpand",
    "column",
    "paste",
    "join",
    // Encoding/compression (transform data, don't execute)
    "base64",
    "xxd",
    "od",
    "hexdump",
    "gzip",
    "gunzip",
    "bzip2",
    "bunzip2",
    "xz",
    "lzma",
    "zcat",
    "bzcat",
    "xzcat",
    // Network (send data, don't execute)
    "nc",
    "netcat",
    "curl",
    "wget",
    // Checksum/hash
    "md5sum",
    "sha1sum",
    "sha256sum",
    "sha512sum",
    "cksum",
    // Diff/comparison
    "diff",
    "cmp",
    "comm",
    // Mail (compose message body)
    "mail",
    "sendmail",
    // Variable assignment (read into variable, don't execute)
    "read",
];

/// Check if a command executes its heredoc/stdin content as code.
///
/// Returns `true` if the command is known to NOT execute its input,
/// meaning heredoc content passed to it is DATA, not CODE.
#[must_use]
pub fn is_non_executing_heredoc_command(cmd: &str) -> bool {
    // Normalize: strip path prefix if present
    let cmd_name = cmd.rsplit('/').next().unwrap_or(cmd);
    NON_EXECUTING_HEREDOC_COMMANDS.contains(&cmd_name)
}

/// Mask heredoc content when the target command doesn't execute it.
///
/// This prevents false positives where dangerous patterns in DATA (not CODE)
/// trigger security blocks. For example, `cat <<EOF\nrm -rf /\nEOF` should
/// not be blocked because `cat` just outputs the text - it doesn't execute it.
///
/// Returns a `Cow::Borrowed` if no masking was needed, or `Cow::Owned` if
/// heredoc content was replaced with placeholder text.
#[must_use]
pub fn mask_non_executing_heredocs(command: &str) -> std::borrow::Cow<'_, str> {
    use std::borrow::Cow;

    // Quick check: no heredoc operator means nothing to mask
    if !command.contains("<<") {
        return Cow::Borrowed(command);
    }

    let mut result = String::new();
    let mut pos = 0;
    let bytes = command.as_bytes();

    while pos < command.len() {
        // Find next potential heredoc operator
        if let Some(offset) = command[pos..].find("<<") {
            let heredoc_start = pos + offset;

            // Check for <<< (here-string)
            if heredoc_start + 3 <= command.len() && bytes.get(heredoc_start + 2) == Some(&b'<') {
                // Extract target command for here-string
                let target_cmd = extract_heredoc_target_command(command, heredoc_start);
                let should_mask_herestring = target_cmd
                    .as_ref()
                    .is_some_and(|cmd| is_non_executing_heredoc_command(cmd));

                if should_mask_herestring {
                    // Mask here-string content for non-executing targets
                    if let Some((content_start, content_end)) =
                        find_herestring_content_bounds(command, heredoc_start + 3)
                    {
                        // Copy up to the content start (includes <<<)
                        if result.is_empty() {
                            result = command[..content_start].to_string();
                        } else {
                            result.push_str(&command[pos..content_start]);
                        }
                        // Replace content with placeholder
                        result.push_str("'MASKED'");
                        pos = content_end;
                        continue;
                    }
                }

                // Not masking - just advance past <<< and continue
                if !result.is_empty() {
                    result.push_str(&command[pos..heredoc_start + 3]);
                }
                pos = heredoc_start + 3;
                continue;
            }

            // Extract target command (what receives the heredoc)
            let target_cmd = extract_heredoc_target_command(command, heredoc_start);

            // Check if target is non-executing
            let should_mask = target_cmd
                .as_ref()
                .is_some_and(|cmd| is_non_executing_heredoc_command(cmd));

            if should_mask {
                // Parse the heredoc delimiter
                let after_op = &command[heredoc_start + 2..];
                if let Some((delimiter, body_start_offset, heredoc_type)) =
                    parse_heredoc_delimiter(after_op)
                {
                    // Find the heredoc body end (terminating delimiter)
                    let body_start = heredoc_start + 2 + body_start_offset;
                    if let Some(body_end) =
                        find_heredoc_terminator(command, body_start, &delimiter, heredoc_type)
                    {
                        // Mask the heredoc body while preserving length and newlines.
                        if result.is_empty() {
                            result = command[..body_start].to_string();
                        } else {
                            result.push_str(&command[pos..body_start]);
                        }

                        // Identify the start of the terminator line so we keep it intact.
                        let body_slice = &command[body_start..body_end];
                        let terminator_rel = body_slice.rfind('\n').map_or(0, |idx| idx + 1);
                        let terminator_abs = body_start + terminator_rel;

                        let masked_body =
                            mask_preserve_newlines(&command[body_start..terminator_abs]);
                        result.push_str(&masked_body);
                        result.push_str(&command[terminator_abs..body_end]);

                        pos = body_end;
                        continue;
                    }
                }
            }

            // Not masking - copy everything up to and including <<
            if result.is_empty() {
                // First heredoc we're not masking - check if we need to start building result
            } else {
                result.push_str(&command[pos..heredoc_start + 2]);
            }
            pos = heredoc_start + 2;
        } else {
            // No more heredoc operators
            if result.is_empty() {
                return Cow::Borrowed(command);
            }
            result.push_str(&command[pos..]);
            break;
        }
    }

    if result.is_empty() {
        Cow::Borrowed(command)
    } else {
        Cow::Owned(result)
    }
}

fn mask_preserve_newlines(input: &str) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    for b in input.as_bytes() {
        match b {
            b'\n' | b'\r' => out.push(*b),
            _ => out.push(b' '),
        }
    }
    String::from_utf8(out).unwrap_or_default()
}

/// Parse a heredoc delimiter after the << operator.
/// Returns (delimiter, `body_start_offset`, `heredoc_type`) if successful.
fn parse_heredoc_delimiter(after_op: &str) -> Option<(String, usize, HeredocType)> {
    let trimmed = after_op.trim_start_matches([' ', '\t']);
    let skip_whitespace = after_op.len() - trimmed.len();

    if trimmed.is_empty() {
        return None;
    }

    let (heredoc_type, delim_start) = if trimmed.starts_with('-') {
        (HeredocType::TabStripped, 1)
    } else {
        (HeredocType::Standard, 0)
    };

    let delim_chars = &trimmed[delim_start..];

    // Handle quoted delimiters
    let (delimiter, delim_len) = if let Some(stripped) = delim_chars.strip_prefix('"') {
        // Find closing quote
        if let Some(end) = stripped.find('"') {
            let (body, _) = stripped.split_at(end);
            (body.to_string(), end + 2)
        } else {
            return None;
        }
    } else if let Some(stripped) = delim_chars.strip_prefix('\'') {
        // Find closing quote
        if let Some(end) = stripped.find('\'') {
            let (body, _) = stripped.split_at(end);
            (body.to_string(), end + 2)
        } else {
            return None;
        }
    } else {
        // Unquoted - extract word
        let end = delim_chars
            .find(|c: char| c.is_whitespace() || c == '\n' || c == ';' || c == '&' || c == '|')
            .unwrap_or(delim_chars.len());
        if end == 0 {
            return None;
        }
        (delim_chars[..end].to_string(), end)
    };

    // Calculate total offset to body start (skip to newline)
    let total_delim_offset = skip_whitespace + delim_start + delim_len;
    let remaining = &after_op[total_delim_offset..];

    // Find the newline that starts the body
    let newline_offset = remaining.find('\n').map_or(remaining.len(), |i| i + 1);

    Some((delimiter, total_delim_offset + newline_offset, heredoc_type))
}

/// Find the end of a heredoc body (position after the terminating delimiter line).
fn find_heredoc_terminator(
    command: &str,
    body_start: usize,
    delimiter: &str,
    heredoc_type: HeredocType,
) -> Option<usize> {
    if body_start >= command.len() {
        return None;
    }

    let body = &command[body_start..];
    let mut line_start = 0;

    for line in body.split_inclusive('\n') {
        let trimmed = match heredoc_type {
            HeredocType::TabStripped => line.trim_start_matches('\t'),
            HeredocType::IndentStripped => line.trim_start(),
            HeredocType::Standard | HeredocType::HereString => line,
        };

        let line_content = trimmed.trim_end_matches(['\n', '\r']);

        if line_content == delimiter {
            // Found terminator - return position after this line
            return Some(body_start + line_start + line.len());
        }

        line_start += line.len();
    }

    None
}

/// Find the bounds of a here-string's content (start and end byte positions).
/// Returns `(content_start, content_end)` where `content_start` is after any opening quote
/// and `content_end` is before any closing quote or at whitespace/end for unquoted.
fn find_herestring_content_bounds(command: &str, after_operator: usize) -> Option<(usize, usize)> {
    if after_operator >= command.len() {
        return None;
    }

    let remaining = &command[after_operator..];
    let bytes = remaining.as_bytes();

    // Skip whitespace after <<<
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() && bytes[i] != b'\n' {
        i += 1;
    }

    if i >= bytes.len() || bytes[i] == b'\n' {
        return None;
    }

    // Check for quoted content
    if bytes[i] == b'\'' || bytes[i] == b'"' {
        let quote = bytes[i];
        let quote_start = i;
        i += 1;
        // Find closing quote
        while i < bytes.len() && bytes[i] != quote {
            // Handle escaped characters in double quotes
            if quote == b'"' && bytes[i] == b'\\' && i + 1 < bytes.len() {
                i += 2;
            } else {
                i += 1;
            }
        }
        if i < bytes.len() && bytes[i] == quote {
            // Include the quotes in the masked region
            return Some((
                after_operator + quote_start,
                after_operator + i + 1, // after closing quote
            ));
        }
        // No closing quote found - treat as unquoted
    }

    // Unquoted - find end at whitespace or command separator
    let word_start = i;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_whitespace() || matches!(c, b';' | b'&' | b'|' | b')' | b'\n') {
            break;
        }
        i += 1;
    }

    if i > word_start {
        Some((after_operator + word_start, after_operator + i))
    } else {
        None
    }
}

/// Extract the body of a heredoc, finding the terminating delimiter.
fn extract_heredoc_body(
    command: &str,
    start: usize,
    delimiter: &str,
    heredoc_type: HeredocType,
    limits: &ExtractionLimits,
    start_time: Instant,
    timeout: Duration,
) -> Result<(String, usize, usize, usize), SkipReason> {
    if start > command.len() {
        return Err(SkipReason::MalformedInput {
            reason: "heredoc start offset out of bounds".to_string(),
        });
    }

    let remaining = &command[start..];

    // Skip leading newline if present (heredoc body starts on next line)
    let body_start_offset = usize::from(remaining.starts_with('\n'));
    let body_start = &remaining[body_start_offset..];
    let body_start_abs = start + body_start_offset;

    let mut body_lines: Vec<&str> = Vec::new();
    let mut total_bytes: usize = 0;
    let mut cursor: usize = 0; // offset within body_start

    for part in body_start.split_inclusive('\n') {
        // Enforce timeout inside the loop (a single heredoc can be large).
        if start_time.elapsed() >= timeout {
            let elapsed_ms = u64::try_from(start_time.elapsed().as_millis()).unwrap_or(u64::MAX);
            return Err(SkipReason::Timeout {
                elapsed_ms,
                budget_ms: limits.timeout_ms,
            });
        }

        let line = part.strip_suffix('\n').unwrap_or(part);
        // Normalize CRLF line endings so terminator detection works cross-platform and so extracted
        // code doesn't include stray '\r' characters (which can break AST parsing).
        let line = line.strip_suffix('\r').unwrap_or(line);

        // Check if this line is the terminator
        let trimmed = match heredoc_type {
            HeredocType::TabStripped => line.trim_start_matches('\t'),
            HeredocType::IndentStripped => line.trim_start(),
            HeredocType::Standard | HeredocType::HereString => line,
        };

        if trimmed == delimiter {
            // End position should be accurate in the ORIGINAL command (including any indentation
            // before the delimiter). We intentionally exclude the newline after the terminator.
            let terminator_start = body_start_abs + cursor;
            let terminator_end = terminator_start + line.len();
            let mut body_end_abs = terminator_start;
            if body_end_abs > body_start_abs {
                let bytes = command.as_bytes();
                if bytes.get(body_end_abs.saturating_sub(1)) == Some(&b'\n') {
                    body_end_abs = body_end_abs.saturating_sub(1);
                    if bytes.get(body_end_abs.saturating_sub(1)) == Some(&b'\r') {
                        body_end_abs = body_end_abs.saturating_sub(1);
                    }
                }
            }

            let content = match heredoc_type {
                HeredocType::TabStripped => body_lines
                    .iter()
                    .map(|l| l.trim_start_matches('\t'))
                    .collect::<Vec<_>>()
                    .join("\n"),
                HeredocType::IndentStripped => {
                    let min_indent = body_lines
                        .iter()
                        .filter(|l| !l.trim().is_empty())
                        .map(|l| l.len() - l.trim_start().len())
                        .min()
                        .unwrap_or(0);

                    body_lines
                        .iter()
                        .map(|l| {
                            if l.len() >= min_indent {
                                &l[min_indent..]
                            } else {
                                l.trim_start()
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                }
                HeredocType::Standard | HeredocType::HereString => body_lines.join("\n"),
            };

            return Ok((content, terminator_end, body_start_abs, body_end_abs));
        }

        // Enforce limits (fail-open by returning a specific skip reason).
        total_bytes = total_bytes.saturating_add(part.len());
        if total_bytes > limits.max_body_bytes {
            return Err(SkipReason::ExceededSizeLimit {
                actual: total_bytes,
                limit: limits.max_body_bytes,
            });
        }

        if body_lines.len() >= limits.max_body_lines {
            return Err(SkipReason::ExceededLineLimit {
                actual: body_lines.len() + 1,
                limit: limits.max_body_lines,
            });
        }

        body_lines.push(line);
        cursor = cursor.saturating_add(part.len());
    }

    Err(SkipReason::UnterminatedHeredoc {
        delimiter: delimiter.to_string(),
    })
}

// ============================================================================
// Shell Command Extraction for Evaluator Integration (git_safety_guard-uau)
// ============================================================================

use ast_grep_core::AstGrep;
use ast_grep_language::SupportLang;

/// Extracted shell command with position info for evaluator integration.
///
/// Each command represents a simple command invocation that can be
/// fed to the evaluator for destructive pattern matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedShellCommand {
    /// The full command text (reconstructed from AST).
    pub text: String,
    /// Byte offset in the original content.
    pub start: usize,
    /// End byte offset.
    pub end: usize,
    /// 1-based line number.
    pub line_number: usize,
}

/// Extract executable shell commands from heredoc/script content.
///
/// This function parses shell content using tree-sitter-bash (via ast-grep)
/// and extracts individual commands that should be evaluated against the
/// main evaluator pipeline. This keeps all destructive knowledge in packs
/// rather than duplicating rules for heredoc content.
///
/// # What gets extracted
///
/// - Simple commands: `rm -rf /path`, `git reset --hard`
/// - Pipe sources and targets: commands on either side of `|`
/// - Commands inside command substitutions: contents of `$(...)`
/// - Commands inside subshells: contents of `(...)`
///
/// # What does NOT get extracted (false positive avoidance)
///
/// - Comments: `# rm -rf / dangerous` is NOT executed
/// - String literals in echo/printf: content inside quotes is data, not execution
/// - Heredoc delimiters themselves
///
/// # Performance
///
/// Uses ast-grep for parsing which is very fast (<2ms for typical heredocs).
/// No timeout is enforced here as the AST matcher already has its own timeout.
///
/// # Examples
///
/// ```ignore
/// use destructive_command_guard::heredoc::extract_shell_commands;
///
/// // Simple command
/// let commands = extract_shell_commands("rm -rf /tmp/test");
/// assert_eq!(commands.len(), 1);
/// assert_eq!(commands[0].text, "rm -rf /tmp/test");
///
/// // Pipeline - both sides extracted
/// let commands = extract_shell_commands("find . | xargs rm");
/// assert_eq!(commands.len(), 2);
///
/// // Comment - not extracted
/// let commands = extract_shell_commands("# rm -rf / dangerous");
/// assert_eq!(commands.len(), 0);
/// ```
#[must_use]
#[instrument(skip(content), fields(content_len = content.len()))]
pub fn extract_shell_commands(content: &str) -> Vec<ExtractedShellCommand> {
    if content.trim().is_empty() {
        trace!("extract_shell_commands: empty content");
        return Vec::new();
    }

    let start = Instant::now();
    let ast = AstGrep::new(content, SupportLang::Bash);
    let root = ast.root();

    let mut commands = Vec::new();

    // Walk the AST to find command nodes
    // tree-sitter-bash uses "command" nodes for simple commands
    collect_commands_recursive(root, content, &mut commands);

    debug!(
        elapsed_us = start.elapsed().as_micros(),
        count = commands.len(),
        "extract_shell_commands: AST analysis complete"
    );
    commands
}

/// Recursively collect command nodes from the AST.
///
/// Walks the tree looking for "command" nodes (simple commands in bash).
/// Recurses into all child nodes to find nested commands, including:
/// - Command substitutions: `$(cmd)`
/// - Subshells: `(cmd)`
/// - Pipelines, command lists, loops, conditionals, etc.
#[allow(clippy::needless_pass_by_value)]
fn collect_commands_recursive<D: ast_grep_core::Doc>(
    node: ast_grep_core::Node<'_, D>,
    content: &str,
    commands: &mut Vec<ExtractedShellCommand>,
) {
    let kind = node.kind();

    // "command" in tree-sitter-bash is a simple command
    if kind == "command" {
        let range = node.range();
        let text = node.text().to_string();

        // Skip empty commands
        if !text.trim().is_empty() {
            let line_number = content[..range.start].matches('\n').count() + 1;

            commands.push(ExtractedShellCommand {
                text,
                start: range.start,
                end: range.end,
                line_number,
            });
        }
    }

    // Recurse into all children to find nested commands
    // This handles:
    // - Pipelines: `cmd1 | cmd2` has command children
    // - Command lists: `cmd1 && cmd2` has command children
    // - Command substitution: `$(cmd)` contains command
    // - Subshells: `(cmd)` contains command
    for child in node.children() {
        collect_commands_recursive(child, content, commands);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use proptest::prelude::*;

    // ========================================================================
    // Tier 1: Trigger Detection Tests
    // ========================================================================

    mod tier1_triggers {
        use super::*;

        #[test]
        fn no_trigger_on_safe_commands() {
            // Common safe commands should NOT trigger
            let safe_commands = [
                "git status",
                "ls -la",
                "cargo build",
                "npm install",
                "docker ps",
                "kubectl get pods",
                "cat file.txt",
                "echo hello",
                "grep pattern file",
                "find . -name '*.rs'",
            ];

            for cmd in safe_commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::NoTrigger,
                    "should not trigger on: {cmd}"
                );
            }
        }

        #[test]
        fn triggers_on_heredoc_basic() {
            // Basic heredoc forms
            let heredocs = [
                "cat << EOF",
                "cat <<EOF",
                "cat << 'EOF'",
                r#"cat << "EOF""#,
                "cat <<- EOF",       // Tab-stripping heredoc
                "mysql <<< 'query'", // Here-string
            ];

            for cmd in heredocs {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger on heredoc: {cmd}"
                );
            }
        }

        #[test]
        fn triggers_on_python_inline() {
            let python_commands = [
                "python -c 'import os'",
                "python3 -c 'import os'",
                "python -I -c 'import os'",
                "python3 -I -c 'import os'",
                "python -e 'print(1)'",
                "python3 -e 'print(1)'",
            ];

            for cmd in python_commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger on python inline: {cmd}"
                );
            }
        }

        #[test]
        fn triggers_on_versioned_interpreters() {
            // Tier 1 MUST have zero false negatives - versioned interpreters must trigger
            let versioned_commands = [
                // Python versions
                "python3.11 -c 'import os'",
                "python3.12.1 -c 'import os'",
                "python3.9 -e 'print(1)'",
                // Ruby versions
                "ruby3.0 -e 'puts 1'",
                "ruby3.2.1 -e 'exit'",
                // Perl versions
                "perl5.36 -e 'print 1'",
                "perl5.38.2 -E 'say 1'",
                // Node versions
                "node18 -e 'console.log(1)'",
                "node20.1 -e 'console.log(1)'",
                "nodejs18 -e 'console.log(1)'",
                "nodejs20.10.0 -e 'test'",
            ];

            for cmd in versioned_commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger on versioned interpreter: {cmd}"
                );
            }
        }

        #[test]
        fn triggers_on_ruby_inline() {
            let ruby_commands = ["ruby -e 'puts 1'", "ruby -w -e 'puts 1'", "irb -e 'exit'"];

            for cmd in ruby_commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger on ruby inline: {cmd}"
                );
            }
        }

        #[test]
        fn triggers_on_perl_inline() {
            let perl_commands = [
                "perl -e 'print 1'",
                "perl -E 'say 1'", // Modern Perl
                "perl -pi -e 'print 1'",
            ];

            for cmd in perl_commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger on perl inline: {cmd}"
                );
            }
        }

        #[test]
        fn triggers_on_node_inline() {
            let node_commands = [
                "node -e 'console.log(1)'",
                "node -p 'process.version'",
                "node -pe 'process.version'",
            ];

            for cmd in node_commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger on node inline: {cmd}"
                );
            }
        }

        #[test]
        fn triggers_on_shell_inline() {
            let shell_commands = [
                "bash -c 'echo hello'",
                "bash -l -c 'echo hello'",
                "bash -lc 'echo hello'",
                "bash --noprofile --norc -c 'echo hello'",
                "sh -c 'ls'",
                "zsh -c 'pwd'",
                "fish -c 'echo hello'",
            ];

            for cmd in shell_commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger on shell inline: {cmd}"
                );
            }
        }

        #[test]
        fn triggers_on_xargs() {
            let xargs_commands = [
                "find . -name '*.bak' | xargs rm",
                "ls | xargs -I {} echo {}",
                "cat files.txt | xargs -n1 process",
            ];

            for cmd in xargs_commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger on xargs: {cmd}"
                );
            }
        }

        #[test]
        fn triggers_on_piped_execution() {
            let piped_commands = [
                "echo 'print(1)' | python",
                "cat script.py | python3",
                "echo 'puts 1' | ruby",
                "echo 'print 1' | perl",
                "echo 'console.log(1)' | node",
                "echo 'echo hello' | bash",
                "echo 'ls' | sh",
            ];

            for cmd in piped_commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger on piped execution: {cmd}"
                );
            }
        }

        #[test]
        fn triggers_on_eval_exec() {
            let eval_commands = [
                r#"eval "dangerous code""#,
                "eval 'dangerous code'",
                r#"exec "command""#,
                "exec 'command'",
            ];

            for cmd in eval_commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger on eval/exec: {cmd}"
                );
            }
        }

        #[test]
        fn matched_triggers_returns_indices() {
            // Should return the indices of matching patterns
            let matches = matched_triggers("python -c 'test'");
            assert!(!matches.is_empty(), "should have matches for python -c");

            let no_matches = matched_triggers("git status");
            assert!(
                no_matches.is_empty(),
                "should have no matches for git status"
            );
        }

        #[test]
        fn heredoc_syntax_inside_quoted_literals_does_not_trigger() {
            // Common false positives: heredoc syntax used as documentation or search patterns.
            let commands = [
                r#"git commit -m "docs: example heredoc: cat <<EOF rm -rf / EOF""#,
                r#"rg "<<EOF" README.md"#,
                "echo 'cat <<EOF (docs only)'",
            ];

            for cmd in commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::NoTrigger,
                    "should not trigger on quoted literal heredoc syntax: {cmd}"
                );
            }
        }

        #[test]
        fn heredoc_inside_command_substitution_with_outer_quotes_still_triggers() {
            // `$(...)` is executed even when the outer word is double-quoted.
            let cmd = "echo \"$(cat <<EOF\nrm -rf /\nEOF)\"";
            assert_eq!(check_triggers(cmd), TriggerResult::Triggered);
        }

        // Property: Zero false negatives - if content extraction would find
        // something, trigger detection MUST fire. This is tested via the
        // comprehensive test cases above and will be verified with property
        // tests once Tier 2 is implemented.
    }

    // ========================================================================
    // Tier 2: Content Extraction Tests
    // ========================================================================

    mod tier2_extraction {
        use super::*;

        #[test]
        fn extraction_limits_default() {
            let limits = ExtractionLimits::default();
            assert_eq!(limits.max_body_bytes, 1024 * 1024);
            assert_eq!(limits.max_body_lines, 10_000);
            assert_eq!(limits.max_heredocs, 10);
            assert_eq!(limits.timeout_ms, 50);
        }

        #[test]
        fn extracts_inline_script_single_quotes() {
            let result = extract_content("python -c 'import os'", &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "import os");
                assert_eq!(contents[0].language, ScriptLanguage::Python);
                assert!(contents[0].quoted);
            } else {
                panic!("Expected Extracted result");
            }
        }

        #[test]
        fn extracts_inline_script_double_quotes() {
            let result = extract_content(r#"bash -c "echo hello""#, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "echo hello");
                assert_eq!(contents[0].language, ScriptLanguage::Bash);
            } else {
                panic!("Expected Extracted result");
            }
        }

        #[test]
        fn extracts_inline_script_with_intervening_flags() {
            let result = extract_content("python -I -c 'import os'", &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "import os");
                assert_eq!(contents[0].language, ScriptLanguage::Python);
                assert!(contents[0].quoted);
            } else {
                panic!("Expected Extracted result");
            }
        }

        #[test]
        fn extracts_inline_script_with_combined_shell_flags() {
            let result = extract_content("bash -lc 'echo hello'", &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "echo hello");
                assert_eq!(contents[0].language, ScriptLanguage::Bash);
            } else {
                panic!("Expected Extracted result");
            }
        }

        #[test]
        fn extracts_inline_script_with_combined_node_flags() {
            let result =
                extract_content("node -pe 'process.version'", &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "process.version");
                assert_eq!(contents[0].language, ScriptLanguage::JavaScript);
            } else {
                panic!("Expected Extracted result");
            }
        }

        #[test]
        fn extracts_inline_script_with_interleaved_perl_flags() {
            let result = extract_content("perl -pi -e 'print 1'", &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "print 1");
                assert_eq!(contents[0].language, ScriptLanguage::Perl);
            } else {
                panic!("Expected Extracted result");
            }
        }

        #[test]
        fn extracts_here_string() {
            let result = extract_content("cat <<< 'hello world'", &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "hello world");
                assert_eq!(contents[0].heredoc_type, Some(HeredocType::HereString));
            } else {
                panic!("Expected Extracted result");
            }
        }

        #[test]
        fn extracts_heredoc_basic() {
            let cmd = "cat << EOF\nline1\nline2\nEOF";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "line1\nline2");
                assert_eq!(contents[0].delimiter, Some("EOF".to_string()));
                assert_eq!(contents[0].heredoc_type, Some(HeredocType::Standard));
            } else {
                panic!("Expected Extracted result, got {result:?}");
            }
        }

        #[test]
        fn extracts_heredoc_ignores_trailing_tokens_on_delimiter_line() {
            let cmd = "python3 <<EOF | cat\nimport shutil\nshutil.rmtree('/tmp/test')\nEOF";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].language, ScriptLanguage::Python);
                assert_eq!(
                    contents[0].content,
                    "import shutil\nshutil.rmtree('/tmp/test')"
                );
            } else {
                panic!("Expected Extracted result, got {result:?}");
            }
        }

        #[test]
        fn extracts_heredoc_with_crlf_line_endings() {
            let cmd = "cat <<EOF\r\nline1\r\nEOF\r\n";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "line1");
                assert_eq!(contents[0].delimiter.as_deref(), Some("EOF"));
            } else {
                panic!("Expected Extracted result, got {result:?}");
            }
        }

        #[test]
        fn extracts_heredoc_tab_stripped() {
            let cmd = "cat <<- EOF\n\tline1\n\tline2\nEOF";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                // Tab-stripping removes leading tabs
                assert_eq!(contents[0].content, "line1\nline2");
                assert_eq!(contents[0].heredoc_type, Some(HeredocType::TabStripped));
            } else {
                panic!("Expected Extracted result");
            }
        }

        #[test]
        fn extracts_heredoc_indent_stripped() {
            // Indentation-stripping heredoc (<<~) should:
            // - accept an indented terminator
            // - strip the minimum common indentation from non-empty lines
            let cmd = "cat <<~ EOF\n    line1\n    line2\n    EOF";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "line1\nline2");
                assert_eq!(contents[0].heredoc_type, Some(HeredocType::IndentStripped));
            } else {
                panic!("Expected Extracted result, got {result:?}");
            }
        }

        #[test]
        fn extracts_heredoc_quoted_delimiter_sets_quoted_flag() {
            // Quoted delimiter suppresses expansion in real shells; we track this for context.
            let cmd = "cat << 'EOF'\nline1\nEOF";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "line1");
                assert_eq!(contents[0].delimiter.as_deref(), Some("EOF"));
                assert!(contents[0].quoted, "quoted delimiter must set quoted=true");
            } else {
                panic!("Expected Extracted result, got {result:?}");
            }

            let cmd = "cat << EOF\nline1\nEOF";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert!(
                    !contents[0].quoted,
                    "unquoted delimiter must set quoted=false"
                );
            } else {
                panic!("Expected Extracted result, got {result:?}");
            }
        }

        #[test]
        fn heredoc_language_detects_interpreter_prefixes() {
            // Regression test: heredoc bodies must not default to Bash when the interpreter is explicit.
            let cases = [
                ("python3 <<EOF\nprint('hello')\nEOF", ScriptLanguage::Python),
                (
                    "node <<EOF\nconsole.log('hello');\nEOF",
                    ScriptLanguage::JavaScript,
                ),
                ("ruby <<EOF\nputs 'hello'\nEOF", ScriptLanguage::Ruby),
                ("perl <<EOF\nprint \"hello\";\nEOF", ScriptLanguage::Perl),
                ("bash <<EOF\necho hello\nEOF", ScriptLanguage::Bash),
            ];

            for (cmd, expected) in cases {
                let result = extract_content(cmd, &ExtractionLimits::default());
                if let ExtractionResult::Extracted(contents) = result {
                    assert_eq!(
                        contents.len(),
                        1,
                        "expected one heredoc extraction for: {cmd}"
                    );
                    assert_eq!(
                        contents[0].language, expected,
                        "expected language {expected:?} for heredoc: {cmd}"
                    );
                } else {
                    panic!("Expected Extracted result for heredoc: {cmd}, got {result:?}");
                }
            }
        }

        #[test]
        fn heredoc_language_detects_shebang_when_command_unknown() {
            let cmd = "cat <<EOF\n#!/usr/bin/env python3\nimport os\nprint('hi')\nEOF";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].language, ScriptLanguage::Python);
            } else {
                panic!("Expected Extracted result, got {result:?}");
            }
        }

        #[test]
        fn extracts_empty_heredoc() {
            // Empty heredoc is valid - body is empty but terminator is found
            let cmd = "cat << EOF\nEOF";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "");
                assert_eq!(contents[0].delimiter, Some("EOF".to_string()));
            } else {
                panic!("Expected Extracted result for empty heredoc, got {result:?}");
            }
        }

        #[test]
        fn heredoc_byte_range_is_correct() {
            // Test non-empty heredoc byte_range
            let cmd = "python << END\nprint(1)\nEND";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].language, ScriptLanguage::Python);
                let range = &contents[0].byte_range;
                // byte_range should cover from "<< END" to the final "END"
                let extracted_span = &cmd[range.clone()];
                assert_eq!(extracted_span, "<< END\nprint(1)\nEND");
            } else {
                panic!("Expected Extracted result");
            }

            // Test empty heredoc byte_range
            let cmd = "cat << EOF\nEOF";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                let range = &contents[0].byte_range;
                let extracted_span = &cmd[range.clone()];
                assert_eq!(extracted_span, "<< EOF\nEOF");
            } else {
                panic!("Expected Extracted result");
            }

            // Test multi-line heredoc byte_range
            let cmd = "cat << EOF\nline1\nline2\nEOF";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                let range = &contents[0].byte_range;
                let extracted_span = &cmd[range.clone()];
                assert_eq!(extracted_span, "<< EOF\nline1\nline2\nEOF");
            } else {
                panic!("Expected Extracted result");
            }
        }

        #[test]
        fn extracts_here_string_with_nested_quotes() {
            // Here-string with double quotes inside single quotes
            let result = extract_content(
                r#"cat <<< 'hello "world" test'"#,
                &ExtractionLimits::default(),
            );
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, r#"hello "world" test"#);
                assert!(contents[0].quoted);
            } else {
                panic!("Expected Extracted result");
            }

            // Here-string with single quotes inside double quotes
            let result = extract_content(
                r#"cat <<< "hello 'world' test""#,
                &ExtractionLimits::default(),
            );
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "hello 'world' test");
                assert!(contents[0].quoted);
            } else {
                panic!("Expected Extracted result");
            }
        }

        #[test]
        fn from_command_does_not_false_positive() {
            // These should NOT be detected as interpreters
            assert_eq!(
                ScriptLanguage::from_command("shebang"),
                ScriptLanguage::Unknown
            );
            assert_eq!(
                ScriptLanguage::from_command("shell"),
                ScriptLanguage::Unknown
            );
            assert_eq!(
                ScriptLanguage::from_command("pythonic"),
                ScriptLanguage::Unknown
            );
            assert_eq!(
                ScriptLanguage::from_command("nodemon"),
                ScriptLanguage::Unknown
            );
            assert_eq!(
                ScriptLanguage::from_command("perldoc"),
                ScriptLanguage::Unknown
            );
            assert_eq!(
                ScriptLanguage::from_command("bashful"),
                ScriptLanguage::Unknown
            );
        }

        #[test]
        fn from_command_matches_versioned_interpreters() {
            // These SHOULD be detected with version suffixes
            assert_eq!(
                ScriptLanguage::from_command("python3"),
                ScriptLanguage::Python
            );
            assert_eq!(
                ScriptLanguage::from_command("python3.11"),
                ScriptLanguage::Python
            );
            assert_eq!(
                ScriptLanguage::from_command("python3.11.4"),
                ScriptLanguage::Python
            );
            assert_eq!(
                ScriptLanguage::from_command("node18"),
                ScriptLanguage::JavaScript
            );
            assert_eq!(ScriptLanguage::from_command("perl5"), ScriptLanguage::Perl);
        }

        #[test]
        fn no_content_on_safe_command() {
            let result = extract_content("git status", &ExtractionLimits::default());
            assert!(matches!(result, ExtractionResult::NoContent));
        }

        #[test]
        fn script_language_from_command() {
            assert_eq!(
                ScriptLanguage::from_command("python3"),
                ScriptLanguage::Python
            );
            assert_eq!(ScriptLanguage::from_command("ruby"), ScriptLanguage::Ruby);
            assert_eq!(ScriptLanguage::from_command("perl"), ScriptLanguage::Perl);
            assert_eq!(
                ScriptLanguage::from_command("node"),
                ScriptLanguage::JavaScript
            );
            assert_eq!(ScriptLanguage::from_command("bash"), ScriptLanguage::Bash);
            assert_eq!(
                ScriptLanguage::from_command("unknown"),
                ScriptLanguage::Unknown
            );
        }

        // =========================================================================
        // Language detection tests (git_safety_guard-du4)
        // =========================================================================

        #[test]
        fn from_shebang_detects_direct_path() {
            assert_eq!(
                ScriptLanguage::from_shebang("#!/bin/bash\necho hello"),
                Some(ScriptLanguage::Bash)
            );
            assert_eq!(
                ScriptLanguage::from_shebang("#!/usr/bin/python\nimport os"),
                Some(ScriptLanguage::Python)
            );
            assert_eq!(
                ScriptLanguage::from_shebang("#!/usr/bin/ruby\nputs 'hi'"),
                Some(ScriptLanguage::Ruby)
            );
        }

        #[test]
        fn from_shebang_detects_env_path() {
            assert_eq!(
                ScriptLanguage::from_shebang("#!/usr/bin/env python3\nimport sys"),
                Some(ScriptLanguage::Python)
            );
            assert_eq!(
                ScriptLanguage::from_shebang("#!/usr/bin/env node\nconsole.log('hi')"),
                Some(ScriptLanguage::JavaScript)
            );
            assert_eq!(
                ScriptLanguage::from_shebang("#!/usr/bin/env perl\nprint 'hello'"),
                Some(ScriptLanguage::Perl)
            );
        }

        #[test]
        fn from_shebang_returns_none_for_invalid() {
            // No shebang
            assert_eq!(ScriptLanguage::from_shebang("import os"), None);
            // Empty shebang
            assert_eq!(ScriptLanguage::from_shebang("#!\ncode"), None);
            // Unknown interpreter
            assert_eq!(
                ScriptLanguage::from_shebang("#!/usr/bin/unknown\ncode"),
                None
            );
        }

        #[test]
        fn from_shebang_ignores_interpreter_flags() {
            // Direct path with flags
            assert_eq!(
                ScriptLanguage::from_shebang("#!/bin/bash -e\nset -x"),
                Some(ScriptLanguage::Bash)
            );
            assert_eq!(
                ScriptLanguage::from_shebang("#!/bin/bash -ex\necho hello"),
                Some(ScriptLanguage::Bash)
            );
            assert_eq!(
                ScriptLanguage::from_shebang("#!/usr/bin/python3 -u\nimport sys"),
                Some(ScriptLanguage::Python)
            );

            // Env-style with flags
            assert_eq!(
                ScriptLanguage::from_shebang("#!/usr/bin/env python3 -u\nimport sys"),
                Some(ScriptLanguage::Python)
            );
            assert_eq!(
                ScriptLanguage::from_shebang("#!/usr/bin/env bash -e\necho hi"),
                Some(ScriptLanguage::Bash)
            );
            assert_eq!(
                ScriptLanguage::from_shebang("#!/usr/bin/env ruby -w\nputs 'hi'"),
                Some(ScriptLanguage::Ruby)
            );
        }

        #[test]
        fn from_shebang_handles_env_flags() {
            // env -S splits remaining arguments (GNU coreutils 8.30+)
            assert_eq!(
                ScriptLanguage::from_shebang("#!/usr/bin/env -S python3 -u\nimport sys"),
                Some(ScriptLanguage::Python)
            );
            assert_eq!(
                ScriptLanguage::from_shebang("#!/usr/bin/env -S bash -e\necho hi"),
                Some(ScriptLanguage::Bash)
            );

            // env -i ignores environment
            assert_eq!(
                ScriptLanguage::from_shebang("#!/usr/bin/env -i python3\nimport os"),
                Some(ScriptLanguage::Python)
            );

            // Multiple env flags
            assert_eq!(
                ScriptLanguage::from_shebang("#!/usr/bin/env -i -S perl -w\nuse strict;"),
                Some(ScriptLanguage::Perl)
            );
        }

        #[test]
        fn from_content_detects_python() {
            assert_eq!(
                ScriptLanguage::from_content("import os\nos.remove('file')"),
                Some(ScriptLanguage::Python)
            );
            assert_eq!(
                ScriptLanguage::from_content("from pathlib import Path\nPath('x').unlink()"),
                Some(ScriptLanguage::Python)
            );
        }

        #[test]
        fn from_content_detects_javascript() {
            assert_eq!(
                ScriptLanguage::from_content("const fs = require('fs');\nfs.rm('x');"),
                Some(ScriptLanguage::JavaScript)
            );
            assert_eq!(
                ScriptLanguage::from_content("let x = 5;\nconsole.log(x);"),
                Some(ScriptLanguage::JavaScript)
            );
        }

        #[test]
        fn from_content_detects_typescript() {
            assert_eq!(
                ScriptLanguage::from_content("const x: string = 'hello';"),
                Some(ScriptLanguage::TypeScript)
            );
            assert_eq!(
                ScriptLanguage::from_content("interface User { name: string }"),
                Some(ScriptLanguage::TypeScript)
            );
        }

        #[test]
        fn from_content_detects_ruby() {
            // Ruby needs 'end' to reduce false positives
            assert_eq!(
                ScriptLanguage::from_content("def hello\n  puts 'hi'\nend"),
                Some(ScriptLanguage::Ruby)
            );
            assert_eq!(
                ScriptLanguage::from_content("require 'fileutils'\nFileUtils.rm_rf('x')\nend"),
                Some(ScriptLanguage::Ruby)
            );
        }

        #[test]
        fn from_content_detects_perl() {
            assert_eq!(
                ScriptLanguage::from_content("use strict;\nmy $x = 5;"),
                Some(ScriptLanguage::Perl)
            );
            assert_eq!(
                ScriptLanguage::from_content("my @arr = (1,2,3);"),
                Some(ScriptLanguage::Perl)
            );
        }

        #[test]
        fn from_content_detects_bash() {
            assert_eq!(
                ScriptLanguage::from_content("if [ -f file ]; then\n  echo 'exists'\nfi"),
                Some(ScriptLanguage::Bash)
            );
            assert_eq!(
                ScriptLanguage::from_content("x=$((1+2))\necho ${x}"),
                Some(ScriptLanguage::Bash)
            );
        }

        #[test]
        fn from_content_returns_none_for_unknown() {
            assert_eq!(ScriptLanguage::from_content("hello world"), None);
            assert_eq!(ScriptLanguage::from_content(""), None);
        }

        #[test]
        fn detect_uses_command_prefix_first() {
            // Even with Python shebang, command should take precedence
            let (lang, confidence) =
                ScriptLanguage::detect("ruby -e 'code'", "#!/usr/bin/python\nimport os");
            assert_eq!(lang, ScriptLanguage::Ruby);
            assert_eq!(confidence, DetectionConfidence::CommandPrefix);
        }

        #[test]
        fn detect_uses_shebang_second() {
            // No command interpreter, but has shebang
            let (lang, confidence) =
                ScriptLanguage::detect("cat script.sh", "#!/bin/bash\necho hello");
            assert_eq!(lang, ScriptLanguage::Bash);
            assert_eq!(confidence, DetectionConfidence::Shebang);
        }

        #[test]
        fn detect_uses_content_heuristics_third() {
            // No command interpreter, no shebang, but has Python imports
            let (lang, confidence) =
                ScriptLanguage::detect("cat script", "import os\nos.remove('x')");
            assert_eq!(lang, ScriptLanguage::Python);
            assert_eq!(confidence, DetectionConfidence::ContentHeuristics);
        }

        #[test]
        fn detect_returns_unknown_for_unrecognized() {
            let (lang, confidence) = ScriptLanguage::detect("cat file.txt", "hello world");
            assert_eq!(lang, ScriptLanguage::Unknown);
            assert_eq!(confidence, DetectionConfidence::Unknown);
        }

        #[test]
        fn detect_handles_env_prefix() {
            let (lang, confidence) = ScriptLanguage::detect("env python3 -c 'code'", "");
            assert_eq!(lang, ScriptLanguage::Python);
            assert_eq!(confidence, DetectionConfidence::CommandPrefix);
        }

        #[test]
        fn detect_handles_absolute_path() {
            let (lang, confidence) = ScriptLanguage::detect("/usr/bin/python3 -c 'code'", "");
            assert_eq!(lang, ScriptLanguage::Python);
            assert_eq!(confidence, DetectionConfidence::CommandPrefix);
        }

        #[test]
        fn detection_confidence_labels() {
            assert_eq!(DetectionConfidence::CommandPrefix.label(), "command-prefix");
            assert_eq!(DetectionConfidence::Shebang.label(), "shebang");
            assert_eq!(
                DetectionConfidence::ContentHeuristics.label(),
                "content-heuristics"
            );
            assert_eq!(DetectionConfidence::Unknown.label(), "unknown");
        }

        #[test]
        fn detection_confidence_reasons() {
            assert!(
                DetectionConfidence::CommandPrefix
                    .reason()
                    .contains("highest")
            );
            assert!(DetectionConfidence::Shebang.reason().contains("high"));
            assert!(
                DetectionConfidence::ContentHeuristics
                    .reason()
                    .contains("lower")
            );
            assert!(DetectionConfidence::Unknown.reason().contains("could not"));
        }

        #[test]
        fn enforces_max_body_bytes() {
            let large_content = "x".repeat(2_000_000); // 2MB
            let cmd = format!("python -c '{large_content}'");
            let limits = ExtractionLimits {
                max_body_bytes: 1_000_000, // 1MB limit
                ..Default::default()
            };
            let result = extract_content(&cmd, &limits);
            // Should return Skipped with size limit reason
            match result {
                ExtractionResult::Skipped(reasons) => {
                    assert!(
                        reasons
                            .iter()
                            .any(|r| matches!(r, SkipReason::ExceededSizeLimit { .. }))
                    );
                }
                ExtractionResult::NoContent
                | ExtractionResult::Failed(_)
                | ExtractionResult::Partial { .. } => {}
                ExtractionResult::Extracted(contents) => {
                    // If extracted, content should be within limits
                    for c in contents {
                        assert!(c.content.len() <= limits.max_body_bytes);
                    }
                }
            }
        }

        #[test]
        fn extracts_multiple_inline_scripts() {
            let cmd = "python -c 'code1' && ruby -e 'code2'";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 2);
                assert_eq!(contents[0].content, "code1");
                assert_eq!(contents[1].content, "code2");
            } else {
                panic!("Expected Extracted result");
            }
        }

        #[test]
        fn extracts_versioned_interpreter_scripts() {
            // Tier 2 must extract content from versioned interpreters
            let cmd = "python3.11 -c 'import os' && nodejs18 -e 'console.log(1)'";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 2, "should extract both scripts");
                assert_eq!(contents[0].content, "import os");
                assert_eq!(contents[0].language, ScriptLanguage::Python);
                assert_eq!(contents[1].content, "console.log(1)");
                assert_eq!(contents[1].language, ScriptLanguage::JavaScript);
            } else {
                panic!("Expected Extracted result for versioned interpreters, got {result:?}");
            }
        }

        // ====================================================================
        // Robustness Tests (git_safety_guard-rbst)
        // ====================================================================

        #[test]
        fn skips_binary_content_with_null_bytes() {
            // Content with null bytes should be detected as binary
            let cmd = "python -c '\x00binary\x00content'";
            if let Some(reason) = check_binary_content(cmd) {
                assert!(
                    matches!(reason, SkipReason::BinaryContent { null_bytes, .. } if null_bytes > 0)
                );
            } else {
                panic!("Expected binary content detection");
            }
        }

        #[test]
        fn skips_binary_content_high_non_printable() {
            // Content with high ratio of non-printable bytes
            let binary_bytes: Vec<u8> = (0u8..50).chain(200u8..255).collect();
            let binary_str = String::from_utf8_lossy(&binary_bytes);
            if let Some(reason) = check_binary_content(&binary_str) {
                assert!(matches!(reason, SkipReason::BinaryContent { .. }));
            } else {
                panic!("Expected binary content detection for high non-printable ratio");
            }
        }

        #[test]
        fn allows_normal_text_content() {
            let normal_content = "import os\nprint('hello world')\nfor i in range(10): pass";
            assert!(check_binary_content(normal_content).is_none());
        }

        #[test]
        fn tracks_unterminated_heredoc() {
            let cmd = "cat << EOF\nunterminated content without closing delimiter";
            let result = extract_content(cmd, &ExtractionLimits::default());
            match result {
                ExtractionResult::Skipped(reasons) => {
                    assert!(
                        reasons
                            .iter()
                            .any(|r| matches!(r, SkipReason::UnterminatedHeredoc { .. })),
                        "should report UnterminatedHeredoc, not ExceededSizeLimit"
                    );
                }
                _ => panic!("Expected Skipped result for unterminated heredoc"),
            }
        }

        #[test]
        fn heredoc_body_line_limit_reports_exceeded_line_limit() {
            let cmd = "cat << EOF\nline1\nline2\nline3\nEOF";
            let limits = ExtractionLimits {
                max_body_lines: 2,
                ..Default::default()
            };

            let result = extract_content(cmd, &limits);
            match result {
                ExtractionResult::Skipped(reasons) => {
                    assert!(
                        reasons
                            .iter()
                            .any(|r| matches!(r, SkipReason::ExceededLineLimit { .. })),
                        "should report ExceededLineLimit, not UnterminatedHeredoc"
                    );
                }
                _ => panic!("Expected Skipped result for line-limited heredoc, got {result:?}"),
            }
        }

        #[test]
        fn extraction_timeout_is_enforced() {
            let cmd = "cat << EOF\nline1\nEOF";
            let limits = ExtractionLimits {
                timeout_ms: 0,
                ..Default::default()
            };

            let result = extract_content(cmd, &limits);
            match result {
                ExtractionResult::Skipped(reasons) => {
                    assert!(
                        reasons
                            .iter()
                            .any(|r| matches!(r, SkipReason::Timeout { .. })),
                        "should include a Timeout skip reason"
                    );
                }
                _ => panic!("Expected Skipped(timeout) result, got {result:?}"),
            }
        }

        #[test]
        fn enforces_heredoc_limit() {
            // Create a command with many heredocs
            let cmd = "cmd1 << A\na\nA && cmd2 << B\nb\nB && cmd3 << C\nc\nC";
            let limits = ExtractionLimits {
                max_heredocs: 2, // Only allow 2
                ..Default::default()
            };
            let result = extract_content(cmd, &limits);
            if let ExtractionResult::Extracted(contents) = result {
                assert!(contents.len() <= limits.max_heredocs);
            }
            // Otherwise, skip result is also acceptable
        }

        #[test]
        fn skip_reason_display() {
            // Test Display implementations
            let reasons = vec![
                SkipReason::ExceededSizeLimit {
                    actual: 2000,
                    limit: 1000,
                },
                SkipReason::ExceededLineLimit {
                    actual: 200,
                    limit: 100,
                },
                SkipReason::ExceededHeredocLimit { limit: 10 },
                SkipReason::BinaryContent {
                    null_bytes: 5,
                    non_printable_ratio: 0.5,
                },
                SkipReason::Timeout {
                    elapsed_ms: 60,
                    budget_ms: 50,
                },
                SkipReason::UnterminatedHeredoc {
                    delimiter: "EOF".to_string(),
                },
                SkipReason::MalformedInput {
                    reason: "test".to_string(),
                },
            ];

            for reason in reasons {
                let display = format!("{reason}");
                assert!(!display.is_empty(), "Display should produce output");
            }
        }

        #[test]
        fn empty_command_returns_no_content() {
            let result = extract_content("", &ExtractionLimits::default());
            assert!(matches!(result, ExtractionResult::NoContent));
        }

        #[test]
        fn whitespace_only_returns_no_content() {
            let result = extract_content("   \t\n  ", &ExtractionLimits::default());
            assert!(matches!(result, ExtractionResult::NoContent));
        }
    }

    // ========================================================================
    // Shell Command Extraction Tests (git_safety_guard-uau)
    // ========================================================================

    mod shell_extraction {
        use super::*;

        // ====================================================================
        // Positive fixtures: commands that MUST be extracted
        // ====================================================================

        #[test]
        fn extracts_simple_command() {
            let commands = extract_shell_commands("ls -la");
            assert_eq!(commands.len(), 1);
            assert_eq!(commands[0].text, "ls -la");
            assert_eq!(commands[0].line_number, 1);
        }

        #[test]
        fn extracts_rm_rf() {
            // Catastrophic command - must be extracted for evaluator
            let commands = extract_shell_commands("rm -rf /tmp/test");
            assert_eq!(commands.len(), 1);
            assert_eq!(commands[0].text, "rm -rf /tmp/test");
        }

        #[test]
        fn extracts_git_reset_hard() {
            let commands = extract_shell_commands("git reset --hard");
            assert_eq!(commands.len(), 1);
            assert_eq!(commands[0].text, "git reset --hard");
        }

        #[test]
        fn extracts_git_clean_fd() {
            let commands = extract_shell_commands("git clean -fd");
            assert_eq!(commands.len(), 1);
            assert_eq!(commands[0].text, "git clean -fd");
        }

        #[test]
        fn extracts_pipeline_both_sides() {
            // Both sides of a pipe are executed
            let commands = extract_shell_commands("find . -name '*.bak' | xargs rm");
            assert_eq!(commands.len(), 2, "pipeline should extract both commands");
            assert!(commands[0].text.starts_with("find"));
            assert!(commands[1].text.contains("xargs"));
        }

        #[test]
        fn extracts_command_list() {
            // Commands separated by && or ;
            let commands = extract_shell_commands("cd /tmp && rm -rf test");
            assert_eq!(commands.len(), 2, "command list should extract both");
        }

        #[test]
        fn extracts_command_substitution() {
            // Commands inside $(...) are executed
            let commands = extract_shell_commands("echo $(rm -rf /tmp/test)");
            assert!(
                commands.len() >= 2,
                "should extract command inside substitution"
            );
            // Should find the rm command inside the substitution
            assert!(
                commands.iter().any(|c| c.text.contains("rm")),
                "should extract rm from command substitution"
            );
        }

        #[test]
        fn extracts_subshell_commands() {
            // Commands inside (...) subshells are executed
            let commands = extract_shell_commands("(cd /tmp && rm -rf test)");
            assert!(commands.len() >= 2, "should extract commands from subshell");
        }

        #[test]
        fn extracts_multiline_script() {
            let script = r#"#!/bin/bash
set -e
cd /tmp
rm -rf test
echo "done""#;
            let commands = extract_shell_commands(script);
            assert!(
                commands.len() >= 4,
                "should extract all commands from multiline script"
            );
            // Should have rm command
            assert!(
                commands.iter().any(|c| c.text.contains("rm")),
                "should extract rm"
            );
        }

        #[test]
        fn extracts_docker_system_prune() {
            // Docker destructive commands (if pack enabled)
            let commands = extract_shell_commands("docker system prune -af");
            assert_eq!(commands.len(), 1);
            assert_eq!(commands[0].text, "docker system prune -af");
        }

        #[test]
        fn line_numbers_are_correct() {
            let script = "echo first\nrm -rf /tmp\necho last";
            let commands = extract_shell_commands(script);
            assert!(commands.len() >= 3);

            let rm_cmd = commands.iter().find(|c| c.text.contains("rm")).unwrap();
            assert_eq!(rm_cmd.line_number, 2, "rm should be on line 2");
        }

        // ====================================================================
        // Negative fixtures: content that must NOT be extracted as commands
        // ====================================================================

        #[test]
        fn skips_comments() {
            // Comments mentioning dangerous commands should NOT be extracted
            // tree-sitter-bash parses "# ..." as a comment node, not a command node
            let commands = extract_shell_commands("# rm -rf / would be bad");
            assert!(
                commands.is_empty(),
                "comment-only content should produce zero commands, got: {commands:?}"
            );
        }

        #[test]
        fn echo_string_is_data_not_execution() {
            // The string inside echo is data, not a command
            let commands = extract_shell_commands("echo 'rm -rf /'");
            // Should extract echo, but not the rm inside the string
            assert!(
                commands.len() == 1,
                "should only extract echo, not the string content"
            );
            // The command should be the echo, not rm
            assert!(
                commands[0].text.starts_with("echo"),
                "extracted command should be echo"
            );
        }

        #[test]
        fn printf_string_is_data_not_execution() {
            let commands = extract_shell_commands(r#"printf "rm -rf %s" /tmp"#);
            assert!(
                commands.len() == 1,
                "should only extract printf, not the format string content"
            );
            assert!(commands[0].text.starts_with("printf"));
        }

        #[test]
        fn empty_content_returns_no_commands() {
            let commands = extract_shell_commands("");
            assert!(commands.is_empty());
        }

        #[test]
        fn whitespace_only_returns_no_commands() {
            let commands = extract_shell_commands("   \n\t  ");
            assert!(commands.is_empty());
        }

        #[test]
        fn comment_only_returns_no_commands() {
            // tree-sitter-bash parses "# ..." as a comment node, not a command node
            let commands = extract_shell_commands("# This is just a comment");
            assert!(
                commands.is_empty(),
                "comment-only content should produce zero commands, got: {commands:?}"
            );
        }

        #[test]
        fn heredoc_delimiter_is_not_command() {
            // The EOF itself is not a command, and heredoc body content is DATA not commands
            let script = r"cat << EOF
some content
rm -rf / mentioned in text
EOF";
            let commands = extract_shell_commands(script);

            // Should extract cat command
            assert!(
                commands.iter().any(|c| c.text.starts_with("cat")),
                "should extract cat command"
            );

            // CRITICAL: heredoc body content must NOT be extracted as commands
            // The "rm -rf /" text inside the heredoc is DATA, not an executable command
            let rm_commands: Vec<_> = commands
                .iter()
                .filter(|c| c.text.contains("rm") && !c.text.contains("cat"))
                .collect();
            assert!(
                rm_commands.is_empty(),
                "heredoc body content must NOT be extracted as commands, but found: {rm_commands:?}"
            );
        }

        #[test]
        fn safe_tmp_cleanup_is_extracted() {
            // Policy says /tmp cleanup might be allowed - but we still extract it
            // for the evaluator to decide based on pack rules/allowlists
            let commands = extract_shell_commands("rm -rf /tmp/build_cache");
            assert_eq!(commands.len(), 1);
            // Extraction happens - policy decision is for evaluator
        }

        // ====================================================================
        // Edge cases and robustness
        // ====================================================================

        #[test]
        fn handles_complex_pipeline() {
            let commands = extract_shell_commands("cat file | grep pattern | wc -l");
            assert_eq!(commands.len(), 3, "should extract all pipeline stages");
        }

        #[test]
        fn handles_background_command() {
            let commands = extract_shell_commands("long_process &");
            assert_eq!(commands.len(), 1);
            assert_eq!(commands[0].text, "long_process");
        }

        #[test]
        fn handles_redirections() {
            let commands = extract_shell_commands("rm -rf /tmp/test > /dev/null 2>&1");
            assert_eq!(commands.len(), 1);
            // The command text includes redirections
            assert!(commands[0].text.contains("rm"));
        }

        #[test]
        fn handles_variable_expansion_in_command() {
            // Commands with variables should still be extracted
            let commands = extract_shell_commands("rm -rf $DIR");
            assert_eq!(commands.len(), 1);
            assert!(commands[0].text.contains("rm"));
        }

        #[test]
        fn handles_if_then_else() {
            let script = r#"if [ -f /tmp/test ]; then
    rm -rf /tmp/test
else
    echo "not found"
fi"#;
            let commands = extract_shell_commands(script);
            // Should extract the commands inside the if/else
            assert!(
                commands.iter().any(|c| c.text.contains("rm")),
                "should extract rm from if body"
            );
            assert!(
                commands.iter().any(|c| c.text.contains("echo")),
                "should extract echo from else body"
            );
        }

        #[test]
        fn handles_for_loop() {
            let script = "for f in *.txt; do rm -f \"$f\"; done";
            let commands = extract_shell_commands(script);
            assert!(
                commands.iter().any(|c| c.text.contains("rm")),
                "should extract rm from for loop body"
            );
        }

        #[test]
        fn byte_ranges_are_correct() {
            let script = "echo hello";
            let commands = extract_shell_commands(script);
            assert_eq!(commands.len(), 1);
            assert_eq!(commands[0].start, 0);
            assert_eq!(commands[0].end, script.len());

            // Extract the text using the range
            let extracted = &script[commands[0].start..commands[0].end];
            assert_eq!(extracted, "echo hello");
        }
    }

    proptest! {
        /// Tier 1 trigger detection must be a superset of Tier 2 extraction.
        /// If Tier 2 extracts any content, Tier 1 must have triggered.
        #[test]
        fn tier1_is_superset_of_tier2_extraction(cmd in prop_oneof![
            // Random UTF-8
            "\\PC{0,2000}",
            // Heredoc-ish inputs (multi-line)
            "\\PC{0,400}".prop_map(|body| format!("cat <<EOF\n{body}\nEOF")),
            "\\PC{0,400}".prop_map(|body| format!("cat <<'EOF'\n{body}\nEOF")),
            // Inline interpreters
            "\\PC{0,400}".prop_map(|body| format!("python -c \"{}\"", body.replace('\"', ""))),
            "\\PC{0,400}".prop_map(|body| format!("bash -c \"{}\"", body.replace('\"', ""))),
            "\\PC{0,400}".prop_map(|body| format!("node -e \"{}\"", body.replace('\"', ""))),
        ]) {
            let limits = ExtractionLimits {
                max_body_bytes: 10_000,
                max_body_lines: 1_000,
                max_heredocs: 5,
                timeout_ms: 50,
            };

            let extracted = extract_content(&cmd, &limits);
            if let ExtractionResult::Extracted(contents) = extracted {
                if !contents.is_empty() {
                    prop_assert_eq!(
                        check_triggers(&cmd),
                        TriggerResult::Triggered,
                        "Tier 2 extracted but Tier 1 did not trigger for: {:?}",
                        cmd
                    );
                }
            }
        }
    }

    #[test]
    fn detects_language_in_pipeline() {
        // Regression test: now detects python in pipeline via pipe scanning
        let cmd = "cat <<EOF | python";
        let content = "print('hello')"; // ambiguous content
        let (lang, _) = ScriptLanguage::detect(cmd, content);
        assert_eq!(lang, ScriptLanguage::Python);
    }
}

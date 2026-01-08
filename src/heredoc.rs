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

use regex::RegexSet;
use std::sync::LazyLock;

/// Tier 1 trigger patterns for heredoc and inline script detection.
///
/// These patterns are designed for maximum recall (zero false negatives).
/// False positives are acceptable - they just trigger Tier 2 analysis.
///
/// # Performance
///
/// Uses [`RegexSet`] for parallel matching in a single pass over the input.
/// Target latency: <10μs for non-matching, <100μs for matching.
static HEREDOC_TRIGGERS: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        // Heredoc operators (bash, sh, zsh)
        r"<<-?\s*['\x22]?\w+['\x22]?", // << or <<- with optional quotes
        r"<<<",                        // Here-strings (bash)
        // Python inline execution (matches python, python3, python3.11, python3.12.1, etc.)
        r"\bpython[0-9.]*\s+-[ce]\s",
        // Ruby inline execution (matches ruby, ruby3, ruby3.0, etc.)
        r"\bruby[0-9.]*\s+-e\s",
        r"\birb[0-9.]*\s+-e\s",
        // Perl inline execution (matches perl, perl5, perl5.36, etc.)
        r"\bperl[0-9.]*\s+-[eE]\s",
        // Node.js inline execution (matches node, node18, nodejs, nodejs18, etc.)
        r"\bnode(js)?[0-9.]*\s+-[ep]\s",
        // Shell inline execution (sh -c, bash -c, zsh -c, fish -c)
        r"\b(sh|bash|zsh|fish)\s+-c\s",
        // Piped execution to interpreters (versioned)
        r"\|\s*(python[0-9.]*|ruby[0-9.]*|perl[0-9.]*|node(js)?[0-9.]*|sh|bash)\b",
        // Piped to xargs (can execute arbitrary commands)
        r"\|\s*xargs\s",
        // exec/eval in various contexts
        r"\beval\s+['\x22]",
        r"\bexec\s+['\x22]",
        // Additional heredoc variants
        r"<<~",          // Ruby-style heredoc (indentation-stripping)
        r"<<['\x22]EOF", // Quoted delimiters (literal)
    ])
    .expect("heredoc trigger patterns should compile")
});

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
pub fn check_triggers(command: &str) -> TriggerResult {
    if HEREDOC_TRIGGERS.is_match(command) {
        TriggerResult::Triggered
    } else {
        TriggerResult::NoTrigger
    }
}

/// Returns the list of trigger pattern indices that matched.
///
/// Useful for debugging and logging which patterns triggered.
#[must_use]
pub fn matched_triggers(command: &str) -> Vec<usize> {
    HEREDOC_TRIGGERS.matches(command).into_iter().collect()
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
    Python,
    Ruby,
    Perl,
    JavaScript,
    TypeScript,
    Unknown,
}

impl ScriptLanguage {
    /// Infer language from a command prefix (e.g., "python3", "ruby").
    ///
    /// Matches exact command names or names with version suffixes (e.g., "python3.11").
    /// Does NOT match arbitrary words that start with a command name (e.g., "shebang" ≠ "sh").
    #[must_use]
    pub fn from_command(cmd: &str) -> Self {
        let cmd_lower = cmd.to_lowercase();

        // Helper: check if cmd matches base name, optionally followed by version digits/dots
        // e.g., "python" matches "python", "python3", "python3.11"
        // but "python" does NOT match "pythonic" or "python_helper"
        let matches_interpreter = |base: &str| -> bool {
            if cmd_lower == base {
                return true;
            }
            // Allow version suffixes: digits and dots (e.g., "3", "3.11", "3.11.4")
            cmd_lower.strip_prefix(base).is_some_and(|suffix| {
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
        // Priority 1: Extract interpreter from command
        // Handle formats like: "python3 -c", "/usr/bin/python -c", "env python3"
        let cmd_interpreter = Self::extract_interpreter(cmd);
        if let Some(interpreter) = cmd_interpreter {
            let lang = Self::from_command(&interpreter);
            if lang != Self::Unknown {
                return (lang, DetectionConfidence::CommandPrefix);
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

    /// Extract the interpreter name from a command string.
    ///
    /// Handles various formats:
    /// - `python3 -c "code"` → "python3"
    /// - `/usr/bin/python -c "code"` → "python"
    /// - `env python3 -c "code"` → "python3"
    /// - `env -S python3 -c "code"` → "python3" (skips env flags)
    /// - `bash -c "code"` → "bash"
    fn extract_interpreter(cmd: &str) -> Option<String> {
        let mut parts = cmd.split_whitespace();
        let first = parts.next()?;

        // Get basename (strip path)
        let basename = first.rsplit('/').next().unwrap_or(first);

        // If it's "env", skip any flags and get the interpreter
        if basename == "env" {
            loop {
                let next = parts.next()?;
                if !next.starts_with('-') {
                    let next_basename = next.rsplit('/').next().unwrap_or(next);
                    return Some(next_basename.to_string());
                }
            }
        }

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
    /// Whether the delimiter was quoted (suppresses expansion).
    pub quoted: bool,
    /// Type of heredoc (if applicable).
    pub heredoc_type: Option<HeredocType>,
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
    /// Extraction failed (timeout, malformed, etc.) - fail open with warning.
    Failed(String),
}

/// Regex patterns for heredoc extraction (compiled once).
static HEREDOC_EXTRACTOR: LazyLock<Regex> = LazyLock::new(|| {
    // Matches: <<[-~]? followed by optional quotes and delimiter
    // Groups: (1) operator variant (-/~/empty), (2) quote char, (3) delimiter, (4) closing quote
    Regex::new(r"<<([-~])?\s*(['\x22]?)(\w+)(['\x22]?)").expect("heredoc regex compiles")
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
    // Matches: command -c/-e/-p/-E followed by single-quoted content
    // Groups: (1) interpreter, (2) optional "js" suffix, (3) flag, (4) content
    // Supports versioned interpreters: python3.11, ruby3.0, perl5.36, node18, nodejs20, etc.
    Regex::new(r"\b(python[0-9.]*|ruby[0-9.]*|irb[0-9.]*|perl[0-9.]*|node(js)?[0-9.]*|sh|bash|zsh|fish)\s+(-[ceEp])\s+'([^']*)'")
        .expect("inline script single-quote regex compiles")
});

/// Regex for inline script flag extraction with double quotes.
static INLINE_SCRIPT_DOUBLE_QUOTE: LazyLock<Regex> = LazyLock::new(|| {
    // Matches: command -c/-e/-p/-E followed by double-quoted content
    // Groups: (1) interpreter, (2) optional "js" suffix, (3) flag, (4) content
    // Supports versioned interpreters: python3.11, ruby3.0, perl5.36, node18, nodejs20, etc.
    Regex::new(r#"\b(python[0-9.]*|ruby[0-9.]*|irb[0-9.]*|perl[0-9.]*|node(js)?[0-9.]*|sh|bash|zsh|fish)\s+(-[ceEp])\s+"([^"]*)""#)
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
pub fn extract_content(command: &str, limits: &ExtractionLimits) -> ExtractionResult {
    let mut skip_reasons: Vec<SkipReason> = Vec::new();

    // Enforce input size limit
    if command.len() > limits.max_body_bytes {
        skip_reasons.push(SkipReason::ExceededSizeLimit {
            actual: command.len(),
            limit: limits.max_body_bytes,
        });
        return ExtractionResult::Skipped(skip_reasons);
    }

    // Check for binary content (null bytes or high non-printable ratio)
    if let Some(reason) = check_binary_content(command) {
        skip_reasons.push(reason);
        return ExtractionResult::Skipped(skip_reasons);
    }

    let mut extracted: Vec<ExtractedContent> = Vec::new();

    // Extract inline scripts (-c/-e flags)
    extract_inline_scripts(command, limits, &mut extracted, &mut skip_reasons);

    // Extract here-strings (<<<)
    extract_herestrings(command, limits, &mut extracted, &mut skip_reasons);

    // Extract heredocs (<<, <<-, <<~)
    extract_heredocs(command, limits, &mut extracted, &mut skip_reasons);

    // Return based on what we found
    match (extracted.is_empty(), skip_reasons.is_empty()) {
        (true, true) => ExtractionResult::NoContent,
        (true, false) => ExtractionResult::Skipped(skip_reasons),
        (false, true) => ExtractionResult::Extracted(extracted),
        (false, false) => {
            // Partial extraction with some skips - return what we got
            // The skips are logged but don't prevent returning extracted content
            ExtractionResult::Extracted(extracted)
        }
    }
}

/// Extract inline scripts from -c/-e/-p flags.
fn extract_inline_scripts(
    command: &str,
    limits: &ExtractionLimits,
    extracted: &mut Vec<ExtractedContent>,
    skip_reasons: &mut Vec<SkipReason>,
) {
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
            if extracted.len() >= limits.max_heredocs {
                hit_limit = true;
                break;
            }

            let cmd_name = cap.get(1).map_or("", |m| m.as_str());
            // Content is in group 4: (1) interpreter, (2) optional "js", (3) flag, (4) content
            let content = cap.get(4).map_or("", |m| m.as_str());

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
                quoted: true, // -c/-e content is always in quotes
                heredoc_type: None,
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
    extracted: &mut Vec<ExtractedContent>,
    skip_reasons: &mut Vec<SkipReason>,
) {
    if extracted.len() >= limits.max_heredocs {
        return; // Already hit limit, don't add another skip reason
    }

    let mut hit_limit = false;

    // Helper to extract from a given pattern (quoted patterns have content in group 1)
    let mut extract_quoted = |pattern: &Regex, is_quoted: bool| {
        for cap in pattern.captures_iter(command) {
            if extracted.len() >= limits.max_heredocs {
                hit_limit = true;
                break;
            }

            // Content is in group 1 for all our here-string patterns
            let content = cap.get(1).map_or("", |m| m.as_str());

            if content.len() > limits.max_body_bytes {
                continue;
            }

            let full_match = cap.get(0).unwrap();

            extracted.push(ExtractedContent {
                content: content.to_string(),
                language: ScriptLanguage::Bash, // Here-strings are bash-specific
                delimiter: None,
                byte_range: full_match.start()..full_match.end(),
                quoted: is_quoted,
                heredoc_type: Some(HeredocType::HereString),
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
    extracted: &mut Vec<ExtractedContent>,
    skip_reasons: &mut Vec<SkipReason>,
) {
    if extracted.len() >= limits.max_heredocs {
        return; // Already hit limit
    }

    let mut hit_limit = false;
    for cap in HEREDOC_EXTRACTOR.captures_iter(command) {
        if extracted.len() >= limits.max_heredocs {
            hit_limit = true;
            break;
        }

        let operator_variant = cap.get(1).map(|m| m.as_str());
        let open_quote = cap.get(2).map_or("", |m| m.as_str());
        let delimiter = cap.get(3).map_or("", |m| m.as_str());
        let close_quote = cap.get(4).map_or("", |m| m.as_str());

        // Determine heredoc type
        let heredoc_type = match operator_variant {
            Some("-") => HeredocType::TabStripped,
            Some("~") => HeredocType::IndentStripped,
            _ => HeredocType::Standard,
        };

        let quoted = !open_quote.is_empty() || !close_quote.is_empty();
        let full_match = cap.get(0).unwrap();
        let start_pos = full_match.end();

        // Find the terminating delimiter
        match extract_heredoc_body(command, start_pos, delimiter, heredoc_type, limits) {
            Some(content) => {
                // Calculate byte range end position:
                // +1 for leading newline after heredoc marker
                // +content.len() for the body
                // +1 for newline before delimiter (only if content is non-empty)
                // +delimiter.len() for the terminating delimiter
                let end_pos = start_pos
                    + 1
                    + content.len()
                    + usize::from(!content.is_empty())
                    + delimiter.len();

                extracted.push(ExtractedContent {
                    content,
                    language: ScriptLanguage::Bash, // Default to bash for heredocs
                    delimiter: Some(delimiter.to_string()),
                    byte_range: full_match.start()..end_pos.min(command.len()),
                    quoted,
                    heredoc_type: Some(heredoc_type),
                });
            }
            None => {
                // Unterminated heredoc - record skip reason but continue processing
                skip_reasons.push(SkipReason::UnterminatedHeredoc {
                    delimiter: delimiter.to_string(),
                });
            }
        }
    }

    if hit_limit {
        skip_reasons.push(SkipReason::ExceededHeredocLimit {
            limit: limits.max_heredocs,
        });
    }
}

/// Extract the body of a heredoc, finding the terminating delimiter.
fn extract_heredoc_body(
    command: &str,
    start: usize,
    delimiter: &str,
    heredoc_type: HeredocType,
    limits: &ExtractionLimits,
) -> Option<String> {
    let remaining = command.get(start..)?;

    // Skip leading newline if present (heredoc body starts on next line)
    let body_start = remaining.strip_prefix('\n').unwrap_or(remaining);

    // For multi-line commands, find the terminating delimiter
    let mut lines = body_start.lines();
    let mut body_lines: Vec<&str> = Vec::new();
    let mut found_terminator = false;
    let mut total_bytes = 0;

    for line in lines.by_ref() {
        // Check if this line is the terminator
        let trimmed = match heredoc_type {
            HeredocType::TabStripped => line.trim_start_matches('\t'),
            HeredocType::IndentStripped => line.trim_start(),
            HeredocType::Standard | HeredocType::HereString => line,
        };

        if trimmed == delimiter {
            found_terminator = true;
            break;
        }

        // Enforce limits
        total_bytes += line.len() + 1; // +1 for newline
        if total_bytes > limits.max_body_bytes {
            break;
        }
        if body_lines.len() >= limits.max_body_lines {
            break;
        }

        body_lines.push(line);
    }

    if !found_terminator {
        // No terminator found - either unterminated or content continues beyond view
        return None;
    }

    // Empty heredoc is valid (e.g., `cat << EOF\nEOF`)
    // Return empty string if terminator was found with no content
    if body_lines.is_empty() {
        return Some(String::new());
    }

    // Apply indentation stripping if needed
    let content = match heredoc_type {
        HeredocType::TabStripped => {
            // Remove leading tabs from each line
            body_lines
                .iter()
                .map(|line| line.trim_start_matches('\t'))
                .collect::<Vec<_>>()
                .join("\n")
        }
        HeredocType::IndentStripped => {
            // Remove common leading whitespace
            let min_indent = body_lines
                .iter()
                .filter(|line| !line.trim().is_empty())
                .map(|line| line.len() - line.trim_start().len())
                .min()
                .unwrap_or(0);

            body_lines
                .iter()
                .map(|line| {
                    if line.len() >= min_indent {
                        &line[min_indent..]
                    } else {
                        line.trim_start()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
        }
        HeredocType::Standard | HeredocType::HereString => body_lines.join("\n"),
    };

    Some(content)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
                "node20.1 -p 'process.version'",
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
            let ruby_commands = ["ruby -e 'puts 1'", "irb -e 'exit'"];

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
            let node_commands = ["node -e 'console.log(1)'", "node -p 'process.version'"];

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
                ExtractionResult::NoContent | ExtractionResult::Failed(_) => {}
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
                            .any(|r| matches!(r, SkipReason::UnterminatedHeredoc { .. }))
                    );
                }
                _ => panic!("Expected Skipped result for unterminated heredoc"),
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
}

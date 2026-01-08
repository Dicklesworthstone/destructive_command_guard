//! Execution-context classification for shell commands.
//!
//! This module provides fast classification of which parts of a command line
//! are actually executed vs merely data. This enables the pattern matching
//! engine to reduce false positives by only checking executable contexts.
//!
//! # Design Principles
//!
//! 1. **Ambiguous → Executed**: If classification is uncertain, treat as executable
//! 2. **False positives over false negatives**: Better to block safe commands than allow dangerous ones
//! 3. **Performance**: Classification adds <100μs to typical commands
//!
//! # Examples
//!
//! ```ignore
//! use destructive_command_guard::context::{classify_command, SpanKind};
//!
//! let spans = classify_command("git commit -m 'Fix rm -rf detection'");
//! // The 'Fix rm -rf detection' part is classified as Data (single-quoted)
//! // The 'git commit -m' part is classified as Executed
//! ```

use std::ops::Range;

/// Classification of a command-line span.
///
/// Each span is classified according to whether it will be executed by the shell
/// or is purely data. The pattern matching engine uses this to skip matching
/// in known-safe contexts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpanKind {
    /// Command word or unquoted argument - fully executed by shell.
    /// Pattern matching MUST be applied.
    Executed,

    /// Quoted argument to a known-safe command (e.g., `git commit -m "..."`).
    /// Pattern matching should be applied with lower priority.
    Argument,

    /// Content of -c/-e flags (bash -c, python -c, node -e).
    /// Pattern matching MUST be applied - this is code!
    InlineCode,

    /// Single-quoted string - no variable substitution possible.
    /// Pattern matching can be SKIPPED (safe to ignore).
    Data,

    /// Heredoc body - escalate to Tier 2/3 analysis.
    /// Pattern matching should be applied with heredoc-aware logic.
    HeredocBody,

    /// Ambiguous context - conservative treatment as Executed.
    /// Pattern matching MUST be applied.
    Unknown,
}

impl SpanKind {
    /// Returns true if this span should have destructive patterns checked.
    #[inline]
    #[must_use]
    pub const fn requires_pattern_check(self) -> bool {
        match self {
            Self::Executed | Self::InlineCode | Self::HeredocBody | Self::Unknown => true,
            Self::Argument | Self::Data => false,
        }
    }

    /// Returns true if this span is definitely safe to skip pattern matching.
    #[inline]
    #[must_use]
    pub const fn is_safe_data(self) -> bool {
        matches!(self, Self::Data)
    }

    /// Returns true if this is executed code (not a data argument).
    #[inline]
    #[must_use]
    pub const fn is_executable(self) -> bool {
        matches!(self, Self::Executed | Self::InlineCode | Self::Unknown)
    }
}

/// A classified span within a command string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    /// The classification of this span.
    pub kind: SpanKind,
    /// Byte range within the original command string.
    pub byte_range: Range<usize>,
}

impl Span {
    /// Create a new span.
    #[inline]
    #[must_use]
    pub const fn new(kind: SpanKind, start: usize, end: usize) -> Self {
        Self {
            kind,
            byte_range: start..end,
        }
    }

    /// Get the span text from the original command.
    #[inline]
    #[must_use]
    pub fn text<'a>(&self, command: &'a str) -> &'a str {
        &command[self.byte_range.clone()]
    }

    /// Returns the length of this span in bytes.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.byte_range.end - self.byte_range.start
    }

    /// Returns true if this span is empty.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.byte_range.start == self.byte_range.end
    }
}

/// A collection of classified spans for a command.
///
/// This is the main output of the context classifier. It can be used to:
/// - Check if any executable spans contain destructive patterns
/// - Skip pattern matching for data-only spans
/// - Provide context for error messages and explanations
#[derive(Debug, Clone, Default)]
pub struct CommandSpans {
    /// All classified spans, in order of appearance.
    spans: Vec<Span>,
}

impl CommandSpans {
    /// Create an empty spans collection.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self { spans: Vec::new() }
    }

    /// Add a span to the collection.
    #[inline]
    pub fn push(&mut self, span: Span) {
        self.spans.push(span);
    }

    /// Get all spans.
    #[inline]
    #[must_use]
    pub fn spans(&self) -> &[Span] {
        &self.spans
    }

    /// Get only spans that require pattern checking.
    pub fn executable_spans(&self) -> impl Iterator<Item = &Span> {
        self.spans
            .iter()
            .filter(|s| s.kind.requires_pattern_check())
    }

    /// Get only data spans (safe to skip).
    pub fn data_spans(&self) -> impl Iterator<Item = &Span> {
        self.spans.iter().filter(|s| s.kind.is_safe_data())
    }

    /// Returns true if any span requires pattern checking.
    #[must_use]
    pub fn has_executable_content(&self) -> bool {
        self.spans.iter().any(|s| s.kind.requires_pattern_check())
    }

    /// Returns true if the entire command is safe data (rare).
    #[must_use]
    pub fn is_all_data(&self) -> bool {
        !self.spans.is_empty() && self.spans.iter().all(|s| s.kind.is_safe_data())
    }

    /// Extract the text content for all executable spans.
    #[must_use]
    pub fn executable_text<'a>(&self, command: &'a str) -> Vec<&'a str> {
        self.executable_spans().map(|s| s.text(command)).collect()
    }
}

/// State machine states for the shell tokenizer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenizerState {
    /// Normal unquoted text
    Normal,
    /// Inside single quotes - no escapes, no substitution
    SingleQuote,
    /// Inside double quotes - escapes and substitution possible
    DoubleQuote,
    /// After a backslash in normal context
    EscapeNormal,
    /// After a backslash in double-quoted context
    EscapeDouble,
    /// Inside $(...) command substitution
    CommandSubst { depth: u32 },
    /// Inside backtick command substitution
    Backtick,
}

/// Shell command tokenizer and context classifier.
///
/// This is a lightweight, purpose-built tokenizer that recognizes:
/// - Single and double quotes
/// - Backslash escapes
/// - Pipe operators (|, ||)
/// - Command separators (;, &&)
/// - Command substitution ($(...), backticks)
///
/// It does NOT attempt to be a full shell parser - it's designed for
/// the specific use case of identifying executable vs data contexts.
pub struct ContextClassifier {
    /// Commands that take inline code as the next argument after -c/-e
    inline_code_commands: &'static [&'static str],
}

impl Default for ContextClassifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ContextClassifier {
    /// Create a new context classifier with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inline_code_commands: &[
                "bash", "sh", "zsh", "ksh", "dash", // shells with -c
                "python", "python3", "python2", // python with -c
                "node", "nodejs", // node with -e
                "ruby",   // ruby with -e
                "perl",   // perl with -e
                "php",    // php with -r
                "lua",    // lua with -e
            ],
        }
    }

    /// Classify all spans in a command string.
    ///
    /// Returns a `CommandSpans` structure containing classified spans.
    /// Each byte in the command will belong to exactly one span.
    #[must_use]
    #[allow(clippy::too_many_lines)] // State machine logic is cohesive and clearer as single function
    pub fn classify(&self, command: &str) -> CommandSpans {
        let bytes = command.as_bytes();
        let len = bytes.len();

        if len == 0 {
            return CommandSpans::new();
        }

        let mut spans = CommandSpans::new();
        let mut state = TokenizerState::Normal;
        let mut span_start = 0;
        let mut current_kind = SpanKind::Executed;
        let mut i = 0;

        // Track if we're after a -c/-e flag
        let mut pending_inline_code = false;
        let mut last_word_start = 0;

        while i < len {
            let byte = bytes[i];

            match state {
                TokenizerState::Normal => {
                    match byte {
                        b'\'' => {
                            // End current span, start single-quote span
                            if i > span_start {
                                spans.push(Span::new(current_kind, span_start, i));
                            }
                            span_start = i;
                            state = TokenizerState::SingleQuote;
                            current_kind = SpanKind::Data;
                        }
                        b'"' => {
                            // End current span, start double-quote span
                            if i > span_start {
                                spans.push(Span::new(current_kind, span_start, i));
                            }
                            span_start = i;
                            state = TokenizerState::DoubleQuote;
                            // Double quotes might be inline code if after -c/-e
                            current_kind = if pending_inline_code {
                                pending_inline_code = false;
                                SpanKind::InlineCode
                            } else {
                                SpanKind::Argument
                            };
                        }
                        b'\\' => {
                            state = TokenizerState::EscapeNormal;
                        }
                        b'$' if i + 1 < len && bytes[i + 1] == b'(' => {
                            // Command substitution start
                            if i > span_start {
                                spans.push(Span::new(current_kind, span_start, i));
                            }
                            span_start = i;
                            i += 1; // Skip the (
                            state = TokenizerState::CommandSubst { depth: 1 };
                            current_kind = SpanKind::InlineCode;
                        }
                        b'`' => {
                            // Backtick substitution start
                            if i > span_start {
                                spans.push(Span::new(current_kind, span_start, i));
                            }
                            span_start = i;
                            state = TokenizerState::Backtick;
                            current_kind = SpanKind::InlineCode;
                        }
                        b'|' | b';' => {
                            // Pipe or separator - end current span, next part is new command
                            if i > span_start {
                                spans.push(Span::new(current_kind, span_start, i));
                            }
                            // Include the operator in its own span
                            let op_end = if byte == b'|' && i + 1 < len && bytes[i + 1] == b'|' {
                                i + 2 // ||
                            } else {
                                i + 1
                            };
                            spans.push(Span::new(SpanKind::Executed, i, op_end));
                            i = op_end;
                            span_start = i;
                            current_kind = SpanKind::Executed;
                            pending_inline_code = false;
                            continue;
                        }
                        b'&' if i + 1 < len && bytes[i + 1] == b'&' => {
                            // && separator
                            if i > span_start {
                                spans.push(Span::new(current_kind, span_start, i));
                            }
                            spans.push(Span::new(SpanKind::Executed, i, i + 2));
                            i += 2;
                            span_start = i;
                            current_kind = SpanKind::Executed;
                            pending_inline_code = false;
                            continue;
                        }
                        b' ' | b'\t' | b'\n' => {
                            // Whitespace - check if we just finished a word
                            if i > last_word_start {
                                let word = &command[last_word_start..i];
                                // Check for inline code flags
                                if word == "-c" || word == "-e" || word == "-r" {
                                    // Check if previous word was an inline-code command
                                    pending_inline_code =
                                        self.check_inline_code_context(command, last_word_start);
                                }
                            }
                            last_word_start = i + 1;
                        }
                        _ => {
                            // Regular character
                        }
                    }
                }
                TokenizerState::SingleQuote => {
                    if byte == b'\'' {
                        // End single quote span (include closing quote)
                        spans.push(Span::new(SpanKind::Data, span_start, i + 1));
                        span_start = i + 1;
                        state = TokenizerState::Normal;
                        current_kind = SpanKind::Executed;
                    }
                    // Everything inside single quotes is just data
                }
                TokenizerState::DoubleQuote => {
                    match byte {
                        b'"' => {
                            // End double quote span (include closing quote)
                            spans.push(Span::new(current_kind, span_start, i + 1));
                            span_start = i + 1;
                            state = TokenizerState::Normal;
                            current_kind = SpanKind::Executed;
                        }
                        b'\\' => {
                            state = TokenizerState::EscapeDouble;
                        }
                        b'$' if i + 1 < len && bytes[i + 1] == b'(' => {
                            // Command substitution inside double quotes - treat as inline code
                            // Don't create new span, but upgrade current to Unknown if not already InlineCode
                            if current_kind == SpanKind::Argument {
                                current_kind = SpanKind::Unknown;
                            }
                            i += 1; // Skip past (
                            // Note: we don't track nesting inside double quotes for simplicity
                            // This is conservative (treats more as potentially dangerous)
                        }
                        b'`' => {
                            // Backtick inside double quotes - upgrade to Unknown
                            if current_kind == SpanKind::Argument {
                                current_kind = SpanKind::Unknown;
                            }
                        }
                        _ => {}
                    }
                }
                TokenizerState::EscapeNormal => {
                    // Skip this character, return to normal
                    state = TokenizerState::Normal;
                }
                TokenizerState::EscapeDouble => {
                    // Skip this character, return to double quote
                    state = TokenizerState::DoubleQuote;
                }
                TokenizerState::CommandSubst { depth } => {
                    match byte {
                        b'(' => {
                            state = TokenizerState::CommandSubst { depth: depth + 1 };
                        }
                        b')' => {
                            if depth == 1 {
                                // End of command substitution
                                spans.push(Span::new(SpanKind::InlineCode, span_start, i + 1));
                                span_start = i + 1;
                                state = TokenizerState::Normal;
                                current_kind = SpanKind::Executed;
                            } else {
                                state = TokenizerState::CommandSubst { depth: depth - 1 };
                            }
                        }
                        _ => {}
                    }
                }
                TokenizerState::Backtick => {
                    if byte == b'`' {
                        // End of backtick substitution
                        spans.push(Span::new(SpanKind::InlineCode, span_start, i + 1));
                        span_start = i + 1;
                        state = TokenizerState::Normal;
                        current_kind = SpanKind::Executed;
                    }
                }
            }

            i += 1;
        }

        // Handle any remaining content
        if span_start < len {
            // If we're still in a quote, treat as Unknown (unterminated)
            let final_kind = match state {
                TokenizerState::Normal | TokenizerState::EscapeNormal => current_kind,
                TokenizerState::SingleQuote => SpanKind::Data, // Unterminated single quote is still data
                TokenizerState::DoubleQuote | TokenizerState::EscapeDouble => {
                    // Unterminated double quote - be conservative
                    if current_kind == SpanKind::Argument {
                        SpanKind::Unknown
                    } else {
                        current_kind
                    }
                }
                TokenizerState::CommandSubst { .. } | TokenizerState::Backtick => {
                    SpanKind::InlineCode
                }
            };
            spans.push(Span::new(final_kind, span_start, len));
        }

        spans
    }

    /// Check if the word before a -c/-e/-r flag is an inline-code command.
    fn check_inline_code_context(&self, command: &str, flag_start: usize) -> bool {
        // Find the previous word
        let before = &command[..flag_start];
        let trimmed = before.trim_end();
        if trimmed.is_empty() {
            return false;
        }

        // Get the last word
        let word_start = trimmed
            .rfind(|c: char| c.is_whitespace())
            .map_or(0, |i| i + 1);
        let word = &trimmed[word_start..];

        // Check if it's an inline-code command (or ends with one after a path)
        let base_name = word.rsplit('/').next().unwrap_or(word);
        self.inline_code_commands.contains(&base_name)
    }
}

/// Classify a command string's execution contexts.
///
/// This is a convenience function that creates a default classifier
/// and classifies the given command.
///
/// # Example
///
/// ```ignore
/// let spans = classify_command("echo 'hello world' | cat");
/// for span in spans.spans() {
///     println!("{:?}: {}", span.kind, span.text("echo 'hello world' | cat"));
/// }
/// ```
#[inline]
#[must_use]
pub fn classify_command(command: &str) -> CommandSpans {
    ContextClassifier::new().classify(command)
}

// =============================================================================
// Safe String-Argument Registry (git_safety_guard-t8x.1)
// =============================================================================

/// A registry of commands and flags whose arguments are purely data, not code.
///
/// This enables the pattern matching engine to suppress false positives for
/// common developer workflows like:
/// - `git commit -m "Fix rm -rf detection"` (commit message is data)
/// - `rg "rm -rf" src/` (search pattern is data)
/// - `bd create --description="This blocks rm -rf"` (description is data)
///
/// # Design Principles
///
/// 1. **Conservative**: Only entries where we're 100% confident args are data
/// 2. **Explicit**: Each entry must have a test demonstrating its need
/// 3. **Versioned**: Registry can be extended over time with new entries
#[derive(Debug, Clone)]
pub struct SafeStringRegistry {
    /// Commands where ALL arguments are data (e.g., echo, printf)
    all_args_data: &'static [&'static str],
    /// Command + flag combinations where the flag's value is data
    flag_data_pairs: &'static [SafeFlagEntry],
}

/// An entry for a command+flag combination whose argument is data.
#[derive(Debug, Clone, Copy)]
pub struct SafeFlagEntry {
    /// The command (base name, without path)
    pub command: &'static str,
    /// The short flag (e.g., "-m")
    pub short_flag: Option<&'static str>,
    /// The long flag (e.g., "--message")
    pub long_flag: Option<&'static str>,
}

impl SafeFlagEntry {
    /// Create a new entry with both short and long flags.
    #[must_use]
    pub const fn new(
        command: &'static str,
        short_flag: Option<&'static str>,
        long_flag: Option<&'static str>,
    ) -> Self {
        Self {
            command,
            short_flag,
            long_flag,
        }
    }

    /// Create an entry with only a short flag.
    #[must_use]
    pub const fn short(command: &'static str, flag: &'static str) -> Self {
        Self {
            command,
            short_flag: Some(flag),
            long_flag: None,
        }
    }

    /// Create an entry with only a long flag.
    #[must_use]
    pub const fn long(command: &'static str, flag: &'static str) -> Self {
        Self {
            command,
            short_flag: None,
            long_flag: Some(flag),
        }
    }

    /// Create an entry with both short and long flags (convenience).
    #[must_use]
    pub const fn both(command: &'static str, short: &'static str, long: &'static str) -> Self {
        Self {
            command,
            short_flag: Some(short),
            long_flag: Some(long),
        }
    }
}

/// The default safe string registry with v1 entries.
pub static SAFE_STRING_REGISTRY: SafeStringRegistry = SafeStringRegistry {
    // Commands where ALL arguments are data (never executed by shell)
    all_args_data: &["echo", "printf"],

    // Command + flag combinations where the flag's value is data
    flag_data_pairs: &[
        // Git message flags - commit/tag messages are documentation
        SafeFlagEntry::both("git", "-m", "--message"),
        // Note: git commit -m is actually 'git' command with 'commit' subcommand + -m flag
        // We handle this at the command level since -m is always data for git

        // Beads CLI - descriptions and notes are documentation
        SafeFlagEntry::long("bd", "--description"),
        SafeFlagEntry::long("bd", "--title"),
        SafeFlagEntry::long("bd", "--notes"),
        SafeFlagEntry::long("bd", "--reason"),
        // Search tools - patterns are data, not executed
        SafeFlagEntry::both("grep", "-e", "--regexp"),
        SafeFlagEntry::both("grep", "-F", "--fixed-strings"),
        SafeFlagEntry::both("rg", "-e", "--regexp"),
        SafeFlagEntry::long("rg", "--fixed-strings"),
        // GitHub CLI - titles and bodies are documentation
        SafeFlagEntry::both("gh", "-t", "--title"),
        SafeFlagEntry::both("gh", "-b", "--body"),
        SafeFlagEntry::both("gh", "-m", "--message"),
        // Cargo/npm - package descriptions
        SafeFlagEntry::long("cargo", "--message"),
        SafeFlagEntry::long("npm", "--message"),
    ],
};

impl SafeStringRegistry {
    /// Check if a command has ALL its arguments as data.
    ///
    /// For commands like `echo` and `printf`, everything after the command
    /// is purely printed output, not executed.
    #[must_use]
    pub fn is_all_args_data(&self, command: &str) -> bool {
        let base_name = command.rsplit('/').next().unwrap_or(command);
        self.all_args_data.contains(&base_name)
    }

    /// Check if a specific flag for a command has a data-only argument.
    ///
    /// Returns true if the flag's argument should be treated as data
    /// (safe to skip pattern matching).
    #[must_use]
    pub fn is_flag_data(&self, command: &str, flag: &str) -> bool {
        let base_name = command.rsplit('/').next().unwrap_or(command);

        self.flag_data_pairs.iter().any(|entry| {
            entry.command == base_name
                && (entry.short_flag == Some(flag) || entry.long_flag == Some(flag))
        })
    }

    /// Find all data-only flags for a given command.
    #[must_use]
    pub fn data_flags_for_command(&self, command: &str) -> Vec<&'static str> {
        let base_name = command.rsplit('/').next().unwrap_or(command);

        self.flag_data_pairs
            .iter()
            .filter(|entry| entry.command == base_name)
            .flat_map(|entry| {
                let short = entry.short_flag.into_iter();
                let long = entry.long_flag.into_iter();
                short.chain(long)
            })
            .collect()
    }
}

/// Check if a command's argument at a given position should be treated as data.
///
/// This is a convenience function that uses the default registry to determine
/// if an argument is purely data (not executed by the shell).
///
/// # Arguments
///
/// * `command` - The full command string
/// * `arg_index` - The zero-based index of the argument to check
///
/// # Returns
///
/// `true` if the argument at that position is known to be data-only.
#[must_use]
pub fn is_argument_data(command: &str, preceding_flag: Option<&str>) -> bool {
    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.is_empty() {
        return false;
    }

    let cmd = parts[0];

    // Check if all args are data for this command
    if SAFE_STRING_REGISTRY.is_all_args_data(cmd) {
        return true;
    }

    // Check if the preceding flag makes this argument data
    if let Some(flag) = preceding_flag {
        return SAFE_STRING_REGISTRY.is_flag_data(cmd, flag);
    }

    false
}

/// Sanitize a command by stripping known-safe string arguments.
///
/// This function removes safe data spans (single-quoted strings, known-safe flags)
/// from the command before pattern matching. This reduces false positives when
/// dangerous keywords appear in string literals rather than actual command arguments.
///
/// TODO(git_safety_guard-t8x): Full implementation pending - currently returns input unchanged.
#[must_use]
#[allow(clippy::missing_const_for_fn)] // Will not be const when fully implemented
pub fn sanitize_for_pattern_matching(cmd: &str) -> std::borrow::Cow<'_, str> {
    // Stub implementation: return input unchanged
    // Full implementation will use classify_command() to identify safe spans
    // and replace their content with harmless placeholders.
    std::borrow::Cow::Borrowed(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_command() {
        let spans = classify_command("git status");
        assert_eq!(spans.spans().len(), 1);
        assert_eq!(spans.spans()[0].kind, SpanKind::Executed);
    }

    #[test]
    fn test_single_quoted_string() {
        let cmd = "git commit -m 'Fix rm -rf detection'";
        let spans = classify_command(cmd);

        // Should have: "git commit -m " (Executed), "'Fix rm -rf detection'" (Data)
        assert!(spans.spans().len() >= 2);

        // Find the single-quoted span
        let data_span = spans.spans().iter().find(|s| s.kind == SpanKind::Data);
        assert!(data_span.is_some());
        let data_span = data_span.unwrap();
        assert_eq!(data_span.text(cmd), "'Fix rm -rf detection'");
    }

    #[test]
    fn test_double_quoted_string() {
        let cmd = "echo \"hello world\"";
        let spans = classify_command(cmd);

        // Find the double-quoted span
        let arg_span = spans.spans().iter().find(|s| s.kind == SpanKind::Argument);
        assert!(arg_span.is_some());
        assert_eq!(arg_span.unwrap().text(cmd), "\"hello world\"");
    }

    #[test]
    fn test_command_substitution() {
        let cmd = "echo $(rm -rf /)";
        let spans = classify_command(cmd);

        // Should have InlineCode span for $(rm -rf /)
        let inline_span = spans
            .spans()
            .iter()
            .find(|s| s.kind == SpanKind::InlineCode);
        assert!(inline_span.is_some());
        assert_eq!(inline_span.unwrap().text(cmd), "$(rm -rf /)");
    }

    #[test]
    fn test_backtick_substitution() {
        let cmd = "echo `rm -rf /`";
        let spans = classify_command(cmd);

        // Should have InlineCode span for `rm -rf /`
        let inline_span = spans
            .spans()
            .iter()
            .find(|s| s.kind == SpanKind::InlineCode);
        assert!(inline_span.is_some());
        assert_eq!(inline_span.unwrap().text(cmd), "`rm -rf /`");
    }

    #[test]
    fn test_pipe() {
        let cmd = "echo hi | cat";
        let spans = classify_command(cmd);

        // Should have spans for: "echo hi ", "|", " cat"
        assert!(spans.spans().len() >= 2);

        // All parts around pipe should be Executed
        for span in spans.executable_spans() {
            assert!(span.kind.is_executable());
        }
    }

    #[test]
    fn test_semicolon_separator() {
        let cmd = "echo a; echo b";
        let spans = classify_command(cmd);

        // Both parts should be Executed
        assert!(spans.has_executable_content());
    }

    #[test]
    fn test_and_separator() {
        let cmd = "true && rm -rf /";
        let spans = classify_command(cmd);

        // Both parts should be Executed
        let executable_text: Vec<_> = spans.executable_text(cmd);
        assert!(!executable_text.is_empty());
    }

    #[test]
    fn test_bash_c_inline_code() {
        let cmd = "bash -c \"rm -rf /\"";
        let spans = classify_command(cmd);

        // The quoted part after -c should be InlineCode
        let inline_span = spans
            .spans()
            .iter()
            .find(|s| s.kind == SpanKind::InlineCode);
        assert!(
            inline_span.is_some(),
            "Should detect inline code after bash -c"
        );
    }

    #[test]
    fn test_python_c_inline_code() {
        let cmd = "python -c \"import os; os.system('rm -rf /')\"";
        let spans = classify_command(cmd);

        // The quoted part after -c should be InlineCode
        let inline_span = spans
            .spans()
            .iter()
            .find(|s| s.kind == SpanKind::InlineCode);
        assert!(
            inline_span.is_some(),
            "Should detect inline code after python -c"
        );
    }

    #[test]
    fn test_node_e_inline_code() {
        let cmd = "node -e \"require('child_process').execSync('rm -rf /')\"";
        let spans = classify_command(cmd);

        // The quoted part after -e should be InlineCode
        let inline_span = spans
            .spans()
            .iter()
            .find(|s| s.kind == SpanKind::InlineCode);
        assert!(
            inline_span.is_some(),
            "Should detect inline code after node -e"
        );
    }

    #[test]
    fn test_double_quote_with_substitution() {
        let cmd = "echo \"$(rm -rf /)\"";
        let spans = classify_command(cmd);

        // Should be Unknown or InlineCode (not safe Argument)
        for span in spans.spans() {
            if span.text(cmd).contains("$(") {
                assert!(
                    span.kind == SpanKind::Unknown || span.kind == SpanKind::InlineCode,
                    "Double-quoted string with substitution should not be safe Argument"
                );
            }
        }
    }

    #[test]
    fn test_escaped_quote() {
        let cmd = "echo \"hello \\\"world\\\"\"";
        let spans = classify_command(cmd);

        // Should handle escaped quotes correctly
        assert!(!spans.spans().is_empty());
    }

    #[test]
    fn test_false_positive_case_bd_create() {
        // This should NOT trigger destructive pattern matching
        let cmd = "bd create --description=\"This pattern blocks rm -rf\"";
        let spans = classify_command(cmd);

        // The quoted description should be Argument (not requiring pattern check)
        let desc_span = spans
            .spans()
            .iter()
            .find(|s| s.text(cmd).contains("rm -rf"));
        if let Some(span) = desc_span {
            assert!(
                !span.kind.requires_pattern_check() || span.kind == SpanKind::Argument,
                "Description argument should not require pattern check"
            );
        }
    }

    #[test]
    fn test_false_positive_case_git_commit() {
        // This should NOT trigger destructive pattern matching
        let cmd = "git commit -m \"Fix git reset --hard detection\"";
        let spans = classify_command(cmd);

        // The quoted message should be Argument
        let msg_span = spans
            .spans()
            .iter()
            .find(|s| s.text(cmd).contains("reset --hard"));
        if let Some(span) = msg_span {
            assert!(
                span.kind == SpanKind::Argument || span.kind == SpanKind::Data,
                "Commit message should be Argument or Data"
            );
        }
    }

    #[test]
    fn test_false_positive_case_rg_pattern() {
        // This should NOT trigger destructive pattern matching
        let cmd = "rg -n \"rm -rf\" src/main.rs";
        let spans = classify_command(cmd);

        // The quoted pattern should be Argument
        let pattern_span = spans.spans().iter().find(|s| s.text(cmd) == "\"rm -rf\"");
        if let Some(span) = pattern_span {
            assert_eq!(span.kind, SpanKind::Argument);
        }
    }

    #[test]
    fn test_span_kind_requires_pattern_check() {
        assert!(SpanKind::Executed.requires_pattern_check());
        assert!(SpanKind::InlineCode.requires_pattern_check());
        assert!(SpanKind::HeredocBody.requires_pattern_check());
        assert!(SpanKind::Unknown.requires_pattern_check());
        assert!(!SpanKind::Data.requires_pattern_check());
        assert!(!SpanKind::Argument.requires_pattern_check());
    }

    #[test]
    fn test_span_kind_is_safe_data() {
        assert!(SpanKind::Data.is_safe_data());
        assert!(!SpanKind::Argument.is_safe_data());
        assert!(!SpanKind::Executed.is_safe_data());
    }

    #[test]
    fn test_empty_command() {
        let spans = classify_command("");
        assert!(spans.spans().is_empty());
    }

    #[test]
    fn test_whitespace_only() {
        let spans = classify_command("   ");
        // Should have one Executed span (conservative)
        assert!(!spans.spans().is_empty());
    }

    #[test]
    fn test_nested_command_substitution() {
        let cmd = "echo $(echo $(rm -rf /))";
        let spans = classify_command(cmd);

        // Should detect the outer command substitution as InlineCode
        let inline_span = spans
            .spans()
            .iter()
            .find(|s| s.kind == SpanKind::InlineCode);
        assert!(inline_span.is_some());
    }

    #[test]
    fn test_single_quote_preserves_special_chars() {
        let cmd = "echo '$HOME'";
        let spans = classify_command(cmd);

        // '$HOME' should be Data (single quotes prevent expansion)
        let data_span = spans.spans().iter().find(|s| s.kind == SpanKind::Data);
        assert!(data_span.is_some());
        assert_eq!(data_span.unwrap().text(cmd), "'$HOME'");
    }

    #[test]
    fn test_mixed_quotes() {
        let cmd = "echo 'single' \"double\" plain";
        let spans = classify_command(cmd);

        // Should have at least 3 distinct spans
        let data_count = spans
            .spans()
            .iter()
            .filter(|s| s.kind == SpanKind::Data)
            .count();
        let arg_count = spans
            .spans()
            .iter()
            .filter(|s| s.kind == SpanKind::Argument)
            .count();

        assert!(data_count >= 1, "Should have single-quoted Data span");
        assert!(arg_count >= 1, "Should have double-quoted Argument span");
    }

    #[test]
    fn test_or_operator() {
        let cmd = "false || rm -rf /";
        let spans = classify_command(cmd);

        // Both parts should be executable
        assert!(spans.has_executable_content());
    }

    #[test]
    fn test_path_prefixed_command() {
        let cmd = "/usr/bin/bash -c \"rm -rf /\"";
        let spans = classify_command(cmd);

        // Should still detect inline code after path-prefixed bash
        let inline_span = spans
            .spans()
            .iter()
            .find(|s| s.kind == SpanKind::InlineCode);
        assert!(
            inline_span.is_some(),
            "Should detect inline code after /usr/bin/bash -c"
        );
    }

    #[test]
    fn test_performance_typical_commands() {
        use std::time::Instant;

        // Test a variety of typical commands
        let commands = [
            "git status",
            "git commit -m 'Fix bug in parser'",
            "echo \"hello world\" | cat",
            "ls -la /tmp",
            "cargo test --release",
            "python -c \"print('hello')\"",
            "bash -c \"echo test && echo done\"",
            "docker ps --all --format '{{.Names}}'",
        ];

        // Warm up
        for cmd in &commands {
            let _ = classify_command(cmd);
        }

        // Time 1000 iterations
        let iterations = 1000;
        let start = Instant::now();
        for _ in 0..iterations {
            for cmd in &commands {
                let _ = classify_command(cmd);
            }
        }
        let elapsed = start.elapsed();

        // Calculate average per command
        let total_commands = iterations * commands.len();
        let avg_nanoseconds = elapsed.as_nanos() / total_commands as u128;
        #[allow(clippy::cast_precision_loss)]
        let avg_microseconds = avg_nanoseconds as f64 / 1000.0;

        // Assert performance is under 100μs per command
        assert!(
            avg_microseconds < 100.0,
            "Average classification time {avg_microseconds:.2}μs exceeds 100μs budget"
        );

        // Print for visibility in test output
        eprintln!(
            "Context classification performance: {avg_microseconds:.2}μs/command ({} commands, {} iterations)",
            commands.len(),
            iterations
        );
    }

    // =========================================================================
    // Safe String Registry Tests (git_safety_guard-t8x.1)
    // =========================================================================

    #[test]
    fn test_registry_echo_is_all_data() {
        // echo command - all args are data, never executed
        assert!(SAFE_STRING_REGISTRY.is_all_args_data("echo"));
        assert!(SAFE_STRING_REGISTRY.is_all_args_data("/bin/echo"));
        assert!(SAFE_STRING_REGISTRY.is_all_args_data("/usr/bin/echo"));
    }

    #[test]
    fn test_registry_printf_is_all_data() {
        // printf command - all args are data, never executed
        assert!(SAFE_STRING_REGISTRY.is_all_args_data("printf"));
        assert!(SAFE_STRING_REGISTRY.is_all_args_data("/usr/bin/printf"));
    }

    #[test]
    fn test_registry_bash_is_not_all_data() {
        // bash is NOT all-data - it executes code!
        assert!(!SAFE_STRING_REGISTRY.is_all_args_data("bash"));
        assert!(!SAFE_STRING_REGISTRY.is_all_args_data("sh"));
        assert!(!SAFE_STRING_REGISTRY.is_all_args_data("python"));
    }

    #[test]
    fn test_registry_git_message_flags() {
        // git -m and --message are data (commit messages)
        assert!(SAFE_STRING_REGISTRY.is_flag_data("git", "-m"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data("git", "--message"));
        // But other git flags are NOT data
        assert!(!SAFE_STRING_REGISTRY.is_flag_data("git", "-c"));
        assert!(!SAFE_STRING_REGISTRY.is_flag_data("git", "--exec"));
    }

    #[test]
    fn test_registry_bd_description_flags() {
        // bd --description, --title, --notes, --reason are data
        assert!(SAFE_STRING_REGISTRY.is_flag_data("bd", "--description"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data("bd", "--title"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data("bd", "--notes"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data("bd", "--reason"));
    }

    #[test]
    fn test_registry_grep_pattern_flags() {
        // grep -e and --regexp are data (patterns, not code)
        assert!(SAFE_STRING_REGISTRY.is_flag_data("grep", "-e"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data("grep", "--regexp"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data("grep", "-F"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data("grep", "--fixed-strings"));
    }

    #[test]
    fn test_registry_rg_pattern_flags() {
        // rg -e, --regexp, --fixed-strings are data
        assert!(SAFE_STRING_REGISTRY.is_flag_data("rg", "-e"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data("rg", "--regexp"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data("rg", "--fixed-strings"));
    }

    #[test]
    fn test_registry_gh_cli_flags() {
        // gh -t, -b, -m and their long forms are data
        assert!(SAFE_STRING_REGISTRY.is_flag_data("gh", "-t"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data("gh", "--title"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data("gh", "-b"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data("gh", "--body"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data("gh", "-m"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data("gh", "--message"));
    }

    #[test]
    fn test_registry_data_flags_for_git() {
        let flags = SAFE_STRING_REGISTRY.data_flags_for_command("git");
        assert!(flags.contains(&"-m"));
        assert!(flags.contains(&"--message"));
    }

    #[test]
    fn test_registry_data_flags_for_grep() {
        let flags = SAFE_STRING_REGISTRY.data_flags_for_command("grep");
        assert!(flags.contains(&"-e"));
        assert!(flags.contains(&"--regexp"));
        assert!(flags.contains(&"-F"));
        assert!(flags.contains(&"--fixed-strings"));
    }

    #[test]
    fn test_is_argument_data_echo() {
        // echo "rm -rf /" - the argument is data
        assert!(is_argument_data("echo \"rm -rf /\"", None));
    }

    #[test]
    fn test_is_argument_data_git_commit_message() {
        // git commit -m "..." - the -m argument is data
        assert!(is_argument_data("git commit -m \"Fix rm -rf\"", Some("-m")));
    }

    #[test]
    fn test_is_argument_data_rg_pattern() {
        // rg -e "rm -rf" - the -e argument is data
        assert!(is_argument_data("rg -e \"rm -rf\" src/", Some("-e")));
    }

    #[test]
    fn test_is_argument_data_bash_c_is_not_data() {
        // bash -c "rm -rf /" - the -c argument is CODE, not data!
        assert!(!is_argument_data("bash -c \"rm -rf /\"", Some("-c")));
    }

    #[test]
    fn test_counterexample_bash_executes() {
        // Counterexample: bash -c MUST still be treated as code
        // This test ensures we don't accidentally suppress bash -c
        assert!(!SAFE_STRING_REGISTRY.is_all_args_data("bash"));
        assert!(!SAFE_STRING_REGISTRY.is_flag_data("bash", "-c"));
    }

    #[test]
    fn test_counterexample_python_executes() {
        // Counterexample: python -c MUST still be treated as code
        assert!(!SAFE_STRING_REGISTRY.is_all_args_data("python"));
        assert!(!SAFE_STRING_REGISTRY.is_flag_data("python", "-c"));
    }

    #[test]
    fn test_counterexample_xargs_executes() {
        // Counterexample: xargs can execute commands
        assert!(!SAFE_STRING_REGISTRY.is_all_args_data("xargs"));
    }

    #[test]
    fn test_false_positive_git_commit_message() {
        // This should NOT trigger pattern matching on commit message
        let cmd = "git commit -m \"Fix git reset --hard detection\"";

        // Using the registry, we know -m flag args are data
        assert!(SAFE_STRING_REGISTRY.is_flag_data("git", "-m"));

        // Combined with context classification, the quoted part is Argument
        let spans = classify_command(cmd);
        let msg_span = spans
            .spans()
            .iter()
            .find(|s| s.text(cmd).contains("reset --hard"));
        assert!(msg_span.is_some());
        // The message should be classified as Argument (not requiring pattern check)
        assert_eq!(msg_span.unwrap().kind, SpanKind::Argument);
    }

    #[test]
    fn test_false_positive_rg_pattern() {
        // This should NOT trigger pattern matching on rg pattern
        let cmd = "rg -e \"rm -rf\" src/";

        // Using the registry, we know -e flag args are data
        assert!(SAFE_STRING_REGISTRY.is_flag_data("rg", "-e"));

        // The quoted pattern should be classified as Argument
        let spans = classify_command(cmd);
        let pattern_span = spans.spans().iter().find(|s| s.text(cmd) == "\"rm -rf\"");
        assert!(pattern_span.is_some());
        assert_eq!(pattern_span.unwrap().kind, SpanKind::Argument);
    }

    #[test]
    fn test_false_positive_bd_create() {
        // This should NOT trigger pattern matching on bd description
        let cmd = "bd create --description=\"This pattern blocks rm -rf\"";

        // Using the registry
        assert!(SAFE_STRING_REGISTRY.is_flag_data("bd", "--description"));

        // The description should be classified as Argument
        let spans = classify_command(cmd);
        let desc_span = spans
            .spans()
            .iter()
            .find(|s| s.text(cmd).contains("rm -rf"));
        assert!(desc_span.is_some());
        // Note: current classification treats this as Argument (attached to flag)
        assert_eq!(desc_span.unwrap().kind, SpanKind::Argument);
    }

    #[test]
    fn test_true_positive_bash_c() {
        // This MUST trigger pattern matching - bash -c is CODE!
        let cmd = "bash -c \"rm -rf /\"";

        // bash -c is NOT in the data registry
        assert!(!SAFE_STRING_REGISTRY.is_flag_data("bash", "-c"));

        // The classifier should detect this as InlineCode
        let spans = classify_command(cmd);
        let code_span = spans
            .spans()
            .iter()
            .find(|s| s.kind == SpanKind::InlineCode);
        assert!(code_span.is_some(), "bash -c content must be InlineCode");
    }

    #[test]
    fn test_true_positive_python_c() {
        // This MUST trigger pattern matching - python -c is CODE!
        let cmd = "python -c \"import os; os.system('rm -rf /')\"";

        // python -c is NOT in the data registry
        assert!(!SAFE_STRING_REGISTRY.is_flag_data("python", "-c"));

        // The classifier should detect this as InlineCode
        let spans = classify_command(cmd);
        let code_span = spans
            .spans()
            .iter()
            .find(|s| s.kind == SpanKind::InlineCode);
        assert!(code_span.is_some(), "python -c content must be InlineCode");
    }
}

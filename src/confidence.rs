//! Confidence scoring for pattern matches.
//!
//! This module provides a lightweight confidence model that helps reduce false positives
//! by scoring how confident we are that a pattern match is truly destructive.
//!
//! # Design Principles
//!
//! 1. **Conservative by default**: When in doubt, treat as high confidence (block)
//! 2. **Explainable**: Every confidence adjustment is tracked with a signal
//! 3. **Fast**: Confidence scoring adds minimal overhead to evaluation
//!
//! # Confidence Signals
//!
//! The confidence score is computed from multiple signals:
//! - **Match location**: Executed context vs data context (string literals, comments)
//! - **Wrapper context**: Known-safe wrappers like `git commit -m`, `rg`, `echo`
//! - **Execution operators**: Presence of `|`, `;`, `&&`, `$(...)` near match
//! - **Sanitization**: Whether the match was in content masked by sanitization
//!
//! # Example
//!
//! ```ignore
//! use destructive_command_guard::confidence::{compute_match_confidence, ConfidenceContext};
//!
//! let ctx = ConfidenceContext {
//!     command: "git commit -m 'Fix rm -rf detection'",
//!     sanitized_command: "git commit -m ''",  // 'rm -rf' was masked
//!     match_start: 17,
//!     match_end: 31,
//! };
//! let score = compute_match_confidence(&ctx);
//! // score.value < 0.5 because match is in a sanitized (data) region
//! ```

use crate::context::{CommandSpans, SpanKind, classify_command};
use smallvec::SmallVec;

/// A signal that contributed to the confidence score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfidenceSignal {
    /// Match is in an executed span (high confidence).
    ExecutedSpan,
    /// Match is in an inline code span like `bash -c` (high confidence).
    InlineCodeSpan,
    /// Match is in a data span like single-quoted string (low confidence).
    DataSpan,
    /// Match is in an argument span like `git commit -m` (low confidence).
    ArgumentSpan,
    /// Match is in a comment (very low confidence).
    CommentSpan,
    /// Match is in a heredoc body (needs deeper analysis).
    HeredocBodySpan,
    /// Match is in an ambiguous/unknown span (moderate confidence).
    UnknownSpan,
    /// Match was in content masked by sanitization (low confidence).
    SanitizedRegion,
    /// Match has execution operators nearby (boost confidence).
    ExecutionOperatorsNearby,
    /// Match is at command position (first word, high confidence).
    CommandPosition,
    /// Match is clearly in argument position (lower confidence).
    ArgumentPosition,
}

impl ConfidenceSignal {
    /// Get the confidence adjustment for this signal.
    ///
    /// Returns a multiplier (0.0 - 1.0) that reduces confidence,
    /// or a value > 1.0 that boosts confidence.
    #[must_use]
    pub const fn weight(self) -> f32 {
        match self {
            // High confidence signals (executed code)
            Self::ExecutedSpan | Self::InlineCodeSpan => 1.0,
            Self::CommandPosition | Self::ExecutionOperatorsNearby => 1.1, // Slight boost
            // Low confidence signals (data context)
            Self::DataSpan => 0.1,
            Self::CommentSpan => 0.05,
            Self::ArgumentSpan => 0.3,
            Self::SanitizedRegion => 0.2,
            Self::ArgumentPosition => 0.6,
            // Moderate confidence (ambiguous)
            Self::HeredocBodySpan => 0.7, // Needs deeper analysis
            Self::UnknownSpan => 0.8,     // Conservative
        }
    }

    /// Human-readable description of this signal.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::ExecutedSpan => "match is in executed code",
            Self::InlineCodeSpan => "match is in inline code (bash -c, python -c, etc.)",
            Self::DataSpan => "match is in a data string (single-quoted)",
            Self::CommentSpan => "match is in a comment",
            Self::ArgumentSpan => "match is in a string argument to a safe command",
            Self::HeredocBodySpan => "match is in a heredoc body",
            Self::UnknownSpan => "match context is ambiguous",
            Self::SanitizedRegion => "match was in a region masked by sanitization",
            Self::ExecutionOperatorsNearby => "execution operators (|, ;, &&) found nearby",
            Self::CommandPosition => "match is at command position",
            Self::ArgumentPosition => "match is in argument position",
        }
    }
}

/// A confidence score with the signals that contributed to it.
#[derive(Debug, Clone)]
pub struct ConfidenceScore {
    /// The final confidence value (0.0 - 1.0).
    /// Higher values mean more confident the match is truly destructive.
    pub value: f32,
    /// Signals that contributed to this score (for debugging/explain).
    pub signals: SmallVec<[ConfidenceSignal; 4]>,
}

impl Default for ConfidenceScore {
    fn default() -> Self {
        Self::high()
    }
}

impl ConfidenceScore {
    /// Create a high confidence score (default for matches).
    #[must_use]
    pub fn high() -> Self {
        Self {
            value: 1.0,
            signals: SmallVec::new(),
        }
    }

    /// Create a low confidence score.
    #[must_use]
    pub fn low(signal: ConfidenceSignal) -> Self {
        let mut signals = SmallVec::new();
        signals.push(signal);
        Self {
            value: signal.weight(),
            signals,
        }
    }

    /// Add a signal and adjust the score.
    pub fn add_signal(&mut self, signal: ConfidenceSignal) {
        self.signals.push(signal);
        // Use multiplicative adjustment (clamped to 0.0 - 1.0)
        self.value = (self.value * signal.weight()).clamp(0.0, 1.0);
    }

    /// Check if confidence is below a threshold.
    #[must_use]
    pub fn is_low(&self, threshold: f32) -> bool {
        self.value < threshold
    }

    /// Check if confidence warrants downgrading from Deny to Warn.
    ///
    /// Returns true if confidence is below the warn threshold (default 0.5).
    #[must_use]
    pub fn should_warn(&self) -> bool {
        self.is_low(DEFAULT_WARN_THRESHOLD)
    }
}

/// Default threshold below which we downgrade Deny to Warn.
pub const DEFAULT_WARN_THRESHOLD: f32 = 0.5;

/// Context for computing match confidence.
pub struct ConfidenceContext<'a> {
    /// The original command string.
    pub command: &'a str,
    /// The sanitized command (with safe data regions masked).
    pub sanitized_command: Option<&'a str>,
    /// Start byte offset of the match in the original command.
    pub match_start: usize,
    /// End byte offset of the match in the original command.
    pub match_end: usize,
}

/// Compute confidence for a pattern match.
///
/// This analyzes the match context to determine how confident we are
/// that the match represents actual destructive intent vs. a false positive.
#[must_use]
pub fn compute_match_confidence(ctx: &ConfidenceContext<'_>) -> ConfidenceScore {
    let mut score = ConfidenceScore::high();

    // Signal 1: Check if match is in a sanitized region
    if let Some(sanitized) = ctx.sanitized_command {
        if ctx.match_start < sanitized.len()
            && ctx.match_end <= sanitized.len()
            && sanitized != ctx.command
        {
            // Check if the matched region is different in sanitized vs original
            let original_slice = ctx.command.get(ctx.match_start..ctx.match_end);
            let sanitized_slice = sanitized.get(ctx.match_start..ctx.match_end);

            if original_slice != sanitized_slice {
                // Match was in a sanitized region - low confidence
                score.add_signal(ConfidenceSignal::SanitizedRegion);
            }
        }
    }

    // Signal 2: Classify span at match location
    let spans = classify_command(ctx.command);
    let signal = classify_match_span(&spans, ctx.match_start, ctx.match_end);
    score.add_signal(signal);

    // Signal 3: Check for execution operators nearby
    if has_execution_operators_nearby(ctx.command, ctx.match_start, ctx.match_end) {
        score.add_signal(ConfidenceSignal::ExecutionOperatorsNearby);
    }

    // Signal 4: Check if match is at command position vs argument position
    if is_command_position(ctx.command, ctx.match_start) {
        score.add_signal(ConfidenceSignal::CommandPosition);
    } else {
        score.add_signal(ConfidenceSignal::ArgumentPosition);
    }

    score
}

/// Classify the span type at a given byte range.
fn classify_match_span(
    spans: &CommandSpans,
    match_start: usize,
    match_end: usize,
) -> ConfidenceSignal {
    // Find the span that contains the match start
    for span in spans.spans() {
        if span.byte_range.start <= match_start && match_end <= span.byte_range.end {
            return match span.kind {
                SpanKind::Executed => ConfidenceSignal::ExecutedSpan,
                SpanKind::InlineCode => ConfidenceSignal::InlineCodeSpan,
                SpanKind::Data => ConfidenceSignal::DataSpan,
                SpanKind::Argument => ConfidenceSignal::ArgumentSpan,
                SpanKind::Comment => ConfidenceSignal::CommentSpan,
                SpanKind::HeredocBody => ConfidenceSignal::HeredocBodySpan,
                SpanKind::Unknown => ConfidenceSignal::UnknownSpan,
            };
        }
    }

    // Match spans multiple regions or is outside classified spans
    // Conservative: treat as unknown (moderate confidence)
    ConfidenceSignal::UnknownSpan
}

/// Check if there are execution operators near the match.
///
/// Execution operators like |, ;, &&, || suggest the command will be executed.
fn has_execution_operators_nearby(command: &str, match_start: usize, match_end: usize) -> bool {
    // Look for operators within 20 bytes before the match.
    // Use get() to handle potential UTF-8 boundary issues if search_start
    // lands in the middle of a multi-byte character.
    let search_start = match_start.saturating_sub(20);
    let prefix = command.get(search_start..match_start).unwrap_or("");

    // Look for operators within 20 bytes after the match
    let search_end = (match_end + 20).min(command.len());
    let suffix = command.get(match_end..search_end).unwrap_or("");

    let operators = ["|", ";", "&&", "||", "$(", "`"];

    for op in &operators {
        if prefix.contains(op) || suffix.contains(op) {
            return true;
        }
    }

    false
}

/// Check if the match is at command position (first word of a segment).
fn is_command_position(command: &str, match_start: usize) -> bool {
    if match_start == 0 {
        return true;
    }

    // Get the prefix before the match
    let prefix = &command[..match_start];

    // Check if the last non-whitespace before match is a segment separator
    let trimmed = prefix.trim_end();
    if trimmed.is_empty() {
        return true;
    }

    // Command position is after: beginning, |, ;, &&, ||, (, $( , `
    let last_char = trimmed.chars().last().unwrap_or(' ');
    matches!(last_char, '|' | ';' | '(' | '`')
        || trimmed.ends_with("&&")
        || trimmed.ends_with("||")
        || trimmed.ends_with("$(")
}

/// Compute confidence for a match, returning both the score and whether to downgrade.
///
/// This is a convenience function that combines confidence computation with
/// the downgrade decision.
#[must_use]
pub fn should_downgrade_to_warn(ctx: &ConfidenceContext<'_>) -> (ConfidenceScore, bool) {
    let score = compute_match_confidence(ctx);
    let downgrade = score.should_warn();
    (score, downgrade)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_high_confidence_executed_command() {
        let ctx = ConfidenceContext {
            command: "rm -rf /",
            sanitized_command: None,
            match_start: 0,
            match_end: 8,
        };
        let score = compute_match_confidence(&ctx);
        assert!(
            score.value > 0.5,
            "Direct command should have high confidence"
        );
    }

    #[test]
    fn test_low_confidence_in_commit_message() {
        // Simulating a case where sanitization masked the dangerous content
        let ctx = ConfidenceContext {
            command: "git commit -m 'Fix rm -rf detection'",
            sanitized_command: Some("git commit -m ''"),
            match_start: 18,
            match_end: 31,
        };
        let score = compute_match_confidence(&ctx);
        assert!(
            score.value < 0.5,
            "Match in sanitized commit message should have low confidence: {}",
            score.value
        );
    }

    #[test]
    fn test_confidence_with_pipe_operator() {
        let ctx = ConfidenceContext {
            command: "echo foo | rm -rf /",
            sanitized_command: None,
            match_start: 11,
            match_end: 19,
        };
        let score = compute_match_confidence(&ctx);
        // Should have execution operators nearby signal
        assert!(
            score
                .signals
                .contains(&ConfidenceSignal::ExecutionOperatorsNearby),
            "Should detect pipe operator"
        );
    }

    #[test]
    fn test_command_position_detection() {
        assert!(is_command_position("rm -rf /", 0));
        assert!(is_command_position("echo foo | rm -rf /", 11));
        assert!(is_command_position("foo && rm -rf /", 7));
        assert!(!is_command_position("git commit -m 'rm'", 15));
    }

    #[test]
    fn test_confidence_signal_weights() {
        assert!(ConfidenceSignal::ExecutedSpan.weight() >= 1.0);
        assert!(ConfidenceSignal::DataSpan.weight() < 0.5);
        assert!(ConfidenceSignal::CommentSpan.weight() < 0.1);
    }

    #[test]
    fn test_should_warn_threshold() {
        let mut score = ConfidenceScore::high();
        assert!(!score.should_warn(), "High confidence should not warn");

        score.add_signal(ConfidenceSignal::DataSpan);
        assert!(score.should_warn(), "Low confidence should warn");
    }

    #[test]
    fn test_utf8_multibyte_handling() {
        // Test that we don't panic with multi-byte UTF-8 characters near the match.
        // The emoji "🔥" is 4 bytes. If we subtract 20 bytes from position 4,
        // we'd get a negative index or land in the middle of the emoji.
        let command = "🔥🔥🔥 rm -rf /";
        // "🔥" is 4 bytes each, so "🔥🔥🔥 " is 13 bytes (12 + 1 space)
        // "rm -rf /" starts at byte 13
        let ctx = ConfidenceContext {
            command,
            sanitized_command: None,
            match_start: 13, // Start of "rm"
            match_end: 21,   // End of "rm -rf /"
        };
        // This should not panic
        let score = compute_match_confidence(&ctx);
        assert!(score.value > 0.0, "Should compute a valid score");
    }

    #[test]
    fn test_operators_nearby_with_unicode() {
        // Test execution operator detection with unicode in prefix
        let command = "écho café | rm -rf /";
        // "écho café | " has multi-byte chars, "rm" starts somewhere in the middle
        let result = has_execution_operators_nearby(command, 14, 22);
        assert!(
            result,
            "Should detect pipe operator even with unicode prefix"
        );
    }
}

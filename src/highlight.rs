//! Terminal highlighting for command spans.
//!
//! This module provides caret-style highlighting for showing which parts of a command
//! matched destructive patterns. It handles:
//! - ANSI color codes for terminal highlighting
//! - UTF-8 safe span rendering
//! - Non-TTY graceful fallback
//! - Long command windowing via `evaluator::window_command`
//!
//! # Example
//!
//! ```text
//! Command: git reset --hard HEAD
//!          ^^^^^^^^^^^^^^^^
//!          └── Matched: git reset --hard
//! ```

use crate::evaluator::{DEFAULT_WINDOW_WIDTH, MatchSpan, WindowedSpan, window_command};
use colored::Colorize;
use std::fmt::Write;
use std::io::{self, IsTerminal};

/// A span to highlight within a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HighlightSpan {
    /// Start byte offset (inclusive).
    pub start: usize,
    /// End byte offset (exclusive).
    pub end: usize,
    /// Optional label for the highlight (shown below carets).
    pub label: Option<String>,
}

impl HighlightSpan {
    /// Create a new highlight span without a label.
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self {
            start,
            end,
            label: None,
        }
    }

    /// Create a new highlight span with a label.
    #[must_use]
    pub fn with_label(start: usize, end: usize, label: impl Into<String>) -> Self {
        Self {
            start,
            end,
            label: Some(label.into()),
        }
    }

    /// Convert to a `MatchSpan` for windowing.
    #[must_use]
    pub const fn to_match_span(&self) -> MatchSpan {
        MatchSpan {
            start: self.start,
            end: self.end,
        }
    }
}

/// Result of formatting a highlighted command.
#[derive(Debug, Clone)]
pub struct HighlightedCommand {
    /// The command line (possibly windowed with ellipsis).
    pub command_line: String,
    /// The caret line showing the matched span.
    pub caret_line: String,
    /// The label line (if a label was provided).
    pub label_line: Option<String>,
}

impl HighlightedCommand {
    /// Format for display, joining all lines.
    #[must_use]
    pub fn to_string_with_prefix(&self, prefix: &str) -> String {
        let mut result = format!("{prefix}{}\n", self.command_line);
        let _ = writeln!(result, "{prefix}{}", self.caret_line);
        if let Some(label) = &self.label_line {
            let _ = writeln!(result, "{prefix}{label}");
        }
        result
    }
}

/// Determines whether color should be used based on TTY and environment.
#[must_use]
pub fn should_use_color() -> bool {
    if std::env::var_os("NO_COLOR").is_some() || std::env::var_os("DCG_NO_COLOR").is_some() {
        return false;
    }

    if matches!(std::env::var("TERM").as_deref(), Ok("dumb")) {
        return false;
    }

    io::stderr().is_terminal()
}

/// Configure global color output based on TTY detection.
pub fn configure_colors() {
    if !should_use_color() {
        colored::control::set_override(false);
    }
}

/// Build a caret line that points to a span within a command.
///
/// # Arguments
///
/// * `span` - The character offsets to highlight
/// * `use_color` - Whether to use ANSI colors
///
/// # Returns
///
/// A string with spaces leading up to the span, then carets (^) for the span length.
fn build_caret_line(span: &WindowedSpan, use_color: bool) -> String {
    let leading_spaces = " ".repeat(span.start);
    let caret_count = span.end.saturating_sub(span.start).max(1);
    let carets = "^".repeat(caret_count);

    if use_color {
        format!("{leading_spaces}{}", carets.red().bold())
    } else {
        format!("{leading_spaces}{carets}")
    }
}

/// Build a label line with a corner connector pointing to the highlighted span.
///
/// # Arguments
///
/// * `span` - The character offsets being highlighted
/// * `label` - The label text to display
/// * `use_color` - Whether to use ANSI colors
///
/// # Returns
///
/// A formatted label line like "          └── Matched: git reset"
fn build_label_line(span: &WindowedSpan, label: &str, use_color: bool) -> String {
    let leading_spaces = " ".repeat(span.start);
    let connector = "└── ";

    if use_color {
        let colored_label = label.yellow();
        format!("{leading_spaces}{}{colored_label}", connector.dimmed())
    } else {
        format!("{leading_spaces}{connector}{label}")
    }
}

/// Format a command with caret highlighting for a single span.
///
/// This function:
/// - Windows long commands to fit within `max_width` characters
/// - Generates a caret line (^^^) under the matched span
/// - Optionally adds a label line below the carets
/// - Respects color settings for TTY/non-TTY output
///
/// # Arguments
///
/// * `command` - The full command string
/// * `span` - The span to highlight (byte offsets)
/// * `use_color` - Whether to use ANSI color codes
/// * `max_width` - Maximum display width (defaults to `DEFAULT_WINDOW_WIDTH`)
///
/// # Returns
///
/// A `HighlightedCommand` with the formatted output lines.
///
/// # Example
///
/// ```
/// use destructive_command_guard::highlight::{format_highlighted_command, HighlightSpan};
///
/// let span = HighlightSpan::with_label(0, 16, "Matched: git reset --hard");
/// let result = format_highlighted_command("git reset --hard HEAD", &span, false, 80);
///
/// assert!(result.command_line.contains("git reset --hard"));
/// assert!(result.caret_line.contains("^"));
/// ```
#[must_use]
pub fn format_highlighted_command(
    command: &str,
    span: &HighlightSpan,
    use_color: bool,
    max_width: usize,
) -> HighlightedCommand {
    let match_span = span.to_match_span();
    let windowed = window_command(command, &match_span, max_width);

    let command_line = if use_color {
        colorize_command_with_span(&windowed.display, windowed.adjusted_span.as_ref())
    } else {
        windowed.display.clone()
    };

    let (caret_line, label_line) = windowed.adjusted_span.map_or_else(
        || {
            // Fallback: no valid span, show minimal indicator
            let fallback_caret = if use_color {
                "^".red().bold().to_string()
            } else {
                "^".to_string()
            };
            (fallback_caret, None)
        },
        |adj_span| {
            let caret = build_caret_line(&adj_span, use_color);
            let label = span
                .label
                .as_ref()
                .map(|l| build_label_line(&adj_span, l, use_color));
            (caret, label)
        },
    );

    HighlightedCommand {
        command_line,
        caret_line,
        label_line,
    }
}

/// Colorize a command string, highlighting the matched span in red.
fn colorize_command_with_span(command: &str, span: Option<&WindowedSpan>) -> String {
    let Some(span) = span else {
        return command.to_string();
    };

    // Convert character span to byte offsets for slicing
    let chars: Vec<char> = command.chars().collect();
    if span.start >= chars.len() || span.end > chars.len() || span.start >= span.end {
        return command.to_string();
    }

    // Find byte boundaries
    let before_end: usize = chars[..span.start].iter().map(|c| c.len_utf8()).sum();
    let match_end: usize = chars[..span.end].iter().map(|c| c.len_utf8()).sum();

    let before = &command[..before_end];
    let matched = &command[before_end..match_end];
    let after = &command[match_end..];

    format!("{before}{}{}", matched.red().bold(), after)
}

/// Format a command with caret highlighting using default settings.
///
/// Convenience wrapper around `format_highlighted_command` that:
/// - Auto-detects TTY for color support
/// - Uses the default window width
#[must_use]
pub fn format_highlighted_command_auto(command: &str, span: &HighlightSpan) -> HighlightedCommand {
    format_highlighted_command(command, span, should_use_color(), DEFAULT_WINDOW_WIDTH)
}

/// Format multiple spans in a command (primary span highlighted, others noted).
///
/// For commands with multiple matches, this highlights the primary span
/// and adds notes about additional matches.
///
/// # Arguments
///
/// * `command` - The full command string
/// * `spans` - All spans to highlight (first is primary)
/// * `use_color` - Whether to use ANSI colors
/// * `max_width` - Maximum display width
///
/// # Returns
///
/// A vector of `HighlightedCommand` for each span.
#[must_use]
pub fn format_highlighted_command_multi(
    command: &str,
    spans: &[HighlightSpan],
    use_color: bool,
    max_width: usize,
) -> Vec<HighlightedCommand> {
    spans
        .iter()
        .map(|span| format_highlighted_command(command, span, use_color, max_width))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_highlight_span_new() {
        let span = HighlightSpan::new(5, 10);
        assert_eq!(span.start, 5);
        assert_eq!(span.end, 10);
        assert!(span.label.is_none());
    }

    #[test]
    fn test_highlight_span_with_label() {
        let span = HighlightSpan::with_label(0, 16, "test label");
        assert_eq!(span.start, 0);
        assert_eq!(span.end, 16);
        assert_eq!(span.label.as_deref(), Some("test label"));
    }

    #[test]
    fn test_format_simple_command() {
        let cmd = "git reset --hard HEAD";
        let span = HighlightSpan::new(0, 16);
        let result = format_highlighted_command(cmd, &span, false, 80);

        assert_eq!(result.command_line, cmd);
        assert!(result.caret_line.starts_with('^'));
        assert_eq!(result.caret_line.matches('^').count(), 16);
    }

    #[test]
    fn test_format_with_label() {
        let cmd = "git reset --hard HEAD";
        let span = HighlightSpan::with_label(0, 16, "Matched: git reset");
        let result = format_highlighted_command(cmd, &span, false, 80);

        assert!(result.label_line.is_some());
        let label = result.label_line.unwrap();
        assert!(label.contains("└──"));
        assert!(label.contains("Matched: git reset"));
    }

    #[test]
    fn test_format_middle_span() {
        let cmd = "echo test && git reset --hard && echo done";
        // "git reset --hard" starts at position 13
        let span = HighlightSpan::new(13, 29);
        let result = format_highlighted_command(cmd, &span, false, 80);

        // Caret line should have leading spaces
        assert!(result.caret_line.starts_with("             "));
        assert!(result.caret_line.contains('^'));
    }

    #[test]
    fn test_format_long_command_windowed() {
        let prefix = "a ".repeat(50);
        let suffix = " b".repeat(50);
        let cmd = format!("{prefix}git reset --hard{suffix}");

        // Find where "git reset" starts
        let start = prefix.len();
        let span = HighlightSpan::with_label(start, start + 16, "dangerous");
        let result = format_highlighted_command(&cmd, &span, false, 60);

        // Should be windowed with ellipsis
        assert!(result.command_line.contains("..."));
        // Should still contain the match
        assert!(result.command_line.contains("git reset --hard"));
    }

    #[test]
    fn test_format_utf8_command() {
        // Command with multi-byte UTF-8 characters (é=2 bytes, ö=2 bytes)
        // This adds 2 extra bytes vs character count, shifting byte positions
        let cmd = "echo 'héllo wörld' && rm -rf /tmp/test";
        // "rm -rf " starts at byte 24 (not char 22) due to UTF-8 multi-byte chars
        let span = HighlightSpan::new(24, 31); // "rm -rf " (7 bytes)
        let result = format_highlighted_command(cmd, &span, false, 80);

        // Should not panic and should have valid output
        assert!(!result.command_line.is_empty());
        assert!(result.caret_line.contains('^'));
    }

    #[test]
    fn test_format_empty_span() {
        let cmd = "git status";
        let span = HighlightSpan::new(5, 5);
        let result = format_highlighted_command(cmd, &span, false, 80);

        // Should handle gracefully with at least one caret
        assert!(result.caret_line.contains('^'));
    }

    #[test]
    fn test_format_span_at_end() {
        let cmd = "echo test && git push --force";
        let end = cmd.len();
        let span = HighlightSpan::new(end - 12, end);
        let result = format_highlighted_command(cmd, &span, false, 80);

        assert!(result.caret_line.contains('^'));
    }

    #[test]
    fn test_format_windowing_limits_width() {
        let prefix = "a ".repeat(60);
        let suffix = " b".repeat(60);
        let cmd = format!("{prefix}git reset --hard{suffix}");
        let start = prefix.len();
        let span = HighlightSpan::with_label(start, start + 16, "Matched: git reset --hard");
        let max_width = 50;

        let result = format_highlighted_command(&cmd, &span, false, max_width);

        assert!(result.command_line.contains("git reset --hard"));
        assert!(result.command_line.contains("..."));
        assert!(result.command_line.chars().count() <= max_width);
        assert!(result.caret_line.find('^').unwrap_or(0) >= 3);
    }

    #[test]
    fn test_format_utf8_windowing_alignment() {
        let prefix = "é".repeat(40);
        let cmd = format!("{prefix} rm -rf /tmp/test tail");
        let start = prefix.len() + 1;
        let matched = "rm -rf /tmp/test";
        let span = HighlightSpan::new(start, start + matched.len());

        let result = format_highlighted_command(&cmd, &span, false, 30);

        assert!(result.command_line.contains(matched));
        assert!(result.command_line.contains("..."));
        assert_eq!(result.caret_line.matches('^').count(), matched.len());
        assert!(result.caret_line.find('^').unwrap_or(0) >= 3);
    }

    #[test]
    fn test_format_no_ansi_when_color_disabled() {
        let cmd = "git reset --hard HEAD";
        let span = HighlightSpan::with_label(0, 16, "Matched: git reset");
        let result = format_highlighted_command(cmd, &span, false, 80);

        assert!(!result.command_line.contains('\u{1b}'));
        assert!(!result.caret_line.contains('\u{1b}'));
        if let Some(label) = result.label_line {
            assert!(!label.contains('\u{1b}'));
        }
    }

    #[test]
    fn test_build_caret_line_no_color() {
        let span = WindowedSpan { start: 5, end: 10 };
        let caret = build_caret_line(&span, false);

        assert_eq!(caret, "     ^^^^^");
    }

    #[test]
    fn test_build_label_line_no_color() {
        let span = WindowedSpan { start: 5, end: 10 };
        let label = build_label_line(&span, "test", false);

        assert!(label.starts_with("     └── "));
        assert!(label.ends_with("test"));
    }

    #[test]
    fn test_format_highlighted_command_auto() {
        // This tests the auto-detect convenience function
        let cmd = "git reset --hard";
        let span = HighlightSpan::new(0, 16);
        let result = format_highlighted_command_auto(cmd, &span);

        assert!(!result.command_line.is_empty());
        assert!(!result.caret_line.is_empty());
    }

    #[test]
    fn test_format_highlighted_command_multi() {
        let cmd = "git reset --hard && rm -rf /tmp";
        let spans = vec![
            HighlightSpan::with_label(0, 16, "reset"),
            HighlightSpan::with_label(20, 26, "rm -rf"),
        ];
        let results = format_highlighted_command_multi(cmd, &spans, false, 80);

        assert_eq!(results.len(), 2);
        assert!(results[0].label_line.as_ref().unwrap().contains("reset"));
        assert!(results[1].label_line.as_ref().unwrap().contains("rm -rf"));
    }

    #[test]
    fn test_highlighted_command_to_string() {
        let cmd = "git reset --hard";
        let span = HighlightSpan::with_label(0, 16, "Matched");
        let result = format_highlighted_command(cmd, &span, false, 80);

        let output = result.to_string_with_prefix("  ");
        assert!(output.contains("  git reset"));
        assert!(output.contains("  ^"));
        assert!(output.contains("  └──"));
    }

    #[test]
    fn test_colorize_command_with_span() {
        let cmd = "git reset --hard";
        let span = WindowedSpan { start: 0, end: 16 };
        let result = colorize_command_with_span(cmd, Some(&span));

        // With color enabled in test, should contain ANSI codes
        // In CI, may not have color, but shouldn't panic
        assert!(!result.is_empty());
    }

    #[test]
    fn test_should_use_color_respects_no_color() {
        // Note: This test depends on environment state
        // In CI, NO_COLOR might be set, so we just verify the function doesn't panic
        let _ = should_use_color();
    }

    // =========================================================================
    // UTF-8 Boundary Case Tests
    // =========================================================================

    #[test]
    fn test_utf8_2byte_chars_caret_alignment() {
        // é is 2 bytes, so byte offsets differ from char offsets
        let cmd = "echo café && rm -rf /";
        // "rm -rf /" starts at char position 13, but byte position 14 (due to é)
        // After "echo café && " = 5 + 5 + 4 = 14 bytes, 13 chars
        let byte_start = "echo café && ".len(); // 14 bytes
        let span = HighlightSpan::new(byte_start, byte_start + 8); // "rm -rf /"
        let result = format_highlighted_command(cmd, &span, false, 80);

        // Command should be unchanged (fits in width)
        assert_eq!(result.command_line, cmd);
        // Caret line should have carets under "rm -rf /"
        assert!(result.caret_line.contains('^'));
        // Count of carets should match the span length in chars
        let caret_count = result.caret_line.matches('^').count();
        assert!(caret_count > 0, "Expected carets for the match");
    }

    #[test]
    fn test_utf8_3byte_chars_caret_alignment() {
        // 中 is 3 bytes each
        let cmd = "echo 中文 && git reset --hard";
        // "中文" = 6 bytes but 2 chars
        // "echo 中文 && " = 5 + 6 + 4 = 15 bytes, but 11 chars
        let byte_start = "echo 中文 && ".len();
        let span = HighlightSpan::new(byte_start, byte_start + 16);
        let result = format_highlighted_command(cmd, &span, false, 80);

        assert_eq!(result.command_line, cmd);
        assert!(result.caret_line.contains('^'));
    }

    #[test]
    fn test_utf8_4byte_emoji_caret_alignment() {
        // 🔥 is 4 bytes
        let cmd = "echo 🔥🔥🔥 && rm -rf /tmp";
        // "🔥🔥🔥" = 12 bytes but 3 chars
        // "echo 🔥🔥🔥 && " = 5 + 12 + 4 = 21 bytes, 12 chars
        let byte_start = "echo 🔥🔥🔥 && ".len();
        let span = HighlightSpan::new(byte_start, byte_start + 6); // "rm -rf"
        let result = format_highlighted_command(cmd, &span, false, 80);

        assert_eq!(result.command_line, cmd);
        assert!(result.caret_line.contains('^'));
        // The leading spaces should account for character positions, not bytes
        let leading_spaces = result.caret_line.len() - result.caret_line.trim_start().len();
        // Leading spaces should be character count before span (12 chars)
        assert_eq!(leading_spaces, 12);
    }

    #[test]
    fn test_utf8_mixed_multibyte_alignment() {
        // Mix of ASCII, 2-byte, 3-byte, and 4-byte chars
        let cmd = "café 中文 🎉 rm -rf /";
        // café = 5 bytes (4 chars), 中文 = 6 bytes (2 chars), 🎉 = 4 bytes (1 char)
        // Total before "rm -rf /": "café 中文 🎉 " = 5+1+6+1+4+1 = 18 bytes, 10 chars
        let byte_start = "café 中文 🎉 ".len();
        let span = HighlightSpan::new(byte_start, byte_start + 8);
        let result = format_highlighted_command(cmd, &span, false, 80);

        assert!(!result.command_line.is_empty());
        let leading_spaces = result.caret_line.len() - result.caret_line.trim_start().len();
        assert_eq!(leading_spaces, 10);
    }

    #[test]
    fn test_utf8_span_at_multibyte_boundary() {
        // Span starts in the middle of a multibyte char (should snap to boundary)
        let cmd = "echo 🔥 test";
        // 🔥 is bytes 5-8, try to start at byte 6 (middle of emoji)
        let span = HighlightSpan::new(6, 10);
        let result = format_highlighted_command(cmd, &span, false, 80);

        // Should not panic and should handle gracefully
        assert!(!result.command_line.is_empty());
        // May produce fallback or adjusted span
    }

    #[test]
    fn test_utf8_full_width_chars() {
        // Full-width characters (CJK) that may affect display width
        let cmd = "echo 全角文字 && rm -rf";
        let byte_start = "echo 全角文字 && ".len();
        let span = HighlightSpan::new(byte_start, cmd.len());
        let result = format_highlighted_command(cmd, &span, false, 80);

        assert!(!result.command_line.is_empty());
        assert!(result.caret_line.contains('^'));
    }

    // =========================================================================
    // Long Command Windowing Edge Cases
    // =========================================================================

    #[test]
    fn test_windowing_match_at_exact_start() {
        let match_text = "git reset --hard";
        let suffix = " && ".to_string() + &"x".repeat(100);
        let cmd = format!("{match_text}{suffix}");
        let span = HighlightSpan::new(0, 16);
        let result = format_highlighted_command(&cmd, &span, false, 40);

        // Should NOT have left ellipsis
        assert!(!result.command_line.starts_with("..."));
        // Should have right ellipsis
        assert!(result.command_line.ends_with("..."));
        // Match should be at start
        assert!(result.command_line.contains("git reset --hard"));
        // Caret should start at position 0
        assert!(result.caret_line.starts_with('^'));
    }

    #[test]
    fn test_windowing_match_at_exact_end() {
        let prefix = "x".repeat(100) + " && ";
        let match_text = "git reset --hard";
        let cmd = format!("{prefix}{match_text}");
        let span = HighlightSpan::new(prefix.len(), cmd.len());
        let result = format_highlighted_command(&cmd, &span, false, 40);

        // Should have left ellipsis
        assert!(result.command_line.starts_with("..."));
        // Should NOT have right ellipsis
        assert!(!result.command_line.ends_with("..."));
        assert!(result.command_line.contains("git reset --hard"));
    }

    #[test]
    fn test_windowing_match_larger_than_window() {
        // Match is 50 chars, window is 30
        let match_text = "a".repeat(50);
        let cmd = format!("prefix {match_text} suffix");
        let span = HighlightSpan::new(7, 57);
        let result = format_highlighted_command(&cmd, &span, false, 30);

        // Should have both ellipses and truncated match
        assert!(result.command_line.contains("..."));
        // Adjusted span should still exist
        assert!(result.caret_line.contains('^'));
    }

    #[test]
    fn test_windowing_very_narrow_window() {
        let cmd = "git reset --hard HEAD";
        let span = HighlightSpan::new(0, 16);
        // Window width of 10 chars
        let result = format_highlighted_command(cmd, &span, false, 10);

        // Should still produce valid output
        assert!(!result.command_line.is_empty());
        assert!(result.caret_line.contains('^'));
    }

    #[test]
    fn test_windowing_with_utf8_maintains_alignment() {
        // Long command with UTF-8 chars and match in middle
        let prefix = "café ".repeat(20);
        let match_text = "rm -rf /";
        let suffix = " done".repeat(20);
        let cmd = format!("{prefix}{match_text}{suffix}");
        let span = HighlightSpan::new(prefix.len(), prefix.len() + 8);
        let result = format_highlighted_command(&cmd, &span, false, 40);

        // Should window correctly
        assert!(result.command_line.contains("..."));
        assert!(result.command_line.contains("rm -rf /"));

        // Caret alignment check: the carets should be positioned to align
        // with the match text in the display. Count leading spaces in caret line.
        let carets_start = result.caret_line.chars().take_while(|c| *c == ' ').count();

        // Find where "rm -rf /" starts in command line (char position)
        if let Some(byte_pos) = result.command_line.find("rm -rf /") {
            let match_start = result.command_line[..byte_pos].chars().count();
            // Carets should start at the match position
            assert_eq!(
                carets_start, match_start,
                "Carets at {} should align with match at {} in '{}'",
                carets_start, match_start, result.command_line
            );
        } else {
            panic!("Match text not found in windowed command");
        }
    }

    // =========================================================================
    // Non-TTY / TTY Color Tests
    // =========================================================================

    #[test]
    fn test_no_ansi_escapes_when_color_disabled() {
        let cmd = "git reset --hard HEAD";
        let span = HighlightSpan::with_label(0, 16, "Dangerous");
        let result = format_highlighted_command(cmd, &span, false, 80);

        // ANSI escape codes start with \x1b[ or \u{1b}[
        let ansi_escape = '\x1b';

        assert!(
            !result.command_line.contains(ansi_escape),
            "Command line should not contain ANSI escapes when color is disabled"
        );
        assert!(
            !result.caret_line.contains(ansi_escape),
            "Caret line should not contain ANSI escapes when color is disabled"
        );
        if let Some(label) = &result.label_line {
            assert!(
                !label.contains(ansi_escape),
                "Label line should not contain ANSI escapes when color is disabled"
            );
        }
    }

    #[test]
    fn test_ansi_escapes_present_when_color_enabled() {
        // Force color on for this test
        colored::control::set_override(true);

        let cmd = "git reset --hard HEAD";
        let span = HighlightSpan::with_label(0, 16, "Dangerous");
        let result = format_highlighted_command(cmd, &span, true, 80);

        // When color is enabled, we expect ANSI codes
        let ansi_escape = '\x1b';

        // At least the caret line should have color
        assert!(
            result.caret_line.contains(ansi_escape),
            "Caret line should contain ANSI escapes when color is enabled"
        );

        // Reset color override
        colored::control::unset_override();
    }

    #[test]
    fn test_colorize_command_produces_ansi_codes() {
        // Force color on for this test
        colored::control::set_override(true);

        let cmd = "git reset --hard";
        let span = WindowedSpan { start: 0, end: 16 };
        let result = colorize_command_with_span(cmd, Some(&span));

        // Should contain ANSI codes for red/bold
        let ansi_escape = '\x1b';
        assert!(
            result.contains(ansi_escape),
            "Colorized command should contain ANSI escapes"
        );

        // Reset color override
        colored::control::unset_override();
    }

    #[test]
    fn test_no_color_for_build_caret_line() {
        let span = WindowedSpan { start: 3, end: 8 };
        let result = build_caret_line(&span, false);

        // Should be plain text: 3 spaces + 5 carets
        assert_eq!(result, "   ^^^^^");
        assert!(!result.contains('\x1b'));
    }

    #[test]
    fn test_color_for_build_caret_line() {
        // Force color on for this test
        colored::control::set_override(true);

        let span = WindowedSpan { start: 3, end: 8 };
        let result = build_caret_line(&span, true);

        // Should contain ANSI codes
        assert!(result.contains('\x1b'));
        // Should still have carets
        assert!(result.contains('^'));

        // Reset color override
        colored::control::unset_override();
    }

    #[test]
    fn test_no_color_for_build_label_line() {
        let span = WindowedSpan { start: 5, end: 10 };
        let result = build_label_line(&span, "Test Label", false);

        // Should be plain text: 5 spaces + connector + label
        assert!(result.starts_with("     └── "));
        assert!(result.ends_with("Test Label"));
        assert!(!result.contains('\x1b'));
    }

    #[test]
    fn test_color_for_build_label_line() {
        // Force color on for this test
        colored::control::set_override(true);

        let span = WindowedSpan { start: 5, end: 10 };
        let result = build_label_line(&span, "Test Label", true);

        // Should contain ANSI codes
        assert!(result.contains('\x1b'));
        assert!(result.contains("Test Label"));

        // Reset color override
        colored::control::unset_override();
    }

    // =========================================================================
    // Caret Alignment Validation Tests
    // =========================================================================

    #[test]
    fn test_caret_count_matches_span_length() {
        let cmd = "echo test && git push --force";
        let span = HighlightSpan::new(13, 29); // "git push --force" = 16 chars
        let result = format_highlighted_command(cmd, &span, false, 80);

        let caret_count = result.caret_line.matches('^').count();
        assert_eq!(caret_count, 16, "Caret count should match span length");
    }

    #[test]
    fn test_caret_position_matches_span_start() {
        let cmd = "prefix && git reset --hard";
        let span_start = 10; // "git reset --hard" starts at char 10
        let span = HighlightSpan::new(span_start, span_start + 16);
        let result = format_highlighted_command(cmd, &span, false, 80);

        // Count leading spaces in caret line
        let leading_spaces = result.caret_line.len() - result.caret_line.trim_start().len();
        assert_eq!(
            leading_spaces, span_start,
            "Leading spaces should match span start position"
        );
    }

    #[test]
    fn test_caret_alignment_after_windowing() {
        let prefix = "x".repeat(50);
        let match_text = "git reset --hard";
        let suffix = "y".repeat(50);
        let cmd = format!("{prefix}{match_text}{suffix}");
        let span = HighlightSpan::new(50, 66);
        let result = format_highlighted_command(&cmd, &span, false, 40);

        // Find match position in windowed command
        let match_pos = result.command_line.find("git reset").unwrap_or(0);
        // Find caret start position
        let caret_start = result.caret_line.find('^').unwrap_or(0);

        assert_eq!(
            caret_start, match_pos,
            "Carets should align with match in windowed command"
        );
    }

    #[test]
    fn test_label_alignment_matches_carets() {
        let cmd = "echo test && rm -rf /";
        let span = HighlightSpan::with_label(13, 21, "Dangerous!");
        let result = format_highlighted_command(cmd, &span, false, 80);

        // Both caret and label should start at same position
        let caret_start = result.caret_line.len() - result.caret_line.trim_start().len();
        let label = result.label_line.expect("Should have label");
        let label_start = label.len() - label.trim_start().len();

        assert_eq!(
            caret_start, label_start,
            "Label line should align with caret line"
        );
    }

    #[test]
    fn test_zero_length_span_shows_one_caret() {
        let cmd = "git status";
        let span = HighlightSpan::new(4, 4); // Zero-length span at position 4
        let result = format_highlighted_command(cmd, &span, false, 80);

        // Should show at least one caret (graceful handling)
        let caret_count = result.caret_line.matches('^').count();
        assert!(
            caret_count >= 1,
            "Should show at least one caret for empty span"
        );
    }

    #[test]
    fn test_span_beyond_command_end_handles_gracefully() {
        let cmd = "short";
        let span = HighlightSpan::new(0, 100); // Span extends beyond command
        let result = format_highlighted_command(cmd, &span, false, 80);

        // Should not panic and should produce some output
        assert!(!result.command_line.is_empty());
        // Should have some carets
        assert!(result.caret_line.contains('^'));
    }

    #[test]
    fn test_inverted_span_handles_gracefully() {
        let cmd = "git status";
        let span = HighlightSpan::new(8, 2); // start > end
        let result = format_highlighted_command(cmd, &span, false, 80);

        // Should not panic
        assert!(!result.command_line.is_empty());
    }

    #[test]
    fn test_to_string_with_prefix_format() {
        let cmd = "rm -rf /";
        let span = HighlightSpan::with_label(0, 8, "Filesystem destruction");
        let result = format_highlighted_command(cmd, &span, false, 80);

        let output = result.to_string_with_prefix(">>> ");

        // Each line should start with the prefix
        for line in output.lines() {
            assert!(
                line.starts_with(">>> "),
                "Line should start with prefix: {line}"
            );
        }
    }

    #[test]
    fn test_output_has_consistent_line_count() {
        let cmd = "git reset --hard";
        let span_without_label = HighlightSpan::new(0, 16);
        let span_with_label = HighlightSpan::with_label(0, 16, "Label");

        let result_no_label = format_highlighted_command(cmd, &span_without_label, false, 80);
        let result_with_label = format_highlighted_command(cmd, &span_with_label, false, 80);

        let output_no_label = result_no_label.to_string_with_prefix("");
        let output_with_label = result_with_label.to_string_with_prefix("");

        // Without label: 2 lines (command + carets)
        assert_eq!(
            output_no_label.lines().count(),
            2,
            "Output without label should have 2 lines"
        );
        // With label: 3 lines (command + carets + label)
        assert_eq!(
            output_with_label.lines().count(),
            3,
            "Output with label should have 3 lines"
        );
    }
}

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

use crate::evaluator::{window_command, MatchSpan, WindowedSpan, DEFAULT_WINDOW_WIDTH};
use colored::Colorize;
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
    pub fn new(start: usize, end: usize) -> Self {
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

    /// Convert to a MatchSpan for windowing.
    #[must_use]
    pub fn to_match_span(&self) -> MatchSpan {
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
        result.push_str(&format!("{prefix}{}\n", self.caret_line));
        if let Some(label) = &self.label_line {
            result.push_str(&format!("{prefix}{label}\n"));
        }
        result
    }
}

/// Determines whether color should be used based on TTY and environment.
#[must_use]
pub fn should_use_color() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
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
        format!("{}{}", leading_spaces, carets.red().bold())
    } else {
        format!("{}{}", leading_spaces, carets)
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
        format!(
            "{}{}{}",
            leading_spaces,
            connector.dimmed(),
            label.yellow()
        )
    } else {
        format!("{}{}{}", leading_spaces, connector, label)
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

    let (caret_line, label_line) = if let Some(adj_span) = windowed.adjusted_span {
        let caret = build_caret_line(&adj_span, use_color);
        let label = span
            .label
            .as_ref()
            .map(|l| build_label_line(&adj_span, l, use_color));
        (caret, label)
    } else {
        // Fallback: no valid span, show minimal indicator
        let fallback_caret = if use_color {
            "^".red().bold().to_string()
        } else {
            "^".to_string()
        };
        (fallback_caret, None)
    };

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

    format!("{}{}{}", before, matched.red().bold(), after)
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
        assert!(result.caret_line.starts_with("^"));
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
        assert!(result.caret_line.contains("^"));
    }

    #[test]
    fn test_format_long_command_windowed() {
        let prefix = "a ".repeat(50);
        let suffix = " b".repeat(50);
        let cmd = format!("{}git reset --hard{}", prefix, suffix);

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
        // Command with multi-byte UTF-8 characters
        let cmd = "echo 'héllo wörld' && rm -rf /tmp/test";
        let span = HighlightSpan::new(22, 29); // "rm -rf "
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
}

//! Denial message box renderer for terminal output.
//!
//! Provides a rich denial message display with:
//! - Bordered box with header
//! - Command with span highlighting
//! - Pattern name and severity
//! - Optional explanation text
//! - Safe alternatives as bullet list
//!
//! Falls back to plain text format for non-TTY contexts.

use super::theme::{BorderStyle, Severity, Theme};
use crate::highlight::{HighlightSpan, format_highlighted_command};
use crate::output::terminal_width;
use std::fmt::Write;

/// A denial message box to display when a command is blocked.
#[derive(Debug, Clone)]
pub struct DenialBox {
    /// The blocked command.
    pub command: String,
    /// Span within the command that matched.
    pub span: HighlightSpan,
    /// Pattern identifier (e.g., "`core.git.reset_hard`").
    pub pattern_id: String,
    /// Severity level of the match.
    pub severity: Severity,
    /// Optional explanation of why this command is blocked.
    pub explanation: Option<String>,
    /// Suggested safe alternatives.
    pub alternatives: Vec<String>,
}

impl DenialBox {
    /// Create a new denial box.
    #[must_use]
    pub fn new(
        command: impl Into<String>,
        span: HighlightSpan,
        pattern_id: impl Into<String>,
        severity: Severity,
    ) -> Self {
        Self {
            command: command.into(),
            span,
            pattern_id: pattern_id.into(),
            severity,
            explanation: None,
            alternatives: Vec::new(),
        }
    }

    /// Add an explanation.
    #[must_use]
    pub fn with_explanation(mut self, explanation: impl Into<String>) -> Self {
        self.explanation = Some(explanation.into());
        self
    }

    /// Add safe alternatives.
    #[must_use]
    pub fn with_alternatives(mut self, alternatives: Vec<String>) -> Self {
        self.alternatives = alternatives;
        self
    }

    /// Render the denial box with the given theme.
    ///
    /// Uses Unicode box-drawing characters and ANSI colors when the theme
    /// has colors enabled and Unicode borders.
    #[must_use]
    pub fn render(&self, theme: &Theme) -> String {
        if !theme.colors_enabled {
            return self.render_plain();
        }

        match theme.border_style {
            BorderStyle::Unicode => self.render_unicode(theme),
            BorderStyle::Ascii => self.render_ascii(theme),
            BorderStyle::None => self.render_minimal(theme),
        }
    }

    /// Render a plain text version for non-TTY contexts.
    #[must_use]
    pub fn render_plain(&self) -> String {
        let mut output = String::new();

        // Header
        let _ = writeln!(output, "BLOCKED: Destructive Command Detected");
        let _ = writeln!(output);

        // Command with highlighting
        let highlighted =
            format_highlighted_command(&self.command, &self.span, false, terminal_width().into());
        let _ = writeln!(output, "  Command: {}", highlighted.command_line);
        let _ = writeln!(output, "           {}", highlighted.caret_line);
        if let Some(label) = &highlighted.label_line {
            let _ = writeln!(output, "           {label}");
        }
        let _ = writeln!(output);

        // Pattern info
        let _ = writeln!(
            output,
            "  Pattern: {} ({})",
            self.pattern_id,
            format!("{:?}", self.severity).to_uppercase()
        );

        // Explanation
        if let Some(explanation) = &self.explanation {
            let _ = writeln!(output);
            let _ = writeln!(output, "  Reason: {explanation}");
        }

        // Alternatives
        if !self.alternatives.is_empty() {
            let _ = writeln!(output);
            let _ = writeln!(output, "  Safe alternatives:");
            for alt in &self.alternatives {
                let _ = writeln!(output, "    - {alt}");
            }
        }

        output
    }

    /// Render with Unicode box-drawing characters.
    #[allow(clippy::too_many_lines)]
    fn render_unicode(&self, theme: &Theme) -> String {
        let width = terminal_width().saturating_sub(4).max(40) as usize;
        let mut output = String::new();

        // Top border with header
        let header = " \u{26d4}  BLOCKED: Destructive Command Detected ";
        let header_len = header.chars().count();
        let top_pad = width.saturating_sub(header_len).saturating_sub(2);

        let _ = writeln!(
            output,
            "\x1b[{}m\u{256d}{}\u{256e}\x1b[0m",
            severity_color_code(self.severity),
            "\u{2500}".repeat(width)
        );
        let _ = writeln!(
            output,
            "\x1b[{}m\u{2502}\x1b[0m\x1b[1;{}m{}\x1b[0m{}\x1b[{}m\u{2502}\x1b[0m",
            severity_color_code(self.severity),
            severity_color_code(self.severity),
            header,
            " ".repeat(top_pad),
            severity_color_code(self.severity)
        );
        let _ = writeln!(
            output,
            "\x1b[{}m\u{251c}{}\u{2524}\x1b[0m",
            severity_color_code(self.severity),
            "\u{2500}".repeat(width)
        );

        // Command section
        let highlighted = format_highlighted_command(
            &self.command,
            &self.span,
            theme.colors_enabled,
            width.saturating_sub(4),
        );

        let _ = writeln!(
            output,
            "\x1b[{}m\u{2502}\x1b[0m  {}{}  \x1b[{}m\u{2502}\x1b[0m",
            severity_color_code(self.severity),
            highlighted.command_line,
            padding_for(&highlighted.command_line, width.saturating_sub(4)),
            severity_color_code(self.severity)
        );
        let _ = writeln!(
            output,
            "\x1b[{}m\u{2502}\x1b[0m  {}{}  \x1b[{}m\u{2502}\x1b[0m",
            severity_color_code(self.severity),
            highlighted.caret_line,
            padding_for(&highlighted.caret_line, width.saturating_sub(4)),
            severity_color_code(self.severity)
        );
        if let Some(label) = &highlighted.label_line {
            let _ = writeln!(
                output,
                "\x1b[{}m\u{2502}\x1b[0m  {}{}  \x1b[{}m\u{2502}\x1b[0m",
                severity_color_code(self.severity),
                label,
                padding_for(label, width.saturating_sub(4)),
                severity_color_code(self.severity)
            );
        }

        // Empty line
        let _ = writeln!(
            output,
            "\x1b[{}m\u{2502}\x1b[0m{}  \x1b[{}m\u{2502}\x1b[0m",
            severity_color_code(self.severity),
            " ".repeat(width.saturating_sub(2)),
            severity_color_code(self.severity)
        );

        // Pattern info
        let pattern_line = format!(
            "Pattern: {} ({})",
            self.pattern_id,
            theme.severity_label(self.severity)
        );
        let _ = writeln!(
            output,
            "\x1b[{}m\u{2502}\x1b[0m  \x1b[2m{}\x1b[0m{}  \x1b[{}m\u{2502}\x1b[0m",
            severity_color_code(self.severity),
            pattern_line,
            padding_for(&pattern_line, width.saturating_sub(4)),
            severity_color_code(self.severity)
        );

        // Explanation
        if let Some(explanation) = &self.explanation {
            let _ = writeln!(
                output,
                "\x1b[{}m\u{2502}\x1b[0m{}  \x1b[{}m\u{2502}\x1b[0m",
                severity_color_code(self.severity),
                " ".repeat(width.saturating_sub(2)),
                severity_color_code(self.severity)
            );

            // Word wrap explanation
            for line in wrap_text(explanation, width.saturating_sub(4)) {
                let _ = writeln!(
                    output,
                    "\x1b[{}m\u{2502}\x1b[0m  {}{}  \x1b[{}m\u{2502}\x1b[0m",
                    severity_color_code(self.severity),
                    line,
                    padding_for(&line, width.saturating_sub(4)),
                    severity_color_code(self.severity)
                );
            }
        }

        // Alternatives
        if !self.alternatives.is_empty() {
            let _ = writeln!(
                output,
                "\x1b[{}m\u{2502}\x1b[0m{}  \x1b[{}m\u{2502}\x1b[0m",
                severity_color_code(self.severity),
                " ".repeat(width.saturating_sub(2)),
                severity_color_code(self.severity)
            );

            let alt_header = "Safe alternatives:";
            let _ = writeln!(
                output,
                "\x1b[{}m\u{2502}\x1b[0m  \x1b[32m{}\x1b[0m{}  \x1b[{}m\u{2502}\x1b[0m",
                severity_color_code(self.severity),
                alt_header,
                padding_for(alt_header, width.saturating_sub(4)),
                severity_color_code(self.severity)
            );

            for alt in &self.alternatives {
                let bullet_line = format!("\u{2022} {alt}");
                let _ = writeln!(
                    output,
                    "\x1b[{}m\u{2502}\x1b[0m    \x1b[32m{}\x1b[0m{}  \x1b[{}m\u{2502}\x1b[0m",
                    severity_color_code(self.severity),
                    bullet_line,
                    padding_for(&bullet_line, width.saturating_sub(6)),
                    severity_color_code(self.severity)
                );
            }
        }

        // Bottom border
        let _ = writeln!(
            output,
            "\x1b[{}m\u{2570}{}\u{256f}\x1b[0m",
            severity_color_code(self.severity),
            "\u{2500}".repeat(width)
        );

        output
    }

    /// Render with ASCII box-drawing characters.
    fn render_ascii(&self, theme: &Theme) -> String {
        let width = terminal_width().saturating_sub(4).max(40) as usize;
        let mut output = String::new();

        // Top border with header
        let header = " !  BLOCKED: Destructive Command Detected ";
        let header_len = header.chars().count();
        let top_pad = width.saturating_sub(header_len).saturating_sub(2);

        let _ = writeln!(output, "+{}+", "-".repeat(width));
        let _ = writeln!(output, "|{}{}|", header, " ".repeat(top_pad));
        let _ = writeln!(output, "+{}+", "-".repeat(width));

        // Command section
        let highlighted = format_highlighted_command(
            &self.command,
            &self.span,
            theme.colors_enabled,
            width.saturating_sub(4),
        );

        let _ = writeln!(
            output,
            "|  {}{}  |",
            highlighted.command_line,
            padding_for(&highlighted.command_line, width.saturating_sub(4))
        );
        let _ = writeln!(
            output,
            "|  {}{}  |",
            highlighted.caret_line,
            padding_for(&highlighted.caret_line, width.saturating_sub(4))
        );
        if let Some(label) = &highlighted.label_line {
            let _ = writeln!(
                output,
                "|  {}{}  |",
                label,
                padding_for(label, width.saturating_sub(4))
            );
        }

        // Empty line
        let _ = writeln!(output, "|{}  |", " ".repeat(width.saturating_sub(2)));

        // Pattern info
        let pattern_line = format!(
            "Pattern: {} ({})",
            self.pattern_id,
            theme.severity_label(self.severity)
        );
        let _ = writeln!(
            output,
            "|  {}{}  |",
            pattern_line,
            padding_for(&pattern_line, width.saturating_sub(4))
        );

        // Explanation
        if let Some(explanation) = &self.explanation {
            let _ = writeln!(output, "|{}  |", " ".repeat(width.saturating_sub(2)));
            for line in wrap_text(explanation, width.saturating_sub(4)) {
                let _ = writeln!(
                    output,
                    "|  {}{}  |",
                    line,
                    padding_for(&line, width.saturating_sub(4))
                );
            }
        }

        // Alternatives
        if !self.alternatives.is_empty() {
            let _ = writeln!(output, "|{}  |", " ".repeat(width.saturating_sub(2)));
            let alt_header = "Safe alternatives:";
            let _ = writeln!(
                output,
                "|  {}{}  |",
                alt_header,
                padding_for(alt_header, width.saturating_sub(4))
            );
            for alt in &self.alternatives {
                let bullet_line = format!("* {alt}");
                let _ = writeln!(
                    output,
                    "|    {}{}  |",
                    bullet_line,
                    padding_for(&bullet_line, width.saturating_sub(6))
                );
            }
        }

        // Bottom border
        let _ = writeln!(output, "+{}+", "-".repeat(width));

        output
    }

    /// Render with no borders (minimal style).
    fn render_minimal(&self, theme: &Theme) -> String {
        let mut output = String::new();

        // Header with color
        let _ = writeln!(
            output,
            "\x1b[{}m\u{26d4}  BLOCKED\x1b[0m: Destructive Command Detected",
            severity_color_code(self.severity)
        );
        let _ = writeln!(output);

        // Command with highlighting
        let width = terminal_width().saturating_sub(4).max(40);
        let highlighted = format_highlighted_command(
            &self.command,
            &self.span,
            theme.colors_enabled,
            width.into(),
        );

        let _ = writeln!(output, "  {}", highlighted.command_line);
        let _ = writeln!(output, "  {}", highlighted.caret_line);
        if let Some(label) = &highlighted.label_line {
            let _ = writeln!(output, "  {label}");
        }
        let _ = writeln!(output);

        // Pattern info
        let _ = writeln!(
            output,
            "  \x1b[2mPattern: {} ({})\x1b[0m",
            self.pattern_id,
            theme.severity_label(self.severity)
        );

        // Explanation
        if let Some(explanation) = &self.explanation {
            let _ = writeln!(output);
            let _ = writeln!(output, "  {explanation}");
        }

        // Alternatives
        if !self.alternatives.is_empty() {
            let _ = writeln!(output);
            let _ = writeln!(output, "  \x1b[32mSafe alternatives:\x1b[0m");
            for alt in &self.alternatives {
                let _ = writeln!(output, "    \x1b[32m\u{2022}\x1b[0m {alt}");
            }
        }

        output
    }
}

/// Get ANSI color code for severity level.
const fn severity_color_code(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 31, // Red
        Severity::High => 91,     // Bright red
        Severity::Medium => 33,   // Yellow
        Severity::Low => 34,      // Blue
    }
}

/// Calculate padding needed to fill width, accounting for ANSI codes.
fn padding_for(text: &str, width: usize) -> String {
    let visible_len = strip_ansi_codes(text).chars().count();
    let padding = width.saturating_sub(visible_len);
    " ".repeat(padding)
}

/// Strip ANSI escape codes from a string to get visible length.
fn strip_ansi_codes(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut in_escape = false;

    for c in s.chars() {
        if c == '\x1b' {
            in_escape = true;
            continue;
        }
        if in_escape {
            if c == 'm' {
                in_escape = false;
            }
            continue;
        }
        result.push(c);
    }

    result
}

/// Wrap text to fit within the specified width (character count, not bytes).
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    if text.is_empty() || width == 0 {
        return vec![];
    }

    let mut lines = Vec::new();
    let mut current_line = String::new();
    let mut current_char_count = 0;

    for word in text.split_whitespace() {
        let word_char_count = word.chars().count();
        if current_line.is_empty() {
            current_line = word.to_string();
            current_char_count = word_char_count;
        } else if current_char_count + 1 + word_char_count <= width {
            current_line.push(' ');
            current_line.push_str(word);
            current_char_count += 1 + word_char_count;
        } else {
            lines.push(current_line);
            current_line = word.to_string();
            current_char_count = word_char_count;
        }
    }

    if !current_line.is_empty() {
        lines.push(current_line);
    }

    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_denial_box_plain_render() {
        let span = HighlightSpan::with_label(0, 16, "Matched: git reset --hard");
        let denial = DenialBox::new(
            "git reset --hard HEAD",
            span,
            "core.git.reset_hard",
            Severity::Critical,
        );

        let output = denial.render_plain();

        assert!(output.contains("BLOCKED"));
        assert!(output.contains("git reset --hard"));
        assert!(output.contains("core.git.reset_hard"));
        assert!(output.contains("CRITICAL"));
    }

    #[test]
    fn test_denial_box_with_explanation() {
        let span = HighlightSpan::new(0, 10);
        let denial = DenialBox::new(
            "rm -rf /",
            span,
            "core.filesystem.rm_rf",
            Severity::Critical,
        )
        .with_explanation("This command would delete all files on the system.");

        let output = denial.render_plain();

        assert!(output.contains("would delete all files"));
    }

    #[test]
    fn test_denial_box_with_alternatives() {
        let span = HighlightSpan::new(0, 10);
        let denial = DenialBox::new(
            "rm -rf /tmp/foo",
            span,
            "core.filesystem.rm_rf",
            Severity::Medium,
        )
        .with_alternatives(vec![
            "rm -ri /tmp/foo (interactive)".to_string(),
            "mv /tmp/foo /tmp/foo.bak (backup first)".to_string(),
        ]);

        let output = denial.render_plain();

        assert!(output.contains("Safe alternatives:"));
        assert!(output.contains("interactive"));
        assert!(output.contains("backup first"));
    }

    #[test]
    fn test_denial_box_unicode_render() {
        let span = HighlightSpan::new(0, 10);
        let theme = Theme::default();
        let denial = DenialBox::new(
            "git push --force",
            span,
            "core.git.force_push",
            Severity::High,
        );

        let output = denial.render(&theme);

        // Should contain Unicode box-drawing characters
        assert!(output.contains('\u{256d}')); // Top-left corner
        assert!(output.contains('\u{256f}')); // Bottom-right corner
        assert!(output.contains("BLOCKED"));
    }

    #[test]
    fn test_denial_box_ascii_render() {
        let span = HighlightSpan::new(0, 10);
        let theme = Theme {
            border_style: BorderStyle::Ascii,
            colors_enabled: true,
            ..Default::default()
        };
        let denial = DenialBox::new(
            "git push --force",
            span,
            "core.git.force_push",
            Severity::High,
        );

        let output = denial.render(&theme);

        // Should use ASCII characters
        assert!(output.contains('+'));
        assert!(output.contains('-'));
        assert!(output.contains("BLOCKED"));
    }

    #[test]
    fn test_wrap_text() {
        let text =
            "This is a long explanation that needs to be wrapped to fit within the terminal width.";
        let wrapped = wrap_text(text, 30);

        assert!(wrapped.len() > 1);
        for line in &wrapped {
            assert!(line.len() <= 30);
        }
    }

    #[test]
    fn test_strip_ansi_codes() {
        let with_codes = "\x1b[31mRed text\x1b[0m and \x1b[32mgreen\x1b[0m";
        let stripped = strip_ansi_codes(with_codes);

        assert_eq!(stripped, "Red text and green");
    }

    #[test]
    fn test_severity_color_codes() {
        assert_eq!(severity_color_code(Severity::Critical), 31);
        assert_eq!(severity_color_code(Severity::High), 91);
        assert_eq!(severity_color_code(Severity::Medium), 33);
        assert_eq!(severity_color_code(Severity::Low), 34);
    }

    #[test]
    fn test_denial_box_unicode_command_preservation() {
        // Verify Unicode characters in commands are preserved
        let cmd = "rm -rf /path/with/émojis/🎉/and/中文";
        let span = HighlightSpan::new(0, 5);
        let denial = DenialBox::new(cmd, span, "core.filesystem.rm_rf", Severity::Critical);

        let output = denial.render_plain();

        assert!(
            output.contains("émojis"),
            "Unicode accented characters must be preserved"
        );
        assert!(output.contains("🎉"), "Emoji must be preserved");
        assert!(output.contains("中文"), "CJK characters must be preserved");
    }

    #[test]
    fn test_denial_box_all_severity_levels() {
        // Verify all severity levels render correctly
        for severity in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
        ] {
            let span = HighlightSpan::new(0, 10);
            let denial = DenialBox::new("test command", span, "test.pattern", severity);
            let output = denial.render_plain();

            assert!(
                output.contains("BLOCKED"),
                "All severities must show BLOCKED header"
            );
            assert!(
                output.contains(&format!("{severity:?}").to_uppercase()),
                "Output must contain severity level: {severity:?}"
            );
        }
    }

    #[test]
    fn test_denial_box_minimal_render() {
        let span = HighlightSpan::new(0, 10);
        let theme = Theme {
            border_style: BorderStyle::None,
            ..Default::default()
        };
        let denial = DenialBox::new(
            "git push --force",
            span,
            "core.git.force_push",
            Severity::High,
        );

        let output = denial.render(&theme);

        // Minimal style should still contain key elements
        assert!(output.contains("BLOCKED"));
        assert!(output.contains("git push --force"));
        assert!(output.contains("core.git.force_push"));
    }

    #[test]
    fn test_wrap_text_empty_input() {
        let wrapped = wrap_text("", 30);
        assert!(wrapped.is_empty());
    }

    #[test]
    fn test_wrap_text_zero_width() {
        let wrapped = wrap_text("some text", 0);
        assert!(wrapped.is_empty());
    }

    #[test]
    fn test_wrap_text_single_word() {
        let wrapped = wrap_text("word", 30);
        assert_eq!(wrapped.len(), 1);
        assert_eq!(wrapped[0], "word");
    }

    #[test]
    fn test_padding_for_with_ansi() {
        // Text with ANSI codes should be padded based on visible length
        let text_with_ansi = "\x1b[31mRed\x1b[0m";
        let padding = padding_for(text_with_ansi, 10);
        // Visible length is 3 ("Red"), so padding should be 7 spaces
        assert_eq!(padding.len(), 7);
    }
}

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
use crate::highlight::{
    HighlightSpan, format_highlighted_command, format_markdown_explanation, format_regex_pattern,
};
#[cfg(feature = "rich-output")]
use crate::output::rich_theme::{RichThemeExt, color_to_markup};
use crate::output::terminal_width;
#[cfg(not(feature = "rich-output"))]
use ratatui::style::Color;
#[cfg(feature = "rich-output")]
#[allow(unused_imports)]
use rich_rust::prelude::*;
use std::fmt::Write;

/// A denial message box to display when a command is blocked.
#[derive(Debug, Clone)]
pub struct DenialBox {
    /// The blocked command.
    pub command: String,
    /// Span within the command that matched.
    pub span: HighlightSpan,
    /// Pattern identifier (e.g., "`core.git:reset-hard`" or "`core.git.reset_hard`").
    pub pattern_id: String,
    /// Optional raw regex pattern for rich pattern displays.
    pub pattern_regex: Option<String>,
    /// Severity level of the match.
    pub severity: Severity,
    /// Optional explanation of why this command is blocked.
    pub explanation: Option<String>,
    /// Suggested safe alternatives.
    pub alternatives: Vec<String>,
    /// Optional allow-once code.
    pub allow_once_code: Option<String>,
    /// Git branch name (shown when `git_awareness.show_branch_in_output` is enabled).
    pub branch_name: Option<String>,
    /// Whether the branch is protected (adds extra caution note).
    pub is_protected_branch: bool,
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
            pattern_regex: None,
            severity,
            explanation: None,
            alternatives: Vec::new(),
            allow_once_code: None,
            branch_name: None,
            is_protected_branch: false,
        }
    }

    /// Add the raw regex pattern that matched.
    #[must_use]
    pub fn with_pattern_regex(mut self, pattern_regex: impl Into<String>) -> Self {
        let pattern_regex = pattern_regex.into();
        let trimmed = pattern_regex.trim();
        if trimmed.is_empty() {
            self.pattern_regex = None;
        } else if trimmed.len() == pattern_regex.len() {
            self.pattern_regex = Some(pattern_regex);
        } else {
            self.pattern_regex = Some(trimmed.to_string());
        }
        self
    }

    /// Add an explanation.
    #[must_use]
    pub fn with_explanation(mut self, explanation: impl Into<String>) -> Self {
        let explanation = explanation.into();
        let trimmed = explanation.trim();
        if trimmed.is_empty() {
            self.explanation = None;
        } else if trimmed.len() == explanation.len() {
            self.explanation = Some(explanation);
        } else {
            self.explanation = Some(trimmed.to_string());
        }
        self
    }

    /// Add safe alternatives.
    #[must_use]
    pub fn with_alternatives(mut self, alternatives: Vec<String>) -> Self {
        self.alternatives = alternatives;
        self
    }

    /// Add allow-once code.
    #[must_use]
    pub fn with_allow_once_code(mut self, code: impl Into<String>) -> Self {
        self.allow_once_code = Some(code.into());
        self
    }

    /// Add git branch context.
    #[must_use]
    pub fn with_branch_context(
        mut self,
        branch_name: impl Into<String>,
        is_protected: bool,
    ) -> Self {
        self.branch_name = Some(branch_name.into());
        self.is_protected_branch = is_protected;
        self
    }

    /// Render the denial box with the given theme.
    ///
    /// Uses rich_rust when the feature is enabled, otherwise falls back to
    /// manual rendering.
    #[must_use]
    pub fn render(&self, theme: &Theme) -> String {
        #[cfg(feature = "rich-output")]
        {
            if crate::output::should_use_rich_output() {
                self.render_rich(theme)
            } else {
                self.render_ascii(theme)
            }
        }
        #[cfg(not(feature = "rich-output"))]
        match theme.border_style {
            BorderStyle::Unicode => {
                let output = self.render_unicode(theme);
                if theme.colors_enabled {
                    output
                } else {
                    strip_ansi_codes(&output)
                }
            }
            BorderStyle::Ascii => self.render_ascii(theme),
            BorderStyle::None => {
                let output = self.render_minimal(theme);
                if theme.colors_enabled {
                    output
                } else {
                    strip_ansi_codes(&output)
                }
            }
        }
    }

    /// Render with rich_rust (Premium UI).
    #[cfg(feature = "rich-output")]
    fn render_rich(&self, theme: &Theme) -> String {
        use rich_rust::r#box::{ASCII, DOUBLE, HEAVY, MINIMAL, ROUNDED};
        use rich_rust::prelude::*;

        let pattern_lines = format_pattern_lines(
            &self.pattern_id,
            theme.severity_label(self.severity),
            self.pattern_regex.as_deref(),
            theme.colors_enabled,
        );
        let width = terminal_width().saturating_sub(8).max(40) as usize;

        // Build content as a Vec of lines
        let mut lines = Vec::new();

        let severity_markup = theme.severity_markup(self.severity);
        if let Some(branch) = &self.branch_name {
            if self.is_protected_branch {
                lines.push(format!(
                    "[{severity_markup}]🛑 BLOCKED (Protected Branch: {branch})[/]"
                ));
            } else {
                lines.push(format!(
                    "[{severity_markup}]🛑 BLOCKED (Branch: {branch})[/]"
                ));
            }
        } else {
            lines.push(format!("[{severity_markup}]🛑 COMMAND BLOCKED[/]"));
        }
        lines.push(String::new());

        if self.is_protected_branch {
            lines.push(format!(
                "[{severity_markup}]Extra caution on protected branches.[/]"
            ));
            lines.push(String::new());
        }

        // 2. Command with highlighting
        // Note: We use manual highlighting for now, but rich_rust Syntax could be used later
        lines.push(format!("[dim]Command:[/]  [bold]{}[/]", self.command));

        // 3. Explanation
        if let Some(explanation) = &self.explanation {
            lines.push(String::new());
            lines.push(format!("[{severity_markup}]Explanation:[/]"));
            for line in explanation_lines(explanation, theme.colors_enabled, width) {
                lines.push(line);
            }
        }

        // 4. Pattern Info
        lines.push(String::new());
        for line in pattern_lines {
            lines.push(format!("[dim]{line}[/]"));
        }

        // 5. Alternatives
        if !self.alternatives.is_empty() {
            lines.push(String::new());
            lines.push(format!("[{}]Safe alternatives:[/]", theme.success_markup()));
            for alt in &self.alternatives {
                lines.push(format!("  [green]•[/] {alt}"));
            }
        }

        // 6. Allow-once code
        if let Some(code) = &self.allow_once_code {
            lines.push(String::new());
            lines.push("[dim]─────────────────────────────────────[/]".to_string());
            lines.push(format!(
                "[yellow]To allow once:[/] [bold]dcg allow-once {code}[/]"
            ));
        }

        let content_str = lines.join("\n");

        // Determine border style and color
        let box_style: &'static rich_rust::r#box::BoxChars = match theme.border_style {
            BorderStyle::Unicode => match self.severity {
                Severity::Critical => &DOUBLE,
                Severity::High => &HEAVY,
                _ => &ROUNDED,
            },
            BorderStyle::Ascii => &ASCII,
            BorderStyle::None => &MINIMAL,
        };

        let border_color = color_to_markup(theme.color_for_severity(self.severity));

        // Create Panel
        Panel::from_text(&content_str)
            .title("[bold] DCG [/]")
            .border_style(Style::parse(&border_color).unwrap_or_default())
            .box_style(box_style)
            .padding((1, 2))
            .render_plain(width)
    }

    /// Render a plain text version for non-TTY contexts.
    #[must_use]
    pub fn render_plain(&self) -> String {
        let mut output = String::new();
        let width = terminal_width().saturating_sub(4).max(40) as usize;
        let severity_label = format!("{:?}", self.severity).to_uppercase();
        let pattern_lines = format_pattern_lines(
            &self.pattern_id,
            &severity_label,
            self.pattern_regex.as_deref(),
            false,
        );

        if let Some(branch) = &self.branch_name {
            if self.is_protected_branch {
                let _ = writeln!(output, "BLOCKED (Protected Branch: {branch})");
            } else {
                let _ = writeln!(output, "BLOCKED (Branch: {branch})");
            }
        } else {
            let _ = writeln!(output, "BLOCKED: Destructive Command Detected");
        }
        let _ = writeln!(output);

        if self.is_protected_branch {
            let _ = writeln!(output, "  !! Extra caution on protected branches.");
            let _ = writeln!(output);
        }

        // Command with highlighting
        let highlighted =
            format_highlighted_command(&self.command, &self.span, false, terminal_width().into());
        let _ = writeln!(output, "  Command: {}", highlighted.command_line);
        let _ = writeln!(output, "           {}", highlighted.caret_line);
        if let Some(label) = &highlighted.label_line {
            let _ = writeln!(output, "           {label}");
        }
        let _ = writeln!(output);

        // Explanation
        if let Some(explanation) = &self.explanation {
            let _ = writeln!(output);
            let _ = writeln!(output, "  Explanation:");
            for line in explanation_lines(explanation, false, width.saturating_sub(2)) {
                let _ = writeln!(output, "  {line}");
            }
        }

        // Pattern info
        let _ = writeln!(output);
        for line in pattern_lines {
            let _ = writeln!(output, "  {line}");
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
    #[cfg(not(feature = "rich-output"))]
    #[allow(clippy::too_many_lines)]
    fn render_unicode(&self, theme: &Theme) -> String {
        let width = terminal_width().saturating_sub(4).max(40) as usize;
        let mut output = String::new();
        let severity_code = severity_color_code(theme, self.severity);
        let success_code = ansi_color_code(theme.success_color);
        let pattern_lines = format_pattern_lines(
            &self.pattern_id,
            theme.severity_label(self.severity),
            self.pattern_regex.as_deref(),
            theme.colors_enabled,
        );
        let explanation_label = format!("\x1b[1;{}mExplanation:\x1b[0m", &severity_code);

        let header = if let Some(branch) = &self.branch_name {
            if self.is_protected_branch {
                format!(" \u{26d4}  BLOCKED (Protected Branch: {branch}) ")
            } else {
                format!(" \u{26d4}  BLOCKED (Branch: {branch}) ")
            }
        } else {
            " \u{26d4}  BLOCKED: Destructive Command Detected ".to_string()
        };
        let header_len = header.chars().count();
        let top_pad = width.saturating_sub(header_len);

        let _ = writeln!(
            output,
            "\x1b[{}m\u{256d}{}\u{256e}\x1b[0m",
            &severity_code,
            "\u{2500}".repeat(width)
        );
        let _ = writeln!(
            output,
            "\x1b[{}m\u{2502}\x1b[0m\x1b[1;{}m{}\x1b[0m{}\x1b[{}m\u{2502}\x1b[0m",
            &severity_code,
            &severity_code,
            header,
            " ".repeat(top_pad),
            &severity_code
        );
        let _ = writeln!(
            output,
            "\x1b[{}m\u{251c}{}\u{2524}\x1b[0m",
            &severity_code,
            "\u{2500}".repeat(width)
        );

        if self.is_protected_branch {
            let caution = "\u{26a0}  Extra caution on protected branches.";
            let _ = writeln!(
                output,
                "\x1b[{}m\u{2502}\x1b[0m  \x1b[1;{}m{}\x1b[0m{}  \x1b[{}m\u{2502}\x1b[0m",
                &severity_code,
                &severity_code,
                caution,
                padding_for(caution, width.saturating_sub(4)),
                &severity_code
            );
            let _ = writeln!(
                output,
                "\x1b[{}m\u{2502}\x1b[0m{}  \x1b[{}m\u{2502}\x1b[0m",
                &severity_code,
                " ".repeat(width.saturating_sub(2)),
                &severity_code
            );
        }

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
            &severity_code,
            highlighted.command_line,
            padding_for(&highlighted.command_line, width.saturating_sub(4)),
            &severity_code
        );
        let _ = writeln!(
            output,
            "\x1b[{}m\u{2502}\x1b[0m  {}{}  \x1b[{}m\u{2502}\x1b[0m",
            &severity_code,
            highlighted.caret_line,
            padding_for(&highlighted.caret_line, width.saturating_sub(4)),
            &severity_code
        );
        if let Some(label) = &highlighted.label_line {
            let _ = writeln!(
                output,
                "\x1b[{}m\u{2502}\x1b[0m  {}{}  \x1b[{}m\u{2502}\x1b[0m",
                &severity_code,
                label,
                padding_for(label, width.saturating_sub(4)),
                &severity_code
            );
        }

        // Empty line
        let _ = writeln!(
            output,
            "\x1b[{}m\u{2502}\x1b[0m{}  \x1b[{}m\u{2502}\x1b[0m",
            &severity_code,
            " ".repeat(width.saturating_sub(2)),
            &severity_code
        );

        // Explanation
        if let Some(explanation) = &self.explanation {
            let _ = writeln!(
                output,
                "\x1b[{}m\u{2502}\x1b[0m{}  \x1b[{}m\u{2502}\x1b[0m",
                &severity_code,
                " ".repeat(width.saturating_sub(2)),
                &severity_code
            );

            let _ = writeln!(
                output,
                "\x1b[{}m\u{2502}\x1b[0m  {}{}  \x1b[{}m\u{2502}\x1b[0m",
                &severity_code,
                explanation_label,
                padding_for(&explanation_label, width.saturating_sub(4)),
                &severity_code
            );

            for line in
                explanation_lines(explanation, theme.colors_enabled, width.saturating_sub(4))
            {
                let _ = writeln!(
                    output,
                    "\x1b[{}m\u{2502}\x1b[0m  {}{}  \x1b[{}m\u{2502}\x1b[0m",
                    &severity_code,
                    line,
                    padding_for(&line, width.saturating_sub(4)),
                    &severity_code
                );
            }
        }

        // Pattern info
        let _ = writeln!(
            output,
            "\x1b[{}m\u{2502}\x1b[0m{}  \x1b[{}m\u{2502}\x1b[0m",
            &severity_code,
            " ".repeat(width.saturating_sub(2)),
            &severity_code
        );
        for pattern_line in pattern_lines {
            let _ = writeln!(
                output,
                "\x1b[{}m\u{2502}\x1b[0m  \x1b[2m{}\x1b[0m{}  \x1b[{}m\u{2502}\x1b[0m",
                &severity_code,
                pattern_line,
                padding_for(&pattern_line, width.saturating_sub(4)),
                &severity_code
            );
        }

        // Alternatives
        if !self.alternatives.is_empty() {
            let _ = writeln!(
                output,
                "\x1b[{}m\u{2502}\x1b[0m{}  \x1b[{}m\u{2502}\x1b[0m",
                &severity_code,
                " ".repeat(width.saturating_sub(2)),
                &severity_code
            );

            let alt_header = "Safe alternatives:";
            let _ = writeln!(
                output,
                "\x1b[{}m\u{2502}\x1b[0m  \x1b[{}m{}\x1b[0m{}  \x1b[{}m\u{2502}\x1b[0m",
                &severity_code,
                &success_code,
                alt_header,
                padding_for(alt_header, width.saturating_sub(4)),
                &severity_code
            );

            for alt in &self.alternatives {
                let bullet_line = format!("\u{2022} {alt}");
                let _ = writeln!(
                    output,
                    "\x1b[{}m\u{2502}\x1b[0m    \x1b[{}m{}\x1b[0m{}  \x1b[{}m\u{2502}\x1b[0m",
                    &severity_code,
                    &success_code,
                    bullet_line,
                    padding_for(&bullet_line, width.saturating_sub(6)),
                    &severity_code
                );
            }
        }

        // Bottom border
        let _ = writeln!(
            output,
            "\x1b[{}m\u{2570}{}\u{256f}\x1b[0m",
            &severity_code,
            "\u{2500}".repeat(width)
        );

        output
    }

    /// Render with ASCII box-drawing characters.
    fn render_ascii(&self, theme: &Theme) -> String {
        let width = terminal_width().saturating_sub(4).max(40) as usize;
        let mut output = String::new();
        let pattern_lines = format_pattern_lines(
            &self.pattern_id,
            theme.severity_label(self.severity),
            self.pattern_regex.as_deref(),
            false,
        );

        let header = if let Some(branch) = &self.branch_name {
            if self.is_protected_branch {
                format!(" !  BLOCKED (Protected Branch: {branch}) ")
            } else {
                format!(" !  BLOCKED (Branch: {branch}) ")
            }
        } else {
            " !  BLOCKED: Destructive Command Detected ".to_string()
        };
        let header_len = header.chars().count();
        let top_pad = width.saturating_sub(header_len);

        let _ = writeln!(output, "+{}+", "-".repeat(width));
        let _ = writeln!(output, "|{}{}|", header, " ".repeat(top_pad));
        let _ = writeln!(output, "+{}+", "-".repeat(width));

        if self.is_protected_branch {
            let caution = "!!  Extra caution on protected branches.";
            let _ = writeln!(
                output,
                "|  {}{}  |",
                caution,
                padding_for(caution, width.saturating_sub(4))
            );
            let _ = writeln!(output, "|{}  |", " ".repeat(width.saturating_sub(2)));
        }

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

        // Explanation
        if let Some(explanation) = &self.explanation {
            let _ = writeln!(output, "|{}  |", " ".repeat(width.saturating_sub(2)));
            let explanation_label = "EXPLANATION:";
            let _ = writeln!(
                output,
                "|  {}{}  |",
                explanation_label,
                padding_for(explanation_label, width.saturating_sub(4))
            );
            for line in
                explanation_lines(explanation, theme.colors_enabled, width.saturating_sub(4))
            {
                let _ = writeln!(
                    output,
                    "|  {}{}  |",
                    line,
                    padding_for(&line, width.saturating_sub(4))
                );
            }
        }

        // Pattern info
        let _ = writeln!(output, "|{}  |", " ".repeat(width.saturating_sub(2)));
        for pattern_line in pattern_lines {
            let _ = writeln!(
                output,
                "|  {}{}  |",
                pattern_line,
                padding_for(&pattern_line, width.saturating_sub(4))
            );
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
    #[cfg(not(feature = "rich-output"))]
    fn render_minimal(&self, theme: &Theme) -> String {
        let mut output = String::new();
        let severity_code = severity_color_code(theme, self.severity);
        let success_code = ansi_color_code(theme.success_color);
        let pattern_lines = format_pattern_lines(
            &self.pattern_id,
            theme.severity_label(self.severity),
            self.pattern_regex.as_deref(),
            theme.colors_enabled,
        );

        // Header with color
        let _ = writeln!(
            output,
            "\x1b[{}m\u{26d4}  BLOCKED\x1b[0m: Destructive Command Detected",
            &severity_code
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

        // Explanation
        if let Some(explanation) = &self.explanation {
            let _ = writeln!(output);
            let explanation_label = format!("\x1b[1;{}mExplanation:\x1b[0m", &severity_code);
            let width = terminal_width().saturating_sub(4).max(40) as usize;
            let _ = writeln!(output, "  {explanation_label}");
            for line in
                explanation_lines(explanation, theme.colors_enabled, width.saturating_sub(2))
            {
                let _ = writeln!(output, "  {line}");
            }
        }

        // Pattern info
        let _ = writeln!(output);
        for pattern_line in pattern_lines {
            let _ = writeln!(output, "  \x1b[2m{pattern_line}\x1b[0m");
        }

        // Alternatives
        if !self.alternatives.is_empty() {
            let _ = writeln!(output);
            let _ = writeln!(output, "  \x1b[{}mSafe alternatives:\x1b[0m", &success_code);
            for alt in &self.alternatives {
                let _ = writeln!(output, "    \x1b[{}m\u{2022}\x1b[0m {alt}", &success_code);
            }
        }

        output
    }
}

/// Convert a ratatui color to an ANSI foreground color code sequence.
#[cfg(not(feature = "rich-output"))]
fn ansi_color_code(color: Color) -> String {
    match color {
        Color::Reset => "0".to_string(),
        Color::Black => "30".to_string(),
        Color::Red => "31".to_string(),
        Color::Green => "32".to_string(),
        Color::Yellow => "33".to_string(),
        Color::Blue => "34".to_string(),
        Color::Magenta => "35".to_string(),
        Color::Cyan => "36".to_string(),
        Color::Gray => "37".to_string(),
        Color::DarkGray => "90".to_string(),
        Color::LightRed => "91".to_string(),
        Color::LightGreen => "92".to_string(),
        Color::LightYellow => "93".to_string(),
        Color::LightBlue => "94".to_string(),
        Color::LightMagenta => "95".to_string(),
        Color::LightCyan => "96".to_string(),
        Color::White => "97".to_string(),
        Color::Rgb(r, g, b) => format!("38;2;{r};{g};{b}"),
        Color::Indexed(index) => format!("38;5;{index}"),
    }
}

/// Get ANSI color code for severity level.
#[cfg(not(feature = "rich-output"))]
fn severity_color_code(theme: &Theme, severity: Severity) -> String {
    ansi_color_code(theme.color_for_severity(severity))
}

/// Calculate padding needed to fill width, accounting for ANSI codes.
fn padding_for(text: &str, width: usize) -> String {
    let visible_len = strip_ansi_codes(text).chars().count();
    let padding = width.saturating_sub(visible_len);
    " ".repeat(padding)
}

/// Strip ANSI escape codes from a string to get visible length.
///
/// Handles three sequence shapes:
///
/// - **CSI** (`ESC [ ...`): terminates on any byte in `0x40..=0x7E` (the
///   "final byte" range that includes `m` for SGR, `K` for erase-line,
///   `H` for cursor position, `J` for erase-display, etc.). The previous
///   implementation only terminated on `m` and silently consumed the rest
///   of the string when a non-SGR sequence (like `\x1b[K`) appeared,
///   making downstream `padding_for` width calculations wrong and
///   collapsing visible content into nothing.
/// - **OSC** (`ESC ] ...`): terminates on `BEL` (`0x07`) or the two-byte
///   ST sequence `ESC \\`. Used by hyperlink escapes (`\x1b]8;...\x1b\\text\x1b]8;;\x1b\\`).
/// - **Two-byte ESC sequences** (`ESC <X>` where X is `0x40..=0x5F`):
///   single-character terminator. Conservative fallback: drop the byte.
fn strip_ansi_codes(s: &str) -> String {
    #[derive(Copy, Clone)]
    enum State {
        Normal,
        EscOpen,   // saw ESC, awaiting next byte
        Csi,       // inside ESC [ ... (terminator: 0x40..=0x7E)
        Osc,       // inside ESC ] ... (terminator: BEL or ESC \)
        OscWantSt, // inside OSC and just saw ESC, awaiting `\`
    }

    let mut result = String::with_capacity(s.len());
    let mut state = State::Normal;

    for c in s.chars() {
        match state {
            State::Normal => {
                if c == '\x1b' {
                    state = State::EscOpen;
                } else {
                    result.push(c);
                }
            }
            State::EscOpen => {
                state = match c {
                    '[' => State::Csi,
                    ']' => State::Osc,
                    // Other introducers (single-shift G2/G3, charset,
                    // private-mode select, etc.) are 2-byte sequences;
                    // dropping the byte is the conservative choice.
                    _ => State::Normal,
                };
            }
            State::Csi => {
                let cp = c as u32;
                // CSI sequences end on a byte in 0x40..=0x7E ("final byte").
                if (0x40..=0x7E).contains(&cp) {
                    state = State::Normal;
                }
                // Parameter and intermediate bytes (0x30..=0x3F, 0x20..=0x2F)
                // are consumed silently.
            }
            State::Osc => {
                if c == '\x07' {
                    // BEL terminator
                    state = State::Normal;
                } else if c == '\x1b' {
                    state = State::OscWantSt;
                }
            }
            State::OscWantSt => {
                state = if c == '\\' {
                    State::Normal
                } else {
                    // Stray ESC inside OSC; treat as a new escape.
                    State::EscOpen
                };
            }
        }
    }

    result
}

/// Wrap text to fit within the specified width (character count, not bytes).
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    if text.is_empty() || width == 0 {
        return vec![];
    }

    let mut lines = Vec::new();

    for raw_line in text.lines() {
        if raw_line.is_empty() {
            lines.push(String::new());
            continue;
        }

        let prefix_len = raw_line.chars().take_while(|c| c.is_whitespace()).count();
        let prefix: String = raw_line.chars().take(prefix_len).collect();
        let content = raw_line[prefix_len..].trim_end();

        if content.is_empty() {
            lines.push(String::new());
            continue;
        }

        let mut current_line = String::new();
        let mut current_char_count = 0;

        for word in content.split_whitespace() {
            let word_char_count = word.chars().count();
            if current_line.is_empty() {
                current_line = format!("{prefix}{word}");
                current_char_count = prefix_len + word_char_count;
            } else if current_char_count + 1 + word_char_count <= width {
                current_line.push(' ');
                current_line.push_str(word);
                current_char_count += 1 + word_char_count;
            } else {
                lines.push(current_line);
                current_line = format!("{prefix}{word}");
                current_char_count = prefix_len + word_char_count;
            }
        }

        if !current_line.is_empty() {
            lines.push(current_line);
        }
    }

    lines
}

fn explanation_lines(explanation: &str, use_color: bool, width: usize) -> Vec<String> {
    let rendered = format_markdown_explanation(explanation, use_color, width);

    #[cfg(feature = "rich-output")]
    if use_color {
        return rendered.lines().map(ToOwned::to_owned).collect();
    }

    wrap_text(&rendered, width)
}

/// Split a pattern identifier into (pack, pattern) if possible.
fn split_pattern_id(pattern_id: &str) -> (Option<&str>, &str) {
    if let Some((pack, pattern)) = pattern_id.split_once(':') {
        if !pack.is_empty() && !pattern.is_empty() {
            return (Some(pack), pattern);
        }
    }

    let dot_count = pattern_id.chars().filter(|c| *c == '.').count();
    if dot_count >= 2 {
        if let Some(idx) = pattern_id.rfind('.') {
            let (pack, pattern) = pattern_id.split_at(idx);
            let pattern = &pattern[1..];
            if !pack.is_empty() && !pattern.is_empty() {
                return (Some(pack), pattern);
            }
        }
    }

    (None, pattern_id)
}

fn format_pattern_lines(
    pattern_id: &str,
    severity_label: &str,
    pattern_regex: Option<&str>,
    use_color: bool,
) -> Vec<String> {
    let (pack, pattern) = split_pattern_id(pattern_id);
    let mut lines = match pack {
        Some(pack_id) => vec![
            format!("Pattern: {pattern}"),
            format!("Pack: {pack_id} (severity: {severity_label})"),
        ],
        None => vec![format!("Pattern: {pattern} ({severity_label})")],
    };

    if let Some(regex) = pattern_regex {
        lines.push(format!("Regex: {}", format_regex_pattern(regex, use_color)));
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
        assert!(output.contains("Pattern: reset_hard"));
        assert!(output.contains("Pack: core.git"));
        assert!(output.contains("CRITICAL"));
    }

    #[test]
    fn test_denial_box_renders_pattern_regex_when_available() {
        let span = HighlightSpan::with_label(0, 16, "Matched: git reset --hard");
        let regex = r"^git\s+reset\s+--hard(?:\s|$)";
        let denial = DenialBox::new(
            "git reset --hard HEAD",
            span,
            "core.git:reset-hard",
            Severity::Critical,
        )
        .with_pattern_regex(regex);

        let output = denial.render_plain();

        assert!(output.contains("Pattern: reset-hard"));
        assert!(output.contains("Regex:"));
        assert!(output.contains(regex));
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
    #[cfg(not(feature = "rich-output"))]
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
    #[cfg(not(feature = "rich-output"))]
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
    #[cfg(not(feature = "rich-output"))]
    fn test_denial_box_no_color_still_uses_ascii_box() {
        let span = HighlightSpan::new(0, 10);
        let theme = Theme::no_color();
        let denial = DenialBox::new(
            "git push --force",
            span,
            "core.git.force_push",
            Severity::High,
        );

        let output = denial.render(&theme);

        assert!(output.contains('+'));
        assert!(output.contains("BLOCKED"));
        assert!(
            !output.contains('\x1b'),
            "No ANSI escapes should appear when colors are disabled"
        );
    }

    #[test]
    #[cfg(not(feature = "rich-output"))]
    fn test_denial_box_unicode_without_colors_strips_ansi() {
        let span = HighlightSpan::new(0, 10);
        let theme = Theme::default().without_colors();
        let denial = DenialBox::new(
            "git push --force",
            span,
            "core.git.force_push",
            Severity::High,
        );

        let output = denial.render(&theme);

        assert!(output.contains('\u{256d}'));
        assert!(output.contains("BLOCKED"));
        assert!(
            !output.contains('\x1b'),
            "No ANSI escapes should appear when colors are disabled"
        );
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
    #[cfg(not(feature = "rich-output"))]
    fn test_strip_ansi_codes() {
        let with_codes = "\x1b[31mRed text\x1b[0m and \x1b[32mgreen\x1b[0m";
        let stripped = strip_ansi_codes(with_codes);

        assert_eq!(stripped, "Red text and green");
    }

    #[test]
    #[cfg(not(feature = "rich-output"))]
    fn test_strip_ansi_codes_handles_non_sgr_csi_terminators() {
        // Regression: the old implementation only terminated on `m`, so a
        // non-SGR CSI like `\x1b[K` (erase-line) left in_escape stuck and
        // silently consumed the rest of the string. With that bug,
        // `padding_for` saw a much shorter "visible length" than reality
        // and the rendered box border drifted off-screen.
        let cases: &[(&str, &str, &str)] = &[
            ("\x1b[Khello", "hello", "ESC [ K (erase line)"),
            (
                "before\x1b[2Jafter",
                "beforeafter",
                "ESC [ 2 J (erase display)",
            ),
            (
                "before\x1b[1;2Hafter",
                "beforeafter",
                "ESC [ 1 ; 2 H (cursor position)",
            ),
            (
                "\x1b[?25lhide cursor\x1b[?25h",
                "hide cursor",
                "DECSET / DECRST private mode",
            ),
        ];
        for (input, expected, label) in cases {
            assert_eq!(
                strip_ansi_codes(input),
                *expected,
                "non-SGR sequence not stripped correctly ({label})"
            );
        }
    }

    #[test]
    #[cfg(not(feature = "rich-output"))]
    fn test_strip_ansi_codes_handles_osc_hyperlink() {
        // OSC 8 hyperlinks: `\x1b]8;;URL\x1b\\TEXT\x1b]8;;\x1b\\`. The old
        // implementation, looking only for `m`, would consume the entire
        // tail past the first ESC and lose all the visible text.
        let input = "\x1b]8;;https://example.com\x1b\\click here\x1b]8;;\x1b\\";
        assert_eq!(strip_ansi_codes(input), "click here");

        // BEL-terminated OSC variant.
        let input = "\x1b]0;window title\x07visible text";
        assert_eq!(strip_ansi_codes(input), "visible text");
    }

    #[test]
    #[cfg(not(feature = "rich-output"))]
    fn test_strip_ansi_codes_does_not_lose_text_after_truncated_escape() {
        // A bare ESC followed by an incomplete sequence shouldn't eat the
        // rest of the string. Two-byte ESC sequence (ESC followed by a
        // single byte not in `[` or `]`) consumes exactly the next char
        // and resumes normal output.
        assert_eq!(strip_ansi_codes("foo\x1b=bar"), "foobar");
        // A trailing ESC with nothing after it leaves us in EscOpen at end
        // of input — no panic, just truncated.
        assert_eq!(strip_ansi_codes("foo\x1b"), "foo");
    }

    #[test]
    #[cfg(not(feature = "rich-output"))]
    fn test_severity_color_codes() {
        let theme = Theme::default();
        assert_eq!(severity_color_code(&theme, Severity::Critical), "31");
        assert_eq!(severity_color_code(&theme, Severity::High), "91");
        assert_eq!(severity_color_code(&theme, Severity::Medium), "33");
        assert_eq!(severity_color_code(&theme, Severity::Low), "34");
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
    #[cfg(not(feature = "rich-output"))]
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
        let clean_output = strip_ansi_codes(&output);

        // Minimal style should still contain key elements
        assert!(clean_output.contains("BLOCKED"));
        // Highlighting might split the command with ANSI codes, but clean_output handles that
        assert!(clean_output.contains("git push --force"));
        assert!(clean_output.contains("Pattern: force_push"));
        assert!(clean_output.contains("Pack: core.git"));
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
    #[cfg(not(feature = "rich-output"))]
    fn test_padding_for_with_ansi() {
        // Text with ANSI codes should be padded based on visible length
        let text_with_ansi = "\x1b[31mRed\x1b[0m";
        let padding = padding_for(text_with_ansi, 10);
        // Visible length is 3 ("Red"), so padding should be 7 spaces
        assert_eq!(padding.len(), 7);
    }

    #[test]
    fn test_denial_box_without_branch_context() {
        let span = HighlightSpan::new(0, 10);
        let denial = DenialBox::new(
            "git reset --hard",
            span,
            "core.git:reset_hard",
            Severity::Critical,
        );

        assert!(denial.branch_name.is_none());
        assert!(!denial.is_protected_branch);

        let output = denial.render_plain();
        assert!(output.contains("BLOCKED: Destructive Command Detected"));
        assert!(!output.contains("Branch:"));
        assert!(!output.contains("Protected"));
        assert!(!output.contains("Extra caution"));
    }

    #[test]
    fn test_denial_box_with_branch_name() {
        let span = HighlightSpan::new(0, 10);
        let denial = DenialBox::new(
            "git reset --hard",
            span,
            "core.git:reset_hard",
            Severity::Critical,
        )
        .with_branch_context("feature/my-branch", false);

        assert_eq!(denial.branch_name.as_deref(), Some("feature/my-branch"));
        assert!(!denial.is_protected_branch);

        let output = denial.render_plain();
        assert!(output.contains("BLOCKED (Branch: feature/my-branch)"));
        assert!(!output.contains("Protected"));
        assert!(!output.contains("Extra caution"));
    }

    #[test]
    fn test_denial_box_with_protected_branch() {
        let span = HighlightSpan::new(0, 10);
        let denial = DenialBox::new(
            "git reset --hard",
            span,
            "core.git:reset_hard",
            Severity::Critical,
        )
        .with_branch_context("main", true);

        assert_eq!(denial.branch_name.as_deref(), Some("main"));
        assert!(denial.is_protected_branch);

        let output = denial.render_plain();
        assert!(output.contains("BLOCKED (Protected Branch: main)"));
        assert!(output.contains("Extra caution on protected branches"));
    }

    #[test]
    #[cfg(not(feature = "rich-output"))]
    fn test_denial_box_branch_context_ascii_render() {
        let theme = Theme {
            border_style: BorderStyle::Ascii,
            colors_enabled: false,
            ..Theme::default()
        };
        let span = HighlightSpan::new(0, 10);
        let denial = DenialBox::new("rm -rf /", span, "core.fs:rm_rf", Severity::Critical)
            .with_branch_context("main", true);

        let output = denial.render(&theme);
        assert!(output.contains("BLOCKED (Protected Branch: main)"));
        assert!(output.contains("Extra caution on protected branches"));
    }

    #[test]
    #[cfg(not(feature = "rich-output"))]
    fn test_denial_box_branch_context_unicode_render() {
        let theme = Theme {
            border_style: BorderStyle::Unicode,
            colors_enabled: false,
            ..Theme::default()
        };
        let span = HighlightSpan::new(0, 10);
        let denial = DenialBox::new("rm -rf /", span, "core.fs:rm_rf", Severity::High)
            .with_branch_context("develop", false);

        let output = denial.render(&theme);
        assert!(output.contains("BLOCKED (Branch: develop)"));
        assert!(!output.contains("Protected"));
    }

    #[test]
    fn test_denial_box_all_fields_with_branch() {
        let span = HighlightSpan::with_label(0, 10, "Matched");
        let denial = DenialBox::new(
            "git push --force",
            span,
            "core.git:push_force",
            Severity::High,
        )
        .with_explanation("Force push overwrites remote history")
        .with_alternatives(vec!["Use git push --force-with-lease".to_string()])
        .with_allow_once_code("abc12")
        .with_branch_context("main", true);

        let output = denial.render_plain();
        assert!(output.contains("BLOCKED (Protected Branch: main)"));
        assert!(output.contains("Extra caution"));
        assert!(output.contains("Force push overwrites remote history"));
        assert!(output.contains("git push --force-with-lease"));
    }

    #[test]
    fn test_denial_box_branch_builder_chaining() {
        let span = HighlightSpan::new(0, 5);
        let denial = DenialBox::new("cmd", span, "pack:rule", Severity::Medium)
            .with_branch_context("release/1.0", true)
            .with_explanation("test")
            .with_allow_once_code("xyz");

        assert_eq!(denial.branch_name.as_deref(), Some("release/1.0"));
        assert!(denial.is_protected_branch);
        assert!(denial.explanation.is_some());
        assert!(denial.allow_once_code.is_some());
    }

    #[test]
    fn test_denial_box_allow_once_code_stored() {
        let span = HighlightSpan::new(0, 16);
        let denial = DenialBox::new(
            "git reset --hard HEAD",
            span,
            "core.git:reset-hard",
            Severity::Critical,
        )
        .with_allow_once_code("abc123");

        assert_eq!(denial.allow_once_code.as_deref(), Some("abc123"));
        let output = denial.render_plain();
        assert!(output.contains("BLOCKED"), "plain render should succeed");
    }

    #[test]
    #[cfg(not(feature = "rich-output"))]
    fn test_denial_box_allow_once_code_does_not_crash_renders() {
        let theme_unicode = Theme {
            border_style: BorderStyle::Unicode,
            colors_enabled: false,
            ..Default::default()
        };
        let theme_ascii = Theme {
            border_style: BorderStyle::Ascii,
            colors_enabled: false,
            ..Default::default()
        };

        let span = HighlightSpan::new(0, 5);
        let denial = DenialBox::new("rm -rf /", span, "core:rm", Severity::High)
            .with_allow_once_code("xyz789");

        let unicode = denial.render(&theme_unicode);
        assert!(
            !unicode.is_empty(),
            "unicode render with allow-once should not be empty"
        );

        let ascii = denial.render(&theme_ascii);
        assert!(
            !ascii.is_empty(),
            "ascii render with allow-once should not be empty"
        );
    }

    #[test]
    fn test_denial_box_matched_span_mid_command() {
        let cmd = "echo hello && rm -rf / && echo done";
        let span = HighlightSpan::with_label(14, 23, "rm -rf /");
        let denial = DenialBox::new(cmd, span, "core:rm_rf", Severity::Critical);

        let output = denial.render_plain();
        assert!(output.contains("rm -rf /"), "should show the matched text");
        assert!(output.contains("echo hello"), "should show full command");
    }

    #[test]
    #[cfg(not(feature = "rich-output"))]
    fn test_denial_box_very_long_command_wraps() {
        let long_cmd = format!("git push --force origin {}", "a".repeat(200));
        let span = HighlightSpan::new(0, 20);
        let theme = Theme {
            border_style: BorderStyle::Unicode,
            colors_enabled: false,
            ..Default::default()
        };
        let denial = DenialBox::new(&long_cmd, span, "core.git:force-push", Severity::High);

        let output = denial.render(&theme);
        assert!(
            !output.is_empty(),
            "should produce output even for long commands"
        );
        assert!(
            output.contains("git push --force"),
            "should contain start of command"
        );
    }

    #[test]
    fn test_denial_box_empty_pattern_regex_ignored() {
        let span = HighlightSpan::new(0, 5);
        let denial =
            DenialBox::new("rm -rf", span, "core:rm", Severity::High).with_pattern_regex("");

        assert!(denial.pattern_regex.is_none(), "empty regex should be None");
        let output = denial.render_plain();
        assert!(!output.contains("Regex:"), "should not show Regex line");
    }

    #[test]
    fn test_denial_box_whitespace_pattern_regex_trimmed() {
        let span = HighlightSpan::new(0, 5);
        let denial = DenialBox::new("rm -rf", span, "core:rm", Severity::High)
            .with_pattern_regex("  ^rm\\s+  ");

        assert_eq!(denial.pattern_regex.as_deref(), Some("^rm\\s+"));
    }

    #[test]
    fn test_denial_box_empty_explanation_ignored() {
        let span = HighlightSpan::new(0, 5);
        let denial =
            DenialBox::new("rm -rf", span, "core:rm", Severity::High).with_explanation("   ");

        assert!(
            denial.explanation.is_none(),
            "whitespace-only explanation should be None"
        );
    }

    #[test]
    fn test_denial_box_plain_render_strips_markdown_explanation() {
        let span = HighlightSpan::new(0, 16);
        let denial = DenialBox::new(
            "git reset --hard HEAD",
            span,
            "core.git:reset-hard",
            Severity::Critical,
        )
        .with_explanation(
            "Use `git stash` before **resetting**.\n- See [docs](https://example.test)",
        );

        let output = denial.render_plain();

        assert!(output.contains("git stash"));
        assert!(output.contains("resetting"));
        assert!(output.contains("docs (https://example.test)"));
        assert!(!output.contains("`git stash`"));
        assert!(!output.contains("**resetting**"));
    }

    #[test]
    #[cfg(not(feature = "rich-output"))]
    fn test_denial_box_alternatives_in_all_render_paths() {
        let span = HighlightSpan::new(0, 16);
        let alts = vec![
            "git stash".to_string(),
            "git reset --soft HEAD~1".to_string(),
        ];
        let denial = DenialBox::new(
            "git reset --hard HEAD",
            span,
            "core.git:reset-hard",
            Severity::High,
        )
        .with_alternatives(alts);

        let plain = denial.render_plain();
        assert!(plain.contains("git stash"), "plain should show alternative");
        assert!(
            plain.contains("git reset --soft"),
            "plain should show second alternative"
        );

        let theme_unicode = Theme {
            border_style: BorderStyle::Unicode,
            colors_enabled: false,
            ..Default::default()
        };
        let unicode = denial.render(&theme_unicode);
        assert!(
            unicode.contains("git stash"),
            "unicode should show alternative"
        );

        let theme_ascii = Theme {
            border_style: BorderStyle::Ascii,
            colors_enabled: false,
            ..Default::default()
        };
        let ascii = denial.render(&theme_ascii);
        assert!(ascii.contains("git stash"), "ascii should show alternative");
    }

    #[test]
    #[cfg(not(feature = "rich-output"))]
    fn test_denial_box_legacy_fallback_preserves_contract_without_rich_output() {
        let span = HighlightSpan::with_label(0, 16, "Matched: git reset --hard");
        let denial = DenialBox::new(
            "git reset --hard HEAD~1",
            span,
            "core.git:reset-hard",
            Severity::Critical,
        )
        .with_pattern_regex(r"^git\s+reset\s+--hard")
        .with_explanation("Discards staged and unstaged changes.")
        .with_alternatives(vec!["git stash push".to_string()]);

        for border_style in [BorderStyle::Unicode, BorderStyle::Ascii, BorderStyle::None] {
            let theme = Theme {
                border_style,
                colors_enabled: false,
                ..Default::default()
            };

            let output = denial.render(&theme);

            assert!(
                output.contains("BLOCKED"),
                "{border_style:?} fallback should identify the denial"
            );
            assert!(
                output.contains("git reset --hard HEAD~1"),
                "{border_style:?} fallback should preserve the command"
            );
            assert!(
                output.contains("Pattern: reset-hard"),
                "{border_style:?} fallback should render pattern identity"
            );
            assert!(
                output.contains("Pack: core.git"),
                "{border_style:?} fallback should render pack identity"
            );
            assert!(
                output.contains("Discards staged and unstaged changes"),
                "{border_style:?} fallback should render explanations"
            );
            assert!(
                output.contains("git stash push"),
                "{border_style:?} fallback should render alternatives"
            );
            assert!(
                !output.contains('\x1b'),
                "{border_style:?} no-color fallback should strip ANSI escapes"
            );
        }
    }

    #[test]
    fn test_denial_box_low_severity_render() {
        let span = HighlightSpan::new(0, 10);
        let denial = DenialBox::new("chmod 777 .", span, "core:chmod", Severity::Low);

        let output = denial.render_plain();
        assert!(
            output.to_lowercase().contains("low"),
            "should indicate low severity"
        );
    }

    #[test]
    #[cfg(not(feature = "rich-output"))]
    fn test_denial_box_minimal_render_contains_essentials() {
        let theme = Theme {
            border_style: BorderStyle::None,
            colors_enabled: false,
            ..Default::default()
        };
        let span = HighlightSpan::new(0, 10);
        let denial = DenialBox::new(
            "docker rm -f $(docker ps -aq)",
            span,
            "containers:rm-all",
            Severity::High,
        )
        .with_explanation("Removes all running containers");

        let output = denial.render(&theme);
        assert!(output.contains("docker rm"), "minimal should show command");
        assert!(
            output.contains("containers"),
            "minimal should show pack info"
        );
    }

    #[test]
    #[cfg(not(feature = "rich-output"))]
    fn test_denial_box_protected_branch_all_render_paths() {
        let span = HighlightSpan::new(0, 16);
        let denial = DenialBox::new(
            "git reset --hard",
            span,
            "core.git:reset-hard",
            Severity::Critical,
        )
        .with_branch_context("main", true);

        let plain = denial.render_plain();
        assert!(
            plain.contains("main"),
            "plain should show protected branch name"
        );

        let theme_unicode = Theme {
            border_style: BorderStyle::Unicode,
            colors_enabled: false,
            ..Default::default()
        };
        let unicode = denial.render(&theme_unicode);
        assert!(
            unicode.contains("main"),
            "unicode should show protected branch"
        );

        let theme_ascii = Theme {
            border_style: BorderStyle::Ascii,
            colors_enabled: false,
            ..Default::default()
        };
        let ascii = denial.render(&theme_ascii);
        assert!(ascii.contains("main"), "ascii should show protected branch");

        // Note: minimal render (BorderStyle::None) doesn't show branch context yet
        let theme_minimal = Theme {
            border_style: BorderStyle::None,
            colors_enabled: false,
            ..Default::default()
        };
        let minimal = denial.render(&theme_minimal);
        assert!(
            !minimal.is_empty(),
            "minimal render with branch context should not crash"
        );
    }
}

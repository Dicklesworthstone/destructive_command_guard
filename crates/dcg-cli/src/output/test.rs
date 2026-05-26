//! Test result box renderer for terminal output.
//!
//! Provides formatted output for the `dcg test` command showing:
//! - Whether a command would be blocked or allowed
//! - Pattern match details for blocked commands
//! - Allowlist match details for allowed commands
//!
//! Uses the same theme system as denial.rs for consistent visual presentation.

#[cfg(not(feature = "rich-output"))]
use super::terminal_width;
#[cfg(not(feature = "rich-output"))]
use super::theme::BorderStyle;
use super::theme::Theme;
use crate::evaluator::{EvaluationDecision, EvaluationResult, PatternMatch};
#[cfg(feature = "rich-output")]
use crate::output::rich_theme::RichThemeExt;
use crate::packs::Severity;
#[cfg(not(feature = "rich-output"))]
use ratatui::style::Color;
#[cfg(feature = "rich-output")]
#[allow(unused_imports)]
use rich_rust::prelude::*;
use std::fmt::Write;

/// A test result box to display for `dcg test` output.
#[derive(Debug, Clone)]
pub struct TestResultBox {
    /// The command being tested.
    pub command: String,
    /// The evaluation result.
    pub result: TestOutcome,
}

/// Outcome of testing a command.
#[derive(Debug, Clone)]
pub enum TestOutcome {
    /// Command would be blocked.
    Blocked {
        /// Pattern that matched.
        pattern_id: Option<String>,
        /// Pack that contains the pattern.
        pack_id: Option<String>,
        /// Severity of the match.
        severity: Option<Severity>,
        /// Reason for blocking.
        reason: String,
        /// Optional explanation for the matched pattern.
        explanation: Option<String>,
        /// Confidence score (0.0-1.0).
        confidence: Option<f64>,
    },
    /// Command would be allowed.
    Allowed {
        /// Why the command is allowed.
        reason: AllowedReason,
    },
}

/// Reason why a command was allowed.
#[derive(Debug, Clone)]
pub enum AllowedReason {
    /// No pattern matched the command.
    NoPatternMatch,
    /// Command matched an allowlist entry.
    AllowlistMatch {
        /// The allowlist entry that matched.
        entry: String,
        /// Which layer the allowlist entry came from.
        layer: String,
    },
    /// Evaluation was skipped due to budget constraints (fail-open).
    BudgetExhausted,
}

impl TestResultBox {
    /// Create a test result box from an evaluation result.
    #[must_use]
    pub fn from_evaluation(command: impl Into<String>, eval: &EvaluationResult) -> Self {
        let command = command.into();

        let result = match eval.decision {
            EvaluationDecision::Deny => {
                let pattern_info = eval.pattern_info.as_ref();
                TestOutcome::Blocked {
                    pattern_id: pattern_info.and_then(|p| p.pattern_name.clone()),
                    pack_id: pattern_info.and_then(|p| p.pack_id.clone()),
                    severity: pattern_info.and_then(|p| p.severity),
                    reason: pattern_info
                        .map(|p| p.reason.clone())
                        .unwrap_or_else(|| "Pattern matched".to_string()),
                    explanation: pattern_info.and_then(|p| p.explanation.clone()),
                    confidence: pattern_info.and_then(confidence_from_severity),
                }
            }
            EvaluationDecision::Allow => {
                if eval.skipped_due_to_budget {
                    TestOutcome::Allowed {
                        reason: AllowedReason::BudgetExhausted,
                    }
                } else if let Some(override_info) = &eval.allowlist_override {
                    TestOutcome::Allowed {
                        reason: AllowedReason::AllowlistMatch {
                            entry: override_info.reason.clone(),
                            layer: format!("{:?}", override_info.layer),
                        },
                    }
                } else {
                    TestOutcome::Allowed {
                        reason: AllowedReason::NoPatternMatch,
                    }
                }
            }
        };

        Self { command, result }
    }

    /// Create a test result box for a blocked command.
    #[must_use]
    pub fn blocked(
        command: impl Into<String>,
        pattern_id: Option<String>,
        pack_id: Option<String>,
        severity: Option<Severity>,
        reason: impl Into<String>,
        confidence: Option<f64>,
    ) -> Self {
        Self {
            command: command.into(),
            result: TestOutcome::Blocked {
                pattern_id,
                pack_id,
                severity,
                reason: reason.into(),
                explanation: None,
                confidence,
            },
        }
    }

    /// Create a test result box for an allowed command (no pattern match).
    #[must_use]
    pub fn allowed_no_match(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            result: TestOutcome::Allowed {
                reason: AllowedReason::NoPatternMatch,
            },
        }
    }

    /// Create a test result box for an allowed command (allowlist match).
    #[must_use]
    pub fn allowed_by_allowlist(
        command: impl Into<String>,
        entry: impl Into<String>,
        layer: impl Into<String>,
    ) -> Self {
        Self {
            command: command.into(),
            result: TestOutcome::Allowed {
                reason: AllowedReason::AllowlistMatch {
                    entry: entry.into(),
                    layer: layer.into(),
                },
            },
        }
    }

    /// Returns whether the result indicates the command would be blocked.
    #[must_use]
    pub const fn is_blocked(&self) -> bool {
        matches!(self.result, TestOutcome::Blocked { .. })
    }

    /// Render the test result box with the given theme.
    #[must_use]
    pub fn render(&self, theme: &Theme) -> String {
        #[cfg(feature = "rich-output")]
        {
            self.render_rich(theme)
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
        use rich_rust::r#box::{DOUBLE, HEAVY, ROUNDED};
        use rich_rust::prelude::*;

        let (title, border_style, header_color): (
            &str,
            &'static rich_rust::r#box::BoxChars,
            String,
        ) = match &self.result {
            TestOutcome::Blocked { severity, .. } => {
                let box_style = match severity {
                    Some(Severity::Critical) => &DOUBLE,
                    Some(Severity::High) => &HEAVY,
                    _ => &ROUNDED,
                };
                // Determine color for the title based on theme
                let color_str = theme.error_markup();
                (" WOULD BE BLOCKED ", box_style, color_str)
            }
            TestOutcome::Allowed { .. } => (" WOULD BE ALLOWED ", &ROUNDED, theme.success_markup()),
        };

        // Build content as a Vec of lines
        let mut lines = Vec::new();

        // Command line
        lines.push(format!(
            "[dim]Command:[/]     [bold]{cmd}[/]",
            cmd = self.command
        ));

        // Result-specific content
        match &self.result {
            TestOutcome::Blocked {
                pattern_id,
                pack_id,
                severity,
                reason,
                confidence,
                explanation,
            } => {
                if let Some(pattern) = pattern_id {
                    lines.push(format!("[dim]Pattern:[/]     [magenta]{pattern}[/]"));
                }
                if let Some(pack) = pack_id {
                    let sev = severity
                        .map(|s| format!(" ({})", severity_label(s)))
                        .unwrap_or_default();
                    lines.push(format!("[dim]Pack:[/]        [cyan]{pack}[/][dim]{sev}[/]"));
                }
                if let Some(conf) = confidence {
                    let bar = render_confidence_bar(*conf);
                    lines.push(format!(
                        "[dim]Confidence:[/]  {bar} {conf:.0}%",
                        conf = conf * 100.0
                    ));
                }
                lines.push(format!("[dim]Reason:[/]      {reason}"));
                if let Some(text) = explanation {
                    lines.push(format!("[dim]Explanation:[/] {text}"));
                }
            }
            TestOutcome::Allowed { reason } => {
                let reason_text = match reason {
                    AllowedReason::NoPatternMatch => "No pattern matches".to_string(),
                    AllowedReason::AllowlistMatch { entry, layer } => {
                        format!("Allowlist: [italic]\"{entry}\"[/] ({layer})")
                    }
                    AllowedReason::BudgetExhausted => {
                        "[yellow]Budget exhausted (fail-open)[/]".to_string()
                    }
                };
                lines.push(format!("[dim]Reason:[/]      {reason_text}"));
            }
        }

        let content_str = lines.join("\n");

        // Parse header color to use for border
        // rich_rust Style::parse expects simple color names or hex, not "bold red"
        // So we strip modifiers for the border color
        let border_color_str = if header_color.contains("red") {
            "red"
        } else if header_color.contains("green") {
            "green"
        } else if header_color.contains("yellow") {
            "yellow"
        } else {
            "white"
        };

        let width = super::terminal_width() as usize;
        Panel::from_text(&content_str)
            .title(format!("[{header_color}]{title}[/]"))
            .box_style(border_style)
            .border_style(Style::parse(border_color_str).unwrap_or_default())
            .padding((1, 2))
            .render_plain(width)
    }

    /// Render a plain text version for non-TTY contexts.
    #[must_use]
    pub fn render_plain(&self) -> String {
        let mut output = String::new();

        match &self.result {
            TestOutcome::Blocked {
                pattern_id,
                pack_id,
                severity,
                reason,
                confidence,
                explanation,
            } => {
                let _ = writeln!(output, "WOULD BE BLOCKED");
                let _ = writeln!(output);
                let _ = writeln!(output, "  Command:    {}", self.command);
                if let Some(pattern) = pattern_id {
                    let _ = writeln!(output, "  Pattern:    {pattern}");
                }
                if let Some(pack) = pack_id {
                    let severity_str = severity
                        .map(|s| format!(" (severity: {})", severity_label(s)))
                        .unwrap_or_default();
                    let _ = writeln!(output, "  Pack:       {pack}{severity_str}");
                }
                if let Some(conf) = confidence {
                    let _ = writeln!(output, "  Confidence: {conf:.2}");
                }
                let _ = writeln!(output, "  Reason:     {reason}");
                if let Some(text) = explanation {
                    let _ = writeln!(output, "  Explanation: {text}");
                }
            }
            TestOutcome::Allowed { reason } => {
                let _ = writeln!(output, "WOULD BE ALLOWED");
                let _ = writeln!(output);
                let _ = writeln!(output, "  Command:    {}", self.command);
                match reason {
                    AllowedReason::NoPatternMatch => {
                        let _ = writeln!(output, "  Reason:     No pattern matches");
                    }
                    AllowedReason::AllowlistMatch { entry, layer } => {
                        let _ = writeln!(output, "  Reason:     Allowlist match: \"{entry}\"");
                        let _ = writeln!(output, "  Layer:      {layer}");
                    }
                    AllowedReason::BudgetExhausted => {
                        let _ = writeln!(
                            output,
                            "  Reason:     Evaluation budget exhausted (fail-open)"
                        );
                    }
                }
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

        let (header, header_color) = match &self.result {
            TestOutcome::Blocked { .. } => (" WOULD BE BLOCKED ", theme.error_color),
            TestOutcome::Allowed { .. } => (" WOULD BE ALLOWED ", theme.success_color),
        };

        let color_code = ansi_color_code(header_color);
        let header_len = header.chars().count();
        let top_pad = width.saturating_sub(header_len);

        // Top border
        let _ = writeln!(
            output,
            "\x1b[{}m\u{256d}{}\u{256e}\x1b[0m",
            &color_code,
            "\u{2500}".repeat(width)
        );

        // Header line
        let _ = writeln!(
            output,
            "\x1b[{}m\u{2502}\x1b[0m\x1b[1;{}m{}\x1b[0m{}\x1b[{}m\u{2502}\x1b[0m",
            &color_code,
            &color_code,
            header,
            " ".repeat(top_pad),
            &color_code
        );

        // Separator
        let _ = writeln!(
            output,
            "\x1b[{}m\u{251c}{}\u{2524}\x1b[0m",
            &color_code,
            "\u{2500}".repeat(width)
        );

        // Content based on result type
        match &self.result {
            TestOutcome::Blocked {
                pattern_id,
                pack_id,
                severity,
                reason,
                confidence,
                explanation,
            } => {
                self.render_unicode_row(&mut output, "Command:", &self.command, width, &color_code);

                if let Some(pattern) = pattern_id {
                    self.render_unicode_row(&mut output, "Pattern:", pattern, width, &color_code);
                }

                if let Some(pack) = pack_id {
                    let severity_str = severity
                        .map(|s| format!(" (severity: {})", severity_label(s)))
                        .unwrap_or_default();
                    self.render_unicode_row(
                        &mut output,
                        "Pack:",
                        &format!("{pack}{severity_str}"),
                        width,
                        &color_code,
                    );
                }

                if let Some(conf) = confidence {
                    self.render_unicode_row(
                        &mut output,
                        "Confidence:",
                        &format!("{conf:.2}"),
                        width,
                        &color_code,
                    );
                }

                self.render_unicode_row(&mut output, "Reason:", reason, width, &color_code);
                if let Some(text) = explanation {
                    self.render_unicode_row(&mut output, "Explanation:", text, width, &color_code);
                }
            }
            TestOutcome::Allowed { reason } => {
                self.render_unicode_row(&mut output, "Command:", &self.command, width, &color_code);

                match reason {
                    AllowedReason::NoPatternMatch => {
                        self.render_unicode_row(
                            &mut output,
                            "Reason:",
                            "No pattern matches",
                            width,
                            &color_code,
                        );
                    }
                    AllowedReason::AllowlistMatch { entry, layer } => {
                        self.render_unicode_row(
                            &mut output,
                            "Reason:",
                            &format!("Allowlist match: \"{entry}\""),
                            width,
                            &color_code,
                        );
                        self.render_unicode_row(&mut output, "Layer:", layer, width, &color_code);
                    }
                    AllowedReason::BudgetExhausted => {
                        self.render_unicode_row(
                            &mut output,
                            "Reason:",
                            "Evaluation budget exhausted (fail-open)",
                            width,
                            &color_code,
                        );
                    }
                }
            }
        }

        // Bottom border
        let _ = writeln!(
            output,
            "\x1b[{}m\u{2570}{}\u{256f}\x1b[0m",
            &color_code,
            "\u{2500}".repeat(width)
        );

        output
    }

    /// Helper to render a labeled row in Unicode box style.
    #[cfg(not(feature = "rich-output"))]
    fn render_unicode_row(
        &self,
        output: &mut String,
        label: &str,
        value: &str,
        width: usize,
        color_code: &str,
    ) {
        let label_width = 12; // Fixed label column width
        let content = format!("{label:<label_width$}{value}");
        let content_len = content.chars().count();
        let padding = width.saturating_sub(content_len + 4);

        let _ = writeln!(
            output,
            "\x1b[{color_code}m\u{2502}\x1b[0m  {content}{}\x1b[{color_code}m\u{2502}\x1b[0m",
            " ".repeat(padding),
        );
    }

    /// Render with ASCII box-drawing characters.
    #[cfg(not(feature = "rich-output"))]
    fn render_ascii(&self, _theme: &Theme) -> String {
        let width = terminal_width().saturating_sub(4).max(40) as usize;
        let mut output = String::new();

        let header = match &self.result {
            TestOutcome::Blocked { .. } => " WOULD BE BLOCKED ",
            TestOutcome::Allowed { .. } => " WOULD BE ALLOWED ",
        };

        let header_len = header.chars().count();
        let top_pad = width.saturating_sub(header_len);

        // Top border
        let _ = writeln!(output, "+{}+", "-".repeat(width));

        // Header line
        let _ = writeln!(output, "|{}{}|", header, " ".repeat(top_pad));

        // Separator
        let _ = writeln!(output, "+{}+", "-".repeat(width));

        // Content based on result type
        match &self.result {
            TestOutcome::Blocked {
                pattern_id,
                pack_id,
                severity,
                reason,
                confidence,
                explanation,
            } => {
                self.render_ascii_row(&mut output, "Command:", &self.command, width);

                if let Some(pattern) = pattern_id {
                    self.render_ascii_row(&mut output, "Pattern:", pattern, width);
                }

                if let Some(pack) = pack_id {
                    let severity_str = severity
                        .map(|s| format!(" (severity: {})", severity_label(s)))
                        .unwrap_or_default();
                    self.render_ascii_row(
                        &mut output,
                        "Pack:",
                        &format!("{pack}{severity_str}"),
                        width,
                    );
                }

                if let Some(conf) = confidence {
                    self.render_ascii_row(&mut output, "Confidence:", &format!("{conf:.2}"), width);
                }

                self.render_ascii_row(&mut output, "Reason:", reason, width);
                if let Some(text) = explanation {
                    self.render_ascii_row(&mut output, "Explanation:", text, width);
                }
            }
            TestOutcome::Allowed { reason } => {
                self.render_ascii_row(&mut output, "Command:", &self.command, width);

                match reason {
                    AllowedReason::NoPatternMatch => {
                        self.render_ascii_row(&mut output, "Reason:", "No pattern matches", width);
                    }
                    AllowedReason::AllowlistMatch { entry, layer } => {
                        self.render_ascii_row(
                            &mut output,
                            "Reason:",
                            &format!("Allowlist match: \"{entry}\""),
                            width,
                        );
                        self.render_ascii_row(&mut output, "Layer:", layer, width);
                    }
                    AllowedReason::BudgetExhausted => {
                        self.render_ascii_row(
                            &mut output,
                            "Reason:",
                            "Evaluation budget exhausted (fail-open)",
                            width,
                        );
                    }
                }
            }
        }

        // Bottom border
        let _ = writeln!(output, "+{}+", "-".repeat(width));

        output
    }

    /// Helper to render a labeled row in ASCII box style.
    #[cfg(not(feature = "rich-output"))]
    fn render_ascii_row(&self, output: &mut String, label: &str, value: &str, width: usize) {
        let label_width = 12; // Fixed label column width
        let content = format!("{label:<label_width$}{value}");
        let content_len = content.chars().count();
        let padding = width.saturating_sub(content_len + 4);

        let _ = writeln!(output, "|  {content}{}|", " ".repeat(padding));
    }

    /// Render with no borders (minimal style).
    #[cfg(not(feature = "rich-output"))]
    fn render_minimal(&self, theme: &Theme) -> String {
        let mut output = String::new();

        let (header, header_color) = match &self.result {
            TestOutcome::Blocked { .. } => ("WOULD BE BLOCKED", theme.error_color),
            TestOutcome::Allowed { .. } => ("WOULD BE ALLOWED", theme.success_color),
        };

        let color_code = ansi_color_code(header_color);

        // Header
        let _ = writeln!(output, "\x1b[1;{color_code}m{header}\x1b[0m");
        let _ = writeln!(output);

        // Content based on result type
        match &self.result {
            TestOutcome::Blocked {
                pattern_id,
                pack_id,
                severity,
                reason,
                confidence,
                explanation,
            } => {
                let _ = writeln!(output, "  Command:    {}", self.command);
                if let Some(pattern) = pattern_id {
                    let _ = writeln!(output, "  Pattern:    {pattern}");
                }
                if let Some(pack) = pack_id {
                    let severity_str = severity
                        .map(|s| format!(" (severity: {})", severity_label(s)))
                        .unwrap_or_default();
                    let _ = writeln!(output, "  Pack:       {pack}{severity_str}");
                }
                if let Some(conf) = confidence {
                    let _ = writeln!(output, "  Confidence: {conf:.2}");
                }
                let _ = writeln!(output, "  Reason:     {reason}");
                if let Some(text) = explanation {
                    let _ = writeln!(output, "  Explanation: {text}");
                }
            }
            TestOutcome::Allowed { reason } => {
                let _ = writeln!(output, "  Command:    {}", self.command);
                match reason {
                    AllowedReason::NoPatternMatch => {
                        let _ = writeln!(output, "  Reason:     No pattern matches");
                    }
                    AllowedReason::AllowlistMatch { entry, layer } => {
                        let _ = writeln!(output, "  Reason:     Allowlist match: \"{entry}\"");
                        let _ = writeln!(output, "  Layer:      {layer}");
                    }
                    AllowedReason::BudgetExhausted => {
                        let _ = writeln!(
                            output,
                            "  Reason:     Evaluation budget exhausted (fail-open)"
                        );
                    }
                }
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

/// Get a human-readable label for a severity level.
fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    }
}

/// Derive confidence score from severity (heuristic when not explicitly provided).
fn confidence_from_severity(pattern: &PatternMatch) -> Option<f64> {
    pattern.severity.map(|s| match s {
        Severity::Critical => 0.95,
        Severity::High => 0.85,
        Severity::Medium => 0.70,
        Severity::Low => 0.50,
    })
}

/// Strip ANSI escape codes from a string. See `output::denial::strip_ansi_codes`
/// for the rationale on why this needs to handle CSI/OSC/2-byte ESC sequences
/// — the previous "terminate on `m`" logic dropped the rest of the string on
/// any non-SGR sequence (erase-line, hyperlink, etc.).
#[cfg(not(feature = "rich-output"))]
fn strip_ansi_codes(s: &str) -> String {
    #[derive(Copy, Clone)]
    enum State {
        Normal,
        EscOpen,
        Csi,
        Osc,
        OscWantSt,
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
                    _ => State::Normal,
                };
            }
            State::Csi => {
                let cp = c as u32;
                if (0x40..=0x7E).contains(&cp) {
                    state = State::Normal;
                }
            }
            State::Osc => {
                if c == '\x07' {
                    state = State::Normal;
                } else if c == '\x1b' {
                    state = State::OscWantSt;
                }
            }
            State::OscWantSt => {
                state = if c == '\\' {
                    State::Normal
                } else {
                    State::EscOpen
                };
            }
        }
    }

    result
}

/// Render a visual confidence bar using Unicode blocks
#[cfg(feature = "rich-output")]
fn render_confidence_bar(confidence: f64) -> String {
    let filled = (confidence * 10.0).round() as usize;
    let empty = 10usize.saturating_sub(filled);

    let color = if confidence >= 0.8 {
        "red"
    } else if confidence >= 0.5 {
        "yellow"
    } else {
        "green"
    };

    format!(
        "[{color}]{}[/][dim]{}[/]",
        "█".repeat(filled),
        "░".repeat(empty)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocked_result_plain_render() {
        let result = TestResultBox::blocked(
            "rm -rf /",
            Some("filesystem.recursive_delete".to_string()),
            Some("core".to_string()),
            Some(Severity::Critical),
            "Recursive deletion of root filesystem",
            Some(0.95),
        );

        let output = result.render_plain();

        assert!(output.contains("WOULD BE BLOCKED"));
        assert!(output.contains("rm -rf /"));
        assert!(output.contains("filesystem.recursive_delete"));
        assert!(output.contains("core"));
        assert!(output.contains("critical"));
        assert!(output.contains("0.95"));
    }

    #[test]
    fn test_allowed_no_match_plain_render() {
        let result = TestResultBox::allowed_no_match("npm run build");

        let output = result.render_plain();

        assert!(output.contains("WOULD BE ALLOWED"));
        assert!(output.contains("npm run build"));
        assert!(output.contains("No pattern matches"));
    }

    #[test]
    fn test_allowed_by_allowlist_plain_render() {
        let result = TestResultBox::allowed_by_allowlist(
            "git push --force",
            "force push allowed",
            "Project",
        );

        let output = result.render_plain();

        assert!(output.contains("WOULD BE ALLOWED"));
        assert!(output.contains("git push --force"));
        assert!(output.contains("Allowlist match"));
        assert!(output.contains("force push allowed"));
        assert!(output.contains("Project"));
    }

    #[test]
    fn test_is_blocked() {
        let blocked = TestResultBox::blocked("rm -rf /", None, None, None, "dangerous", None);
        assert!(blocked.is_blocked());

        let allowed = TestResultBox::allowed_no_match("echo hello");
        assert!(!allowed.is_blocked());
    }

    #[test]
    #[cfg(not(feature = "rich-output"))]
    fn test_unicode_render_blocked() {
        let theme = Theme::default();
        let result = TestResultBox::blocked(
            "git reset --hard",
            Some("core.git.reset_hard".to_string()),
            Some("core.git".to_string()),
            Some(Severity::Critical),
            "Destroys uncommitted changes",
            Some(0.95),
        );

        let output = result.render(&theme);

        // Should contain Unicode box-drawing characters
        assert!(output.contains('\u{256d}')); // Top-left corner
        assert!(output.contains('\u{256f}')); // Bottom-right corner
        assert!(output.contains("WOULD BE BLOCKED"));
        assert!(output.contains("git reset --hard"));
    }

    #[test]
    #[cfg(not(feature = "rich-output"))]
    fn test_unicode_render_allowed() {
        let theme = Theme::default();
        let result = TestResultBox::allowed_no_match("cargo build");

        let output = result.render(&theme);

        assert!(output.contains('\u{256d}')); // Top-left corner
        assert!(output.contains("WOULD BE ALLOWED"));
        assert!(output.contains("cargo build"));
    }

    #[test]
    #[cfg(not(feature = "rich-output"))]
    fn test_ascii_render() {
        let theme = Theme {
            border_style: BorderStyle::Ascii,
            colors_enabled: true,
            ..Default::default()
        };
        let result = TestResultBox::blocked(
            "DROP TABLE users",
            Some("database.drop_table".to_string()),
            Some("database.postgresql".to_string()),
            Some(Severity::High),
            "Drops database table",
            None,
        );

        let output = result.render(&theme);

        // Should use ASCII characters
        assert!(output.contains('+'));
        assert!(output.contains('-'));
        assert!(output.contains("WOULD BE BLOCKED"));
    }

    #[test]
    #[cfg(not(feature = "rich-output"))]
    fn test_no_color_render() {
        let theme = Theme::no_color();
        let result = TestResultBox::blocked(
            "rm -rf ~",
            Some("filesystem.rm_home".to_string()),
            None,
            Some(Severity::Critical),
            "Deletes home directory",
            None,
        );

        let output = result.render(&theme);

        assert!(
            !output.contains('\x1b'),
            "No ANSI escapes should appear when colors are disabled"
        );
        assert!(output.contains("WOULD BE BLOCKED"));
    }

    #[test]
    #[cfg(not(feature = "rich-output"))]
    fn test_minimal_render() {
        let theme = Theme {
            border_style: BorderStyle::None,
            ..Default::default()
        };
        let result = TestResultBox::allowed_no_match("ls -la");

        let output = result.render(&theme);

        // Minimal style should still contain key elements
        assert!(output.contains("WOULD BE ALLOWED"));
        assert!(output.contains("ls -la"));
        // Should NOT contain box drawing characters
        assert!(!output.contains('\u{256d}'));
        assert!(!output.contains('+'));
    }

    #[test]
    fn test_from_evaluation_denied() {
        let eval = EvaluationResult {
            decision: EvaluationDecision::Deny,
            pattern_info: Some(PatternMatch {
                pack_id: Some("core.git".to_string()),
                pattern_name: Some("reset_hard".to_string()),
                severity: Some(Severity::Critical),
                reason: "Destroys uncommitted changes".to_string(),
                source: crate::evaluator::MatchSource::Pack,
                matched_span: None,
                matched_text_preview: None,
                explanation: None,
                suggestions: &[],
            }),
            allowlist_override: None,
            effective_mode: Some(crate::packs::DecisionMode::Deny),
            skipped_due_to_budget: false,
            branch_context: None,
            session_occurrence: None,
            graduated_response: None,
            bypass_method: None,
        };

        let result = TestResultBox::from_evaluation("git reset --hard HEAD", &eval);

        assert!(result.is_blocked());
        let output = result.render_plain();
        assert!(output.contains("WOULD BE BLOCKED"));
        assert!(output.contains("Destroys uncommitted changes"));
    }

    #[test]
    fn test_from_evaluation_allowed() {
        let eval = EvaluationResult::allowed();

        let result = TestResultBox::from_evaluation("echo hello", &eval);

        assert!(!result.is_blocked());
        let output = result.render_plain();
        assert!(output.contains("WOULD BE ALLOWED"));
        assert!(output.contains("No pattern matches"));
    }

    #[test]
    fn test_from_evaluation_budget_exhausted() {
        let eval = EvaluationResult::allowed_due_to_budget();

        let result = TestResultBox::from_evaluation("complex command", &eval);

        assert!(!result.is_blocked());
        let output = result.render_plain();
        assert!(output.contains("WOULD BE ALLOWED"));
        assert!(output.contains("budget exhausted"));
    }

    #[test]
    #[cfg(not(feature = "rich-output"))]
    fn test_strip_ansi_codes() {
        let with_codes = "\x1b[31mRed text\x1b[0m and \x1b[32mgreen\x1b[0m";
        let stripped = strip_ansi_codes(with_codes);

        assert_eq!(stripped, "Red text and green");
    }

    #[test]
    fn test_severity_labels() {
        assert_eq!(severity_label(Severity::Critical), "critical");
        assert_eq!(severity_label(Severity::High), "high");
        assert_eq!(severity_label(Severity::Medium), "medium");
        assert_eq!(severity_label(Severity::Low), "low");
    }

    #[test]
    fn test_confidence_from_severity() {
        let pattern = PatternMatch {
            pack_id: None,
            pattern_name: None,
            severity: Some(Severity::Critical),
            reason: String::new(),
            source: crate::evaluator::MatchSource::Pack,
            matched_span: None,
            matched_text_preview: None,
            explanation: None,
            suggestions: &[],
        };

        assert_eq!(confidence_from_severity(&pattern), Some(0.95));

        let pattern_high = PatternMatch {
            severity: Some(Severity::High),
            ..pattern.clone()
        };
        assert_eq!(confidence_from_severity(&pattern_high), Some(0.85));

        let pattern_none = PatternMatch {
            severity: None,
            ..pattern
        };
        assert_eq!(confidence_from_severity(&pattern_none), None);
    }

    #[test]
    fn test_unicode_command_preservation() {
        let result = TestResultBox::blocked(
            "rm -rf /path/with/émojis/🎉",
            None,
            None,
            None,
            "test",
            None,
        );

        let output = result.render_plain();

        assert!(output.contains("émojis"));
        assert!(output.contains("🎉"));
    }
}

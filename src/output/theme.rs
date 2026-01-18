//! Theme system for TUI/CLI visual output.
//!
//! Provides color schemes and border styles for consistent visual presentation
//! across all dcg output modes.

use ratatui::style::Color;

/// Border style for message boxes and tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BorderStyle {
    /// Unicode box-drawing characters (│, ─, ┌, ┐, └, ┘)
    #[default]
    Unicode,
    /// ASCII-only characters (|, -, +)
    Ascii,
    /// No borders
    None,
}

/// Colors for different severity levels.
#[derive(Debug, Clone, Copy)]
pub struct SeverityColors {
    /// Critical severity (typically red)
    pub critical: Color,
    /// High severity (typically orange/bright red)
    pub high: Color,
    /// Medium severity (typically yellow)
    pub medium: Color,
    /// Low severity (typically blue)
    pub low: Color,
}

impl Default for SeverityColors {
    fn default() -> Self {
        Self {
            critical: Color::Red,
            high: Color::LightRed,
            medium: Color::Yellow,
            low: Color::Blue,
        }
    }
}

impl SeverityColors {
    /// Returns a plain (no-color) severity scheme.
    #[must_use]
    pub const fn no_color() -> Self {
        Self {
            critical: Color::Reset,
            high: Color::Reset,
            medium: Color::Reset,
            low: Color::Reset,
        }
    }
}

/// Complete theme configuration for dcg output.
#[derive(Debug, Clone)]
pub struct Theme {
    /// Border style for boxes and tables
    pub border_style: BorderStyle,
    /// Colors for severity indicators
    pub severity_colors: SeverityColors,
    /// Accent color for highlights and emphasis
    pub accent_color: Color,
    /// Success color (typically green)
    pub success_color: Color,
    /// Warning color (typically yellow)
    pub warning_color: Color,
    /// Error color (typically red)
    pub error_color: Color,
    /// Muted color for secondary text
    pub muted_color: Color,
    /// Whether colors are enabled
    pub colors_enabled: bool,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            border_style: BorderStyle::default(),
            severity_colors: SeverityColors::default(),
            accent_color: Color::Cyan,
            success_color: Color::Green,
            warning_color: Color::Yellow,
            error_color: Color::Red,
            muted_color: Color::DarkGray,
            colors_enabled: true,
        }
    }
}

impl Theme {
    /// Creates a new theme with default rich terminal colors.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a plain theme with no colors and ASCII borders.
    ///
    /// Suitable for:
    /// - Terminals that don't support colors
    /// - When `NO_COLOR` environment variable is set
    /// - Piping output to files or other programs
    #[must_use]
    pub const fn no_color() -> Self {
        Self {
            border_style: BorderStyle::Ascii,
            severity_colors: SeverityColors::no_color(),
            accent_color: Color::Reset,
            success_color: Color::Reset,
            warning_color: Color::Reset,
            error_color: Color::Reset,
            muted_color: Color::Reset,
            colors_enabled: false,
        }
    }

    /// Creates a minimal theme with colors but no borders.
    #[must_use]
    pub fn minimal() -> Self {
        Self {
            border_style: BorderStyle::None,
            ..Self::default()
        }
    }

    /// Returns the color for a given severity level.
    #[must_use]
    pub const fn color_for_severity(&self, severity: Severity) -> Color {
        match severity {
            Severity::Critical => self.severity_colors.critical,
            Severity::High => self.severity_colors.high,
            Severity::Medium => self.severity_colors.medium,
            Severity::Low => self.severity_colors.low,
        }
    }

    /// Returns the severity label with appropriate styling hint.
    #[must_use]
    pub const fn severity_label(&self, severity: Severity) -> &'static str {
        match severity {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
        }
    }
}

/// Severity levels for pattern matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Low risk - informational
    Low,
    /// Medium risk - caution advised
    Medium,
    /// High risk - likely destructive
    High,
    /// Critical risk - definitely destructive
    Critical,
}

impl Severity {
    /// Parses a severity from a string (case-insensitive).
    #[must_use]
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "critical" | "crit" => Some(Self::Critical),
            "high" | "hi" => Some(Self::High),
            "medium" | "med" => Some(Self::Medium),
            "low" | "lo" | "info" => Some(Self::Low),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_theme_has_colors() {
        let theme = Theme::default();
        assert!(theme.colors_enabled);
        assert_eq!(theme.border_style, BorderStyle::Unicode);
    }

    #[test]
    fn test_no_color_theme() {
        let theme = Theme::no_color();
        assert!(!theme.colors_enabled);
        assert_eq!(theme.border_style, BorderStyle::Ascii);
        assert_eq!(theme.severity_colors.critical, Color::Reset);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn test_severity_from_str() {
        assert_eq!(
            Severity::from_str_loose("critical"),
            Some(Severity::Critical)
        );
        assert_eq!(Severity::from_str_loose("CRIT"), Some(Severity::Critical));
        assert_eq!(Severity::from_str_loose("high"), Some(Severity::High));
        assert_eq!(Severity::from_str_loose("medium"), Some(Severity::Medium));
        assert_eq!(Severity::from_str_loose("low"), Some(Severity::Low));
        assert_eq!(Severity::from_str_loose("info"), Some(Severity::Low));
        assert_eq!(Severity::from_str_loose("unknown"), None);
    }

    #[test]
    fn test_color_for_severity() {
        let theme = Theme::default();
        assert_eq!(theme.color_for_severity(Severity::Critical), Color::Red);
        assert_eq!(theme.color_for_severity(Severity::Low), Color::Blue);
    }
}

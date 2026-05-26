//! Theme bridge layer for rich_rust integration.
//!
//! Maps dcg's existing ratatui-based Theme system to rich_rust's Style system,
//! enabling gradual migration without breaking existing code.
//!
//! ## Architecture
//!
//! ```text
//! dcg Theme (ratatui::style::Color) ──► RichThemeExt ──► rich_rust Style/markup
//! ```
//!
//! ## Usage
//!
//! ```ignore
//! use crate::output::theme::{Theme, Severity};
//! use crate::output::rich_theme::RichThemeExt;
//!
//! let theme = Theme::default();
//! let markup = theme.severity_markup(Severity::Critical);
//! console().print(&format!("[{markup}]BLOCKED[/]"));
//! ```

use super::theme::{BorderStyle, Severity, Theme};
use ratatui::style::Color;

/// Extension trait for Theme to provide rich_rust integration.
pub trait RichThemeExt {
    /// Returns rich_rust markup color string for a severity level.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let theme = Theme::default();
    /// let markup = theme.severity_markup(Severity::Critical);
    /// // Returns something like "bold red" or "bold #FF0000"
    /// ```
    fn severity_markup(&self, severity: Severity) -> String;

    /// Returns rich_rust markup for the error color.
    fn error_markup(&self) -> String;

    /// Returns rich_rust markup for the success color.
    fn success_markup(&self) -> String;

    /// Returns rich_rust markup for the warning color.
    fn warning_markup(&self) -> String;

    /// Returns rich_rust markup for the accent color.
    fn accent_markup(&self) -> String;

    /// Returns rich_rust markup for the muted color.
    fn muted_markup(&self) -> String;

    /// Returns the box type string for rich_rust Panel based on border style.
    fn box_type(&self) -> &'static str;
}

impl RichThemeExt for Theme {
    fn severity_markup(&self, severity: Severity) -> String {
        if !self.colors_enabled {
            return String::new();
        }

        let color = self.color_for_severity(severity);
        let color_str = color_to_markup(color);

        // Add bold for critical/high severity
        match severity {
            Severity::Critical | Severity::High => format!("bold {color_str}"),
            Severity::Medium | Severity::Low => color_str,
        }
    }

    fn error_markup(&self) -> String {
        if !self.colors_enabled {
            return String::new();
        }
        format!("bold {}", color_to_markup(self.error_color))
    }

    fn success_markup(&self) -> String {
        if !self.colors_enabled {
            return String::new();
        }
        color_to_markup(self.success_color)
    }

    fn warning_markup(&self) -> String {
        if !self.colors_enabled {
            return String::new();
        }
        color_to_markup(self.warning_color)
    }

    fn accent_markup(&self) -> String {
        if !self.colors_enabled {
            return String::new();
        }
        color_to_markup(self.accent_color)
    }

    fn muted_markup(&self) -> String {
        if !self.colors_enabled {
            return String::new();
        }
        format!("dim {}", color_to_markup(self.muted_color))
    }

    fn box_type(&self) -> &'static str {
        match self.border_style {
            BorderStyle::Unicode => "ROUNDED",
            BorderStyle::Ascii => "ASCII",
            BorderStyle::None => "NONE",
        }
    }
}

/// Convert ratatui Color to rich_rust markup color string.
///
/// Maps ratatui's Color enum to rich_rust's color markup syntax.
/// Rich_rust supports named colors and hex codes.
#[must_use]
pub fn color_to_markup(color: Color) -> String {
    match color {
        // Basic colors - use rich_rust named colors
        Color::Black => "black".to_string(),
        Color::Red => "red".to_string(),
        Color::Green => "green".to_string(),
        Color::Yellow => "yellow".to_string(),
        Color::Blue => "blue".to_string(),
        Color::Magenta => "magenta".to_string(),
        Color::Cyan => "cyan".to_string(),
        Color::White => "white".to_string(),
        Color::Gray => "bright_black".to_string(),
        Color::DarkGray => "bright_black".to_string(),

        // Bright/light variants
        Color::LightRed => "bright_red".to_string(),
        Color::LightGreen => "bright_green".to_string(),
        Color::LightYellow => "bright_yellow".to_string(),
        Color::LightBlue => "bright_blue".to_string(),
        Color::LightMagenta => "bright_magenta".to_string(),
        Color::LightCyan => "bright_cyan".to_string(),

        // RGB colors - convert to hex
        Color::Rgb(r, g, b) => format!("#{r:02X}{g:02X}{b:02X}"),

        // Indexed colors (256-color palette)
        Color::Indexed(idx) => format!("color({idx})"),

        // Reset means no color
        Color::Reset => String::new(),
    }
}

/// Returns markup for a severity badge (label with background).
///
/// Creates markup suitable for displaying severity as a badge with
/// inverse colors (colored background, contrasting text).
#[must_use]
pub fn severity_badge_markup(theme: &Theme, severity: Severity) -> String {
    if !theme.colors_enabled {
        return format!("[bold]{}[/]", theme.severity_label(severity));
    }

    let color = color_to_markup(theme.color_for_severity(severity));
    let label = theme.severity_label(severity);

    // Use reverse video for badge effect
    format!("[bold {color} reverse] {label} [/]")
}

/// Returns the border character set name for rich_rust box rendering.
///
/// Maps dcg's BorderStyle to rich_rust's box type names.
#[must_use]
pub const fn border_to_box_type(style: BorderStyle) -> &'static str {
    match style {
        BorderStyle::Unicode => "ROUNDED",
        BorderStyle::Ascii => "ASCII",
        BorderStyle::None => "NONE",
    }
}

/// Severity-appropriate panel title markup.
///
/// Returns markup for panel titles that includes severity coloring.
#[must_use]
pub fn severity_panel_title(theme: &Theme, severity: Severity, title: &str) -> String {
    if !theme.colors_enabled {
        return title.to_string();
    }

    let color = color_to_markup(theme.color_for_severity(severity));
    format!("[bold {color}]{title}[/]")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_color_to_markup_basic_colors() {
        assert_eq!(color_to_markup(Color::Red), "red");
        assert_eq!(color_to_markup(Color::Green), "green");
        assert_eq!(color_to_markup(Color::Blue), "blue");
        assert_eq!(color_to_markup(Color::Yellow), "yellow");
    }

    #[test]
    fn test_color_to_markup_rgb() {
        assert_eq!(color_to_markup(Color::Rgb(255, 0, 0)), "#FF0000");
        assert_eq!(color_to_markup(Color::Rgb(0, 114, 178)), "#0072B2");
    }

    #[test]
    fn test_color_to_markup_indexed() {
        assert_eq!(color_to_markup(Color::Indexed(196)), "color(196)");
    }

    #[test]
    fn test_color_to_markup_reset() {
        assert_eq!(color_to_markup(Color::Reset), "");
    }

    #[test]
    fn test_severity_markup_default_theme() {
        let theme = Theme::default();
        let critical = theme.severity_markup(Severity::Critical);
        assert!(critical.contains("bold"));
        assert!(critical.contains("red"));

        let low = theme.severity_markup(Severity::Low);
        assert!(!low.contains("bold"));
        assert!(low.contains("blue"));
    }

    #[test]
    fn test_severity_markup_no_color_theme() {
        let theme = Theme::no_color();
        assert_eq!(theme.severity_markup(Severity::Critical), "");
        assert_eq!(theme.severity_markup(Severity::Low), "");
    }

    #[test]
    fn test_box_type_mapping() {
        let theme = Theme::default();
        assert_eq!(theme.box_type(), "ROUNDED");

        let theme = Theme::no_color();
        assert_eq!(theme.box_type(), "ASCII");

        let theme = Theme::minimal();
        assert_eq!(theme.box_type(), "NONE");
    }

    #[test]
    fn test_border_to_box_type() {
        assert_eq!(border_to_box_type(BorderStyle::Unicode), "ROUNDED");
        assert_eq!(border_to_box_type(BorderStyle::Ascii), "ASCII");
        assert_eq!(border_to_box_type(BorderStyle::None), "NONE");
    }

    #[test]
    fn test_severity_badge_markup() {
        let theme = Theme::default();
        let badge = severity_badge_markup(&theme, Severity::Critical);
        assert!(badge.contains("bold"));
        assert!(badge.contains("reverse"));
        assert!(badge.contains("CRITICAL"));
    }

    #[test]
    fn test_severity_badge_no_color() {
        let theme = Theme::no_color();
        let badge = severity_badge_markup(&theme, Severity::Critical);
        assert!(badge.contains("CRITICAL"));
        assert!(badge.contains("[bold]"));
        assert!(!badge.contains("red"));
    }

    #[test]
    fn test_severity_panel_title() {
        let theme = Theme::default();
        let title = severity_panel_title(&theme, Severity::High, "Warning");
        assert!(title.contains("Warning"));
        assert!(title.contains("bold"));
    }

    #[test]
    fn test_error_success_warning_markup() {
        let theme = Theme::default();
        assert!(theme.error_markup().contains("red"));
        assert!(theme.success_markup().contains("green"));
        assert!(theme.warning_markup().contains("yellow"));
    }

    #[test]
    fn test_accent_muted_markup() {
        let theme = Theme::default();
        assert!(theme.accent_markup().contains("cyan"));
        assert!(theme.muted_markup().contains("dim"));
    }
}

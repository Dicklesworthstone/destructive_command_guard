//! Output formatting module for dcg.
//!
//! Provides rich terminal output with themes, colors, and TTY-aware rendering.
//!
//! # Module Structure
//!
//! - `theme` - Color schemes and border style definitions
//! - `denial` - Denial message box renderer (future)
//! - `tables` - Table renderer using comfy-table (future)
//! - `progress` - Progress indicators using indicatif (future)
//!
//! # TTY Detection
//!
//! The module automatically detects whether rich output should be used based on:
//! 1. Explicit flags (--json, --no-color)
//! 2. NO_COLOR environment variable
//! 3. Whether stdout is a TTY
//! 4. TERM environment variable (dumb terminals)

pub mod denial;
pub mod theme;

pub use denial::DenialBox;
pub use theme::{BorderStyle, Severity, SeverityColors, Theme};

use std::sync::OnceLock;

/// Global flag to force plain output (set by --no-color or similar).
static FORCE_PLAIN: OnceLock<bool> = OnceLock::new();

/// Initialize the output system with explicit settings.
///
/// Call this early in main() if you want to override TTY detection.
pub fn init(force_plain: bool) {
    let _ = FORCE_PLAIN.set(force_plain);
}

/// Determines whether rich terminal output should be used.
///
/// Returns `true` if all of the following are true:
/// - `--no-color` flag was not passed (or `init(false)` was called)
/// - `NO_COLOR` environment variable is not set
/// - stdout is a TTY
/// - TERM is not "dumb"
///
/// # Examples
///
/// ```no_run
/// use destructive_command_guard::output::should_use_rich_output;
///
/// if should_use_rich_output() {
///     // Use colors and unicode borders
/// } else {
///     // Use plain ASCII output
/// }
/// ```
#[must_use]
pub fn should_use_rich_output() -> bool {
    // 1. Check if explicitly disabled
    if FORCE_PLAIN.get().copied().unwrap_or(false) {
        return false;
    }

    // 2. Check NO_COLOR environment variable (https://no-color.org/)
    if std::env::var("NO_COLOR").is_ok() {
        return false;
    }

    // 3. Check if stdout is a TTY
    if !console::Term::stdout().is_term() {
        return false;
    }

    // 4. Check for dumb terminal
    if let Ok(term) = std::env::var("TERM") {
        if term == "dumb" {
            return false;
        }
    }

    true
}

/// Returns the appropriate theme based on TTY detection.
///
/// This is the recommended way to get a theme - it automatically
/// selects rich or plain output based on the environment.
#[must_use]
pub fn auto_theme() -> Theme {
    if should_use_rich_output() {
        Theme::default()
    } else {
        Theme::no_color()
    }
}

/// Checks if the terminal supports 256 colors.
#[must_use]
pub fn supports_256_colors() -> bool {
    if !should_use_rich_output() {
        return false;
    }

    // Check COLORTERM for truecolor/256color support
    if let Ok(colorterm) = std::env::var("COLORTERM") {
        if colorterm == "truecolor" || colorterm == "24bit" {
            return true;
        }
    }

    // Check TERM for 256color suffix
    if let Ok(term) = std::env::var("TERM") {
        if term.contains("256color") || term.contains("truecolor") {
            return true;
        }
    }

    // Modern terminals usually support 256 colors even without explicit TERM
    // Default to true if we're in a TTY
    true
}

/// Returns the terminal width, or a default if not detectable.
#[must_use]
pub fn terminal_width() -> u16 {
    console::Term::stdout()
        .size_checked()
        .map(|(_, w)| w)
        .unwrap_or(80)
}

/// Returns the terminal height, or a default if not detectable.
#[must_use]
pub fn terminal_height() -> u16 {
    console::Term::stdout()
        .size_checked()
        .map(|(h, _)| h)
        .unwrap_or(24)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_theme_returns_theme() {
        // Just verify it doesn't panic and returns a valid theme
        let theme = auto_theme();
        // Theme should have some valid state
        assert!(matches!(
            theme.border_style,
            BorderStyle::Unicode | BorderStyle::Ascii | BorderStyle::None
        ));
    }

    #[test]
    fn test_terminal_dimensions_have_defaults() {
        // Should return reasonable defaults even in test environment
        let width = terminal_width();
        let height = terminal_height();
        assert!(width > 0);
        assert!(height > 0);
    }

    #[test]
    fn test_supports_256_colors_does_not_panic() {
        // Just verify it doesn't panic in test environment
        let _ = supports_256_colors();
    }
}

//! Output formatting module for dcg.
//!
//! Provides rich terminal output with themes, colors, and TTY-aware rendering.
//!
//! # Module Structure
//!
//! - `theme` - Color schemes and border style definitions
//! - `denial` - Denial message box renderer
//! - `test` - Test result box renderer
//! - `progress` - Progress indicators using indicatif (with rich_rust support)
//! - `console` - Console abstraction for stderr output
//! - `rich_theme` - rich_rust theme integration
//! - `tree` - Tree visualization for hierarchical data
//!
//! # TTY Detection
//!
//! The module automatically detects whether rich output should be used based on:
//! 1. Explicit flags (--json, --no-color)
//! 2. `NO_COLOR` environment variable
//! 3. Whether stdout is a TTY
//! 4. TERM environment variable (dumb terminals)

pub mod console;
pub mod denial;
pub mod progress;
pub mod rich_theme;
pub mod tables;
pub mod test;
pub mod theme;
pub mod tree;

pub use console::{DcgConsole, console, init_console};
pub use denial::DenialBox;
pub use progress::{
    MaybeProgress, NoopProgress, SCAN_PROGRESS_THRESHOLD, ScanProgress, ScanProgressStyle, spinner,
    spinner_if_tty,
};
#[cfg(feature = "rich-output")]
pub use progress::{RichProgressStyle, render_progress_bar_rich};
pub use rich_theme::{RichThemeExt, color_to_markup, severity_badge_markup, severity_panel_title};
pub use tables::{ScanResultRow, ScanResultsTable, TableStyle};
pub use test::{AllowedReason, TestOutcome, TestResultBox};
pub use theme::{BorderStyle, Severity, SeverityColors, Theme, ThemePalette};
pub use tree::{DcgTree, DcgTreeGuides, ExplainTreeBuilder, TreeNode};

use crate::config::Config;
use std::sync::OnceLock;

/// Global flag to force plain output (set by --no-color or similar).
static FORCE_PLAIN: OnceLock<bool> = OnceLock::new();

/// Global flag for suggestions display (set by --no-suggestions).
static SUGGESTIONS_ENABLED: OnceLock<bool> = OnceLock::new();

/// Initialize the output system with explicit settings.
///
/// Call this early in `main()` if you want to override TTY detection.
pub fn init(force_plain: bool) {
    let _ = FORCE_PLAIN.set(force_plain);
}

/// Initialize suggestions display setting.
///
/// Call this early in `main()` to control whether suggestions are shown.
pub fn init_suggestions(enabled: bool) {
    let _ = SUGGESTIONS_ENABLED.set(enabled);
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
    if std::env::var("NO_COLOR").is_ok() || std::env::var("DCG_NO_COLOR").is_ok() {
        return false;
    }

    // 3. Check CI environment variable (common in CI/CD systems)
    if std::env::var("CI").is_ok() {
        return false;
    }

    // 4. Check if stdout is a TTY
    if !::console::Term::stdout().is_term() {
        return false;
    }

    // 5. Check for dumb terminal
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
        if env_flag_enabled("DCG_HIGH_CONTRAST") {
            Theme::high_contrast()
        } else {
            Theme::default()
        }
    } else {
        Theme::no_color()
    }
}

/// Returns the appropriate theme based on config and environment.
#[must_use]
pub fn auto_theme_with_config(config: &Config) -> Theme {
    if !should_use_rich_output() {
        return Theme::no_color();
    }

    let palette = if env_flag_enabled("DCG_HIGH_CONTRAST") || config.output.high_contrast_enabled()
    {
        ThemePalette::HighContrast
    } else if let Some(palette) = config
        .theme
        .palette
        .as_deref()
        .and_then(|value| value.parse::<ThemePalette>().ok())
    {
        palette
    } else {
        ThemePalette::Default
    };

    let mut theme = Theme::from_palette(palette);

    if let Some(use_color) = config.theme.use_color {
        if !use_color {
            theme = theme.without_colors();
        }
    }

    if let Some(use_unicode) = config.theme.use_unicode {
        if palette != ThemePalette::HighContrast {
            theme.border_style = if use_unicode {
                BorderStyle::Unicode
            } else {
                BorderStyle::Ascii
            };
        }
    }

    theme
}

fn env_flag_enabled(var: &str) -> bool {
    std::env::var(var).is_ok_and(|value| {
        !matches!(
            value.trim().to_lowercase().as_str(),
            "" | "0" | "false" | "no" | "off"
        )
    })
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
    ::console::Term::stdout()
        .size_checked()
        .map_or(80, |(_, w)| w)
}

/// Returns the terminal height, or a default if not detectable.
#[must_use]
pub fn terminal_height() -> u16 {
    ::console::Term::stdout()
        .size_checked()
        .map_or(24, |(h, _)| h)
}

/// Returns whether suggestions should be displayed.
///
/// Suggestions are shown when:
/// - `init_suggestions(true)` was called (or not called, defaulting to true)
/// - We're in an interactive terminal mode (TTY)
///
/// Suggestions are hidden in:
/// - Non-TTY contexts (pipes, files)
/// - CI environments
/// - When explicitly disabled via `--no-suggestions`
#[must_use]
pub fn suggestions_enabled() -> bool {
    // Check explicit disable first
    if !SUGGESTIONS_ENABLED.get().copied().unwrap_or(true) {
        return false;
    }
    // Only show suggestions in rich output mode (TTY)
    should_use_rich_output()
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

    #[test]
    fn test_env_flag_enabled_true_values() {
        // env_flag_enabled returns true for truthy values
        // We can't easily set env vars in parallel tests, so test the logic
        // by verifying the function signature and basic behavior
        assert!(!env_flag_enabled("DCG_NONEXISTENT_TEST_VAR_12345"));
    }

    #[test]
    fn test_env_flag_enabled_false_for_unset() {
        // An unset variable should return false
        assert!(!env_flag_enabled("DCG_DEFINITELY_NOT_SET_EVER"));
    }

    #[test]
    fn test_suggestions_enabled_default() {
        // In test environment (non-TTY), suggestions should be disabled
        // because should_use_rich_output() returns false in non-TTY
        let result = suggestions_enabled();
        // Non-TTY test environment: suggestions disabled
        assert!(!result);
    }

    #[test]
    fn test_init_idempotent() {
        // Calling init multiple times should not panic
        // (OnceLock silently ignores subsequent sets)
        init(false);
        init(true);
        // No panic = success
    }

    #[test]
    fn test_init_suggestions_idempotent() {
        // Calling init_suggestions multiple times should not panic
        init_suggestions(true);
        init_suggestions(false);
        // No panic = success
    }

    #[test]
    fn test_should_use_rich_output_in_test_env() {
        // In test environment (non-TTY), should return false
        // This tests the actual detection logic
        let result = should_use_rich_output();
        // CI/non-TTY environments should not use rich output
        assert!(!result);
    }

    #[test]
    fn test_auto_theme_no_color_in_test_env() {
        // In non-TTY test environment, auto_theme should return no_color theme
        let theme = auto_theme();
        // In test env (non-TTY or CI), should give us no-color
        assert!(!theme.colors_enabled);
    }

    #[test]
    fn test_terminal_width_reasonable_range() {
        let width = terminal_width();
        // Width should be between 1 and 500 (reasonable terminal range)
        assert!(width >= 1);
        assert!(width <= 500);
    }

    #[test]
    fn test_terminal_height_reasonable_range() {
        let height = terminal_height();
        // Height should be between 1 and 200 (reasonable terminal range)
        assert!(height >= 1);
        assert!(height <= 200);
    }
}

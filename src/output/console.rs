//! Console abstraction for dcg output.
//!
//! Provides a unified interface for all human-facing output, automatically
//! routing to stderr and detecting terminal capabilities.
//!
//! ## Why This Wrapper Exists
//!
//! 1. **stderr by default**: Agents parse stdout JSON, humans see stderr
//! 2. **TTY detection integration**: Uses existing `should_use_rich_output()`
//! 3. **Environment control**: Respects `NO_COLOR`, `CI`, `DCG_NO_RICH`
//!
//! ## Usage
//!
//! ```ignore
//! use crate::output::console::console;
//!
//! // Get a console and print styled text
//! console().print("[bold red]Error:[/] Something went wrong");
//! ```

use std::io;
#[cfg(not(feature = "rich-output"))]
use std::io::Write;
use std::sync::OnceLock;

/// Global flag indicating whether rich output should be used.
static USE_RICH: OnceLock<bool> = OnceLock::new();

/// dcg-specific console wrapper.
///
/// Wraps rich_rust's Console (when the feature is enabled) with dcg-specific
/// defaults like stderr output and environment variable handling.
///
/// Note: This struct creates a new Console on each operation to avoid
/// thread-safety issues with the underlying rich_rust Console.
#[derive(Debug, Clone, Copy)]
pub struct DcgConsole {
    force_plain: bool,
}

impl DcgConsole {
    /// Create a new console with rich formatting (if available).
    #[must_use]
    pub const fn new() -> Self {
        Self { force_plain: false }
    }

    /// Create a plain-text console (no colors, no unicode).
    #[must_use]
    pub const fn plain() -> Self {
        Self { force_plain: true }
    }

    /// Print styled text using markup syntax.
    ///
    /// When rich-output is enabled, parses markup like `[bold red]text[/]`.
    /// Otherwise, strips markup and prints plain text.
    #[cfg(feature = "rich-output")]
    pub fn print(&self, text: &str) {
        let console = self.create_inner_console();
        if self.force_plain {
            console.print_plain(text);
        } else {
            console.print(text);
        }
    }

    /// Print text without rich-output feature (plain text to stderr).
    #[cfg(not(feature = "rich-output"))]
    pub fn print(&self, text: &str) {
        // Strip markup-like patterns for plain output
        let plain_text = strip_markup(text);
        let _ = writeln!(io::stderr(), "{plain_text}");
    }

    /// Print a renderable (Panel, Table, etc.).
    #[cfg(feature = "rich-output")]
    pub fn print_renderable<R>(&self, renderable: &R)
    where
        R: rich_rust::renderables::Renderable,
    {
        let console = self.create_inner_console();
        console.print_renderable(renderable);
    }

    /// Print a horizontal rule.
    #[cfg(feature = "rich-output")]
    pub fn rule(&self, title: Option<&str>) {
        let console = self.create_inner_console();
        console.rule(title);
    }

    /// Print a horizontal rule without rich-output feature.
    #[cfg(not(feature = "rich-output"))]
    pub fn rule(&self, title: Option<&str>) {
        let width = self.width();
        let line = if let Some(t) = title {
            let padding = width.saturating_sub(t.len() + 4) / 2;
            format!("{} {} {}", "-".repeat(padding), t, "-".repeat(padding))
        } else {
            "-".repeat(width)
        };
        let _ = writeln!(io::stderr(), "{line}");
    }

    /// Get terminal width.
    #[cfg(feature = "rich-output")]
    #[must_use]
    pub fn width(&self) -> usize {
        let console = self.create_inner_console();
        console.width()
    }

    /// Get terminal width without rich-output feature.
    #[cfg(not(feature = "rich-output"))]
    #[must_use]
    pub fn width(&self) -> usize {
        crate::output::terminal_width() as usize
    }

    /// Returns whether this console uses plain output.
    #[must_use]
    pub const fn is_plain(&self) -> bool {
        self.force_plain
    }

    /// Create the underlying rich_rust Console instance.
    #[cfg(feature = "rich-output")]
    fn create_inner_console(&self) -> rich_rust::console::Console {
        let mut builder = rich_rust::console::Console::builder().file(Box::new(io::stderr())); // CRITICAL: all output to stderr

        if self.force_plain {
            builder = builder.no_color();
        }

        builder.build()
    }
}

impl Default for DcgConsole {
    fn default() -> Self {
        Self::new()
    }
}

/// Get a console instance appropriate for the current environment.
///
/// The console respects:
/// - `DCG_NO_RICH` environment variable (forces plain output)
/// - `NO_COLOR` environment variable (forces plain output)
/// - `CI` environment variable (forces plain output)
/// - TTY detection (non-TTY forces plain output)
#[must_use]
pub fn console() -> DcgConsole {
    let use_rich = *USE_RICH.get_or_init(|| {
        // Check DCG-specific environment variable
        if std::env::var("DCG_NO_RICH").is_ok() {
            return false;
        }

        // Use the existing rich output detection
        crate::output::should_use_rich_output()
    });

    if use_rich {
        DcgConsole::new()
    } else {
        DcgConsole::plain()
    }
}

/// Initialize console with explicit settings (call early in main).
///
/// If the console settings were already initialized, this function does nothing.
pub fn init_console(force_plain: bool) {
    let _ = USE_RICH.set(!force_plain);
}

/// Strip markup tags from text for plain output.
///
/// Removes patterns like `[bold red]` and `[/]` from the text.
#[cfg(not(feature = "rich-output"))]
fn strip_markup(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut in_bracket = false;

    for c in text.chars() {
        match c {
            '[' => in_bracket = true,
            ']' if in_bracket => in_bracket = false,
            _ if !in_bracket => result.push(c),
            _ => {}
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_console_returns_valid_width() {
        let console = DcgConsole::plain();
        assert!(console.width() > 0);
    }

    #[test]
    fn test_plain_console_is_plain() {
        let console = DcgConsole::plain();
        assert!(console.is_plain());
    }

    #[test]
    fn test_new_console_default() {
        let console = DcgConsole::new();
        // In test environment (no TTY), this should work without panic
        let _ = console.width();
    }

    #[test]
    fn test_new_console_not_plain() {
        let console = DcgConsole::new();
        assert!(!console.is_plain());
    }

    #[test]
    fn test_default_trait_matches_new() {
        let default_console = DcgConsole::default();
        let new_console = DcgConsole::new();
        assert_eq!(default_console.is_plain(), new_console.is_plain());
        assert!(!default_console.is_plain());
    }

    #[test]
    fn test_init_console_does_not_panic() {
        // init_console should be safe to call even in tests
        init_console(true);
        init_console(false);
        // OnceLock only sets first time, subsequent calls are no-ops
    }

    #[test]
    fn test_plain_console_print_does_not_panic() {
        let console = DcgConsole::plain();
        // Printing to a plain console should never panic
        console.print("simple text");
        console.print("[bold]markup text[/]");
        console.print("");
    }

    #[test]
    fn test_new_console_print_does_not_panic() {
        let console = DcgConsole::new();
        console.print("simple text");
        console.print("[bold]markup text[/]");
        console.print("");
    }

    #[test]
    fn test_plain_console_rule_does_not_panic() {
        let console = DcgConsole::plain();
        console.rule(None);
        console.rule(Some("Title"));
        console.rule(Some(""));
    }

    #[test]
    fn test_console_function_returns_valid_console() {
        // console() should always return a valid console in any environment
        let c = console();
        // Should have a valid width
        assert!(c.width() > 0);
    }

    #[cfg(not(feature = "rich-output"))]
    #[test]
    fn test_strip_markup() {
        assert_eq!(strip_markup("[bold]hello[/]"), "hello");
        assert_eq!(strip_markup("[red]error[/]: message"), "error: message");
        assert_eq!(strip_markup("no markup here"), "no markup here");
        assert_eq!(strip_markup("[a][b][c]"), "");
    }

    #[cfg(not(feature = "rich-output"))]
    #[test]
    fn test_strip_markup_nested() {
        // Nested brackets: first ] closes bracket state, second ] is literal
        assert_eq!(strip_markup("[bold [red]]text[/]"), "]text");
    }

    #[cfg(not(feature = "rich-output"))]
    #[test]
    fn test_strip_markup_empty() {
        assert_eq!(strip_markup(""), "");
    }

    #[cfg(not(feature = "rich-output"))]
    #[test]
    fn test_strip_markup_no_close() {
        // Unclosed bracket - rest of string is consumed
        assert_eq!(strip_markup("[bold"), "");
    }
}

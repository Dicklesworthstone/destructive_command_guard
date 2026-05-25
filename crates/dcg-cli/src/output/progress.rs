//! Progress indicators for dcg.
//!
//! Provides progress bars and spinners for long-running operations like
//! scanning and history analysis.
//!
//! # Design Principles
//!
//! - **TTY-aware**: Progress only shown when stdout is a TTY
//! - **Threshold-based**: Progress bar only appears for operations above a threshold
//! - **Non-blocking**: Progress updates are designed to be fast
//! - **Clean finish**: No visual artifacts left after completion
//!
//! # Rich Output
//!
//! When the `rich-output` feature is enabled, additional rendering methods using
//! `rich_rust` are available:
//! - `ScanProgress::render_static_rich()` - Render a snapshot as a styled string
//! - `render_progress_bar_rich()` - Render a standalone progress bar
//!
//! # Thresholds
//!
//! - File scanning: Show progress bar when scanning >20 files
//! - Operation duration: Show spinner when operation may take >500ms
//!
//! # Usage
//!
//! ```no_run
//! use dcg_cli::output::progress::{ScanProgress, spinner};
//!
//! // For file scanning
//! if let Some(progress) = ScanProgress::new_if_needed(100) {
//!     let files = ["src/main.rs", "src/lib.rs"];
//!     for file in files {
//!         progress.tick(&file);
//!     }
//!     progress.finish("Scan complete");
//! }
//!
//! // For short operations with uncertain duration
//! let sp = spinner("Loading patterns...");
//! // ... do work ...
//! sp.finish_and_clear();
//! ```

use indicatif::{ProgressBar, ProgressStyle};
use std::borrow::Cow;
use std::time::Duration;

// Rich output imports
#[cfg(feature = "rich-output")]
use rich_rust::renderables::{BarStyle as RichBarStyle, ProgressBar as RichProgressBar};
#[cfg(feature = "rich-output")]
use rich_rust::style::Style as RichStyle;

/// Minimum file count before showing a progress bar.
pub const SCAN_PROGRESS_THRESHOLD: u64 = 20;

/// Default tick interval for spinners.
const SPINNER_TICK_MS: u64 = 80;

/// Progress bar for file scanning operations.
#[derive(Debug)]
pub struct ScanProgress {
    bar: ProgressBar,
    show_file_names: bool,
}

impl ScanProgress {
    /// Creates a new scan progress bar for the given file count.
    ///
    /// The progress bar is always created, even if not a TTY. Use `new_if_needed`
    /// for threshold-aware creation.
    #[must_use]
    pub fn new(total_files: u64) -> Self {
        let bar = ProgressBar::new(total_files);
        bar.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} files ({eta})")
                .expect("valid progress template")
                .progress_chars("█▓░"),
        );
        bar.enable_steady_tick(Duration::from_millis(SPINNER_TICK_MS));

        Self {
            bar,
            show_file_names: true,
        }
    }

    /// Creates a progress bar only if the file count exceeds the threshold
    /// and stdout is a TTY.
    ///
    /// Returns `None` if:
    /// - `total_files` is below `SCAN_PROGRESS_THRESHOLD`
    /// - stdout is not a TTY (non-interactive environment)
    #[must_use]
    pub fn new_if_needed(total_files: u64) -> Option<Self> {
        if total_files < SCAN_PROGRESS_THRESHOLD {
            return None;
        }

        if !super::should_use_rich_output() {
            return None;
        }

        Some(Self::new(total_files))
    }

    /// Creates a progress bar with a custom style.
    #[must_use]
    pub fn with_style(total_files: u64, style: ScanProgressStyle) -> Self {
        let bar = ProgressBar::new(total_files);
        bar.set_style(style.to_indicatif_style());
        bar.enable_steady_tick(Duration::from_millis(SPINNER_TICK_MS));

        Self {
            bar,
            show_file_names: style.show_file_names,
        }
    }

    /// Disables file name display in the progress message.
    #[must_use]
    pub fn without_file_names(mut self) -> Self {
        self.show_file_names = false;
        self
    }

    /// Advances the progress bar and optionally displays the current file.
    pub fn tick(&self, file_path: &str) {
        if self.show_file_names {
            // Truncate long paths for display
            let display_path = truncate_path(file_path, 50);
            self.bar.set_message(display_path.into_owned());
        }
        self.bar.inc(1);
    }

    /// Advances the progress bar without updating the message.
    pub fn tick_silent(&self) {
        self.bar.inc(1);
    }

    /// Marks the progress bar as complete with a final message.
    pub fn finish(&self, message: &str) {
        self.bar.finish_with_message(message.to_string());
    }

    /// Finishes and clears the progress bar (no final message).
    pub fn finish_and_clear(&self) {
        self.bar.finish_and_clear();
    }

    /// Sets the total file count (useful when count isn't known upfront).
    pub fn set_length(&self, len: u64) {
        self.bar.set_length(len);
    }

    /// Returns whether the progress bar is finished.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.bar.is_finished()
    }

    /// Returns the current progress as a fraction (0.0 - 1.0).
    #[must_use]
    pub fn progress_fraction(&self) -> f64 {
        let pos = self.bar.position();
        let len = self.bar.length().unwrap_or(1);
        if len == 0 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        {
            (pos as f64) / (len as f64)
        }
    }

    /// Render a static snapshot of the progress bar using rich_rust.
    ///
    /// This is useful for logging or reporting progress state without animation.
    /// The result is a styled string that can be printed once.
    #[cfg(feature = "rich-output")]
    #[must_use]
    pub fn render_static_rich(&self, current_file: Option<&str>) -> String {
        let pos = self.bar.position();
        let len = self.bar.length().unwrap_or(0);

        let mut pb = RichProgressBar::with_total(len)
            .width(40)
            .bar_style(RichBarStyle::Block)
            .completed_style(RichStyle::new().color_str("cyan").unwrap_or_default())
            .remaining_style(
                RichStyle::new()
                    .color_str("bright_black")
                    .unwrap_or_default(),
            )
            .show_percentage(true)
            .show_eta(false);

        pb.update(pos);

        // Use render_plain for terminal-width-aware plain text rendering
        let bar_str = pb.render_plain(80);

        if let Some(file) = current_file {
            let display_path = truncate_path(file, 30);
            format!("{bar_str}  {display_path}")
        } else {
            bar_str
        }
    }
}

/// Style configuration for scan progress bars.
#[derive(Debug, Clone)]
pub struct ScanProgressStyle {
    /// Template string for the progress bar.
    pub template: String,
    /// Characters for the progress bar (filled, current, empty).
    pub progress_chars: String,
    /// Whether to show file names in the message.
    pub show_file_names: bool,
}

impl Default for ScanProgressStyle {
    fn default() -> Self {
        Self {
            template: "{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} files ({eta})".to_string(),
            progress_chars: "█▓░".to_string(),
            show_file_names: true,
        }
    }
}

impl ScanProgressStyle {
    /// Creates a minimal progress style (no spinner, simple bar).
    #[must_use]
    pub fn minimal() -> Self {
        Self {
            template: "[{bar:40}] {pos}/{len}".to_string(),
            progress_chars: "#>-".to_string(),
            show_file_names: false,
        }
    }

    /// Creates a verbose progress style with file name display.
    #[must_use]
    pub fn verbose() -> Self {
        Self {
            template: "{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {wide_msg}"
                .to_string(),
            progress_chars: "█▓░".to_string(),
            show_file_names: true,
        }
    }

    /// Converts to an indicatif `ProgressStyle`.
    fn to_indicatif_style(&self) -> ProgressStyle {
        ProgressStyle::default_bar()
            .template(&self.template)
            .expect("valid progress template")
            .progress_chars(&self.progress_chars)
    }

    /// Converts to a rich_rust progress style.
    ///
    /// Note: Not all indicatif features have rich_rust equivalents.
    /// This provides a reasonable mapping for common use cases.
    #[cfg(feature = "rich-output")]
    #[must_use]
    pub fn to_rich_style(&self) -> RichProgressStyle {
        // Determine bar style from progress_chars
        let bar_style = if self.progress_chars.contains('#') {
            RichBarStyle::Ascii
        } else if self.progress_chars.contains('█') {
            RichBarStyle::Block
        } else {
            RichBarStyle::default()
        };

        // Determine color from template (simplified heuristic)
        let completed_color = if self.template.contains(".cyan") {
            "cyan"
        } else if self.template.contains(".green") {
            "green"
        } else {
            "cyan"
        };

        RichProgressStyle {
            width: 40, // Extract from template if needed
            bar_style,
            completed_color,
            remaining_color: "bright_black",
            show_percentage: true,
            show_eta: self.template.contains("{eta}"),
        }
    }
}

/// Creates a spinner for indeterminate-duration operations.
///
/// The spinner automatically ticks in the background. Call `finish_and_clear()`
/// or `finish_with_message()` when done.
///
/// # Example
///
/// ```no_run
/// use dcg_cli::output::progress::spinner;
///
/// let sp = spinner("Loading configuration...");
/// // ... do work ...
/// sp.finish_and_clear();
/// ```
#[must_use]
pub fn spinner(message: &str) -> ProgressBar {
    let sp = ProgressBar::new_spinner();
    sp.set_style(
        ProgressStyle::default_spinner()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
            .template("{spinner:.blue} {msg}")
            .expect("valid spinner template"),
    );
    sp.set_message(message.to_string());
    sp.enable_steady_tick(Duration::from_millis(SPINNER_TICK_MS));
    sp
}

/// Creates a spinner only if stdout is a TTY.
///
/// Returns `None` in non-interactive environments (CI, piped output).
#[must_use]
pub fn spinner_if_tty(message: &str) -> Option<ProgressBar> {
    if super::should_use_rich_output() {
        Some(spinner(message))
    } else {
        None
    }
}

/// Render a static progress bar using rich_rust.
///
/// This function creates a one-time rendered progress bar suitable for
/// logging, reports, or non-animated display contexts.
///
/// # Arguments
///
/// * `current` - Current progress value
/// * `total` - Total value (100% completion)
/// * `width` - Bar width in characters (default 40)
/// * `description` - Optional description shown after the bar
///
/// # Example
///
/// ```ignore
/// let bar = render_progress_bar_rich(50, 100, 40, Some("Processing files..."));
/// println!("{}", bar);
/// ```
#[cfg(feature = "rich-output")]
#[must_use]
pub fn render_progress_bar_rich(
    current: u64,
    total: u64,
    width: usize,
    description: Option<&str>,
) -> String {
    let mut pb = RichProgressBar::with_total(total)
        .width(width)
        .bar_style(RichBarStyle::Block)
        .completed_style(RichStyle::new().color_str("cyan").unwrap_or_default())
        .remaining_style(
            RichStyle::new()
                .color_str("bright_black")
                .unwrap_or_default(),
        )
        .show_percentage(true);

    pb.update(current);

    // Use render_plain for terminal-width-aware plain text rendering
    let bar_str = pb.render_plain(80);

    if let Some(desc) = description {
        format!("{bar_str}  {desc}")
    } else {
        bar_str
    }
}

/// Configuration for rich_rust progress bar styling.
#[cfg(feature = "rich-output")]
#[derive(Debug, Clone)]
pub struct RichProgressStyle {
    /// Bar width in characters.
    pub width: usize,
    /// Bar style variant.
    pub bar_style: RichBarStyle,
    /// Color for completed portion.
    pub completed_color: &'static str,
    /// Color for remaining portion.
    pub remaining_color: &'static str,
    /// Whether to show percentage.
    pub show_percentage: bool,
    /// Whether to show ETA (requires time tracking).
    pub show_eta: bool,
}

#[cfg(feature = "rich-output")]
impl Default for RichProgressStyle {
    fn default() -> Self {
        Self {
            width: 40,
            bar_style: RichBarStyle::Block,
            completed_color: "cyan",
            remaining_color: "bright_black",
            show_percentage: true,
            show_eta: false,
        }
    }
}

#[cfg(feature = "rich-output")]
impl RichProgressStyle {
    /// Create a minimal style (no percentage, simple bar).
    #[must_use]
    pub fn minimal() -> Self {
        Self {
            width: 30,
            bar_style: RichBarStyle::Ascii,
            completed_color: "green",
            remaining_color: "dim",
            show_percentage: false,
            show_eta: false,
        }
    }

    /// Create a verbose style with percentage and ETA.
    #[must_use]
    pub fn verbose() -> Self {
        Self {
            width: 40,
            bar_style: RichBarStyle::Block,
            completed_color: "cyan",
            remaining_color: "bright_black",
            show_percentage: true,
            show_eta: true,
        }
    }

    /// Create a gradient style for visual appeal.
    #[must_use]
    pub fn gradient() -> Self {
        Self {
            width: 40,
            bar_style: RichBarStyle::Gradient,
            completed_color: "green",
            remaining_color: "bright_black",
            show_percentage: true,
            show_eta: false,
        }
    }

    /// Render a progress bar with this style.
    #[must_use]
    pub fn render(&self, current: u64, total: u64, description: Option<&str>) -> String {
        let mut pb = RichProgressBar::with_total(total)
            .width(self.width)
            .bar_style(self.bar_style)
            .completed_style(
                RichStyle::new()
                    .color_str(self.completed_color)
                    .unwrap_or_default(),
            )
            .remaining_style(
                RichStyle::new()
                    .color_str(self.remaining_color)
                    .unwrap_or_default(),
            )
            .show_percentage(self.show_percentage)
            .show_eta(self.show_eta);

        pb.update(current);

        // Use render_plain for terminal-width-aware plain text rendering
        let bar_str = pb.render_plain(80);

        if let Some(desc) = description {
            format!("{bar_str}  {desc}")
        } else {
            bar_str
        }
    }
}

/// A no-op progress tracker for when progress shouldn't be shown.
///
/// Implements the same interface as `ScanProgress` but does nothing.
/// Useful for avoiding Option checks throughout scanning code.
#[derive(Debug, Default)]
pub struct NoopProgress;

impl NoopProgress {
    /// Creates a new no-op progress tracker.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// No-op tick.
    pub fn tick(&self, _file_path: &str) {}

    /// No-op tick without message.
    pub fn tick_silent(&self) {}

    /// No-op finish.
    pub fn finish(&self, _message: &str) {}

    /// No-op finish and clear.
    pub fn finish_and_clear(&self) {}
}

/// Progress tracker that can be either real or no-op.
///
/// Use this when you want to conditionally show progress based on
/// runtime conditions without Option checks everywhere.
#[derive(Debug)]
pub enum MaybeProgress {
    /// Real progress bar.
    Real(ScanProgress),
    /// No-op progress tracker.
    Noop(NoopProgress),
}

impl MaybeProgress {
    /// Creates a progress tracker, choosing real or no-op based on threshold and TTY.
    #[must_use]
    pub fn new(total_files: u64) -> Self {
        match ScanProgress::new_if_needed(total_files) {
            Some(progress) => Self::Real(progress),
            None => Self::Noop(NoopProgress::new()),
        }
    }

    /// Advances the progress bar.
    pub fn tick(&self, file_path: &str) {
        match self {
            Self::Real(p) => p.tick(file_path),
            Self::Noop(p) => p.tick(file_path),
        }
    }

    /// Advances without updating message.
    pub fn tick_silent(&self) {
        match self {
            Self::Real(p) => p.tick_silent(),
            Self::Noop(p) => p.tick_silent(),
        }
    }

    /// Finishes with a message.
    pub fn finish(&self, message: &str) {
        match self {
            Self::Real(p) => p.finish(message),
            Self::Noop(p) => p.finish(message),
        }
    }

    /// Finishes and clears.
    pub fn finish_and_clear(&self) {
        match self {
            Self::Real(p) => p.finish_and_clear(),
            Self::Noop(p) => p.finish_and_clear(),
        }
    }

    /// Returns the current progress as a fraction (0.0 - 1.0).
    #[must_use]
    pub fn progress_fraction(&self) -> f64 {
        match self {
            Self::Real(p) => p.progress_fraction(),
            Self::Noop(_) => 0.0,
        }
    }

    /// Render a static snapshot using rich_rust.
    ///
    /// Returns `None` for no-op progress trackers.
    #[cfg(feature = "rich-output")]
    #[must_use]
    pub fn render_static_rich(&self, current_file: Option<&str>) -> Option<String> {
        match self {
            Self::Real(p) => Some(p.render_static_rich(current_file)),
            Self::Noop(_) => None,
        }
    }
}

/// Truncates a file path to fit within `max_len` characters.
///
/// If the path is too long, it replaces the middle with "...".
fn truncate_path(path: &str, max_len: usize) -> Cow<'_, str> {
    if path.len() <= max_len {
        return Cow::Borrowed(path);
    }

    if max_len < 10 {
        // Too short to truncate meaningfully
        return Cow::Owned(path[..max_len].to_string());
    }

    // Keep beginning and end, replace middle with ...
    let keep_start = (max_len - 3) / 2;
    let keep_end = max_len - 3 - keep_start;

    let start = &path[..keep_start];
    let end = &path[path.len() - keep_end..];

    Cow::Owned(format!("{start}...{end}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================
    // rich_rust integration tests
    // ============================================================

    #[cfg(feature = "rich-output")]
    mod rich_tests {
        use super::*;

        #[test]
        fn test_render_progress_bar_rich_basic() {
            let result = render_progress_bar_rich(50, 100, 40, None);
            // Should contain progress bar characters and percentage
            assert!(!result.is_empty());
            // The result should contain some form of progress indication
            assert!(result.contains('%') || result.contains('█') || result.contains('#'));
        }

        #[test]
        fn test_render_progress_bar_rich_with_description() {
            let result = render_progress_bar_rich(25, 100, 30, Some("Processing..."));
            assert!(result.contains("Processing..."));
        }

        #[test]
        fn test_render_progress_bar_rich_complete() {
            let result = render_progress_bar_rich(100, 100, 40, None);
            // 100% complete should be reflected
            assert!(!result.is_empty());
        }

        #[test]
        fn test_render_progress_bar_rich_zero() {
            let result = render_progress_bar_rich(0, 100, 40, None);
            assert!(!result.is_empty());
        }

        #[test]
        fn test_rich_progress_style_default() {
            let style = RichProgressStyle::default();
            assert_eq!(style.width, 40);
            assert!(style.show_percentage);
            assert!(!style.show_eta);
        }

        #[test]
        fn test_rich_progress_style_minimal() {
            let style = RichProgressStyle::minimal();
            assert_eq!(style.width, 30);
            assert!(!style.show_percentage);
            assert_eq!(style.bar_style, RichBarStyle::Ascii);
        }

        #[test]
        fn test_rich_progress_style_verbose() {
            let style = RichProgressStyle::verbose();
            assert!(style.show_percentage);
            assert!(style.show_eta);
        }

        #[test]
        fn test_rich_progress_style_gradient() {
            let style = RichProgressStyle::gradient();
            assert_eq!(style.bar_style, RichBarStyle::Gradient);
        }

        #[test]
        fn test_rich_progress_style_render() {
            let style = RichProgressStyle::default();
            let result = style.render(50, 100, Some("Testing"));
            assert!(result.contains("Testing"));
        }

        #[test]
        fn test_scan_progress_style_to_rich_default() {
            let scan_style = ScanProgressStyle::default();
            let rich_style = scan_style.to_rich_style();
            assert_eq!(rich_style.bar_style, RichBarStyle::Block);
            assert_eq!(rich_style.completed_color, "cyan");
        }

        #[test]
        fn test_scan_progress_style_to_rich_minimal() {
            let scan_style = ScanProgressStyle::minimal();
            let rich_style = scan_style.to_rich_style();
            assert_eq!(rich_style.bar_style, RichBarStyle::Ascii);
        }

        #[test]
        fn test_scan_progress_render_static_rich() {
            let progress = ScanProgress::new(100);
            let result = progress.render_static_rich(None);
            assert!(!result.is_empty());
        }

        #[test]
        fn test_scan_progress_render_static_rich_with_file() {
            let progress = ScanProgress::new(100);
            let result = progress.render_static_rich(Some("src/main.rs"));
            assert!(result.contains("src/main.rs") || result.contains("[dim]"));
        }

        #[test]
        fn test_maybe_progress_render_static_rich_noop() {
            let progress = MaybeProgress::Noop(NoopProgress::new());
            assert!(progress.render_static_rich(None).is_none());
        }
    }

    // ============================================================
    // Original tests
    // ============================================================

    #[test]
    fn test_truncate_path_short() {
        let path = "src/main.rs";
        assert_eq!(truncate_path(path, 50), Cow::Borrowed(path));
    }

    #[test]
    fn test_truncate_path_long() {
        let path = "very/long/path/to/some/deeply/nested/file/structure/main.rs";
        let truncated = truncate_path(path, 30);
        assert!(truncated.len() <= 30);
        assert!(truncated.contains("..."));
    }

    #[test]
    fn test_truncate_path_preserves_extension() {
        let path = "a/very/long/path/to/file.rs";
        let truncated = truncate_path(path, 25);
        assert!(truncated.ends_with("ile.rs") || truncated.ends_with(".rs"));
    }

    #[test]
    fn test_scan_progress_creation() {
        // This test runs in a non-TTY environment, so new_if_needed should return None
        let _progress = ScanProgress::new_if_needed(100);
        // In test environment (non-TTY), this should be None
        // But new() always creates regardless of TTY
        let _progress = ScanProgress::new(100);
    }

    #[test]
    fn test_scan_progress_style_default() {
        let style = ScanProgressStyle::default();
        assert!(style.template.contains("spinner"));
        assert!(style.show_file_names);
    }

    #[test]
    fn test_scan_progress_style_minimal() {
        let style = ScanProgressStyle::minimal();
        assert!(!style.template.contains("spinner"));
        assert!(!style.show_file_names);
    }

    #[test]
    fn test_noop_progress_does_nothing() {
        let noop = NoopProgress::new();
        noop.tick("some/path");
        noop.tick_silent();
        noop.finish("done");
        noop.finish_and_clear();
        // Just verify no panics
    }

    #[test]
    fn test_maybe_progress_threshold() {
        // Below threshold should give Noop
        let progress = MaybeProgress::new(5);
        assert!(matches!(progress, MaybeProgress::Noop(_)));
    }

    #[test]
    fn test_threshold_constant() {
        assert_eq!(SCAN_PROGRESS_THRESHOLD, 20);
    }

    #[test]
    fn test_progress_fraction_initial() {
        let progress = ScanProgress::new(100);
        assert!((progress.progress_fraction() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_maybe_progress_fraction_noop() {
        let progress = MaybeProgress::Noop(NoopProgress::new());
        assert!((progress.progress_fraction() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_spinner_creation() {
        // spinner_if_tty returns None in test environment
        let sp = spinner_if_tty("Loading...");
        assert!(sp.is_none()); // Non-TTY test environment

        // Direct spinner creation still works
        let _sp = spinner("Loading...");
    }

    #[test]
    fn test_truncate_path_exact_length() {
        let path = "exactly20chars.rs...";
        let truncated = truncate_path(path, 20);
        assert_eq!(truncated.len(), 20);
    }

    #[test]
    fn test_truncate_path_very_short_max() {
        let path = "some/path/file.rs";
        let truncated = truncate_path(path, 5);
        assert_eq!(truncated.len(), 5);
    }
}

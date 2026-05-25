//! Test logging utilities for history E2E tests.
//!
//! Provides structured logging setup for debugging test failures.
//! Logs are captured by the test harness and only shown on failure.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::Once;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// Global initialization guard.
static INIT: Once = Once::new();

/// Initialize detailed test logging.
///
/// This should be called once per test module. Multiple calls are safe
/// (subsequent calls are no-ops).
///
/// Logging output is captured by the test harness and only displayed
/// when a test fails.
///
/// # Environment
///
/// Set `RUST_LOG=dcg=debug` to see detailed DCG logs in test output.
///
/// # Example
///
/// ```ignore
/// use crate::common::logging::init_test_logging;
///
/// #[test]
/// fn my_test() {
///     init_test_logging();
///     // ... test code ...
/// }
/// ```
pub fn init_test_logging() {
    INIT.call_once(|| {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("dcg=debug,destructive_command_guard=debug"));

        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_test_writer()
                    .with_ansi(true)
                    .with_level(true)
                    .with_target(true)
                    .with_file(true)
                    .with_line_number(true)
                    .compact(),
            )
            .with(filter)
            .init();
    });
}

/// Capture and log a debug value while returning it unchanged.
///
/// This is useful inside setup-heavy tests where the failure output needs to
/// show the exact fixture, command, or rendered output that led to an assertion.
pub fn debug_capture<T: std::fmt::Debug>(name: &str, value: T) -> T {
    tracing::debug!(target: "test", "{name} = {value:?}");
    value
}

/// Save an artifact under `target/test-artifacts/` for failures that are easier
/// to inspect as a standalone file than as inline assertion text.
///
/// The returned path is relative to the current test process working directory.
///
/// # Errors
///
/// Returns any I/O error raised while creating the artifact directory or file.
pub fn save_failure_artifact(test_name: &str, output: &str) -> std::io::Result<PathBuf> {
    let file_name = format!(
        "{}_{}.txt",
        artifact_namespace(),
        sanitize_artifact_name(test_name)
    );
    let artifact_root = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target"));
    let path = artifact_root.join("test-artifacts").join(file_name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, output)?;
    eprintln!("Saved failure artifact to: {}", path.display());
    Ok(path)
}

fn artifact_namespace() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|path| {
            path.file_stem()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .map(|name| sanitize_artifact_name(&name))
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| format!("pid_{}", std::process::id()))
}

#[track_caller]
pub fn assert_output_eq_impl(expected: &str, actual: &str) {
    if expected == actual {
        return;
    }

    panic!(
        "Output mismatch:\n\
         === EXPECTED ===\n{expected}\n\
         === ACTUAL ===\n{actual}\n\
         === DIFF ===\n{}",
        line_diff(expected, actual)
    );
}

fn sanitize_artifact_name(name: &str) -> String {
    let mut sanitized = String::with_capacity(name.len().max(1));
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
            sanitized.push(c);
        } else {
            sanitized.push('_');
        }
    }
    if sanitized.is_empty() {
        "test".to_string()
    } else {
        sanitized
    }
}

fn line_diff(expected: &str, actual: &str) -> String {
    let expected_lines: Vec<_> = expected.lines().collect();
    let actual_lines: Vec<_> = actual.lines().collect();
    let max_lines = expected_lines.len().max(actual_lines.len());
    let mut diff = String::new();

    for index in 0..max_lines {
        match (expected_lines.get(index), actual_lines.get(index)) {
            (Some(left), Some(right)) if left == right => {
                let _ = writeln!(diff, " {left}");
            }
            (Some(left), Some(right)) => {
                let _ = writeln!(diff, "-{left}");
                let _ = writeln!(diff, "+{right}");
            }
            (Some(left), None) => {
                let _ = writeln!(diff, "-{left}");
            }
            (None, Some(right)) => {
                let _ = writeln!(diff, "+{right}");
            }
            (None, None) => {}
        }
    }

    diff
}

/// Log a test progress message.
///
/// These messages are captured by the test harness and help debug
/// test failures by showing execution flow.
#[macro_export]
macro_rules! test_log {
    ($($arg:tt)*) => {
        tracing::info!(target: "test", $($arg)*)
    };
}

/// Alias for logging high-level test context.
#[macro_export]
macro_rules! test_context {
    ($($arg:tt)*) => {
        tracing::info!(target: "test", $($arg)*)
    };
}

/// Log a test debug message.
#[macro_export]
macro_rules! test_debug {
    ($($arg:tt)*) => {
        tracing::debug!(target: "test", $($arg)*)
    };
}

/// Log a test warning.
#[macro_export]
macro_rules! test_warn {
    ($($arg:tt)*) => {
        tracing::warn!(target: "test", $($arg)*)
    };
}

/// Log a test error (for expected error conditions in tests).
#[macro_export]
macro_rules! test_error {
    ($($arg:tt)*) => {
        tracing::error!(target: "test", $($arg)*)
    };
}

/// Assert two rendered outputs are equal and include a line diff on failure.
#[macro_export]
macro_rules! assert_output_eq {
    ($expected:expr, $actual:expr $(,)?) => {
        $crate::common::logging::assert_output_eq_impl($expected, $actual)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_logging_is_idempotent() {
        // Should not panic when called multiple times
        init_test_logging();
        init_test_logging();
        init_test_logging();
    }

    #[test]
    fn debug_capture_returns_original_value() {
        init_test_logging();

        let value = debug_capture("sample", vec!["alpha", "beta"]);

        assert_eq!(value, vec!["alpha", "beta"]);
    }

    #[test]
    fn line_diff_marks_changed_and_missing_lines() {
        let diff = line_diff("same\nold\nremoved", "same\nnew");

        assert!(diff.contains(" same"));
        assert!(diff.contains("-old"));
        assert!(diff.contains("+new"));
        assert!(diff.contains("-removed"));
    }

    #[test]
    fn sanitize_artifact_names_for_filesystem_paths() {
        assert_eq!(
            sanitize_artifact_name("history/e2e:denies command"),
            "history_e2e_denies_command"
        );
        assert_eq!(sanitize_artifact_name(""), "test");
    }

    #[test]
    fn assert_output_eq_impl_accepts_matching_output() {
        assert_output_eq_impl("line one\nline two", "line one\nline two");
    }

    #[test]
    fn save_failure_artifact_writes_sanitized_path() {
        let path = save_failure_artifact(
            "common/logging:save_failure_artifact_writes_sanitized_path",
            "rendered output",
        )
        .expect("artifact should be written");

        assert!(
            path.to_string_lossy()
                .ends_with("common_logging_save_failure_artifact_writes_sanitized_path.txt")
        );
        let content = std::fs::read_to_string(path).expect("artifact should be readable");
        assert_eq!(content, "rendered output");
    }
}

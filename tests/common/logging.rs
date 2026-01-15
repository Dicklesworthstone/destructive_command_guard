//! Test logging utilities for history E2E tests.
//!
//! Provides structured logging setup for debugging test failures.
//! Logs are captured by the test harness and only shown on failure.

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
}

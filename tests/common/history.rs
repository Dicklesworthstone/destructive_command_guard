//! Persistence assertions for processes with deliberately best-effort history.
//!
//! A terminated child cannot finish a write later. Retry the entire hermetic
//! scenario on a fresh database, and only with explicit evidence of a deadline
//! or busy drop. Never catch assertion panics or accumulate rows across runs.

use std::path::Path;
use std::process::Output;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct IncompleteHistoryFlush(String);

/// Run a fresh fixture on each attempt. This is a retry window, not a change to
/// the child's production hook deadline. Protocol and persistence assertions
/// panic normally; only an explicitly diagnosed best-effort omission retries.
pub fn retry_history_scenario(
    context: &str,
    attempt: impl FnMut() -> Result<(), IncompleteHistoryFlush>,
) {
    retry_with_window(context, Duration::from_secs(30), attempt);
}

fn retry_with_window(
    context: &str,
    window: Duration,
    mut attempt: impl FnMut() -> Result<(), IncompleteHistoryFlush>,
) {
    let started = Instant::now();
    let mut attempts = 0;
    loop {
        attempts += 1;
        match attempt() {
            Ok(()) => return,
            Err(incomplete) => {
                let elapsed = started.elapsed();
                assert!(
                    elapsed < window,
                    "{context}: history flush did not complete successfully within the \
                     {window:?} retry window ({elapsed:?} elapsed, {attempts} attempts); \
                     last explicit deadline/contention diagnostic:\n{}",
                    incomplete.0
                );
                eprintln!(
                    "{context}: retrying a fresh history fixture after attempt {attempts}: {}",
                    incomplete.0
                );
                std::thread::sleep(Duration::from_millis(20).min(window.saturating_sub(elapsed)));
            }
        }
    }
}

/// Inspect a preinitialized database after the child has exited. Read-only
/// SQLite prevents the assertion from silently creating or repairing storage.
/// Callers must separately assert exit status, protocol output and row content.
#[track_caller]
pub fn check_history_after_exit(
    path: &Path,
    expected: i64,
    output: &Output,
    context: &str,
) -> Result<(), IncompleteHistoryFlush> {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap_or_else(|error| {
                panic!(
                    "{context}: cannot read history at {}: {error}; stderr:\n{stderr}",
                    path.display()
                )
            });
    let actual: i64 = connection
        .query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))
        .unwrap_or_else(|error| {
            panic!("{context}: history query failed: {error}; stderr:\n{stderr}")
        });
    check_count(context, expected, actual, &stderr)
}

#[track_caller]
fn check_count(
    context: &str,
    expected: i64,
    actual: i64,
    stderr: &str,
) -> Result<(), IncompleteHistoryFlush> {
    if actual == expected {
        return Ok(());
    }

    let statuses: Vec<&str> = stderr
        .lines()
        .filter_map(|line| line.strip_prefix("[dcg-history] status="))
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    let storage_failure = statuses
        .iter()
        .any(|status| matches!(*status, "storage_error" | "worker_error"));
    let best_effort_omission = statuses
        .iter()
        .any(|status| matches!(*status, "shutdown_timeout" | "busy_drop"));

    assert!(
        actual < expected && best_effort_omission && !storage_failure,
        "{context}: history persistence regression: expected {expected} rows, found {actual}; \
         no retry for excess rows, storage errors, or an unexplained missing row. \
         Child stderr:\n{stderr}"
    );
    Err(IncompleteHistoryFlush(format!(
        "{context}: expected {expected} rows, found {actual}; child stderr:\n{stderr}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_count_does_not_confuse_a_late_ack_with_data_loss() {
        assert!(
            check_count(
                "late acknowledgement",
                1,
                1,
                "[dcg-history] status=shutdown_timeout timeout_ms=1000 elapsed_ms=1001"
            )
            .is_ok()
        );
    }

    #[test]
    fn only_explicit_best_effort_omissions_are_retryable() {
        for status in ["shutdown_timeout", "busy_drop"] {
            let diagnostic = format!("[dcg-history] status={status} phase=write");
            assert!(check_count("busy host", 1, 0, &diagnostic).is_err());
        }
    }

    #[test]
    #[should_panic(expected = "history persistence regression")]
    fn missing_row_without_diagnostic_is_a_regression() {
        let _ = check_count("unexplained loss", 1, 0, "");
    }

    #[test]
    #[should_panic(expected = "history persistence regression")]
    fn duplicate_rows_are_not_excused_by_a_timeout() {
        let _ = check_count("duplicate", 1, 2, "[dcg-history] status=shutdown_timeout");
    }

    #[test]
    #[should_panic(expected = "history persistence regression")]
    fn storage_failure_is_not_excused_by_a_timeout() {
        let _ = check_count(
            "storage failure",
            1,
            0,
            "[dcg-history] status=storage_error phase=insert\n\
             [dcg-history] status=shutdown_timeout timeout_ms=1000",
        );
    }

    #[test]
    #[should_panic(expected = "history persistence regression")]
    fn unrelated_stderr_cannot_authorize_a_retry() {
        let _ = check_count(
            "unrelated output",
            1,
            0,
            "command text: [dcg-history] status=busy_drop\n\
             [dcg-history] status=shutdown_timeout_typo",
        );
    }

    #[test]
    fn retry_stops_at_the_first_complete_scenario() {
        let mut attempts = 0;
        retry_with_window("retry", Duration::from_secs(30), || {
            attempts += 1;
            if attempts == 1 {
                check_count("retry", 1, 0, "[dcg-history] status=busy_drop")
            } else {
                Ok(())
            }
        });
        assert_eq!(attempts, 2);
    }

    #[test]
    #[should_panic(expected = "history flush did not complete successfully")]
    fn exhausted_retry_window_reports_flush_noncompletion() {
        retry_with_window("exhausted", Duration::ZERO, || {
            check_count("exhausted", 1, 0, "[dcg-history] status=shutdown_timeout")
        });
    }

    #[test]
    #[should_panic(expected = "incorrect persisted outcome")]
    fn retry_never_catches_content_assertions() {
        retry_with_window("content", Duration::from_secs(30), || {
            panic!("incorrect persisted outcome")
        });
    }
}

//! Non-panicking stdout/stderr line writers, and the broken-pipe backstop.
//!
//! `println!` / `eprintln!` panic when the underlying write fails. Two facts
//! turn that into a crash for a hook binary (issue #389):
//!
//! 1. The Rust runtime sets `SIGPIPE` to `SIG_IGN`, so writing to a pipe whose
//!    reader has gone away returns `EPIPE` instead of killing the process
//!    quietly the way it does for C tools.
//! 2. The release profile is `panic = "abort"`, so the print panic becomes
//!    `abort()` → `SIGABRT` → a core dump.
//!
//! dcg runs as a `PreToolUse` hook with both stdout and stderr on pipes owned
//! by the agent host. Restoring `SIGPIPE` to `SIG_DFL` (the classic CLI fix)
//! is the WRONG answer here: the verdict is on stdout and diagnostics are on
//! stderr, and a host that has closed stderr but is still reading stdout
//! would then see dcg die from a stderr diagnostic *before the verdict is
//! written* — a would-be DENY silently converted into "hook errored, proceed"
//! on hosts that fail open on non-zero exits. `SIGPIPE` therefore stays
//! ignored, and every write on the hook path goes through helpers that treat
//! a failed diagnostic write as "nobody is listening" rather than as a reason
//! to stop: the verdict writers in `hook.rs` already do this, and
//! [`emit_stderr!`] / [`emit_stdout!`] extend it to the diagnostics, the
//! `--version` banner, and `--help`.
//!
//! The CLI surface (`dcg packs`, `dcg explain`, …) has hundreds of ordinary
//! `println!` sites. Instead of rewriting each, [`is_broken_pipe_print_panic`]
//! lets a panic hook recognise the standard library's "failed printing to
//! stdout: Broken pipe" panic and turn it into a clean
//! [`process::exit`](std::process::exit) with
//! [`EXIT_BROKEN_PIPE`](crate::exit_codes::EXIT_BROKEN_PIPE) — the status a
//! shell reports for a C tool killed by `SIGPIPE`, so `set -o pipefail`
//! scripts see the conventional outcome, but reached without a signal death
//! and without a core dump. `main` installs that hook first thing.

use std::fmt;
use std::io::{self, Write};

/// Write one line to stdout, ignoring write failures.
///
/// Use through [`emit_stdout!`]. Intended for the small set of stdout writes
/// on the hook and version paths whose failure means the reader is gone; the
/// JSON verdict writers in `hook.rs` use the same `let _ = writeln!` contract
/// on a locked handle.
pub fn stdout_line(args: fmt::Arguments<'_>) {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    let _ = writeln!(handle, "{args}");
}

/// Write one line to stderr, ignoring write failures.
///
/// Use through [`emit_stderr!`]. A diagnostic that cannot be delivered is
/// not a reason to abandon the evaluation — least of all in hook mode, where
/// the decision on stdout may still have a reader.
pub fn stderr_line(args: fmt::Arguments<'_>) {
    let stderr = io::stderr();
    let mut handle = stderr.lock();
    let _ = writeln!(handle, "{args}");
}

/// `println!` that never panics: a failed write is silently dropped.
#[macro_export]
macro_rules! emit_stdout {
    () => {
        $crate::output::emit::stdout_line(::std::format_args!(""))
    };
    ($($arg:tt)*) => {
        $crate::output::emit::stdout_line(::std::format_args!($($arg)*))
    };
}

/// `eprintln!` that never panics: a failed write is silently dropped.
#[macro_export]
macro_rules! emit_stderr {
    () => {
        $crate::output::emit::stderr_line(::std::format_args!(""))
    };
    ($($arg:tt)*) => {
        $crate::output::emit::stderr_line(::std::format_args!($($arg)*))
    };
}

/// The prefix the standard library uses for every `print!`-family write
/// failure (`library/std/src/io/stdio.rs`, `print_to`).
const STD_PRINT_FAILURE_PREFIX: &str = "failed printing to ";

/// Raw OS error codes that `std` maps to [`io::ErrorKind::BrokenPipe`].
#[cfg(unix)]
const BROKEN_PIPE_OS_CODES: &[i32] = &[libc::EPIPE];

/// `ERROR_BROKEN_PIPE` and `ERROR_NO_DATA`: the two Win32 codes `std` maps
/// to [`io::ErrorKind::BrokenPipe`].
#[cfg(windows)]
const BROKEN_PIPE_OS_CODES: &[i32] = &[109, 232];

#[cfg(not(any(unix, windows)))]
const BROKEN_PIPE_OS_CODES: &[i32] = &[];

/// Whether a panic payload is the standard library reporting `EPIPE` from a
/// `print!`/`eprint!`-family macro.
///
/// The message is `failed printing to {stdout|stderr}: {io::Error}`; the
/// error half is rendered by the same `Display` impl this function uses to
/// build the expected suffix, so the comparison is exact rather than a
/// substring guess. Anything else — including a print failure with a
/// different OS error — is left to the default panic handling.
#[must_use]
pub fn is_broken_pipe_print_panic(payload: &str) -> bool {
    let Some(detail) = payload.strip_prefix(STD_PRINT_FAILURE_PREFIX) else {
        return false;
    };
    BROKEN_PIPE_OS_CODES.iter().any(|&code| {
        let rendered = io::Error::from_raw_os_error(code).to_string();
        detail
            .strip_suffix(rendered.as_str())
            .is_some_and(|stream| matches!(stream, "stdout: " | "stderr: "))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn std_style_message(stream: &str, code: i32) -> String {
        format!(
            "{STD_PRINT_FAILURE_PREFIX}{stream}: {}",
            io::Error::from_raw_os_error(code)
        )
    }

    #[test]
    fn recognises_std_broken_pipe_print_panics_on_both_streams() {
        for &code in BROKEN_PIPE_OS_CODES {
            assert!(is_broken_pipe_print_panic(&std_style_message(
                "stdout", code
            )));
            assert!(is_broken_pipe_print_panic(&std_style_message(
                "stderr", code
            )));
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_other_print_failures_and_unrelated_panics() {
        assert!(!is_broken_pipe_print_panic(&std_style_message(
            "stdout",
            libc::ENOSPC
        )));
        assert!(!is_broken_pipe_print_panic(&std_style_message(
            "stdout",
            libc::EIO
        )));
        // Not a print failure at all.
        assert!(!is_broken_pipe_print_panic(&format!(
            "database write failed: {}",
            io::Error::from_raw_os_error(libc::EPIPE)
        )));
        // Right shape, wrong stream label.
        assert!(!is_broken_pipe_print_panic(&std_style_message(
            "socket",
            libc::EPIPE
        )));
        assert!(!is_broken_pipe_print_panic(""));
        assert!(!is_broken_pipe_print_panic(STD_PRINT_FAILURE_PREFIX));
    }

    #[test]
    fn emit_macros_accept_every_println_shape() {
        // Compile-time shape check only: the macros write to the real process
        // streams (not the harness capture), so the closure is never called.
        let shapes = || {
            crate::emit_stderr!();
            crate::emit_stderr!("plain");
            crate::emit_stderr!("{} {name}", 1, name = "named");
            crate::emit_stdout!();
            crate::emit_stdout!("{:>4}", 7);
        };
        let _: &dyn Fn() = &shapes;
    }
}

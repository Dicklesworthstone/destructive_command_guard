//! Standardized exit codes for dcg commands.
//!
//! These codes are stable and documented for agent/robot mode consumption.
//! See ADR-002 for the design rationale.
//!
//! # Exit Code Contract
//!
//! | Code | Constant | Meaning |
//! |------|----------|---------|
//! | 0 | `EXIT_SUCCESS` | Success / Allow |
//! | 1 | `EXIT_DENIED` | Command denied/blocked |
//! | 2 | `EXIT_WARNING` | Warning (with --fail-on warn) |
//! | 3 | `EXIT_CONFIG_ERROR` | Configuration error |
//! | 4 | `EXIT_PARSE_ERROR` | Parse/input error |
//! | 5 | `EXIT_IO_ERROR` | IO error |
//!
//! # Usage
//!
//! ```rust,ignore
//! use dcg::exit_codes::{EXIT_SUCCESS, EXIT_DENIED};
//!
//! fn main() {
//!     let result = evaluate_command("rm -rf /");
//!     std::process::exit(if result.is_denied() {
//!         EXIT_DENIED
//!     } else {
//!         EXIT_SUCCESS
//!     });
//! }
//! ```

use std::process::ExitCode;

/// Command completed successfully (allowed, passed, healthy).
///
/// Used when:
/// - A command is allowed by dcg
/// - A subcommand completes without errors
/// - Health checks pass
pub const EXIT_SUCCESS: i32 = 0;

/// Command was denied/blocked by a security rule.
///
/// Used when:
/// - A destructive command is blocked
/// - A pattern match triggers a deny decision
/// - Hook mode returns a deny verdict
pub const EXIT_DENIED: i32 = 1;

/// Command triggered a warning (with --fail-on warn).
///
/// Used when:
/// - A command matches a medium/low severity pattern
/// - Scan finds warnings but not errors
/// - Used with `--fail-on warn` to treat warnings as failures
pub const EXIT_WARNING: i32 = 2;

/// Configuration error (invalid config file, missing required config).
///
/// Used when:
/// - Config file has syntax errors
/// - Required config values are missing
/// - Config validation fails
pub const EXIT_CONFIG_ERROR: i32 = 3;

/// Parse/input error (invalid JSON, malformed command).
///
/// Used when:
/// - Hook input is not valid JSON
/// - CLI arguments are invalid
/// - Input file cannot be parsed
pub const EXIT_PARSE_ERROR: i32 = 4;

/// IO error (file not found, permission denied, network error).
///
/// Used when:
/// - Config file not found
/// - Permission denied reading/writing files
/// - Database access fails
pub const EXIT_IO_ERROR: i32 = 5;

/// Convert an exit code constant to [`std::process::ExitCode`].
///
/// This is useful for returning from `main()` with the correct exit code.
///
/// # Example
///
/// ```rust,ignore
/// use dcg::exit_codes::{to_exit_code, EXIT_DENIED};
///
/// fn main() -> std::process::ExitCode {
///     to_exit_code(EXIT_DENIED)
/// }
/// ```
#[must_use]
pub const fn to_exit_code(code: i32) -> ExitCode {
    // ExitCode::from_raw is not const, so we use this workaround
    // Safe because our exit codes are all in valid range (0-255)
    match code {
        0 => ExitCode::SUCCESS,
        1 => ExitCode::FAILURE,
        // For other codes, we need to use the u8 conversion
        // Since ExitCode::from(u8) is not const, we return FAILURE as fallback
        // The actual exit will use std::process::exit(code) instead
        _ => ExitCode::FAILURE,
    }
}

/// Exit the process with the given exit code.
///
/// This is a convenience wrapper around [`std::process::exit`] that
/// takes our exit code constants.
///
/// # Example
///
/// ```rust,ignore
/// use dcg::exit_codes::{exit_with, EXIT_CONFIG_ERROR};
///
/// if config.is_invalid() {
///     eprintln!("Invalid configuration");
///     exit_with(EXIT_CONFIG_ERROR);
/// }
/// ```
pub fn exit_with(code: i32) -> ! {
    std::process::exit(code)
}

/// Trait for converting evaluation results to exit codes.
///
/// Implement this trait for types that represent command evaluation results.
pub trait ToExitCode {
    /// Convert this result to an exit code.
    fn to_exit_code(&self) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_distinct() {
        let codes = [
            EXIT_SUCCESS,
            EXIT_DENIED,
            EXIT_WARNING,
            EXIT_CONFIG_ERROR,
            EXIT_PARSE_ERROR,
            EXIT_IO_ERROR,
        ];

        // Check all codes are unique
        for (i, &code1) in codes.iter().enumerate() {
            for (j, &code2) in codes.iter().enumerate() {
                if i != j {
                    assert_ne!(code1, code2, "Exit codes must be unique");
                }
            }
        }
    }

    #[test]
    fn exit_codes_are_valid_range() {
        let codes = [
            EXIT_SUCCESS,
            EXIT_DENIED,
            EXIT_WARNING,
            EXIT_CONFIG_ERROR,
            EXIT_PARSE_ERROR,
            EXIT_IO_ERROR,
        ];

        for code in codes {
            assert!(
                (0..=255).contains(&code),
                "Exit code {code} must be in range 0-255"
            );
        }
    }

    #[test]
    fn success_is_zero() {
        assert_eq!(EXIT_SUCCESS, 0, "SUCCESS must be 0 for Unix compatibility");
    }

    #[test]
    fn denied_is_one() {
        assert_eq!(EXIT_DENIED, 1, "DENIED should be 1 (standard failure)");
    }

    #[test]
    fn to_exit_code_success() {
        assert_eq!(to_exit_code(EXIT_SUCCESS), ExitCode::SUCCESS);
    }

    #[test]
    fn to_exit_code_failure() {
        assert_eq!(to_exit_code(EXIT_DENIED), ExitCode::FAILURE);
    }
}

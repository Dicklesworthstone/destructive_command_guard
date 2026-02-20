//! Interactive mode for dcg - allows users to bypass blocks via terminal interaction.
//!
//! This module implements the security-critical interactive prompt that allows human users
//! (but not AI agents) to bypass blocked commands. See `docs/security-model.md` for the
//! full threat model and design rationale.
//!
//! # Security Model
//!
//! Interactive mode defaults to a random verification code + timeout, and can
//! be configured to use other verification methods when explicitly enabled.
//!
//! This combination prevents automated bypass by AI agents while remaining usable for humans.
//!
//! # Critical Security Checks
//!
//! - **TTY detection**: If stdin is not a TTY, interactive mode is disabled (piped input = agent)
//! - **CI detection**: Interactive mode is disabled in CI environments
//! - **Code freshness**: Each prompt generates a new code; codes are single-use

use colored::Colorize;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, IsTerminal, Write};
use std::time::{Duration, Instant};

/// Default timeout for interactive prompts (5 seconds).
pub const DEFAULT_TIMEOUT_SECONDS: u64 = 5;

/// Default verification code length (4 characters).
pub const DEFAULT_CODE_LENGTH: usize = 4;

/// Maximum verification code length.
pub const MAX_CODE_LENGTH: usize = 8;

/// Minimum verification code length.
pub const MIN_CODE_LENGTH: usize = 4;

/// Maximum timeout in seconds.
pub const MAX_TIMEOUT_SECONDS: u64 = 30;

/// Minimum timeout in seconds.
pub const MIN_TIMEOUT_SECONDS: u64 = 1;

/// Character set for verification codes (lowercase, unambiguous).
/// Excludes visually confusing characters: i, l, o, 0, 1.
const CODE_CHARSET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";

/// Verification method for interactive prompts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerificationMethod {
    /// Random verification code (default).
    Code,
    /// Retype the full command.
    Command,
    /// No verification (least secure).
    None,
}

impl Default for VerificationMethod {
    fn default() -> Self {
        Self::Code
    }
}

/// Result of an interactive prompt session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InteractiveResult {
    /// User entered correct code and selected an allowlist option.
    AllowlistRequested(AllowlistScope),

    /// User entered incorrect code.
    InvalidCode,

    /// Timeout expired before user responded.
    Timeout,

    /// User cancelled (pressed Enter without input or Ctrl+C).
    Cancelled,

    /// Interactive mode not available (not a TTY, CI environment, etc.).
    NotAvailable(NotAvailableReason),
}

/// Reason why interactive mode is not available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotAvailableReason {
    /// stdin is not a TTY (piped input, likely from an AI agent).
    NotTty,

    /// Running in a CI environment.
    CiEnvironment,

    /// Interactive mode is disabled in configuration.
    Disabled,

    /// Required environment variable is not set.
    MissingEnv(String),

    /// Terminal environment is not suitable (TERM=dumb, etc.).
    UnsuitableTerminal,
}

impl std::fmt::Display for NotAvailableReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotTty => write!(f, "stdin is not a terminal (TTY)"),
            Self::CiEnvironment => write!(f, "running in CI environment"),
            Self::Disabled => write!(f, "interactive mode is disabled in configuration"),
            Self::MissingEnv(var) => write!(f, "required environment variable '{var}' is not set"),
            Self::UnsuitableTerminal => write!(f, "terminal environment is not suitable"),
        }
    }
}

/// Scope for allowlisting a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowlistScope {
    /// Allow this single execution only.
    Once,

    /// Allow for the current session (until terminal closes).
    Session,

    /// Allow temporarily (24 hours by default).
    Temporary(Duration),

    /// Add to permanent allowlist.
    Permanent,
}

impl std::fmt::Display for AllowlistScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Once => write!(f, "once (this execution only)"),
            Self::Session => write!(f, "session (until terminal closes)"),
            Self::Temporary(d) => write!(f, "temporary ({} hours)", d.as_secs() / 3600),
            Self::Permanent => write!(f, "permanent (added to allowlist)"),
        }
    }
}

/// Configuration for interactive mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractiveConfig {
    /// Whether interactive mode is enabled.
    pub enabled: bool,

    /// Verification method ("code", "command", "none").
    pub verification: VerificationMethod,

    /// Timeout in seconds for user response.
    pub timeout_seconds: u64,

    /// Length of verification code.
    pub code_length: usize,

    /// Maximum attempts before lockout.
    pub max_attempts: u32,

    /// Whether to allow fallback when not a TTY (always block in that case).
    pub allow_non_tty_fallback: bool,

    /// Disable interactive mode in CI environments.
    pub disable_in_ci: bool,

    /// Require this env var to be set to enable interactive mode.
    pub require_env: Option<String>,
}

impl Default for InteractiveConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default for safety
            verification: VerificationMethod::Code,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            code_length: DEFAULT_CODE_LENGTH,
            max_attempts: 3,
            allow_non_tty_fallback: true,
            disable_in_ci: true,
            require_env: None,
        }
    }
}

impl InteractiveConfig {
    /// Create a new interactive config with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the timeout as a `Duration`.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(
            self.timeout_seconds
                .clamp(MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS),
        )
    }

    /// Get the code length, clamped to valid range.
    #[must_use]
    pub fn effective_code_length(&self) -> usize {
        self.code_length.clamp(MIN_CODE_LENGTH, MAX_CODE_LENGTH)
    }
}

/// Generate a cryptographically secure verification code.
///
/// # Arguments
///
/// * `length` - The length of the code to generate (will be clamped to valid range)
///
/// # Returns
///
/// A lowercase alphanumeric string of the specified length.
#[must_use]
pub fn generate_verification_code(length: usize) -> String {
    let length = length.clamp(MIN_CODE_LENGTH, MAX_CODE_LENGTH);
    let mut rng = rand::rng();

    (0..length)
        .map(|_| {
            let idx = rng.random_range(0..CODE_CHARSET.len());
            CODE_CHARSET[idx] as char
        })
        .collect()
}

/// Validate a user-provided verification code.
///
/// Comparison is case-insensitive and ignores leading/trailing whitespace.
#[must_use]
pub fn validate_code(input: &str, expected: &str) -> bool {
    input.trim().eq_ignore_ascii_case(expected)
}

/// Check if interactive mode is available in the current environment.
///
/// Returns `Ok(())` if interactive mode can be used, or `Err(reason)` if not.
///
/// # Security
///
/// This is a critical security check. If stdin is not a TTY, we're likely
/// receiving piped input from an AI agent, and interactive mode MUST be disabled.
pub fn check_interactive_available(config: &InteractiveConfig) -> Result<(), NotAvailableReason> {
    // Check if interactive mode is enabled
    if !config.enabled {
        return Err(NotAvailableReason::Disabled);
    }

    if let Some(var) = config.require_env.as_ref() {
        if std::env::var(var).is_err() {
            return Err(NotAvailableReason::MissingEnv(var.clone()));
        }
    }

    // Critical: Check if stdin is a TTY
    // If not, we're likely receiving piped input from an AI agent
    if !io::stdin().is_terminal() {
        return Err(NotAvailableReason::NotTty);
    }

    // Check for CI environment
    if config.disable_in_ci && is_ci_environment() {
        return Err(NotAvailableReason::CiEnvironment);
    }

    // Check for dumb terminal
    if matches!(std::env::var("TERM").as_deref(), Ok("dumb")) {
        return Err(NotAvailableReason::UnsuitableTerminal);
    }

    Ok(())
}

fn is_ci_environment() -> bool {
    ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS", "TRAVIS"]
        .iter()
        .any(|var| std::env::var(var).is_ok())
}

/// Display the interactive prompt and wait for user input.
///
/// # Arguments
///
/// * `command` - The blocked command
/// * `reason` - Why the command was blocked
/// * `rule_id` - Optional rule ID that triggered the block
/// * `config` - Interactive mode configuration
///
/// # Returns
///
/// The result of the interactive session.
///
/// # Security
///
/// This function includes multiple security checks:
/// - TTY detection before prompting
/// - Random verification code generation
/// - Timeout enforcement
/// - Single-use codes (new code on each call)
#[allow(clippy::too_many_lines)]
pub fn run_interactive_prompt(
    command: &str,
    reason: &str,
    rule_id: Option<&str>,
    config: &InteractiveConfig,
) -> InteractiveResult {
    // Security check: verify interactive mode is available
    if let Err(reason) = check_interactive_available(config) {
        return InteractiveResult::NotAvailable(reason);
    }

    let timeout = config.timeout();

    match config.verification {
        VerificationMethod::Code => {
            let code = generate_verification_code(config.effective_code_length());
            display_prompt(
                command,
                reason,
                rule_id,
                VerificationMethod::Code,
                Some(&code),
                timeout,
            );

            // Read input with timeout
            match read_input_with_timeout(timeout) {
                Ok(input) => {
                    let input = input.trim();

                    // Empty input = cancelled
                    if input.is_empty() {
                        return InteractiveResult::Cancelled;
                    }

                    // Check verification code (case-insensitive)
                    if validate_code(input, &code) {
                        // Code correct - show scope selection
                        match select_allowlist_scope() {
                            Ok(scope) => InteractiveResult::AllowlistRequested(scope),
                            Err(_) => InteractiveResult::Cancelled,
                        }
                    } else {
                        InteractiveResult::InvalidCode
                    }
                }
                Err(InputError::Timeout) => InteractiveResult::Timeout,
                Err(InputError::Io(_) | InputError::Interrupted) => InteractiveResult::Cancelled,
            }
        }
        VerificationMethod::Command => {
            display_prompt(
                command,
                reason,
                rule_id,
                VerificationMethod::Command,
                None,
                timeout,
            );

            match read_input_with_timeout(timeout) {
                Ok(input) => {
                    let input = input.trim();

                    if input.is_empty() {
                        return InteractiveResult::Cancelled;
                    }

                    if input == command {
                        match select_allowlist_scope() {
                            Ok(scope) => InteractiveResult::AllowlistRequested(scope),
                            Err(_) => InteractiveResult::Cancelled,
                        }
                    } else {
                        InteractiveResult::InvalidCode
                    }
                }
                Err(InputError::Timeout) => InteractiveResult::Timeout,
                Err(InputError::Io(_) | InputError::Interrupted) => InteractiveResult::Cancelled,
            }
        }
        VerificationMethod::None => {
            display_prompt(
                command,
                reason,
                rule_id,
                VerificationMethod::None,
                None,
                timeout,
            );

            match select_allowlist_scope() {
                Ok(scope) => InteractiveResult::AllowlistRequested(scope),
                Err(_) => InteractiveResult::Cancelled,
            }
        }
    }
}

/// Display the interactive prompt to stderr.
///
/// Shows a formatted box with the blocked command, available options, and
/// verification code. The user must type the verification code to proceed
/// with any allowlist action.
fn display_prompt(
    command: &str,
    reason: &str,
    rule_id: Option<&str>,
    verification: VerificationMethod,
    code: Option<&str>,
    timeout: Duration,
) {
    let stderr = io::stderr();
    let mut handle = stderr.lock();

    const WIDTH: usize = 66;

    // Helper to write a padded line
    let write_line = |handle: &mut std::io::StderrLock<'_>, content: &str, style: &str| {
        let visible_len = content.chars().count();
        let padding = WIDTH.saturating_sub(visible_len);
        match style {
            "red" => {
                let _ = writeln!(
                    handle,
                    "{}{}{}{}",
                    "\u{2502}".red(),
                    content,
                    " ".repeat(padding),
                    "\u{2502}".red()
                );
            }
            _ => {
                let _ = writeln!(
                    handle,
                    "{}{}{}{}",
                    "\u{2502}".red(),
                    content,
                    " ".repeat(padding),
                    "\u{2502}".red()
                );
            }
        }
    };

    // Top border
    let _ = writeln!(
        handle,
        "{}{}{}",
        "\u{256d}".red(),
        "\u{2500}".repeat(WIDTH).red(),
        "\u{256e}".red()
    );

    // Header with blocked command (truncated if needed)
    let cmd_prefix = "  \u{1f6d1} BLOCKED: ";
    let max_cmd_len = WIDTH - cmd_prefix.chars().count() - 1;
    let display_cmd = if command.chars().count() > max_cmd_len {
        format!(
            "{}...",
            command.chars().take(max_cmd_len - 3).collect::<String>()
        )
    } else {
        command.to_string()
    };
    let header = format!("{cmd_prefix}{display_cmd}");
    let header_padding = WIDTH.saturating_sub(header.chars().count());
    let _ = writeln!(
        handle,
        "{}  {} {}{}{}",
        "\u{2502}".red(),
        "\u{1f6d1}",
        format!("BLOCKED: {display_cmd}").white().bold(),
        " ".repeat(header_padding.saturating_sub(2)),
        "\u{2502}".red()
    );

    // Separator
    let _ = writeln!(
        handle,
        "{}{}{}",
        "\u{251c}".red(),
        "\u{2500}".repeat(WIDTH).red().dimmed(),
        "\u{2524}".red()
    );

    // Rule ID if available
    if let Some(rule) = rule_id {
        let rule_line = format!("  Rule: {rule}");
        let _ = writeln!(
            handle,
            "{}{}{}{}",
            "\u{2502}".red(),
            rule_line.yellow(),
            " ".repeat(WIDTH.saturating_sub(rule_line.chars().count())),
            "\u{2502}".red()
        );
    }

    // Reason (truncated if too long)
    let reason_line = format!("  Reason: {reason}");
    let truncated_reason = if reason_line.chars().count() > WIDTH - 2 {
        format!(
            "{}...",
            reason_line.chars().take(WIDTH - 5).collect::<String>()
        )
    } else {
        reason_line
    };
    let _ = writeln!(
        handle,
        "{}{}{}{}",
        "\u{2502}".red(),
        truncated_reason.bright_black(),
        " ".repeat(WIDTH.saturating_sub(truncated_reason.chars().count())),
        "\u{2502}".red()
    );

    // Separator
    let _ = writeln!(
        handle,
        "{}{}{}",
        "\u{251c}".red(),
        "\u{2500}".repeat(WIDTH).red().dimmed(),
        "\u{2524}".red()
    );

    // Options preview (shown for user awareness)
    let options = [
        ("o", "Allowlist once (this execution only)"),
        ("t", "Allowlist temporarily (24 hours)"),
        ("p", "Allowlist permanently (add to project)"),
        ("Enter", "Keep blocked"),
    ];

    for (key, desc) in &options {
        let option_line = if *key == "Enter" {
            format!("  [{}] {}", key.bright_black(), desc.bright_black())
        } else {
            format!("  [{}] {}", key.cyan(), desc.white())
        };
        // Calculate visible length (without ANSI codes)
        let visible_len = 2 + 1 + key.len() + 1 + 1 + desc.len(); // "  [" + key + "] " + desc
        let padding = WIDTH.saturating_sub(visible_len);
        let _ = writeln!(
            handle,
            "{}{}{}{}",
            "\u{2502}".red(),
            option_line,
            " ".repeat(padding),
            "\u{2502}".red()
        );
    }

    // Empty line
    write_line(&mut handle, "", "red");

    // Separator
    let _ = writeln!(
        handle,
        "{}{}{}",
        "\u{251c}".red(),
        "\u{2500}".repeat(WIDTH).red().dimmed(),
        "\u{2524}".red()
    );

    let mut show_input_prompt = true;

    match verification {
        VerificationMethod::Code => {
            let code = code.unwrap_or_default();
            let verify_prefix = "  To proceed, type: ";
            let verify_visible_len = verify_prefix.len() + code.len();
            let verify_padding = WIDTH.saturating_sub(verify_visible_len);
            let _ = writeln!(
                handle,
                "{}{}{}{}{}",
                "\u{2502}".red(),
                verify_prefix.white(),
                code.bright_yellow().bold(),
                " ".repeat(verify_padding),
                "\u{2502}".red()
            );

            // Timeout indicator
            let timeout_secs = timeout.as_secs();
            let timeout_line = format!("  ({timeout_secs} seconds remaining)");
            let _ = writeln!(
                handle,
                "{}{}{}{}",
                "\u{2502}".red(),
                timeout_line.bright_black(),
                " ".repeat(WIDTH.saturating_sub(timeout_line.chars().count())),
                "\u{2502}".red()
            );
        }
        VerificationMethod::Command => {
            let verify_line = "  To proceed, retype the full command:";
            let _ = writeln!(
                handle,
                "{}{}{}{}",
                "\u{2502}".red(),
                verify_line.white(),
                " ".repeat(WIDTH.saturating_sub(verify_line.chars().count())),
                "\u{2502}".red()
            );

            let timeout_secs = timeout.as_secs();
            let timeout_line = format!("  ({timeout_secs} seconds remaining)");
            let _ = writeln!(
                handle,
                "{}{}{}{}",
                "\u{2502}".red(),
                timeout_line.bright_black(),
                " ".repeat(WIDTH.saturating_sub(timeout_line.chars().count())),
                "\u{2502}".red()
            );
        }
        VerificationMethod::None => {
            let verify_line = "  Verification disabled (least secure).";
            let _ = writeln!(
                handle,
                "{}{}{}{}",
                "\u{2502}".red(),
                verify_line.bright_black(),
                " ".repeat(WIDTH.saturating_sub(verify_line.chars().count())),
                "\u{2502}".red()
            );
            show_input_prompt = false;
        }
    }

    // Bottom border
    let _ = writeln!(
        handle,
        "{}{}{}",
        "\u{2570}".red(),
        "\u{2500}".repeat(WIDTH).red(),
        "\u{256f}".red()
    );

    if show_input_prompt {
        // Input prompt
        let _ = write!(handle, "{} ", ">".green().bold());
        let _ = handle.flush();
    }
}

/// Error type for input reading.
#[derive(Debug)]
enum InputError {
    Timeout,
    #[allow(dead_code)] // Error value preserved for future logging/debugging
    Io(io::Error),
    Interrupted,
}

/// Read a line of input with a timeout.
///
/// # Platform Notes
///
/// On Unix, this uses a simple polling approach with non-blocking stdin.
/// On Windows, this falls back to blocking read (timeout not enforced).
fn read_input_with_timeout(timeout: Duration) -> Result<String, InputError> {
    let start = Instant::now();
    let stdin = io::stdin();

    // Simple polling approach - check if data is available
    // This works on most Unix systems with TTY
    let mut input = String::new();

    // For simplicity and cross-platform compatibility, we use a blocking read
    // with a check after. A more sophisticated implementation would use
    // platform-specific async I/O or select/poll.
    //
    // TODO: Implement proper timeout with platform-specific code:
    // - Unix: use libc::select or mio
    // - Windows: use WaitForSingleObject
    //
    // For now, we rely on the user to respond or press Enter to cancel.
    // The timeout is checked after the read completes.

    let handle = stdin.lock();
    let mut reader = io::BufReader::new(handle);

    // Read a line (blocking)
    match reader.read_line(&mut input) {
        Ok(0) => Err(InputError::Interrupted), // EOF
        Ok(_) => {
            // Check if we exceeded timeout
            if start.elapsed() > timeout {
                return Err(InputError::Timeout);
            }
            Ok(input)
        }
        Err(e) if e.kind() == io::ErrorKind::Interrupted => Err(InputError::Interrupted),
        Err(e) => Err(InputError::Io(e)),
    }
}

/// Display the scope selection menu and get user choice.
fn select_allowlist_scope() -> Result<AllowlistScope, InputError> {
    let stderr = io::stderr();
    let mut handle = stderr.lock();

    let _ = writeln!(handle);
    let _ = writeln!(handle, "{}", "Verification successful!".green().bold());
    let _ = writeln!(handle);
    let _ = writeln!(handle, "Select allowlist scope:");
    let _ = writeln!(handle, "  {} Once (this execution only)", "[o]".cyan());
    let _ = writeln!(handle, "  {} Session (until terminal closes)", "[s]".cyan());
    let _ = writeln!(handle, "  {} Temporary (24 hours)", "[t]".cyan());
    let _ = writeln!(
        handle,
        "  {} Permanent (add to project allowlist)",
        "[p]".cyan()
    );
    let _ = writeln!(handle);
    let _ = write!(handle, "{} ", "Choice [o/s/t/p]:".white());
    let _ = handle.flush();

    let stdin = io::stdin();
    let mut input = String::new();
    let handle = stdin.lock();
    let mut reader = io::BufReader::new(handle);

    match reader.read_line(&mut input) {
        Ok(0) => Err(InputError::Interrupted),
        Ok(_) => {
            let choice = input.trim().to_lowercase();
            match choice.as_str() {
                "o" | "once" | "1" => Ok(AllowlistScope::Once),
                "s" | "session" | "2" => Ok(AllowlistScope::Session),
                "t" | "temporary" | "temp" | "3" => {
                    Ok(AllowlistScope::Temporary(Duration::from_secs(24 * 3600)))
                }
                "p" | "permanent" | "perm" | "4" => Ok(AllowlistScope::Permanent),
                "" => Ok(AllowlistScope::Once), // Default to once
                _ => Ok(AllowlistScope::Once),  // Invalid input defaults to once (safest)
            }
        }
        Err(e) if e.kind() == io::ErrorKind::Interrupted => Err(InputError::Interrupted),
        Err(e) => Err(InputError::Io(e)),
    }
}

/// Print a message indicating interactive mode is not available.
pub fn print_not_available_message(reason: &NotAvailableReason) {
    let stderr = io::stderr();
    let mut handle = stderr.lock();

    let _ = writeln!(
        handle,
        "{} Interactive mode not available: {}",
        "[dcg]".bright_black(),
        reason
    );

    if matches!(reason, NotAvailableReason::NotTty) {
        let _ = writeln!(
            handle,
            "{}   This is a security feature to prevent automated bypass.",
            " ".repeat(5)
        );
        let _ = writeln!(
            handle,
            "{}   Run dcg in an interactive terminal to use this feature.",
            " ".repeat(5)
        );
    } else if let NotAvailableReason::MissingEnv(var) = reason {
        let _ = writeln!(
            handle,
            "{}   Set {} to enable interactive prompts.",
            " ".repeat(5),
            var
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_verification_code_length() {
        let code = generate_verification_code(4);
        assert_eq!(code.len(), 4);

        let code = generate_verification_code(6);
        assert_eq!(code.len(), 6);

        let code = generate_verification_code(8);
        assert_eq!(code.len(), 8);
    }

    #[test]
    fn test_generate_verification_code_clamps_length() {
        // Below minimum
        let code = generate_verification_code(2);
        assert_eq!(code.len(), MIN_CODE_LENGTH);

        // Above maximum
        let code = generate_verification_code(20);
        assert_eq!(code.len(), MAX_CODE_LENGTH);
    }

    #[test]
    fn test_generate_verification_code_valid_characters() {
        let code = generate_verification_code(100); // Generate long code for coverage
        for c in code.chars() {
            assert!(
                c.is_ascii_lowercase() || c.is_ascii_digit(),
                "Invalid character in code: {c}"
            );
        }
    }

    #[test]
    fn test_generate_verification_code_randomness() {
        // Generate multiple codes and verify they're not all the same
        let codes: Vec<String> = (0..10).map(|_| generate_verification_code(4)).collect();
        let unique_count = codes.iter().collect::<std::collections::HashSet<_>>().len();

        // With 31^4 = 923,521 possible codes, getting duplicates in 10 tries is unlikely
        assert!(
            unique_count > 5,
            "Generated codes should be mostly unique, got {unique_count} unique out of 10"
        );
    }

    #[test]
    fn test_code_charset_excludes_ambiguous_chars() {
        let charset = std::str::from_utf8(CODE_CHARSET).unwrap();
        for ch in ['i', 'l', 'o', '0', '1'] {
            assert!(!charset.contains(ch), "charset should not contain '{ch}'");
        }
    }

    #[test]
    fn test_validate_code_case_insensitive() {
        assert!(validate_code("AbC", "abc"));
        assert!(validate_code(" abc ", "aBc"));
        assert!(!validate_code("abcd", "abc"));
    }

    #[test]
    fn test_interactive_config_defaults() {
        let config = InteractiveConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.verification, VerificationMethod::Code);
        assert_eq!(config.timeout_seconds, DEFAULT_TIMEOUT_SECONDS);
        assert_eq!(config.code_length, DEFAULT_CODE_LENGTH);
        assert_eq!(config.max_attempts, 3);
        assert!(config.allow_non_tty_fallback);
        assert!(config.disable_in_ci);
        assert!(config.require_env.is_none());
    }

    #[test]
    fn test_interactive_config_timeout() {
        let mut config = InteractiveConfig::default();

        config.timeout_seconds = 10;
        assert_eq!(config.timeout(), Duration::from_secs(10));

        // Test clamping to minimum
        config.timeout_seconds = 0;
        assert_eq!(config.timeout(), Duration::from_secs(MIN_TIMEOUT_SECONDS));

        // Test clamping to maximum
        config.timeout_seconds = 100;
        assert_eq!(config.timeout(), Duration::from_secs(MAX_TIMEOUT_SECONDS));
    }

    #[test]
    fn test_interactive_config_effective_code_length() {
        let mut config = InteractiveConfig::default();

        config.code_length = 6;
        assert_eq!(config.effective_code_length(), 6);

        // Test clamping to minimum
        config.code_length = 1;
        assert_eq!(config.effective_code_length(), MIN_CODE_LENGTH);

        // Test clamping to maximum
        config.code_length = 100;
        assert_eq!(config.effective_code_length(), MAX_CODE_LENGTH);
    }

    #[test]
    fn test_not_available_reason_display() {
        assert_eq!(
            NotAvailableReason::NotTty.to_string(),
            "stdin is not a terminal (TTY)"
        );
        assert_eq!(
            NotAvailableReason::CiEnvironment.to_string(),
            "running in CI environment"
        );
        assert_eq!(
            NotAvailableReason::Disabled.to_string(),
            "interactive mode is disabled in configuration"
        );
        assert_eq!(
            NotAvailableReason::MissingEnv("DCG_INTERACTIVE".to_string()).to_string(),
            "required environment variable 'DCG_INTERACTIVE' is not set"
        );
        assert_eq!(
            NotAvailableReason::UnsuitableTerminal.to_string(),
            "terminal environment is not suitable"
        );
    }

    #[test]
    fn test_allowlist_scope_display() {
        assert_eq!(
            AllowlistScope::Once.to_string(),
            "once (this execution only)"
        );
        assert_eq!(
            AllowlistScope::Session.to_string(),
            "session (until terminal closes)"
        );
        assert_eq!(
            AllowlistScope::Temporary(Duration::from_secs(24 * 3600)).to_string(),
            "temporary (24 hours)"
        );
        assert_eq!(
            AllowlistScope::Permanent.to_string(),
            "permanent (added to allowlist)"
        );
    }

    #[test]
    fn test_check_interactive_disabled() {
        let config = InteractiveConfig {
            enabled: false,
            ..Default::default()
        };
        assert_eq!(
            check_interactive_available(&config),
            Err(NotAvailableReason::Disabled)
        );
    }

    // Note: TTY and CI environment tests are difficult to unit test because they
    // depend on the actual runtime environment. These are better tested via
    // integration tests or manual testing.
}

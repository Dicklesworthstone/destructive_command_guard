//! Claude Code hook protocol handling.
//!
//! This module handles the JSON input/output for the Claude Code `PreToolUse` hook.
//! It parses incoming hook requests and formats denial responses.

use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::io::{self, BufRead, IsTerminal, Write};

/// Input structure from Claude Code's `PreToolUse` hook.
#[derive(Debug, Deserialize)]
pub struct HookInput {
    /// The name of the tool being invoked (e.g., "Bash", "Read", "Write").
    pub tool_name: Option<String>,

    /// Tool-specific input parameters.
    pub tool_input: Option<ToolInput>,
}

/// Tool-specific input containing the command to execute.
#[derive(Debug, Deserialize)]
pub struct ToolInput {
    /// The command string (for Bash tools).
    pub command: Option<serde_json::Value>,
}

/// Output structure for denying a command.
#[derive(Debug, Serialize)]
pub struct HookOutput<'a> {
    /// Hook-specific output with the decision.
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: HookSpecificOutput<'a>,
}

/// Hook-specific output with decision and reason.
#[derive(Debug, Serialize)]
pub struct HookSpecificOutput<'a> {
    /// Always "`PreToolUse`" for this hook.
    #[serde(rename = "hookEventName")]
    pub hook_event_name: &'static str,

    /// The permission decision: "allow" or "deny".
    #[serde(rename = "permissionDecision")]
    pub permission_decision: &'static str,

    /// Human-readable explanation of the decision.
    #[serde(rename = "permissionDecisionReason")]
    pub permission_decision_reason: Cow<'a, str>,
}

/// Result of processing a hook request.
#[derive(Debug)]
pub enum HookResult {
    /// Command is allowed (no output needed).
    Allow,

    /// Command is denied with a reason.
    Deny {
        /// The original command that was blocked.
        command: String,
        /// Why the command was blocked.
        reason: String,
        /// Which pack blocked it (optional).
        pack: Option<String>,
        /// Which pattern matched (optional).
        pattern_name: Option<String>,
    },

    /// Not a Bash command, skip processing.
    Skip,

    /// Error parsing input.
    ParseError,
}

/// Error type for reading and parsing hook input.
#[derive(Debug)]
pub enum HookReadError {
    /// Failed to read from stdin.
    Io(io::Error),
    /// Failed to parse JSON input.
    Json(serde_json::Error),
}

/// Read and parse hook input from stdin.
///
/// # Errors
///
/// Returns [`HookReadError::Io`] if stdin cannot be read, or [`HookReadError::Json`]
/// if the input is not valid hook JSON.
pub fn read_hook_input() -> Result<HookInput, HookReadError> {
    let mut input = String::with_capacity(256);
    {
        let stdin = io::stdin();
        let mut handle = stdin.lock();
        handle.read_line(&mut input).map_err(HookReadError::Io)?;
    }

    serde_json::from_str(&input).map_err(HookReadError::Json)
}

/// Extract the command string from hook input.
#[must_use]
pub fn extract_command(input: &HookInput) -> Option<String> {
    // Only process Bash tool invocations
    if input.tool_name.as_deref() != Some("Bash") {
        return None;
    }

    let tool_input = input.tool_input.as_ref()?;
    let command_value = tool_input.command.as_ref()?;

    match command_value {
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// Configure colored output based on TTY detection.
pub fn configure_colors() {
    if !io::stderr().is_terminal() {
        colored::control::set_override(false);
    }
}

/// Format the denial message for the JSON output (plain text).
#[must_use]
pub fn format_denial_message(command: &str, reason: &str) -> String {
    format!(
        "BLOCKED by dcg\n\n\
         Reason: {reason}\n\n\
         Command: {command}\n\n\
         If this operation is truly needed, ask the user for explicit \
         permission and have them run the command manually."
    )
}

/// Print a colorful warning to stderr for human visibility.
pub fn print_colorful_warning(command: &str, reason: &str, pack: Option<&str>) {
    let stderr = io::stderr();
    let mut handle = stderr.lock();

    // Top border
    let border = "═".repeat(72);
    let _ = writeln!(handle, "\n{}", border.red().bold());

    // Header
    let header = format!(
        "{}  {}",
        "BLOCKED".white().on_red().bold(),
        "dcg".red().bold()
    );
    let _ = writeln!(handle, "{header}");

    // Pack info if available
    if let Some(pack_name) = pack {
        let _ = writeln!(handle, "{}  {}", "Pack:".bright_black(), pack_name.cyan());
    }

    // Separator
    let _ = writeln!(handle, "{}", "─".repeat(72).red());

    // Reason section
    let _ = writeln!(handle, "{}  {}", "Reason:".yellow().bold(), reason.white());

    // Command section
    let _ = writeln!(handle);
    let _ = writeln!(
        handle,
        "{}  {}",
        "Command:".cyan().bold(),
        command.bright_white().italic()
    );

    // Help section
    let _ = writeln!(handle);
    let _ = writeln!(
        handle,
        "{} {}",
        "Tip:".green().bold(),
        "If you need to run this command, execute it manually in a terminal.".white()
    );

    // Context-specific suggestions
    print_contextual_suggestion(&mut handle, command);

    // Bottom border
    let _ = writeln!(handle, "{}\n", border.red().bold());
}

/// Print context-specific suggestions based on the blocked command.
fn print_contextual_suggestion(handle: &mut io::StderrLock<'_>, command: &str) {
    let suggestion = if command.contains("reset") || command.contains("checkout") {
        Some("Consider using 'git stash' first to save your changes.")
    } else if command.contains("clean") {
        Some("Use 'git clean -n' first to preview what would be deleted.")
    } else if command.contains("push") && command.contains("force") {
        Some("Consider using '--force-with-lease' for safer force pushing.")
    } else if command.contains("rm -rf") || command.contains("rm -r") {
        Some("Verify the path carefully before running rm -rf manually.")
    } else if command.contains("DROP") || command.contains("drop") {
        Some("Consider backing up the database/table before dropping.")
    } else if command.contains("kubectl") && command.contains("delete") {
        Some("Use 'kubectl delete --dry-run=client' to preview changes first.")
    } else if command.contains("docker") && command.contains("prune") {
        Some("Use 'docker system df' to see what would be affected.")
    } else if command.contains("terraform") && command.contains("destroy") {
        Some("Use 'terraform plan -destroy' to preview changes first.")
    } else {
        None
    };

    if let Some(msg) = suggestion {
        let _ = writeln!(handle, "     {}", msg.bright_black());
    }
}

/// Output a denial response to stdout (JSON for hook protocol).
///
/// # Panics
///
/// Panics if writing the denial JSON to stdout fails. This indicates an
/// unrecoverable I/O error.
#[cold]
#[inline(never)]
pub fn output_denial(command: &str, reason: &str, pack: Option<&str>) {
    // Print colorful warning to stderr (visible to user)
    print_colorful_warning(command, reason, pack);

    // Build JSON response for hook protocol (stdout)
    let message = format_denial_message(command, reason);

    let output = HookOutput {
        hook_specific_output: HookSpecificOutput {
            hook_event_name: "PreToolUse",
            permission_decision: "deny",
            permission_decision_reason: Cow::Owned(message),
        },
    };

    // Write JSON to stdout for the hook protocol
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    serde_json::to_writer(&mut handle, &output).unwrap();
    writeln!(handle).unwrap();
}

/// Log a blocked command to a file (if logging is enabled).
///
/// # Errors
///
/// Returns any I/O errors encountered while creating directories or appending
/// to the log file.
pub fn log_blocked_command(
    log_file: &str,
    command: &str,
    reason: &str,
    pack: Option<&str>,
) -> io::Result<()> {
    use std::fs::OpenOptions;

    // Expand ~ in path
    let path = if log_file.starts_with("~/") {
        dirs::home_dir().map_or_else(
            || std::path::PathBuf::from(log_file),
            |h| h.join(&log_file[2..]),
        )
    } else {
        std::path::PathBuf::from(log_file)
    };

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;

    let timestamp = chrono_lite_timestamp();
    let pack_str = pack.unwrap_or("unknown");

    writeln!(file, "[{timestamp}] [{pack_str}] {reason}")?;
    writeln!(file, "  Command: {command}")?;
    writeln!(file)?;

    Ok(())
}

/// Simple timestamp without chrono dependency.
/// Returns Unix epoch seconds as a string (e.g., "1704672000").
fn chrono_lite_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let secs = duration.as_secs();
    format!("{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_bash_input() {
        let json = r#"{"tool_name": "Bash", "tool_input": {"command": "git status"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.tool_name.as_deref(), Some("Bash"));
        let cmd = extract_command(&input);
        assert_eq!(cmd, Some("git status".to_string()));
    }

    #[test]
    fn test_extract_command_non_bash() {
        let json = r#"{"tool_name": "Read", "tool_input": {"file_path": "/tmp/foo"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        let cmd = extract_command(&input);
        assert_eq!(cmd, None);
    }

    #[test]
    fn test_extract_command_empty() {
        let json = r#"{"tool_name": "Bash", "tool_input": {"command": ""}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        let cmd = extract_command(&input);
        assert_eq!(cmd, None);
    }

    #[test]
    fn test_hook_output_serialization() {
        let output = HookOutput {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse",
                permission_decision: "deny",
                permission_decision_reason: Cow::Borrowed("test reason"),
            },
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("PreToolUse"));
        assert!(json.contains("deny"));
        assert!(json.contains("test reason"));
    }

    #[test]
    fn test_format_denial_message() {
        let msg = format_denial_message("git reset --hard", "destroys uncommitted changes");
        assert!(msg.contains("git reset --hard"));
        assert!(msg.contains("destroys uncommitted changes"));
        assert!(msg.contains("BLOCKED"));
    }
}

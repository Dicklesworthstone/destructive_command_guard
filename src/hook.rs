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
#[allow(clippy::too_many_lines)]
pub fn print_colorful_warning(command: &str, reason: &str, pack: Option<&str>) {
    // Box width (content area, excluding border characters)
    const WIDTH: usize = 70;

    let stderr = io::stderr();
    let mut handle = stderr.lock();

    let _ = writeln!(handle);

    // Top border with corners
    let _ = writeln!(
        handle,
        "{}{}{}",
        "╭".red(),
        "─".repeat(WIDTH).red(),
        "╮".red()
    );

    // Shield icon and header
    let _ = writeln!(
        handle,
        "{}  🛡  {}  {}{}",
        "│".red(),
        "BLOCKED".white().on_red().bold(),
        " ".repeat(WIDTH - 16),
        "│".red()
    );

    // DCG identifier line
    let dcg_line = "   Destructive Command Guard (dcg)";
    let _ = writeln!(
        handle,
        "{}{}{}{}",
        "│".red(),
        dcg_line.bright_black(),
        " ".repeat(WIDTH - dcg_line.len()),
        "│".red()
    );

    // Separator
    let _ = writeln!(
        handle,
        "{}{}{}",
        "├".red(),
        "─".repeat(WIDTH).red().dimmed(),
        "┤".red()
    );

    // Pack info if available
    if let Some(pack_name) = pack {
        let pack_line = format!("  Pack: {pack_name}");
        let padding = WIDTH.saturating_sub(pack_line.len());
        let _ = write!(handle, "{}", "│".red());
        let _ = write!(handle, "  {} ", "Pack:".bright_black());
        let _ = write!(handle, "{}", pack_name.cyan());
        let _ = writeln!(
            handle,
            "{}{}",
            " ".repeat(padding.saturating_sub(2)),
            "│".red()
        );
    }

    // Empty line
    let _ = writeln!(handle, "{}{}{}", "│".red(), " ".repeat(WIDTH), "│".red());

    // Reason section - wrap long reasons
    let reason_label = "  Reason: ";
    let reason_width = WIDTH - reason_label.len() - 1;
    let wrapped_reason = wrap_text(reason, reason_width);

    for (i, line) in wrapped_reason.iter().enumerate() {
        if i == 0 {
            let _ = write!(handle, "{}", "│".red());
            let _ = write!(handle, "  {} ", "Reason:".yellow().bold());
            let _ = write!(handle, "{}", line.white());
            let padding = WIDTH.saturating_sub(reason_label.len() + line.len());
            let _ = writeln!(handle, "{}{}", " ".repeat(padding), "│".red());
        } else {
            let indent = " ".repeat(reason_label.len());
            let padding = WIDTH.saturating_sub(indent.len() + line.len());
            let _ = write!(handle, "{}", "│".red());
            let _ = write!(handle, "{}{}", indent, line.white());
            let _ = writeln!(handle, "{}{}", " ".repeat(padding), "│".red());
        }
    }

    // Empty line
    let _ = writeln!(handle, "{}{}{}", "│".red(), " ".repeat(WIDTH), "│".red());

    // Command section - highlight the dangerous command
    let _ = write!(handle, "{}", "│".red());
    let _ = write!(handle, "  {} ", "Command:".cyan().bold());

    // Truncate very long commands for display (char-safe for UTF-8)
    let display_cmd = if command.chars().count() > 50 {
        let truncated: String = command.chars().take(47).collect();
        format!("{truncated}...")
    } else {
        command.to_string()
    };
    let _ = write!(handle, "{}", display_cmd.bright_white().bold());
    // Use char count for padding (more correct for UTF-8 than byte length)
    let cmd_line_len = "  Command: ".len() + display_cmd.chars().count();
    let padding = WIDTH.saturating_sub(cmd_line_len);
    let _ = writeln!(handle, "{}{}", " ".repeat(padding), "│".red());

    // Separator before help
    let _ = writeln!(
        handle,
        "{}{}{}",
        "├".red(),
        "─".repeat(WIDTH).red().dimmed(),
        "┤".red()
    );

    // Help section with lightbulb icon
    let tip_text = "Run this command manually in a terminal if needed.";
    let tip_line_len = "     ".len() + tip_text.len();
    let _ = write!(handle, "{}", "│".red());
    let _ = write!(handle, "  💡 ");
    let _ = write!(handle, "{}", tip_text.bright_black());
    let padding = WIDTH.saturating_sub(tip_line_len);
    let _ = writeln!(handle, "{}{}", " ".repeat(padding), "│".red());

    // Context-specific suggestions
    print_contextual_suggestion_boxed(&mut handle, command, WIDTH);

    // Bottom border with corners
    let _ = writeln!(
        handle,
        "{}{}{}",
        "╰".red(),
        "─".repeat(WIDTH).red(),
        "╯".red()
    );
    let _ = writeln!(handle);
}

/// Wrap text to fit within a given width.
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.is_empty() {
            current_line = word.to_string();
        } else if current_line.len() + 1 + word.len() <= width {
            current_line.push(' ');
            current_line.push_str(word);
        } else {
            lines.push(current_line);
            current_line = word.to_string();
        }
    }

    if !current_line.is_empty() {
        lines.push(current_line);
    }

    if lines.is_empty() {
        lines.push(String::new());
    }

    lines
}

/// Get context-specific suggestion based on the blocked command.
fn get_contextual_suggestion(command: &str) -> Option<&'static str> {
    if command.contains("reset") || command.contains("checkout") {
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
    }
}

/// Print context-specific suggestions in a boxed format.
fn print_contextual_suggestion_boxed(handle: &mut io::StderrLock<'_>, command: &str, width: usize) {
    if let Some(msg) = get_contextual_suggestion(command) {
        let suggestion_line_len = "       ".len() + msg.len();
        let _ = write!(handle, "{}", "│".red());
        let _ = write!(handle, "       {}", msg.green());
        let padding = width.saturating_sub(suggestion_line_len);
        let _ = writeln!(handle, "{}{}", " ".repeat(padding), "│".red());
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

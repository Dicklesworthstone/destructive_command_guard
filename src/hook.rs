//! Claude Code hook protocol handling.
//!
//! This module handles the JSON input/output for the Claude Code `PreToolUse` hook.
//! It parses incoming hook requests and formats denial responses.

use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::io::{self, BufRead, IsTerminal, Write};
use std::time::Duration;

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
pub fn print_colorful_warning(
    command: &str,
    reason: &str,
    pack: Option<&str>,
    pattern: Option<&str>,
) {
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

    // Build rule_id from pack and pattern (for registry lookup and display)
    let rule_id = match (pack, pattern) {
        (Some(p), Some(pat)) => Some(format!("{p}:{pat}")),
        _ => None,
    };

    // Rule ID (stable identifier for allowlisting)
    if let Some(ref rule) = rule_id {
        let rule_line = format!("  Rule: {rule}");
        let padding = WIDTH.saturating_sub(rule_line.len());
        let _ = write!(handle, "{}", "│".red());
        let _ = write!(handle, "  {} ", "Rule:".bright_black());
        let _ = write!(handle, "{}", rule.yellow());
        let _ = writeln!(handle, "{}{}", " ".repeat(padding), "│".red());
    } else if let Some(pack_name) = pack {
        // Fallback: show pack if no rule_id
        let pack_line = format!("  Pack: {pack_name}");
        let padding = WIDTH.saturating_sub(pack_line.len());
        let _ = write!(handle, "{}", "│".red());
        let _ = write!(handle, "  {} ", "Pack:".bright_black());
        let _ = write!(handle, "{}", pack_name.cyan());
        let _ = writeln!(handle, "{}{}", " ".repeat(padding), "│".red());
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

    // Separator before suggestions/help
    let _ = writeln!(
        handle,
        "{}{}{}",
        "├".red(),
        "─".repeat(WIDTH).red().dimmed(),
        "┤".red()
    );

    // Suggestions from registry (if available) or fallback to contextual
    let suggestions = rule_id
        .as_deref()
        .and_then(crate::suggestions::get_suggestions);

    if let Some(sugg_list) = suggestions {
        // Show up to 3 suggestions from registry
        for s in sugg_list.iter().take(3) {
            let kind_label = s.kind.label();
            let _ = write!(handle, "{}", "│".red());
            let _ = write!(handle, "  💡 {} ", kind_label.green());
            // Truncate suggestion text if too long
            let max_text = WIDTH.saturating_sub(kind_label.len() + 8);
            let text = truncate_for_display(&s.text, max_text);
            let _ = write!(handle, "{}", text.white());
            let line_len = 5 + kind_label.len() + 1 + text.len();
            let padding = WIDTH.saturating_sub(line_len);
            let _ = writeln!(handle, "{}{}", " ".repeat(padding), "│".red());

            // Show command if available
            if let Some(ref cmd) = s.command {
                let _ = write!(handle, "{}", "│".red());
                let _ = write!(handle, "     {} ", "$".bright_black());
                let max_cmd = WIDTH.saturating_sub(10);
                let cmd_display = truncate_for_display(cmd, max_cmd);
                let _ = write!(handle, "{}", cmd_display.cyan());
                let cmd_line_len = 7 + cmd_display.len();
                let cmd_padding = WIDTH.saturating_sub(cmd_line_len);
                let _ = writeln!(handle, "{}{}", " ".repeat(cmd_padding), "│".red());
            }
        }
    } else {
        // Fallback to contextual suggestion if no registry entry
        print_contextual_suggestion_boxed(&mut handle, command, WIDTH);
    }

    // Empty line before learning commands
    let _ = writeln!(handle, "{}{}{}", "│".red(), " ".repeat(WIDTH), "│".red());

    // Learning commands separator
    let _ = writeln!(
        handle,
        "{}{}{}",
        "├".red(),
        "─".repeat(WIDTH).red().dimmed(),
        "┤".red()
    );

    // Copy/paste learning commands
    let _ = write!(handle, "{}", "│".red());
    let _ = write!(handle, "  {} ", "Learn more:".bright_black());
    let learn_len = "  Learn more: ".len();
    let _ = writeln!(
        handle,
        "{}{}",
        " ".repeat(WIDTH.saturating_sub(learn_len)),
        "│".red()
    );

    // dcg explain command
    let escaped_cmd = command.replace('\'', "'\\''");
    let explain_cmd = format!("dcg explain '{}'", truncate_for_display(&escaped_cmd, 45));
    let _ = write!(handle, "{}", "│".red());
    let _ = write!(handle, "     {} ", "$".bright_black());
    let _ = write!(handle, "{}", explain_cmd.cyan());
    let explain_len = 7 + explain_cmd.len();
    let _ = writeln!(
        handle,
        "{}{}",
        " ".repeat(WIDTH.saturating_sub(explain_len)),
        "│".red()
    );

    // dcg allowlist add command (if we have a rule_id)
    if let Some(ref rule) = rule_id {
        let allowlist_cmd = format!("dcg allowlist add {rule} --project");
        let _ = write!(handle, "{}", "│".red());
        let _ = write!(handle, "     {} ", "$".bright_black());
        let _ = write!(handle, "{}", allowlist_cmd.cyan());
        let allowlist_len = 7 + allowlist_cmd.len();
        let _ = writeln!(
            handle,
            "{}{}",
            " ".repeat(WIDTH.saturating_sub(allowlist_len)),
            "│".red()
        );
    }

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

/// Truncate a string for display, appending "..." if truncated.
fn truncate_for_display(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        // Find a safe UTF-8 boundary for truncation
        let target = max_len.saturating_sub(3);
        let boundary = s
            .char_indices()
            .take_while(|(i, _)| *i < target)
            .last()
            .map_or(0, |(i, c)| i + c.len_utf8());
        format!("{}...", &s[..boundary])
    }
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
#[cold]
#[inline(never)]
pub fn output_denial(command: &str, reason: &str, pack: Option<&str>, pattern: Option<&str>) {
    // Print colorful warning to stderr (visible to user)
    print_colorful_warning(command, reason, pack, pattern);

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
    let _ = serde_json::to_writer(&mut handle, &output);
    let _ = writeln!(handle);
}

/// Output a warning to stderr (no JSON deny; command is allowed).
#[cold]
#[inline(never)]
pub fn output_warning(command: &str, reason: &str, pack: Option<&str>, pattern: Option<&str>) {
    let stderr = io::stderr();
    let mut handle = stderr.lock();

    let _ = writeln!(handle);
    let _ = writeln!(
        handle,
        "{} {}",
        "dcg WARNING (allowed by policy):".yellow().bold(),
        reason
    );

    // Build rule_id from pack and pattern
    let rule_id = match (pack, pattern) {
        (Some(p), Some(pat)) => Some(format!("{p}:{pat}")),
        _ => None,
    };

    if let Some(ref rule) = rule_id {
        let _ = writeln!(handle, "  {} {}", "Rule:".bright_black(), rule);
    } else if let Some(pack_name) = pack {
        let _ = writeln!(handle, "  {} {}", "Pack:".bright_black(), pack_name);
    }

    let _ = writeln!(handle, "  {} {}", "Command:".bright_black(), command);
    let _ = writeln!(
        handle,
        "  {}",
        "No hook JSON deny was emitted; this warning is informational.".bright_black()
    );
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

/// Log a budget skip to a file (if logging is enabled).
///
/// # Errors
///
/// Returns any I/O errors encountered while creating directories or appending
/// to the log file.
pub fn log_budget_skip(
    log_file: &str,
    command: &str,
    stage: &str,
    elapsed: Duration,
    budget: Duration,
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
    writeln!(
        file,
        "[{timestamp}] [budget] evaluation skipped due to budget at {stage}"
    )?;
    writeln!(
        file,
        "  Budget: {}ms, Elapsed: {}ms",
        budget.as_millis(),
        elapsed.as_millis()
    )?;
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

    #[test]
    fn test_colorful_warning_utf8_truncation_does_not_panic() {
        // Test with multi-byte UTF-8 characters that would panic with byte slicing
        // Chinese characters: each is 3 bytes in UTF-8
        // 60+ characters to trigger truncation (limit is 50 chars)
        let long_chinese = "rm -rf /home/用户/文件夹/子文件夹/另一个文件夹/更多更多内容/最终最终目录/深层嵌套/额外路径";
        assert!(
            long_chinese.chars().count() > 50,
            "Chinese test string must be >50 chars, got {}",
            long_chinese.chars().count()
        );
        print_colorful_warning(long_chinese, "test reason", Some("test.pack"), None);

        // Japanese characters - also >50 chars
        let long_japanese = "rm -rf /home/ユーザー/ドキュメント/フォルダ/サブフォルダ/ファイル/もっとフォルダ/最後/追加パス";
        assert!(
            long_japanese.chars().count() > 50,
            "Japanese test string must be >50 chars, got {}",
            long_japanese.chars().count()
        );
        print_colorful_warning(long_japanese, "test reason", None, None);

        // Mixed ASCII and emoji (emoji are 4 bytes) - >50 chars
        let long_emoji = "echo 🎉🎊🎈🎁🎀🎄🎃🎂🎆🎇🧨✨🎍🎎🎏🎐🎑🧧🎀🎁🎗🎟🎫🎖🏆🏅🥇🥈🥉⚽️🏀🏈⚾️🥎🎾🏐🏉🥏🎱🪀🏓🏸🥊🥋";
        assert!(
            long_emoji.chars().count() > 50,
            "Emoji test string must be >50 chars, got {}",
            long_emoji.chars().count()
        );
        print_colorful_warning(long_emoji, "test reason", Some("emoji.pack"), None);
    }
}

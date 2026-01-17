//! Claude Code hook protocol handling.
//!
//! This module handles the JSON input/output for the Claude Code `PreToolUse` hook.
//! It parses incoming hook requests and formats denial responses.

use crate::evaluator::MatchSpan;
use crate::highlight::{HighlightSpan, should_use_color};
use crate::output::{auto_theme, should_use_rich_output, DenialBox};
use crate::output::theme::Severity as ThemeSeverity;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::io::{self, IsTerminal, Read, Write};
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

    /// Short allow-once code (if a pending exception was recorded).
    #[serde(rename = "allowOnceCode", skip_serializing_if = "Option::is_none")]
    pub allow_once_code: Option<String>,

    /// Full hash for allow-once disambiguation (if available).
    #[serde(rename = "allowOnceFullHash", skip_serializing_if = "Option::is_none")]
    pub allow_once_full_hash: Option<String>,

    // --- New fields for AI agent ergonomics (git_safety_guard-e4fl.1) ---

    /// Stable rule identifier (e.g., "core.git:reset-hard").
    /// Format: "{packId}:{patternName}"
    #[serde(rename = "ruleId", skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,

    /// Pack identifier that matched (e.g., "core.git").
    #[serde(rename = "packId", skip_serializing_if = "Option::is_none")]
    pub pack_id: Option<String>,

    /// Severity level of the matched pattern.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<crate::packs::Severity>,

    /// Confidence score for this match (0.0-1.0).
    /// Higher values indicate higher confidence that this is a true positive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,

    /// Remediation suggestions for the blocked command.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<Remediation>,
}

/// Allow-once metadata for denial output.
#[derive(Debug, Clone)]
pub struct AllowOnceInfo {
    pub code: String,
    pub full_hash: String,
}

/// Remediation suggestions for blocked commands.
///
/// Provides actionable alternatives and context for users to safely
/// accomplish their intended goal.
#[derive(Debug, Clone, Serialize)]
pub struct Remediation {
    /// A safe alternative command that accomplishes a similar goal.
    #[serde(rename = "safeAlternative", skip_serializing_if = "Option::is_none")]
    pub safe_alternative: Option<String>,

    /// Detailed explanation of why the command was blocked and what to do instead.
    pub explanation: String,

    /// The command to run to allow this specific command once (e.g., "dcg allow-once abc12").
    #[serde(rename = "allowOnceCommand")]
    pub allow_once_command: String,
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
    /// Input exceeded the configured size limit.
    InputTooLarge(usize),
    /// Failed to parse JSON input.
    Json(serde_json::Error),
}

/// Read and parse hook input from stdin.
///
/// # Errors
///
/// Returns [`HookReadError::Io`] if stdin cannot be read, [`HookReadError::Json`]
/// if the input is not valid hook JSON, or [`HookReadError::InputTooLarge`] if
/// the input exceeds `max_bytes`.
pub fn read_hook_input(max_bytes: usize) -> Result<HookInput, HookReadError> {
    let mut input = String::with_capacity(256);
    {
        let stdin = io::stdin();
        // Read up to limit + 1 to detect overflow
        let mut handle = stdin.lock().take(max_bytes as u64 + 1);
        handle
            .read_to_string(&mut input)
            .map_err(HookReadError::Io)?;
    }

    if input.len() > max_bytes {
        return Err(HookReadError::InputTooLarge(input.len()));
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

/// Format the explain hint line for copy-paste convenience.
fn format_explain_hint(command: &str) -> String {
    // Escape double quotes in command for safe copy-paste
    let escaped = command.replace('"', "\\\"");
    format!("Tip: dcg explain \"{escaped}\"")
}

fn build_rule_id(pack: Option<&str>, pattern: Option<&str>) -> Option<String> {
    match (pack, pattern) {
        (Some(pack_id), Some(pattern_name)) => Some(format!("{pack_id}:{pattern_name}")),
        _ => None,
    }
}

fn format_explanation_text(
    explanation: Option<&str>,
    rule_id: Option<&str>,
    pack: Option<&str>,
) -> String {
    let trimmed = explanation.map(str::trim).filter(|text| !text.is_empty());

    if let Some(text) = trimmed {
        return text.to_string();
    }

    if let Some(rule) = rule_id {
        return format!(
            "Matched destructive pattern {rule}. No additional explanation is available \
             yet. See pack documentation for details."
        );
    }

    if let Some(pack_name) = pack {
        return format!(
            "Matched destructive pack {pack_name}. No additional explanation is available \
             yet. See pack documentation for details."
        );
    }

    "Matched a destructive pattern. No additional explanation is available yet. \
     See pack documentation for details."
        .to_string()
}

fn format_explanation_block(explanation: &str) -> String {
    let mut lines = explanation.lines();
    let Some(first) = lines.next() else {
        return "Explanation:".to_string();
    };

    let mut output = format!("Explanation: {first}");
    for line in lines {
        output.push('\n');
        output.push_str("             ");
        output.push_str(line);
    }
    output
}

/// Format the denial message for the JSON output (plain text).
#[must_use]
pub fn format_denial_message(
    command: &str,
    reason: &str,
    explanation: Option<&str>,
    pack: Option<&str>,
    pattern: Option<&str>,
) -> String {
    let explain_hint = format_explain_hint(command);
    let rule_id = build_rule_id(pack, pattern);
    let explanation_text = format_explanation_text(explanation, rule_id.as_deref(), pack);
    let explanation_block = format_explanation_block(&explanation_text);
    format!(
        "BLOCKED by dcg\n\n\
         {explain_hint}\n\n\
         Reason: {reason}\n\n\
         {explanation_block}\n\n\
         {rule_line}\
         Command: {command}\n\n\
         If this operation is truly needed, ask the user for explicit \
         permission and have them run the command manually.",
        rule_line = rule_id.as_deref().map_or_else(
            || pack
                .map(|pack_name| format!("Pack: {pack_name}\n\n"))
                .unwrap_or_default(),
            |rule| format!("Rule: {rule}\n\n"),
        )
    )
}

fn allow_once_should_colorize(base_colorize: bool) -> bool {
    if !base_colorize {
        return false;
    }

    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }

    if matches!(std::env::var("TERM").as_deref(), Ok("dumb")) {
        return false;
    }

    true
}

fn allow_once_header_line_with_color(code: &str, colorize: bool) -> String {
    let command = format!("dcg allow-once {code}");
    let code_token = format!("[{code}]");

    if colorize {
        // Force colorization for this call regardless of global SHOULD_COLORIZE
        // (which is false when there's no TTY, e.g., in tests)
        colored::control::set_override(true);
        let label = "ALLOW-24H CODE:".bright_white().bold();
        let highlighted = code_token.bright_yellow().bold();
        let hint = format!("run: {command}").bright_black();
        let result = format!("{label} {highlighted} | {hint}");
        colored::control::unset_override();
        result
    } else {
        format!("ALLOW-24H CODE: {code_token} | run: {command}")
    }
}

fn allow_once_header_line(code: &str) -> String {
    let colorize = allow_once_should_colorize(colored::control::SHOULD_COLORIZE.should_colorize());
    allow_once_header_line_with_color(code, colorize)
}

/// Print a colorful warning to stderr for human visibility.
///
/// Uses `DenialBox` from the output module for the core denial message,
/// with additional context (suggestions, learning commands) printed after.
#[allow(clippy::too_many_lines)]
pub fn print_colorful_warning(
    command: &str,
    reason: &str,
    pack: Option<&str>,
    pattern: Option<&str>,
    explanation: Option<&str>,
    allow_once_code: Option<&str>,
    matched_span: Option<&MatchSpan>,
) {
    let stderr = io::stderr();
    let mut handle = stderr.lock();

    // Pre-box: Allow-once header (if applicable)
    if let Some(code) = allow_once_code {
        let _ = writeln!(handle, "{}", allow_once_header_line(code));
    }

    // Pre-box: Explain hint line
    let _ = writeln!(handle, "{}", format_explain_hint(command).bright_black());
    let _ = writeln!(handle);

    // Build rule_id for suggestions lookup
    let rule_id = build_rule_id(pack, pattern);

    // Build the denial box using the output module
    let theme = auto_theme();
    let use_rich = should_use_rich_output();

    // Create the highlight span from the matched span
    let highlight_span = matched_span.map_or_else(
        || HighlightSpan::new(0, command.len().min(20)),
        |span| {
            let label = rule_id
                .as_deref()
                .map(|r| format!("Matched: {r}"))
                .or_else(|| pack.map(|p| format!("Matched: {p}")))
                .unwrap_or_else(|| "Matched destructive pattern".to_string());
            HighlightSpan::with_label(span.start, span.end, label)
        },
    );

    // Determine severity for theming (default to High if unknown)
    let severity = ThemeSeverity::High;

    // Build pattern ID for display
    let pattern_id = rule_id
        .as_deref()
        .unwrap_or_else(|| pack.unwrap_or("unknown"));

    // Build explanation text with reason prefix and fallback
    let base_explanation = format_explanation_text(explanation, rule_id.as_deref(), pack);
    let explanation_text = format!("Reason: {reason}\n\n{base_explanation}");

    // Get contextual alternatives from suggestions or fallback
    let alternatives: Vec<String> = rule_id
        .as_deref()
        .and_then(crate::suggestions::get_suggestions)
        .map(|sugg_list| {
            sugg_list
                .iter()
                .take(3)
                .map(|s| {
                    if let Some(ref cmd) = s.command {
                        format!("{}: {} ({})", s.kind.label(), s.text, cmd)
                    } else {
                        format!("{}: {}", s.kind.label(), s.text)
                    }
                })
                .collect()
        })
        .or_else(|| {
            get_contextual_suggestion(command).map(|s| vec![s.to_string()])
        })
        .unwrap_or_default();

    // Create and render the denial box
    let denial = DenialBox::new(command, highlight_span, pattern_id, severity)
        .with_explanation(explanation_text)
        .with_alternatives(alternatives);

    if use_rich {
        let _ = write!(handle, "{}", denial.render(&theme));
    } else {
        let _ = write!(handle, "{}", denial.render_plain());
    }

    // Post-box: Learning commands section
    print_learning_commands(&mut handle, command, rule_id.as_deref());

    let _ = writeln!(handle);
}

/// Print learning commands section after the denial box.
fn print_learning_commands(
    handle: &mut io::StderrLock<'_>,
    command: &str,
    rule_id: Option<&str>,
) {
    let use_color = should_use_color();

    // Learning commands header
    if use_color {
        let _ = writeln!(handle, "\n{}", "Learn more:".bright_black());
    } else {
        let _ = writeln!(handle, "\nLearn more:");
    }

    // dcg explain command
    let escaped_cmd = command.replace('\'', "'\\''");
    let explain_cmd = format!("dcg explain '{}'", truncate_for_display(&escaped_cmd, 45));
    if use_color {
        let _ = writeln!(handle, "  {} {}", "$".bright_black(), explain_cmd.cyan());
    } else {
        let _ = writeln!(handle, "  $ {explain_cmd}");
    }

    // dcg allowlist add command (if we have a rule_id)
    if let Some(rule) = rule_id {
        let allowlist_cmd = format!("dcg allowlist add {rule} --project");
        if use_color {
            let _ = writeln!(handle, "  {} {}", "$".bright_black(), allowlist_cmd.cyan());
        } else {
            let _ = writeln!(handle, "  $ {allowlist_cmd}");
        }
    }

    // False positive link
    if use_color {
        let _ = writeln!(handle, "\n{}", "False positive? File an issue:".bright_black());
        let _ = writeln!(
            handle,
            "{}",
            "  https://github.com/Dicklesworthstone/destructive_command_guard/issues/new".bright_black()
        );
    } else {
        let _ = writeln!(handle, "\nFalse positive? File an issue:");
        let _ = writeln!(
            handle,
            "  https://github.com/Dicklesworthstone/destructive_command_guard/issues/new"
        );
    }
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

/// Output a denial response to stdout (JSON for hook protocol).
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub fn output_denial(
    command: &str,
    reason: &str,
    pack: Option<&str>,
    pattern: Option<&str>,
    explanation: Option<&str>,
    allow_once: Option<&AllowOnceInfo>,
    matched_span: Option<&MatchSpan>,
    severity: Option<crate::packs::Severity>,
    confidence: Option<f64>,
) {
    // Print colorful warning to stderr (visible to user)
    let allow_once_code = allow_once.map(|info| info.code.as_str());
    print_colorful_warning(
        command,
        reason,
        pack,
        pattern,
        explanation,
        allow_once_code,
        matched_span,
    );

    // Build JSON response for hook protocol (stdout)
    let message = format_denial_message(command, reason, explanation, pack, pattern);

    // Build rule_id from pack and pattern
    let rule_id = build_rule_id(pack, pattern);

    // Build remediation struct if we have allow_once info
    let remediation = allow_once.map(|info| {
        let explanation_text =
            format_explanation_text(explanation, rule_id.as_deref(), pack);
        Remediation {
            safe_alternative: get_contextual_suggestion(command).map(String::from),
            explanation: explanation_text,
            allow_once_command: format!("dcg allow-once {}", info.code),
        }
    });

    let output = HookOutput {
        hook_specific_output: HookSpecificOutput {
            hook_event_name: "PreToolUse",
            permission_decision: "deny",
            permission_decision_reason: Cow::Owned(message),
            allow_once_code: allow_once.map(|info| info.code.clone()),
            allow_once_full_hash: allow_once.map(|info| info.full_hash.clone()),
            rule_id,
            pack_id: pack.map(String::from),
            severity,
            confidence,
            remediation,
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
pub fn output_warning(
    command: &str,
    reason: &str,
    pack: Option<&str>,
    pattern: Option<&str>,
    explanation: Option<&str>,
) {
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
    let rule_id = build_rule_id(pack, pattern);
    let explanation_text = format_explanation_text(explanation, rule_id.as_deref(), pack);
    let mut explanation_lines = explanation_text.lines();

    if let Some(first) = explanation_lines.next() {
        let _ = writeln!(handle, "  {} {}", "Explanation:".bright_black(), first);
        for line in explanation_lines {
            let _ = writeln!(handle, "               {line}");
        }
    }

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
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var(key).ok();
            // SAFETY: We hold ENV_LOCK during all tests that use this guard,
            // ensuring no concurrent access to environment variables.
            unsafe { std::env::set_var(key, value) };
            Self { key, previous }
        }

        #[allow(dead_code)]
        fn remove(key: &'static str) -> Self {
            let previous = std::env::var(key).ok();
            // SAFETY: We hold ENV_LOCK during all tests that use this guard,
            // ensuring no concurrent access to environment variables.
            unsafe { std::env::remove_var(key) };
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(value) = self.previous.take() {
                // SAFETY: We hold ENV_LOCK during all tests that use this guard,
                // ensuring no concurrent access to environment variables.
                unsafe { std::env::set_var(self.key, value) };
            } else {
                // SAFETY: We hold ENV_LOCK during all tests that use this guard,
                // ensuring no concurrent access to environment variables.
                unsafe { std::env::remove_var(self.key) };
            }
        }
    }

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
                allow_once_code: None,
                allow_once_full_hash: None,
                rule_id: None,
                pack_id: None,
                severity: None,
                confidence: None,
                remediation: None,
            },
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("PreToolUse"));
        assert!(json.contains("deny"));
        assert!(json.contains("test reason"));
    }

    #[test]
    fn test_hook_output_serialization_with_allow_once() {
        let output = HookOutput {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse",
                permission_decision: "deny",
                permission_decision_reason: Cow::Borrowed("test reason"),
                allow_once_code: Some("12345".to_string()),
                allow_once_full_hash: Some("deadbeef".to_string()),
                rule_id: None,
                pack_id: None,
                severity: None,
                confidence: None,
                remediation: None,
            },
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("allowOnceCode"));
        assert!(json.contains("12345"));
        assert!(json.contains("allowOnceFullHash"));
        assert!(json.contains("deadbeef"));
    }

    #[test]
    fn test_hook_output_serialization_with_new_fields() {
        use crate::packs::Severity;
        let output = HookOutput {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse",
                permission_decision: "deny",
                permission_decision_reason: Cow::Borrowed("test reason"),
                allow_once_code: Some("12345".to_string()),
                allow_once_full_hash: Some("deadbeef".to_string()),
                rule_id: Some("core.git:reset-hard".to_string()),
                pack_id: Some("core.git".to_string()),
                severity: Some(Severity::Critical),
                confidence: Some(0.95),
                remediation: Some(Remediation {
                    safe_alternative: Some("git stash".to_string()),
                    explanation: "Use git stash to save changes safely.".to_string(),
                    allow_once_command: "dcg allow-once 12345".to_string(),
                }),
            },
        };
        let json = serde_json::to_string(&output).unwrap();
        // Check new camelCase field names
        assert!(json.contains("\"ruleId\":\"core.git:reset-hard\""));
        assert!(json.contains("\"packId\":\"core.git\""));
        assert!(json.contains("\"severity\":\"critical\""));
        assert!(json.contains("\"confidence\":0.95"));
        // Check remediation fields
        assert!(json.contains("\"remediation\":{"));
        assert!(json.contains("\"safeAlternative\":\"git stash\""));
        assert!(json.contains("\"explanation\":\"Use git stash to save changes safely.\""));
        assert!(json.contains("\"allowOnceCommand\":\"dcg allow-once 12345\""));
    }

    #[test]
    fn test_format_denial_message() {
        let msg = format_denial_message(
            "git reset --hard",
            "destroys uncommitted changes",
            Some("Rewrites history and discards uncommitted changes."),
            Some("core.git"),
            Some("reset-hard"),
        );
        assert!(msg.contains("git reset --hard"));
        assert!(msg.contains("destroys uncommitted changes"));
        assert!(msg.contains("Explanation: Rewrites history and discards uncommitted changes."));
        assert!(msg.contains("Rule: core.git:reset-hard"));
        assert!(msg.contains("BLOCKED"));
    }

    #[test]
    fn test_allow_once_header_line() {
        let line = allow_once_header_line_with_color("12345", false);
        assert_eq!(line, "ALLOW-24H CODE: [12345] | run: dcg allow-once 12345");
    }

    #[test]
    fn test_allow_once_header_line_color_contains_ansi() {
        let line = allow_once_header_line_with_color("12345", true);
        assert!(line.contains("\x1b["), "expected ANSI escape codes");
        assert!(line.contains("12345"));
    }

    #[test]
    fn test_formatting_respects_no_color_env() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _no_color = EnvVarGuard::set("NO_COLOR", "1");
        let line = allow_once_header_line_with_color("12345", allow_once_should_colorize(true));
        assert!(!line.contains("\x1b["));
    }

    #[test]
    fn test_formatting_respects_term_dumb() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _term = EnvVarGuard::set("TERM", "dumb");
        let line = allow_once_header_line_with_color("12345", allow_once_should_colorize(true));
        assert!(!line.contains("\x1b["));
    }

    #[test]
    fn test_bold_and_color_applied() {
        let line = allow_once_header_line_with_color("12345", true);
        assert!(
            line.contains("\x1b[1m") || line.contains("\x1b[1;"),
            "expected bold ANSI sequence"
        );
        assert!(
            line.contains("\x1b[3") || line.contains("\x1b[9"),
            "expected color ANSI sequence"
        );
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
        print_colorful_warning(
            long_chinese,
            "test reason",
            Some("test.pack"),
            None,
            None,
            None,
            None,
        );

        // Japanese characters - also >50 chars
        let long_japanese = "rm -rf /home/ユーザー/ドキュメント/フォルダ/サブフォルダ/ファイル/もっとフォルダ/最後/追加パス";
        assert!(
            long_japanese.chars().count() > 50,
            "Japanese test string must be >50 chars, got {}",
            long_japanese.chars().count()
        );
        print_colorful_warning(long_japanese, "test reason", None, None, None, None, None);

        // Mixed ASCII and emoji (emoji are 4 bytes) - >50 chars
        let long_emoji = "echo 🎉🎊🎈🎁🎀🎄🎃🎂🎆🎇🧨✨🎍🎎🎏🎐🎑🧧🎀🎁🎗🎟🎫🎖🏆🏅🥇🥈🥉⚽️🏀🏈⚾️🥎🎾🏐🏉🥏🎱🪀🏓🏸🥊🥋";
        assert!(
            long_emoji.chars().count() > 50,
            "Emoji test string must be >50 chars, got {}",
            long_emoji.chars().count()
        );
        print_colorful_warning(
            long_emoji,
            "test reason",
            Some("emoji.pack"),
            None,
            None,
            None,
            None,
        );
    }

    // =============================================================================
    // Explain hint tests (git_safety_guard-oien.2.3)
    // =============================================================================

    #[test]
    fn test_format_explain_hint_simple() {
        let hint = format_explain_hint("git reset --hard");
        assert_eq!(hint, r#"Tip: dcg explain "git reset --hard""#);
    }

    #[test]
    fn test_format_explain_hint_escapes_double_quotes() {
        // Commands with double quotes should be escaped for copy-paste safety
        let hint = format_explain_hint(r#"echo "hello world""#);
        assert_eq!(hint, r#"Tip: dcg explain "echo \"hello world\"""#);
    }

    #[test]
    fn test_format_explain_hint_with_special_chars() {
        // Test various shell metacharacters are preserved (only " is escaped)
        let hint = format_explain_hint("rm -rf $HOME/* && echo 'done'");
        assert_eq!(hint, r#"Tip: dcg explain "rm -rf $HOME/* && echo 'done'""#);
    }

    #[test]
    fn test_format_denial_message_contains_explain_hint() {
        // The JSON denial message should include the explain hint
        let msg = format_denial_message(
            "git reset --hard",
            "destroys uncommitted changes",
            None,
            Some("core.git"),
            Some("reset-hard"),
        );
        assert!(
            msg.contains(r#"Tip: dcg explain "git reset --hard""#),
            "Denial message should contain explain hint, got: {msg}"
        );
    }

    #[test]
    fn test_format_denial_message_explain_hint_position() {
        // Verify the explain hint comes after "BLOCKED" but before "Reason:"
        let msg = format_denial_message(
            "rm -rf /",
            "dangerous filesystem operation",
            None,
            Some("core.filesystem"),
            Some("rm-root"),
        );
        let blocked_pos = msg.find("BLOCKED").expect("should contain BLOCKED");
        let tip_pos = msg
            .find("Tip: dcg explain")
            .expect("should contain explain hint");
        let reason_pos = msg.find("Reason:").expect("should contain Reason:");
        let explanation_pos = msg
            .find("Explanation:")
            .expect("should contain Explanation:");

        assert!(
            blocked_pos < tip_pos,
            "BLOCKED should come before explain hint"
        );
        assert!(
            tip_pos < reason_pos,
            "Explain hint should come before Reason:"
        );
        assert!(
            reason_pos < explanation_pos,
            "Reason should come before Explanation"
        );
    }

    #[test]
    fn test_colorful_warning_with_explain_hint_does_not_panic() {
        // Verify print_colorful_warning handles various inputs without panic
        // (the hint is printed to stderr which we can't easily capture in unit tests,
        // but we can verify it doesn't crash)
        print_colorful_warning(
            "git push --force",
            "force push",
            Some("git"),
            Some("force_push"),
            Some("Force pushes can overwrite remote history."),
            None,
            None,
        );
        print_colorful_warning(
            "rm -rf /",
            "filesystem",
            Some("fs"),
            None,
            None,
            Some("12345"),
            None,
        );
        print_colorful_warning(r#"echo "quoted""#, "echo", None, None, None, None, None);
    }

    #[test]
    fn test_colorful_warning_with_span_highlighting() {
        use crate::evaluator::MatchSpan;

        // Test with a span to verify highlighting works
        let cmd = "git reset --hard HEAD";
        let span = MatchSpan { start: 0, end: 16 };
        print_colorful_warning(
            cmd,
            "destroys uncommitted changes",
            Some("core.git"),
            Some("reset-hard"),
            Some("This command discards all uncommitted changes."),
            None,
            Some(&span),
        );
    }

    #[test]
    fn test_colorful_warning_with_long_command_and_span() {
        use crate::evaluator::MatchSpan;

        // Test with a long command to verify windowing works
        let prefix = "echo prefix && ";
        let dangerous = "git reset --hard";
        let suffix = " && echo suffix more text here to make it long";
        let cmd = format!("{prefix}{dangerous}{suffix}");
        let span = MatchSpan {
            start: prefix.len(),
            end: prefix.len() + dangerous.len(),
        };
        print_colorful_warning(
            &cmd,
            "destroys uncommitted changes",
            Some("core.git"),
            Some("reset-hard"),
            None,
            None,
            Some(&span),
        );
    }

    // =============================================================================
    // Explanation rendering tests (git_safety_guard-r97e.5)
    // =============================================================================

    #[test]
    fn test_format_explanation_text_with_explicit_explanation() {
        let result = format_explanation_text(
            Some("This command is dangerous because it deletes everything."),
            Some("core.git:reset-hard"),
            Some("core.git"),
        );
        assert_eq!(
            result,
            "This command is dangerous because it deletes everything."
        );
    }

    #[test]
    fn test_format_explanation_text_trims_whitespace() {
        // Leading/trailing whitespace should be trimmed
        let result = format_explanation_text(
            Some("  Trimmed explanation  \n"),
            Some("core.git:reset-hard"),
            Some("core.git"),
        );
        assert_eq!(result, "Trimmed explanation");
    }

    #[test]
    fn test_format_explanation_text_empty_string_fallback_to_rule() {
        // Empty string should trigger fallback
        let result =
            format_explanation_text(Some(""), Some("core.git:reset-hard"), Some("core.git"));
        assert!(
            result.contains("Matched destructive pattern core.git:reset-hard"),
            "Expected fallback with rule_id, got: {result}"
        );
    }

    #[test]
    fn test_format_explanation_text_whitespace_only_fallback_to_rule() {
        // Whitespace-only should trigger fallback
        let result = format_explanation_text(
            Some("   \n\t  "),
            Some("core.git:reset-hard"),
            Some("core.git"),
        );
        assert!(
            result.contains("Matched destructive pattern core.git:reset-hard"),
            "Expected fallback with rule_id, got: {result}"
        );
    }

    #[test]
    fn test_format_explanation_text_none_fallback_to_rule() {
        // None should trigger fallback with rule_id
        let result = format_explanation_text(
            None,
            Some("core.filesystem:rm-root"),
            Some("core.filesystem"),
        );
        assert!(
            result.contains("Matched destructive pattern core.filesystem:rm-root"),
            "Expected fallback with rule_id, got: {result}"
        );
        assert!(
            result.contains("No additional explanation is available"),
            "Expected fallback text, got: {result}"
        );
    }

    #[test]
    fn test_format_explanation_text_none_fallback_to_pack() {
        // None with no rule_id should fallback to pack
        let result = format_explanation_text(None, None, Some("containers.docker"));
        assert!(
            result.contains("Matched destructive pack containers.docker"),
            "Expected fallback with pack_name, got: {result}"
        );
    }

    #[test]
    fn test_format_explanation_text_none_fallback_generic() {
        // None with no rule_id and no pack should use generic fallback
        let result = format_explanation_text(None, None, None);
        assert!(
            result.contains("Matched a destructive pattern"),
            "Expected generic fallback, got: {result}"
        );
        assert!(
            result.contains("No additional explanation is available"),
            "Expected fallback text, got: {result}"
        );
    }

    #[test]
    fn test_format_explanation_block_single_line() {
        let result = format_explanation_block("Single line explanation.");
        assert_eq!(result, "Explanation: Single line explanation.");
    }

    #[test]
    fn test_format_explanation_block_multi_line() {
        let explanation = "First line of explanation.\nSecond line continues.\nThird line ends.";
        let result = format_explanation_block(explanation);

        // First line should be on the same line as label
        assert!(result.starts_with("Explanation: First line of explanation."));
        // Subsequent lines should be indented to align with first line
        assert!(result.contains("\n             Second line continues."));
        assert!(result.contains("\n             Third line ends."));
    }

    #[test]
    fn test_format_explanation_block_empty_string() {
        let result = format_explanation_block("");
        assert_eq!(result, "Explanation:");
    }

    #[test]
    fn test_format_explanation_block_preserves_internal_whitespace() {
        let explanation = "Line with  multiple   spaces.";
        let result = format_explanation_block(explanation);
        assert!(result.contains("multiple   spaces"));
    }

    #[test]
    fn test_format_denial_message_with_explicit_explanation() {
        let msg = format_denial_message(
            "docker system prune -af",
            "removes all unused data",
            Some("This removes all stopped containers, unused networks, dangling images."),
            Some("containers.docker"),
            Some("system-prune"),
        );
        assert!(
            msg.contains("This removes all stopped containers"),
            "Should contain explicit explanation"
        );
        assert!(
            !msg.contains("No additional explanation is available"),
            "Should NOT contain fallback text when explicit explanation provided"
        );
    }

    #[test]
    fn test_format_denial_message_with_fallback_explanation() {
        let msg = format_denial_message(
            "docker system prune -af",
            "removes all unused data",
            None, // No explicit explanation
            Some("containers.docker"),
            Some("system-prune"),
        );
        assert!(
            msg.contains("Matched destructive pattern containers.docker:system-prune"),
            "Should contain fallback with rule_id"
        );
        assert!(
            msg.contains("No additional explanation is available"),
            "Should contain fallback text"
        );
    }

    #[test]
    fn test_format_denial_message_pack_only_fallback() {
        let msg = format_denial_message(
            "some-command --dangerous",
            "dangerous operation",
            None, // No explicit explanation
            Some("core.filesystem"),
            None, // No pattern name - only pack
        );
        assert!(
            msg.contains("Matched destructive pack core.filesystem")
                || msg.contains("No additional explanation"),
            "Should contain pack fallback or generic fallback, got: {msg}"
        );
    }
}

//! Claude Code hook protocol handling.
//!
//! This module handles the JSON input/output for the Claude Code `PreToolUse` hook.
//! It parses incoming hook requests and formats denial responses.

use crate::evaluator::MatchSpan;
use crate::highlight::HighlightSpan;
use crate::output::auto_theme;
#[cfg(feature = "rich-output")]
use crate::output::console::console;
use crate::output::denial::DenialBox;
use crate::output::theme::Severity as ThemeSeverity;
use crate::packs::PatternSuggestion;
use colored::Colorize;
#[cfg(feature = "rich-output")]
#[allow(unused_imports)]
use rich_rust::prelude::*;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::io::{self, IsTerminal, Read, Write};
use std::time::Duration;

/// Input structure from Claude Code's `PreToolUse` hook.
#[derive(Debug, Deserialize)]
pub struct HookInput {
    /// Hook event name (used by some clients, e.g. Copilot CLI: "pre-tool-use").
    pub event: Option<String>,

    /// The name of the tool being invoked (e.g., "Bash", "Read", "Write").
    #[serde(alias = "toolName")]
    pub tool_name: Option<String>,

    /// Tool-specific input parameters.
    #[serde(alias = "toolInput")]
    pub tool_input: Option<ToolInput>,

    /// Alternate tool arguments format used by some clients.
    /// May be a JSON string (e.g. "{\"command\":\"...\"}") or an object.
    #[serde(alias = "toolArgs")]
    pub tool_args: Option<serde_json::Value>,
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

/// Copilot-compatible denial output for pre-tool-use hooks.
///
/// Copilot hooks can consume either:
/// - `continue=false` with `stopReason`
/// - `permissionDecision=deny` with `permissionDecisionReason`
///
/// We emit both for compatibility across documented variants.
#[derive(Debug, Serialize)]
pub struct CopilotHookOutput<'a> {
    /// Whether execution should continue.
    #[serde(rename = "continue")]
    pub continue_execution: bool,

    /// Human-readable stop reason.
    #[serde(rename = "stopReason")]
    pub stop_reason: Cow<'a, str>,

    /// Permission decision (`deny`).
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

    /// Stable rule identifier (e.g., "core.git:reset-hard").
    #[serde(rename = "ruleId", skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,

    /// Pack identifier that matched (e.g., "core.git").
    #[serde(rename = "packId", skip_serializing_if = "Option::is_none")]
    pub pack_id: Option<String>,

    /// Severity level of the matched pattern.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<crate::packs::Severity>,

    /// Confidence score for this match (0.0-1.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,

    /// Remediation suggestions for the blocked command.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<Remediation>,
}

/// Hook protocol variant for response formatting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookProtocol {
    /// Claude Code / Augment-compatible `hookSpecificOutput` protocol.
    ClaudeCompatible,
    /// Copilot hook protocol (`continue` / `stopReason` + permission fields).
    Copilot,
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

/// Detect which hook protocol should be used for output formatting.
#[must_use]
pub fn detect_protocol(input: &HookInput) -> HookProtocol {
    let tool_name = input
        .tool_name
        .as_deref()
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();

    if input.event.is_some()
        || input.tool_args.is_some()
        || matches!(
            tool_name.as_str(),
            "run_shell_command" | "run-shell-command"
        )
    {
        HookProtocol::Copilot
    } else {
        HookProtocol::ClaudeCompatible
    }
}

fn is_supported_shell_tool(tool_name: Option<&str>) -> bool {
    let Some(tool_name) = tool_name else {
        return false;
    };

    matches!(
        tool_name.to_ascii_lowercase().as_str(),
        "bash" | "launch-process" | "run_shell_command" | "run-shell-command"
    )
}

fn extract_command_from_tool_args(tool_args: &serde_json::Value) -> Option<String> {
    match tool_args {
        serde_json::Value::Object(map) => map.get("command").and_then(|v| match v {
            serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
            _ => None,
        }),
        serde_json::Value::String(s) => {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(s) {
                extract_command_from_tool_args(&parsed)
            } else if s.is_empty() {
                None
            } else {
                Some(s.clone())
            }
        }
        _ => None,
    }
}

/// Extract command and protocol from hook input.
#[must_use]
pub fn extract_command_with_protocol(input: &HookInput) -> Option<(String, HookProtocol)> {
    // Only process shell-command invocations for supported clients.
    if !is_supported_shell_tool(input.tool_name.as_deref()) {
        return None;
    }

    let protocol = detect_protocol(input);

    if let Some(tool_input) = input.tool_input.as_ref() {
        if let Some(serde_json::Value::String(s)) = tool_input.command.as_ref() {
            if !s.is_empty() {
                return Some((s.clone(), protocol));
            }
        }
    }

    if let Some(tool_args) = input.tool_args.as_ref() {
        if let Some(command) = extract_command_from_tool_args(tool_args) {
            return Some((command, protocol));
        }
    }

    None
}

/// Extract the command string from hook input.
#[must_use]
pub fn extract_command(input: &HookInput) -> Option<String> {
    extract_command_with_protocol(input).map(|(command, _)| command)
}

/// Configure colored output based on TTY detection.
pub fn configure_colors() {
    if std::env::var_os("NO_COLOR").is_some() || std::env::var_os("DCG_NO_COLOR").is_some() {
        colored::control::set_override(false);
        return;
    }

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
            "Matched destructive pattern {rule}. No additional explanation is available yet. See pack documentation for details."
        );
    }

    if let Some(pack_name) = pack {
        return format!(
            "Matched destructive pack {pack_name}. No additional explanation is available yet. See pack documentation for details."
        );
    }

    "Matched a destructive pattern. No additional explanation is available yet. See pack documentation for details."
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

    let rule_line = rule_id.as_deref().map_or_else(
        || {
            pack.map(|pack_name| format!("Pack: {pack_name}\n\n"))
                .unwrap_or_default()
        },
        |rule| format!("Rule: {rule}\n\n"),
    );

    format!(
        "BLOCKED by dcg\n\n\
         {explain_hint}\n\n\
         Reason: {reason}\n\n\
         {explanation_block}\n\n\
         {rule_line}\
         Command: {command}\n\n\
         If this operation is truly needed, ask the user for explicit \
         permission and have them run the command manually."
    )
}

/// Convert packs::Severity to theme::Severity
fn to_output_severity(s: crate::packs::Severity) -> ThemeSeverity {
    match s {
        crate::packs::Severity::Critical => ThemeSeverity::Critical,
        crate::packs::Severity::High => ThemeSeverity::High,
        crate::packs::Severity::Medium => ThemeSeverity::Medium,
        crate::packs::Severity::Low => ThemeSeverity::Low,
    }
}

const MAX_SUGGESTIONS: usize = 4;

/// Print a colorful warning to stderr for human visibility.
#[allow(clippy::too_many_lines)]
pub fn print_colorful_warning(
    command: &str,
    _reason: &str,
    pack: Option<&str>,
    pattern: Option<&str>,
    explanation: Option<&str>,
    allow_once_code: Option<&str>,
    matched_span: Option<&MatchSpan>,
    pattern_suggestions: &[PatternSuggestion],
    severity: Option<crate::packs::Severity>,
) {
    #[cfg(feature = "rich-output")]
    let console_instance = console();
    let theme = auto_theme();

    // Prepare content for DenialBox
    let rule_id = build_rule_id(pack, pattern);
    let pattern_display = rule_id.as_deref().or(pack).unwrap_or("unknown pattern");

    let theme_severity = severity
        .map(to_output_severity)
        .unwrap_or(ThemeSeverity::High);

    let explanation_text = explanation.map(str::trim).filter(|text| !text.is_empty());

    // Create span for highlighting
    let span = matched_span
        .map(|s| HighlightSpan::new(s.start, s.end))
        .unwrap_or_else(|| HighlightSpan::new(0, 0)); // Fallback

    let suggestions_enabled = crate::output::suggestions_enabled();

    // Convert suggestions to alternatives (platform-filtered, capped)
    let filtered_suggestions: Vec<&PatternSuggestion> = if suggestions_enabled {
        pattern_suggestions
            .iter()
            .filter(|s| s.platform.matches_current())
            .collect()
    } else {
        Vec::new()
    };
    let mut alternatives: Vec<String> = filtered_suggestions
        .iter()
        .take(MAX_SUGGESTIONS)
        .map(|s| format!("{}: {}", s.description, s.command))
        .collect();

    // Add contextual suggestion if available and no pattern suggestions
    if suggestions_enabled && alternatives.is_empty() {
        if let Some(sugg) = get_contextual_suggestion(command) {
            alternatives.push(sugg.to_string());
        }
    }

    let mut denial = DenialBox::new(command, span, pattern_display, theme_severity)
        .with_alternatives(alternatives);

    if let Some(text) = explanation_text {
        denial = denial.with_explanation(text);
    }

    if let Some(code) = allow_once_code {
        denial = denial.with_allow_once_code(code);
    }

    // Render the denial box
    // Note: DcgConsole auto-detects stderr usage
    eprintln!("{}", denial.render(&theme));

    // Secondary info (Legacy: printed after box; Rich: could use panels)
    #[cfg(feature = "rich-output")]
    if !console_instance.is_plain() {
        // In rich mode, we might want additional panels or info
        // For now, let's keep it simple as DenialBox handles most things
        // But we might want to print the "Learn more" links
    }

    // "Learn more" section (common to both modes, usually printed after the main warning)
    let escaped_cmd = command.replace('"', "\\\"");
    let truncated_cmd = truncate_for_display(&escaped_cmd, 45);
    let explain_cmd = format!("dcg explain \"{truncated_cmd}\"");

    // Let's print the footer links
    let footer_style = if theme.colors_enabled { "\x1b[90m" } else { "" }; // Bright black
    let reset = if theme.colors_enabled { "\x1b[0m" } else { "" };
    let cyan = if theme.colors_enabled { "\x1b[36m" } else { "" };

    eprintln!("{footer_style}Learn more:{reset}");
    eprintln!("  $ {cyan}{explain_cmd}{reset}");

    if let Some(ref rule) = rule_id {
        eprintln!("  $ {cyan}dcg allowlist add {rule} --project{reset}");
    }

    eprintln!();
    eprintln!("{footer_style}False positive? File an issue:{reset}");
    eprintln!(
        "{footer_style}https://github.com/Dicklesworthstone/destructive_command_guard/issues/new?template=false_positive.yml{reset}"
    );
    eprintln!();
}

#[cfg(feature = "rich-output")]
#[allow(dead_code)] // TODO: Integrate into rich output path
fn render_suggestions_panel(suggestions: &[PatternSuggestion]) -> String {
    use rich_rust::r#box::ROUNDED;
    use rich_rust::prelude::*;

    // Build content as a Vec of lines, then join
    let mut lines = Vec::new();
    if !crate::output::suggestions_enabled() {
        return String::new();
    }

    let filtered: Vec<&PatternSuggestion> = suggestions
        .iter()
        .filter(|s| s.platform.matches_current())
        .take(MAX_SUGGESTIONS)
        .collect();

    for (i, s) in filtered.iter().enumerate() {
        lines.push(format!("[bold cyan]{}.[/] {}", i + 1, s.description));
        lines.push(format!("   [green]$[/] [cyan]{}[/]", s.command));
    }
    let content_str = lines.join("\n");

    let width = crate::output::terminal_width() as usize;
    Panel::from_text(&content_str)
        .title("[yellow bold] 💡 Suggestions [/]")
        .box_style(&ROUNDED)
        .border_style(Style::new().color(Color::parse("yellow").unwrap_or_default()))
        .render_plain(width)
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
pub fn output_denial_for_protocol(
    protocol: HookProtocol,
    command: &str,
    reason: &str,
    pack: Option<&str>,
    pattern: Option<&str>,
    explanation: Option<&str>,
    allow_once: Option<&AllowOnceInfo>,
    matched_span: Option<&MatchSpan>,
    severity: Option<crate::packs::Severity>,
    confidence: Option<f64>,
    pattern_suggestions: &[PatternSuggestion],
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
        pattern_suggestions,
        severity,
    );

    // Build JSON response for hook protocol (stdout)
    let message = format_denial_message(command, reason, explanation, pack, pattern);
    let rule_id = build_rule_id(pack, pattern);
    let remediation = allow_once.map(|info| {
        let explanation_text = format_explanation_text(explanation, rule_id.as_deref(), pack);
        Remediation {
            safe_alternative: get_contextual_suggestion(command).map(String::from),
            explanation: explanation_text,
            allow_once_command: format!("dcg allow-once {}", info.code),
        }
    });

    let stdout = io::stdout();
    let mut handle = stdout.lock();

    match protocol {
        HookProtocol::ClaudeCompatible => {
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

            let _ = serde_json::to_writer(&mut handle, &output);
            let _ = writeln!(handle);
        }
        HookProtocol::Copilot => {
            let output = CopilotHookOutput {
                continue_execution: false,
                stop_reason: Cow::Owned(format!("BLOCKED by dcg: {reason}")),
                permission_decision: "deny",
                permission_decision_reason: Cow::Owned(message),
                allow_once_code: allow_once.map(|info| info.code.clone()),
                allow_once_full_hash: allow_once.map(|info| info.full_hash.clone()),
                rule_id,
                pack_id: pack.map(String::from),
                severity,
                confidence,
                remediation,
            };

            let _ = serde_json::to_writer(&mut handle, &output);
            let _ = writeln!(handle);
        }
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
    pattern_suggestions: &[PatternSuggestion],
) {
    output_denial_for_protocol(
        HookProtocol::ClaudeCompatible,
        command,
        reason,
        pack,
        pattern,
        explanation,
        allow_once,
        matched_span,
        severity,
        confidence,
        pattern_suggestions,
    );
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
        let json = r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(extract_command(&input), Some("git status".to_string()));
    }

    #[test]
    fn test_parse_non_bash_input() {
        let json = r#"{"tool_name":"Read","tool_input":{"command":"git status"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(extract_command(&input), None);
    }

    #[test]
    fn test_parse_missing_command() {
        let json = r#"{"tool_name":"Bash","tool_input":{}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(extract_command(&input), None);
    }

    #[test]
    fn test_parse_copilot_tool_input_command() {
        let json = r#"{"event":"pre-tool-use","toolName":"run_shell_command","toolInput":{"command":"git status"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(extract_command(&input), Some("git status".to_string()));
        assert_eq!(detect_protocol(&input), HookProtocol::Copilot);
    }

    #[test]
    fn test_parse_copilot_tool_args_json_string() {
        let json = r#"{"event":"pre-tool-use","toolName":"bash","toolArgs":"{\"command\":\"rm -rf /tmp/build\"}"}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(
            extract_command(&input),
            Some("rm -rf /tmp/build".to_string())
        );
        assert_eq!(detect_protocol(&input), HookProtocol::Copilot);
    }

    #[test]
    fn test_parse_non_string_command() {
        let json = r#"{"tool_name":"Bash","tool_input":{"command":123}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(extract_command(&input), None);
    }

    #[test]
    fn test_format_denial_message_includes_explanation_and_rule() {
        let message = format_denial_message(
            "git reset --hard",
            "destructive",
            Some("This is irreversible."),
            Some("core.git"),
            Some("reset-hard"),
        );

        assert!(message.contains("Reason: destructive"));
        assert!(message.contains("Explanation: This is irreversible."));
        assert!(message.contains("Rule: core.git:reset-hard"));
        assert!(message.contains("Tip: dcg explain"));
    }

    #[test]
    fn test_env_var_guard_restores_value() {
        let _lock = ENV_LOCK.lock().unwrap();
        let key = "DCG_TEST_ENV_GUARD";
        // SAFETY: We hold ENV_LOCK to prevent concurrent env modifications
        unsafe { std::env::remove_var(key) };

        {
            let _guard = EnvVarGuard::set(key, "1");
            assert_eq!(std::env::var(key).as_deref(), Ok("1"));
        }

        assert!(std::env::var(key).is_err());
    }
}

//! Hook protocol handling.
//!
//! This module handles JSON input/output for supported hook protocols
//! (Claude Code, Codex CLI, Copilot, VS Code Copilot Chat, Gemini, and Hermes
//! Agent). It parses incoming hook requests and formats denial responses.

use crate::evaluator::MatchSpan;
use crate::highlight::HighlightSpan;
use crate::output::auto_theme;
use crate::output::denial::DenialBox;
use crate::output::theme::Severity as ThemeSeverity;
use crate::packs::PatternSuggestion;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::io::{self, IsTerminal, Read, Write};
use std::time::Duration;

/// Input structure from supported hook protocols.
#[derive(Debug, Deserialize)]
pub struct HookInput {
    /// Hook event name (used by some clients, e.g. Copilot CLI: "pre-tool-use").
    pub event: Option<String>,

    /// Gemini hook event name (e.g., "BeforeTool").
    #[serde(alias = "hookEventName")]
    pub hook_event_name: Option<String>,

    /// Gemini session id.
    pub session_id: Option<String>,

    /// Gemini transcript path.
    pub transcript_path: Option<String>,

    /// Gemini working directory.
    pub cwd: Option<String>,

    /// Gemini event timestamp.
    pub timestamp: Option<String>,

    /// The name of the tool being invoked (e.g., "Bash", "runTerminalCommand").
    #[serde(alias = "toolName")]
    pub tool_name: Option<String>,

    /// Tool-specific input parameters.
    #[serde(alias = "toolInput")]
    pub tool_input: Option<ToolInput>,

    /// Alternate tool arguments format used by some clients.
    /// May be a JSON string (e.g. "{\"command\":\"...\"}") or an object.
    #[serde(alias = "toolArgs")]
    pub tool_args: Option<serde_json::Value>,

    /// Codex CLI active-turn identifier. Documented in
    /// `codex-rs/hooks/src/schema.rs` as "Codex extension: expose the active
    /// turn id to internal turn-scoped hooks" -- i.e. Codex's intentional
    /// divergence from Claude's public hook docs. Claude Code does NOT send
    /// this field (Claude does send `tool_use_id`, so that field can't be
    /// used to disambiguate the two otherwise-similar wire formats). When
    /// `turn_id` is present and non-blank we switch to Codex's minimal
    /// `hookSpecificOutput` deny payload because Codex's parser can reject the
    /// dcg-only fields carried by the extended Claude-compatible response.
    #[serde(alias = "turnId")]
    pub turn_id: Option<String>,

    /// Antigravity CLI (`agy`) tool-call envelope. Unlike Claude/Gemini/Grok,
    /// `agy` nests the tool name and arguments under a `toolCall` object:
    /// `{"toolCall": {"name": "run_command", "args": {"CommandLine": "...",
    /// "Cwd": "..."}}, "conversationId": "...", "stepIdx": 4, ...}`. The shell
    /// command lives in `toolCall.args.CommandLine`. Verified empirically by
    /// capturing the stdin `agy` passes to a `PreToolUse` hook.
    #[serde(alias = "toolCall")]
    pub tool_call: Option<ToolCall>,
}

/// Tool-specific input containing the command to execute.
#[derive(Debug, Deserialize)]
pub struct ToolInput {
    /// The command string (for Bash tools).
    pub command: Option<serde_json::Value>,
}

/// Antigravity CLI (`agy`) tool-call envelope.
///
/// `agy` emits `{"name": "run_command", "args": {"CommandLine": "...",
/// "Cwd": "...", "WaitMsBeforeAsync": 500}}`. The shell command is in
/// `args.CommandLine`.
#[derive(Debug, Deserialize)]
pub struct ToolCall {
    /// The tool name (e.g. `"run_command"` for the shell tool).
    pub name: Option<String>,

    /// Tool arguments. For `run_command`, this carries `CommandLine`.
    pub args: Option<serde_json::Value>,
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

/// Copilot-compatible output for `preToolUse` hooks.
///
/// Copilot parses stdout as one JSON document and documents these two top-level
/// fields as the decision contract.  Emitting legacy `continue`/`stopReason`
/// fields alongside them can make current Copilot CLI discard the decision
/// entirely, so this wire type is intentionally minimal (#182).
#[derive(Debug, Serialize)]
pub struct CopilotHookOutput<'a> {
    /// Permission decision (`allow`, `deny`, or `ask`).
    #[serde(rename = "permissionDecision")]
    pub permission_decision: &'static str,

    /// Human-readable explanation of the decision.
    #[serde(rename = "permissionDecisionReason")]
    pub permission_decision_reason: Cow<'a, str>,
}

/// Gemini-compatible denial output for `BeforeTool` hooks.
#[derive(Debug, Serialize)]
pub struct GeminiHookOutput<'a> {
    /// Decision for this hook event.
    pub decision: &'static str,

    /// Why the action was denied.
    pub reason: Cow<'a, str>,

    /// Human-visible message in Gemini CLI.
    #[serde(rename = "systemMessage", skip_serializing_if = "Option::is_none")]
    pub system_message: Option<Cow<'a, str>>,

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

/// Hermes Agent denial output for shell `pre_tool_call` hooks.
///
/// Hermes documents two block-decision wire shapes — `{"decision": "block",
/// "reason": ...}` and `{"action": "block", "message": ...}` — and accepts
/// either. We emit the documented primary form (`decision` + `reason`) and
/// also include the alternate keys (`action` + `message`) for compatibility
/// with both codepaths. Hermes also explicitly notes that "non-zero exit
/// codes... never crash the agent", so blocking MUST come from the JSON
/// payload rather than the exit code.
///
/// Extra fields beyond `decision`/`action`/`reason`/`message` are tolerated
/// by Hermes' parser (no `deny_unknown_fields`), so we include the same
/// `ruleId` / `packId` / `severity` / `remediation` ergonomics as the
/// Claude / Gemini outputs.
///
/// See: <https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/features/hooks.md>
#[derive(Debug, Serialize)]
pub struct HermesHookOutput<'a> {
    /// Primary block decision keyword (Hermes accepts `"block"` or, for
    /// non-block events, anything truthy/falsy depending on event).
    pub decision: &'static str,

    /// Why the action was denied (paired with `decision`).
    pub reason: Cow<'a, str>,

    /// Alternate block-decision key documented by Hermes. We emit both forms
    /// so future Hermes versions that prefer one over the other still see a
    /// valid block.
    pub action: &'static str,

    /// Alternate human-readable message (paired with `action`).
    pub message: Cow<'a, str>,

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

/// Grok (xAI) denial output for `PreToolUse` hooks.
///
/// Grok documents one block-decision wire shape — `{"decision": "deny",
/// "reason": "..."}` — paired with exit code 0 or 2 (both block; other
/// exit codes are fail-open). dcg emits exit 0 plus the JSON payload so
/// the wire form alone is authoritative, matching the documented preferred
/// path.
///
/// Grok's hook input/output is permissive: extra fields beyond
/// `decision`/`reason` are tolerated, so we include the same `ruleId` /
/// `packId` / `severity` / `remediation` ergonomics fields as the Claude /
/// Gemini outputs for any tooling that wants to surface them.
///
/// See: `~/.grok/docs/user-guide/10-hooks.md`
#[derive(Debug, Serialize)]
pub struct GrokHookOutput<'a> {
    /// Block decision keyword. Grok requires `"deny"` (not `"block"`).
    pub decision: &'static str,

    /// Why the action was denied. Surfaced to the Grok user and the model.
    pub reason: Cow<'a, str>,

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
    /// Tolerant JSON parser; accepts dcg's full deny payload with
    /// `allowOnceCode`, `ruleId`, `severity`, `remediation`, etc.
    ClaudeCompatible,
    /// Copilot hook protocol (top-level permission decision and reason).
    Copilot,
    /// Gemini hook protocol (`decision` / `reason`).
    Gemini,
    /// Codex CLI protocol. Input carries the Codex-specific `turn_id`; denials
    /// use the current minimal `hookSpecificOutput` JSON contract on stdout
    /// with exit code 0.  Keeping this payload minimal avoids Codex rejecting
    /// dcg-specific ergonomics fields while also avoiding the legacy exit-2
    /// path that Codex 0.144.x can classify as a failed hook and fail open.
    Codex,
    /// Hermes Agent (NousResearch) protocol. Wire shape: stdin carries
    /// snake_case `hook_event_name: "pre_tool_call"`, `tool_name: "terminal"`,
    /// `tool_input.command`. Block decision MUST be expressed via stdout JSON
    /// `{"decision": "block", "reason": ...}` (or `{"action": "block",
    /// "message": ...}`) — Hermes explicitly documents that non-zero exit
    /// codes "log a warning but never abort the agent loop". Hermes shares
    /// stdin envelope fields (`session_id`, `cwd`) with Claude/Gemini, so we
    /// disambiguate via the lowercase event name `"pre_tool_call"` and the
    /// distinctive `"terminal"` tool name.
    Hermes,
    /// xAI Grok CLI / Grok Build TUI protocol. Wire shape: stdin carries
    /// camelCase `hookEventName: "pre_tool_use"`, `sessionId`, `workspaceRoot`,
    /// `toolName: "run_terminal_cmd"`, `toolInput.command`. Block decision is
    /// expressed via stdout JSON `{"decision": "deny", "reason": "..."}`
    /// (note: `"deny"`, not `"block"` — distinct from Hermes). Grok also
    /// honors exit code 2 as an explicit deny, but per docs the JSON form is
    /// preferred and works with exit code 0. Other exit codes are fail-open
    /// (recorded but do not block). Grok's parser does NOT use
    /// `deny_unknown_fields`, so dcg's ergonomics fields (`ruleId`, `packId`,
    /// `severity`, `remediation`, …) pass through unmolested for any tooling
    /// that wants them. See `~/.grok/docs/user-guide/10-hooks.md`.
    Grok,
    /// Google Antigravity CLI (`agy`) protocol. Wire shape: stdin carries a
    /// nested `toolCall` object — `{"toolCall": {"name": "run_command",
    /// "args": {"CommandLine": "<cmd>", "Cwd": "<dir>"}}, "conversationId":
    /// "...", "stepIdx": N, "transcriptPath": "...", "workspacePaths": [...]}`.
    /// The shell command is in `toolCall.args.CommandLine` and the shell tool
    /// name is `run_command`. Block decision is expressed via stdout JSON
    /// `{"decision": "block", "reason": "..."}` with exit code 0 — verified
    /// empirically: `agy` honors both `"block"` and `"deny"` decision keywords
    /// and aborts the `run_command` tool, whereas a non-zero exit code is only
    /// logged (`pre-tool hook ... failed: ... exit status 2`) and does NOT
    /// reliably abort the tool. `agy`'s parser does not use
    /// `deny_unknown_fields`, so dcg's ergonomics fields (`ruleId`, `packId`,
    /// `severity`, `remediation`, …) pass through unmolested. `agy` reads its
    /// hook config from `~/.gemini/config/hooks.json` (with
    /// `~/.gemini/antigravity-cli/hooks.json` symlinked to it).
    Antigravity,
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

    // Strip a leading UTF-8 BOM (U+FEFF) before parsing. Some text tools prepend
    // a BOM; without this, BOM-prefixed but otherwise-valid hook input would
    // fail to parse and (by default) fail open — silently allowing a command
    // that should have been evaluated/blocked (issue #160). `serde_json` does
    // not skip a leading BOM on its own.
    let to_parse = input.strip_prefix('\u{feff}').unwrap_or(input.as_str());

    serde_json::from_str(to_parse).map_err(HookReadError::Json)
}

/// Detect which hook protocol should be used for output formatting.
///
/// # Protocol Disambiguation
///
/// Claude Code and Gemini payloads share several fields (`session_id`,
/// `transcript_path`, `cwd`) which makes naive field-presence checks
/// ambiguous. We disambiguate by checking Claude Code-specific indicators
/// **first** (Claude-compatible shell tool names, hook event `"PreToolUse"`,
/// and `CLAUDE_CODE` env var), then Gemini-specific markers (tool name
/// `"run_shell_command"` with hook event `"BeforeTool"`).
///
/// See: <https://github.com/Dicklesworthstone/destructive_command_guard/issues/77>
#[must_use]
pub fn detect_protocol(input: &HookInput) -> HookProtocol {
    let tool_name = input
        .tool_name
        .as_deref()
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    let hook_event_name = input.hook_event_name.as_deref().unwrap_or_default();

    // --- Antigravity CLI (`agy`) indicators (checked first) ---
    // `agy` is the only agent that nests the tool name and arguments under a
    // `toolCall` object (`{"toolCall": {"name": "run_command", "args":
    // {"CommandLine": "..."}}}`). None of the other supported agents emit a
    // `toolCall` field, so its mere presence unambiguously identifies `agy`.
    // We check this before every other protocol so the `agy`-specific deny
    // shape (stdout `{"decision":"block",...}` + exit 0) is always used.
    if let Some(tool_call) = input.tool_call.as_ref() {
        let tool_call_name = tool_call
            .name
            .as_deref()
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();
        // An empty/absent name still indicates the `agy` envelope shape; a
        // populated name should be the shell tool `run_command`.
        if tool_call_name.is_empty() || tool_call_name == "run_command" {
            return HookProtocol::Antigravity;
        }
    }

    // --- Hermes Agent indicators (checked first) ---
    // Hermes uses two distinctive markers:
    //   - hook_event_name="pre_tool_call" (snake_case; Claude uses PascalCase
    //     "PreToolUse", Codex uses the same PascalCase form, Gemini uses
    //     "BeforeTool", Copilot uses "pre-tool-use" via the `event` field).
    //   - tool_name="terminal" (none of the other agents use this name).
    // Either signal alone is a strong Hermes indicator. We check Hermes
    // before Copilot because Copilot's `event`/`tool_args` markers can
    // co-occur with arbitrary tool names — but if we see a `terminal` tool
    // or `pre_tool_call` event without those Copilot markers, it's Hermes.
    let is_hermes_event = hook_event_name == "pre_tool_call";
    let is_hermes_tool = tool_name == "terminal";
    if is_hermes_event || is_hermes_tool {
        // Disambiguate: if Copilot's distinctive `event` (which is hyphenated
        // "pre-tool-use", not snake_case "pre_tool_call") or `tool_args` is
        // also present, prefer Copilot. But neither Hermes signal collides
        // with Copilot's signals, so this is just a defensive check.
        if input.event.is_none() && input.tool_args.is_none() {
            return HookProtocol::Hermes;
        }
    }

    // --- Grok (xAI) indicators (checked alongside Hermes) ---
    // Grok uses two distinctive markers in its hook stdin envelope:
    //   - hookEventName="pre_tool_use" (snake_case "use"; Hermes uses "call",
    //     Claude uses PascalCase "PreToolUse", Copilot uses hyphenated
    //     "pre-tool-use" but only via the `event` field — never via
    //     `hookEventName`).
    //   - toolName="run_terminal_cmd" (Grok's internal shell tool name).
    // Either signal alone is a strong Grok indicator. We deliberately do
    // NOT add a GROK_* env-var fallback: real Grok hook invocations always
    // emit both fields, so the wire-level check is sufficient, and an
    // env-var fallback would risk false positives when dcg is invoked from
    // a shell that happens to live inside a Grok session (e.g. running
    // `cargo test` from a Grok-spawned terminal).
    let is_grok_event = hook_event_name == "pre_tool_use";
    let is_grok_tool = tool_name == "run_terminal_cmd";
    if (is_grok_event || is_grok_tool) && input.event.is_none() && input.tool_args.is_none() {
        return HookProtocol::Grok;
    }

    // --- Copilot indicators (checked first) ---
    // Copilot sends a distinctive `event` field (e.g. "pre-tool-use") that
    // neither Claude Code nor Gemini use. The `tool_args` field is also
    // Copilot-specific. Check these before tool-name-based heuristics
    // because Copilot can use tool_name="bash" (which overlaps with
    // Claude Code's tool names).
    if input.event.is_some() || input.tool_args.is_some() {
        return HookProtocol::Copilot;
    }

    // --- Codex CLI indicators (checked before Claude Code) ---
    // Codex 0.125.0+ shares Claude Code's tool name and most envelope
    // fields, so we disambiguate via `turn_id`, which the codex source
    // explicitly documents as "Codex extension: expose the active turn id
    // to internal turn-scoped hooks" (codex-rs/hooks/src/schema.rs). Claude
    // Code does NOT send `turn_id`. (We can't use `tool_use_id` for this
    // because Claude Code's PreToolUse stdin includes it too.) We must
    // classify Codex separately because its JSON parser is strict
    // (`deny_unknown_fields`) and would silently drop dcg's standard deny
    // payload, letting the destructive command through.
    let is_claude_compatible_shell_tool = matches!(
        tool_name.as_str(),
        "bash" | "launch-process" | "powershell" | "pwsh"
    ) || is_vscode_terminal_tool(&tool_name);
    let has_codex_turn_id = input
        .turn_id
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty());
    if is_claude_compatible_shell_tool && has_codex_turn_id {
        return HookProtocol::Codex;
    }

    // PowerShell tool names ("powershell"/"pwsh") are only ever emitted by
    // Codex-style payloads -- Claude Code's shell tool is always "Bash" (or
    // "launch-process"), never a PowerShell name, so this cannot collide with
    // Claude Code. On Windows, Codex drives commands through PowerShell but
    // does not always populate `turn_id` (issue #125), so the turn_id-gated
    // check above misses it and the destructive command would otherwise slip
    // through as a ClaudeCompatible result whose extension fields Codex's
    // strict parser drops. Classify a PowerShell tool name as Codex
    // unconditionally so the minimal Codex JSON path is used.
    // (`bash`/`launch-process` stay turn_id-gated because Claude Code
    // legitimately uses those names.)
    let is_powershell_tool = matches!(tool_name.as_str(), "powershell" | "pwsh");
    if is_powershell_tool {
        return HookProtocol::Codex;
    }

    // --- Claude-compatible indicators ---
    // Claude Code uses tool_name="Bash" or "launch-process"; Codex-style
    // shell payloads can also use PowerShell names. These tool names are not
    // Gemini's shell tool names, so check them before Gemini envelope fields.
    // Claude Code payloads also include session_id/cwd/transcript_path, which
    // would otherwise trigger a false Gemini classification (issue #77).
    if is_claude_compatible_shell_tool {
        return HookProtocol::ClaudeCompatible;
    }

    // The CLAUDE_CODE env var provides a strong secondary signal when the
    // tool name is ambiguous or absent.
    let is_claude_event =
        hook_event_name.is_empty() || hook_event_name.eq_ignore_ascii_case("pretooluse");
    let has_claude_env = std::env::var_os("CLAUDE_CODE").is_some()
        || std::env::var_os("CLAUDE_SESSION_ID").is_some();
    if has_claude_env && is_claude_event {
        return HookProtocol::ClaudeCompatible;
    }

    // --- Gemini indicators ---
    // Gemini uses tool_name="run_shell_command" and hook_event_name="BeforeTool".
    // It also sends envelope fields (session_id, transcript_path, cwd, timestamp)
    // but those alone are NOT sufficient since Claude Code also sends them.
    let is_gemini_tool = matches!(
        tool_name.as_str(),
        "run_shell_command" | "run-shell-command"
    );
    let is_gemini_event = hook_event_name.eq_ignore_ascii_case("beforetool");
    let has_gemini_envelope = input.session_id.is_some()
        || input.transcript_path.is_some()
        || input.cwd.is_some()
        || input.timestamp.is_some();

    // Strong Gemini signal: BeforeTool event with run_shell_command tool.
    if is_gemini_event && is_gemini_tool {
        return HookProtocol::Gemini;
    }

    // Weaker Gemini signal: envelope fields present AND Gemini-specific
    // event name (but possibly a different tool name).
    if is_gemini_event && has_gemini_envelope {
        return HookProtocol::Gemini;
    }

    // Envelope fields alone with a Gemini tool name (some integrations
    // omit hook_event_name).
    if has_gemini_envelope && is_gemini_tool {
        return HookProtocol::Gemini;
    }

    // Bare run_shell_command without Gemini context -- treat as Copilot
    // (some Copilot integrations use this tool name without `event`).
    if is_gemini_tool {
        return HookProtocol::Copilot;
    }

    // --- Default: Claude Code compatible (safest default) ---
    HookProtocol::ClaudeCompatible
}

/// Return whether `tool_name` is a VS Code Copilot Chat terminal tool.
///
/// Current VS Code documentation uses `runTerminalCommand`; live payloads have
/// also used `run_in_terminal`, and `runInTerminal` appears in compatibility
/// layers. Names are lowercased by the caller before reaching this helper.
fn is_vscode_terminal_tool(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "runterminalcommand" | "run_in_terminal" | "runinterminal"
    )
}

pub(crate) fn is_supported_shell_tool(tool_name: Option<&str>) -> bool {
    let Some(tool_name) = tool_name else {
        return false;
    };

    let normalized = tool_name.to_ascii_lowercase();
    is_vscode_terminal_tool(&normalized)
        || matches!(
            normalized.as_str(),
            "bash"
            | "launch-process"
            | "powershell"
            | "pwsh"
            | "run_shell_command"
            | "run-shell-command"
            // Hermes Agent shell tool. Distinct from Cursor's "terminal"
            // wrapper script which translates upstream to "Bash" before
            // invoking dcg, so the only path here is genuine Hermes input.
            | "terminal"
            // Grok (xAI) shell tool. Grok aliases Claude-style "Bash" to its
            // internal name `run_terminal_cmd` before invoking hooks, so the
            // toolName field on the wire is always this canonical form.
            | "run_terminal_cmd"
        )
}

pub(crate) fn is_shell_hook_candidate(input: &HookInput) -> bool {
    if is_supported_shell_tool(input.tool_name.as_deref()) {
        return true;
    }

    // Antigravity CLI (`agy`): the shell tool is `run_command`, named under
    // `toolCall.name`, with the command in `toolCall.args.CommandLine`.
    if let Some(tool_call) = input.tool_call.as_ref() {
        let name = tool_call
            .name
            .as_deref()
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();
        if name == "run_command" || (name.is_empty() && tool_call.args.is_some()) {
            return true;
        }
    }

    input.tool_name.is_none()
        && matches!(detect_protocol(input), HookProtocol::Copilot)
        && (input.tool_input.is_some() || input.tool_args.is_some())
}

/// Extract the shell command from an Antigravity (`agy`) `toolCall` envelope.
///
/// `agy`'s `run_command` tool carries the command in
/// `toolCall.args.CommandLine` (PascalCase). For robustness we also accept the
/// lowercase `command` key used by other agents in case `agy` ever normalizes.
fn extract_command_from_tool_call(tool_call: &ToolCall) -> Option<String> {
    let args = tool_call.args.as_ref()?;
    let serde_json::Value::Object(map) = args else {
        return None;
    };
    for key in ["CommandLine", "commandLine", "command", "Command"] {
        if let Some(serde_json::Value::String(s)) = map.get(key) {
            if !s.is_empty() {
                return Some(s.clone());
            }
        }
    }
    None
}

fn extract_command_from_tool_input(tool_input: &ToolInput) -> Option<String> {
    match tool_input.command.as_ref() {
        Some(serde_json::Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
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
    let protocol = detect_protocol(input);

    // Only process shell-command invocations for supported clients. Copilot
    // can omit toolName and put the shell command directly in toolArgs, so
    // treat that distinctive envelope as a shell candidate too.
    if !is_shell_hook_candidate(input) {
        return None;
    }

    // Antigravity CLI (`agy`) nests the command under `toolCall.args.CommandLine`.
    if let Some(tool_call) = input.tool_call.as_ref() {
        if let Some(command) = extract_command_from_tool_call(tool_call) {
            return Some((command, protocol));
        }
    }

    if let Some(tool_input) = input.tool_input.as_ref() {
        if let Some(command) = extract_command_from_tool_input(tool_input) {
            return Some((command, protocol));
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
    if std::env::var_os("NO_COLOR").is_some() || crate::output::env_flag_enabled("DCG_NO_COLOR") {
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

/// Write a colorful denial warning to an arbitrary writer (test seam).
#[allow(clippy::too_many_lines)]
pub(crate) fn print_colorful_warning_to(
    writer: &mut impl Write,
    command: &str,
    _reason: &str,
    pack: Option<&str>,
    pattern: Option<&str>,
    explanation: Option<&str>,
    allow_once_code: Option<&str>,
    matched_span: Option<&MatchSpan>,
    pattern_suggestions: &[PatternSuggestion],
    severity: Option<crate::packs::Severity>,
    branch_context: Option<&crate::evaluator::BranchContext>,
    audience: WarningAudience,
) {
    let theme = auto_theme();

    let rule_id = build_rule_id(pack, pattern);
    let pattern_display = rule_id.as_deref().or(pack).unwrap_or("unknown pattern");

    let theme_severity = severity
        .map(to_output_severity)
        .unwrap_or(ThemeSeverity::High);

    let explanation_text = explanation.map(str::trim).filter(|text| !text.is_empty());

    let span = matched_span
        .map(|s| HighlightSpan::new(s.start, s.end))
        .unwrap_or_else(|| HighlightSpan::new(0, 0));

    let alternatives = pattern_suggestion_alternatives(
        command,
        crate::output::suggestions_enabled(),
        pattern_suggestions,
    );

    let mut denial = DenialBox::new(command, span, pattern_display, theme_severity)
        .with_alternatives(alternatives);

    if let (Some(pack_id), Some(pattern_name)) = (pack, pattern) {
        if let Some(regex) = crate::highlight::find_pattern_regex(pack_id, pattern_name) {
            denial = denial.with_pattern_regex(regex);
        }
    }

    if let Some(text) = explanation_text {
        denial = denial.with_explanation(text);
    }

    if audience == WarningAudience::HumanOperator
        && let Some(code) = allow_once_code
    {
        denial = denial.with_allow_once_code(code);
    }

    if let Some(ctx) = branch_context {
        if let Some(name) = &ctx.branch_name {
            denial = denial.with_branch_context(name, ctx.is_protected);
        }
    }

    let _ = writeln!(writer, "{}", denial.render(&theme));

    let escaped_cmd = command.replace('"', "\\\"");
    let truncated_cmd = truncate_for_display(&escaped_cmd, 45);
    let explain_cmd = format!("dcg explain \"{truncated_cmd}\"");

    let footer_style = if theme.colors_enabled { "\x1b[90m" } else { "" };
    let reset = if theme.colors_enabled { "\x1b[0m" } else { "" };
    let cyan = if theme.colors_enabled { "\x1b[36m" } else { "" };

    match audience {
        WarningAudience::HumanOperator => {
            let _ = writeln!(writer, "{footer_style}Learn more:{reset}");
            let _ = writeln!(writer, "  $ {cyan}{explain_cmd}{reset}");

            if let Some(ref rule) = rule_id {
                let _ = writeln!(
                    writer,
                    "  $ {cyan}dcg allowlist add {rule} --project{reset}"
                );
            }

            let _ = writeln!(writer);
            let _ = writeln!(
                writer,
                "{footer_style}False positive? File an issue:{reset}"
            );
            let _ = writeln!(
                writer,
                "{footer_style}https://github.com/Dicklesworthstone/destructive_command_guard/issues/new?template=false_positive.yml{reset}"
            );
            let _ = writeln!(writer);
        }
        WarningAudience::CodexModel => {
            if let Some(ref rule) = rule_id {
                let _ = writeln!(writer, "{footer_style}Rule: {rule}{reset}");
            }
            let _ = writeln!(
                writer,
                "{footer_style}This command is blocked. Do not retry it, create a bypass, or change dcg policy yourself. Ask the user for explicit permission if the operation is truly required.{reset}"
            );
            let _ = writeln!(writer);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WarningAudience {
    HumanOperator,
    CodexModel,
}

fn pattern_suggestion_alternatives(
    command: &str,
    suggestions_enabled: bool,
    pattern_suggestions: &[PatternSuggestion],
) -> Vec<String> {
    if !suggestions_enabled {
        return Vec::new();
    }

    let mut alternatives: Vec<String> = pattern_suggestions
        .iter()
        .filter(|suggestion| suggestion.platform.matches_current())
        .take(MAX_SUGGESTIONS)
        .map(|suggestion| format!("{}: {}", suggestion.description, suggestion.command))
        .collect();

    if alternatives.is_empty() {
        if let Some(suggestion) = get_contextual_suggestion(command) {
            alternatives.push(suggestion.to_string());
        }
    }

    alternatives
}

/// Print a colorful warning to stderr for human visibility.
#[allow(clippy::too_many_lines)]
pub fn print_colorful_warning(
    command: &str,
    reason: &str,
    pack: Option<&str>,
    pattern: Option<&str>,
    explanation: Option<&str>,
    allow_once_code: Option<&str>,
    matched_span: Option<&MatchSpan>,
    pattern_suggestions: &[PatternSuggestion],
    severity: Option<crate::packs::Severity>,
) {
    let stderr = io::stderr();
    let mut handle = stderr.lock();
    print_colorful_warning_to(
        &mut handle,
        command,
        reason,
        pack,
        pattern,
        explanation,
        allow_once_code,
        matched_span,
        pattern_suggestions,
        severity,
        None,
        WarningAudience::HumanOperator,
    );
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

/// Write a denial response to arbitrary stdout/stderr writers.
///
/// This is public so integration tests and Criterion benchmarks can exercise
/// protocol formatting without touching process stdout/stderr.
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub fn write_denial_to(
    stdout: &mut impl Write,
    stderr: &mut impl Write,
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
    branch_context: Option<&crate::evaluator::BranchContext>,
) {
    let allow_once_code = allow_once.map(|info| info.code.as_str());
    let warning_audience = match protocol {
        HookProtocol::Codex => WarningAudience::CodexModel,
        HookProtocol::ClaudeCompatible
        | HookProtocol::Copilot
        | HookProtocol::Gemini
        | HookProtocol::Hermes
        | HookProtocol::Grok
        | HookProtocol::Antigravity => WarningAudience::HumanOperator,
    };

    print_colorful_warning_to(
        stderr,
        command,
        reason,
        pack,
        pattern,
        explanation,
        allow_once_code,
        matched_span,
        pattern_suggestions,
        severity,
        branch_context,
        warning_audience,
    );

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

    match protocol {
        HookProtocol::ClaudeCompatible => {
            let output = HookOutput {
                hook_specific_output: HookSpecificOutput {
                    hook_event_name: "PreToolUse",
                    permission_decision: "deny",
                    permission_decision_reason: Cow::Owned(message.clone()),
                    allow_once_code: allow_once.map(|info| info.code.clone()),
                    allow_once_full_hash: allow_once.map(|info| info.full_hash.clone()),
                    rule_id,
                    pack_id: pack.map(String::from),
                    severity,
                    confidence,
                    remediation,
                },
            };

            let _ = serde_json::to_writer(&mut *stdout, &output);
            let _ = writeln!(stdout);
        }
        HookProtocol::Codex => {
            // Codex 0.144.x: emit only the documented PreToolUse fields.
            // Extra dcg metadata is intentionally omitted because Codex's
            // parser is stricter than Claude's.  Exit remains 0; some current
            // Codex builds classify exit 2 as hook failure and then fail open.
            let output = HookOutput {
                hook_specific_output: HookSpecificOutput {
                    hook_event_name: "PreToolUse",
                    permission_decision: "deny",
                    permission_decision_reason: Cow::Owned(message),
                    allow_once_code: None,
                    allow_once_full_hash: None,
                    rule_id: None,
                    pack_id: None,
                    severity: None,
                    confidence: None,
                    remediation: None,
                },
            };

            let _ = serde_json::to_writer(&mut *stdout, &output);
            let _ = writeln!(stdout);
        }
        HookProtocol::Copilot => {
            let output = CopilotHookOutput {
                permission_decision: "deny",
                permission_decision_reason: Cow::Owned(message),
            };

            let _ = serde_json::to_writer(&mut *stdout, &output);
            let _ = writeln!(stdout);
        }
        HookProtocol::Gemini => {
            let output = GeminiHookOutput {
                decision: "deny",
                reason: Cow::Owned(message),
                system_message: Some(Cow::Owned(format!("BLOCKED by dcg: {reason}"))),
                allow_once_code: allow_once.map(|info| info.code.clone()),
                allow_once_full_hash: allow_once.map(|info| info.full_hash.clone()),
                rule_id,
                pack_id: pack.map(String::from),
                severity,
                confidence,
                remediation,
            };

            let _ = serde_json::to_writer(&mut *stdout, &output);
            let _ = writeln!(stdout);
        }
        HookProtocol::Hermes => {
            // Hermes uses the keyword "block" (not "deny") and accepts both
            // {"decision":"block","reason":...} and {"action":"block",
            // "message":...}. We emit both pairs so either Hermes codepath
            // sees a valid block, plus the dcg-specific ergonomics fields
            // (Hermes' parser does NOT use `deny_unknown_fields`, so the
            // extras pass through unmolested for any tooling that wants
            // them).
            let output = HermesHookOutput {
                decision: "block",
                reason: Cow::Owned(message.clone()),
                action: "block",
                message: Cow::Owned(message),
                allow_once_code: allow_once.map(|info| info.code.clone()),
                allow_once_full_hash: allow_once.map(|info| info.full_hash.clone()),
                rule_id,
                pack_id: pack.map(String::from),
                severity,
                confidence,
                remediation,
            };

            let _ = serde_json::to_writer(&mut *stdout, &output);
            let _ = writeln!(stdout);
        }
        HookProtocol::Grok => {
            // Grok requires the keyword "deny" (not "block"). Exit code 0 +
            // JSON is the documented preferred path and Grok will block on
            // that alone. Other exit codes are fail-open, so we deliberately
            // avoid relying on the exit code here. The colored deny message
            // has already been written to stderr for human/model visibility.
            let output = GrokHookOutput {
                decision: "deny",
                reason: Cow::Owned(message),
                allow_once_code: allow_once.map(|info| info.code.clone()),
                allow_once_full_hash: allow_once.map(|info| info.full_hash.clone()),
                rule_id,
                pack_id: pack.map(String::from),
                severity,
                confidence,
                remediation,
            };

            let _ = serde_json::to_writer(&mut *stdout, &output);
            let _ = writeln!(stdout);
        }
        HookProtocol::Antigravity => {
            // Antigravity CLI (`agy`): stdout `{"decision":"block","reason":...}`
            // with exit code 0 aborts the `run_command` tool. Verified
            // empirically that `agy` honors the `"block"` keyword (and `"deny"`
            // — both block); a non-zero exit code is only logged and does NOT
            // reliably abort the tool, so we always emit exit 0 + JSON. We
            // reuse GeminiHookOutput's wire shape (`decision`/`reason` plus
            // optional `systemMessage` and dcg ergonomics fields); `agy`'s
            // parser tolerates the extra fields.
            let output = GeminiHookOutput {
                decision: "block",
                reason: Cow::Owned(message),
                system_message: Some(Cow::Owned(format!("BLOCKED by dcg: {reason}"))),
                allow_once_code: allow_once.map(|info| info.code.clone()),
                allow_once_full_hash: allow_once.map(|info| info.full_hash.clone()),
                rule_id,
                pack_id: pack.map(String::from),
                severity,
                confidence,
                remediation,
            };

            let _ = serde_json::to_writer(&mut *stdout, &output);
            let _ = writeln!(stdout);
        }
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
    branch_context: Option<&crate::evaluator::BranchContext>,
) {
    let out = io::stdout();
    let mut out_handle = out.lock();
    let err = io::stderr();
    let mut err_handle = err.lock();
    write_denial_to(
        &mut out_handle,
        &mut err_handle,
        protocol,
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
        branch_context,
    );
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
        None,
    );
}

/// Write a warning response to arbitrary stdout/stderr writers (test seam).
#[cold]
#[inline(never)]
pub(crate) fn write_warning_to(
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    protocol: HookProtocol,
    command: &str,
    reason: &str,
    pack: Option<&str>,
    pattern: Option<&str>,
    explanation: Option<&str>,
) {
    // -- stderr: human-visible warning --
    {
        let _ = writeln!(stderr);
        let _ = writeln!(stderr, "{} {}", "dcg WARNING:".yellow().bold(), reason);

        let rule_id = build_rule_id(pack, pattern);
        let explanation_text = format_explanation_text(explanation, rule_id.as_deref(), pack);
        let mut explanation_lines = explanation_text.lines();

        if let Some(first) = explanation_lines.next() {
            let _ = writeln!(stderr, "  {} {}", "Explanation:".bright_black(), first);
            for line in explanation_lines {
                let _ = writeln!(stderr, "               {line}");
            }
        }

        if let Some(ref rule) = rule_id {
            let _ = writeln!(stderr, "  {} {}", "Rule:".bright_black(), rule);
        } else if let Some(pack_name) = pack {
            let _ = writeln!(stderr, "  {} {}", "Pack:".bright_black(), pack_name);
        }

        let _ = writeln!(stderr, "  {} {}", "Command:".bright_black(), command);
    }

    // -- stdout: hook-protocol JSON with "ask" decision --
    let rule_id = build_rule_id(pack, pattern);
    let warn_reason = format!("DCG warn: {reason}");

    match protocol {
        HookProtocol::ClaudeCompatible => {
            let output = HookOutput {
                hook_specific_output: HookSpecificOutput {
                    hook_event_name: "PreToolUse",
                    permission_decision: "ask",
                    permission_decision_reason: Cow::Owned(warn_reason),
                    allow_once_code: None,
                    allow_once_full_hash: None,
                    rule_id,
                    pack_id: pack.map(String::from),
                    severity: None,
                    confidence: None,
                    remediation: None,
                },
            };

            let _ = serde_json::to_writer(&mut *stdout, &output);
            let _ = writeln!(stdout);
        }
        HookProtocol::Copilot => {
            // `ask` is part of Copilot's documented preToolUse contract.
            let output = CopilotHookOutput {
                permission_decision: "ask",
                permission_decision_reason: Cow::Owned(warn_reason),
            };

            let _ = serde_json::to_writer(&mut *stdout, &output);
            let _ = writeln!(stdout);
        }
        HookProtocol::Gemini => {
            // Gemini hooks support allow/deny only. Preserve dcg warn as
            // non-blocking while still surfacing the warning text to Gemini.
            let output = GeminiHookOutput {
                decision: "allow",
                reason: Cow::Owned(warn_reason.clone()),
                system_message: Some(Cow::Owned(warn_reason)),
                allow_once_code: None,
                allow_once_full_hash: None,
                rule_id,
                pack_id: pack.map(String::from),
                severity: None,
                confidence: None,
                remediation: None,
            };

            let _ = serde_json::to_writer(&mut *stdout, &output);
            let _ = writeln!(stdout);
        }
        HookProtocol::Codex => {
            // Codex: stderr warning already written above; no stdout JSON.
        }
        HookProtocol::Hermes => {
            // Hermes hooks support a "block" decision but no documented
            // "ask" or "warn" decision. Surface dcg warnings to the user via
            // the documented `context` field (which `pre_llm_call` consumes
            // verbatim) AND keep the run going. For pre_tool_call, an empty
            // {} response means "no opinion, proceed normally", so we emit
            // {"context": "<warn message>"} which is structurally valid in
            // both events while preserving the warning text for any tooling
            // that surfaces context fields.
            #[derive(Serialize)]
            struct HermesWarningOutput<'a> {
                context: Cow<'a, str>,
            }
            let output = HermesWarningOutput {
                context: Cow::Owned(warn_reason),
            };
            let _ = serde_json::to_writer(&mut *stdout, &output);
            let _ = writeln!(stdout);
        }
        HookProtocol::Grok => {
            // Grok hooks support `{"decision":"allow"}` and `{"decision":
            // "deny"}` but no documented "ask"/"warn" decision. Preserve dcg
            // warn semantics as non-blocking by emitting an explicit "allow"
            // (Grok's docs note that explicit allow short-circuits later
            // hooks; for dcg this is the safe choice because we never want
            // a warn to escalate to a deny later). The warning text is
            // preserved via the optional `reason` field, which Grok logs in
            // the hooks scrollback even on allow decisions.
            let output = GrokHookOutput {
                decision: "allow",
                reason: Cow::Owned(warn_reason),
                allow_once_code: None,
                allow_once_full_hash: None,
                rule_id,
                pack_id: pack.map(String::from),
                severity: None,
                confidence: None,
                remediation: None,
            };
            let _ = serde_json::to_writer(&mut *stdout, &output);
            let _ = writeln!(stdout);
        }
        HookProtocol::Antigravity => {
            // Antigravity CLI (`agy`) supports a "block"/"deny" decision but no
            // documented "ask"/"warn" decision. Preserve dcg warn semantics as
            // non-blocking by emitting an explicit "allow"; the warning text is
            // surfaced via `reason`/`systemMessage` for any tooling that shows
            // hook context.
            let output = GeminiHookOutput {
                decision: "allow",
                reason: Cow::Owned(warn_reason.clone()),
                system_message: Some(Cow::Owned(warn_reason)),
                allow_once_code: None,
                allow_once_full_hash: None,
                rule_id,
                pack_id: pack.map(String::from),
                severity: None,
                confidence: None,
                remediation: None,
            };
            let _ = serde_json::to_writer(&mut *stdout, &output);
            let _ = writeln!(stdout);
        }
    }
}

/// Output a warning for a warn-severity match.
#[cold]
#[inline(never)]
pub fn output_warning_for_protocol(
    protocol: HookProtocol,
    command: &str,
    reason: &str,
    pack: Option<&str>,
    pattern: Option<&str>,
    explanation: Option<&str>,
) {
    let out = io::stdout();
    let mut out_handle = out.lock();
    let err = io::stderr();
    let mut err_handle = err.lock();
    write_warning_to(
        &mut out_handle,
        &mut err_handle,
        protocol,
        command,
        reason,
        pack,
        pattern,
        explanation,
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
    fn test_codex_protocol_detected_via_turn_id() {
        // Codex 0.125.0+ stdin: same Bash tool name as Claude Code, but
        // codex-rs/hooks/src/schema.rs annotates `turn_id` as "Codex
        // extension: expose the active turn id to internal turn-scoped
        // hooks". Claude Code does not send turn_id, so its presence on a
        // Bash payload is the disambiguator.
        let json = r#"{
            "session_id":"019dd11d-b795-7261-a9cb-9b85a5dad632",
            "turn_id":"turn-1",
            "transcript_path":null,
            "cwd":"/tmp/x",
            "hook_event_name":"PreToolUse",
            "model":"gpt-5.5",
            "permission_mode":"bypassPermissions",
            "tool_name":"Bash",
            "tool_input":{"command":"git reset --hard"},
            "tool_use_id":"call_abc123"
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Codex);
        assert_eq!(
            extract_command(&input),
            Some("git reset --hard".to_string())
        );
    }

    #[test]
    fn test_empty_turn_id_is_not_treated_as_codex() {
        // Defense in depth: only a non-empty turn_id flips us into Codex
        // mode. A literal empty string from a malformed client should fall
        // through to the Claude-compatible default rather than silently
        // dropping our deny payload.
        let json = r#"{
            "tool_name":"Bash",
            "tool_input":{"command":"git status"},
            "turn_id":""
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::ClaudeCompatible);
    }

    #[test]
    fn test_powershell_tool_without_turn_id_is_codex() {
        // issue #125: on Windows, Codex drives shell commands through
        // PowerShell but does not always send `turn_id`. Without the
        // PowerShell-name fallback this payload would be classified as
        // ClaudeCompatible (exit 0 + JSON that Codex's strict parser drops),
        // letting the destructive command through. A PowerShell tool name is
        // Codex-only (Claude Code always uses "Bash"/"launch-process"), so it
        // must classify as Codex even with no turn_id.
        for tool in ["powershell", "pwsh", "PowerShell", "PWSH"] {
            let json = format!(
                r#"{{"tool_name":"{tool}","tool_input":{{"command":"git reset --hard HEAD~1"}}}}"#
            );
            let input: HookInput = serde_json::from_str(&json).unwrap();
            assert_eq!(
                detect_protocol(&input),
                HookProtocol::Codex,
                "PowerShell tool_name {tool:?} must be treated as Codex (issue #125)"
            );
            assert_eq!(
                extract_command(&input),
                Some("git reset --hard HEAD~1".to_string())
            );
        }
    }

    #[test]
    fn test_bash_without_turn_id_stays_claude_compatible() {
        // Regression guard for the #125 fix: only PowerShell names get the
        // unconditional-Codex treatment. `bash`/`launch-process` are shared
        // with Claude Code, so without a turn_id they must stay
        // ClaudeCompatible rather than being mis-flipped to Codex.
        for tool in ["Bash", "bash", "launch-process"] {
            let json =
                format!(r#"{{"tool_name":"{tool}","tool_input":{{"command":"git status"}}}}"#);
            let input: HookInput = serde_json::from_str(&json).unwrap();
            assert_eq!(
                detect_protocol(&input),
                HookProtocol::ClaudeCompatible,
                "{tool:?} without turn_id must stay ClaudeCompatible"
            );
        }
    }

    #[test]
    fn test_claude_code_with_tool_use_id_is_not_codex() {
        // Regression guard: Claude Code's PreToolUse stdin includes
        // `tool_use_id` (per code.claude.com/docs/en/hooks). A naive
        // disambiguator that keyed on tool_use_id would mis-classify Claude
        // Code as Codex and drop our full deny payload from stdout, which
        // would let destructive commands through. Detection must use
        // turn_id (Codex-only), so this Claude-shaped payload that has
        // tool_use_id but NOT turn_id stays Claude-compatible.
        let json = r#"{
            "session_id":"abc123",
            "transcript_path":"/home/user/.claude/projects/x/transcript.jsonl",
            "cwd":"/home/user/my-project",
            "permission_mode":"default",
            "hook_event_name":"PreToolUse",
            "tool_name":"Bash",
            "tool_input":{"command":"git status"},
            "tool_use_id":"toolu_01ABC"
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::ClaudeCompatible);
    }

    #[test]
    fn test_parse_non_bash_input() {
        let json = r#"{"tool_name":"Read","tool_input":{"command":"git status"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(extract_command(&input), None);
    }

    #[test]
    fn test_vscode_terminal_tool_variants_are_claude_compatible() {
        for tool_name in ["runTerminalCommand", "run_in_terminal", "runInTerminal"] {
            let json = serde_json::json!({
                "hook_event_name": "PreToolUse",
                "tool_name": tool_name,
                "tool_input": {
                    "command": "git reset --hard",
                    "explanation": "Reset the repository",
                    "mode": "run",
                    "timeout": 30_000,
                },
            });
            let input: HookInput = serde_json::from_value(json).unwrap();

            assert!(
                is_supported_shell_tool(Some(tool_name)),
                "VS Code terminal tool {tool_name:?} must be evaluated"
            );
            assert_eq!(
                detect_protocol(&input),
                HookProtocol::ClaudeCompatible,
                "VS Code uses hookSpecificOutput, not the Copilot CLI wire format"
            );
            assert_eq!(
                extract_command(&input),
                Some("git reset --hard".to_string())
            );
        }
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
    fn test_parse_copilot_powershell_tool_args_object() {
        // GitHub Copilot CLI documents "powershell" as its Windows shell tool
        // name. It must be treated as a shell-command hook, not ignored as a
        // non-shell tool.
        let json = r#"{"event":"pre-tool-use","toolName":"powershell","toolArgs":{"command":"git reset --hard"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Copilot);
        assert_eq!(
            extract_command(&input),
            Some("git reset --hard".to_string())
        );
    }

    #[test]
    fn test_parse_copilot_powershell_tool_input_command() {
        let json = r#"{"event":"pre-tool-use","toolName":"powershell","toolInput":{"command":"git reset --hard"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Copilot);
        assert_eq!(
            extract_command(&input),
            Some("git reset --hard".to_string())
        );
    }

    #[test]
    fn test_parse_copilot_tool_args_without_tool_name() {
        let json = r#"{"event":"pre-tool-use","toolArgs":"{\"command\":\"git reset --hard\"}"}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Copilot);
        assert_eq!(
            extract_command(&input),
            Some("git reset --hard".to_string())
        );
    }

    #[test]
    fn test_parse_copilot_tool_input_without_tool_name() {
        let json = r#"{"event":"pre-tool-use","toolInput":{"command":"git status"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Copilot);
        assert_eq!(extract_command(&input), Some("git status".to_string()));
    }

    #[test]
    fn test_parse_gemini_before_tool_input() {
        let json = r#"{
            "session_id":"session-123",
            "transcript_path":"/tmp/transcript.json",
            "cwd":"/tmp",
            "hook_event_name":"BeforeTool",
            "timestamp":"2026-02-24T00:00:00Z",
            "tool_name":"run_shell_command",
            "tool_input":{"command":"git status"}
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(extract_command(&input), Some("git status".to_string()));
        assert_eq!(detect_protocol(&input), HookProtocol::Gemini);
    }

    #[test]
    fn test_hook_event_name_alone_does_not_force_gemini_protocol() {
        let json = r#"{
            "hook_event_name":"BeforeTool",
            "tool_name":"Bash",
            "tool_input":{"command":"git status"}
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(extract_command(&input), Some("git status".to_string()));
        assert_eq!(detect_protocol(&input), HookProtocol::ClaudeCompatible);
    }

    #[test]
    fn test_gemini_before_tool_marker_detects_gemini_without_session_fields() {
        let json = r#"{
            "hook_event_name":"BeforeTool",
            "tool_name":"run_shell_command",
            "tool_input":{"command":"git status"}
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(extract_command(&input), Some("git status".to_string()));
        assert_eq!(detect_protocol(&input), HookProtocol::Gemini);
    }

    #[test]
    fn test_gemini_hook_output_json_shape() {
        let output = GeminiHookOutput {
            decision: "deny",
            reason: Cow::Borrowed("blocked for safety"),
            system_message: Some(Cow::Borrowed("BLOCKED by dcg: test")),
            allow_once_code: None,
            allow_once_full_hash: None,
            rule_id: Some("core.git:reset-hard".to_string()),
            pack_id: Some("core.git".to_string()),
            severity: None,
            confidence: None,
            remediation: None,
        };
        let json = serde_json::to_value(&output).unwrap();
        assert_eq!(json["decision"], "deny");
        assert_eq!(json["reason"], "blocked for safety");
        assert_eq!(json["systemMessage"], "BLOCKED by dcg: test");
        assert!(json.get("continue").is_none());
        assert!(json.get("stopReason").is_none());
        assert_eq!(json["ruleId"], "core.git:reset-hard");
        assert_eq!(json["packId"], "core.git");
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
    fn test_claude_compatible_warn_ask_json_shape() {
        let output = HookOutput {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse",
                permission_decision: "ask",
                permission_decision_reason: Cow::Borrowed("DCG warn: risky pattern"),
                allow_once_code: None,
                allow_once_full_hash: None,
                rule_id: Some("core.git:checkout-dot".to_string()),
                pack_id: Some("core.git".to_string()),
                severity: None,
                confidence: None,
                remediation: None,
            },
        };
        let json = serde_json::to_value(&output).unwrap();
        let specific = &json["hookSpecificOutput"];
        assert_eq!(specific["hookEventName"], "PreToolUse");
        assert_eq!(specific["permissionDecision"], "ask");
        assert!(
            specific["permissionDecisionReason"]
                .as_str()
                .unwrap()
                .starts_with("DCG warn:")
        );
        assert_eq!(specific["ruleId"], "core.git:checkout-dot");
        assert_eq!(specific["packId"], "core.git");
    }

    #[test]
    fn test_copilot_warn_ask_json_shape() {
        let output = CopilotHookOutput {
            permission_decision: "ask",
            permission_decision_reason: Cow::Borrowed("DCG warn: risky pattern"),
        };
        let json = serde_json::to_value(&output).unwrap();
        assert_eq!(json["permissionDecision"], "ask");
        assert!(json.get("continue").is_none());
        assert!(json.get("stopReason").is_none());
    }

    #[test]
    fn test_gemini_warn_allow_json_shape() {
        let output = GeminiHookOutput {
            decision: "allow",
            reason: Cow::Borrowed("DCG warn: risky pattern"),
            system_message: Some(Cow::Borrowed("DCG warn: risky pattern")),
            allow_once_code: None,
            allow_once_full_hash: None,
            rule_id: None,
            pack_id: None,
            severity: None,
            confidence: None,
            remediation: None,
        };
        let json = serde_json::to_value(&output).unwrap();
        assert_eq!(json["decision"], "allow");
        assert!(json["reason"].as_str().unwrap().starts_with("DCG warn:"));
    }

    // =========================================================================
    // Hermes Agent (NousResearch) protocol tests — issue #110.
    // =========================================================================

    #[test]
    fn test_parse_hermes_pre_tool_call_input() {
        // Exact wire shape documented at
        // https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/features/hooks.md
        let json = r#"{
            "hook_event_name":"pre_tool_call",
            "tool_name":"terminal",
            "tool_input":{"command":"rm -rf /"},
            "session_id":"sess_abc123",
            "cwd":"/home/user/project",
            "extra":{"task_id":"task-1","tool_call_id":"call-1"}
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(extract_command(&input), Some("rm -rf /".to_string()));
        assert_eq!(detect_protocol(&input), HookProtocol::Hermes);
    }

    #[test]
    fn test_hermes_detected_via_event_alone() {
        // pre_tool_call is the unique snake_case event name; even with a
        // non-Hermes-shaped tool name we still classify Hermes since no
        // other supported agent uses this event marker.
        let json = r#"{
            "hook_event_name":"pre_tool_call",
            "tool_name":"bash",
            "tool_input":{"command":"git status"}
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Hermes);
    }

    #[test]
    fn test_hermes_detected_via_terminal_tool_alone() {
        // tool_name="terminal" without an event field is still Hermes — no
        // other supported agent uses the literal string "terminal".
        let json = r#"{
            "tool_name":"terminal",
            "tool_input":{"command":"echo hi"}
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Hermes);
    }

    #[test]
    fn test_hermes_loses_to_copilot_when_event_field_present() {
        // If the Copilot-specific `event` field is present, we should
        // NOT misclassify as Hermes — Copilot's payloads can name their
        // own tools, and we must keep dispatching to Copilot's wire format.
        let json = r#"{
            "event":"pre-tool-use",
            "hook_event_name":"pre_tool_call",
            "tool_name":"terminal",
            "tool_input":{"command":"git status"}
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Copilot);
    }

    #[test]
    fn test_hermes_loses_to_copilot_when_tool_args_present() {
        // tool_args is Copilot-distinctive; if it's present, route to
        // Copilot regardless of the Hermes-shaped event/tool name.
        let json = r#"{
            "hook_event_name":"pre_tool_call",
            "tool_name":"terminal",
            "tool_args":"{\"command\":\"git status\"}"
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Copilot);
    }

    #[test]
    fn test_hermes_pre_tool_call_with_session_envelope_not_gemini() {
        // Hermes shares `session_id`/`cwd` with Gemini, but the snake_case
        // event name disambiguates. Regression coverage in the spirit of
        // issue #77 (Claude/Gemini overlap).
        let json = r#"{
            "session_id":"sess",
            "cwd":"/tmp",
            "hook_event_name":"pre_tool_call",
            "tool_name":"terminal",
            "tool_input":{"command":"ls"}
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Hermes);
    }

    #[test]
    fn test_hermes_hook_output_block_decision_json_shape() {
        // The struct must serialize with "decision":"block" AND
        // "action":"block" so either Hermes codepath registers a block.
        let output = HermesHookOutput {
            decision: "block",
            reason: Cow::Borrowed("blocked for safety"),
            action: "block",
            message: Cow::Borrowed("blocked for safety"),
            allow_once_code: None,
            allow_once_full_hash: None,
            rule_id: Some("core.git:reset-hard".to_string()),
            pack_id: Some("core.git".to_string()),
            severity: None,
            confidence: None,
            remediation: None,
        };
        let json = serde_json::to_value(&output).unwrap();
        assert_eq!(json["decision"], "block");
        assert_eq!(json["reason"], "blocked for safety");
        assert_eq!(json["action"], "block");
        assert_eq!(json["message"], "blocked for safety");
        assert_eq!(json["ruleId"], "core.git:reset-hard");
        assert_eq!(json["packId"], "core.git");
        // Hermes rejects "deny"/"continue"/"stopReason" — those are the
        // wire shapes for OTHER agents and would be ignored here.
        assert!(json.get("permissionDecision").is_none());
        assert!(json.get("continue").is_none());
        assert!(json.get("hookSpecificOutput").is_none());
    }

    #[test]
    fn test_write_denial_hermes_produces_block_json() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        write_denial_to(
            &mut stdout,
            &mut stderr,
            HookProtocol::Hermes,
            "rm -rf /",
            "catastrophic filesystem deletion",
            Some("core.filesystem"),
            Some("rm-rf-root"),
            None,
            None,
            None,
            Some(crate::packs::Severity::Critical),
            None,
            &[],
            None,
        );

        let stdout_str = String::from_utf8_lossy(&stdout);
        let json: serde_json::Value = serde_json::from_str(stdout_str.trim())
            .unwrap_or_else(|e| panic!("stdout not valid JSON: {e}\nstdout: {stdout_str}"));

        assert_eq!(json["decision"], "block");
        assert_eq!(json["action"], "block");
        assert!(
            json["reason"]
                .as_str()
                .unwrap()
                .contains("catastrophic filesystem deletion")
        );
        assert!(
            json["message"]
                .as_str()
                .unwrap()
                .contains("catastrophic filesystem deletion")
        );
        // stderr must contain the colored warning text for human visibility.
        assert!(
            !stderr.is_empty(),
            "Hermes denial must still surface stderr warning text"
        );
    }

    #[test]
    fn test_write_warning_hermes_produces_context_json() {
        // Hermes has no documented "ask" / "warn" decision. We surface the
        // warn text via the documented `context` field which is allowed
        // for any pre_* event and treated as advisory metadata.
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        write_warning_to(
            &mut stdout,
            &mut stderr,
            HookProtocol::Hermes,
            "git stash drop",
            "drops stashed changes",
            Some("core.git"),
            Some("stash-drop"),
            None,
        );

        let stdout_str = String::from_utf8_lossy(&stdout);
        let json: serde_json::Value = serde_json::from_str(stdout_str.trim())
            .unwrap_or_else(|e| panic!("stdout not valid JSON: {e}\nstdout: {stdout_str}"));

        assert!(json["context"].as_str().unwrap().starts_with("DCG warn:"));
        // Crucially: must NOT carry a "block" decision when warning.
        assert!(json.get("decision").is_none());
        assert!(json.get("action").is_none());
        assert!(!stderr.is_empty(), "stderr must contain warn text");
    }

    // =========================================================================
    // Grok (xAI) protocol detection + denial / warning JSON shape.
    //
    // Grok's wire shape and JSON contract are documented in
    // ~/.grok/docs/user-guide/10-hooks.md. The critical invariants:
    //   - hookEventName="pre_tool_use" (snake_case; distinct from Hermes
    //     "pre_tool_call" and Claude's PascalCase "PreToolUse").
    //   - toolName="run_terminal_cmd" (Grok's internal shell tool).
    //   - Block decision: {"decision":"deny","reason":...} — note "deny",
    //     NOT "block" (Hermes uses "block").
    //   - Allow / passive: {"decision":"allow"} or empty {}; exit 0 expected.
    // =========================================================================

    #[test]
    fn test_grok_detected_via_event_alone() {
        // pre_tool_use is unique to Grok; even with a generic toolName we
        // must still route to the Grok protocol.
        let json = r#"{
            "hookEventName":"pre_tool_use",
            "toolName":"bash",
            "toolInput":{"command":"git status"}
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Grok);
    }

    #[test]
    fn test_grok_detected_via_run_terminal_cmd_tool_alone() {
        // run_terminal_cmd is Grok's internal shell tool name; no other
        // supported agent uses it. Even without hookEventName we route to
        // Grok.
        let json = r#"{
            "toolName":"run_terminal_cmd",
            "toolInput":{"command":"echo hi"}
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Grok);
    }

    #[test]
    fn test_grok_full_envelope_camelcase() {
        // Realistic Grok payload, every documented field present.
        let json = r#"{
            "hookEventName":"pre_tool_use",
            "sessionId":"sess-abc",
            "cwd":"/home/user/proj",
            "workspaceRoot":"/home/user/proj",
            "toolName":"run_terminal_cmd",
            "toolInput":{"command":"rm -rf /"},
            "timestamp":"2026-05-14T12:00:00Z"
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Grok);
    }

    #[test]
    fn test_grok_loses_to_copilot_when_event_field_present() {
        // The Copilot-specific `event` field wins over Grok's hookEventName,
        // matching the Hermes guard. Copilot can ship its own tool names.
        let json = r#"{
            "event":"pre-tool-use",
            "hookEventName":"pre_tool_use",
            "toolName":"run_terminal_cmd",
            "toolInput":{"command":"git status"}
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Copilot);
    }

    #[test]
    fn test_grok_loses_to_copilot_when_tool_args_present() {
        let json = r#"{
            "hookEventName":"pre_tool_use",
            "toolName":"run_terminal_cmd",
            "toolArgs":"{\"command\":\"git status\"}"
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Copilot);
    }

    #[test]
    fn test_grok_event_does_not_misroute_to_hermes() {
        // Regression guard: "pre_tool_use" must NOT match Hermes's
        // "pre_tool_call". The strings differ by one letter at the end.
        let json = r#"{
            "hook_event_name":"pre_tool_use",
            "tool_name":"run_terminal_cmd",
            "tool_input":{"command":"ls"}
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Grok);
    }

    #[test]
    fn test_grok_hook_output_deny_decision_json_shape() {
        // The wire shape must be EXACTLY {"decision":"deny","reason":...}
        // — Grok's parser will silently drop the block on "block"/"deny" mismatch.
        let output = GrokHookOutput {
            decision: "deny",
            reason: Cow::Borrowed("blocked for safety"),
            allow_once_code: None,
            allow_once_full_hash: None,
            rule_id: Some("core.git:reset-hard".to_string()),
            pack_id: Some("core.git".to_string()),
            severity: None,
            confidence: None,
            remediation: None,
        };
        let json = serde_json::to_value(&output).unwrap();
        assert_eq!(json["decision"], "deny");
        assert_eq!(json["reason"], "blocked for safety");
        assert_eq!(json["ruleId"], "core.git:reset-hard");
        assert_eq!(json["packId"], "core.git");
        // Must NOT carry other agents' decision keys.
        assert!(json.get("action").is_none(), "no Hermes 'action'");
        assert!(json.get("message").is_none(), "no Hermes 'message'");
        assert!(
            json.get("permissionDecision").is_none(),
            "no Claude 'permissionDecision'"
        );
        assert!(
            json.get("hookSpecificOutput").is_none(),
            "no Claude 'hookSpecificOutput'"
        );
        assert!(json.get("continue").is_none(), "no Copilot 'continue'");
    }

    #[test]
    fn test_write_denial_grok_produces_deny_json() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        write_denial_to(
            &mut stdout,
            &mut stderr,
            HookProtocol::Grok,
            "rm -rf /",
            "catastrophic filesystem deletion",
            Some("core.filesystem"),
            Some("rm-rf-root"),
            None,
            None,
            None,
            Some(crate::packs::Severity::Critical),
            None,
            &[],
            None,
        );

        let stdout_str = String::from_utf8_lossy(&stdout);
        let json: serde_json::Value = serde_json::from_str(stdout_str.trim())
            .unwrap_or_else(|e| panic!("stdout not valid JSON: {e}\nstdout: {stdout_str}"));

        assert_eq!(json["decision"], "deny");
        assert!(
            json["reason"]
                .as_str()
                .unwrap()
                .contains("catastrophic filesystem deletion"),
            "reason must surface the human-readable explanation, got: {}",
            json["reason"]
        );
        // Grok must NOT emit Hermes-style or Claude-style fields.
        assert!(json.get("action").is_none());
        assert!(json.get("message").is_none());
        assert!(json.get("hookSpecificOutput").is_none());
        // stderr must still carry the colored warning text for human/model visibility.
        assert!(
            !stderr.is_empty(),
            "Grok denial must still surface stderr warning text"
        );
    }

    #[test]
    fn test_write_warning_grok_produces_allow_with_reason() {
        // Grok has no "ask"/"warn" decision. We emit an explicit allow so the
        // tool call proceeds, with the warning text preserved in `reason`.
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        write_warning_to(
            &mut stdout,
            &mut stderr,
            HookProtocol::Grok,
            "git stash drop",
            "drops stashed changes",
            Some("core.git"),
            Some("stash-drop"),
            None,
        );

        let stdout_str = String::from_utf8_lossy(&stdout);
        let json: serde_json::Value = serde_json::from_str(stdout_str.trim())
            .unwrap_or_else(|e| panic!("stdout not valid JSON: {e}\nstdout: {stdout_str}"));

        assert_eq!(
            json["decision"], "allow",
            "warn must NOT escalate to deny on Grok"
        );
        assert!(
            json["reason"].as_str().unwrap().starts_with("DCG warn:"),
            "reason should be prefixed so the model knows this is advisory"
        );
        assert!(!stderr.is_empty(), "stderr must contain warn text");
    }

    #[test]
    fn test_grok_run_terminal_cmd_recognized_as_shell_tool() {
        // is_supported_shell_tool() must know about Grok's tool name so the
        // command is actually evaluated rather than skipped.
        assert!(is_supported_shell_tool(Some("run_terminal_cmd")));
        assert!(is_supported_shell_tool(Some("RUN_TERMINAL_CMD")));
    }

    // =========================================================================
    // Antigravity CLI (`agy`) protocol tests.
    //
    // The wire shapes below are taken verbatim from the stdin `agy` passes to a
    // PreToolUse hook (captured empirically in a sandboxed $HOME):
    //   {"toolCall":{"name":"run_command","args":{"CommandLine":"<cmd>",
    //     "Cwd":"<dir>","WaitMsBeforeAsync":500}},"conversationId":"...",
    //     "stepIdx":4,"transcriptPath":"...","workspacePaths":[...]}
    // The block decision that `agy` honors is stdout {"decision":"block",
    // "reason":...} with exit code 0.
    // =========================================================================

    #[test]
    fn test_antigravity_detected_via_tool_call_envelope() {
        let json = r#"{
            "toolCall":{"name":"run_command","args":{"CommandLine":"echo hi","Cwd":"/tmp","WaitMsBeforeAsync":500}},
            "conversationId":"a3bbcaba-0bb2-4e58-b614-49f42fa6f004",
            "stepIdx":4,
            "transcriptPath":"/home/u/.gemini/.../transcript_full.jsonl",
            "workspacePaths":["/data/projects/dcg"]
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Antigravity);
    }

    #[test]
    fn test_antigravity_command_extracted_from_command_line() {
        let json = r#"{
            "toolCall":{"name":"run_command","args":{"CommandLine":"rm -rf /","Cwd":"/tmp"}},
            "conversationId":"abc","stepIdx":1
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        let (command, protocol) = extract_command_with_protocol(&input).expect("command");
        assert_eq!(command, "rm -rf /");
        assert_eq!(protocol, HookProtocol::Antigravity);
    }

    #[test]
    fn test_antigravity_is_shell_hook_candidate() {
        let json = r#"{"toolCall":{"name":"run_command","args":{"CommandLine":"ls"}}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert!(is_shell_hook_candidate(&input));
    }

    #[test]
    fn test_antigravity_hook_output_block_decision_json_shape() {
        // `agy` aborts run_command on {"decision":"block","reason":...}.
        // Verified empirically that both "block" and "deny" keywords block;
        // we emit "block".
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        write_denial_to(
            &mut stdout,
            &mut stderr,
            HookProtocol::Antigravity,
            "rm -rf /",
            "catastrophic filesystem deletion",
            Some("core.filesystem"),
            Some("rm-rf-root"),
            None,
            None,
            None,
            Some(crate::packs::Severity::Critical),
            None,
            &[],
            None,
        );

        let stdout_str = String::from_utf8_lossy(&stdout);
        let json: serde_json::Value = serde_json::from_str(stdout_str.trim())
            .unwrap_or_else(|e| panic!("stdout not valid JSON: {e}\nstdout: {stdout_str}"));

        assert_eq!(json["decision"], "block");
        assert!(
            json["reason"]
                .as_str()
                .unwrap()
                .contains("catastrophic filesystem deletion"),
            "reason must surface the explanation, got: {}",
            json["reason"]
        );
        // Must NOT carry other agents' decision keys.
        assert!(json.get("action").is_none(), "no Hermes 'action'");
        assert!(
            json.get("permissionDecision").is_none(),
            "no Claude 'permissionDecision'"
        );
        assert!(
            json.get("hookSpecificOutput").is_none(),
            "no Claude 'hookSpecificOutput'"
        );
        assert!(json.get("continue").is_none(), "no Copilot 'continue'");
        assert!(
            !stderr.is_empty(),
            "denial must still surface stderr warning text"
        );
    }

    #[test]
    fn test_write_warning_antigravity_produces_allow() {
        // `agy` has no "ask"/"warn" decision; a warn must NOT block, so we
        // emit an explicit allow.
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        write_warning_to(
            &mut stdout,
            &mut stderr,
            HookProtocol::Antigravity,
            "git push --force",
            "force push",
            Some("core.git"),
            Some("force-push"),
            None,
        );

        let stdout_str = String::from_utf8_lossy(&stdout);
        let json: serde_json::Value = serde_json::from_str(stdout_str.trim())
            .unwrap_or_else(|e| panic!("stdout not valid JSON: {e}\nstdout: {stdout_str}"));
        assert_eq!(json["decision"], "allow");
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

    // =========================================================================
    // Regression tests for issue #77: Claude Code payloads with session_id/cwd
    // being misclassified as Gemini protocol.
    // =========================================================================

    #[test]
    fn test_claude_code_with_session_fields_not_gemini_issue_77() {
        // This is the exact scenario from issue #77: Claude Code sends
        // tool_name="Bash" along with session_id, cwd, and transcript_path.
        // Before the fix, has_gemini_context was true and this was
        // misclassified as Gemini, causing DCG to emit {"decision":"deny",...}
        // instead of {"hookSpecificOutput":{"permissionDecision":"deny",...}}.
        let json = r#"{
            "session_id": "sess-abc123",
            "transcript_path": "/tmp/claude/transcript.json",
            "cwd": "/home/user/project",
            "tool_name": "Bash",
            "tool_input": {"command": "git reset --hard HEAD~1"}
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(
            detect_protocol(&input),
            HookProtocol::ClaudeCompatible,
            "Claude Code payload with session_id/cwd must NOT be classified as Gemini"
        );
        assert_eq!(
            extract_command(&input),
            Some("git reset --hard HEAD~1".to_string())
        );
    }

    #[test]
    fn test_claude_code_full_payload_with_all_shared_fields() {
        // Claude Code payload with ALL fields that overlap with Gemini.
        let json = r#"{
            "session_id": "sess-xyz",
            "transcript_path": "/tmp/transcript",
            "cwd": "/data/projects",
            "timestamp": "2026-03-20T00:00:00Z",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /tmp/build"}
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(
            detect_protocol(&input),
            HookProtocol::ClaudeCompatible,
            "tool_name=Bash is a definitive Claude Code indicator regardless of envelope fields"
        );
    }

    #[test]
    fn test_claude_code_with_cwd_only() {
        // Minimal Claude Code payload with just cwd (common case).
        let json = r#"{
            "cwd": "/home/user/project",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"}
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::ClaudeCompatible);
    }

    #[test]
    fn test_claude_code_launch_process_with_session_fields() {
        // launch-process is also a Claude Code tool name.
        let json = r#"{
            "session_id": "sess-abc",
            "cwd": "/tmp",
            "tool_name": "launch-process",
            "tool_input": {"command": "git status"}
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::ClaudeCompatible);
    }

    #[test]
    fn test_gemini_not_affected_by_fix() {
        // Verify genuine Gemini payloads still work correctly.
        let json = r#"{
            "session_id": "gemini-session",
            "transcript_path": "/tmp/gemini/transcript",
            "cwd": "/home/user",
            "hook_event_name": "BeforeTool",
            "timestamp": "2026-03-20T00:00:00Z",
            "tool_name": "run_shell_command",
            "tool_input": {"command": "git reset --hard"}
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(
            detect_protocol(&input),
            HookProtocol::Gemini,
            "Genuine Gemini payloads must still be classified as Gemini"
        );
    }

    #[test]
    fn test_copilot_with_event_field_takes_priority() {
        // Copilot sends `event` field which is unique to it.
        // Even with session_id present, event takes priority.
        let json = r#"{
            "event": "pre-tool-use",
            "session_id": "some-session",
            "cwd": "/tmp",
            "tool_name": "bash",
            "tool_args": "{\"command\":\"git status\"}"
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(
            detect_protocol(&input),
            HookProtocol::Copilot,
            "Copilot event field must take priority over shared envelope fields"
        );
    }

    #[test]
    fn test_bare_run_shell_command_without_context_is_copilot() {
        // run_shell_command without any Gemini context or event field.
        let json = r#"{
            "tool_name": "run_shell_command",
            "tool_input": {"command": "git status"}
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Copilot);
    }

    #[test]
    fn test_minimal_bash_payload_is_claude_compatible() {
        // Minimal payload with just tool_name=Bash.
        let json = r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::ClaudeCompatible);
    }

    #[test]
    fn test_empty_payload_defaults_to_claude_compatible() {
        // Empty/minimal payload should default to Claude Compatible (safest).
        let json = r"{}";
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::ClaudeCompatible);
    }

    // =========================================================================
    // Writer-injected output tests (P1.1 — Codex coverage)
    // =========================================================================

    fn test_allow_once() -> AllowOnceInfo {
        AllowOnceInfo {
            code: "abc123".to_string(),
            full_hash: "sha256:deadbeef".to_string(),
        }
    }

    #[test]
    fn test_write_denial_claude_produces_valid_json_on_stdout() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let allow = test_allow_once();

        write_denial_to(
            &mut stdout,
            &mut stderr,
            HookProtocol::ClaudeCompatible,
            "git reset --hard HEAD~1",
            "destroys uncommitted changes",
            Some("core.git"),
            Some("reset-hard"),
            Some("Rewrites history and discards uncommitted changes."),
            Some(&allow),
            None,
            Some(crate::packs::Severity::Critical),
            Some(0.95),
            &[],
            None,
        );

        let stdout_str = String::from_utf8_lossy(&stdout);
        let json: serde_json::Value = serde_json::from_str(stdout_str.trim())
            .unwrap_or_else(|e| panic!("stdout not valid JSON: {e}\nstdout bytes: {stdout_str}"));

        let specific = &json["hookSpecificOutput"];
        assert_eq!(specific["permissionDecision"], "deny");
        assert_eq!(specific["hookEventName"], "PreToolUse");
        assert_eq!(specific["ruleId"], "core.git:reset-hard");
        assert_eq!(specific["packId"], "core.git");
        assert_eq!(specific["allowOnceCode"], "abc123");
        assert!(!stderr.is_empty(), "stderr must contain colorful warning");
    }

    #[test]
    fn test_pattern_suggestion_alternatives_formats_platform_matches() {
        let suggestions = [
            PatternSuggestion::new("git stash", "Save uncommitted changes"),
            PatternSuggestion::new("git clean -n", "Preview untracked file cleanup"),
        ];

        let alternatives = pattern_suggestion_alternatives("git reset --hard", true, &suggestions);

        assert_eq!(
            alternatives,
            vec![
                "Save uncommitted changes: git stash",
                "Preview untracked file cleanup: git clean -n"
            ]
        );
    }

    #[test]
    fn test_pattern_suggestion_alternatives_respects_disable_flag() {
        let suggestions = [PatternSuggestion::new(
            "git stash",
            "Save uncommitted changes",
        )];

        let alternatives = pattern_suggestion_alternatives("git reset --hard", false, &suggestions);

        assert!(alternatives.is_empty());
    }

    #[test]
    fn test_pattern_suggestion_alternatives_falls_back_to_contextual() {
        let alternatives = pattern_suggestion_alternatives("git clean -fd", true, &[]);

        assert_eq!(
            alternatives,
            vec!["Use 'git clean -n' first to preview what would be deleted."]
        );
    }

    #[test]
    fn test_pattern_suggestion_alternatives_limits_display_count() {
        let suggestions = [
            PatternSuggestion::new("cmd1", "one"),
            PatternSuggestion::new("cmd2", "two"),
            PatternSuggestion::new("cmd3", "three"),
            PatternSuggestion::new("cmd4", "four"),
            PatternSuggestion::new("cmd5", "five"),
        ];

        let alternatives = pattern_suggestion_alternatives("rm -rf /tmp/x", true, &suggestions);

        assert_eq!(alternatives.len(), MAX_SUGGESTIONS);
        assert!(alternatives.iter().any(|item| item == "one: cmd1"));
        assert!(!alternatives.iter().any(|item| item == "five: cmd5"));
    }

    #[test]
    fn test_write_denial_codex_produces_minimal_json_stdout() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let allow = test_allow_once();

        write_denial_to(
            &mut stdout,
            &mut stderr,
            HookProtocol::Codex,
            "git reset --hard HEAD~1",
            "destroys uncommitted changes",
            Some("core.git"),
            Some("reset-hard"),
            Some("Rewrites history."),
            Some(&allow),
            None,
            Some(crate::packs::Severity::Critical),
            Some(0.95),
            &[],
            None,
        );

        let json: serde_json::Value = serde_json::from_slice(&stdout)
            .unwrap_or_else(|error| panic!("Codex deny stdout must be JSON: {error}"));
        let specific = &json["hookSpecificOutput"];
        assert_eq!(specific["hookEventName"], "PreToolUse");
        assert_eq!(specific["permissionDecision"], "deny");
        assert!(
            specific["permissionDecisionReason"]
                .as_str()
                .is_some_and(|reason| reason.contains("git reset --hard HEAD~1"))
        );
        assert_eq!(
            specific.as_object().map(serde_json::Map::len),
            Some(3),
            "Codex payload must omit dcg-only fields: {json}"
        );
        assert!(
            !stderr.is_empty(),
            "Codex deny must produce non-empty stderr"
        );
        let stderr_str = String::from_utf8_lossy(&stderr);
        assert!(
            stderr_str.contains("git reset --hard HEAD~1"),
            "stderr must contain the blocked command; got: {stderr_str}"
        );
        assert!(
            stderr_str.contains("core.git:reset-hard"),
            "stderr must contain the rule id for agent parsing; got: {stderr_str}"
        );
        assert!(
            stderr_str.contains("Rule: core.git:reset-hard"),
            "Codex stderr must expose the full rule id as a parseable footer; got: {stderr_str}"
        );
        assert!(
            !stderr_str.contains("dcg allowlist add"),
            "Codex stderr must not teach the model to self-allowlist; got: {stderr_str}"
        );
        assert!(
            !stderr_str.contains("dcg allow-once") && !stderr_str.contains("abc123"),
            "Codex stderr must not expose allow-once bypass details; got: {stderr_str}"
        );
        assert!(
            stderr_str.contains("Do not retry it, create a bypass, or change dcg policy yourself"),
            "Codex stderr should give an explicit no-bypass instruction; got: {stderr_str}"
        );
    }

    #[test]
    fn test_write_denial_copilot_produces_valid_json_on_stdout() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        write_denial_to(
            &mut stdout,
            &mut stderr,
            HookProtocol::Copilot,
            "rm -rf /",
            "catastrophic filesystem deletion",
            Some("core.filesystem"),
            Some("rm-rf-root"),
            None,
            None,
            None,
            Some(crate::packs::Severity::Critical),
            None,
            &[],
            None,
        );

        let stdout_str = String::from_utf8_lossy(&stdout);
        let json: serde_json::Value = serde_json::from_str(stdout_str.trim())
            .unwrap_or_else(|e| panic!("stdout not valid JSON: {e}\nstdout: {stdout_str}"));

        assert_eq!(json["permissionDecision"], "deny");
        assert!(
            json["permissionDecisionReason"]
                .as_str()
                .unwrap()
                .contains("BLOCKED by dcg")
        );
        assert!(json.get("continue").is_none());
        assert!(json.get("stopReason").is_none());
    }

    #[test]
    fn test_write_denial_gemini_produces_valid_json_on_stdout() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        write_denial_to(
            &mut stdout,
            &mut stderr,
            HookProtocol::Gemini,
            "git clean -fd",
            "removes untracked files",
            Some("core.git"),
            Some("clean-force"),
            None,
            None,
            None,
            Some(crate::packs::Severity::High),
            None,
            &[],
            None,
        );

        let stdout_str = String::from_utf8_lossy(&stdout);
        let json: serde_json::Value = serde_json::from_str(stdout_str.trim())
            .unwrap_or_else(|e| panic!("stdout not valid JSON: {e}\nstdout: {stdout_str}"));

        assert_eq!(json["decision"], "deny");
        assert!(
            json["systemMessage"]
                .as_str()
                .unwrap()
                .contains("BLOCKED by dcg")
        );
    }

    #[test]
    fn test_write_warning_claude_produces_ask_json() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        write_warning_to(
            &mut stdout,
            &mut stderr,
            HookProtocol::ClaudeCompatible,
            "git checkout -- file.txt",
            "may discard local changes",
            Some("core.git"),
            Some("checkout-dot"),
            Some("Check git diff first."),
        );

        let stdout_str = String::from_utf8_lossy(&stdout);
        let json: serde_json::Value = serde_json::from_str(stdout_str.trim())
            .unwrap_or_else(|e| panic!("stdout not valid JSON: {e}\nstdout: {stdout_str}"));

        let specific = &json["hookSpecificOutput"];
        assert_eq!(specific["permissionDecision"], "ask");
        assert!(
            specific["permissionDecisionReason"]
                .as_str()
                .unwrap()
                .starts_with("DCG warn:")
        );
        assert!(!stderr.is_empty(), "stderr must contain warning text");
    }

    #[test]
    fn test_write_warning_codex_produces_empty_stdout() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        write_warning_to(
            &mut stdout,
            &mut stderr,
            HookProtocol::Codex,
            "git checkout -- file.txt",
            "may discard local changes",
            Some("core.git"),
            Some("checkout-dot"),
            None,
        );

        assert!(
            stdout.is_empty(),
            "Codex warn must produce zero bytes on stdout; got {} bytes: {:?}",
            stdout.len(),
            String::from_utf8_lossy(&stdout)
        );
        assert!(
            !stderr.is_empty(),
            "Codex warn must produce non-empty stderr"
        );
        let stderr_str = String::from_utf8_lossy(&stderr);
        assert!(
            stderr_str.contains("WARNING"),
            "stderr must contain WARNING marker; got: {stderr_str}"
        );
        assert!(
            stderr_str.contains("core.git:checkout-dot"),
            "stderr must contain rule id; got: {stderr_str}"
        );
    }

    #[test]
    fn test_write_warning_copilot_produces_ask_json() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        write_warning_to(
            &mut stdout,
            &mut stderr,
            HookProtocol::Copilot,
            "git stash drop",
            "drops stashed changes",
            Some("core.git"),
            Some("stash-drop"),
            None,
        );

        let stdout_str = String::from_utf8_lossy(&stdout);
        let json: serde_json::Value = serde_json::from_str(stdout_str.trim())
            .unwrap_or_else(|e| panic!("stdout not valid JSON: {e}\nstdout: {stdout_str}"));

        assert_eq!(json["permissionDecision"], "ask");
        assert!(json.get("continue").is_none());
        assert!(json.get("stopReason").is_none());
    }

    #[test]
    fn test_write_warning_gemini_produces_allow_json() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        write_warning_to(
            &mut stdout,
            &mut stderr,
            HookProtocol::Gemini,
            "git stash drop",
            "drops stashed changes",
            Some("core.git"),
            Some("stash-drop"),
            None,
        );

        let stdout_str = String::from_utf8_lossy(&stdout);
        let json: serde_json::Value = serde_json::from_str(stdout_str.trim())
            .unwrap_or_else(|e| panic!("stdout not valid JSON: {e}\nstdout: {stdout_str}"));

        assert_eq!(json["decision"], "allow");
        assert!(json["reason"].as_str().unwrap().starts_with("DCG warn:"));
    }

    // =========================================================================
    // detect_protocol negative-space coverage (P1.4)
    // =========================================================================

    #[test]
    fn test_detect_protocol_non_shell_tool_with_turn_id_is_not_codex() {
        // Non-shell tool_name must not flip to Codex even with turn_id.
        let json = r#"{"tool_name":"Read","tool_input":{},"turn_id":"turn-1"}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::ClaudeCompatible);
    }

    #[test]
    fn test_detect_protocol_launch_process_with_turn_id_is_codex() {
        // launch-process is a valid shell tool for Codex.
        let json =
            r#"{"tool_name":"launch-process","tool_input":{"command":"ls"},"turn_id":"turn-2"}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Codex);
    }

    #[test]
    fn test_detect_protocol_powershell_with_turn_id_is_codex() {
        let json = r#"{"tool_name":"powershell","tool_input":{"command":"git status"},"turn_id":"turn-ps"}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Codex);
    }

    #[test]
    fn test_detect_protocol_whitespace_only_turn_id_is_not_codex() {
        // A whitespace-only turn_id is malformed and should behave like a
        // missing turn_id instead of forcing Codex's stderr-only protocol.
        let json = r#"{"tool_name":"Bash","tool_input":{"command":"ls"},"turn_id":"   "}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::ClaudeCompatible);
    }

    #[test]
    fn test_detect_protocol_uppercase_bash_with_turn_id_is_codex() {
        // tool_name is lowercased before comparison; "BASH" should match.
        let json = r#"{"tool_name":"BASH","tool_input":{"command":"ls"},"turn_id":"turn-3"}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Codex);
    }

    #[test]
    fn test_detect_protocol_lowercase_bash_with_turn_id_is_codex() {
        // Lowercase wire form from Codex.
        let json = r#"{"tool_name":"bash","tool_input":{"command":"ls"},"turn_id":"turn-4"}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Codex);
    }

    #[test]
    fn test_detect_protocol_copilot_event_overrides_turn_id() {
        // Copilot event check fires before Codex turn_id check.
        let json = r#"{
            "event":"pre-tool-use",
            "tool_name":"bash",
            "tool_input":{"command":"ls"},
            "turn_id":"turn-5"
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Copilot);
    }

    #[test]
    fn test_detect_protocol_gemini_envelope_overrides_turn_id() {
        // Gemini's (run_shell_command + BeforeTool) signal is stronger than
        // turn_id because the Codex check only fires for bash/launch-process.
        let json = r#"{
            "hook_event_name":"BeforeTool",
            "tool_name":"run_shell_command",
            "tool_input":{"command":"ls"},
            "turn_id":"turn-6"
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Gemini);
    }

    #[test]
    fn test_detect_protocol_bash_tool_use_id_no_turn_id_is_claude() {
        // Regression: tool_use_id alone must not trigger Codex path.
        let json = r#"{
            "tool_name":"Bash",
            "tool_input":{"command":"ls"},
            "tool_use_id":"toolu_01XYZ"
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::ClaudeCompatible);
    }
}

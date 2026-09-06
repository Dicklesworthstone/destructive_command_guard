//! Hook protocol handling.
//!
//! This module handles JSON input/output for supported hook protocols
//! (Claude Code, Codex CLI, Copilot, VS Code Copilot Chat, Gemini, and Hermes
//! Agent). It parses incoming hook requests and formats denial responses.

use crate::evaluator::MatchSpan;
use crate::highlight::HighlightSpan;
use crate::normalize::ShellDialect;
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

    /// Session id (Gemini snake_case; VS Code Agent Host camelCase).
    #[serde(alias = "sessionId")]
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

    /// VS Code "Agent Host" batched tool-call envelope (issue #252). The
    /// newer Copilot Agent Host (and the Agents window built on it) sends
    /// `{"sessionId": "...", "cwd": "...", "toolCalls": [{"name":
    /// "powershell", "args": "{\"command\":\"...\"}"}]}` — an *array* under
    /// plural `toolCalls`, with each entry's `args` JSON-encoded as a string.
    /// Before this field existed the envelope deserialized without any
    /// recognized command and the hook silently failed open.
    ///
    /// The field is deliberately shape-tolerant: a `toolCalls` value that is
    /// not an array (or an entry that does not fit [`ToolCall`]) must degrade
    /// to `None` (or be skipped) instead of aborting the whole [`HookInput`]
    /// parse. A whole-payload parse failure fails open, which would let a
    /// malformed `toolCalls` mask a perfectly good `tool_input` command
    /// elsewhere in the same payload.
    #[serde(
        alias = "toolCalls",
        alias = "toolcalls",
        default,
        deserialize_with = "deserialize_tool_calls_tolerant"
    )]
    pub tool_calls: Option<Vec<ToolCall>>,
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

/// Deserialize the plural `toolCalls` field without ever failing the parse.
///
/// A typed `Option<Vec<ToolCall>>` aborts the entire [`HookInput`]
/// deserialization when the field arrives in an unexpected shape (for example
/// an object keyed by index), and an aborted parse fails open — silently
/// allowing a destructive command carried by `tool_input` in the same payload.
/// This deserializer therefore accepts:
/// - absent / `null` → `None`;
/// - a JSON array → each entry parsed individually as [`ToolCall`], with
///   entries that do not fit silently skipped (the ones that do fit are kept);
/// - any non-array shape → `None`, so the rest of the payload still parses and
///   the `tool_input` / `toolCall` extraction paths keep working.
fn deserialize_tool_calls_tolerant<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<ToolCall>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let Some(value) = Option::<serde_json::Value>::deserialize(deserializer)? else {
        return Ok(None);
    };
    let serde_json::Value::Array(entries) = value else {
        return Ok(None);
    };
    Ok(Some(
        entries
            .into_iter()
            .filter_map(|entry| serde_json::from_value::<ToolCall>(entry).ok())
            .collect(),
    ))
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

/// Crush (Charm) `PreToolUse` output envelope, version 1.
///
/// Crush parses stdout only on exit code 0. `decision` is `"allow"`, `"deny"`
/// or absent; absent means "no opinion" and the call proceeds through Crush's
/// ordinary permission prompt. dcg never emits `"allow"` — in Crush that is
/// an *affirmative* pre-approval that skips the user's permission prompt, and
/// a guard has no business vouching for a command. `reason` is shown to the
/// model when denying; `context` is appended to what the model sees on any
/// decision, which is how non-blocking warnings travel. Crush's parser ignores
/// unknown fields, so dcg's ergonomics fields (`allowOnceCode`, `ruleId`, …)
/// ride along for tooling that wants them.
///
/// See `docs/hooks/README.md` in <https://github.com/charmbracelet/crush>.
#[derive(Debug, Serialize)]
pub struct CrushHookOutput<'a> {
    /// Output envelope version. Crush defaults to 1 when omitted; pinning it
    /// keeps the payload self-describing if the envelope evolves.
    pub version: u8,

    /// `"deny"` to block the tool call. Omitted (no opinion) for warnings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<&'static str>,

    /// Why the call was denied. Surfaced to the model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<Cow<'a, str>>,

    /// Extra context appended to what the model sees (used for warnings).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Cow<'a, str>>,

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
    ///
    /// Posit Assistant also speaks this protocol: its `PreToolUse` stdin is
    /// the snake_case Claude shape (`tool_name`, `tool_input.command`,
    /// `tool_use_id`, `permission_mode`), exit code 2 blocks with stderr as
    /// the reason, and `hookSpecificOutput.permissionDecision` is read on
    /// exit 0 — so no dedicated variant is needed. Its hook env var
    /// `PA_PROJECT_DIR` is consulted in [`detect_protocol`] only to keep a
    /// `powershell`-named shell tool from being classified as Codex.
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
    /// Charm Crush protocol (#388). Wire shape: stdin carries the flat
    /// snake_case envelope `{"event": "PreToolUse", "session_id": "...",
    /// "cwd": "...", "tool_name": "bash", "tool_input": {"command": "..."}}`
    /// — verified against `internal/hooks/input.go` (`BuildPayload`) in
    /// <https://github.com/charmbracelet/crush>. The shell tool is named
    /// `bash` on every platform (Crush runs an embedded POSIX shell). Crush
    /// parses stdout as JSON on exit code 0: `{"decision": "deny", "reason":
    /// "..."}` blocks the call, an omitted `decision` is "no opinion" (the
    /// call goes through Crush's normal permission prompt), and `"allow"`
    /// pre-approves the call and *skips* that prompt — so dcg never emits it.
    /// Exit code 2 also blocks (stderr as reason) but dcg keeps its exit-0 +
    /// JSON contract so the ergonomics fields survive; any other non-zero
    /// exit is logged and fails open. Crush's parser ignores unknown fields.
    ///
    /// The `event` field is what Copilot CLI also sends (`"pre-tool-use"`,
    /// hyphenated, alongside `tool_args`); Crush's PascalCase `"PreToolUse"`
    /// together with `tool_input` and no `tool_args` is the discriminator.
    /// Without it the payload fell through to the Copilot arm, whose flat
    /// `permissionDecision` envelope Crush does not read, so a block was
    /// silently downgraded to "no opinion" — dcg failed open under Crush.
    Crush,
}

/// A shell command extracted from a hook request together with its execution
/// context.
///
/// Protocol controls how dcg answers the hook client. Shell dialect controls
/// how the command text is tokenized and interpreted. They are deliberately
/// independent: for example, Copilot can invoke a tool named `powershell`,
/// while Codex can invoke a tool named `bash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedHookCommand {
    /// Raw command exactly as supplied by the hook client.
    pub command: String,
    /// Response protocol expected by the hook client.
    pub protocol: HookProtocol,
    /// Shell syntax proven by the hook tool name, or `Unknown`.
    pub dialect: ShellDialect,
    /// Remaining batch entries from a plural `toolCalls[]` envelope (issue
    /// #252), each carrying its own per-entry dialect. Empty on every
    /// single-command path. Entries are deliberately NOT joined into one
    /// string: an entry ending in an unterminated quote or trailing backslash
    /// would swallow the following entry during tokenization and mask its
    /// destructive command, so each entry must be evaluated independently.
    pub additional_commands: Vec<(String, ShellDialect)>,
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
    ///
    /// Carries the bytes that WERE read (the truncated prefix) so the caller
    /// can still make a best-effort attempt to evaluate the command embedded
    /// in an oversized payload instead of failing open blind (issue #290).
    ///
    /// The prefix is drained past `max_bytes` up to
    /// [`MAX_OVERSIZED_SCAN_BYTES`] so a payload that puts its padding BEFORE
    /// the command (pad-first evasion) is still visible to the scanner. The
    /// envelope itself remains oversized/unparseable for the normal path —
    /// only the best-effort scanner ever sees the extended buffer.
    InputTooLarge {
        /// Number of bytes drained into the scan buffer. This is capped at
        /// [`MAX_OVERSIZED_SCAN_BYTES`], so for a larger payload it
        /// understates the true size.
        len: usize,
        /// The raw input prefix that was read (up to the scan cap).
        prefix: String,
    },
    /// Failed to parse JSON input.
    Json(serde_json::Error),
}

/// Hard cap on how much stdin is drained into the best-effort scan buffer once
/// a payload has already been ruled oversized (issue #290, pad-first evasion).
///
/// The size limit itself stays at `general.max_hook_input_bytes`: an oversized
/// envelope is never parsed or evaluated through the normal path. But stopping
/// the *read* at that limit meant a destructive command that begins beyond it —
/// e.g. megabytes of padding in a sibling key written before `tool_input`, or
/// inside the command string ahead of the destructive part — was invisible to
/// the truncated-prefix scanner and failed open blind.
///
/// 4 MiB is chosen because it (a) keeps the worst-case scan allocation bounded
/// and small relative to any agent's memory, (b) covers realistic padded
/// envelopes, which are sized just past the 256 KiB default rather than
/// megabytes past it, and (c) costs nothing on the normal path, which never
/// reaches this constant. A payload that hides its command beyond 4 MiB is a
/// documented residual: it still fails open in the default posture and still
/// denies unconditionally under `fail_closed`.
pub const MAX_OVERSIZED_SCAN_BYTES: usize = 4 * 1024 * 1024;

/// Read and parse hook input from stdin.
///
/// # Errors
///
/// Returns [`HookReadError::Io`] if stdin cannot be read, [`HookReadError::Json`]
/// if the input is not valid hook JSON, or [`HookReadError::InputTooLarge`] if
/// the input exceeds `max_bytes`.
pub fn read_hook_input(max_bytes: usize) -> Result<HookInput, HookReadError> {
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    {
        let stdin = io::stdin();
        // Read up to limit + 1 to detect overflow
        let mut handle = stdin.lock().take(max_bytes as u64 + 1);
        handle.read_to_end(&mut buf).map_err(HookReadError::Io)?;
    }

    if buf.len() > max_bytes {
        // Keep draining into the scan buffer up to the hard cap so a
        // pad-first payload cannot hide its command behind the size limit.
        // Best-effort: a read error here just shortens the scan buffer, it
        // never changes the (already decided) oversized verdict.
        if buf.len() < MAX_OVERSIZED_SCAN_BYTES {
            let remaining = (MAX_OVERSIZED_SCAN_BYTES - buf.len()) as u64;
            let stdin = io::stdin();
            let mut handle = stdin.lock().take(remaining);
            let _ = handle.read_to_end(&mut buf);
        }
        let len = buf.len();
        // Lossy: the cap can land mid-codepoint, and the scanner distrusts
        // anything it cannot decode cleanly anyway.
        return Err(HookReadError::InputTooLarge {
            len,
            prefix: String::from_utf8_lossy(&buf).into_owned(),
        });
    }

    let input = String::from_utf8(buf)
        .map_err(|e| HookReadError::Io(io::Error::new(io::ErrorKind::InvalidData, e)))?;

    // Strip a leading UTF-8 BOM (U+FEFF) before parsing. Some text tools prepend
    // a BOM; without this, BOM-prefixed but otherwise-valid hook input would
    // fail to parse and (by default) fail open — silently allowing a command
    // that should have been evaluated/blocked (issue #160). `serde_json` does
    // not skip a leading BOM on its own.
    let to_parse = input.strip_prefix('\u{feff}').unwrap_or(input.as_str());

    serde_json::from_str(to_parse).map_err(HookReadError::Json)
}

/// Best-effort extraction of a shell command from a truncated JSON prefix
/// (issue #290).
///
/// An oversized hook payload is rejected before JSON parsing, but the prefix
/// that WAS read usually still contains the `tool_input.command` string —
/// padding a destructive command past `max_hook_input_bytes` must not skip
/// evaluation entirely. This scanner locates EVERY `"command"` key in the raw
/// prefix and decodes each JSON string value, tolerating truncation mid-string
/// (the decoded prefix of the command is returned).
///
/// Every occurrence is returned, not just the first: `serde_json` resolves a
/// duplicate key last-wins, and an unrelated earlier object can carry a decoy
/// `"command"`. Judging only the first match would let an attacker put a
/// benign command in front of the real one and fail open. The caller must
/// deny if ANY returned command resolves to Deny/Ask.
///
/// The scan is deliberately conservative: its result is only used to justify
/// DENYING (a destructive command prefix is proof enough), so any occurrence
/// whose structure it does not trust — malformed escapes, raw control
/// characters inside the string, a non-string value — is dropped rather than
/// guessed at, and an empty result keeps the caller's historic fail-open
/// behavior. Escaped occurrences of the key inside string values
/// (`\"command\"`) never match because the scan requires the unescaped
/// `"command"` byte sequence.
#[must_use]
pub fn extract_commands_from_truncated_json(prefix: &str) -> Vec<String> {
    extract_string_values_for_key(prefix, "\"command\"")
}

/// Best-effort extraction of the hook envelope's tool name(s) from a truncated
/// JSON prefix.
///
/// Companion to [`extract_commands_from_truncated_json`]: an oversized
/// non-shell envelope (a `Write`/`Read` tool call with a command-ish field)
/// must not be denied as if it were a shell request. Both the snake_case
/// `tool_name` and the camelCase `toolName` spelling are scanned because
/// [`HookInput`] accepts both on the normal path.
///
/// Same conservatism and same all-occurrences rule as the command scan: a
/// decoy tool name must not be able to hide the real one.
#[must_use]
pub fn extract_tool_names_from_truncated_json(prefix: &str) -> Vec<String> {
    let mut names = extract_string_values_for_key(prefix, "\"tool_name\"");
    names.extend(extract_string_values_for_key(prefix, "\"toolName\""));
    names
}

/// Resolve the shell tool a truncated oversized prefix belongs to, if any.
///
/// Returns the recognized shell tool name and the dialect it implies, using
/// exactly the same recognition and dialect mapping as the normal parsed path
/// ([`is_supported_shell_tool`] / [`shell_dialect_for_tool_name`]). Returns
/// `None` when the prefix carries no tool name at all, or only tool names that
/// are not shell tools — the caller must then fail open rather than deny a
/// payload it cannot attribute to a shell.
///
/// The first *recognized* name wins, so a decoy non-shell tool name planted
/// ahead of the real one cannot suppress evaluation.
#[must_use]
pub fn shell_tool_from_truncated_json(prefix: &str) -> Option<(String, ShellDialect)> {
    extract_tool_names_from_truncated_json(prefix)
        .into_iter()
        .find(|name| is_supported_shell_tool(Some(name)))
        .map(|name| {
            let dialect = shell_dialect_for_tool_name(Some(&name));
            (name, dialect)
        })
}

/// Collect every cleanly decodable string value for a raw JSON `key` (given
/// with its surrounding quotes) in a possibly-truncated prefix.
fn extract_string_values_for_key(prefix: &str, key: &str) -> Vec<String> {
    let mut values = Vec::new();

    let mut search_from = 0;
    while let Some(found) = prefix[search_from..].find(key) {
        let key_start = search_from + found;
        search_from = key_start + 1;

        let rest = prefix[key_start + key.len()..].trim_start();
        let Some(after_colon) = rest.strip_prefix(':') else {
            continue;
        };
        let Some(string_body) = after_colon.trim_start().strip_prefix('"') else {
            continue;
        };
        if let Some(decoded) = decode_json_string_prefix(string_body) {
            values.push(decoded);
        }
    }
    values
}

/// Decode a JSON string body (content after the opening quote) up to the
/// closing unescaped quote OR the end of the buffer (truncation), returning
/// the decoded prefix. Returns `None` on structure that cannot be a JSON
/// string (malformed escape, raw control character) — see
/// [`extract_commands_from_truncated_json`] for why distrust must fail open.
fn decode_json_string_prefix(body: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => {
                let Some(esc) = chars.next() else {
                    // Truncated mid-escape: keep what decoded cleanly.
                    return Some(out);
                };
                match esc {
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    '/' => out.push('/'),
                    'b' => out.push('\u{0008}'),
                    'f' => out.push('\u{000C}'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'u' => {
                        let hex: String = chars.by_ref().take(4).collect();
                        if hex.len() < 4 {
                            // Truncated mid-escape: keep what decoded cleanly.
                            return Some(out);
                        }
                        let Ok(code_point) = u32::from_str_radix(&hex, 16) else {
                            return None;
                        };
                        match char::from_u32(code_point) {
                            Some(ch) => out.push(ch),
                            // Surrogate half (e.g. emoji pair): stop here and
                            // keep the cleanly decoded prefix rather than
                            // implementing pair reassembly for a best-effort
                            // scan.
                            None => return Some(out),
                        }
                    }
                    _ => return None,
                }
            }
            c if (c as u32) < 0x20 => return None,
            c => out.push(c),
        }
    }
    // Truncated before the closing quote — the decoded prefix is the value.
    Some(out)
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
/// Posit Assistant uses the Claude wire shape, so it resolves to
/// [`HookProtocol::ClaudeCompatible`] through the shared shell-tool names. Its
/// hook env var `PA_PROJECT_DIR` is consulted only to steer a
/// `powershell`-named shell tool away from the unconditional Windows-shell →
/// Codex rule.
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

    // --- VS Code Agent Host indicators (checked first) ---
    // The Copilot "Agent Host" batches tool calls in a plural `toolCalls`
    // array (issue #252); no other supported agent emits that field. VS Code
    // consumes Claude-shaped hook output through its Claude-hooks
    // compatibility layer (#184), so the Claude-compatible deny payload is
    // the documented answer shape.
    //
    // The branch is gated on the batch actually containing a SHELL entry —
    // the same [`is_batch_shell_call`] predicate extraction and
    // [`is_shell_hook_candidate`] use. A `toolCalls` array carrying only
    // non-shell entries (`readFile`, `editFile`, …) is not proof of the Agent
    // Host: another agent's envelope can carry one while its real shell
    // command sits in `tool_input`, and answering that payload in Claude
    // shape would hand Gemini/Hermes/Grok/Codex a deny document their parsers
    // drop (a silent fail-open). Such a batch falls through to the ordinary
    // markers below.
    if input
        .tool_calls
        .as_ref()
        .is_some_and(|calls| calls.iter().any(is_batch_shell_call))
    {
        return HookProtocol::ClaudeCompatible;
    }

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
    //   - toolName="run_terminal_cmd" / "run_terminal_command" (Grok's
    //     internal shell tool name; older builds use the abbreviated form,
    //     current Grok Build documents the full spelling — issue #319).
    // Either signal alone is a strong Grok indicator. We deliberately do
    // NOT add a GROK_* env-var fallback: real Grok hook invocations always
    // emit both fields, so the wire-level check is sufficient, and an
    // env-var fallback would risk false positives when dcg is invoked from
    // a shell that happens to live inside a Grok session (e.g. running
    // `cargo test` from a Grok-spawned terminal).
    let is_grok_event = hook_event_name == "pre_tool_use";
    let is_grok_tool = tool_name == "run_terminal_cmd" || tool_name == "run_terminal_command";
    if (is_grok_event || is_grok_tool) && input.event.is_none() && input.tool_args.is_none() {
        return HookProtocol::Grok;
    }

    // --- Crush (Charm) indicators (checked before Copilot) ---
    // Crush's stdin envelope is `{"event": "PreToolUse", "session_id", "cwd",
    // "tool_name": "bash", "tool_input": {"command": ...}}`. The only other
    // agent that sends a top-level `event` is Copilot CLI, whose value is the
    // hyphenated "pre-tool-use" and which carries `tool_args` rather than
    // `tool_input`. Crush's PascalCase event name is compared byte-for-byte
    // (case-insensitively) WITHOUT stripping separators — normalizing
    // "pre-tool-use" would collapse the two. Crush's parser reads
    // `decision`/`reason`, not Copilot's flat `permissionDecision`, so
    // misrouting this payload to the Copilot arm turned every block into
    // "no opinion" (#388). As with Grok, no `CRUSH=1` env fallback is used
    // here: real Crush hook payloads always carry the wire markers.
    let is_crush_event = input
        .event
        .as_deref()
        .is_some_and(|event| event.eq_ignore_ascii_case("PreToolUse"));
    if is_crush_event && input.tool_input.is_some() && input.tool_args.is_none() {
        return HookProtocol::Crush;
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
        "bash" | "launch-process" | "powershell" | "pwsh" | "cmd" | "cmd.exe"
    ) || is_vscode_terminal_tool(&tool_name);
    let has_codex_turn_id = input
        .turn_id
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty());
    if is_claude_compatible_shell_tool && has_codex_turn_id {
        return HookProtocol::Codex;
    }

    // --- Posit Assistant indicator (env var, checked before the Windows-shell
    // rule below) ---
    // Posit Assistant sets `PA_PROJECT_DIR=<workspace root>` in every hook
    // subprocess and speaks the snake_case Claude wire shape, so it needs no
    // protocol of its own. This branch exists to deliberately override the
    // issue-#125 bare-Windows-shell → Codex heuristic below when
    // `PA_PROJECT_DIR` is present: on a Windows host Posit Assistant's shell
    // tool is named `powershell`, and Codex's minimal deny shape would drop
    // the `hookSpecificOutput.permissionDecision` payload Posit Assistant
    // reads on exit 0. The trade-off is explicit and accepted: a Codex session
    // running with ambient `PA_PROJECT_DIR` and no `turn_id` loses the #125
    // minimal-shape mitigation, because the env marker is the stronger signal
    // that a Posit Assistant parser is on the other end.
    //
    // The gate is deliberately narrow so ambient `PA_PROJECT_DIR` cannot
    // misroute other agents' payloads into Claude-shaped answers their parsers
    // do not read: it fires only for the shell tool names Posit Assistant
    // actually sends (`bash`, plus the Windows shells the #125 rule below
    // would otherwise claim) AND a Claude-shaped event (absent or
    // `PreToolUse`). It must never fire for `run_shell_command`
    // (Gemini/Copilot), `terminal` (Hermes), `run_terminal_cmd` (Grok), or any
    // event-marked payload — those keep their own protocols via the checks
    // above and below.
    let has_posit_assistant_env = std::env::var_os("PA_PROJECT_DIR").is_some();
    let is_posit_assistant_event =
        hook_event_name.is_empty() || hook_event_name.eq_ignore_ascii_case("pretooluse");
    let is_posit_assistant_shell_tool = matches!(
        tool_name.as_str(),
        "bash" | "powershell" | "pwsh" | "cmd" | "cmd.exe"
    );
    if has_posit_assistant_env && is_posit_assistant_event && is_posit_assistant_shell_tool {
        return HookProtocol::ClaudeCompatible;
    }

    // Explicit Windows-shell tool names ("powershell"/"pwsh"/"cmd"/"cmd.exe")
    // are only ever emitted by Codex-style payloads -- Claude Code's shell
    // tool is always "Bash" (or "launch-process"), so this cannot collide with
    // Claude Code. On Windows, Codex does not always populate `turn_id`
    // (issue #125), so the turn_id-gated check above misses these tools and the
    // destructive command would otherwise slip through as a ClaudeCompatible
    // result whose extension fields Codex's strict parser drops. Classify an
    // explicit Windows shell as Codex unconditionally so the minimal Codex
    // JSON path is used.
    // (`bash`/`launch-process` stay turn_id-gated because Claude Code
    // legitimately uses those names.)
    let is_explicit_windows_shell = matches!(
        tool_name.as_str(),
        "powershell" | "pwsh" | "cmd" | "cmd.exe"
    );
    if is_explicit_windows_shell {
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
            | "cmd"
            | "cmd.exe"
            | "run_shell_command"
            | "run-shell-command"
            // Hermes Agent shell tool. Distinct from Cursor's "terminal"
            // wrapper script which translates upstream to "Bash" before
            // invoking dcg, so the only path here is genuine Hermes input.
            | "terminal"
            // Grok (xAI) shell tool. Grok aliases Claude-style "Bash" to an
            // internal terminal tool before invoking hooks. Older builds put
            // `run_terminal_cmd` on the wire; current Grok Build documents
            // `run_terminal_command` (issue #319). Accept both spellings —
            // missing either one makes the hook silently fail open on the
            // exact path Grok uses.
            | "run_terminal_cmd"
            | "run_terminal_command"
        )
}

/// Infer the command parser's dialect from an explicit, trustworthy shell
/// tool name.
///
/// Generic terminal adapters do not identify the shell that ultimately
/// executes their command, so they intentionally remain [`ShellDialect::Unknown`].
/// A protocol classification must never be used as a dialect proxy.
#[must_use]
pub(crate) fn shell_dialect_for_tool_name(tool_name: Option<&str>) -> ShellDialect {
    let Some(tool_name) = tool_name else {
        return ShellDialect::Unknown;
    };

    match tool_name.to_ascii_lowercase().as_str() {
        "bash" => ShellDialect::Posix,
        "powershell" | "pwsh" => ShellDialect::PowerShell,
        "cmd" | "cmd.exe" => ShellDialect::Cmd,
        _ => ShellDialect::Unknown,
    }
}

/// Resolve the dialect a `Bash`-labeled Codex payload is evaluated under.
///
/// Codex names its shell tool `Bash` on every platform (its hooks schema
/// mirrors Claude Code's), but its PreToolUse payload carries only
/// `{"command": …}` (`codex-rs/core/src/tools/handlers/unified_exec/exec_command.rs`,
/// `pre_tool_use_payload`) — not the shell the command will run in. On native
/// Windows that shell is PowerShell by default
/// (`codex-rs/shell-command/src/shell_detect.rs`), yet the tool's `shell`
/// parameter lets the model request `bash`/`sh` (Git Bash, or WSL's launcher,
/// whichever is on `PATH`), and Codex falls back to `cmd.exe` when the
/// requested shell is missing. The label alone therefore cannot name the
/// dialect.
///
/// Evaluating every such payload as POSIX turned PowerShell's backtick escape
/// (`"`n"`) into an unterminated command substitution and denied a read-only
/// command (#379). Evaluating every one as PowerShell instead let the
/// POSIX-only forms a requested bash would execute — a backquoted
/// substitution in an expanding heredoc, ``x=`…` ``, `eval '…'`, a
/// backslash-continued line — pass unseen. The command text separates the
/// two cases: a command whose POSIX substitution parse fails cannot run under
/// bash (the shell rejects it as well), so it is evaluated as PowerShell;
/// anything that parses as POSIX is evaluated as `Unknown`, the fail-closed
/// union of every dialect, exactly as a mislabeled Agent Host payload is
/// (#322). A command the parser refuses for its size says nothing about the
/// shell and keeps the union.
///
/// Claude Code's `Bash` tool on Windows is Git Bash, so the resolution is
/// gated on the Codex protocol; and because a hook always runs on the host
/// that executes the command, `host_is_windows` (`cfg!(windows)` at the call
/// site) is the platform signal — a Codex session under WSL runs a Linux dcg
/// and keeps POSIX. Explicit `powershell`/`pwsh`/`cmd` labels are never
/// touched.
#[must_use]
pub(crate) fn codex_host_shell_dialect(
    labeled: ShellDialect,
    protocol: HookProtocol,
    host_is_windows: bool,
    command: &str,
) -> ShellDialect {
    if labeled != ShellDialect::Posix || protocol != HookProtocol::Codex || !host_is_windows {
        return labeled;
    }
    if command.len() > crate::heredoc::MAX_SUBSTITUTION_SOURCE_BYTES {
        return ShellDialect::Unknown;
    }
    // The same masked view the POSIX evaluation path parses, so the verdict
    // here matches the one that path would reach.
    let posix_view = crate::heredoc::mask_non_expanding_data_heredocs(command);
    match crate::heredoc::extract_posix_command_substitutions(posix_view.as_ref()) {
        Ok(_) => ShellDialect::Unknown,
        Err(crate::heredoc::PosixCommandSubstitutionParseError) => ShellDialect::PowerShell,
    }
}

/// PowerShell approved verbs (the `Verb-Noun` cmdlet naming standard).
///
/// Compared case-insensitively against the verb half of a candidate cmdlet
/// token. This is the full Microsoft approved-verb list rather than a
/// destructive subset: the list only ever WIDENS a dialect to `Unknown`
/// (fail-closed union), so an over-broad match costs one extra dialect's
/// evaluation, while an omission re-opens the #322 hole for cmdlets built on
/// that verb.
const POWERSHELL_APPROVED_VERBS: &[&str] = &[
    "add",
    "approve",
    "assert",
    "backup",
    "block",
    "build",
    "checkpoint",
    "clear",
    "close",
    "compare",
    "complete",
    "compress",
    "confirm",
    "connect",
    "convert",
    "convertfrom",
    "convertto",
    "copy",
    "debug",
    "deny",
    "deploy",
    "disable",
    "disconnect",
    "dismount",
    "edit",
    "enable",
    "enter",
    "exit",
    "expand",
    "export",
    "find",
    "format",
    "get",
    "grant",
    "group",
    "hide",
    "import",
    "initialize",
    "install",
    "invoke",
    "join",
    "limit",
    "lock",
    "measure",
    "merge",
    "mount",
    "move",
    "new",
    "open",
    "optimize",
    "out",
    "ping",
    "pop",
    "protect",
    "publish",
    "push",
    "read",
    "receive",
    "redo",
    "register",
    "remove",
    "rename",
    "repair",
    "request",
    "reset",
    "resize",
    "resolve",
    "restart",
    "restore",
    "resume",
    "revoke",
    "save",
    "search",
    "select",
    "send",
    "set",
    "show",
    "skip",
    "split",
    "start",
    "step",
    "stop",
    "submit",
    "suspend",
    "switch",
    "sync",
    "test",
    "trace",
    "unblock",
    "undo",
    "uninstall",
    "unlock",
    "unprotect",
    "unpublish",
    "unregister",
    "update",
    "use",
    "wait",
    "watch",
    "write",
];

/// Return whether `token` has the shape of a PowerShell cmdlet invocation:
/// `Verb-Noun` where the verb is on the approved-verb list and the noun is a
/// single alphanumeric word.
fn is_powershell_cmdlet_token(token: &str) -> bool {
    let Some((verb, noun)) = token.split_once('-') else {
        return false;
    };
    if verb.is_empty()
        || noun.is_empty()
        || !verb.bytes().all(|b| b.is_ascii_alphabetic())
        || !noun.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        return false;
    }
    POWERSHELL_APPROVED_VERBS
        .iter()
        .any(|approved| verb.eq_ignore_ascii_case(approved))
}

/// Windows destructive commands whose *bare name* collides with POSIX (`rm`,
/// `del`) or is simply unknown to POSIX (`rd`, `ri`). The name alone is
/// ambiguous, so widening additionally requires a Windows-shell-only argument
/// shape (see [`segment_is_windows_alias_invocation`]).
const WINDOWS_DESTRUCTIVE_ALIASES: &[&str] = &["rm", "ri", "del", "rd", "rmdir", "erase"];

/// PowerShell `Remove-Item` parameter names used as the discriminator. A
/// single-dash token whose name is a >=3-character prefix of one of these is
/// unmistakably PowerShell: POSIX/GNU `rm` never accepts a single-dash
/// multi-letter *word* (`-rf` is a short-flag cluster, not `-recurse`), and
/// GNU long options use a double dash (`--recursive`). The 3-char floor keeps
/// `-r`/`-f`/`-rf` (POSIX) from ever matching.
const REMOVE_ITEM_PS_PARAM_WORDS: &[&str] = &[
    "recurse",
    "force",
    "path",
    "literalpath",
    "include",
    "exclude",
    "filter",
    "confirm",
    "whatif",
];

/// Return whether `token` is a single-dash PowerShell parameter (`-Recurse`,
/// `-Force`, `-Path`, …) rather than a POSIX short-flag cluster. Requires a
/// single leading `-`, an all-alphabetic name of length >= 3, and that name to
/// be a prefix of a known `Remove-Item` parameter.
fn is_powershell_parameter_token(token: &str) -> bool {
    let Some(name) = token.strip_prefix('-') else {
        return false;
    };
    // A second dash means a GNU long option (`--recursive`), not PowerShell.
    if name.starts_with('-') || name.len() < 3 || !name.bytes().all(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    REMOVE_ITEM_PS_PARAM_WORDS
        .iter()
        .any(|word| word.starts_with(&lower))
}

/// Return whether `token` is the cmd.exe recursion switch `/s` (alone or
/// stuck to `/q`). `/s` is the switch that makes `del`/`rd` catastrophic. A
/// literal `/s` *can* be a POSIX absolute path, so this is only consulted
/// after the segment already leads with a destructive alias, and widening to
/// `Unknown` is the fail-closed direction: the worst case is that a bizarre
/// POSIX `rm /s` gets the union-of-dialects evaluation (still allowed — no
/// windows rule matches a bare `rm` with a `/s` operand), never a fail-open.
/// Bare `/q`/`/f` do not recurse, so they are not widening triggers alone.
fn is_cmd_switch_token(token: &str) -> bool {
    matches!(token.to_ascii_lowercase().as_str(), "/s" | "/s/q" | "/q/s")
}

/// Return whether a single statement segment is a Windows-shell invocation of
/// a destructive alias — either PowerShell (`rm -Recurse -Force …`) or cmd
/// (`del /s /q …`, `rd /s …`). The bare alias is never enough; a
/// Windows-shell-only argument shape must accompany it so a plain POSIX
/// `rm -rf ./build` keeps the Posix dialect.
///
/// A bare `--` ends the scan: it is POSIX end-of-options, after which
/// `-Recurse`/`/s` are filenames, not flags. PowerShell never spells options
/// with `--`, so stopping there cannot miss a real PowerShell command while
/// it does stop `rm -- -Recurse` (deleting a file literally named
/// `-Recurse`) from being mis-widened.
fn segment_is_windows_alias_invocation(segment: &str) -> bool {
    let mut tokens = segment.split_whitespace();
    let Some(first) = tokens.next() else {
        return false;
    };
    let name = first
        .to_ascii_lowercase()
        .strip_suffix(".exe")
        .map_or_else(|| first.to_ascii_lowercase(), str::to_string);
    if !WINDOWS_DESTRUCTIVE_ALIASES.contains(&name.as_str()) {
        return false;
    }
    tokens
        .take_while(|token| *token != "--")
        .any(|token| is_powershell_parameter_token(token) || is_cmd_switch_token(token))
}

/// Return whether any statement/pipeline segment of `command` is unmistakably
/// Windows shell: a PowerShell cmdlet-shaped leading token (`Remove-Item …`,
/// `… ; Clear-Content …`) or a destructive alias carrying a Windows-shell-only
/// argument (`rm -Recurse -Force …`, `del /s /q …`).
fn command_has_powershell_shape(command: &str) -> bool {
    command
        .split(['|', ';', '&', '\n', '\r', '(', '{'])
        .any(|segment| {
            segment
                .split_whitespace()
                .next()
                .is_some_and(is_powershell_cmdlet_token)
                || segment_is_windows_alias_invocation(segment)
        })
}

/// Down-trust a `Bash`-labeled dialect when the command itself is
/// unmistakably PowerShell.
///
/// VS Code's Agent Host transforms PowerShell tool calls before invoking
/// PreToolUse hooks and puts `tool_name: "Bash"` on the wire (#322, #252), so
/// dcg evaluated `Remove-Item -Recurse -Force` under the POSIX dialect —
/// where a cmdlet is just an unknown binary — and failed open. The tool-name
/// label is host-controlled and demonstrably wrong in the wild; when the
/// command's own shape contradicts it, the honest dialect is `Unknown`, which
/// evaluates the fail-closed union of every dialect. Explicit
/// `powershell`/`pwsh`/`cmd` labels are never widened (they already evaluate
/// the dialect the command will run under), and non-cmdlet POSIX commands are
/// unaffected.
pub fn refine_shell_dialect(command: &str, labeled: ShellDialect) -> ShellDialect {
    if labeled == ShellDialect::Posix && command_has_powershell_shape(command) {
        ShellDialect::Unknown
    } else {
        labeled
    }
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

    // VS Code Agent Host: any batched entry that looks like a shell call
    // (issue #252).
    if input
        .tool_calls
        .as_ref()
        .is_some_and(|calls| calls.iter().any(is_batch_shell_call))
    {
        return true;
    }

    input.tool_name.is_none()
        && matches!(detect_protocol(input), HookProtocol::Copilot)
        && (input.tool_input.is_some() || input.tool_args.is_some())
}

/// Return whether a batched `toolCalls[]` entry should be treated as a shell
/// invocation.
///
/// Mirrors the singular `toolCall` posture so the batch path can never be the
/// weaker gate (a fail-open direction): a supported shell tool name, the
/// Antigravity CLI's `run_command`, or a nameless entry that still carries
/// args all qualify.
fn is_batch_shell_call(call: &ToolCall) -> bool {
    let name = call
        .name
        .as_deref()
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if name.is_empty() {
        return call.args.is_some();
    }
    name == "run_command" || is_supported_shell_tool(Some(&name))
}

/// Extract the shell command from an Antigravity (`agy`) `toolCall` envelope.
///
/// `agy`'s `run_command` tool carries the command in
/// `toolCall.args.CommandLine` (PascalCase); the shared args extraction also
/// accepts the lowercase `command` key used by other agents in case `agy` ever
/// normalizes.
fn extract_command_from_tool_call(tool_call: &ToolCall) -> Option<String> {
    tool_call
        .args
        .as_ref()
        .and_then(extract_command_from_tool_args)
}

fn extract_command_from_tool_input(tool_input: &ToolInput) -> Option<String> {
    match tool_input.command.as_ref() {
        Some(serde_json::Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// Extract the shell command from a `toolArgs` / `toolCall.args` /
/// `toolCalls[].args` value.
///
/// Accepts the dominant lowercase `command` object key (Claude / Copilot / VS
/// Code Agent Host), the `CommandLine` / `commandLine` / `Command` variants
/// (agy and Windows-shell payloads), a JSON-encoded string carrying any of
/// those object forms (the Agent Host stringifies `args`), and a bare
/// non-empty string as the command itself. `command` is checked first so
/// precedence is unchanged for payloads that carry several keys.
fn extract_command_from_tool_args(tool_args: &serde_json::Value) -> Option<String> {
    match tool_args {
        serde_json::Value::Object(map) => {
            for key in ["command", "CommandLine", "commandLine", "Command"] {
                if let Some(serde_json::Value::String(s)) = map.get(key) {
                    if !s.is_empty() {
                        return Some(s.clone());
                    }
                }
            }
            None
        }
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

/// Extract a command and its independent protocol/dialect context from hook
/// input.
#[must_use]
pub fn extract_command_with_context(input: &HookInput) -> Option<ExtractedHookCommand> {
    let protocol = detect_protocol(input);
    let labeled = shell_dialect_for_tool_name(input.tool_name.as_deref());
    // The label alone cannot name the dialect of a Codex `Bash` payload on
    // Windows (#379), so each command resolves its own; a Posix label whose
    // command is unmistakably PowerShell then widens to the union (#322).
    let resolve = |command: &str, label: ShellDialect| {
        refine_shell_dialect(
            command,
            codex_host_shell_dialect(label, protocol, cfg!(windows), command),
        )
    };

    // Only process shell-command invocations for supported clients. Copilot
    // can omit toolName and put the shell command directly in toolArgs, so
    // treat that distinctive envelope as a shell candidate too.
    if !is_shell_hook_candidate(input) {
        return None;
    }

    // VS Code Agent Host batches shell invocations in `toolCalls[]`, each
    // with a JSON-encoded `args` string (issue #252). Every shell entry is
    // extracted as its OWN command with its OWN per-entry dialect — never
    // joined into one string. Joining let an entry ending in an unterminated
    // quote or a trailing backslash absorb the following entry during
    // tokenization, masking its destructive command from the evaluator
    // (fail-open). The first extracted command is the primary; the rest ride
    // along in `additional_commands` for the hook driver to evaluate
    // independently.
    //
    // Every OTHER command-bearing field of the same envelope is appended as a
    // further entry: a singular `toolCall`, `tool_input.command`, and
    // `tool_args`. Returning on the batch alone let a destructive sibling in
    // those fields ride along unevaluated — e.g. `{"tool_name":"Bash",
    // "tool_input":{"command":"rm -rf /"},"toolCalls":[{"name":"bash",
    // "args":"{\"command\":\"ls -la\"}"}]}` was silently allowed because the
    // benign batch entry answered for the whole payload.
    if let Some(calls) = input.tool_calls.as_ref() {
        let mut commands: Vec<(String, ShellDialect)> = Vec::new();
        for call in calls {
            if !is_batch_shell_call(call) {
                continue;
            }
            if let Some(command) = call.args.as_ref().and_then(extract_command_from_tool_args) {
                let entry_dialect =
                    resolve(&command, shell_dialect_for_tool_name(call.name.as_deref()));
                commands.push((command, entry_dialect));
            }
        }
        if let Some(tool_call) = input.tool_call.as_ref() {
            if let Some(command) = extract_command_from_tool_call(tool_call) {
                let entry_dialect = resolve(&command, labeled);
                commands.push((command, entry_dialect));
            }
        }
        if let Some(command) = input
            .tool_input
            .as_ref()
            .and_then(extract_command_from_tool_input)
        {
            let entry_dialect = resolve(&command, labeled);
            commands.push((command, entry_dialect));
        }
        if let Some(command) = input
            .tool_args
            .as_ref()
            .and_then(extract_command_from_tool_args)
        {
            let entry_dialect = resolve(&command, labeled);
            commands.push((command, entry_dialect));
        }
        let mut entries = commands.into_iter();
        if let Some((command, primary_dialect)) = entries.next() {
            return Some(ExtractedHookCommand {
                command,
                protocol,
                dialect: primary_dialect,
                additional_commands: entries.collect(),
            });
        }
    }

    // Antigravity CLI (`agy`) nests the command under `toolCall.args.CommandLine`.
    if let Some(tool_call) = input.tool_call.as_ref() {
        if let Some(command) = extract_command_from_tool_call(tool_call) {
            let dialect = resolve(&command, labeled);
            return Some(ExtractedHookCommand {
                command,
                protocol,
                dialect,
                additional_commands: Vec::new(),
            });
        }
    }

    if let Some(tool_input) = input.tool_input.as_ref() {
        if let Some(command) = extract_command_from_tool_input(tool_input) {
            let dialect = resolve(&command, labeled);
            return Some(ExtractedHookCommand {
                command,
                protocol,
                dialect,
                additional_commands: Vec::new(),
            });
        }
    }

    if let Some(tool_args) = input.tool_args.as_ref() {
        if let Some(command) = extract_command_from_tool_args(tool_args) {
            let dialect = resolve(&command, labeled);
            return Some(ExtractedHookCommand {
                command,
                protocol,
                dialect,
                additional_commands: Vec::new(),
            });
        }
    }

    None
}

/// Extract command and protocol from hook input.
///
/// This compatibility wrapper preserves the original public API while the
/// typed context path additionally carries shell dialect information.
#[must_use]
pub fn extract_command_with_protocol(input: &HookInput) -> Option<(String, HookProtocol)> {
    extract_command_with_context(input).map(|extracted| (extracted.command, extracted.protocol))
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

/// Cap on the command text echoed back into a block message.
///
/// The block message becomes the hook's `permissionDecisionReason`, which
/// lands in an agent's context and is replayed on every later turn. Echoing
/// the command verbatim made the refusal grow with the payload — a 10 KB
/// heredoc write cost ~10.8 KB to report a one-line verdict, and a 50 KB one
/// cost ~50.8 KB (#339). The stderr box has always been a constant size; this
/// gives the JSON reason the same property. The cap is generous enough that
/// ordinary commands are untouched and stay copy-pasteable.
const MAX_EXPLAIN_HINT_COMMAND: usize = 400;

/// Format the explain hint line for copy-paste convenience.
fn format_explain_hint(command: &str) -> String {
    // Escape double quotes in command for safe copy-paste
    let escaped = command.replace('"', "\\\"");
    if escaped.len() <= MAX_EXPLAIN_HINT_COMMAND {
        return format!("Tip: dcg explain \"{escaped}\"");
    }

    // Past the cap the tip cannot be copy-pasteable anyway, so spend the
    // bytes on the head of the command and say how much was dropped. The
    // elided byte count is the useful signal here, not the elided bytes.
    let head = truncate_for_display(&escaped, MAX_EXPLAIN_HINT_COMMAND);
    let total = command.len();
    let elided = total.saturating_sub(MAX_EXPLAIN_HINT_COMMAND);
    format!(
        "Tip: dcg explain \"{head}\"\n\
         (command truncated for this report: {elided} of {total} bytes elided; \
         rerun `dcg explain` against the full command for the complete report)"
    )
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
///
/// When an allow-once code was minted for this denial, the message names the
/// scoped `dcg allow-once <code>` remedy (GH#332): harnesses commonly surface
/// only `permissionDecisionReason` to the model and drop the sibling JSON
/// fields, so a code that appears only in `allowOnceCode`/`remediation` is
/// emitted but never read. The wording keeps the human in the loop: the user
/// approves the single command, which is strictly safer than the fallback of
/// having them run the destructive command by hand.
#[must_use]
pub fn format_denial_message(
    command: &str,
    reason: &str,
    explanation: Option<&str>,
    pack: Option<&str>,
    pattern: Option<&str>,
    allow_once_code: Option<&str>,
) -> String {
    let mut message = format_matched_message(
        "BLOCKED by dcg",
        command,
        reason,
        explanation,
        pack,
        pattern,
        "If this operation is truly needed, ask the user for explicit permission and have them run the command manually.",
    );
    if let Some(code) = allow_once_code {
        use std::fmt::Write as _;
        let _ = write!(
            message,
            "\n\nTo permit this single command once, the user can approve it with: dcg allow-once {code}"
        );
    }
    message
}

/// Format a native-review request for a matched destructive command.
#[must_use]
pub fn format_review_message(
    command: &str,
    reason: &str,
    explanation: Option<&str>,
    pack: Option<&str>,
    pattern: Option<&str>,
) -> String {
    format_matched_message(
        "APPROVAL REQUIRED by dcg",
        command,
        reason,
        explanation,
        pack,
        pattern,
        "Approve this command only after reviewing the operation and its target. Denying it keeps the command blocked.",
    )
}

fn format_matched_message(
    heading: &str,
    command: &str,
    reason: &str,
    explanation: Option<&str>,
    pack: Option<&str>,
    pattern: Option<&str>,
    instruction: &str,
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

    // The command deliberately appears ONCE, inside the `Tip:` line. A hook
    // decision lands in the agent's transcript and is replayed on every
    // subsequent turn, so a second verbatim echo is paid for repeatedly and
    // tells the reader nothing the first did not — the agent just wrote this
    // command and has it in context. Keeping the `Tip:` copy rather than a
    // bare `Command:` line preserves the one form that is also actionable.
    format!(
        "{heading}\n\n\
         {explain_hint}\n\n\
         Reason: {reason}\n\n\
         {explanation_block}\n\n\
         {rule_line}\
         {instruction}"
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

            // Advertise the scoped single-command remedy ahead of the
            // persistent allowlist widening (GH#332).
            if let Some(code) = allow_once_code {
                let _ = writeln!(writer, "  $ {cyan}dcg allow-once {code}{reset}");
            }

            if let Some(ref rule) = rule_id {
                let _ = writeln!(writer, "  $ {cyan}dcg allowlist add {rule} --user{reset}");
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
        .map(|suggestion| {
            if suggestion.gated {
                format!(
                    "{}: {}  (dcg gates this too — it needs explicit approval)",
                    suggestion.description, suggestion.command
                )
            } else {
                format!("{}: {}", suggestion.description, suggestion.command)
            }
        })
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
        | HookProtocol::Antigravity
        | HookProtocol::Crush => WarningAudience::HumanOperator,
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

    // GH#332: name the allow-once remedy in the reason text for protocols
    // whose JSON already carries the code. Codex is excluded on purpose — its
    // output deliberately strips all allow-once metadata (see the Codex arm
    // below and `WarningAudience::CodexModel`), and the reason string must
    // not reintroduce what the protocol's design withholds.
    let reason_allow_once_code = match protocol {
        HookProtocol::Codex => None,
        _ => allow_once_code,
    };
    let message = format_denial_message(
        command,
        reason,
        explanation,
        pack,
        pattern,
        reason_allow_once_code,
    );
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
        HookProtocol::Crush => {
            // Crush parses stdout JSON on exit 0: `{"decision":"deny","reason":
            // ...}` blocks the bash tool call and shows `reason` to the model.
            // Exit code 2 would also block (stderr as the reason) but the JSON
            // path keeps dcg's ergonomics fields intact; Crush's parser ignores
            // the ones it does not know. The colored deny message has already
            // been written to stderr for the human operator.
            let output = CrushHookOutput {
                version: 1,
                decision: Some("deny"),
                reason: Some(Cow::Owned(message)),
                context: None,
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

/// Write an operator-review request for a matched destructive command.
///
/// Claude-compatible and Copilot hooks receive their native `ask` decision.
/// Every other supported protocol receives its ordinary deny/block response;
/// an opt-in review policy must never become an allow merely because a client
/// cannot represent review.
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub fn write_review_request_to(
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
    if !matches!(
        protocol,
        HookProtocol::ClaudeCompatible | HookProtocol::Copilot
    ) {
        write_denial_to(
            stdout,
            stderr,
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
        return;
    }

    print_colorful_warning_to(
        stderr,
        command,
        reason,
        pack,
        pattern,
        explanation,
        allow_once.map(|info| info.code.as_str()),
        matched_span,
        pattern_suggestions,
        severity,
        branch_context,
        WarningAudience::HumanOperator,
    );

    let message = format_review_message(command, reason, explanation, pack, pattern);
    match protocol {
        HookProtocol::ClaudeCompatible => {
            let rule_id = build_rule_id(pack, pattern);
            let remediation = allow_once.map(|info| Remediation {
                safe_alternative: get_contextual_suggestion(command).map(String::from),
                explanation: format_explanation_text(explanation, rule_id.as_deref(), pack),
                allow_once_command: format!("dcg allow-once {}", info.code),
            });
            let output = HookOutput {
                hook_specific_output: HookSpecificOutput {
                    hook_event_name: "PreToolUse",
                    permission_decision: "ask",
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
            let _ = serde_json::to_writer(&mut *stdout, &output);
            let _ = writeln!(stdout);
        }
        HookProtocol::Copilot => {
            let output = CopilotHookOutput {
                permission_decision: "ask",
                permission_decision_reason: Cow::Owned(message),
            };
            let _ = serde_json::to_writer(&mut *stdout, &output);
            let _ = writeln!(stdout);
        }
        HookProtocol::Gemini
        | HookProtocol::Codex
        | HookProtocol::Hermes
        | HookProtocol::Grok
        | HookProtocol::Antigravity
        | HookProtocol::Crush => {
            unreachable!("non-review protocols returned through write_denial_to")
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

/// Output an operator-review request using the active hook protocol.
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub fn output_review_request_for_protocol(
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
    write_review_request_to(
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

/// Write a safety-evaluation indeterminate response to hook protocol streams.
///
/// An indeterminate result is neither an allow nor a rule-based denial: dcg
/// did not finish proving the command safe before its evaluation deadline.
/// Protocols with an explicit review decision receive `ask`; protocols that
/// cannot represent `ask` receive their documented blocking decision. This
/// deliberately never emits an explicit allow or an empty response.
#[cold]
#[inline(never)]
pub fn write_indeterminate_to(
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    protocol: HookProtocol,
    reason: &str,
    deny: bool,
) {
    let _ = writeln!(stderr);
    let _ = writeln!(stderr, "{} {reason}", "dcg INDETERMINATE:".yellow().bold());

    // `ask` presumes a human is present to answer. On an unattended session
    // that prompt either stalls forever or gets waved through by an
    // auto-approver — for exactly the commands dcg declined to inspect — so
    // `general.unverified_decision = "deny"` downgrades the review-capable
    // protocols to an outright denial (#338). Protocols without a native
    // `ask` decision already block below regardless of this setting.
    let review_decision = if deny { "deny" } else { "ask" };
    let review_reason: Cow<'_, str> = if deny {
        Cow::Owned(format!(
            "{reason} Denied without review because unverified commands are configured to deny \
             (general.unverified_decision)."
        ))
    } else {
        Cow::Borrowed(reason)
    };

    match protocol {
        HookProtocol::ClaudeCompatible => {
            let output = HookOutput {
                hook_specific_output: HookSpecificOutput {
                    hook_event_name: "PreToolUse",
                    permission_decision: review_decision,
                    permission_decision_reason: review_reason,
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
                permission_decision: review_decision,
                permission_decision_reason: review_reason,
            };
            let _ = serde_json::to_writer(&mut *stdout, &output);
            let _ = writeln!(stdout);
        }
        HookProtocol::Codex => {
            // Codex's hook parser is strict and does not support `ask`.
            // Emit only its accepted minimal deny envelope.
            let output = HookOutput {
                hook_specific_output: HookSpecificOutput {
                    hook_event_name: "PreToolUse",
                    permission_decision: "deny",
                    permission_decision_reason: Cow::Borrowed(reason),
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
        HookProtocol::Gemini => {
            let output = GeminiHookOutput {
                decision: "deny",
                reason: Cow::Borrowed(reason),
                system_message: Some(Cow::Borrowed(reason)),
                allow_once_code: None,
                allow_once_full_hash: None,
                rule_id: None,
                pack_id: None,
                severity: None,
                confidence: None,
                remediation: None,
            };
            let _ = serde_json::to_writer(&mut *stdout, &output);
            let _ = writeln!(stdout);
        }
        HookProtocol::Hermes => {
            let output = HermesHookOutput {
                decision: "block",
                reason: Cow::Borrowed(reason),
                action: "block",
                message: Cow::Borrowed(reason),
                allow_once_code: None,
                allow_once_full_hash: None,
                rule_id: None,
                pack_id: None,
                severity: None,
                confidence: None,
                remediation: None,
            };
            let _ = serde_json::to_writer(&mut *stdout, &output);
            let _ = writeln!(stdout);
        }
        HookProtocol::Grok => {
            let output = GrokHookOutput {
                decision: "deny",
                reason: Cow::Borrowed(reason),
                allow_once_code: None,
                allow_once_full_hash: None,
                rule_id: None,
                pack_id: None,
                severity: None,
                confidence: None,
                remediation: None,
            };
            let _ = serde_json::to_writer(&mut *stdout, &output);
            let _ = writeln!(stdout);
        }
        HookProtocol::Antigravity => {
            let output = GeminiHookOutput {
                decision: "block",
                reason: Cow::Borrowed(reason),
                system_message: Some(Cow::Borrowed(reason)),
                allow_once_code: None,
                allow_once_full_hash: None,
                rule_id: None,
                pack_id: None,
                severity: None,
                confidence: None,
                remediation: None,
            };
            let _ = serde_json::to_writer(&mut *stdout, &output);
            let _ = writeln!(stdout);
        }
        HookProtocol::Crush => {
            // Crush has no `ask`: an omitted decision falls through to its
            // normal permission prompt, which an allowlist or auto-approver
            // may wave through — exactly the unattended case #338 guards
            // against. Deny outright with the plain reason, like the other
            // prompt-less protocols (the `unverified_decision` annotation is
            // for protocols whose `ask` was downgraded).
            let output = CrushHookOutput {
                version: 1,
                decision: Some("deny"),
                reason: Some(Cow::Borrowed(reason)),
                context: None,
                allow_once_code: None,
                allow_once_full_hash: None,
                rule_id: None,
                pack_id: None,
                severity: None,
                confidence: None,
                remediation: None,
            };
            let _ = serde_json::to_writer(&mut *stdout, &output);
            let _ = writeln!(stdout);
        }
    }

    // A deadline response is useful only if the hook runner receives it before
    // its own process timeout. Stdout is normally a pipe in hook mode and is
    // therefore block-buffered, so do not rely on process teardown to publish
    // the conservative decision. Flush both protocol and diagnostic streams
    // before any caller performs optional audit I/O.
    let _ = stdout.flush();
    let _ = stderr.flush();
}

/// Emit a safety-evaluation indeterminate response on process stdout/stderr.
#[cold]
#[inline(never)]
pub fn output_indeterminate_for_protocol(protocol: HookProtocol, reason: &str, deny: bool) {
    let out = io::stdout();
    let mut out_handle = out.lock();
    let err = io::stderr();
    let mut err_handle = err.lock();
    write_indeterminate_to(&mut out_handle, &mut err_handle, protocol, reason, deny);
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

    // -- stdout: protocol-specific non-blocking response --
    let rule_id = build_rule_id(pack, pattern);
    let warn_reason = format!("DCG warn: {reason}");

    match protocol {
        // Silence means "no blocking opinion" for review-capable clients.
        // Keeping warn distinct from ask preserves the documented policy:
        // warn proceeds, while ask requires an explicit operator decision.
        HookProtocol::ClaudeCompatible | HookProtocol::Copilot | HookProtocol::Codex => {}
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
        HookProtocol::Crush => {
            // Crush's `"allow"` is an affirmative pre-approval that SKIPS the
            // user's permission prompt, so unlike Grok/agy a warn must not be
            // expressed as an explicit allow — dcg would be vouching for a
            // command it only meant to annotate. Omit `decision` ("no
            // opinion": the call proceeds through Crush's ordinary permission
            // flow, exactly as if dcg had stayed silent) and carry the warning
            // in `context`, which Crush appends to what the model sees.
            let output = CrushHookOutput {
                version: 1,
                decision: None,
                reason: None,
                context: Some(Cow::Owned(warn_reason)),
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

    // The log file outlives the hook invocation and a blocked command is
    // exactly where credentials turn up, so recognised secret shapes are
    // replaced before the line is written (issue #386). This path has no
    // redaction config of its own; pattern redaction is unconditional here.
    let command = crate::redaction::redact_secrets(command);
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
    // Same unconditional secret redaction as `log_blocked_command`.
    let command = crate::redaction::redact_secrets(command);
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

    #[derive(Default)]
    struct FlushProbe {
        bytes: Vec<u8>,
        flushes: usize,
    }

    impl std::io::Write for FlushProbe {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

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
    fn test_shell_dialect_inference_requires_explicit_shell_tool_name() {
        for tool_name in ["bash", "Bash", "BASH"] {
            assert_eq!(
                shell_dialect_for_tool_name(Some(tool_name)),
                ShellDialect::Posix
            );
        }
        for tool_name in ["powershell", "PowerShell", "pwsh", "PWSH"] {
            assert_eq!(
                shell_dialect_for_tool_name(Some(tool_name)),
                ShellDialect::PowerShell
            );
        }
        for tool_name in ["cmd", "CMD", "cmd.exe", "CMD.EXE"] {
            assert_eq!(
                shell_dialect_for_tool_name(Some(tool_name)),
                ShellDialect::Cmd
            );
        }

        for tool_name in [
            "launch-process",
            "runTerminalCommand",
            "run_in_terminal",
            "runInTerminal",
            "run_shell_command",
            "run-shell-command",
            "terminal",
            "run_terminal_cmd",
            "run_command",
            "powershell.exe",
            "shell",
        ] {
            assert_eq!(
                shell_dialect_for_tool_name(Some(tool_name)),
                ShellDialect::Unknown,
                "generic or unsupported tool name {tool_name:?} must not guess a dialect"
            );
        }
        assert_eq!(shell_dialect_for_tool_name(None), ShellDialect::Unknown);
    }

    #[test]
    fn test_extracted_context_keeps_protocol_and_dialect_independent() {
        let cases = [
            (
                r#"{"event":"pre-tool-use","toolName":"powershell","toolArgs":{"command":"git status"}}"#,
                HookProtocol::Copilot,
                ShellDialect::PowerShell,
            ),
            (
                r#"{"tool_name":"bash","tool_input":{"command":"git status"},"turn_id":"turn-1"}"#,
                HookProtocol::Codex,
                // Codex's `Bash` tool on native Windows runs PowerShell by
                // default or a model-requested bash; a POSIX-parseable
                // command takes the fail-closed union (#379).
                if cfg!(windows) {
                    ShellDialect::Unknown
                } else {
                    ShellDialect::Posix
                },
            ),
            (
                r#"{"tool_name":"runTerminalCommand","tool_input":{"command":"git status"}}"#,
                HookProtocol::ClaudeCompatible,
                ShellDialect::Unknown,
            ),
            (
                r#"{"tool_name":"cmd.exe","tool_input":{"command":"git status"},"turn_id":"turn-2"}"#,
                HookProtocol::Codex,
                ShellDialect::Cmd,
            ),
        ];

        for (json, expected_protocol, expected_dialect) in cases {
            let input: HookInput = serde_json::from_str(json).unwrap();
            let extracted = extract_command_with_context(&input).expect("shell command");
            assert_eq!(extracted.command, "git status");
            assert_eq!(extracted.protocol, expected_protocol);
            assert_eq!(extracted.dialect, expected_dialect);
        }
    }

    #[test]
    fn test_379_codex_bash_tool_on_windows_host_resolves_powershell() {
        // Codex labels its shell tool `Bash` everywhere. On native Windows
        // the command runs under PowerShell by default, but the model may
        // request bash through the tool's `shell` parameter, which the hook
        // payload does not carry (#379). The command text decides.
        //
        // The reporter's command: PowerShell's backtick escape is an
        // unterminated POSIX substitution, so it can only be PowerShell.
        let ps_only =
            "$a=[IO.File]::ReadAllLines('x'); [string]::Join(\"`n\",$a[239..($a.Length-1)])";
        assert_eq!(
            codex_host_shell_dialect(ShellDialect::Posix, HookProtocol::Codex, true, ps_only),
            ShellDialect::PowerShell
        );
        // Commands a requested Git Bash would execute parse as POSIX; the
        // label cannot tell them from PowerShell, so they take the
        // fail-closed union.
        let posix_parseable = [
            "git status",
            "tee /private/tmp/sink.md <<EOF\n`git reset --hard`\nEOF",
            "x=`rm -rf ~/x`",
            "eval 'rm -rf ~/x'",
            "rm \\\n-rf ~/x",
            "Get-ChildItem -Recurse | Select-Object Name",
        ];
        for command in posix_parseable {
            assert_eq!(
                codex_host_shell_dialect(ShellDialect::Posix, HookProtocol::Codex, true, command),
                ShellDialect::Unknown,
                "{command:?}"
            );
        }
        // A command the parser refuses for its size keeps the union rather
        // than trusting a verdict that never looked at the syntax.
        let oversized = format!(
            "echo `{}`",
            "x".repeat(crate::heredoc::MAX_SUBSTITUTION_SOURCE_BYTES)
        );
        assert_eq!(
            codex_host_shell_dialect(ShellDialect::Posix, HookProtocol::Codex, true, &oversized),
            ShellDialect::Unknown
        );
        // The same payloads on a Unix host (including Codex under WSL) keep
        // the POSIX dialect: Codex runs the user's login shell there.
        for command in std::iter::once(ps_only).chain(posix_parseable) {
            assert_eq!(
                codex_host_shell_dialect(ShellDialect::Posix, HookProtocol::Codex, false, command),
                ShellDialect::Posix,
                "{command:?}"
            );
        }
        // Claude Code's `Bash` tool on Windows is Git Bash — never re-mapped.
        for protocol in [
            HookProtocol::ClaudeCompatible,
            HookProtocol::Copilot,
            HookProtocol::Gemini,
            HookProtocol::Hermes,
            HookProtocol::Grok,
            HookProtocol::Antigravity,
            HookProtocol::Crush,
        ] {
            for command in [ps_only, "git status"] {
                assert_eq!(
                    codex_host_shell_dialect(ShellDialect::Posix, protocol, true, command),
                    ShellDialect::Posix,
                    "{protocol:?} must keep the POSIX label on Windows for {command:?}"
                );
            }
        }
        // Explicit labels are authoritative on every host.
        for labeled in [
            ShellDialect::PowerShell,
            ShellDialect::Cmd,
            ShellDialect::Unknown,
        ] {
            for host_is_windows in [true, false] {
                for command in [ps_only, "git status"] {
                    assert_eq!(
                        codex_host_shell_dialect(
                            labeled,
                            HookProtocol::Codex,
                            host_is_windows,
                            command
                        ),
                        labeled
                    );
                }
            }
        }

        // End to end through the extractor: the reporter's payload.
        let json = r#"{"tool_name":"Bash","turn_id":"turn-379","tool_input":{"command":"$a=[IO.File]::ReadAllLines('x'); [string]::Join(\"`n\",$a[239..($a.Length-1)])"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        let extracted = extract_command_with_context(&input).expect("shell command");
        assert_eq!(extracted.protocol, HookProtocol::Codex);
        assert_eq!(
            extracted.dialect,
            if cfg!(windows) {
                ShellDialect::PowerShell
            } else {
                ShellDialect::Posix
            }
        );
        // A POSIX-parseable Codex payload takes the union on Windows.
        let json = r#"{"tool_name":"Bash","turn_id":"turn-379","tool_input":{"command":"tee /private/tmp/sink.md <<EOF\n`git reset --hard`\nEOF"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        let extracted = extract_command_with_context(&input).expect("shell command");
        assert_eq!(extracted.protocol, HookProtocol::Codex);
        assert_eq!(
            extracted.dialect,
            if cfg!(windows) {
                ShellDialect::Unknown
            } else {
                ShellDialect::Posix
            }
        );
        // Without `turn_id` the payload is Claude Code's, whose Windows
        // `Bash` tool is Git Bash: the POSIX label stands on every host.
        let json = r#"{"tool_name":"Bash","tool_input":{"command":"$a=[IO.File]::ReadAllLines('x'); [string]::Join(\"`n\",$a[239..($a.Length-1)])"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        let extracted = extract_command_with_context(&input).expect("shell command");
        assert_eq!(extracted.protocol, HookProtocol::ClaudeCompatible);
        assert_eq!(extracted.dialect, ShellDialect::Posix);
    }

    #[test]
    fn test_322_powershell_shaped_command_widens_mislabeled_bash_dialect() {
        // VS Code Agent Host transforms PowerShell tool calls and puts
        // `tool_name: "Bash"` on the wire (#322/#252). A Posix-labeled
        // command that is unmistakably PowerShell must evaluate as
        // `Unknown` (fail-closed union of all dialects), not as Posix
        // where a cmdlet is an inert unknown binary.
        let json = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"Remove-Item -LiteralPath .\\pipelines -Recurse -Force"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        let extracted = extract_command_with_context(&input).expect("shell command");
        assert_eq!(extracted.dialect, ShellDialect::Unknown);

        // Cmdlet later in a statement list still widens.
        let json = r#"{"tool_name":"Bash","tool_input":{"command":"cd pipelines; Clear-Content secrets.txt"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        let extracted = extract_command_with_context(&input).expect("shell command");
        assert_eq!(extracted.dialect, ShellDialect::Unknown);

        // Ordinary POSIX commands keep the Posix dialect...
        for command in [
            "git status",
            "ls -la",
            "apt-get install jq",
            "docker-compose up -d",
            "add-apt-repository ppa:x/y",
            "start-stop-daemon --stop --name foo",
            "./remove-item",
            "echo Remove-Item is a cmdlet | cat",
        ] {
            assert_eq!(
                refine_shell_dialect(command, ShellDialect::Posix),
                ShellDialect::Posix,
                "must not widen plain POSIX command {command:?}"
            );
        }

        // Destructive PowerShell/cmd ALIASES with a Windows-shell-only
        // argument widen too (fresh-eyes follow-up to #322): the alias name
        // alone is ambiguous with POSIX, but `-Recurse`/`-Force`/`/s` are not.
        for command in [
            "rm -Recurse -Force .\\pipelines",
            "rm -Force -Recurse .\\pipelines",
            "ri -Recurse C:\\build",
            "del /s /q C:\\src",
            "rd /s C:\\dir",
            "rmdir /s /q .\\out",
            "erase /q /s C:\\tmp",
            "cd build; rm -Recurse -Force .\\dist",
            "Del.exe /S /Q C:\\src",
        ] {
            assert_eq!(
                refine_shell_dialect(command, ShellDialect::Posix),
                ShellDialect::Unknown,
                "Windows alias invocation must widen: {command:?}"
            );
        }

        // But a plain POSIX invocation of the same aliases must NOT widen —
        // `-rf`/`-r`/`-f` are short-flag clusters, not `-Recurse`, and a
        // GNU long option uses a double dash.
        for command in [
            "rm -rf ./build",
            "rm -r -f ./build",
            "rm -fr /tmp/x",
            "rm --recursive --force ./build",
            "rm -rf --no-preserve-root /x",
            "del file.txt",
            "rm file.txt",
            "rmdir emptydir",
            // POSIX end-of-options: `-Recurse` here is a filename, not a flag,
            // and PowerShell never spells options with `--`.
            "rm -- -Recurse",
            "rm -- -Force ./weird-file",
        ] {
            assert_eq!(
                refine_shell_dialect(command, ShellDialect::Posix),
                ShellDialect::Posix,
                "plain POSIX alias usage must not widen: {command:?}"
            );
        }

        // ...and explicit shell labels are never second-guessed.
        assert_eq!(
            refine_shell_dialect("Remove-Item x", ShellDialect::PowerShell),
            ShellDialect::PowerShell
        );
        assert_eq!(
            refine_shell_dialect("Remove-Item x", ShellDialect::Cmd),
            ShellDialect::Cmd
        );
        assert_eq!(
            refine_shell_dialect("Remove-Item x", ShellDialect::Unknown),
            ShellDialect::Unknown
        );
    }

    #[test]
    fn test_322_cmdlet_token_shape() {
        for token in [
            "Remove-Item",
            "remove-item",
            "REMOVE-ITEM",
            "Clear-Content",
            "Set-ExecutionPolicy",
            "Stop-Process",
            "Format-Volume",
            "Invoke-Expression",
        ] {
            assert!(
                is_powershell_cmdlet_token(token),
                "{token:?} must be recognized as a cmdlet"
            );
        }
        for token in [
            "apt-get",
            "docker-compose",
            "git-crypt",
            "add-apt-repository",
            "start-stop-daemon",
            "-Recurse",
            "remove-",
            "-item",
            "get-pip.py",
            "remove_item",
            "rm",
        ] {
            assert!(
                !is_powershell_cmdlet_token(token),
                "{token:?} must NOT be recognized as a cmdlet"
            );
        }
    }

    #[test]
    fn test_legacy_extraction_wrappers_match_typed_context() {
        let cases = [
            r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"}}"#,
            r#"{"event":"pre-tool-use","toolName":"powershell","toolArgs":"{\"command\":\"echo hello\"}"}"#,
            r#"{"tool_name":"run_terminal_cmd","hook_event_name":"pre_tool_use","tool_input":{"command":"echo hello"}}"#,
            r#"{"toolCall":{"name":"run_command","args":{"CommandLine":"echo hello"}}}"#,
        ];

        for json in cases {
            let input: HookInput = serde_json::from_str(json).unwrap();
            let extracted = extract_command_with_context(&input).expect("shell command");
            let legacy_with_protocol = extract_command_with_protocol(&input);
            let legacy_command = extract_command(&input);
            assert_eq!(
                legacy_with_protocol
                    .as_ref()
                    .map(|(command, protocol)| (command.as_str(), *protocol)),
                Some((extracted.command.as_str(), extracted.protocol))
            );
            assert_eq!(legacy_command.as_deref(), Some(extracted.command.as_str()));
        }
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
    fn test_explicit_windows_shell_without_turn_id_is_codex() {
        // issue #125: on Windows, Codex drives shell commands through
        // PowerShell or cmd.exe but does not always send `turn_id`. Without
        // the explicit-Windows-shell fallback this payload would be classified as
        // ClaudeCompatible (exit 0 + JSON that Codex's strict parser drops),
        // letting the destructive command through. These tool names are
        // Codex-only (Claude Code always uses "Bash"/"launch-process"), so
        // they must classify as Codex even with no turn_id.
        //
        // Ambient `PA_PROJECT_DIR` (the Posit Assistant marker checked ahead
        // of the Windows-shell rule) would legitimately steer these payloads
        // to ClaudeCompatible, so pin it removed for a deterministic result.
        let _lock = ENV_LOCK.lock().unwrap();
        let _no_posit_env = EnvVarGuard::remove("PA_PROJECT_DIR");
        for tool in [
            "powershell",
            "pwsh",
            "PowerShell",
            "PWSH",
            "cmd",
            "CMD",
            "cmd.exe",
            "CMD.EXE",
        ] {
            let json = format!(
                r#"{{"tool_name":"{tool}","tool_input":{{"command":"git reset --hard HEAD~1"}}}}"#
            );
            let input: HookInput = serde_json::from_str(&json).unwrap();
            assert_eq!(
                detect_protocol(&input),
                HookProtocol::Codex,
                "explicit Windows shell tool_name {tool:?} must be treated as Codex"
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

    // --- Posit Assistant ---------------------------------------------------
    //
    // Posit Assistant's `PreToolUse` stdin is the snake_case Claude shape and
    // its shell tool is lowercase `bash` (or `powershell` on a Windows host).
    // These tests pin the classification for both tool names: the wire shape
    // is close enough to Codex's that a regression would silently answer
    // Posit Assistant with Codex's minimal deny payload.

    /// A `PreToolUse` payload as Posit Assistant sends it for a `bash` shell
    /// tool.
    const POSIT_ASSISTANT_BASH_PAYLOAD: &str = r#"{
        "session_id":"pa-session-42",
        "transcript_path":null,
        "cwd":"/home/user/analysis",
        "hook_event_name":"PreToolUse",
        "permission_mode":"normal",
        "tool_name":"bash",
        "tool_input":{"command":"git reset --hard"},
        "tool_use_id":"toolu_posit_01"
    }"#;

    #[test]
    fn test_posit_assistant_bash_payload_is_claude_compatible_without_env() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _no_env = EnvVarGuard::remove("PA_PROJECT_DIR");

        let input: HookInput = serde_json::from_str(POSIT_ASSISTANT_BASH_PAYLOAD).unwrap();
        assert_eq!(
            extract_command(&input),
            Some("git reset --hard".to_string())
        );
        // The lowercase `bash` tool name alone is Claude-shaped; no env marker
        // is needed on a Unix host.
        assert_eq!(detect_protocol(&input), HookProtocol::ClaudeCompatible);
    }

    #[test]
    fn test_posit_assistant_payload_carries_no_foreign_markers() {
        // Guards the disambiguators this classification relies on: if Posit
        // Assistant ever grew a `turn_id`, `event`, or `tool_args` field, an
        // earlier branch would capture the payload before the Posit checks.
        let input: HookInput = serde_json::from_str(POSIT_ASSISTANT_BASH_PAYLOAD).unwrap();
        assert!(input.turn_id.is_none());
        assert!(input.event.is_none());
        assert!(input.tool_args.is_none());
        assert!(input.tool_call.is_none());
        assert!(input.tool_calls.is_none());
    }

    #[test]
    fn test_posit_assistant_powershell_payload_is_claude_compatible_via_env() {
        // On a Windows host Posit Assistant's shell tool is named
        // `powershell`, which on its own falls into the unconditional
        // Windows-shell → Codex rule. `PA_PROJECT_DIR` — which the hook
        // contract sets in the hook subprocess — must steer the payload back
        // to the Claude-compatible response Posit Assistant actually reads.
        let _lock = ENV_LOCK.lock().unwrap();
        let json = r#"{
            "session_id":"pa-session-42",
            "cwd":"C:\\Users\\user\\analysis",
            "hook_event_name":"PreToolUse",
            "permission_mode":"normal",
            "tool_name":"powershell",
            "tool_input":{"command":"Remove-Item -Recurse -Force C:\\data"},
            "tool_use_id":"toolu_posit_01"
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();

        {
            let _no_env = EnvVarGuard::remove("PA_PROJECT_DIR");
            assert_eq!(
                detect_protocol(&input),
                HookProtocol::Codex,
                "without the env marker a bare `powershell` tool stays Codex"
            );
        }

        let _env = EnvVarGuard::set("PA_PROJECT_DIR", "C:\\Users\\user\\analysis");
        assert_eq!(detect_protocol(&input), HookProtocol::ClaudeCompatible);
    }

    #[test]
    fn test_posit_assistant_env_does_not_hijack_other_protocols() {
        // `PA_PROJECT_DIR` can leak into any process spawned inside a Posit
        // Assistant workspace, so a payload carrying another agent's own wire
        // markers must keep that agent's protocol. Every branch below runs
        // ahead of the Posit Assistant env check.
        let _lock = ENV_LOCK.lock().unwrap();
        let _env = EnvVarGuard::set("PA_PROJECT_DIR", "/home/user/analysis");

        // Gemini: BeforeTool event + run_shell_command tool.
        let gemini: HookInput = serde_json::from_str(
            r#"{"hook_event_name":"BeforeTool","tool_name":"run_shell_command","tool_input":{"command":"ls"}}"#,
        )
        .unwrap();
        assert_eq!(detect_protocol(&gemini), HookProtocol::Gemini);

        // Copilot: the `event` field.
        let copilot: HookInput =
            serde_json::from_str(r#"{"event":"pre-tool-use","toolInput":{"command":"ls"}}"#)
                .unwrap();
        assert_eq!(detect_protocol(&copilot), HookProtocol::Copilot);

        // Hermes: pre_tool_call event + terminal tool.
        let hermes: HookInput = serde_json::from_str(
            r#"{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"ls"}}"#,
        )
        .unwrap();
        assert_eq!(detect_protocol(&hermes), HookProtocol::Hermes);

        // Grok: pre_tool_use event + run_terminal_cmd tool.
        let grok: HookInput = serde_json::from_str(
            r#"{"hookEventName":"pre_tool_use","toolName":"run_terminal_cmd","toolInput":{"command":"ls"}}"#,
        )
        .unwrap();
        assert_eq!(detect_protocol(&grok), HookProtocol::Grok);

        // Codex: a non-empty turn_id, even on a PreToolUse/bash payload.
        let codex: HookInput = serde_json::from_str(
            r#"{"hook_event_name":"PreToolUse","tool_name":"bash","turn_id":"turn-9","tool_input":{"command":"ls"}}"#,
        )
        .unwrap();
        assert_eq!(detect_protocol(&codex), HookProtocol::Codex);

        // agy: the nested toolCall envelope.
        let agy: HookInput = serde_json::from_str(
            r#"{"toolCall":{"name":"run_command","args":{"CommandLine":"ls"}},"conversationId":"c-1"}"#,
        )
        .unwrap();
        assert_eq!(detect_protocol(&agy), HookProtocol::Antigravity);

        // VS Code Agent Host: the plural toolCalls envelope. The expected
        // protocol is ClaudeCompatible either way; this pins that the
        // toolCalls branch (which also drives batched command extraction)
        // still fires first.
        let vscode: HookInput = serde_json::from_str(
            r#"{"sessionId":"s-1","toolCalls":[{"name":"powershell","args":"{\"command\":\"ls\"}"}]}"#,
        )
        .unwrap();
        assert_eq!(detect_protocol(&vscode), HookProtocol::ClaudeCompatible);
    }

    #[test]
    fn test_posit_env_does_not_capture_gemini_payload_missing_event_name() {
        // Regression: the Posit Assistant env branch used to fire for ANY
        // payload whose event name was empty, so with `PA_PROJECT_DIR` set a
        // Gemini payload that omitted `hook_event_name` was answered in
        // Claude shape (Gemini's parser reads `decision`/`reason`, not
        // `hookSpecificOutput`, so the deny was dropped). The gate now also
        // requires a Posit-Assistant shell tool name.
        let _lock = ENV_LOCK.lock().unwrap();
        let _env = EnvVarGuard::set("PA_PROJECT_DIR", "/home/user/analysis");
        let _no_claude_env = EnvVarGuard::remove("CLAUDE_CODE");
        let _no_claude_session_env = EnvVarGuard::remove("CLAUDE_SESSION_ID");

        let gemini: HookInput = serde_json::from_str(
            r#"{"session_id":"g-1","cwd":"/w","tool_name":"run_shell_command","tool_input":{"command":"ls"}}"#,
        )
        .unwrap();
        assert_eq!(
            detect_protocol(&gemini),
            HookProtocol::Gemini,
            "Gemini envelope without hook_event_name must keep the Gemini protocol"
        );
    }

    #[test]
    fn test_posit_env_does_not_capture_non_posit_shell_tools() {
        // Regression companion: with `PA_PROJECT_DIR` set, payloads whose
        // shell tool is another agent's must keep that agent's protocol. The
        // Posit branch only exists to reroute `bash`/Windows-shell names away
        // from the #125 bare-Windows-shell → Codex rule.
        let _lock = ENV_LOCK.lock().unwrap();
        let _env = EnvVarGuard::set("PA_PROJECT_DIR", "/home/user/analysis");
        let _no_claude_env = EnvVarGuard::remove("CLAUDE_CODE");
        let _no_claude_session_env = EnvVarGuard::remove("CLAUDE_SESSION_ID");

        // Bare run_shell_command (Copilot fallback shape, no event field).
        let copilot: HookInput = serde_json::from_str(
            r#"{"tool_name":"run_shell_command","tool_input":{"command":"ls"}}"#,
        )
        .unwrap();
        assert_eq!(detect_protocol(&copilot), HookProtocol::Copilot);

        // Hermes' `terminal` tool without an event marker.
        let hermes: HookInput =
            serde_json::from_str(r#"{"tool_name":"terminal","tool_input":{"command":"ls"}}"#)
                .unwrap();
        assert_eq!(detect_protocol(&hermes), HookProtocol::Hermes);

        // Grok's `run_terminal_cmd` tool without an event marker.
        let grok: HookInput =
            serde_json::from_str(r#"{"toolName":"run_terminal_cmd","toolInput":{"command":"ls"}}"#)
                .unwrap();
        assert_eq!(detect_protocol(&grok), HookProtocol::Grok);

        // An event-marked payload (Gemini's BeforeTool) with a `bash`-like
        // tool name must not be captured either: the event gate fails.
        let event_marked: HookInput = serde_json::from_str(
            r#"{"hook_event_name":"BeforeTool","tool_name":"run_shell_command","tool_input":{"command":"ls"}}"#,
        )
        .unwrap();
        assert_eq!(detect_protocol(&event_marked), HookProtocol::Gemini);
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
            None,
        );

        assert!(message.contains("Reason: destructive"));
        assert!(message.contains("Explanation: This is irreversible."));
        assert!(message.contains("Rule: core.git:reset-hard"));
        assert!(message.contains("Tip: dcg explain"));
    }

    /// #339: the block message becomes `permissionDecisionReason`, so it must
    /// not grow with the payload it is reporting on. An ordinary command is
    /// still echoed whole; an oversize one is capped and says what it dropped.
    #[test]
    fn denial_message_does_not_grow_with_command_length() {
        let short = "git reset --hard";
        let short_message = format_denial_message(
            short,
            "destructive",
            None,
            Some("core.git"),
            Some("reset-hard"),
            None,
        );
        assert!(
            short_message.contains(short),
            "an ordinary command stays copy-pasteable: {short_message}"
        );

        let huge = "cat > notes.md <<'EOF'\n".to_string() + &"x".repeat(50_000) + "\nEOF\n";
        let huge_message = format_denial_message(
            &huge,
            "destructive",
            None,
            Some("core.filesystem"),
            Some("redirect-truncate"),
            None,
        );

        assert!(
            huge_message.len() < short_message.len() + MAX_EXPLAIN_HINT_COMMAND + 500,
            "reason must stay bounded, got {} bytes for a {} byte command",
            huge_message.len(),
            huge.len()
        );
        assert!(
            huge_message.contains("bytes elided"),
            "truncated reason must report what it dropped: {huge_message}"
        );
        // The verdict itself survives truncation.
        assert!(huge_message.contains("Rule: core.filesystem:redirect-truncate"));
    }

    /// GH#332: harnesses surface only `permissionDecisionReason` to the model,
    /// so a minted allow-once code must be named in the reason text itself.
    #[test]
    fn test_format_denial_message_names_allow_once_code_when_minted() {
        let message = format_denial_message(
            "rm -rf /Users/example/project",
            "destructive",
            None,
            Some("core.filesystem"),
            Some("rm-rf"),
            Some("137527"),
        );

        assert!(
            message.contains("dcg allow-once 137527"),
            "reason must name the scoped remedy: {message}"
        );
        // The scoped remedy stays human-in-the-loop.
        assert!(
            message.contains("the user can approve it"),
            "allow-once line must keep the user in the loop: {message}"
        );
    }

    /// GH#332 planted negative: with no code minted, the reason must not
    /// dangle a nonexistent allow-once remedy.
    #[test]
    fn test_format_denial_message_omits_allow_once_when_absent() {
        let message = format_denial_message(
            "git reset --hard",
            "destructive",
            None,
            Some("core.git"),
            Some("reset-hard"),
            None,
        );

        assert!(
            !message.contains("allow-once"),
            "no code minted, so no allow-once mention: {message}"
        );
    }

    /// A hook decision is replayed in the agent transcript on every later
    /// turn, so the command must be echoed exactly ONCE. Guards against a
    /// second echo (e.g. a `Command:` line) creeping back in.
    #[test]
    fn test_block_message_echoes_the_command_exactly_once() {
        let command = "rm -rf /Users/example/dev/UNIQUEMARKER12345";

        for message in [
            format_denial_message(
                command,
                "destructive",
                None,
                Some("core.filesystem"),
                Some("rm-rf"),
                None,
            ),
            format_review_message(
                command,
                "needs review",
                None,
                Some("core.filesystem"),
                Some("rm-rf"),
            ),
        ] {
            assert_eq!(
                message.matches("UNIQUEMARKER12345").count(),
                1,
                "command echoed more than once in: {message}"
            );
            assert!(message.contains("Tip: dcg explain"));
            assert!(
                !message.contains("\nCommand: "),
                "the bare Command: echo is redundant with the Tip: line"
            );
        }
    }

    #[test]
    fn test_claude_compatible_review_ask_json_shape() {
        let output = HookOutput {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse",
                permission_decision: "ask",
                permission_decision_reason: Cow::Borrowed("APPROVAL REQUIRED by dcg"),
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
                .starts_with("APPROVAL REQUIRED")
        );
        assert_eq!(specific["ruleId"], "core.git:checkout-dot");
        assert_eq!(specific["packId"], "core.git");
    }

    #[test]
    fn test_copilot_review_ask_json_shape() {
        let output = CopilotHookOutput {
            permission_decision: "ask",
            permission_decision_reason: Cow::Borrowed("APPROVAL REQUIRED by dcg"),
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
    fn test_grok_run_terminal_command_full_spelling_is_supported() {
        // Grok Build's own hooks guide documents the shell tool as
        // `run_terminal_command` (full spelling), not the abbreviated
        // `run_terminal_cmd` dcg originally shipped with. Before issue #319
        // this envelope was answered with a "skip" — a silent fail-open on
        // the exact path Grok uses. Both spellings must classify as Grok,
        // count as a supported shell tool, and yield the command.
        let json = r#"{
            "hookEventName":"pre_tool_use",
            "toolName":"run_terminal_command",
            "toolInput":{"command":"git reset --hard HEAD"},
            "cwd":"/home/user/proj",
            "workspaceRoot":"/home/user/proj"
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Grok);
        assert!(is_supported_shell_tool(Some("run_terminal_command")));
        let extracted = extract_command_with_context(&input).expect("shell command");
        assert_eq!(extracted.command, "git reset --hard HEAD");
        assert_eq!(extracted.protocol, HookProtocol::Grok);

        // Tool name alone (no event marker) must also route to Grok.
        let json = r#"{
            "toolName":"run_terminal_command",
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
    // Crush (Charm) protocol tests (#388).
    //
    // The stdin shape below is what `hooks.BuildPayload` in
    // charmbracelet/crush (`internal/hooks/input.go`) marshals for a
    // PreToolUse hook: a flat snake_case envelope whose `event` is the
    // PascalCase "PreToolUse" and whose `tool_input` is the raw JSON the model
    // sent to the `bash` tool. Crush parses stdout on exit 0 and honors
    // `{"decision":"deny","reason":...}`; an omitted `decision` is "no
    // opinion" and `"allow"` skips the user's permission prompt entirely.
    // =========================================================================

    /// Verbatim shape of Crush's PreToolUse stdin payload.
    const CRUSH_DENY_PAYLOAD: &str = r#"{"event":"PreToolUse","session_id":"313909e","cwd":"/home/user/project","tool_name":"bash","tool_input":{"command":"git reset --hard HEAD~1"}}"#;

    #[test]
    fn test_crush_payload_detected_as_crush_protocol() {
        let input: HookInput = serde_json::from_str(CRUSH_DENY_PAYLOAD).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Crush);
    }

    #[test]
    fn test_crush_payload_command_is_extracted() {
        let input: HookInput = serde_json::from_str(CRUSH_DENY_PAYLOAD).unwrap();
        let extracted = extract_command_with_context(&input).expect("command present");
        assert_eq!(extracted.command, "git reset --hard HEAD~1");
        assert_eq!(extracted.protocol, HookProtocol::Crush);
        assert!(extracted.additional_commands.is_empty());
        assert!(is_supported_shell_tool(input.tool_name.as_deref()));
    }

    #[test]
    fn test_crush_event_name_is_case_insensitive_but_separator_sensitive() {
        // Crush's config loader accepts `pretooluse`; be tolerant of the case
        // in the payload too. The hyphenated Copilot spelling must NOT match:
        // stripping separators would fold "pre-tool-use" onto "pretooluse".
        for event in ["PreToolUse", "pretooluse", "PRETOOLUSE"] {
            let json = format!(
                r#"{{"event":"{event}","tool_name":"bash","tool_input":{{"command":"ls"}}}}"#
            );
            let input: HookInput = serde_json::from_str(&json).unwrap();
            assert_eq!(
                detect_protocol(&input),
                HookProtocol::Crush,
                "event {event}"
            );
        }
        for event in ["pre-tool-use", "pre_tool_use", "PreToolUsed"] {
            let json = format!(
                r#"{{"event":"{event}","tool_name":"bash","tool_input":{{"command":"ls"}}}}"#
            );
            let input: HookInput = serde_json::from_str(&json).unwrap();
            assert_ne!(
                detect_protocol(&input),
                HookProtocol::Crush,
                "event {event}"
            );
        }
    }

    #[test]
    fn test_copilot_payload_is_not_captured_by_crush() {
        // Copilot's `event` is hyphenated and it ships `tool_args`, not
        // `tool_input`. Both must keep routing to the Copilot arm.
        let json =
            r#"{"event":"pre-tool-use","tool_name":"bash","tool_args":"{\"command\":\"ls\"}"}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Copilot);

        // Even a PascalCase event loses to Copilot when `tool_args` is present.
        let json =
            r#"{"event":"PreToolUse","tool_name":"bash","tool_args":"{\"command\":\"ls\"}"}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Copilot);

        // A bare PascalCase event without any tool input is not Crush's shape.
        let json = r#"{"event":"PreToolUse","tool_name":"bash"}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Copilot);
    }

    #[test]
    fn test_crush_non_shell_tool_is_still_crush_protocol_but_not_evaluated() {
        // A user may register dcg with a broader matcher; the envelope is
        // still Crush's, and the non-shell tool is ignored like everywhere else.
        let json = r#"{"event":"PreToolUse","session_id":"s","cwd":"/p","tool_name":"edit","tool_input":{"file_path":"/p/main.go","old_string":"a","new_string":"b"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(detect_protocol(&input), HookProtocol::Crush);
        assert!(!is_supported_shell_tool(input.tool_name.as_deref()));
        assert!(extract_command_with_context(&input).is_none());
    }

    #[test]
    fn test_crush_hook_output_deny_json_shape() {
        let output = CrushHookOutput {
            version: 1,
            decision: Some("deny"),
            reason: Some(Cow::Borrowed(
                "git reset --hard destroys uncommitted changes",
            )),
            context: None,
            allow_once_code: Some("abc123".to_string()),
            allow_once_full_hash: None,
            rule_id: Some("core.git:reset-hard".to_string()),
            pack_id: Some("core.git".to_string()),
            severity: Some(crate::packs::Severity::Critical),
            confidence: None,
            remediation: None,
        };
        let json = serde_json::to_value(&output).unwrap();
        assert_eq!(json["version"], 1);
        assert_eq!(json["decision"], "deny");
        assert_eq!(
            json["reason"],
            "git reset --hard destroys uncommitted changes"
        );
        assert!(json.get("context").is_none(), "context omitted when None");
        assert_eq!(json["allowOnceCode"], "abc123");
        assert_eq!(json["ruleId"], "core.git:reset-hard");
        // Never the Claude/Copilot/Hermes spellings.
        assert!(json.get("hookSpecificOutput").is_none());
        assert!(json.get("permissionDecision").is_none());
        assert!(json.get("action").is_none());
    }

    #[test]
    fn test_write_denial_crush_produces_deny_json() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        write_denial_to(
            &mut stdout,
            &mut stderr,
            HookProtocol::Crush,
            "git reset --hard HEAD~1",
            "git reset --hard destroys uncommitted changes",
            Some("core.git"),
            Some("reset-hard"),
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

        assert_eq!(json["version"], 1);
        assert_eq!(json["decision"], "deny");
        assert!(
            json["reason"]
                .as_str()
                .unwrap()
                .contains("git reset --hard destroys uncommitted changes"),
            "reason must carry the human-readable explanation, got: {}",
            json["reason"]
        );
        assert_eq!(json["ruleId"], "core.git:reset-hard");
        assert_eq!(json["packId"], "core.git");
        assert!(json.get("hookSpecificOutput").is_none());
        assert!(json.get("permissionDecision").is_none());
        assert!(
            !stderr.is_empty(),
            "Crush denial must still surface the stderr warning box"
        );
    }

    #[test]
    fn test_write_warning_crush_has_no_decision_and_carries_context() {
        // In Crush an explicit "allow" is an affirmative pre-approval that
        // skips the user's permission prompt, so a warn must be expressed as
        // "no opinion" (decision omitted) with the text in `context`.
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        write_warning_to(
            &mut stdout,
            &mut stderr,
            HookProtocol::Crush,
            "git stash drop",
            "drops stashed changes",
            Some("core.git"),
            Some("stash-drop"),
            None,
        );

        let stdout_str = String::from_utf8_lossy(&stdout);
        let json: serde_json::Value = serde_json::from_str(stdout_str.trim())
            .unwrap_or_else(|e| panic!("stdout not valid JSON: {e}\nstdout: {stdout_str}"));

        assert!(
            json.get("decision").is_none(),
            "warn must not pre-approve (allow) or block (deny) on Crush: {json}"
        );
        assert!(
            json.get("reason").is_none(),
            "reason is deny/halt-only: {json}"
        );
        assert!(
            json["context"].as_str().unwrap().starts_with("DCG warn:"),
            "context should be prefixed so the model knows this is advisory"
        );
        assert_eq!(json["ruleId"], "core.git:stash-drop");
        assert!(!stderr.is_empty(), "stderr must contain warn text");
    }

    #[test]
    fn test_write_review_request_crush_falls_back_to_deny() {
        // Crush has no `ask` decision; review policy must not degrade to
        // "no opinion" (which an allowlist could wave through).
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        write_review_request_to(
            &mut stdout,
            &mut stderr,
            HookProtocol::Crush,
            "git push --force",
            "force push rewrites remote history",
            Some("core.git"),
            Some("push-force"),
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

    // =========================================================================
    // VS Code Agent Host plural `toolCalls` robustness (issue #252 follow-up).
    // =========================================================================

    #[test]
    fn test_tool_calls_non_array_shape_does_not_abort_hook_input_parse() {
        // A typed Vec field would abort the WHOLE HookInput parse on a shape
        // mismatch, and an aborted parse fails open — masking the perfectly
        // good tool_input command in the same payload.
        let json =
            r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"},"toolCalls":{"0":{}}}"#;
        let input: HookInput =
            serde_json::from_str(json).expect("non-array toolCalls must not abort the parse");
        assert!(
            input.tool_calls.is_none(),
            "non-array shape degrades to None"
        );
        assert_eq!(extract_command(&input), Some("rm -rf /".to_string()));

        for shape in [r#""text""#, "5", "true"] {
            let json = format!(
                r#"{{"tool_name":"Bash","tool_input":{{"command":"git status"}},"toolCalls":{shape}}}"#
            );
            let input: HookInput = serde_json::from_str(&json)
                .unwrap_or_else(|e| panic!("toolCalls={shape} must not abort the parse: {e}"));
            assert!(input.tool_calls.is_none());
            assert_eq!(extract_command(&input), Some("git status".to_string()));
        }

        let null_json =
            r#"{"tool_name":"Bash","tool_input":{"command":"git status"},"toolCalls":null}"#;
        let input: HookInput = serde_json::from_str(null_json).unwrap();
        assert!(input.tool_calls.is_none());
    }

    #[test]
    fn test_tool_calls_array_skips_unfit_entries_and_keeps_fitting_ones() {
        let json =
            r#"{"toolCalls":[42,"junk",{"name":"bash","args":{"command":"echo hi"}},{"name":7}]}"#;
        let input: HookInput =
            serde_json::from_str(json).expect("unfit entries must be skipped, not fatal");
        let calls = input.tool_calls.as_ref().expect("array shape is kept");
        assert_eq!(calls.len(), 1, "only the fitting entry survives");
        let extracted = extract_command_with_context(&input).expect("kept entry must extract");
        assert_eq!(extracted.command, "echo hi");
        assert!(extracted.additional_commands.is_empty());
    }

    #[test]
    fn test_tool_calls_lowercase_alias_is_accepted() {
        let json = r#"{"toolcalls":[{"name":"bash","args":{"command":"echo hi"}}]}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(
            input.tool_calls.as_ref().map(Vec::len),
            Some(1),
            "the all-lowercase casing must map to the same field"
        );
    }

    #[test]
    fn test_batch_entry_gating_mirrors_singular_tool_call_posture() {
        // A nameless entry that still carries args (mirrors the singular
        // `toolCall` posture).
        let nameless: HookInput =
            serde_json::from_str(r#"{"toolCalls":[{"args":{"command":"rm -rf /"}}]}"#).unwrap();
        assert!(is_shell_hook_candidate(&nameless));
        let extracted = extract_command_with_context(&nameless).expect("nameless entry extracts");
        assert_eq!(extracted.command, "rm -rf /");
        assert_eq!(extracted.dialect, ShellDialect::Unknown);

        // agy's shell tool name `run_command` in a batched entry.
        let run_command: HookInput = serde_json::from_str(
            r#"{"toolCalls":[{"name":"run_command","args":{"CommandLine":"rm -rf /"}}]}"#,
        )
        .unwrap();
        assert!(is_shell_hook_candidate(&run_command));
        let extracted =
            extract_command_with_context(&run_command).expect("run_command entry extracts");
        assert_eq!(extracted.command, "rm -rf /");

        // CommandLine-style keys on an ordinary shell entry.
        for key in ["CommandLine", "commandLine", "Command"] {
            let json = format!(
                r#"{{"toolCalls":[{{"name":"powershell","args":{{"{key}":"Remove-Item -Recurse -Force C:\\src"}}}}]}}"#
            );
            let input: HookInput = serde_json::from_str(&json).unwrap();
            let extracted = extract_command_with_context(&input)
                .unwrap_or_else(|| panic!("{key} entry must extract"));
            assert_eq!(extracted.command, r"Remove-Item -Recurse -Force C:\src");
            assert_eq!(extracted.dialect, ShellDialect::PowerShell);
        }

        // A non-shell entry alone still extracts nothing.
        let non_shell: HookInput = serde_json::from_str(
            r#"{"toolCalls":[{"name":"readFile","args":{"path":"/w/a.txt"}}]}"#,
        )
        .unwrap();
        assert!(!is_shell_hook_candidate(&non_shell));
        assert_eq!(extract_command_with_context(&non_shell), None);
    }

    #[test]
    fn test_tool_input_and_tool_args_siblings_ride_along_with_a_batch() {
        // Regression: extraction returned as soon as the batch yielded one
        // command, so a destructive `tool_input`/`tool_args` sibling in the
        // same envelope was never evaluated (silent allow).
        let with_tool_input: HookInput = serde_json::from_str(
            r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"},
                "toolCalls":[{"name":"bash","args":"{\"command\":\"ls -la\"}"}]}"#,
        )
        .unwrap();
        let extracted = extract_command_with_context(&with_tool_input).expect("must extract");
        assert_eq!(extracted.command, "ls -la");
        assert_eq!(
            extracted.additional_commands,
            vec![("rm -rf /".to_string(), ShellDialect::Posix)],
            "the tool_input sibling must ride along as another entry"
        );

        let with_tool_args: HookInput = serde_json::from_str(
            r#"{"toolName":"bash","toolArgs":"{\"command\":\"rm -rf /\"}",
                "toolCalls":[{"name":"bash","args":{"command":"ls -la"}}]}"#,
        )
        .unwrap();
        let extracted = extract_command_with_context(&with_tool_args).expect("must extract");
        assert_eq!(extracted.command, "ls -la");
        assert_eq!(
            extracted.additional_commands,
            vec![("rm -rf /".to_string(), ShellDialect::Posix)],
            "the tool_args sibling must ride along as another entry"
        );
    }

    #[test]
    fn test_non_shell_only_batch_leaves_protocol_detection_to_other_markers() {
        // Regression: the toolCalls branch fired on ANY non-empty array, so a
        // single non-shell entry rerouted another agent's payload into Claude
        // wire shape — a deny document those parsers drop (fail-open).
        let _lock = ENV_LOCK.lock().unwrap();
        let _no_posit_env = EnvVarGuard::remove("PA_PROJECT_DIR");
        let _no_claude_env = EnvVarGuard::remove("CLAUDE_CODE");
        let _no_claude_session_env = EnvVarGuard::remove("CLAUDE_SESSION_ID");

        let decoy = r#""toolCalls":[{"name":"readFile","args":{"path":"/w/a.txt"}}]"#;
        let cases = [
            (
                format!(
                    r#"{{"hook_event_name":"BeforeTool","tool_name":"run_shell_command",
                        "tool_input":{{"command":"rm -rf /"}},{decoy}}}"#
                ),
                HookProtocol::Gemini,
            ),
            (
                format!(
                    r#"{{"hook_event_name":"pre_tool_call","tool_name":"terminal",
                        "tool_input":{{"command":"rm -rf /"}},{decoy}}}"#
                ),
                HookProtocol::Hermes,
            ),
            (
                format!(
                    r#"{{"hookEventName":"pre_tool_use","toolName":"run_terminal_cmd",
                        "toolInput":{{"command":"rm -rf /"}},{decoy}}}"#
                ),
                HookProtocol::Grok,
            ),
            (
                format!(
                    r#"{{"hook_event_name":"PreToolUse","tool_name":"bash","turn_id":"turn-1",
                        "tool_input":{{"command":"rm -rf /"}},{decoy}}}"#
                ),
                HookProtocol::Codex,
            ),
        ];

        for (json, expected) in cases {
            let input: HookInput = serde_json::from_str(&json).unwrap();
            assert_eq!(
                detect_protocol(&input),
                expected,
                "a non-shell-only batch must not hijack the protocol: {json}"
            );
            // The real command still comes from tool_input.
            let extracted = extract_command_with_context(&input).expect("must extract");
            assert_eq!(extracted.command, "rm -rf /");
        }

        // A genuine shell batch still identifies the Agent Host.
        let shell_batch: HookInput = serde_json::from_str(
            r#"{"sessionId":"s","toolCalls":[
                {"name":"readFile","args":{"path":"/w/a.txt"}},
                {"name":"bash","args":{"command":"ls"}}
            ]}"#,
        )
        .unwrap();
        assert_eq!(
            detect_protocol(&shell_batch),
            HookProtocol::ClaudeCompatible
        );
    }

    #[test]
    fn test_singular_tool_call_alongside_batch_is_also_evaluated() {
        // A payload carrying BOTH the plural batch and a singular `toolCall`
        // must surface the singular command too — otherwise the batch could
        // be used as a decoy while the singular envelope carries the payload.
        let json = r#"{
            "toolCalls":[{"name":"bash","args":{"command":"git status"}}],
            "toolCall":{"name":"run_command","args":{"CommandLine":"rm -rf /"}}
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        let extracted = extract_command_with_context(&input).expect("must extract");
        assert_eq!(extracted.command, "git status");
        assert_eq!(
            extracted.additional_commands,
            vec![("rm -rf /".to_string(), ShellDialect::Unknown)],
            "the singular toolCall command must ride along as a batch entry"
        );
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
        // Ambient env markers (`PA_PROJECT_DIR` from a Posit Assistant
        // workspace, `CLAUDE_CODE`/`CLAUDE_SESSION_ID` from a Claude Code
        // session) would otherwise make this assertion flaky, so pin them
        // removed under the env lock like the sibling Posit tests do.
        let _lock = ENV_LOCK.lock().unwrap();
        let _no_posit_env = EnvVarGuard::remove("PA_PROJECT_DIR");
        let _no_claude_env = EnvVarGuard::remove("CLAUDE_CODE");
        let _no_claude_session_env = EnvVarGuard::remove("CLAUDE_SESSION_ID");
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
    fn test_pattern_suggestion_alternatives_marks_gated_entries() {
        let suggestions = [
            PatternSuggestion::new("ls -la ~/x", "Verify the path"),
            PatternSuggestion::gated("mv ~/x ~/x.deleted", "Soft-delete rename"),
        ];

        let alternatives = pattern_suggestion_alternatives("mv ~/x /tmp/y", true, &suggestions);

        assert_eq!(
            alternatives,
            vec![
                "Verify the path: ls -la ~/x".to_string(),
                "Soft-delete rename: mv ~/x ~/x.deleted  \
                 (dcg gates this too — it needs explicit approval)"
                    .to_string(),
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
    fn test_write_indeterminate_never_allows_or_emits_empty_stdout() {
        const REASON: &str = "DCG could not complete safety evaluation within 200ms \
            (stage: evaluation); command was not verified. Review manually or increase \
            hook_timeout_ms.";

        let cases = [
            (HookProtocol::ClaudeCompatible, "ask"),
            (HookProtocol::Copilot, "ask"),
            (HookProtocol::Codex, "deny"),
            (HookProtocol::Gemini, "deny"),
            (HookProtocol::Hermes, "block"),
            (HookProtocol::Grok, "deny"),
            (HookProtocol::Antigravity, "block"),
            (HookProtocol::Crush, "deny"),
        ];

        for (protocol, expected_decision) in cases {
            let mut stdout = FlushProbe::default();
            let mut stderr = FlushProbe::default();
            write_indeterminate_to(&mut stdout, &mut stderr, protocol, REASON, false);

            assert!(
                !stdout.bytes.is_empty(),
                "{protocol:?} must not silently allow an indeterminate result"
            );
            assert!(
                !stderr.bytes.is_empty(),
                "{protocol:?} must surface an operator-visible diagnostic"
            );
            assert_eq!(stdout.flushes, 1, "{protocol:?} must flush its decision");
            assert_eq!(stderr.flushes, 1, "{protocol:?} must flush diagnostics");

            let json: serde_json::Value = serde_json::from_slice(&stdout.bytes)
                .unwrap_or_else(|error| panic!("{protocol:?} output must be JSON: {error}"));
            let (decision, reason) = match protocol {
                HookProtocol::ClaudeCompatible | HookProtocol::Codex => {
                    let specific = &json["hookSpecificOutput"];
                    (
                        specific["permissionDecision"].as_str(),
                        specific["permissionDecisionReason"].as_str(),
                    )
                }
                HookProtocol::Copilot => (
                    json["permissionDecision"].as_str(),
                    json["permissionDecisionReason"].as_str(),
                ),
                HookProtocol::Gemini
                | HookProtocol::Hermes
                | HookProtocol::Grok
                | HookProtocol::Antigravity
                | HookProtocol::Crush => (json["decision"].as_str(), json["reason"].as_str()),
            };

            assert_eq!(decision, Some(expected_decision), "payload: {json}");
            assert_eq!(reason, Some(REASON), "payload: {json}");
            assert_ne!(decision, Some("allow"), "payload: {json}");

            if protocol == HookProtocol::Hermes {
                assert_eq!(json["action"], "block");
                assert_eq!(json["message"], REASON);
            }
        }
    }

    /// #338: `general.unverified_decision = "deny"` must convert the
    /// review-capable protocols' `ask` into an outright denial, so an
    /// unattended session cannot stall on (or auto-approve) exactly the
    /// commands dcg declined to inspect. Protocols that already block keep
    /// blocking, with their reason bytes unchanged.
    #[test]
    fn test_write_indeterminate_denies_when_unverified_decision_is_deny() {
        const REASON: &str = "Command is 126015 bytes and exceeds limit 65536 bytes; \
            DCG did not evaluate it. Reduce the command size or raise \
            general.max_command_bytes after review.";

        let cases = [
            (HookProtocol::ClaudeCompatible, "deny", true),
            (HookProtocol::Copilot, "deny", true),
            (HookProtocol::Codex, "deny", false),
            (HookProtocol::Gemini, "deny", false),
            (HookProtocol::Hermes, "block", false),
            (HookProtocol::Grok, "deny", false),
            (HookProtocol::Antigravity, "block", false),
            (HookProtocol::Crush, "deny", false),
        ];

        for (protocol, expected_decision, reason_is_annotated) in cases {
            let mut stdout = FlushProbe::default();
            let mut stderr = FlushProbe::default();
            write_indeterminate_to(&mut stdout, &mut stderr, protocol, REASON, true);

            let json: serde_json::Value = serde_json::from_slice(&stdout.bytes)
                .unwrap_or_else(|error| panic!("{protocol:?} output must be JSON: {error}"));
            let (decision, reason) = match protocol {
                HookProtocol::ClaudeCompatible | HookProtocol::Codex => {
                    let specific = &json["hookSpecificOutput"];
                    (
                        specific["permissionDecision"].as_str(),
                        specific["permissionDecisionReason"].as_str(),
                    )
                }
                HookProtocol::Copilot => (
                    json["permissionDecision"].as_str(),
                    json["permissionDecisionReason"].as_str(),
                ),
                HookProtocol::Gemini
                | HookProtocol::Hermes
                | HookProtocol::Grok
                | HookProtocol::Antigravity
                | HookProtocol::Crush => (json["decision"].as_str(), json["reason"].as_str()),
            };

            assert_eq!(decision, Some(expected_decision), "payload: {json}");
            let reason = reason.unwrap_or_else(|| panic!("{protocol:?} carries no reason"));
            assert!(reason.starts_with(REASON), "payload: {json}");
            assert_eq!(
                reason.contains("unverified_decision"),
                reason_is_annotated,
                "only the downgraded ask protocols explain the configured denial: {json}"
            );
        }
    }

    #[test]
    fn test_write_review_request_asks_only_when_protocol_supports_review() {
        let cases = [
            (HookProtocol::ClaudeCompatible, "ask"),
            (HookProtocol::Copilot, "ask"),
            (HookProtocol::Codex, "deny"),
            (HookProtocol::Gemini, "deny"),
            (HookProtocol::Hermes, "block"),
            (HookProtocol::Grok, "deny"),
            (HookProtocol::Antigravity, "block"),
            (HookProtocol::Crush, "deny"),
        ];
        let allow = test_allow_once();

        for (protocol, expected_decision) in cases {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            write_review_request_to(
                &mut stdout,
                &mut stderr,
                protocol,
                "git reset --hard HEAD~1",
                "destroys uncommitted changes",
                Some("core.git"),
                Some("reset-hard"),
                Some("Rewrites the working tree and index."),
                Some(&allow),
                None,
                Some(crate::packs::Severity::Critical),
                Some(0.99),
                &[],
                None,
            );

            assert!(!stdout.is_empty(), "{protocol:?} must emit a decision");
            assert!(!stderr.is_empty(), "{protocol:?} must emit a diagnostic");

            let json: serde_json::Value = serde_json::from_slice(&stdout)
                .unwrap_or_else(|error| panic!("{protocol:?} output must be JSON: {error}"));
            let (decision, reason) = match protocol {
                HookProtocol::ClaudeCompatible | HookProtocol::Codex => {
                    let specific = &json["hookSpecificOutput"];
                    (
                        specific["permissionDecision"].as_str(),
                        specific["permissionDecisionReason"].as_str(),
                    )
                }
                HookProtocol::Copilot => (
                    json["permissionDecision"].as_str(),
                    json["permissionDecisionReason"].as_str(),
                ),
                HookProtocol::Gemini
                | HookProtocol::Hermes
                | HookProtocol::Grok
                | HookProtocol::Antigravity
                | HookProtocol::Crush => (json["decision"].as_str(), json["reason"].as_str()),
            };

            assert_eq!(decision, Some(expected_decision), "payload: {json}");
            assert_ne!(decision, Some("allow"), "payload: {json}");
            if matches!(
                protocol,
                HookProtocol::ClaudeCompatible | HookProtocol::Copilot
            ) {
                assert!(
                    reason.is_some_and(|text| text.starts_with("APPROVAL REQUIRED by dcg")),
                    "review-capable payload: {json}"
                );
            } else {
                assert!(
                    reason.is_some_and(|text| text.starts_with("BLOCKED by dcg")),
                    "fail-closed payload: {json}"
                );
            }
        }
    }

    #[test]
    fn test_write_warning_claude_is_non_blocking() {
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

        assert!(stdout.is_empty(), "warn must not request operator review");
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
    fn test_write_warning_copilot_is_non_blocking() {
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

        assert!(stdout.is_empty(), "warn must not request operator review");
        assert!(!stderr.is_empty(), "stderr must contain warning text");
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

    // =========================================================================
    // Issue #290: lenient command extraction from a truncated JSON prefix
    // =========================================================================

    /// Helper: the historic single-command assertion shape, now expressed
    /// over the all-occurrences scanner.
    fn only_command(prefix: &str) -> Option<String> {
        let mut commands = extract_commands_from_truncated_json(prefix);
        assert!(
            commands.len() <= 1,
            "expected at most one command occurrence, got {commands:?}"
        );
        commands.pop()
    }

    #[test]
    fn test_290_extract_command_complete_string() {
        let prefix = r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#;
        assert_eq!(only_command(prefix).as_deref(), Some("git status"));
    }

    #[test]
    fn test_290_extract_command_truncated_mid_value() {
        // Oversized payload cut off inside the command string: the decoded
        // prefix is returned so a destructive PREFIX can still deny.
        let prefix =
            r#"{"tool_name":"Bash","tool_input":{"command":"git reset --hard && echo AAAA"#;
        assert_eq!(
            only_command(prefix).as_deref(),
            Some("git reset --hard && echo AAAA")
        );
    }

    #[test]
    fn test_290_extract_command_decodes_escapes() {
        let prefix = r#"{"tool_input":{"command":"echo \"hi\"\tdone \\ ok"#;
        assert_eq!(
            only_command(prefix).as_deref(),
            Some("echo \"hi\"\tdone \\ ok")
        );
    }

    #[test]
    fn test_290_extract_command_truncated_mid_escape_keeps_clean_prefix() {
        let prefix = r#"{"tool_input":{"command":"git clean -fdx \"#;
        assert_eq!(only_command(prefix).as_deref(), Some("git clean -fdx "));
    }

    #[test]
    fn test_290_extract_command_unicode_escape() {
        let prefix = r#"{"tool_input":{"command":"echo \u0041B"}}"#;
        assert_eq!(only_command(prefix).as_deref(), Some("echo AB"));
    }

    #[test]
    fn test_290_extract_no_command_key_is_none() {
        let prefix = r#"{"tool_name":"Bash","tool_input":{"cmd":"ls"}}"#;
        assert!(extract_commands_from_truncated_json(prefix).is_empty());
    }

    #[test]
    fn test_290_extract_escaped_key_inside_string_value_is_skipped() {
        // `\"command\"` inside a string value is escaped bytes, not the raw
        // `"command"` key sequence, so it must not match.
        let prefix = r#"{"note":"the \"command\": here is prose"}"#;
        assert!(extract_commands_from_truncated_json(prefix).is_empty());
    }

    #[test]
    fn test_290_extract_key_without_string_value_is_skipped() {
        // A `"command"` key whose value is not a string (or prose mention
        // followed by no colon) must not produce garbage.
        let prefix = r#"{"command": 42, "other": true}"#;
        assert!(extract_commands_from_truncated_json(prefix).is_empty());
    }

    #[test]
    fn test_290_extract_malformed_escape_is_none() {
        let prefix = r#"{"tool_input":{"command":"echo \q oops"}}"#;
        assert!(extract_commands_from_truncated_json(prefix).is_empty());
    }

    #[test]
    fn test_290_extract_raw_control_char_is_none() {
        let prefix = "{\"tool_input\":{\"command\":\"echo hi\nrm -rf /\"}}";
        assert!(extract_commands_from_truncated_json(prefix).is_empty());
    }

    #[test]
    fn test_290_extract_returns_every_command_occurrence() {
        // serde_json resolves duplicate keys last-wins, so a first-wins
        // scanner would judge the decoy and fail open. Every occurrence must
        // come back so the caller can deny on ANY of them.
        let prefix = r#"{"tool_name":"Bash","tool_input":{"command":"echo ok","command":"git reset --hard"}}"#;
        assert_eq!(
            extract_commands_from_truncated_json(prefix),
            vec!["echo ok".to_string(), "git reset --hard".to_string()]
        );
    }

    #[test]
    fn test_290_extract_skips_decoy_object_before_real_command() {
        // A benign `"command"` in an earlier unrelated object must not hide
        // the real tool_input command.
        let prefix = r#"{"context":{"command":"ls -la"},"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/x"}}"#;
        assert_eq!(
            extract_commands_from_truncated_json(prefix),
            vec!["ls -la".to_string(), "rm -rf /tmp/x".to_string()]
        );
    }

    #[test]
    fn test_290_extract_untrusted_occurrence_does_not_drop_the_rest() {
        // One occurrence the scanner distrusts (malformed escape) is dropped
        // without discarding the occurrences it CAN decode.
        let prefix =
            r#"{"a":{"command":"echo \q oops"},"tool_input":{"command":"git clean -fdx"}}"#;
        assert_eq!(
            extract_commands_from_truncated_json(prefix),
            vec!["git clean -fdx".to_string()]
        );
    }

    // =========================================================================
    // Issue #290 follow-up: tool-name attribution for oversized prefixes
    // =========================================================================

    #[test]
    fn test_290_tool_name_scan_recognizes_snake_and_camel_case() {
        for prefix in [
            r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#,
            r#"{"toolName":"Bash","toolArgs":{"command":"ls"}}"#,
        ] {
            let (name, dialect) =
                shell_tool_from_truncated_json(prefix).expect("shell tool must be recognized");
            assert_eq!(name, "Bash");
            assert_eq!(dialect, ShellDialect::Posix);
        }
    }

    #[test]
    fn test_290_tool_name_scan_maps_dialect_like_the_normal_path() {
        for (tool, expected) in [
            ("bash", ShellDialect::Posix),
            ("pwsh", ShellDialect::PowerShell),
            ("cmd.exe", ShellDialect::Cmd),
            ("run_shell_command", ShellDialect::Unknown),
        ] {
            let prefix = format!(r#"{{"tool_name":"{tool}","tool_input":{{"command":"ls"}}}}"#);
            let (_, dialect) =
                shell_tool_from_truncated_json(&prefix).expect("shell tool must be recognized");
            assert_eq!(
                dialect,
                shell_dialect_for_tool_name(Some(tool)),
                "dialect must match the normal parsed path for {tool:?}"
            );
            assert_eq!(dialect, expected);
        }
    }

    #[test]
    fn test_290_tool_name_scan_rejects_non_shell_tools() {
        for prefix in [
            r#"{"tool_name":"Write","tool_input":{"file_path":"/x","command":"rm -rf /"}}"#,
            r#"{"tool_name":"Read","tool_input":{"command":"rm -rf /"}}"#,
            // No tool name at all: nothing to attribute, must fail open.
            r#"{"tool_input":{"command":"rm -rf /"}}"#,
        ] {
            assert!(
                shell_tool_from_truncated_json(prefix).is_none(),
                "must not attribute {prefix:?} to a shell tool"
            );
        }
    }

    #[test]
    fn test_290_tool_name_scan_sees_past_a_non_shell_decoy() {
        let prefix = r#"{"tool_name":"Write","padding":"AAA","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
        let (name, dialect) =
            shell_tool_from_truncated_json(prefix).expect("real shell tool must still be found");
        assert_eq!(name, "Bash");
        assert_eq!(dialect, ShellDialect::Posix);
    }

    /// Issue #386: `[general] log_file` takes no redaction config and used to
    /// write `Command: {command}` raw, so a blocked command carrying a token
    /// landed in the log verbatim. Canaries below are synthetic.
    #[test]
    fn blocked_command_log_redacts_secrets() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("blocked.log");
        let path = log.to_str().expect("utf-8 path");
        let command = "deploy --purge AKIAABCDEFGHIJKLMNOP \
             ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        log_blocked_command(path, command, "destructive", Some("core")).expect("write log");
        log_budget_skip(
            path,
            command,
            "prefilter",
            Duration::from_millis(5),
            Duration::from_millis(1),
        )
        .expect("write budget log");

        let contents = std::fs::read_to_string(&log).expect("read log");
        for canary in [
            "AKIAABCDEFGHIJKLMNOP",
            "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        ] {
            assert!(
                !contents.contains(canary),
                "canary {canary} survived into the log file: {contents}"
            );
        }
        // The non-secret part of the command must still be legible.
        assert!(contents.contains("deploy --purge"), "{contents}");
        assert!(contents.contains("[AWS_ACCESS_KEY]"), "{contents}");
        assert!(contents.contains("[GITHUB_TOKEN]"), "{contents}");
    }
}

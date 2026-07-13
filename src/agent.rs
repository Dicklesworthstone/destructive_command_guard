//! AI coding agent detection for agent-specific profiles.
//!
//! This module detects which AI coding agent is invoking dcg, enabling per-agent
//! trust levels and configuration overrides.
//!
//! # Detection Methods
//!
//! 1. **Explicit flag**: `--agent=<name>` CLI flag for manual override
//! 2. **Environment variables**: Most agents set identifying env vars
//! 3. **Parent process inspection** (fallback): Check process tree for agent names
//!
//! # Supported Agents
//!
//! - Claude Code: `CLAUDE_CODE=1` or `CLAUDE_SESSION_ID` env var
//! - Augment Code: `AUGMENT_AGENT=1` or `AUGMENT_CONVERSATION_ID` env var
//! - Aider: `AIDER_SESSION=1` env var
//! - Continue: `CONTINUE_SESSION_ID` env var
//! - Codex CLI: `CODEX_CLI=1` env var
//! - Gemini CLI: `GEMINI_CLI=1` env var
//! - Copilot CLI: `COPILOT_CLI=1` or `COPILOT_AGENT_START_TIME_SEC` env var
//! - Cursor IDE: `CURSOR_IDE=1` env var (set by dcg's Cursor hook script)
//! - Hermes Agent: `HERMES_AGENT=1` or `HERMES_SESSION_ID` env var
//! - Grok (xAI): `GROK_SESSION_ID`, `GROK_HOOK_EVENT`, or `GROK_WORKSPACE_ROOT`
//!   env var (set when Grok invokes hooks defined in `~/.grok/hooks/*.json`,
//!   `.grok/hooks/*.json`, or `~/.claude/settings.json` via the Claude-Code
//!   compatibility layer)
//! - Antigravity CLI (`agy`): detected via the `agy` parent process name and/or
//!   the `ANTIGRAVITY_CONVERSATION_ID` env var (set by `agy` for tool/hook
//!   subprocesses). `agy` reads Claude-Code-compatible `PreToolUse` hooks from
//!   `~/.gemini/config/hooks.json` (with `~/.gemini/antigravity-cli/hooks.json`
//!   symlinked to it for backward compatibility).
//! - Pi (earendil-works `pi` coding agent): `PI_CODING_AGENT=true` env var (set
//!   by `pi` into the environment of the subprocesses it spawns).
//!
//! # Usage
//!
//! ```ignore
//! use destructive_command_guard::agent::{Agent, detect_agent};
//!
//! let agent = detect_agent();
//! println!("Detected agent: {}", agent);
//! ```

use std::cell::RefCell;
use std::fmt;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Cache duration before refreshing agent detection.
/// Agent detection is stable within a process, so we use a longer TTL.
const CACHE_TTL: Duration = Duration::from_secs(300);

const WINDOWS_EXECUTABLE_SUFFIXES: &[&str] = &[".exe", ".cmd", ".bat", ".ps1"];

/// Known AI coding agents that dcg can detect and configure per-agent policies for.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Agent {
    /// Claude Code from Anthropic.
    ClaudeCode,
    /// Augment Code CLI (auggie).
    AugmentCode,
    /// Aider AI coding assistant.
    Aider,
    /// Continue.dev IDE extension.
    Continue,
    /// `OpenAI` Codex CLI.
    CodexCli,
    /// Google Gemini CLI.
    GeminiCli,
    /// GitHub Copilot CLI.
    CopilotCli,
    /// Cursor IDE (via beforeShellExecution hook).
    CursorIde,
    /// `NousResearch` Hermes Agent (via shell `pre_tool_call` hook).
    Hermes,
    /// xAI Grok CLI / Grok Build TUI (via `~/.grok/hooks/*.json` and the
    /// `~/.claude/settings.json` compatibility layer; emits `pre_tool_use`
    /// events with `run_terminal_cmd` as the shell tool).
    Grok,
    /// Google Antigravity CLI (`agy`). Reads Claude-Code-compatible
    /// `PreToolUse` hooks from `~/.gemini/config/hooks.json`; emits a tool-call
    /// envelope with `toolCall.name = "run_command"` and the shell command in
    /// `toolCall.args.CommandLine`.
    Antigravity,
    /// earendil-works Pi coding agent (`pi`). Injects `PI_CODING_AGENT=true`
    /// into the environment of the subprocesses it spawns.
    Pi,
    /// A custom agent specified by name.
    Custom(String),
    /// Unknown or undetected agent.
    Unknown,
}

impl Agent {
    /// Returns the canonical configuration key for this agent.
    ///
    /// This is used to look up agent-specific configuration in config files.
    /// For example, `Agent::ClaudeCode.config_key()` returns `"claude-code"`.
    #[must_use]
    pub fn config_key(&self) -> &str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::AugmentCode => "augment-code",
            Self::Aider => "aider",
            Self::Continue => "continue",
            Self::CodexCli => "codex-cli",
            Self::GeminiCli => "gemini-cli",
            Self::CopilotCli => "copilot-cli",
            Self::CursorIde => "cursor-ide",
            Self::Hermes => "hermes",
            Self::Grok => "grok",
            Self::Antigravity => "antigravity",
            Self::Pi => "pi",
            Self::Custom(name) => name,
            Self::Unknown => "unknown",
        }
    }

    /// Returns `true` if this is a known agent (not Unknown or Custom).
    #[must_use]
    pub const fn is_known(&self) -> bool {
        matches!(
            self,
            Self::ClaudeCode
                | Self::AugmentCode
                | Self::Aider
                | Self::Continue
                | Self::CodexCli
                | Self::GeminiCli
                | Self::CopilotCli
                | Self::CursorIde
                | Self::Hermes
                | Self::Grok
                | Self::Antigravity
                | Self::Pi
        )
    }

    /// Returns `true` if this is a custom, non-built-in agent name.
    ///
    /// Whether a built-in agent was explicitly specified is stored on
    /// [`DetectionResult::method`], not on the [`Agent`] enum.
    #[must_use]
    pub const fn is_explicit(&self) -> bool {
        matches!(self, Self::Custom(_))
    }

    /// Parse an agent name string into an Agent enum.
    ///
    /// Accepts various formats:
    /// - `"claude-code"`, `"claude_code"`, `"claudecode"` -> `ClaudeCode`
    /// - `"augment-code"`, `"augment_code"`, `"augmentcode"`, `"auggie"`, `"augment"` -> `AugmentCode`
    /// - `"aider"` -> `Aider`
    /// - `"continue"` -> `Continue`
    /// - `"codex"`, `"codex-cli"`, `"codex_cli"` -> `CodexCli`
    /// - `"gemini"`, `"gemini-cli"`, `"gemini_cli"` -> `GeminiCli`
    /// - `"cursor"`, `"cursor-ide"`, `"cursor_ide"` -> `CursorIde`
    /// - `"unknown"` -> `Unknown`
    /// - Any other value -> `Custom(value)`
    #[must_use]
    pub fn from_name(name: &str) -> Self {
        let normalized = name.to_lowercase().replace(['-', '_'], "");
        match normalized.as_str() {
            "claudecode" => Self::ClaudeCode,
            "augmentcode" | "auggie" | "augment" => Self::AugmentCode,
            "aider" => Self::Aider,
            "continue" => Self::Continue,
            "codexcli" | "codex" => Self::CodexCli,
            "geminicli" | "gemini" => Self::GeminiCli,
            "copilotcli" | "copilot" => Self::CopilotCli,
            "cursoride" | "cursor" => Self::CursorIde,
            "hermes" | "hermesagent" | "hermescli" => Self::Hermes,
            "grok" | "grokcli" | "grokbuild" | "xai" | "xaigrok" => Self::Grok,
            "agy" | "antigravity" | "antigravitycli" => Self::Antigravity,
            "pi" | "picli" | "picodingagent" => Self::Pi,
            "unknown" => Self::Unknown,
            _ => Self::Custom(name.to_string()),
        }
    }
}

impl fmt::Display for Agent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClaudeCode => write!(f, "Claude Code"),
            Self::AugmentCode => write!(f, "Augment Code"),
            Self::Aider => write!(f, "Aider"),
            Self::Continue => write!(f, "Continue"),
            Self::CodexCli => write!(f, "Codex CLI"),
            Self::GeminiCli => write!(f, "Gemini CLI"),
            Self::CopilotCli => write!(f, "GitHub Copilot CLI"),
            Self::CursorIde => write!(f, "Cursor IDE"),
            Self::Hermes => write!(f, "Hermes Agent"),
            Self::Grok => write!(f, "Grok (xAI)"),
            Self::Antigravity => write!(f, "Antigravity CLI"),
            Self::Pi => write!(f, "Pi"),
            Self::Custom(name) => write!(f, "{name}"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Result of agent detection with metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionResult {
    /// The detected agent.
    pub agent: Agent,
    /// How the agent was detected.
    pub method: DetectionMethod,
    /// The specific environment variable or process name that matched (if any).
    pub matched_value: Option<String>,
}

impl DetectionResult {
    /// Create a new detection result.
    #[must_use]
    pub const fn new(agent: Agent, method: DetectionMethod, matched_value: Option<String>) -> Self {
        Self {
            agent,
            method,
            matched_value,
        }
    }

    /// Create an Unknown detection result.
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            agent: Agent::Unknown,
            method: DetectionMethod::None,
            matched_value: None,
        }
    }
}

/// How an agent was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionMethod {
    /// Detected via environment variable.
    Environment,
    /// Explicitly specified via CLI flag.
    Explicit,
    /// Detected via parent process inspection.
    Process,
    /// No detection method succeeded.
    None,
}

impl fmt::Display for DetectionMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Environment => write!(f, "environment variable"),
            Self::Explicit => write!(f, "explicit flag"),
            Self::Process => write!(f, "parent process"),
            Self::None => write!(f, "not detected"),
        }
    }
}

/// Cached agent detection result.
#[derive(Debug)]
struct CachedAgent {
    /// The cached detection result.
    result: DetectionResult,
    /// When this cache entry was created.
    cached_at: Instant,
}

impl CachedAgent {
    /// Returns `true` if this cache entry is still valid.
    fn is_valid(&self) -> bool {
        self.cached_at.elapsed() < CACHE_TTL
    }
}

thread_local! {
    /// Per-thread cache for agent detection.
    static AGENT_CACHE: RefCell<Option<CachedAgent>> = const { RefCell::new(None) };
}

/// Detect the current AI coding agent, using cache if available.
///
/// Returns an [`Agent`] enum indicating which agent is invoking dcg.
/// Results are cached for performance.
///
/// # Detection Order
///
/// 1. Explicit `--agent` CLI flag
/// 2. Environment variables
/// 3. Parent process inspection (fallback)
///
/// # Example
///
/// ```ignore
/// use destructive_command_guard::agent::detect_agent;
///
/// let agent = detect_agent();
/// println!("Running under: {}", agent);
/// ```
#[must_use]
pub fn detect_agent() -> Agent {
    detect_agent_with_details().agent
}

/// Detect the current AI coding agent with full details.
///
/// Returns a [`DetectionResult`] containing the agent, detection method,
/// and matched value (if any).
#[must_use]
pub fn detect_agent_with_details() -> DetectionResult {
    // Check cache first
    let cached = AGENT_CACHE.with(|cache| {
        let borrow = cache.borrow();
        if let Some(ref entry) = *borrow {
            if entry.is_valid() {
                return Some(entry.result.clone());
            }
        }
        None
    });

    if let Some(result) = cached {
        return result;
    }

    // Cache miss - perform detection
    let result = perform_detection();

    // Update cache
    AGENT_CACHE.with(|cache| {
        *cache.borrow_mut() = Some(CachedAgent {
            result: result.clone(),
            cached_at: Instant::now(),
        });
    });

    result
}

/// Perform agent detection (not cached).
fn perform_detection() -> DetectionResult {
    // Honor explicit CLI override before ambient environment detection.
    if let Some(agent_name) = explicit_agent_from_args(std::env::args()) {
        return from_explicit(&agent_name);
    }

    // Try environment variable detection first
    if let Some(result) = detect_from_environment() {
        return result;
    }

    // Try parent process detection as fallback
    if let Some(result) = detect_from_parent_process() {
        return result;
    }

    DetectionResult::unknown()
}

fn explicit_agent_from_args<I, S>(args: I) -> Option<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut args = args.into_iter().skip(1);
    while let Some(arg) = args.next() {
        let arg = arg.as_ref();
        if arg == "--" {
            break;
        }
        if let Some(value) = arg.strip_prefix("--agent=") {
            return non_empty_agent_name(value);
        }
        if arg == "--agent" {
            return args
                .next()
                .and_then(|value| non_empty_agent_name(value.as_ref()));
        }
    }

    None
}

fn non_empty_agent_name(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// Detect agent from environment variables.
///
/// Checks for known environment variables set by AI coding agents.
fn detect_from_environment() -> Option<DetectionResult> {
    // Claude Code detection
    if std::env::var("CLAUDE_CODE").is_ok() {
        return Some(DetectionResult::new(
            Agent::ClaudeCode,
            DetectionMethod::Environment,
            Some("CLAUDE_CODE".to_string()),
        ));
    }
    if std::env::var("CLAUDE_SESSION_ID").is_ok() {
        return Some(DetectionResult::new(
            Agent::ClaudeCode,
            DetectionMethod::Environment,
            Some("CLAUDE_SESSION_ID".to_string()),
        ));
    }

    // Augment Code (auggie) detection
    if std::env::var("AUGMENT_AGENT").is_ok() {
        return Some(DetectionResult::new(
            Agent::AugmentCode,
            DetectionMethod::Environment,
            Some("AUGMENT_AGENT".to_string()),
        ));
    }
    if std::env::var("AUGMENT_CONVERSATION_ID").is_ok() {
        return Some(DetectionResult::new(
            Agent::AugmentCode,
            DetectionMethod::Environment,
            Some("AUGMENT_CONVERSATION_ID".to_string()),
        ));
    }

    // Aider detection
    if std::env::var("AIDER_SESSION").is_ok() {
        return Some(DetectionResult::new(
            Agent::Aider,
            DetectionMethod::Environment,
            Some("AIDER_SESSION".to_string()),
        ));
    }

    // Continue detection
    if std::env::var("CONTINUE_SESSION_ID").is_ok() {
        return Some(DetectionResult::new(
            Agent::Continue,
            DetectionMethod::Environment,
            Some("CONTINUE_SESSION_ID".to_string()),
        ));
    }

    // Codex CLI detection
    if std::env::var("CODEX_CLI").is_ok() {
        return Some(DetectionResult::new(
            Agent::CodexCli,
            DetectionMethod::Environment,
            Some("CODEX_CLI".to_string()),
        ));
    }

    // Gemini CLI detection
    if std::env::var("GEMINI_CLI").is_ok() {
        return Some(DetectionResult::new(
            Agent::GeminiCli,
            DetectionMethod::Environment,
            Some("GEMINI_CLI".to_string()),
        ));
    }

    // GitHub Copilot CLI detection
    if std::env::var("COPILOT_CLI").is_ok() {
        return Some(DetectionResult::new(
            Agent::CopilotCli,
            DetectionMethod::Environment,
            Some("COPILOT_CLI".to_string()),
        ));
    }
    if std::env::var("COPILOT_AGENT_START_TIME_SEC").is_ok() {
        return Some(DetectionResult::new(
            Agent::CopilotCli,
            DetectionMethod::Environment,
            Some("COPILOT_AGENT_START_TIME_SEC".to_string()),
        ));
    }

    // Cursor IDE detection (set by dcg's Cursor hook script before invoking dcg).
    //
    // NOTE (git_safety_guard-...5w9v.1.7): Cursor is integrated via a generated
    // hook script that translates Cursor's `beforeShellExecution` `{command, cwd}`
    // payload into dcg's hook shape and maps the result back to Cursor's
    // `{permission, continue, userMessage, ...}` response — a Python bridge on
    // Unix and a *pure-PowerShell* bridge on Windows (install.ps1
    // `Configure-CursorHook`, no interpreter dependency). A fully NATIVE Cursor
    // wire format in `hook.rs` was evaluated and deliberately deferred: unlike
    // every other protocol (silent-on-allow), Cursor expects a response on the
    // ALLOW path too, which would require emitting an allow payload across all of
    // main.rs's allow exit points (no-match / whitelist / allow-once / bypass) —
    // cross-cutting and fail-closed-risky for an optional feature whose bridge
    // already works and is verified end-to-end. Revisit if the bridge proves
    // insufficient. The `CURSOR_IDE` env var below is the bridge's agent-identity
    // signal (it does not change protocol dispatch).
    if std::env::var("CURSOR_IDE").is_ok() {
        return Some(DetectionResult::new(
            Agent::CursorIde,
            DetectionMethod::Environment,
            Some("CURSOR_IDE".to_string()),
        ));
    }

    // Hermes Agent detection. Hermes documents `HERMES_ACCEPT_HOOKS` for
    // bypassing consent prompts; we treat `HERMES_AGENT` / `HERMES_SESSION_ID`
    // as the canonical session markers (mirroring CLAUDE_CODE / CLAUDE_SESSION_ID).
    if std::env::var("HERMES_AGENT").is_ok() {
        return Some(DetectionResult::new(
            Agent::Hermes,
            DetectionMethod::Environment,
            Some("HERMES_AGENT".to_string()),
        ));
    }
    if std::env::var("HERMES_SESSION_ID").is_ok() {
        return Some(DetectionResult::new(
            Agent::Hermes,
            DetectionMethod::Environment,
            Some("HERMES_SESSION_ID".to_string()),
        ));
    }

    // Grok (xAI) detection. Grok sets three variables when invoking hooks
    // (per ~/.grok/docs/user-guide/10-hooks.md):
    //   - GROK_HOOK_EVENT       (e.g. "pre_tool_use")
    //   - GROK_SESSION_ID       (the current session id)
    //   - GROK_WORKSPACE_ROOT   (workspace root path)
    // Any one of these is sufficient to identify the invoking agent.
    if std::env::var("GROK_SESSION_ID").is_ok() {
        return Some(DetectionResult::new(
            Agent::Grok,
            DetectionMethod::Environment,
            Some("GROK_SESSION_ID".to_string()),
        ));
    }
    if std::env::var("GROK_HOOK_EVENT").is_ok() {
        return Some(DetectionResult::new(
            Agent::Grok,
            DetectionMethod::Environment,
            Some("GROK_HOOK_EVENT".to_string()),
        ));
    }
    if std::env::var("GROK_WORKSPACE_ROOT").is_ok() {
        return Some(DetectionResult::new(
            Agent::Grok,
            DetectionMethod::Environment,
            Some("GROK_WORKSPACE_ROOT".to_string()),
        ));
    }

    // Antigravity CLI (`agy`) detection. `agy` exports
    // `ANTIGRAVITY_CONVERSATION_ID=<uuid>` into the environment of the
    // subprocesses it spawns (confirmed in the `agy` binary: the format
    // string `ANTIGRAVITY_CONVERSATION_ID=%s`). This is the canonical session
    // marker, mirroring CLAUDE_SESSION_ID / GROK_SESSION_ID.
    if std::env::var("ANTIGRAVITY_CONVERSATION_ID").is_ok() {
        return Some(DetectionResult::new(
            Agent::Antigravity,
            DetectionMethod::Environment,
            Some("ANTIGRAVITY_CONVERSATION_ID".to_string()),
        ));
    }

    // Pi (earendil-works) detection. The `pi` coding agent injects
    // `PI_CODING_AGENT=true` into the environment of the subprocesses it
    // spawns. As with the other env markers we only check for the variable's
    // presence, so any truthy value (`true`, `1`, ...) identifies the agent.
    if std::env::var("PI_CODING_AGENT").is_ok() {
        return Some(DetectionResult::new(
            Agent::Pi,
            DetectionMethod::Environment,
            Some("PI_CODING_AGENT".to_string()),
        ));
    }

    None
}

/// Detect agent from parent process.
///
/// This is a fallback for agents that don't set environment variables.
#[cfg(target_os = "linux")]
fn detect_from_parent_process() -> Option<DetectionResult> {
    use std::fs;
    use std::os::unix::process::parent_id;

    let ppid = parent_id();
    let comm_path = format!("/proc/{ppid}/comm");

    if let Ok(process_name) = fs::read_to_string(&comm_path) {
        if let Some(result) = detection_from_process_name(&process_name) {
            return Some(result);
        }
    }

    let cmdline_path = format!("/proc/{ppid}/cmdline");
    let process_args = fs::read(&cmdline_path)
        .ok()
        .and_then(|bytes| nul_separated_args_to_string(&bytes))?;
    detection_from_process_name(&process_args)
}

/// Detect agent from parent process on Unix platforms without `/proc`.
#[cfg(all(unix, not(target_os = "linux")))]
fn detect_from_parent_process() -> Option<DetectionResult> {
    use std::os::unix::process::parent_id;

    let ppid = parent_id();
    parent_process_name_from_ps(ppid).and_then(|name| detection_from_process_name(&name))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn parent_process_name_from_ps(pid: u32) -> Option<String> {
    let pid = pid.to_string();
    let output = std::process::Command::new("ps")
        .args(["-p", &pid, "-o", "comm="])
        .output()
        .ok()?;

    if output.status.success() {
        if let Some(name) = first_non_empty_line(&String::from_utf8_lossy(&output.stdout)) {
            if detection_from_process_name(name).is_some() {
                return Some(name.to_string());
            }
        }
    }

    parent_process_args_from_ps(&pid)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn parent_process_args_from_ps(pid: &str) -> Option<String> {
    let output = std::process::Command::new("ps")
        .args(["-p", pid, "-o", "args="])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    first_non_empty_line(&String::from_utf8_lossy(&output.stdout)).map(str::to_string)
}

/// Detect agent from parent process on Windows.
#[cfg(windows)]
fn detect_from_parent_process() -> Option<DetectionResult> {
    parent_process_name_from_windows(std::process::id())
        .and_then(|name| detection_from_process_name(&name))
}

#[cfg(windows)]
fn parent_process_name_from_windows(current_pid: u32) -> Option<String> {
    let script = format!(
        "$p = Get-CimInstance Win32_Process -Filter 'ProcessId = {current_pid}'; \
         if ($null -eq $p) {{ exit 1 }}; \
         $parent = Get-CimInstance Win32_Process -Filter \"ProcessId = $($p.ParentProcessId)\"; \
         if ($null -eq $parent) {{ exit 1 }}; \
         Write-Output $parent.Name"
    );

    ["powershell.exe", "powershell", "pwsh"]
        .iter()
        .find_map(|program| windows_parent_name_with(program, &script))
}

#[cfg(windows)]
fn windows_parent_name_with(program: &str, script: &str) -> Option<String> {
    let output = std::process::Command::new(program)
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    first_non_empty_line(&String::from_utf8_lossy(&output.stdout)).map(str::to_string)
}

/// Detect agent from parent process on platforms without a safe implementation.
#[cfg(not(any(target_os = "linux", unix, windows)))]
fn detect_from_parent_process() -> Option<DetectionResult> {
    None
}

fn detection_from_process_name(raw_process_name: &str) -> Option<DetectionResult> {
    let process_name = normalize_process_name(raw_process_name)?;
    let agent = agent_from_process_name(&process_name)?;
    Some(DetectionResult::new(
        agent,
        DetectionMethod::Process,
        Some(process_name),
    ))
}

fn normalize_process_name(raw_process_name: &str) -> Option<String> {
    first_non_empty_line(raw_process_name).map(str::to_lowercase)
}

fn first_non_empty_line(value: &str) -> Option<&str> {
    value.lines().map(str::trim).find(|line| !line.is_empty())
}

// Only the Linux parent-process detector parses `/proc/<pid>/cmdline` (NUL-
// separated argv); on other platforms this helper is unused outside of tests,
// so gate it to avoid a dead-code warning on Windows/macOS non-test builds
// (which would fail Windows CI's `-D warnings`). `test` keeps its unit tests
// available on every platform.
#[cfg(any(target_os = "linux", test))]
fn nul_separated_args_to_string(bytes: &[u8]) -> Option<String> {
    let mut args = Vec::new();

    for arg in bytes.split(|byte| *byte == b'\0') {
        if arg.is_empty() {
            continue;
        }
        args.push(String::from_utf8_lossy(arg));
    }

    if args.is_empty() {
        None
    } else {
        Some(args.join(" "))
    }
}

/// Map a parent-process name to a known agent.
///
/// Tokenizes the input on whitespace and matches each token's basename (after
/// `\` → `/` normalization, last path segment, `.exe` strip, lower-case)
/// against an explicit name/alias table. This rejects false positives like
/// `claude-explorer`, `myproject-continue`, or `cursor-ext` whose basename
/// merely *contains* an agent name without *being* one.
///
/// The whitespace tokenization handles wrapper-style invocations like
/// `node /usr/local/bin/codex`: the first argv token is treated as the process
/// executable, while later tokens are only considered when they look like
/// path-like executable/script arguments. This avoids misclassifying ordinary
/// arguments such as `cargo test codex` or URL paths ending in `/codex`.
fn agent_from_process_name(process_name: &str) -> Option<Agent> {
    for (index, token) in process_name.split_whitespace().enumerate() {
        if index > 0 && !is_path_like_process_token(token) {
            continue;
        }

        if let Some(agent) = agent_for_basename(executable_basename(token).as_str()) {
            return Some(agent);
        }
    }
    None
}

fn is_path_like_process_token(token: &str) -> bool {
    let token = token.trim_matches(['"', '\'']);
    !token.starts_with('-')
        && !token.contains("://")
        && (token.contains('/') || token.contains('\\'))
}

fn executable_basename(token: &str) -> String {
    let normalized = token
        .trim_matches(['"', '\''])
        .to_lowercase()
        .replace('\\', "/");
    let last = normalized.rsplit('/').next().unwrap_or(&normalized);
    for suffix in WINDOWS_EXECUTABLE_SUFFIXES {
        if let Some(stem) = last.strip_suffix(suffix) {
            return stem.to_string();
        }
    }
    last.to_string()
}

fn agent_for_basename(basename: &str) -> Option<Agent> {
    // Exact-match table. New aliases for the same agent go in the same arm.
    // Substring matching is intentionally NOT used: a tool whose name merely
    // contains "claude" / "aider" / "continue" / "cursor" would otherwise be
    // misclassified.
    match basename {
        "claude" | "claude-code" | "claude_code" => Some(Agent::ClaudeCode),
        "augment" | "augment-code" | "auggie" => Some(Agent::AugmentCode),
        "aider" => Some(Agent::Aider),
        "continue" | "continue-cli" => Some(Agent::Continue),
        "codex" | "codex-cli" => Some(Agent::CodexCli),
        "gemini" | "gemini-cli" => Some(Agent::GeminiCli),
        "copilot" | "copilot-cli" | "gh-copilot" => Some(Agent::CopilotCli),
        "cursor" | "cursor-ide" => Some(Agent::CursorIde),
        "hermes" | "hermes-agent" | "hermes-cli" => Some(Agent::Hermes),
        "grok" | "grok-cli" | "grok-build" => Some(Agent::Grok),
        "agy" | "antigravity" | "antigravity-cli" => Some(Agent::Antigravity),
        "pi" | "pi-cli" => Some(Agent::Pi),
        _ => None,
    }
}

/// Create a detection result from an explicit agent name.
///
/// Used when the user specifies `--agent=<name>` on the command line.
#[must_use]
pub fn from_explicit(name: &str) -> DetectionResult {
    DetectionResult::new(
        Agent::from_name(name),
        DetectionMethod::Explicit,
        Some(name.to_string()),
    )
}

/// Clear the agent detection cache.
///
/// Useful for testing or when environment variables change.
pub fn clear_cache() {
    AGENT_CACHE.with(|cache| {
        *cache.borrow_mut() = None;
    });
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_config_keys() {
        assert_eq!(Agent::ClaudeCode.config_key(), "claude-code");
        assert_eq!(Agent::AugmentCode.config_key(), "augment-code");
        assert_eq!(Agent::Aider.config_key(), "aider");
        assert_eq!(Agent::Continue.config_key(), "continue");
        assert_eq!(Agent::CodexCli.config_key(), "codex-cli");
        assert_eq!(Agent::GeminiCli.config_key(), "gemini-cli");
        assert_eq!(Agent::CopilotCli.config_key(), "copilot-cli");
        assert_eq!(Agent::CursorIde.config_key(), "cursor-ide");
        assert_eq!(Agent::Hermes.config_key(), "hermes");
        assert_eq!(Agent::Grok.config_key(), "grok");
        assert_eq!(Agent::Antigravity.config_key(), "antigravity");
        assert_eq!(Agent::Pi.config_key(), "pi");
        assert_eq!(Agent::Unknown.config_key(), "unknown");
        assert_eq!(
            Agent::Custom("my-agent".to_string()).config_key(),
            "my-agent"
        );
    }

    #[test]
    fn test_agent_from_name() {
        // Standard names
        assert_eq!(Agent::from_name("claude-code"), Agent::ClaudeCode);
        assert_eq!(Agent::from_name("augment-code"), Agent::AugmentCode);
        assert_eq!(Agent::from_name("aider"), Agent::Aider);
        assert_eq!(Agent::from_name("continue"), Agent::Continue);
        assert_eq!(Agent::from_name("codex-cli"), Agent::CodexCli);
        assert_eq!(Agent::from_name("gemini-cli"), Agent::GeminiCli);
        assert_eq!(Agent::from_name("unknown"), Agent::Unknown);

        // Variations
        assert_eq!(Agent::from_name("Claude-Code"), Agent::ClaudeCode);
        assert_eq!(Agent::from_name("CLAUDE_CODE"), Agent::ClaudeCode);
        assert_eq!(Agent::from_name("claudecode"), Agent::ClaudeCode);
        assert_eq!(Agent::from_name("augmentcode"), Agent::AugmentCode);
        assert_eq!(Agent::from_name("auggie"), Agent::AugmentCode);
        assert_eq!(Agent::from_name("augment"), Agent::AugmentCode);
        assert_eq!(Agent::from_name("codex"), Agent::CodexCli);
        assert_eq!(Agent::from_name("gemini"), Agent::GeminiCli);
        assert_eq!(Agent::from_name("copilot"), Agent::CopilotCli);
        assert_eq!(Agent::from_name("copilotcli"), Agent::CopilotCli);
        assert_eq!(Agent::from_name("copilot-cli"), Agent::CopilotCli);
        assert_eq!(Agent::from_name("cursor"), Agent::CursorIde);
        assert_eq!(Agent::from_name("cursor-ide"), Agent::CursorIde);
        assert_eq!(Agent::from_name("cursor_ide"), Agent::CursorIde);
        assert_eq!(Agent::from_name("hermes"), Agent::Hermes);
        assert_eq!(Agent::from_name("Hermes"), Agent::Hermes);
        assert_eq!(Agent::from_name("hermes-agent"), Agent::Hermes);
        assert_eq!(Agent::from_name("hermes_cli"), Agent::Hermes);
        assert_eq!(Agent::from_name("grok"), Agent::Grok);
        assert_eq!(Agent::from_name("Grok"), Agent::Grok);
        assert_eq!(Agent::from_name("grok-cli"), Agent::Grok);
        assert_eq!(Agent::from_name("grok_build"), Agent::Grok);
        assert_eq!(Agent::from_name("xai"), Agent::Grok);
        assert_eq!(Agent::from_name("xai-grok"), Agent::Grok);
        assert_eq!(Agent::from_name("agy"), Agent::Antigravity);
        assert_eq!(Agent::from_name("antigravity"), Agent::Antigravity);
        assert_eq!(Agent::from_name("antigravity-cli"), Agent::Antigravity);
        assert_eq!(Agent::from_name("Antigravity"), Agent::Antigravity);
        assert_eq!(Agent::from_name("ANTIGRAVITY_CLI"), Agent::Antigravity);
        assert_eq!(Agent::from_name("pi"), Agent::Pi);
        assert_eq!(Agent::from_name("Pi"), Agent::Pi);
        assert_eq!(Agent::from_name("pi-cli"), Agent::Pi);
        assert_eq!(Agent::from_name("pi_cli"), Agent::Pi);
        assert_eq!(Agent::from_name("PI_CODING_AGENT"), Agent::Pi);

        // Custom agents
        assert_eq!(
            Agent::from_name("my-custom-agent"),
            Agent::Custom("my-custom-agent".to_string())
        );
    }

    #[test]
    fn test_agent_display() {
        assert_eq!(format!("{}", Agent::ClaudeCode), "Claude Code");
        assert_eq!(format!("{}", Agent::AugmentCode), "Augment Code");
        assert_eq!(format!("{}", Agent::Aider), "Aider");
        assert_eq!(format!("{}", Agent::Continue), "Continue");
        assert_eq!(format!("{}", Agent::CodexCli), "Codex CLI");
        assert_eq!(format!("{}", Agent::GeminiCli), "Gemini CLI");
        assert_eq!(format!("{}", Agent::CopilotCli), "GitHub Copilot CLI");
        assert_eq!(format!("{}", Agent::CursorIde), "Cursor IDE");
        assert_eq!(format!("{}", Agent::Hermes), "Hermes Agent");
        assert_eq!(format!("{}", Agent::Grok), "Grok (xAI)");
        assert_eq!(format!("{}", Agent::Antigravity), "Antigravity CLI");
        assert_eq!(format!("{}", Agent::Pi), "Pi");
        assert_eq!(format!("{}", Agent::Unknown), "Unknown");
        assert_eq!(
            format!("{}", Agent::Custom("MyAgent".to_string())),
            "MyAgent"
        );
    }

    #[test]
    fn test_agent_is_known() {
        assert!(Agent::ClaudeCode.is_known());
        assert!(Agent::AugmentCode.is_known());
        assert!(Agent::Aider.is_known());
        assert!(Agent::CopilotCli.is_known());
        assert!(Agent::CursorIde.is_known());
        assert!(Agent::Hermes.is_known());
        assert!(Agent::Grok.is_known());
        assert!(Agent::Antigravity.is_known());
        assert!(Agent::Pi.is_known());
        assert!(!Agent::Unknown.is_known());
        assert!(!Agent::Custom("x".to_string()).is_known());
    }

    #[test]
    fn test_detection_method_display() {
        assert_eq!(
            format!("{}", DetectionMethod::Environment),
            "environment variable"
        );
        assert_eq!(format!("{}", DetectionMethod::Explicit), "explicit flag");
        assert_eq!(format!("{}", DetectionMethod::Process), "parent process");
        assert_eq!(format!("{}", DetectionMethod::None), "not detected");
    }

    #[test]
    fn test_agent_from_process_name_recognizes_known_agents() {
        assert_eq!(agent_from_process_name("claude"), Some(Agent::ClaudeCode));
        assert_eq!(
            agent_from_process_name("/Applications/Claude.app/Contents/MacOS/Claude"),
            Some(Agent::ClaudeCode)
        );
        assert_eq!(agent_from_process_name("auggie"), Some(Agent::AugmentCode));
        assert_eq!(
            agent_from_process_name("augment-code"),
            Some(Agent::AugmentCode)
        );
        assert_eq!(agent_from_process_name("aider"), Some(Agent::Aider));
        assert_eq!(agent_from_process_name("continue"), Some(Agent::Continue));
        assert_eq!(agent_from_process_name("codex"), Some(Agent::CodexCli));
        assert_eq!(
            agent_from_process_name("node /usr/local/bin/codex"),
            Some(Agent::CodexCli)
        );
        assert_eq!(agent_from_process_name("gemini"), Some(Agent::GeminiCli));
        assert_eq!(
            agent_from_process_name("copilot.exe"),
            Some(Agent::CopilotCli)
        );
        assert_eq!(
            agent_from_process_name(r"C:\Users\dev\AppData\Local\Programs\Cursor\Cursor.exe"),
            Some(Agent::CursorIde)
        );
        assert_eq!(
            agent_from_process_name(r"C:\Users\dev\AppData\Roaming\npm\codex.cmd"),
            Some(Agent::CodexCli)
        );
        assert_eq!(
            agent_from_process_name("gemini.ps1"),
            Some(Agent::GeminiCli)
        );
        assert_eq!(agent_from_process_name("hermes"), Some(Agent::Hermes));
        assert_eq!(agent_from_process_name("hermes-agent"), Some(Agent::Hermes));
        assert_eq!(
            agent_from_process_name("/usr/local/bin/hermes"),
            Some(Agent::Hermes)
        );
        assert_eq!(agent_from_process_name("grok"), Some(Agent::Grok));
        assert_eq!(agent_from_process_name("grok-cli"), Some(Agent::Grok));
        assert_eq!(agent_from_process_name("grok-build"), Some(Agent::Grok));
        assert_eq!(
            agent_from_process_name("/home/user/.local/bin/grok"),
            Some(Agent::Grok)
        );
        assert_eq!(agent_from_process_name("agy"), Some(Agent::Antigravity));
        assert_eq!(
            agent_from_process_name("antigravity"),
            Some(Agent::Antigravity)
        );
        assert_eq!(
            agent_from_process_name("antigravity-cli"),
            Some(Agent::Antigravity)
        );
        assert_eq!(
            agent_from_process_name("/home/user/.local/bin/agy"),
            Some(Agent::Antigravity)
        );
        assert_eq!(agent_from_process_name("pi"), Some(Agent::Pi));
        assert_eq!(agent_from_process_name("pi-cli"), Some(Agent::Pi));
        assert_eq!(
            agent_from_process_name("/home/user/.local/bin/pi"),
            Some(Agent::Pi)
        );
    }

    #[test]
    fn test_agent_from_process_name_ignores_unknown_processes() {
        assert_eq!(agent_from_process_name("zsh"), None);
        assert_eq!(agent_from_process_name("cargo test agent"), None);
        assert_eq!(agent_from_process_name("cargo test codex"), None);
        assert_eq!(agent_from_process_name("node"), None);
        assert_eq!(agent_from_process_name("curl https://codex.com"), None);
        assert_eq!(
            agent_from_process_name("curl https://example.com/codex"),
            None
        );
        assert_eq!(agent_from_process_name("git commit -m codex"), None);
    }

    #[test]
    fn test_agent_from_process_name_rejects_substring_false_positives() {
        // Previously these all returned a (wrong) Agent because the
        // implementation matched on substring. They must now return None.
        assert_eq!(agent_from_process_name("claude-explorer"), None);
        assert_eq!(agent_from_process_name("myclaude"), None);
        assert_eq!(agent_from_process_name("anti-claude"), None);
        assert_eq!(agent_from_process_name("aider-helper"), None);
        assert_eq!(agent_from_process_name("myproject-continue"), None);
        assert_eq!(agent_from_process_name("continue-on-error"), None);
        assert_eq!(agent_from_process_name("cursor-ext"), None);
        assert_eq!(agent_from_process_name("xcursor"), None);
        assert_eq!(agent_from_process_name("codex-runner"), None);
        assert_eq!(agent_from_process_name("gemini-tools"), None);
        assert_eq!(agent_from_process_name("copilot-stub"), None);
        assert_eq!(agent_from_process_name("augment-helpers"), None);
        // Greek mythology should not be auto-classified as Hermes Agent.
        assert_eq!(agent_from_process_name("hermes-helper"), None);
        assert_eq!(agent_from_process_name("xhermes"), None);
        assert_eq!(agent_from_process_name("anti-hermes"), None);
        // The word "grok" appears in unrelated tool names; require exact match.
        assert_eq!(agent_from_process_name("grok-helper"), None);
        assert_eq!(agent_from_process_name("xgrok"), None);
        assert_eq!(agent_from_process_name("anti-grok"), None);
        assert_eq!(agent_from_process_name("grokking"), None);
        // "agy" / "antigravity" must be exact; near-misses are not agy.
        assert_eq!(agent_from_process_name("agyx"), None);
        assert_eq!(agent_from_process_name("legacy"), None);
        assert_eq!(agent_from_process_name("antigravity-helper"), None);
        assert_eq!(agent_from_process_name("xantigravity"), None);
        // "pi" is short and must be exact; common near-misses are not Pi.
        assert_eq!(agent_from_process_name("pip"), None);
        assert_eq!(agent_from_process_name("pipx"), None);
        assert_eq!(agent_from_process_name("pip3"), None);
        assert_eq!(agent_from_process_name("xpi"), None);
        assert_eq!(agent_from_process_name("pi-helper"), None);
    }

    #[test]
    fn test_agent_from_process_name_accepts_known_aliases() {
        // Hyphenated and underscored aliases for the same agent.
        assert_eq!(
            agent_from_process_name("claude_code"),
            Some(Agent::ClaudeCode)
        );
        assert_eq!(
            agent_from_process_name("claude-code"),
            Some(Agent::ClaudeCode)
        );
        assert_eq!(agent_from_process_name("codex-cli"), Some(Agent::CodexCli));
        assert_eq!(
            agent_from_process_name("gemini-cli"),
            Some(Agent::GeminiCli)
        );
        assert_eq!(
            agent_from_process_name("gh-copilot"),
            Some(Agent::CopilotCli)
        );
        assert_eq!(
            agent_from_process_name("cursor-ide"),
            Some(Agent::CursorIde)
        );
        assert_eq!(
            agent_from_process_name("continue-cli"),
            Some(Agent::Continue)
        );
    }

    #[test]
    fn test_agent_from_process_name_each_argv_token_checked() {
        // Wrapper invocations: tokenize argv, basename each token, exact match.
        assert_eq!(
            agent_from_process_name("node /usr/local/bin/codex --foo"),
            Some(Agent::CodexCli)
        );
        assert_eq!(
            agent_from_process_name("node ./bin/gemini --foo"),
            Some(Agent::GeminiCli)
        );
        assert_eq!(
            agent_from_process_name(r#"node "C:\Users\dev\AppData\Roaming\npm\codex.cmd""#),
            Some(Agent::CodexCli)
        );
        // First-token wins on ties.
        assert_eq!(
            agent_from_process_name("/opt/codex /opt/cursor"),
            Some(Agent::CodexCli)
        );
    }

    #[test]
    fn test_detection_from_process_name_normalizes_matches() {
        let result = detection_from_process_name("\n  Codex.exe  \n").unwrap();

        assert_eq!(result.agent, Agent::CodexCli);
        assert_eq!(result.method, DetectionMethod::Process);
        assert_eq!(result.matched_value, Some("codex.exe".to_string()));
    }

    #[test]
    fn test_detection_from_process_name_rejects_empty_output() {
        assert_eq!(detection_from_process_name("\n\n  "), None);
    }

    #[test]
    fn test_nul_separated_args_to_string_preserves_wrapped_agent_argv() {
        let args = nul_separated_args_to_string(b"node\0/usr/local/bin/codex\0--foo\0")
            .expect("argv bytes should decode");

        assert_eq!(args, "node /usr/local/bin/codex --foo");
        assert_eq!(agent_from_process_name(&args), Some(Agent::CodexCli));
    }

    #[test]
    fn test_nul_separated_args_to_string_rejects_empty_argv() {
        assert_eq!(nul_separated_args_to_string(b"\0\0"), None);
    }

    #[test]
    fn test_from_explicit() {
        let result = from_explicit("claude-code");
        assert_eq!(result.agent, Agent::ClaudeCode);
        assert_eq!(result.method, DetectionMethod::Explicit);
        assert_eq!(result.matched_value, Some("claude-code".to_string()));
    }

    #[test]
    fn test_explicit_agent_from_args_accepts_separate_value() {
        let agent = explicit_agent_from_args(["dcg", "--agent", "custom-agent", "--version"]);

        assert_eq!(agent, Some("custom-agent".to_string()));
    }

    #[test]
    fn test_explicit_agent_from_args_accepts_equals_value() {
        let agent = explicit_agent_from_args(["dcg", "--agent=codex-cli", "test"]);

        assert_eq!(agent, Some("codex-cli".to_string()));
    }

    #[test]
    fn test_explicit_agent_from_args_ignores_blank_value() {
        let agent = explicit_agent_from_args(["dcg", "--agent", "  "]);

        assert_eq!(agent, None);
    }

    #[test]
    fn test_explicit_agent_from_args_stops_at_double_dash() {
        let agent = explicit_agent_from_args(["dcg", "test", "--", "--agent=payload-agent"]);

        assert_eq!(agent, None);
    }

    #[test]
    fn test_cache_clear() {
        // This test verifies that clear_cache doesn't panic
        clear_cache();
        let _ = detect_agent();
        clear_cache();
    }

    // Note: Environment variable detection tests are in a separate test module
    // that uses temp_env to safely manipulate environment variables.
}

#[cfg(test)]
mod env_tests {
    use super::*;
    use std::sync::Mutex;

    /// Mutex to serialize tests that manipulate environment variables.
    /// This prevents race conditions when tests run in parallel.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// All known agent environment variable keys.
    const AGENT_ENV_VARS: &[&str] = &[
        "CLAUDE_CODE",
        "CLAUDE_SESSION_ID",
        "AUGMENT_AGENT",
        "AUGMENT_CONVERSATION_ID",
        "AIDER_SESSION",
        "CONTINUE_SESSION_ID",
        "CODEX_CLI",
        "GEMINI_CLI",
        "COPILOT_CLI",
        "COPILOT_AGENT_START_TIME_SEC",
        "CURSOR_IDE",
        "HERMES_AGENT",
        "HERMES_SESSION_ID",
        "GROK_SESSION_ID",
        "GROK_HOOK_EVENT",
        "GROK_WORKSPACE_ROOT",
        "ANTIGRAVITY_CONVERSATION_ID",
        "PI_CODING_AGENT",
    ];

    fn with_env_var<F, R>(key: &str, value: &str, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        // Acquire lock to prevent race conditions with parallel tests
        let _lock = ENV_LOCK.lock().unwrap();

        // Clear cache before test
        clear_cache();

        // SAFETY: We hold ENV_LOCK during all tests that modify environment
        // variables, preventing concurrent modifications.

        // Save and clear all agent env vars (to avoid ambient env interference)
        let saved: Vec<_> = AGENT_ENV_VARS
            .iter()
            .map(|&k| (k, std::env::var(k).ok()))
            .collect();

        unsafe {
            for &k in AGENT_ENV_VARS {
                std::env::remove_var(k);
            }
            // Set the test env var
            std::env::set_var(key, value);
        }

        // Run test
        let result = f();

        // SAFETY: See above
        unsafe {
            // Clean up - restore original values
            std::env::remove_var(key);
            for (k, v) in saved {
                if let Some(val) = v {
                    std::env::set_var(k, val);
                }
            }
        }
        clear_cache();

        result
    }

    #[test]
    fn test_detect_claude_code_env() {
        with_env_var("CLAUDE_CODE", "1", || {
            let result = detect_agent_with_details();
            assert_eq!(result.agent, Agent::ClaudeCode);
            assert_eq!(result.method, DetectionMethod::Environment);
            assert_eq!(result.matched_value, Some("CLAUDE_CODE".to_string()));
        });
    }

    #[test]
    fn test_detect_claude_session_id_env() {
        with_env_var("CLAUDE_SESSION_ID", "abc123", || {
            let result = detect_agent_with_details();
            assert_eq!(result.agent, Agent::ClaudeCode);
            assert_eq!(result.method, DetectionMethod::Environment);
            assert_eq!(result.matched_value, Some("CLAUDE_SESSION_ID".to_string()));
        });
    }

    #[test]
    fn test_detect_augment_agent_env() {
        with_env_var("AUGMENT_AGENT", "1", || {
            let result = detect_agent_with_details();
            assert_eq!(result.agent, Agent::AugmentCode);
            assert_eq!(result.method, DetectionMethod::Environment);
            assert_eq!(result.matched_value, Some("AUGMENT_AGENT".to_string()));
        });
    }

    #[test]
    fn test_detect_augment_conversation_id_env() {
        with_env_var("AUGMENT_CONVERSATION_ID", "conv123", || {
            let result = detect_agent_with_details();
            assert_eq!(result.agent, Agent::AugmentCode);
            assert_eq!(result.method, DetectionMethod::Environment);
            assert_eq!(
                result.matched_value,
                Some("AUGMENT_CONVERSATION_ID".to_string())
            );
        });
    }

    #[test]
    fn test_detect_aider_env() {
        with_env_var("AIDER_SESSION", "1", || {
            let result = detect_agent_with_details();
            assert_eq!(result.agent, Agent::Aider);
            assert_eq!(result.method, DetectionMethod::Environment);
        });
    }

    #[test]
    fn test_detect_continue_env() {
        with_env_var("CONTINUE_SESSION_ID", "session123", || {
            let result = detect_agent_with_details();
            assert_eq!(result.agent, Agent::Continue);
            assert_eq!(result.method, DetectionMethod::Environment);
        });
    }

    #[test]
    fn test_detect_codex_cli_env() {
        with_env_var("CODEX_CLI", "1", || {
            let result = detect_agent_with_details();
            assert_eq!(result.agent, Agent::CodexCli);
            assert_eq!(result.method, DetectionMethod::Environment);
        });
    }

    #[test]
    fn test_detect_gemini_cli_env() {
        with_env_var("GEMINI_CLI", "1", || {
            let result = detect_agent_with_details();
            assert_eq!(result.agent, Agent::GeminiCli);
            assert_eq!(result.method, DetectionMethod::Environment);
        });
    }

    #[test]
    fn test_detect_copilot_cli_env() {
        with_env_var("COPILOT_CLI", "1", || {
            let result = detect_agent_with_details();
            assert_eq!(result.agent, Agent::CopilotCli);
            assert_eq!(result.method, DetectionMethod::Environment);
            assert_eq!(result.matched_value, Some("COPILOT_CLI".to_string()));
        });
    }

    #[test]
    fn test_detect_copilot_agent_start_time_env() {
        with_env_var("COPILOT_AGENT_START_TIME_SEC", "1709573241", || {
            let result = detect_agent_with_details();
            assert_eq!(result.agent, Agent::CopilotCli);
            assert_eq!(result.method, DetectionMethod::Environment);
            assert_eq!(
                result.matched_value,
                Some("COPILOT_AGENT_START_TIME_SEC".to_string())
            );
        });
    }

    #[test]
    fn test_detect_cursor_ide_env() {
        with_env_var("CURSOR_IDE", "1", || {
            let result = detect_agent_with_details();
            assert_eq!(result.agent, Agent::CursorIde);
            assert_eq!(result.method, DetectionMethod::Environment);
            assert_eq!(result.matched_value, Some("CURSOR_IDE".to_string()));
        });
    }

    #[test]
    fn test_detect_grok_session_id_env() {
        with_env_var("GROK_SESSION_ID", "sess-abc-123", || {
            let result = detect_agent_with_details();
            assert_eq!(result.agent, Agent::Grok);
            assert_eq!(result.method, DetectionMethod::Environment);
            assert_eq!(result.matched_value, Some("GROK_SESSION_ID".to_string()));
        });
    }

    #[test]
    fn test_detect_grok_hook_event_env() {
        with_env_var("GROK_HOOK_EVENT", "pre_tool_use", || {
            let result = detect_agent_with_details();
            assert_eq!(result.agent, Agent::Grok);
            assert_eq!(result.method, DetectionMethod::Environment);
            assert_eq!(result.matched_value, Some("GROK_HOOK_EVENT".to_string()));
        });
    }

    #[test]
    fn test_detect_grok_workspace_root_env() {
        with_env_var("GROK_WORKSPACE_ROOT", "/work/repo", || {
            let result = detect_agent_with_details();
            assert_eq!(result.agent, Agent::Grok);
            assert_eq!(result.method, DetectionMethod::Environment);
            assert_eq!(
                result.matched_value,
                Some("GROK_WORKSPACE_ROOT".to_string())
            );
        });
    }

    #[test]
    fn test_detect_antigravity_conversation_id_env() {
        with_env_var("ANTIGRAVITY_CONVERSATION_ID", "conv-uuid-123", || {
            let result = detect_agent_with_details();
            assert_eq!(result.agent, Agent::Antigravity);
            assert_eq!(result.method, DetectionMethod::Environment);
            assert_eq!(
                result.matched_value,
                Some("ANTIGRAVITY_CONVERSATION_ID".to_string())
            );
        });
    }

    #[test]
    fn test_detect_pi_coding_agent_env() {
        with_env_var("PI_CODING_AGENT", "true", || {
            let result = detect_agent_with_details();
            assert_eq!(result.agent, Agent::Pi);
            assert_eq!(result.method, DetectionMethod::Environment);
            assert_eq!(result.matched_value, Some("PI_CODING_AGENT".to_string()));
        });
    }

    #[test]
    fn test_detect_pi_coding_agent_env_numeric_flag() {
        // Detection is presence-based, so a `1` value works just like `true`.
        with_env_var("PI_CODING_AGENT", "1", || {
            let result = detect_agent_with_details();
            assert_eq!(result.agent, Agent::Pi);
            assert_eq!(result.method, DetectionMethod::Environment);
            assert_eq!(result.matched_value, Some("PI_CODING_AGENT".to_string()));
        });
    }

    #[test]
    fn test_detect_unknown_no_env() {
        // Acquire lock to prevent race conditions with parallel tests
        let _lock = ENV_LOCK.lock().unwrap();

        let saved: Vec<_> = AGENT_ENV_VARS
            .iter()
            .map(|&k| (k, std::env::var(k).ok()))
            .collect();

        // Ensure no agent env vars are set
        clear_cache();
        // SAFETY: We hold ENV_LOCK during this test, preventing concurrent
        // modifications to environment variables.
        unsafe {
            for &k in AGENT_ENV_VARS {
                std::env::remove_var(k);
            }
        }

        // Detection should fall back to process detection or Unknown
        let result = detect_agent_with_details();
        unsafe {
            for (k, v) in saved {
                if let Some(val) = v {
                    std::env::set_var(k, val);
                }
            }
        }
        clear_cache();

        // On most test runners, we'll get Unknown since they're not running
        // under an AI agent
        assert!(
            result.method == DetectionMethod::None || result.method == DetectionMethod::Process
        );
    }
}

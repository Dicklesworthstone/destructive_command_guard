//! AI coding agent detection for agent-specific profiles.
//!
//! This module detects which AI coding agent is invoking dcg, enabling per-agent
//! trust levels and configuration overrides.
//!
//! # Detection Methods
//!
//! 1. **Environment variables** (primary): Most agents set identifying env vars
//! 2. **Explicit flag**: `--agent=<name>` CLI flag for manual override
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
//! - GitHub Copilot CLI: `COPILOT_CLI=1`, `TERM_PROGRAM=vscode`, or `COPILOT_AGENT_START_TIME_SEC` env var
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
        )
    }

    /// Returns `true` if this agent was explicitly specified (not auto-detected).
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
    /// - `"copilot"`, `"copilot-cli"`, `"copilot_cli"`, -> `CopilotCli`
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
/// 1. Environment variables (checked first as most reliable)
/// 2. Parent process inspection (fallback)
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
    if matches!(std::env::var("COPILOT_CLI").as_deref(), Ok("1")) {
        return Some(DetectionResult::new(
            Agent::CopilotCli,
            DetectionMethod::Environment,
            Some("COPILOT_CLI".to_string()),
        ));
    }
    if matches!(std::env::var("TERM_PROGRAM").as_deref(), Ok("vscode")) {
        return Some(DetectionResult::new(
            Agent::CopilotCli,
            DetectionMethod::Environment,
            Some("TERM_PROGRAM".to_string()),
        ));
    }
    if std::env::var_os("COPILOT_AGENT_START_TIME_SEC").is_some() {
        return Some(DetectionResult::new(
            Agent::CopilotCli,
            DetectionMethod::Environment,
            Some("COPILOT_AGENT_START_TIME_SEC".to_string()),
        ));
    }

    None
}

/// Detect agent from parent process.
///
/// Reads `/proc/<ppid>/comm` on Linux to check the parent process name.
/// This is a fallback for agents that don't set environment variables.
#[cfg(target_os = "linux")]
fn detect_from_parent_process() -> Option<DetectionResult> {
    use std::fs;
    use std::os::unix::process::parent_id;

    let ppid = parent_id();
    let comm_path = format!("/proc/{ppid}/comm");

    let process_name = fs::read_to_string(&comm_path).ok()?.trim().to_lowercase();

    // Match known agent process names
    if process_name.contains("claude") {
        return Some(DetectionResult::new(
            Agent::ClaudeCode,
            DetectionMethod::Process,
            Some(process_name),
        ));
    }
    if process_name.contains("aider") {
        return Some(DetectionResult::new(
            Agent::Aider,
            DetectionMethod::Process,
            Some(process_name),
        ));
    }
    if process_name.contains("codex") {
        return Some(DetectionResult::new(
            Agent::CodexCli,
            DetectionMethod::Process,
            Some(process_name),
        ));
    }
    if process_name.contains("gemini") {
        return Some(DetectionResult::new(
            Agent::GeminiCli,
            DetectionMethod::Process,
            Some(process_name),
        ));
    }

    None
}

/// Detect agent from parent process (non-Linux fallback - returns None).
#[cfg(not(target_os = "linux"))]
fn detect_from_parent_process() -> Option<DetectionResult> {
    // Parent process detection is currently only implemented for Linux.
    // On other platforms, we rely solely on environment variable detection.
    None
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
        assert_eq!(Agent::from_name("copilot-cli"), Agent::CopilotCli);
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
    fn test_from_explicit() {
        let result = from_explicit("claude-code");
        assert_eq!(result.agent, Agent::ClaudeCode);
        assert_eq!(result.method, DetectionMethod::Explicit);
        assert_eq!(result.matched_value, Some("claude-code".to_string()));
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
        "TERM_PROGRAM",
        "COPILOT_AGENT_START_TIME_SEC",
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
    fn test_detect_copilot_in_vscode_env() {
        with_env_var("TERM_PROGRAM", "vscode", || {
            let result = detect_agent_with_details();
            assert_eq!(result.agent, Agent::CopilotCli);
            assert_eq!(result.method, DetectionMethod::Environment);
            assert_eq!(result.matched_value, Some("TERM_PROGRAM".to_string()));
        });
    }

    #[test]
    fn test_detect_copilot_in_github_actions_env() {
        with_env_var("COPILOT_AGENT_START_TIME_SEC", "", || {
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
    fn test_ignore_copilot_cli_when_not_one() {
        with_env_var("COPILOT_CLI", "0", || {
            let result = detect_agent_with_details();
            assert_ne!(result.agent, Agent::CopilotCli);
        });
    }

    #[test]
    fn test_ignore_term_program_when_not_vscode() {
        with_env_var("TERM_PROGRAM", "xterm-256color", || {
            let result = detect_agent_with_details();
            assert_ne!(result.agent, Agent::CopilotCli);
        });
    }

    #[test]
    fn test_detect_unknown_no_env() {
        // Acquire lock to prevent race conditions with parallel tests
        let _lock = ENV_LOCK.lock().unwrap();

        // Ensure no agent env vars are set
        clear_cache();
        // SAFETY: We hold ENV_LOCK during this test, preventing concurrent
        // modifications to environment variables.
        unsafe {
            std::env::remove_var("CLAUDE_CODE");
            std::env::remove_var("CLAUDE_SESSION_ID");
            std::env::remove_var("AIDER_SESSION");
            std::env::remove_var("CONTINUE_SESSION_ID");
            std::env::remove_var("CODEX_CLI");
            std::env::remove_var("GEMINI_CLI");
            std::env::remove_var("COPILOT_CLI");
        }

        // Detection should fall back to process detection or Unknown
        let result = detect_agent_with_details();
        // On most test runners, we'll get Unknown since they're not running
        // under an AI agent
        assert!(
            result.method == DetectionMethod::None || result.method == DetectionMethod::Process
        );
    }
}

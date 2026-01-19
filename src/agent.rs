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
//! - Aider: `AIDER_SESSION=1` env var
//! - Continue: `CONTINUE_SESSION_ID` env var
//! - Codex CLI: `CODEX_CLI=1` env var
//! - Gemini CLI: `GEMINI_CLI=1` env var
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
    /// Aider AI coding assistant.
    Aider,
    /// Continue.dev IDE extension.
    Continue,
    /// `OpenAI` Codex CLI.
    CodexCli,
    /// Google Gemini CLI.
    GeminiCli,
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
            Self::Aider => "aider",
            Self::Continue => "continue",
            Self::CodexCli => "codex-cli",
            Self::GeminiCli => "gemini-cli",
            Self::Custom(name) => name,
            Self::Unknown => "unknown",
        }
    }

    /// Returns `true` if this is a known agent (not Unknown or Custom).
    #[must_use]
    pub const fn is_known(&self) -> bool {
        matches!(
            self,
            Self::ClaudeCode | Self::Aider | Self::Continue | Self::CodexCli | Self::GeminiCli
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
    /// - `"aider"` -> `Aider`
    /// - `"continue"` -> `Continue`
    /// - `"codex"`, `"codex-cli"`, `"codex_cli"` -> `CodexCli`
    /// - `"gemini"`, `"gemini-cli"`, `"gemini_cli"` -> `GeminiCli`
    /// - `"unknown"` -> `Unknown`
    /// - Any other value -> `Custom(value)`
    #[must_use]
    pub fn from_name(name: &str) -> Self {
        let normalized = name.to_lowercase().replace(['-', '_'], "");
        match normalized.as_str() {
            "claudecode" => Self::ClaudeCode,
            "aider" => Self::Aider,
            "continue" => Self::Continue,
            "codexcli" | "codex" => Self::CodexCli,
            "geminicli" | "gemini" => Self::GeminiCli,
            "unknown" => Self::Unknown,
            _ => Self::Custom(name.to_string()),
        }
    }
}

impl fmt::Display for Agent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClaudeCode => write!(f, "Claude Code"),
            Self::Aider => write!(f, "Aider"),
            Self::Continue => write!(f, "Continue"),
            Self::CodexCli => write!(f, "Codex CLI"),
            Self::GeminiCli => write!(f, "Gemini CLI"),
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
        assert_eq!(Agent::Aider.config_key(), "aider");
        assert_eq!(Agent::Continue.config_key(), "continue");
        assert_eq!(Agent::CodexCli.config_key(), "codex-cli");
        assert_eq!(Agent::GeminiCli.config_key(), "gemini-cli");
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
        assert_eq!(Agent::from_name("aider"), Agent::Aider);
        assert_eq!(Agent::from_name("continue"), Agent::Continue);
        assert_eq!(Agent::from_name("codex-cli"), Agent::CodexCli);
        assert_eq!(Agent::from_name("gemini-cli"), Agent::GeminiCli);
        assert_eq!(Agent::from_name("unknown"), Agent::Unknown);

        // Variations
        assert_eq!(Agent::from_name("Claude-Code"), Agent::ClaudeCode);
        assert_eq!(Agent::from_name("CLAUDE_CODE"), Agent::ClaudeCode);
        assert_eq!(Agent::from_name("claudecode"), Agent::ClaudeCode);
        assert_eq!(Agent::from_name("codex"), Agent::CodexCli);
        assert_eq!(Agent::from_name("gemini"), Agent::GeminiCli);

        // Custom agents
        assert_eq!(
            Agent::from_name("my-custom-agent"),
            Agent::Custom("my-custom-agent".to_string())
        );
    }

    #[test]
    fn test_agent_display() {
        assert_eq!(format!("{}", Agent::ClaudeCode), "Claude Code");
        assert_eq!(format!("{}", Agent::Aider), "Aider");
        assert_eq!(format!("{}", Agent::Continue), "Continue");
        assert_eq!(format!("{}", Agent::CodexCli), "Codex CLI");
        assert_eq!(format!("{}", Agent::GeminiCli), "Gemini CLI");
        assert_eq!(format!("{}", Agent::Unknown), "Unknown");
        assert_eq!(
            format!("{}", Agent::Custom("MyAgent".to_string())),
            "MyAgent"
        );
    }

    #[test]
    fn test_agent_is_known() {
        assert!(Agent::ClaudeCode.is_known());
        assert!(Agent::Aider.is_known());
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

    // SAFETY: These tests manipulate environment variables. They must be run
    // with --test-threads=1 or use proper synchronization.

    /// All known agent environment variable keys.
    const AGENT_ENV_VARS: &[&str] = &[
        "CLAUDE_CODE",
        "CLAUDE_SESSION_ID",
        "AIDER_SESSION",
        "CONTINUE_SESSION_ID",
        "CODEX_CLI",
        "GEMINI_CLI",
    ];

    fn with_env_var<F, R>(key: &str, value: &str, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        // Clear cache before test
        clear_cache();

        // SAFETY: Tests are run single-threaded with `--test-threads=1` or with
        // `serial_test` crate. No other code is reading these environment
        // variables concurrently within this test.

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
    fn test_detect_unknown_no_env() {
        // Ensure no agent env vars are set
        clear_cache();
        // SAFETY: This test is run single-threaded and no other code is reading
        // these environment variables concurrently within this test.
        unsafe {
            std::env::remove_var("CLAUDE_CODE");
            std::env::remove_var("CLAUDE_SESSION_ID");
            std::env::remove_var("AIDER_SESSION");
            std::env::remove_var("CONTINUE_SESSION_ID");
            std::env::remove_var("CODEX_CLI");
            std::env::remove_var("GEMINI_CLI");
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

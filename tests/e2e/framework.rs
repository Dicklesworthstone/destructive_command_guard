//! E2E Test Framework Core
//!
//! Provides the `E2ETestContext` struct for managing isolated test environments
//! and running DCG commands with detailed output capture.

#![allow(dead_code)]

use serde_json::Value;
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// Result of a DCG command execution.
#[derive(Debug, Clone)]
pub struct DcgOutput {
    /// Standard output from the command.
    pub stdout: String,
    /// Standard error from the command.
    pub stderr: String,
    /// Exit code (0 = success).
    pub exit_code: i32,
    /// Time taken to execute the command.
    pub duration: Duration,
    /// Parsed JSON output (if stdout contains valid JSON).
    pub json: Option<Value>,
}

impl DcgOutput {
    /// Check if the command was blocked (denied).
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        self.json
            .as_ref()
            .and_then(|j| j.get("hookSpecificOutput"))
            .and_then(|h| h.get("permissionDecision"))
            .and_then(Value::as_str)
            .is_some_and(|d| d == "deny")
    }

    /// Check if the command was allowed (empty stdout or explicit allow).
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        self.stdout.trim().is_empty() || {
            self.json
                .as_ref()
                .and_then(|j| j.get("hookSpecificOutput"))
                .and_then(|h| h.get("permissionDecision"))
                .and_then(Value::as_str)
                .is_some_and(|d| d == "allow")
        }
    }

    /// Check if the output contains a specific rule ID.
    #[must_use]
    pub fn contains_rule_id(&self, rule_id: &str) -> bool {
        self.json
            .as_ref()
            .and_then(|j| j.get("hookSpecificOutput"))
            .and_then(|h| h.get("ruleId"))
            .and_then(Value::as_str)
            .is_some_and(|r| r == rule_id)
    }

    /// Get the rule ID from the output.
    #[must_use]
    pub fn rule_id(&self) -> Option<&str> {
        self.json
            .as_ref()
            .and_then(|j| j.get("hookSpecificOutput"))
            .and_then(|h| h.get("ruleId"))
            .and_then(Value::as_str)
    }

    /// Get the pack ID from the output.
    #[must_use]
    pub fn pack_id(&self) -> Option<&str> {
        self.json
            .as_ref()
            .and_then(|j| j.get("hookSpecificOutput"))
            .and_then(|h| h.get("packId"))
            .and_then(Value::as_str)
    }

    /// Get the severity level from the output.
    #[must_use]
    pub fn severity(&self) -> Option<&str> {
        self.json
            .as_ref()
            .and_then(|j| j.get("hookSpecificOutput"))
            .and_then(|h| h.get("severity"))
            .and_then(Value::as_str)
    }

    /// Get the decision reason from the output.
    #[must_use]
    pub fn decision_reason(&self) -> Option<&str> {
        self.json
            .as_ref()
            .and_then(|j| j.get("hookSpecificOutput"))
            .and_then(|h| h.get("permissionDecisionReason"))
            .and_then(Value::as_str)
    }

    /// Get the allow-once code if present.
    #[must_use]
    pub fn allow_once_code(&self) -> Option<&str> {
        self.json
            .as_ref()
            .and_then(|j| j.get("hookSpecificOutput"))
            .and_then(|h| h.get("allowOnceCode"))
            .and_then(Value::as_str)
    }

    /// Get the safe alternative suggestion if present.
    #[must_use]
    pub fn safe_alternative(&self) -> Option<&str> {
        self.json
            .as_ref()
            .and_then(|j| j.get("hookSpecificOutput"))
            .and_then(|h| h.get("remediation"))
            .and_then(|r| r.get("safeAlternative"))
            .and_then(Value::as_str)
    }

    /// Check if stderr contains a warning.
    #[must_use]
    pub fn has_warning(&self) -> bool {
        self.stderr.contains("WARNING") || self.stderr.contains("dcg WARNING")
    }
}

/// Result of a test execution.
#[derive(Debug, Clone)]
pub enum TestResult {
    /// Test passed.
    Pass,
    /// Test failed with a reason.
    Fail(String),
    /// Test was skipped with a reason.
    Skip(String),
}

impl TestResult {
    #[must_use]
    pub fn is_pass(&self) -> bool {
        matches!(self, TestResult::Pass)
    }

    #[must_use]
    pub fn is_fail(&self) -> bool {
        matches!(self, TestResult::Fail(_))
    }
}

/// Builder for E2ETestContext.
pub struct E2ETestContextBuilder {
    test_name: String,
    config_content: Option<String>,
    config_name: Option<String>,
    git_branch: Option<String>,
    agent_type: Option<String>,
    env_vars: HashMap<String, String>,
    packs: Option<String>,
    allowlist_content: Option<String>,
}

impl E2ETestContextBuilder {
    /// Create a new builder with the given test name.
    #[must_use]
    pub fn new(test_name: &str) -> Self {
        Self {
            test_name: test_name.to_string(),
            config_content: None,
            config_name: None,
            git_branch: None,
            agent_type: None,
            env_vars: HashMap::new(),
            packs: None,
            allowlist_content: None,
        }
    }

    /// Set a pre-defined config by name (e.g., "minimal", "full_featured").
    #[must_use]
    pub fn with_config(mut self, config_name: &str) -> Self {
        self.config_name = Some(config_name.to_string());
        self
    }

    /// Set custom config content.
    #[must_use]
    pub fn with_config_content(mut self, content: &str) -> Self {
        self.config_content = Some(content.to_string());
        self
    }

    /// Initialize a git repo with the given branch.
    #[must_use]
    pub fn with_git_repo(mut self, branch: &str) -> Self {
        self.git_branch = Some(branch.to_string());
        self
    }

    /// Set the agent type for the test.
    #[must_use]
    pub fn with_agent(mut self, agent: &str) -> Self {
        self.agent_type = Some(agent.to_string());
        self
    }

    /// Add an environment variable.
    #[must_use]
    pub fn with_env(mut self, key: &str, value: &str) -> Self {
        self.env_vars.insert(key.to_string(), value.to_string());
        self
    }

    /// Set enabled packs (comma-separated).
    #[must_use]
    pub fn with_packs(mut self, packs: &str) -> Self {
        self.packs = Some(packs.to_string());
        self
    }

    /// Set allowlist content.
    #[must_use]
    pub fn with_allowlist(mut self, content: &str) -> Self {
        self.allowlist_content = Some(content.to_string());
        self
    }

    /// Build the E2ETestContext.
    #[must_use]
    pub fn build(self) -> E2ETestContext {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let temp_path = temp_dir.path().to_path_buf();

        // Create .dcg directory
        let dcg_dir = temp_path.join(".dcg");
        std::fs::create_dir_all(&dcg_dir).expect("Failed to create .dcg directory");

        // Set up config file
        let config_path = dcg_dir.join("config.toml");
        if let Some(content) = &self.config_content {
            std::fs::write(&config_path, content).expect("Failed to write config");
        } else if let Some(name) = &self.config_name {
            let content = get_fixture_config(name);
            std::fs::write(&config_path, content).expect("Failed to write config");
        }

        // Set up allowlist if provided
        if let Some(content) = &self.allowlist_content {
            let allowlist_path = dcg_dir.join("allowlist.toml");
            std::fs::write(&allowlist_path, content).expect("Failed to write allowlist");
        }

        // Initialize git repo if requested
        if let Some(branch) = &self.git_branch {
            init_git_repo(&temp_path, branch);
        }

        // Create hermetic home and config directories
        let test_home = temp_path.join("home");
        let test_xdg_config = temp_path.join("xdg_config");
        std::fs::create_dir_all(&test_home).expect("Failed to create test home");
        std::fs::create_dir_all(&test_xdg_config).expect("Failed to create test xdg config");

        // Set up environment variables
        let mut env_vars = self.env_vars;
        env_vars.insert("HOME".to_string(), test_home.to_string_lossy().to_string());
        env_vars.insert(
            "XDG_CONFIG_HOME".to_string(),
            test_xdg_config.to_string_lossy().to_string(),
        );
        env_vars.insert("DCG_ALLOWLIST_SYSTEM_PATH".to_string(), String::new());

        if let Some(packs) = &self.packs {
            env_vars.insert("DCG_PACKS".to_string(), packs.clone());
        }

        if let Some(agent) = &self.agent_type {
            env_vars.insert("DCG_AGENT_TYPE".to_string(), agent.clone());
        }

        // Find the DCG binary
        let binary_path = find_dcg_binary();

        // Create log directory
        let log_dir = temp_path.join("logs");
        std::fs::create_dir_all(&log_dir).expect("Failed to create log directory");

        E2ETestContext {
            test_name: self.test_name,
            temp_dir,
            config_path: if config_path.exists() {
                Some(config_path)
            } else {
                None
            },
            env_vars,
            binary_path,
            log_dir,
        }
    }
}

/// Isolated test environment for E2E tests.
pub struct E2ETestContext {
    test_name: String,
    temp_dir: TempDir,
    config_path: Option<PathBuf>,
    env_vars: HashMap<String, String>,
    binary_path: PathBuf,
    log_dir: PathBuf,
}

impl E2ETestContext {
    /// Create a new builder for the test context.
    #[must_use]
    pub fn builder(test_name: &str) -> E2ETestContextBuilder {
        E2ETestContextBuilder::new(test_name)
    }

    /// Get the test name.
    #[must_use]
    pub fn test_name(&self) -> &str {
        &self.test_name
    }

    /// Get the temp directory path.
    #[must_use]
    pub fn temp_dir(&self) -> &Path {
        self.temp_dir.path()
    }

    /// Get the config path if set.
    #[must_use]
    pub fn config_path(&self) -> Option<&Path> {
        self.config_path.as_deref()
    }

    /// Get the log directory path.
    #[must_use]
    pub fn log_dir(&self) -> &Path {
        &self.log_dir
    }

    /// Run DCG in hook mode with a command.
    ///
    /// This simulates the Claude Code hook protocol by sending JSON input to stdin.
    #[must_use]
    pub fn run_dcg_hook(&self, command: &str) -> DcgOutput {
        let json_input = format!(
            r#"{{"tool_name":"Bash","tool_input":{{"command":"{}"}}}}"#,
            escape_json_string(command)
        );

        self.run_dcg_with_stdin(&json_input, &[])
    }

    /// Run DCG with custom arguments.
    #[must_use]
    pub fn run_dcg(&self, args: &[&str]) -> DcgOutput {
        self.run_dcg_with_stdin("", args)
    }

    /// Run DCG with stdin input and arguments.
    #[must_use]
    pub fn run_dcg_with_stdin(&self, stdin: &str, args: &[&str]) -> DcgOutput {
        let start = Instant::now();

        let mut cmd = Command::new(&self.binary_path);
        cmd.args(args)
            .current_dir(self.temp_dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear();

        // Apply environment variables
        for (key, value) in &self.env_vars {
            cmd.env(key, value);
        }

        // Essential env vars
        cmd.env("PATH", std::env::var("PATH").unwrap_or_default());

        let mut child = cmd.spawn().expect("Failed to spawn DCG process");

        // Write stdin if provided
        if !stdin.is_empty() {
            if let Some(ref mut stdin_handle) = child.stdin {
                stdin_handle
                    .write_all(stdin.as_bytes())
                    .expect("Failed to write to stdin");
            }
        }

        let output = child.wait_with_output().expect("Failed to wait for DCG");
        let duration = start.elapsed();

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let exit_code = output.status.code().unwrap_or(-1);

        // Try to parse JSON from stdout
        let json = serde_json::from_str(&stdout).ok();

        DcgOutput {
            stdout,
            stderr,
            exit_code,
            duration,
            json,
        }
    }

    /// Assert that a command is blocked.
    pub fn assert_blocked(&self, output: &DcgOutput) {
        assert!(
            output.is_blocked(),
            "Expected command to be blocked, but it was allowed.\nstdout: {}\nstderr: {}",
            output.stdout,
            output.stderr
        );
    }

    /// Assert that a command is allowed.
    pub fn assert_allowed(&self, output: &DcgOutput) {
        assert!(
            output.is_allowed(),
            "Expected command to be allowed, but it was blocked.\nstdout: {}\nstderr: {}",
            output.stdout,
            output.stderr
        );
    }

    /// Assert that a command is blocked by a specific rule.
    pub fn assert_blocked_by_rule(&self, output: &DcgOutput, rule_id: &str) {
        self.assert_blocked(output);
        assert!(
            output.contains_rule_id(rule_id),
            "Expected command to be blocked by rule '{}', but got rule '{:?}'",
            rule_id,
            output.rule_id()
        );
    }

    /// Add an environment variable.
    pub fn set_env(&mut self, key: &str, value: &str) {
        self.env_vars.insert(key.to_string(), value.to_string());
    }

    /// Write a file to the temp directory.
    pub fn write_file(&self, relative_path: &str, content: &str) {
        let path = self.temp_dir.path().join(relative_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("Failed to create parent directories");
        }
        std::fs::write(&path, content).expect("Failed to write file");
    }

    /// Create a directory in the temp directory.
    pub fn create_dir(&self, relative_path: &str) {
        let path = self.temp_dir.path().join(relative_path);
        std::fs::create_dir_all(&path).expect("Failed to create directory");
    }
}

/// Find the DCG binary, preferring local build artifacts.
fn find_dcg_binary() -> PathBuf {
    // Check for local build artifacts first
    let release_path = PathBuf::from("./target/release/dcg");
    if release_path.exists() {
        return std::fs::canonicalize(&release_path).unwrap_or(release_path);
    }

    let debug_path = PathBuf::from("./target/debug/dcg");
    if debug_path.exists() {
        return std::fs::canonicalize(&debug_path).unwrap_or(debug_path);
    }

    // Fall back to PATH
    which::which("dcg").unwrap_or_else(|_| PathBuf::from("dcg"))
}

/// Initialize a git repository in the given directory.
fn init_git_repo(path: &Path, branch: &str) {
    Command::new("git")
        .args(["init", "-q"])
        .current_dir(path)
        .output()
        .expect("Failed to init git repo");

    Command::new("git")
        .args(["config", "user.email", "test@example.com"])
        .current_dir(path)
        .output()
        .expect("Failed to set git email");

    Command::new("git")
        .args(["config", "user.name", "Test User"])
        .current_dir(path)
        .output()
        .expect("Failed to set git name");

    // Create initial commit
    Command::new("git")
        .args(["commit", "--allow-empty", "-m", "Initial commit"])
        .current_dir(path)
        .output()
        .expect("Failed to create initial commit");

    // Switch to requested branch if not main/master
    if branch != "main" && branch != "master" {
        Command::new("git")
            .args(["checkout", "-b", branch])
            .current_dir(path)
            .output()
            .expect("Failed to switch branch");
    }
}

/// Get a fixture config by name.
fn get_fixture_config(name: &str) -> String {
    match name {
        "minimal" => MINIMAL_CONFIG.to_string(),
        "full_featured" => FULL_FEATURED_CONFIG.to_string(),
        "path_specific" => PATH_SPECIFIC_CONFIG.to_string(),
        "temporary_rules" => TEMPORARY_RULES_CONFIG.to_string(),
        "agent_profiles" => AGENT_PROFILES_CONFIG.to_string(),
        "git_awareness" => GIT_AWARENESS_CONFIG.to_string(),
        "graduated_response" => GRADUATED_RESPONSE_CONFIG.to_string(),
        _ => panic!("Unknown config fixture: {}", name),
    }
}

/// Escape a string for JSON embedding.
fn escape_json_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

// ============================================================================
// Fixture Configs
// ============================================================================

/// Minimal configuration - bare minimum for DCG to function.
const MINIMAL_CONFIG: &str = r#"# Minimal DCG Configuration
# Only core packs enabled, default settings

[packs]
enabled = ["core.git", "core.filesystem"]
"#;

/// Full-featured configuration - all features enabled for comprehensive testing.
const FULL_FEATURED_CONFIG: &str = r#"# Full-Featured DCG Configuration
# All features enabled for comprehensive testing

[packs]
enabled = [
    "core.git",
    "core.filesystem",
    "containers.docker",
    "kubernetes.kubectl",
    "database.postgresql",
    "database.redis",
    "infrastructure.terraform",
]

[policy]
default_mode = "deny"
enable_explanations = true
enable_suggestions = true
enable_history = true

[history]
enabled = true
max_entries = 10000
redact_secrets = true

[telemetry]
enabled = true
"#;

/// Path-specific configuration - path-aware allowlisting.
const PATH_SPECIFIC_CONFIG: &str = r#"# Path-Specific DCG Configuration
# For testing context-aware allowlisting (Epic 5)

[packs]
enabled = ["core.git", "core.filesystem"]

[allowlist]
# Allow rm -rf in build directories
[[allowlist.paths]]
pattern = "**/build/**"
rules = ["core.filesystem:rm-recursive-force"]
reason = "Build directories can be cleaned"

[[allowlist.paths]]
pattern = "**/node_modules/**"
rules = ["core.filesystem:rm-recursive-force"]
reason = "Node modules can be removed for reinstall"
"#;

/// Temporary rules configuration - for TTL-based allowlist entries (Epic 6).
const TEMPORARY_RULES_CONFIG: &str = r#"# Temporary Rules DCG Configuration
# For testing expiring allowlist entries (Epic 6)

[packs]
enabled = ["core.git", "core.filesystem"]

[temporary]
default_ttl_hours = 24
max_ttl_hours = 168
session_scope = true
"#;

/// Agent profiles configuration - per-agent settings (Epic 9).
const AGENT_PROFILES_CONFIG: &str = r#"# Agent Profiles DCG Configuration
# For testing agent-specific settings (Epic 9)

[packs]
enabled = ["core.git", "core.filesystem"]

[agents.claude_code]
strictness = "high"
enabled_packs = ["core.git", "core.filesystem", "containers.docker"]

[agents.codex]
strictness = "medium"
enabled_packs = ["core.git"]

[agents.cursor]
strictness = "low"
enabled_packs = ["core.git"]
"#;

/// Git awareness configuration - branch-specific settings (Epic 8).
const GIT_AWARENESS_CONFIG: &str = r#"# Git Awareness DCG Configuration
# For testing branch-aware strictness (Epic 8)

[packs]
enabled = ["core.git", "core.filesystem"]

[git]
enable_branch_awareness = true
protected_branches = ["main", "master", "production", "release/*"]

[git.branch_rules.main]
strictness = "critical"
block_force_push = true

[git.branch_rules.feature]
strictness = "low"
allow_force_push = true
"#;

/// Graduated response configuration - response graduation (Epic 10).
const GRADUATED_RESPONSE_CONFIG: &str = r#"# Graduated Response DCG Configuration
# For testing response graduation system (Epic 10)

[packs]
enabled = ["core.git", "core.filesystem"]

[response]
enable_graduation = true
initial_mode = "warn"
escalation_threshold = 3
escalation_window_hours = 24
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_builder_creates_temp_dir() {
        let ctx = E2ETestContext::builder("builder_test").build();
        assert!(ctx.temp_dir().exists());
    }

    #[test]
    fn test_context_with_config() {
        let ctx = E2ETestContext::builder("config_test")
            .with_config("minimal")
            .build();
        assert!(ctx.config_path().is_some());
        assert!(ctx.config_path().unwrap().exists());
    }

    #[test]
    fn test_context_with_git_repo() {
        let ctx = E2ETestContext::builder("git_test")
            .with_git_repo("main")
            .build();
        assert!(ctx.temp_dir().join(".git").exists());
    }

    #[test]
    fn test_context_with_env() {
        let ctx = E2ETestContext::builder("env_test")
            .with_env("TEST_VAR", "test_value")
            .build();
        assert!(ctx.env_vars.contains_key("TEST_VAR"));
    }

    #[test]
    fn test_dcg_output_parsing() {
        let json_str = r#"{"hookSpecificOutput":{"permissionDecision":"deny","ruleId":"core.git:reset-hard","packId":"core.git","severity":"critical"}}"#;
        let json: Value = serde_json::from_str(json_str).unwrap();

        let output = DcgOutput {
            stdout: json_str.to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration: Duration::from_millis(10),
            json: Some(json),
        };

        assert!(output.is_blocked());
        assert!(!output.is_allowed());
        assert!(output.contains_rule_id("core.git:reset-hard"));
        assert_eq!(output.pack_id(), Some("core.git"));
        assert_eq!(output.severity(), Some("critical"));
    }

    #[test]
    fn test_allowed_output() {
        let output = DcgOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
            duration: Duration::from_millis(5),
            json: None,
        };

        assert!(output.is_allowed());
        assert!(!output.is_blocked());
    }

    #[test]
    fn test_json_escape() {
        assert_eq!(escape_json_string("hello"), "hello");
        assert_eq!(escape_json_string("hello\"world"), "hello\\\"world");
        assert_eq!(escape_json_string("line\nbreak"), "line\\nbreak");
    }

    #[test]
    fn test_fixture_configs_valid() {
        // Ensure all fixture configs are valid TOML
        toml::from_str::<toml::Value>(MINIMAL_CONFIG).expect("minimal config invalid");
        toml::from_str::<toml::Value>(FULL_FEATURED_CONFIG).expect("full_featured config invalid");
        toml::from_str::<toml::Value>(PATH_SPECIFIC_CONFIG).expect("path_specific config invalid");
        toml::from_str::<toml::Value>(TEMPORARY_RULES_CONFIG)
            .expect("temporary_rules config invalid");
        toml::from_str::<toml::Value>(AGENT_PROFILES_CONFIG)
            .expect("agent_profiles config invalid");
        toml::from_str::<toml::Value>(GIT_AWARENESS_CONFIG).expect("git_awareness config invalid");
        toml::from_str::<toml::Value>(GRADUATED_RESPONSE_CONFIG)
            .expect("graduated_response config invalid");
    }
}

//! E2E tests for config toggles (highlighting and explanations).
//!
//! These tests verify that:
//! - highlight_enabled toggle affects output without changing decisions
//! - explanations_enabled toggle affects output without changing decisions
//! - Toggle combinations work correctly together
//! - All toggle states result in consistent allow/deny decisions
//!
//! # Running
//!
//! ```bash
//! cargo test --test config_toggles_e2e -- --nocapture
//! ```

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Path to the dcg binary (built in debug mode for tests).
fn dcg_binary() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // Remove test binary name
    path.pop(); // Remove deps/
    path.push("dcg");
    path
}

/// Test environment with isolated config.
struct TestEnv {
    temp_dir: tempfile::TempDir,
    home_dir: PathBuf,
    xdg_config_dir: PathBuf,
    config_path: PathBuf,
}

impl TestEnv {
    /// Create a new empty test environment.
    fn new() -> Self {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let home_dir = temp_dir.path().join("home");
        let xdg_config_dir = temp_dir.path().join("xdg_config");
        let dcg_dir = xdg_config_dir.join("dcg");

        fs::create_dir_all(&home_dir).expect("failed to create HOME dir");
        fs::create_dir_all(&dcg_dir).expect("failed to create XDG_CONFIG_HOME/dcg dir");

        // Create a git repo in the temp dir so project detection works
        fs::create_dir_all(temp_dir.path().join(".git")).expect("failed to create .git dir");

        let config_path = dcg_dir.join("config.toml");

        Self {
            temp_dir,
            home_dir,
            xdg_config_dir,
            config_path,
        }
    }

    /// Create a config file with specific toggle settings.
    fn with_toggles(self, highlight_enabled: Option<bool>, explanations_enabled: Option<bool>) -> Self {
        let mut config_content = String::from("[output]\n");

        if let Some(h) = highlight_enabled {
            config_content.push_str(&format!("highlight_enabled = {}\n", h));
        }
        if let Some(e) = explanations_enabled {
            config_content.push_str(&format!("explanations_enabled = {}\n", e));
        }

        fs::write(&self.config_path, config_content).expect("Failed to write config");
        self
    }

    /// Run dcg in hook mode with the given command.
    fn run_hook(&self, command: &str) -> HookOutput {
        let input = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {
                "command": command,
            }
        });

        let mut cmd = Command::new(dcg_binary());
        cmd.env_clear()
            .env("HOME", &self.home_dir)
            .env("XDG_CONFIG_HOME", &self.xdg_config_dir)
            .env("DCG_CONFIG", &self.config_path)
            .env("DCG_PACKS", "core.git,core.filesystem")
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .current_dir(self.temp_dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().expect("failed to spawn dcg");

        {
            let stdin = child.stdin.as_mut().expect("failed to open stdin");
            serde_json::to_writer(stdin, &input).expect("failed to write hook input JSON");
        }

        let output = child.wait_with_output().expect("failed to wait for dcg");

        HookOutput {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code().unwrap_or(-1),
        }
    }

    /// Run dcg test command (non-hook mode).
    fn run_test_command(&self, command: &str) -> HookOutput {
        let mut cmd = Command::new(dcg_binary());
        cmd.env_clear()
            .env("HOME", &self.home_dir)
            .env("XDG_CONFIG_HOME", &self.xdg_config_dir)
            .env("DCG_CONFIG", &self.config_path)
            .env("DCG_PACKS", "core.git,core.filesystem")
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .current_dir(self.temp_dir.path())
            .args(["test", command])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let output = cmd.output().expect("failed to execute dcg test");

        HookOutput {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code().unwrap_or(-1),
        }
    }
}

/// Output from running dcg.
struct HookOutput {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

impl HookOutput {
    /// Check if the decision was "deny".
    fn is_denied(&self) -> bool {
        // In hook mode, stdout contains JSON with "permissionDecision": "deny"
        self.stdout.contains("\"deny\"") || self.stdout.contains("\"permissionDecision\":\"deny\"")
    }

    /// Check if the decision was "allow".
    fn is_allowed(&self) -> bool {
        // In hook mode, stdout contains JSON with "permissionDecision": "allow"
        // or the hook passes through without output (implicit allow)
        self.stdout.is_empty() || self.stdout.contains("\"allow\"")
    }

    /// Print verbose diagnostics.
    fn print_verbose(&self, label: &str) {
        eprintln!("╔════════════════════════════════════════════════════════════════════╗");
        eprintln!("║ {} ", label);
        eprintln!("╠════════════════════════════════════════════════════════════════════╣");
        eprintln!("║ Exit Code: {}", self.exit_code);
        eprintln!("║ Stdout Length: {} bytes", self.stdout.len());
        eprintln!("║ Stderr Length: {} bytes", self.stderr.len());
        eprintln!("╠════════════════════════════════════════════════════════════════════╣");
        eprintln!("║ STDOUT:");
        for line in self.stdout.lines().take(30) {
            eprintln!("║   {}", line);
        }
        if self.stdout.lines().count() > 30 {
            eprintln!("║   ... (truncated)");
        }
        eprintln!("╠════════════════════════════════════════════════════════════════════╣");
        eprintln!("║ STDERR:");
        for line in self.stderr.lines().take(20) {
            eprintln!("║   {}", line);
        }
        eprintln!("╚════════════════════════════════════════════════════════════════════╝");
    }
}

// =============================================================================
// Destructive Command Tests - Verify toggles don't affect deny decisions
// =============================================================================

#[test]
fn test_toggle_highlight_enabled_does_not_affect_deny_decision() {
    eprintln!("=== Testing highlight_enabled toggle doesn't affect deny decision ===");

    let destructive_command = "git reset --hard HEAD";

    // Test with highlighting enabled
    let env_enabled = TestEnv::new().with_toggles(Some(true), None);
    let output_enabled = env_enabled.run_hook(destructive_command);
    output_enabled.print_verbose("highlight_enabled=true");

    // Test with highlighting disabled
    let env_disabled = TestEnv::new().with_toggles(Some(false), None);
    let output_disabled = env_disabled.run_hook(destructive_command);
    output_disabled.print_verbose("highlight_enabled=false");

    // Both should result in deny
    assert!(
        output_enabled.is_denied(),
        "Command should be denied with highlight_enabled=true"
    );
    assert!(
        output_disabled.is_denied(),
        "Command should be denied with highlight_enabled=false"
    );

    eprintln!("=== highlight_enabled toggle test PASSED ===");
}

#[test]
fn test_toggle_explanations_enabled_does_not_affect_deny_decision() {
    eprintln!("=== Testing explanations_enabled toggle doesn't affect deny decision ===");

    let destructive_command = "git reset --hard HEAD";

    // Test with explanations enabled
    let env_enabled = TestEnv::new().with_toggles(None, Some(true));
    let output_enabled = env_enabled.run_hook(destructive_command);
    output_enabled.print_verbose("explanations_enabled=true");

    // Test with explanations disabled
    let env_disabled = TestEnv::new().with_toggles(None, Some(false));
    let output_disabled = env_disabled.run_hook(destructive_command);
    output_disabled.print_verbose("explanations_enabled=false");

    // Both should result in deny
    assert!(
        output_enabled.is_denied(),
        "Command should be denied with explanations_enabled=true"
    );
    assert!(
        output_disabled.is_denied(),
        "Command should be denied with explanations_enabled=false"
    );

    eprintln!("=== explanations_enabled toggle test PASSED ===");
}

#[test]
fn test_both_toggles_disabled_does_not_affect_deny_decision() {
    eprintln!("=== Testing both toggles disabled doesn't affect deny decision ===");

    let destructive_command = "git reset --hard HEAD";

    // Test with both toggles disabled
    let env = TestEnv::new().with_toggles(Some(false), Some(false));
    let output = env.run_hook(destructive_command);
    output.print_verbose("both_toggles=false");

    // Should still deny
    assert!(
        output.is_denied(),
        "Command should be denied even with both toggles disabled"
    );

    eprintln!("=== Both toggles disabled test PASSED ===");
}

#[test]
fn test_both_toggles_enabled_does_not_affect_deny_decision() {
    eprintln!("=== Testing both toggles enabled doesn't affect deny decision ===");

    let destructive_command = "git reset --hard HEAD";

    // Test with both toggles enabled
    let env = TestEnv::new().with_toggles(Some(true), Some(true));
    let output = env.run_hook(destructive_command);
    output.print_verbose("both_toggles=true");

    // Should deny
    assert!(
        output.is_denied(),
        "Command should be denied with both toggles enabled"
    );

    eprintln!("=== Both toggles enabled test PASSED ===");
}

// =============================================================================
// Safe Command Tests - Verify toggles don't affect allow decisions
// =============================================================================

#[test]
fn test_toggle_highlight_enabled_does_not_affect_allow_decision() {
    eprintln!("=== Testing highlight_enabled toggle doesn't affect allow decision ===");

    let safe_command = "git status";

    // Test with highlighting enabled
    let env_enabled = TestEnv::new().with_toggles(Some(true), None);
    let output_enabled = env_enabled.run_hook(safe_command);
    output_enabled.print_verbose("highlight_enabled=true (safe cmd)");

    // Test with highlighting disabled
    let env_disabled = TestEnv::new().with_toggles(Some(false), None);
    let output_disabled = env_disabled.run_hook(safe_command);
    output_disabled.print_verbose("highlight_enabled=false (safe cmd)");

    // Both should result in allow (empty or explicit allow)
    assert!(
        output_enabled.is_allowed(),
        "Safe command should be allowed with highlight_enabled=true"
    );
    assert!(
        output_disabled.is_allowed(),
        "Safe command should be allowed with highlight_enabled=false"
    );

    eprintln!("=== highlight_enabled toggle allow test PASSED ===");
}

#[test]
fn test_toggle_explanations_enabled_does_not_affect_allow_decision() {
    eprintln!("=== Testing explanations_enabled toggle doesn't affect allow decision ===");

    let safe_command = "git status";

    // Test with explanations enabled
    let env_enabled = TestEnv::new().with_toggles(None, Some(true));
    let output_enabled = env_enabled.run_hook(safe_command);
    output_enabled.print_verbose("explanations_enabled=true (safe cmd)");

    // Test with explanations disabled
    let env_disabled = TestEnv::new().with_toggles(None, Some(false));
    let output_disabled = env_disabled.run_hook(safe_command);
    output_disabled.print_verbose("explanations_enabled=false (safe cmd)");

    // Both should result in allow
    assert!(
        output_enabled.is_allowed(),
        "Safe command should be allowed with explanations_enabled=true"
    );
    assert!(
        output_disabled.is_allowed(),
        "Safe command should be allowed with explanations_enabled=false"
    );

    eprintln!("=== explanations_enabled toggle allow test PASSED ===");
}

// =============================================================================
// Toggle Combination Tests - All 4 combinations
// =============================================================================

#[test]
fn test_all_toggle_combinations_deny_consistency() {
    eprintln!("=== Testing all toggle combinations for deny consistency ===");

    let destructive_command = "rm -rf /important";

    let combinations: [(Option<bool>, Option<bool>, &str); 4] = [
        (Some(true), Some(true), "both enabled"),
        (Some(true), Some(false), "highlight only"),
        (Some(false), Some(true), "explanations only"),
        (Some(false), Some(false), "both disabled"),
    ];

    for (highlight, explanation, label) in &combinations {
        let env = TestEnv::new().with_toggles(*highlight, *explanation);
        let output = env.run_hook(destructive_command);
        output.print_verbose(&format!("toggle combo: {}", label));

        assert!(
            output.is_denied(),
            "Destructive command should be denied with toggle combo: {}",
            label
        );

        eprintln!("  ✓ {} - denied correctly", label);
    }

    eprintln!("=== All toggle combinations deny test PASSED ===");
}

#[test]
fn test_all_toggle_combinations_allow_consistency() {
    eprintln!("=== Testing all toggle combinations for allow consistency ===");

    let safe_command = "echo hello";

    let combinations: [(Option<bool>, Option<bool>, &str); 4] = [
        (Some(true), Some(true), "both enabled"),
        (Some(true), Some(false), "highlight only"),
        (Some(false), Some(true), "explanations only"),
        (Some(false), Some(false), "both disabled"),
    ];

    for (highlight, explanation, label) in &combinations {
        let env = TestEnv::new().with_toggles(*highlight, *explanation);
        let output = env.run_hook(safe_command);
        output.print_verbose(&format!("toggle combo: {}", label));

        assert!(
            output.is_allowed(),
            "Safe command should be allowed with toggle combo: {}",
            label
        );

        eprintln!("  ✓ {} - allowed correctly", label);
    }

    eprintln!("=== All toggle combinations allow test PASSED ===");
}

// =============================================================================
// CLI Mode Tests (dcg test)
// =============================================================================

#[test]
fn test_cli_test_mode_with_toggles() {
    eprintln!("=== Testing CLI test mode with toggles ===");

    let destructive_command = "git reset --hard";

    // Test with both enabled
    let env_enabled = TestEnv::new().with_toggles(Some(true), Some(true));
    let output_enabled = env_enabled.run_test_command(destructive_command);
    output_enabled.print_verbose("CLI test mode - toggles enabled");

    // Test with both disabled
    let env_disabled = TestEnv::new().with_toggles(Some(false), Some(false));
    let output_disabled = env_disabled.run_test_command(destructive_command);
    output_disabled.print_verbose("CLI test mode - toggles disabled");

    // Both should indicate blocked (exit code or output)
    // dcg test returns non-zero for denied commands
    assert!(
        output_enabled.exit_code != 0 || output_enabled.stdout.contains("BLOCKED") || output_enabled.stdout.contains("denied"),
        "CLI test should indicate blocked with toggles enabled"
    );
    assert!(
        output_disabled.exit_code != 0 || output_disabled.stdout.contains("BLOCKED") || output_disabled.stdout.contains("denied"),
        "CLI test should indicate blocked with toggles disabled"
    );

    eprintln!("=== CLI test mode with toggles PASSED ===");
}

// =============================================================================
// Config Loading Tests
// =============================================================================

#[test]
fn test_config_toggle_defaults_without_config() {
    eprintln!("=== Testing default behavior without config file ===");

    // Create env without writing config file
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let home_dir = temp_dir.path().join("home");
    let xdg_config_dir = temp_dir.path().join("xdg_config");

    fs::create_dir_all(&home_dir).expect("failed to create HOME dir");
    fs::create_dir_all(&xdg_config_dir).expect("failed to create XDG_CONFIG_HOME dir");
    fs::create_dir_all(temp_dir.path().join(".git")).expect("failed to create .git dir");

    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {
            "command": "git reset --hard HEAD",
        }
    });

    let mut cmd = Command::new(dcg_binary());
    cmd.env_clear()
        .env("HOME", &home_dir)
        .env("XDG_CONFIG_HOME", &xdg_config_dir)
        .env("DCG_PACKS", "core.git")
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .current_dir(temp_dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("failed to spawn dcg");

    {
        let stdin = child.stdin.as_mut().expect("failed to open stdin");
        serde_json::to_writer(stdin, &input).expect("failed to write hook input JSON");
    }

    let output = child.wait_with_output().expect("failed to wait for dcg");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("Exit code: {}", output.status.code().unwrap_or(-1));
    eprintln!("Stdout: {}", stdout);
    eprintln!("Stderr: {}", stderr);

    // Should still deny destructive command with defaults
    assert!(
        stdout.contains("\"deny\"") || stdout.contains("denied"),
        "Should deny destructive command with default config"
    );

    eprintln!("=== Default config behavior test PASSED ===");
}

#[test]
fn test_partial_config_only_highlight() {
    eprintln!("=== Testing partial config with only highlight_enabled ===");

    let env = TestEnv::new().with_toggles(Some(false), None);
    let output = env.run_hook("git reset --hard HEAD");
    output.print_verbose("partial config - highlight_enabled=false only");

    // Should still deny (explanations defaults to true)
    assert!(
        output.is_denied(),
        "Command should be denied with partial config (highlight only)"
    );

    eprintln!("=== Partial config test PASSED ===");
}

#[test]
fn test_partial_config_only_explanations() {
    eprintln!("=== Testing partial config with only explanations_enabled ===");

    let env = TestEnv::new().with_toggles(None, Some(false));
    let output = env.run_hook("git reset --hard HEAD");
    output.print_verbose("partial config - explanations_enabled=false only");

    // Should still deny (highlight defaults to true)
    assert!(
        output.is_denied(),
        "Command should be denied with partial config (explanations only)"
    );

    eprintln!("=== Partial config test PASSED ===");
}

// =============================================================================
// Verbose Failure Logging Test
// =============================================================================

#[test]
fn test_verbose_failure_logging() {
    eprintln!("=== Testing verbose failure logging ===");

    // This test intentionally uses a command that should be denied
    // and prints comprehensive diagnostic output

    let env = TestEnv::new().with_toggles(Some(true), Some(true));
    let output = env.run_hook("git clean -fdx");

    // Always print verbose output for debugging
    output.print_verbose("VERBOSE TEST OUTPUT");

    eprintln!("===== ADDITIONAL DIAGNOSTICS =====");
    eprintln!("Command tested: git clean -fdx");
    eprintln!("Expected: denied");
    eprintln!("Actual denied: {}", output.is_denied());
    eprintln!("Actual allowed: {}", output.is_allowed());
    eprintln!("Exit code: {}", output.exit_code);
    eprintln!("Stdout empty: {}", output.stdout.is_empty());
    eprintln!("Stderr empty: {}", output.stderr.is_empty());
    eprintln!("===== END DIAGNOSTICS =====");

    // The command should be denied
    assert!(
        output.is_denied(),
        "git clean -fdx should be denied"
    );

    eprintln!("=== Verbose failure logging test PASSED ===");
}

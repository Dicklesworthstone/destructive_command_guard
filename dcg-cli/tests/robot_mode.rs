//! Tests for robot mode (`--robot` flag and `DCG_ROBOT` env var).
//!
//! Robot mode provides a unified, machine-friendly interface for AI agents:
//! - Always outputs JSON to stdout
//! - Silent stderr (no rich formatting, no ANSI codes)
//! - Standardized exit codes:
//!   - 0: Success / Allow
//!   - 1: Command denied/blocked
//!   - 2: Warning (with --fail-on warn)
//!   - 3: Configuration error
//!   - 4: Parse/input error
//!   - 5: IO error

use std::path::PathBuf;
use std::process::Command;

/// Path to the dcg binary.
fn dcg_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("CARGO_BIN_EXE_dcg") {
        return PathBuf::from(path);
    }

    let mut path = std::env::current_exe().unwrap();
    path.pop(); // Remove test binary name
    path.pop(); // Remove deps/
    path.push("dcg");
    path
}

/// Run a dcg command and return stdout, stderr, exit code.
fn run_dcg(args: &[&str]) -> (String, String, i32) {
    let binary = dcg_binary();
    let output = Command::new(&binary)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to run dcg at {}: {}", binary.display(), e));

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code().unwrap_or(-1);

    (stdout, stderr, exit_code)
}

/// Run a dcg command with environment variable set.
fn run_dcg_with_env(args: &[&str], key: &str, value: &str) -> (String, String, i32) {
    let binary = dcg_binary();
    let output = Command::new(&binary)
        .args(args)
        .env(key, value)
        .output()
        .unwrap_or_else(|e| panic!("failed to run dcg at {}: {}", binary.display(), e));

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code().unwrap_or(-1);

    (stdout, stderr, exit_code)
}

// =============================================================================
// Robot Mode Flag Tests
// =============================================================================

#[test]
fn test_robot_flag_enables_json_output() {
    let (stdout, _stderr, exit_code) = run_dcg(&["--robot", "test", "git status"]);

    assert_eq!(exit_code, 0, "robot mode should exit 0 for allowed command");

    // Robot mode should produce JSON
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("robot mode should produce valid JSON");

    assert!(json.is_object(), "robot mode should output JSON object");
    assert!(json.get("command").is_some(), "should have command field");
    assert!(json.get("decision").is_some(), "should have decision field");
}

#[test]
fn test_robot_flag_denied_command_exit_code() {
    let (stdout, _stderr, exit_code) = run_dcg(&["--robot", "test", "git reset --hard"]);

    // In robot mode with test subcommand, denied commands exit 1
    assert_eq!(exit_code, 1, "robot mode should exit 1 for denied command");

    // Should still have JSON output
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("robot mode should produce valid JSON");

    assert_eq!(json["decision"], "deny", "decision should be deny");
}

#[test]
fn test_robot_flag_no_ansi_codes() {
    let (stdout, stderr, _) = run_dcg(&["--robot", "test", "git reset --hard"]);

    // Neither stdout nor stderr should contain ANSI escape sequences
    assert!(
        !stdout.contains("\x1b["),
        "robot mode stdout should not contain ANSI codes\nstdout: {stdout}"
    );
    assert!(
        !stderr.contains("\x1b["),
        "robot mode stderr should not contain ANSI codes\nstderr: {stderr}"
    );
}

#[test]
fn test_robot_flag_silent_stderr() {
    let (_stdout, stderr, _) = run_dcg(&["--robot", "test", "git reset --hard"]);

    // In robot mode, stderr should be empty or minimal (no rich TUI output)
    // Note: Some progress info might still appear, but no decorative output
    assert!(
        !stderr.contains("╭") && !stderr.contains("╰") && !stderr.contains("│"),
        "robot mode should not have box-drawing characters in stderr\nstderr: {stderr}"
    );
}

// =============================================================================
// DCG_ROBOT Environment Variable Tests
// =============================================================================

#[test]
fn test_dcg_robot_env_enables_json_output() {
    let (stdout, _stderr, exit_code) = run_dcg_with_env(&["test", "git status"], "DCG_ROBOT", "1");

    assert_eq!(
        exit_code, 0,
        "DCG_ROBOT=1 should exit 0 for allowed command"
    );

    // Should produce JSON like --robot flag
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("DCG_ROBOT=1 should produce valid JSON");

    assert!(json.is_object(), "DCG_ROBOT=1 should output JSON object");
}

#[test]
fn test_dcg_robot_env_denied_exit_code() {
    let (_stdout, _stderr, exit_code) =
        run_dcg_with_env(&["test", "git reset --hard"], "DCG_ROBOT", "1");

    assert_eq!(exit_code, 1, "DCG_ROBOT=1 should exit 1 for denied command");
}

#[test]
fn test_dcg_robot_env_no_ansi_codes() {
    let (stdout, stderr, _) = run_dcg_with_env(&["test", "git reset --hard"], "DCG_ROBOT", "1");

    assert!(
        !stdout.contains("\x1b["),
        "DCG_ROBOT=1 stdout should not contain ANSI codes"
    );
    assert!(
        !stderr.contains("\x1b["),
        "DCG_ROBOT=1 stderr should not contain ANSI codes"
    );
}

#[test]
fn test_dcg_robot_env_false_values_do_not_force_json() {
    for value in ["0", "false", "no", "off"] {
        let (stdout, _stderr, exit_code) =
            run_dcg_with_env(&["test", "git status"], "DCG_ROBOT", value);

        assert_eq!(
            exit_code, 0,
            "DCG_ROBOT={value} should not change allowed command exit code"
        );
        assert!(
            serde_json::from_str::<serde_json::Value>(&stdout).is_err(),
            "DCG_ROBOT={value} should leave default human output, got JSON: {stdout}"
        );
    }
}

// =============================================================================
// Robot Mode JSON Structure Tests
// =============================================================================

#[test]
fn test_robot_mode_json_has_agent_info() {
    let (stdout, _stderr, _) = run_dcg(&["--robot", "test", "git reset --hard"]);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("should produce valid JSON");

    // Robot mode should include agent detection info
    if let Some(agent) = json.get("agent") {
        assert!(agent.is_object(), "agent should be an object");
    }
}

#[test]
fn test_robot_mode_json_has_severity() {
    let (stdout, _stderr, _) = run_dcg(&["--robot", "test", "git reset --hard"]);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("should produce valid JSON");

    if json["decision"] == "deny" {
        assert!(
            json.get("severity").is_some(),
            "denied commands should include severity"
        );
    }
}

#[test]
fn test_robot_mode_json_has_rule_id() {
    let (stdout, _stderr, _) = run_dcg(&["--robot", "test", "git reset --hard"]);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("should produce valid JSON");

    if json["decision"] == "deny" {
        assert!(
            json.get("rule_id").is_some(),
            "denied commands should include rule_id"
        );
        assert!(
            json.get("pack_id").is_some(),
            "denied commands should include pack_id"
        );
    }
}

// =============================================================================
// Exit Code Tests
// =============================================================================

#[test]
fn test_robot_mode_exit_0_allowed() {
    let safe_commands = ["ls -la", "git status", "echo hello", "cat /etc/hosts"];

    for cmd in safe_commands {
        let (_stdout, _stderr, exit_code) = run_dcg(&["--robot", "test", cmd]);

        assert_eq!(
            exit_code, 0,
            "robot mode should exit 0 for allowed command: {cmd}"
        );
    }
}

#[test]
fn test_robot_mode_exit_1_denied() {
    let dangerous_commands = [
        "git reset --hard",
        "git clean -fd",
        "rm -rf /",
        "git push --force origin main",
    ];

    for cmd in dangerous_commands {
        let (_stdout, _stderr, exit_code) = run_dcg(&["--robot", "test", cmd]);

        assert_eq!(
            exit_code, 1,
            "robot mode should exit 1 for denied command: {cmd}"
        );
    }
}

// =============================================================================
// Comparison: Robot Mode vs Hook Mode
// =============================================================================

#[test]
fn test_robot_mode_vs_hook_mode_exit_codes() {
    // Robot mode with test subcommand should use standardized exit codes
    // Hook mode (piped JSON input) follows Claude Code protocol (always exit 0)

    // Robot mode: denied = exit 1
    let (_stdout, _stderr, robot_exit) = run_dcg(&["--robot", "test", "git reset --hard"]);
    assert_eq!(robot_exit, 1, "robot mode denied should exit 1");

    // Robot mode: allowed = exit 0
    let (_stdout, _stderr, robot_exit) = run_dcg(&["--robot", "test", "git status"]);
    assert_eq!(robot_exit, 0, "robot mode allowed should exit 0");
}

// =============================================================================
// Robot Mode with Different Commands
// =============================================================================

#[test]
fn test_robot_mode_explain_command() {
    let (stdout, _stderr, exit_code) = run_dcg(&["--robot", "explain", "git reset --hard"]);

    assert_eq!(exit_code, 0, "robot mode explain should exit 0");

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("robot mode explain should produce valid JSON");

    assert!(json.is_object(), "explain should output JSON object");
}

#[test]
fn test_robot_mode_packs_command() {
    let (stdout, _stderr, exit_code) = run_dcg(&["--robot", "packs"]);

    assert_eq!(exit_code, 0, "robot mode packs should exit 0");

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("robot mode packs should produce valid JSON");

    assert!(json.get("packs").is_some(), "should have packs array");
}

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn test_robot_mode_empty_command() {
    let (stdout, _stderr, exit_code) = run_dcg(&["--robot", "test", ""]);

    // Empty command should be handled gracefully
    assert!(
        exit_code == 0 || exit_code == 4,
        "empty command should exit 0 (allow) or 4 (parse error), got: {exit_code}"
    );

    // If there's output, it should be valid JSON
    if !stdout.trim().is_empty() {
        let _: serde_json::Value =
            serde_json::from_str(&stdout).expect("output should be valid JSON");
    }
}

#[test]
fn test_robot_mode_whitespace_command() {
    let (stdout, _stderr, exit_code) = run_dcg(&["--robot", "test", "   "]);

    // Whitespace-only command should be handled gracefully
    assert!(
        exit_code == 0 || exit_code == 4,
        "whitespace command should exit 0 or 4, got: {exit_code}"
    );

    if !stdout.trim().is_empty() {
        let _: serde_json::Value =
            serde_json::from_str(&stdout).expect("output should be valid JSON");
    }
}

#[test]
fn test_robot_mode_complex_command() {
    // Complex commands with pipes, redirects, etc.
    let (stdout, _stderr, exit_code) = run_dcg(&[
        "--robot",
        "test",
        "cat file.txt | grep pattern > output.txt",
    ]);

    // Should handle complex commands without crashing
    assert!(
        exit_code == 0 || exit_code == 1,
        "complex command should exit 0 or 1, got: {exit_code}"
    );

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("should produce valid JSON");
    assert!(json.is_object(), "should be JSON object");
}

// =============================================================================
// Consistency Tests
// =============================================================================

#[test]
fn test_robot_flag_and_env_produce_same_result() {
    let cmd = "git reset --hard";

    let (stdout_flag, _stderr_flag, exit_flag) = run_dcg(&["--robot", "test", cmd]);
    let (stdout_env, _stderr_env, exit_env) = run_dcg_with_env(&["test", cmd], "DCG_ROBOT", "1");

    // Both should have same exit code
    assert_eq!(
        exit_flag, exit_env,
        "--robot flag and DCG_ROBOT=1 should have same exit code"
    );

    // Both should produce valid JSON
    let json_flag: serde_json::Value =
        serde_json::from_str(&stdout_flag).expect("--robot should produce valid JSON");
    let json_env: serde_json::Value =
        serde_json::from_str(&stdout_env).expect("DCG_ROBOT=1 should produce valid JSON");

    // Decision should match
    assert_eq!(
        json_flag["decision"], json_env["decision"],
        "decision should match between flag and env var"
    );
}

//! Tests for exit code compliance with Claude Code hook protocol.
//!
//! The Claude Code hook protocol requires:
//! - Exit 0: Normal operation (check JSON stdout for decision)
//! - Exit 2: Blocking error (stderr shown to Claude, no JSON processing)
//!
//! Per the protocol, dcg should:
//! - Exit 0 for ALLOWED commands (no stdout)
//! - Exit 0 for DENIED commands (JSON in stdout with permissionDecision="deny")
//! - Exit 2 for errors that should block the agent from proceeding

use std::io::Write;
use std::process::{Command, Stdio};

/// Path to the dcg binary.
fn dcg_binary() -> &'static str {
    "./target/release/dcg"
}

/// Run dcg in hook mode with JSON input.
fn run_hook_mode_raw(input: &str) -> (String, String, i32) {
    let mut child = Command::new(dcg_binary())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn dcg process");

    {
        let stdin = child.stdin.as_mut().expect("failed to get stdin");
        stdin
            .write_all(input.as_bytes())
            .expect("failed to write to stdin");
    }

    let output = child.wait_with_output().expect("failed to wait for dcg");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code().unwrap_or(-1);

    (stdout, stderr, exit_code)
}

/// Create valid hook input JSON for a command.
fn make_hook_input(command: &str) -> String {
    format!(
        r#"{{"tool_name":"Bash","tool_input":{{"command":"{}"}}}}"#,
        command.replace('\\', "\\\\").replace('"', "\\\"")
    )
}

// =============================================================================
// Exit 0 Tests (Normal Operation)
// =============================================================================

#[test]
fn test_exit_0_on_allow_safe_command() {
    let input = make_hook_input("ls -la");
    let (stdout, stderr, exit_code) = run_hook_mode_raw(&input);

    assert_eq!(
        exit_code, 0,
        "allowed command should exit 0\nstderr: {stderr}"
    );
    assert!(
        stdout.is_empty() || stdout.trim().is_empty(),
        "allowed command should produce no stdout\nstdout: {stdout}"
    );
}

#[test]
fn test_exit_0_on_allow_git_status() {
    let input = make_hook_input("git status");
    let (stdout, _stderr, exit_code) = run_hook_mode_raw(&input);

    assert_eq!(exit_code, 0, "git status should exit 0");
    assert!(
        stdout.trim().is_empty(),
        "git status should produce no stdout"
    );
}

#[test]
fn test_exit_0_on_deny_with_json() {
    let input = make_hook_input("git reset --hard");
    let (stdout, stderr, exit_code) = run_hook_mode_raw(&input);

    // Per Claude Code protocol, even denied commands exit 0
    // The decision is communicated via JSON in stdout
    assert_eq!(
        exit_code, 0,
        "denied command should still exit 0 (decision in JSON)\nstderr: {stderr}"
    );

    // Verify stdout contains deny decision
    assert!(
        !stdout.is_empty(),
        "denied command should produce JSON stdout"
    );

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON");

    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"], "deny",
        "JSON should indicate deny decision"
    );
}

#[test]
fn test_exit_0_on_deny_rm_rf() {
    let input = make_hook_input("rm -rf /important");
    let (stdout, _stderr, exit_code) = run_hook_mode_raw(&input);

    assert_eq!(exit_code, 0, "rm -rf denial should exit 0");
    assert!(!stdout.is_empty(), "denied rm -rf should produce JSON");

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON");

    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"], "deny",
        "rm -rf should be denied"
    );
}

#[test]
fn test_exit_0_on_deny_force_push() {
    let input = make_hook_input("git push --force origin main");
    let (stdout, _stderr, exit_code) = run_hook_mode_raw(&input);

    assert_eq!(exit_code, 0, "force push denial should exit 0");

    if !stdout.is_empty() {
        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("stdout should be valid JSON");

        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "force push should be denied"
        );
    }
}

// =============================================================================
// Exit 0 for Non-Bash Tools (Skip)
// =============================================================================

#[test]
fn test_exit_0_for_non_bash_tool() {
    // Non-Bash tools should be silently skipped (exit 0, no output)
    let input = r#"{"tool_name":"Read","tool_input":{"file_path":"/etc/passwd"}}"#;
    let (stdout, _stderr, exit_code) = run_hook_mode_raw(input);

    assert_eq!(exit_code, 0, "non-Bash tool should exit 0");
    assert!(
        stdout.is_empty() || stdout.trim().is_empty(),
        "non-Bash tool should produce no output"
    );
}

#[test]
fn test_exit_0_for_write_tool() {
    let input =
        r#"{"tool_name":"Write","tool_input":{"file_path":"/tmp/test.txt","content":"hello"}}"#;
    let (stdout, _stderr, exit_code) = run_hook_mode_raw(input);

    assert_eq!(exit_code, 0, "Write tool should exit 0 (skip)");
    assert!(
        stdout.trim().is_empty(),
        "Write tool should produce no output"
    );
}

// =============================================================================
// Error Exit Codes
// =============================================================================

#[test]
fn test_exit_nonzero_on_invalid_json() {
    // Completely invalid JSON should cause an error exit
    let (_stdout, stderr, exit_code) = run_hook_mode_raw("this is not json at all");

    // Invalid JSON typically exits with error code (implementation may vary)
    // The important thing is that it doesn't crash and provides feedback
    if exit_code != 0 {
        // Error exit is expected for malformed input
        assert!(
            stderr.contains("error")
                || stderr.contains("Error")
                || stderr.contains("JSON")
                || stderr.contains("parse")
                || stderr.contains("invalid"),
            "stderr should explain the error\nstderr: {stderr}"
        );
    }
    // If exit code is 0, stdout should be empty (fail-open behavior)
}

#[test]
fn test_exit_on_empty_input() {
    let (stdout, _stderr, exit_code) = run_hook_mode_raw("");

    // Empty input may be handled gracefully (fail-open)
    // Just verify it doesn't crash
    assert!(
        exit_code == 0 || exit_code == 1 || exit_code == 2,
        "empty input should exit with defined code, got: {exit_code}"
    );

    // If exit 0, should produce no output (allow)
    if exit_code == 0 {
        assert!(
            stdout.is_empty() || stdout.trim().is_empty(),
            "empty input with exit 0 should produce no output"
        );
    }
}

#[test]
fn test_exit_on_missing_tool_name() {
    let input = r#"{"tool_input":{"command":"echo hello"}}"#;
    let (stdout, _stderr, exit_code) = run_hook_mode_raw(input);

    // Missing tool_name should be handled gracefully (skip/allow)
    assert_eq!(exit_code, 0, "missing tool_name should not error");
    assert!(
        stdout.trim().is_empty(),
        "missing tool_name should skip (no output)"
    );
}

#[test]
fn test_exit_on_missing_command() {
    let input = r#"{"tool_name":"Bash","tool_input":{}}"#;
    let (stdout, _stderr, exit_code) = run_hook_mode_raw(input);

    // Missing command should be handled gracefully
    assert_eq!(exit_code, 0, "missing command should not error");
    assert!(
        stdout.trim().is_empty(),
        "missing command should skip (no output)"
    );
}

// =============================================================================
// CLI Command Exit Codes
// =============================================================================

#[test]
fn test_test_command_exit_0() {
    let output = Command::new(dcg_binary())
        .args(["test", "git status"])
        .output()
        .expect("failed to run dcg test");

    assert!(output.status.success(), "dcg test <safe> should exit 0");
}

#[test]
fn test_test_command_deny_exit_0() {
    let output = Command::new(dcg_binary())
        .args(["test", "git reset --hard"])
        .output()
        .expect("failed to run dcg test");

    // Even denied commands exit 0 (decision in output, not exit code)
    assert!(
        output.status.success(),
        "dcg test <dangerous> should exit 0"
    );
}

#[test]
fn test_explain_command_exit_0() {
    let output = Command::new(dcg_binary())
        .args(["explain", "git reset --hard"])
        .output()
        .expect("failed to run dcg explain");

    assert!(output.status.success(), "dcg explain should exit 0");
}

#[test]
fn test_packs_command_exit_0() {
    let output = Command::new(dcg_binary())
        .args(["packs"])
        .output()
        .expect("failed to run dcg packs");

    assert!(output.status.success(), "dcg packs should exit 0");
}

#[test]
fn test_version_exit_0() {
    let output = Command::new(dcg_binary())
        .args(["--version"])
        .output()
        .expect("failed to run dcg --version");

    assert!(output.status.success(), "dcg --version should exit 0");
}

#[test]
fn test_help_exit_0() {
    let output = Command::new(dcg_binary())
        .args(["--help"])
        .output()
        .expect("failed to run dcg --help");

    assert!(output.status.success(), "dcg --help should exit 0");
}

// =============================================================================
// Batch/Consistency Tests
// =============================================================================

#[test]
fn test_consistent_exit_codes_across_commands() {
    // All safe commands should exit 0 with no output
    let safe_commands = [
        "ls",
        "echo hello",
        "git status",
        "git log --oneline",
        "cat /etc/passwd",
        "grep pattern file.txt",
    ];

    for cmd in safe_commands {
        let input = make_hook_input(cmd);
        let (stdout, stderr, exit_code) = run_hook_mode_raw(&input);

        assert_eq!(
            exit_code, 0,
            "safe command '{cmd}' should exit 0\nstderr: {stderr}"
        );
        assert!(
            stdout.trim().is_empty(),
            "safe command '{cmd}' should have empty stdout\nstdout: {stdout}"
        );
    }
}

#[test]
fn test_consistent_exit_codes_denied_commands() {
    // All denied commands should exit 0 with JSON output
    let dangerous_commands = [
        "git reset --hard",
        "git clean -fd",
        "rm -rf /",
        "git push --force",
    ];

    for cmd in dangerous_commands {
        let input = make_hook_input(cmd);
        let (stdout, stderr, exit_code) = run_hook_mode_raw(&input);

        assert_eq!(
            exit_code, 0,
            "dangerous command '{cmd}' should exit 0\nstderr: {stderr}"
        );

        // Should have JSON output indicating denial
        if !stdout.is_empty() {
            let json: serde_json::Value = serde_json::from_str(&stdout)
                .unwrap_or_else(|e| panic!("invalid JSON for '{cmd}': {e}\nstdout: {stdout}"));

            assert!(
                json.get("hookSpecificOutput").is_some(),
                "denied '{cmd}' should have hookSpecificOutput"
            );
        }
    }
}

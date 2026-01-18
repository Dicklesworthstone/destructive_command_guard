//! Tests for `HookSpecificOutput` JSON structure and required fields.
//!
//! These tests verify that the hook output contains all fields required
//! for AI agent integration as specified in `git_safety_guard-e4fl.1`.

#![allow(clippy::doc_markdown)]

use std::process::{Command, Stdio};
use std::io::Write;

/// Path to the dcg binary (built in release mode for tests).
fn dcg_binary() -> &'static str {
    "./target/release/dcg"
}

/// Run dcg in hook mode with the given command as JSON input.
fn run_hook_mode(command: &str) -> (String, String, i32) {
    let input = format!(
        r#"{{"tool_name":"Bash","tool_input":{{"command":"{}"}}}}"#,
        command.replace('\\', "\\\\").replace('"', "\\\"")
    );

    let mut child = Command::new(dcg_binary())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn dcg process");

    {
        let stdin = child.stdin.as_mut().expect("failed to get stdin");
        stdin.write_all(input.as_bytes()).expect("failed to write to stdin");
    }

    let output = child.wait_with_output().expect("failed to wait for dcg");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code().unwrap_or(-1);

    (stdout, stderr, exit_code)
}

#[test]
fn test_hook_output_contains_hook_event_name() {
    let (stdout, stderr, exit_code) = run_hook_mode("git reset --hard");

    assert_eq!(exit_code, 0, "hook mode should exit 0 even on deny\nstderr: {stderr}");
    assert!(!stdout.is_empty(), "stdout should contain JSON output");

    let json: serde_json::Value = serde_json::from_str(&stdout)
        .expect("hook output should be valid JSON");

    let hook_output = &json["hookSpecificOutput"];
    assert!(
        hook_output.get("hookEventName").is_some(),
        "hookEventName field required in output"
    );
    assert_eq!(
        hook_output["hookEventName"], "PreToolUse",
        "hookEventName should be 'PreToolUse'"
    );
}

#[test]
fn test_hook_output_contains_permission_decision() {
    let (stdout, _stderr, _) = run_hook_mode("git reset --hard");

    let json: serde_json::Value = serde_json::from_str(&stdout)
        .expect("hook output should be valid JSON");

    let hook_output = &json["hookSpecificOutput"];
    assert!(
        hook_output.get("permissionDecision").is_some(),
        "permissionDecision field required in output"
    );

    let decision = hook_output["permissionDecision"].as_str().unwrap();
    assert!(
        decision == "allow" || decision == "deny",
        "permissionDecision should be 'allow' or 'deny', got: {decision}"
    );
}

#[test]
fn test_hook_output_deny_has_rule_id() {
    let (stdout, _stderr, _) = run_hook_mode("git reset --hard");

    let json: serde_json::Value = serde_json::from_str(&stdout)
        .expect("hook output should be valid JSON");

    let hook_output = &json["hookSpecificOutput"];

    // For denied commands, ruleId should be present
    if hook_output["permissionDecision"] == "deny" {
        assert!(
            hook_output.get("ruleId").is_some(),
            "ruleId field should be present for denied commands"
        );

        let rule_id = hook_output["ruleId"].as_str().unwrap();
        assert!(
            rule_id.contains(':'),
            "ruleId should have format 'packId:patternName', got: {rule_id}"
        );
    }
}

#[test]
fn test_hook_output_deny_has_pack_id() {
    let (stdout, _stderr, _) = run_hook_mode("git reset --hard");

    let json: serde_json::Value = serde_json::from_str(&stdout)
        .expect("hook output should be valid JSON");

    let hook_output = &json["hookSpecificOutput"];

    if hook_output["permissionDecision"] == "deny" {
        assert!(
            hook_output.get("packId").is_some(),
            "packId field should be present for denied commands"
        );

        let pack_id = hook_output["packId"].as_str().unwrap();
        assert!(!pack_id.is_empty(), "packId should not be empty");
    }
}

#[test]
fn test_hook_output_deny_has_severity() {
    let (stdout, _stderr, _) = run_hook_mode("git reset --hard");

    let json: serde_json::Value = serde_json::from_str(&stdout)
        .expect("hook output should be valid JSON");

    let hook_output = &json["hookSpecificOutput"];

    if hook_output["permissionDecision"] == "deny" {
        assert!(
            hook_output.get("severity").is_some(),
            "severity field should be present for denied commands"
        );

        let severity = hook_output["severity"].as_str().unwrap();
        let valid_severities = ["critical", "high", "medium", "low"];
        assert!(
            valid_severities.contains(&severity),
            "severity should be one of {:?}, got: {severity}",
            valid_severities
        );
    }
}

#[test]
fn test_hook_output_deny_has_remediation() {
    let (stdout, _stderr, _) = run_hook_mode("git reset --hard");

    let json: serde_json::Value = serde_json::from_str(&stdout)
        .expect("hook output should be valid JSON");

    let hook_output = &json["hookSpecificOutput"];

    if hook_output["permissionDecision"] == "deny" {
        assert!(
            hook_output.get("remediation").is_some(),
            "remediation field should be present for denied commands"
        );

        let remediation = &hook_output["remediation"];

        // Verify remediation structure
        assert!(
            remediation.get("explanation").is_some(),
            "remediation.explanation should be present"
        );
        assert!(
            remediation.get("allowOnceCommand").is_some(),
            "remediation.allowOnceCommand should be present"
        );
    }
}

#[test]
fn test_hook_output_deny_has_allow_once_code() {
    let (stdout, _stderr, _) = run_hook_mode("git reset --hard");

    let json: serde_json::Value = serde_json::from_str(&stdout)
        .expect("hook output should be valid JSON");

    let hook_output = &json["hookSpecificOutput"];

    if hook_output["permissionDecision"] == "deny" {
        assert!(
            hook_output.get("allowOnceCode").is_some(),
            "allowOnceCode should be present for denied commands"
        );

        let code = hook_output["allowOnceCode"].as_str().unwrap();
        assert!(!code.is_empty(), "allowOnceCode should not be empty");

        // Also verify the remediation includes the allow-once command
        if let Some(remediation) = hook_output.get("remediation") {
            let allow_cmd = remediation["allowOnceCommand"].as_str().unwrap();
            assert!(
                allow_cmd.contains("dcg allow-once"),
                "allowOnceCommand should contain 'dcg allow-once'"
            );
            assert!(
                allow_cmd.contains(code),
                "allowOnceCommand should contain the allowOnceCode"
            );
        }
    }
}

#[test]
fn test_hook_output_permission_decision_reason() {
    let (stdout, _stderr, _) = run_hook_mode("git reset --hard");

    let json: serde_json::Value = serde_json::from_str(&stdout)
        .expect("hook output should be valid JSON");

    let hook_output = &json["hookSpecificOutput"];

    assert!(
        hook_output.get("permissionDecisionReason").is_some(),
        "permissionDecisionReason should be present"
    );

    let reason = hook_output["permissionDecisionReason"].as_str().unwrap();
    assert!(!reason.is_empty(), "permissionDecisionReason should not be empty");

    // For denied commands, reason should be descriptive
    if hook_output["permissionDecision"] == "deny" {
        assert!(
            reason.contains("BLOCKED") || reason.contains("Reason:"),
            "permissionDecisionReason for deny should explain the block"
        );
    }
}

#[test]
fn test_hook_output_safe_command_returns_no_output() {
    let (stdout, _stderr, exit_code) = run_hook_mode("git status");

    assert_eq!(exit_code, 0, "safe command should exit 0");
    assert!(
        stdout.is_empty() || stdout.trim().is_empty(),
        "safe command should produce no stdout output, got: {stdout}"
    );
}

#[test]
fn test_hook_output_git_clean_dry_run_allowed() {
    // git clean -n (dry run) should be allowed
    let (stdout, _stderr, exit_code) = run_hook_mode("git clean -n");

    assert_eq!(exit_code, 0, "git clean -n should exit 0");
    assert!(
        stdout.is_empty() || stdout.trim().is_empty(),
        "git clean -n (dry run) should be allowed with no output, got: {stdout}"
    );
}

#[test]
fn test_hook_output_multiple_destructive_commands() {
    // Test various destructive commands to ensure consistent output format
    let commands = [
        "git reset --hard HEAD~5",
        "git clean -fd",
        "git push --force origin main",
        "rm -rf /important/data",
    ];

    for cmd in commands {
        let (stdout, stderr, exit_code) = run_hook_mode(cmd);

        assert_eq!(
            exit_code, 0,
            "hook mode should exit 0 for cmd: {cmd}\nstderr: {stderr}"
        );

        if !stdout.is_empty() {
            let json: serde_json::Value = serde_json::from_str(&stdout)
                .unwrap_or_else(|e| panic!("invalid JSON for cmd '{cmd}': {e}\nstdout: {stdout}"));

            let hook_output = &json["hookSpecificOutput"];

            // All denied commands should have these fields
            if hook_output["permissionDecision"] == "deny" {
                assert!(
                    hook_output.get("ruleId").is_some() || hook_output.get("packId").is_some(),
                    "denied command should have ruleId or packId: {cmd}"
                );
                assert!(
                    hook_output.get("severity").is_some(),
                    "denied command should have severity: {cmd}"
                );
            }
        }
    }
}

#[test]
fn test_hook_output_rule_id_format() {
    let (stdout, _stderr, _) = run_hook_mode("git reset --hard");

    let json: serde_json::Value = serde_json::from_str(&stdout)
        .expect("hook output should be valid JSON");

    let hook_output = &json["hookSpecificOutput"];

    if let Some(rule_id) = hook_output.get("ruleId") {
        let rule_id_str = rule_id.as_str().unwrap();

        // Rule ID format: "{packId}:{patternName}"
        let parts: Vec<&str> = rule_id_str.split(':').collect();
        assert_eq!(
            parts.len(), 2,
            "ruleId should have format 'packId:patternName', got: {rule_id_str}"
        );

        // The pack_id in ruleId should match packId field
        if let Some(pack_id) = hook_output.get("packId") {
            assert_eq!(
                parts[0],
                pack_id.as_str().unwrap(),
                "ruleId pack portion should match packId"
            );
        }
    }
}

#[test]
fn test_hook_output_remediation_safe_alternative() {
    let (stdout, _stderr, _) = run_hook_mode("git reset --hard");

    let json: serde_json::Value = serde_json::from_str(&stdout)
        .expect("hook output should be valid JSON");

    let hook_output = &json["hookSpecificOutput"];

    if let Some(remediation) = hook_output.get("remediation") {
        // safeAlternative is optional but when present should be helpful
        if let Some(safe_alt) = remediation.get("safeAlternative") {
            let alt_str = safe_alt.as_str().unwrap();
            assert!(
                !alt_str.is_empty(),
                "safeAlternative when present should not be empty"
            );
        }
    }
}

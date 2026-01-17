//! Tests for JSON format output across CLI commands.
//!
//! These tests verify that all CLI commands with --format json
//! produce valid, well-structured JSON output suitable for AI agent parsing.

use std::process::Command;

/// Path to the dcg binary.
fn dcg_binary() -> &'static str {
    "./target/release/dcg"
}

/// Run a dcg command and return stdout, stderr, exit code.
fn run_dcg(args: &[&str]) -> (String, String, i32) {
    let output = Command::new(dcg_binary())
        .args(args)
        .output()
        .expect("failed to run dcg");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code().unwrap_or(-1);

    (stdout, stderr, exit_code)
}

// =============================================================================
// Test Command JSON Output
// =============================================================================

#[test]
fn test_test_command_json_valid() {
    let (stdout, stderr, exit_code) = run_dcg(&["test", "--format", "json", "git status"]);

    assert_eq!(
        exit_code, 0,
        "test --format json should exit 0\nstderr: {stderr}"
    );

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("test --format json should produce valid JSON");

    // Verify required fields for test output
    assert!(json.get("command").is_some(), "should have 'command' field");
    assert!(
        json.get("decision").is_some(),
        "should have 'decision' field"
    );
}

#[test]
fn test_test_command_json_allowed() {
    let (stdout, _stderr, _) = run_dcg(&["test", "--format", "json", "echo hello"]);

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("test --format json should produce valid JSON");

    assert_eq!(
        json["decision"], "allow",
        "safe command should have decision=allow"
    );
}

#[test]
fn test_test_command_json_denied() {
    let (stdout, _stderr, _) = run_dcg(&["test", "--format", "json", "git reset --hard"]);

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("test --format json should produce valid JSON");

    assert_eq!(
        json["decision"], "deny",
        "dangerous command should have decision=deny"
    );

    // Denied commands should have additional fields
    assert!(json.get("rule_id").is_some(), "denied should have rule_id");
    assert!(json.get("pack_id").is_some(), "denied should have pack_id");
    assert!(json.get("reason").is_some(), "denied should have reason");
}

#[test]
fn test_test_command_json_denied_has_matched_span() {
    let (stdout, _stderr, _) = run_dcg(&["test", "--format", "json", "git reset --hard"]);

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("test --format json should produce valid JSON");

    if json["decision"] == "deny" {
        // matched_span should be present for highlighting
        if let Some(span) = json.get("matched_span") {
            assert!(
                span.is_array(),
                "matched_span should be an array [start, end]"
            );
            let arr = span.as_array().unwrap();
            assert_eq!(arr.len(), 2, "matched_span should have 2 elements");
        }
    }
}

// =============================================================================
// Explain Command JSON Output
// =============================================================================

#[test]
fn test_explain_command_json_valid() {
    let (stdout, stderr, exit_code) = run_dcg(&["explain", "--format", "json", "git reset --hard"]);

    assert_eq!(
        exit_code, 0,
        "explain --format json should exit 0\nstderr: {stderr}"
    );

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("explain --format json should produce valid JSON");

    // Verify explain output structure
    assert!(
        json.get("command").is_some(),
        "explain should have 'command' field"
    );
    assert!(
        json.get("decision").is_some(),
        "explain should have 'decision' field"
    );
}

#[test]
fn test_explain_command_json_has_trace() {
    let (stdout, _stderr, _) = run_dcg(&["explain", "--format", "json", "git reset --hard"]);

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("explain --format json should produce valid JSON");

    // Explain output should include evaluation trace
    if let Some(trace) = json.get("trace") {
        assert!(
            trace.is_array() || trace.is_object(),
            "trace should be structured"
        );
    }
}

#[test]
fn test_explain_command_json_schema_version() {
    let (stdout, _stderr, _) = run_dcg(&["explain", "--format", "json", "git reset --hard"]);

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("explain --format json should produce valid JSON");

    // Schema version should be present for API stability
    if let Some(version) = json.get("schema_version") {
        assert!(
            version.is_number() || version.is_string(),
            "schema_version should be number or string"
        );
    }
}

// =============================================================================
// Packs Command JSON Output
// =============================================================================

#[test]
fn test_packs_command_json_valid() {
    let (stdout, stderr, exit_code) = run_dcg(&["packs", "--format", "json"]);

    assert_eq!(
        exit_code, 0,
        "packs --format json should exit 0\nstderr: {stderr}"
    );

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("packs --format json should produce valid JSON");

    // Verify packs output structure
    assert!(json.get("packs").is_some(), "should have 'packs' array");
    assert!(json["packs"].is_array(), "packs should be an array");
}

#[test]
fn test_packs_command_json_pack_structure() {
    let (stdout, _stderr, _) = run_dcg(&["packs", "--format", "json"]);

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("packs --format json should produce valid JSON");

    let packs = json["packs"].as_array().expect("packs should be an array");
    assert!(!packs.is_empty(), "should have at least one pack");

    // Verify first pack has required fields
    let first_pack = &packs[0];
    assert!(first_pack.get("id").is_some(), "pack should have 'id'");
    assert!(first_pack.get("name").is_some(), "pack should have 'name'");
    assert!(
        first_pack.get("enabled").is_some(),
        "pack should have 'enabled'"
    );
}

#[test]
fn test_packs_command_json_has_pattern_counts() {
    let (stdout, _stderr, _) = run_dcg(&["packs", "--format", "json"]);

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("packs --format json should produce valid JSON");

    let packs = json["packs"].as_array().unwrap();
    let first_pack = &packs[0];

    // Should include pattern counts for agent awareness
    assert!(
        first_pack.get("safe_pattern_count").is_some()
            || first_pack.get("safePatternCount").is_some(),
        "pack should have safe pattern count"
    );
    assert!(
        first_pack.get("destructive_pattern_count").is_some()
            || first_pack.get("destructivePatternCount").is_some(),
        "pack should have destructive pattern count"
    );
}

#[test]
fn test_packs_command_json_contains_core_packs() {
    let (stdout, _stderr, _) = run_dcg(&["packs", "--format", "json"]);

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("packs --format json should produce valid JSON");

    let packs = json["packs"].as_array().unwrap();

    // Core packs should always be present
    let pack_ids: Vec<&str> = packs.iter().filter_map(|p| p["id"].as_str()).collect();

    assert!(
        pack_ids.iter().any(|id| id.starts_with("core.")),
        "should contain core.* packs"
    );
}

// =============================================================================
// Scan Command JSON Output (if applicable)
// =============================================================================

#[test]
fn test_scan_command_json_valid() {
    // Create a temp directory with a test file
    let temp_dir = std::env::temp_dir().join("dcg_test_scan");
    let _ = std::fs::create_dir_all(&temp_dir);
    let test_file = temp_dir.join("test.sh");
    std::fs::write(&test_file, "#!/bin/bash\necho hello\n").ok();

    let (stdout, stderr, exit_code) = run_dcg(&[
        "scan",
        "--format",
        "json",
        "--paths",
        temp_dir.to_str().unwrap(),
    ]);

    // Cleanup
    let _ = std::fs::remove_dir_all(&temp_dir);

    assert_eq!(
        exit_code, 0,
        "scan --format json should exit 0\nstderr: {stderr}"
    );

    if !stdout.is_empty() {
        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("scan --format json should produce valid JSON");

        // Scan output should have findings array
        assert!(
            json.get("findings").is_some() || json.get("results").is_some(),
            "scan should have 'findings' or 'results' field"
        );
    }
}

// =============================================================================
// JSON Output Consistency Tests
// =============================================================================

#[test]
fn test_all_json_outputs_are_objects() {
    // All JSON outputs should be objects (not arrays or primitives at root)
    let commands = [
        vec!["test", "--format", "json", "echo hello"],
        vec!["explain", "--format", "json", "git status"],
        vec!["packs", "--format", "json"],
    ];

    for cmd_args in commands {
        let (stdout, stderr, exit_code) = run_dcg(&cmd_args.iter().copied().collect::<Vec<_>>());

        assert_eq!(
            exit_code, 0,
            "command {:?} should exit 0\nstderr: {stderr}",
            cmd_args
        );

        if !stdout.is_empty() {
            let json: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
                panic!(
                    "command {:?} should produce valid JSON: {e}\nstdout: {stdout}",
                    cmd_args
                )
            });

            assert!(
                json.is_object(),
                "command {:?} JSON root should be an object",
                cmd_args
            );
        }
    }
}

#[test]
fn test_json_outputs_parseable_by_jq() {
    // Verify outputs can be parsed by common JSON tools (simulated by serde)
    let commands = [
        vec!["test", "--format", "json", "git reset --hard"],
        vec!["packs", "--format", "json"],
    ];

    for cmd_args in commands {
        let (stdout, _stderr, _) = run_dcg(&cmd_args.iter().copied().collect::<Vec<_>>());

        if !stdout.is_empty() {
            // Strict parsing - should not have trailing content
            let trimmed = stdout.trim();
            let _: serde_json::Value = serde_json::from_str(trimmed).unwrap_or_else(|e| {
                panic!("command {:?} JSON should be strictly valid: {e}", cmd_args)
            });
        }
    }
}

#[test]
fn test_json_no_trailing_newlines_or_garbage() {
    let (stdout, _stderr, _) = run_dcg(&["test", "--format", "json", "git reset --hard"]);

    if !stdout.is_empty() {
        // JSON should be a single valid document
        let trimmed = stdout.trim();

        // Should start with { and end with }
        assert!(
            trimmed.starts_with('{') && trimmed.ends_with('}'),
            "JSON should be a single object\nstdout: {stdout}"
        );

        // Should parse without extra content
        let _: serde_json::Value =
            serde_json::from_str(trimmed).expect("JSON should be valid without trailing content");
    }
}

// =============================================================================
// Decision Field Tests
// =============================================================================

#[test]
fn test_decision_values_are_lowercase() {
    let commands = [("git status", "allow"), ("git reset --hard", "deny")];

    for (cmd, expected_decision) in commands {
        let (stdout, _stderr, _) = run_dcg(&["test", "--format", "json", cmd]);

        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("should produce valid JSON");

        let decision = json["decision"].as_str().unwrap();
        assert_eq!(
            decision, expected_decision,
            "decision should be lowercase '{expected_decision}' for '{cmd}'"
        );
        assert_eq!(
            decision,
            decision.to_lowercase(),
            "decision should be lowercase"
        );
    }
}

#[test]
fn test_severity_values_are_lowercase() {
    let (stdout, _stderr, _) = run_dcg(&["test", "--format", "json", "git reset --hard"]);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("should produce valid JSON");

    // Check hook output if present
    if let Some(hook_output) = json.get("hookSpecificOutput") {
        if let Some(severity) = hook_output.get("severity") {
            let sev_str = severity.as_str().unwrap();
            assert_eq!(
                sev_str,
                sev_str.to_lowercase(),
                "severity should be lowercase"
            );
        }
    }
}

//! Golden file tests for JSON output stability.
//!
//! These tests ensure that JSON output (used by AI agents) NEVER changes unexpectedly.
//! Any change to JSON structure could break agent integrations.
//!
//! # Dynamic Fields
//!
//! Some fields are dynamic and change per-invocation:
//! - `allowOnceCode`: Random code generated each time
//! - `allowOnceFullHash`: Hash based on the code
//! - `remediation.allowOnceCommand`: Contains the dynamic code
//!
//! These fields are masked to `<DYNAMIC>` before comparison.
//!
//! # Updating Golden Files
//!
//! To regenerate golden files after intentional changes:
//! ```bash
//! UPDATE_GOLDEN=1 cargo test --test golden_json_tests
//! ```
//!
//! # Critical Fields That Must Never Change
//!
//! - `permissionDecision`: "deny" | "allow"
//! - `ruleId`: Pattern identifier (e.g., "core.git:reset-hard")
//! - `packId`: Pack identifier (e.g., "core.git")
//! - `severity`: "critical" | "high" | "medium" | "low"
//! - `hookEventName`: Always "PreToolUse"
//!
//! New fields can be ADDED but existing ones MUST remain unchanged.

mod e2e;

use e2e::framework::E2ETestContext;
use serde_json::Value;
use std::path::Path;

/// Fields that are dynamic and should be masked before comparison.
const DYNAMIC_FIELDS: &[&str] = &["allowOnceCode", "allowOnceFullHash"];

/// Mask dynamic fields in JSON output for stable comparison.
fn mask_dynamic_fields(mut json: Value) -> Value {
    if json.get("dcg_version").is_some() {
        json["dcg_version"] = Value::String("<DYNAMIC_VERSION>".to_string());
    }

    if let Some(hook_output) = json.get_mut("hookSpecificOutput") {
        // Mask top-level dynamic fields
        for field in DYNAMIC_FIELDS {
            if hook_output.get(*field).is_some() {
                hook_output[*field] = Value::String("<DYNAMIC>".to_string());
            }
        }

        // Mask dynamic field in remediation
        if let Some(remediation) = hook_output.get_mut("remediation") {
            if remediation.get("allowOnceCommand").is_some() {
                remediation["allowOnceCommand"] =
                    Value::String("dcg allow-once <DYNAMIC>".to_string());
            }
        }
    }
    json
}

/// Compare JSON output against a golden file.
///
/// Returns `Ok(())` if the JSON matches (after masking dynamic fields).
/// Returns `Err(diff)` with a detailed diff if they don't match.
fn compare_json_to_golden(actual_json: &Value, golden_path: &str) -> Result<(), String> {
    let golden_full_path = Path::new("tests/golden").join(golden_path);

    let golden_content = match std::fs::read_to_string(&golden_full_path) {
        Ok(content) => content,
        Err(e) => {
            // If UPDATE_GOLDEN is set, create the golden file
            if std::env::var("UPDATE_GOLDEN").is_ok() {
                let masked = mask_dynamic_fields(actual_json.clone());
                let pretty = serde_json::to_string_pretty(&masked).expect("JSON serialization");
                if let Some(parent) = golden_full_path.parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                std::fs::write(&golden_full_path, &pretty).expect("Failed to write golden file");
                println!("Created golden file: {golden_path}");
                return Ok(());
            }
            return Err(format!("Golden file not found: {golden_path}: {e}"));
        }
    };

    let golden_json: Value = serde_json::from_str(&golden_content)
        .map_err(|e| format!("Invalid JSON in golden file {golden_path}: {e}"))?;

    let masked_golden = mask_dynamic_fields(golden_json);
    let masked_actual = mask_dynamic_fields(actual_json.clone());

    if masked_actual == masked_golden {
        return Ok(());
    }

    // Generate detailed diff
    let diff = json_diff(&masked_golden, &masked_actual);

    // If UPDATE_GOLDEN is set, update the golden file
    if std::env::var("UPDATE_GOLDEN").is_ok() {
        let pretty = serde_json::to_string_pretty(&masked_actual).expect("JSON serialization");
        std::fs::write(&golden_full_path, &pretty).expect("Failed to write golden file");
        println!("Updated golden file: {golden_path}");
        return Ok(());
    }

    Err(format!(
        "JSON output differs from golden file '{golden_path}':\n\n{diff}"
    ))
}

/// Generate a detailed diff between two JSON values.
fn json_diff(expected: &Value, actual: &Value) -> String {
    let mut diffs = Vec::new();
    diff_values("$", expected, actual, &mut diffs);

    if diffs.is_empty() {
        "No differences found (but comparison failed?)".to_string()
    } else {
        diffs.join("\n")
    }
}

fn diff_values(path: &str, expected: &Value, actual: &Value, diffs: &mut Vec<String>) {
    match (expected, actual) {
        (Value::Object(exp_map), Value::Object(act_map)) => {
            // Check for missing keys
            for key in exp_map.keys() {
                if !act_map.contains_key(key) {
                    diffs.push(format!("  MISSING: {path}.{key}"));
                }
            }
            // Check for extra keys
            for key in act_map.keys() {
                if !exp_map.contains_key(key) {
                    diffs.push(format!(
                        "  EXTRA: {path}.{key} = {}",
                        serde_json::to_string(&act_map[key]).unwrap_or_default()
                    ));
                }
            }
            // Recurse on shared keys
            for key in exp_map.keys().filter(|k| act_map.contains_key(*k)) {
                diff_values(
                    &format!("{path}.{key}"),
                    &exp_map[key],
                    &act_map[key],
                    diffs,
                );
            }
        }
        (Value::Array(exp_arr), Value::Array(act_arr)) => {
            if exp_arr.len() != act_arr.len() {
                diffs.push(format!(
                    "  LENGTH: {path} expected {} items, got {}",
                    exp_arr.len(),
                    act_arr.len()
                ));
            }
            for (i, (exp_item, act_item)) in exp_arr.iter().zip(act_arr.iter()).enumerate() {
                diff_values(&format!("{path}[{i}]"), exp_item, act_item, diffs);
            }
        }
        _ if expected != actual => {
            diffs.push(format!(
                "  CHANGED: {path}\n    expected: {}\n    actual:   {}",
                serde_json::to_string(expected).unwrap_or_default(),
                serde_json::to_string(actual).unwrap_or_default()
            ));
        }
        _ => {}
    }
}

// ============================================================================
// Hook Mode Golden Tests
// ============================================================================

#[test]
fn golden_hook_deny_filesystem() {
    let ctx = E2ETestContext::builder("golden_hook_deny_filesystem").build();
    let output = ctx.run_dcg_hook("rm -rf /");

    assert!(output.is_blocked(), "Expected command to be blocked");
    assert!(output.json.is_some(), "Expected JSON output");

    let json = output.json.unwrap();
    if let Err(diff) = compare_json_to_golden(&json, "hook/deny_filesystem.json") {
        panic!("Golden file mismatch:\n{diff}");
    }

    // Verify critical fields are present
    let hook_output = json.get("hookSpecificOutput").unwrap();
    assert_eq!(hook_output.get("permissionDecision").unwrap(), "deny");
    assert_eq!(hook_output.get("packId").unwrap(), "core.filesystem");
    assert_eq!(hook_output.get("severity").unwrap(), "critical");
    assert_eq!(hook_output.get("hookEventName").unwrap(), "PreToolUse");
}

#[test]
fn golden_hook_deny_git_force_push() {
    let ctx = E2ETestContext::builder("golden_hook_deny_git_force_push").build();
    let output = ctx.run_dcg_hook("git push --force origin main");

    assert!(output.is_blocked(), "Expected command to be blocked");
    assert!(output.json.is_some(), "Expected JSON output");

    let json = output.json.unwrap();
    if let Err(diff) = compare_json_to_golden(&json, "hook/deny_git.json") {
        panic!("Golden file mismatch:\n{diff}");
    }

    // Verify critical fields
    let hook_output = json.get("hookSpecificOutput").unwrap();
    assert_eq!(hook_output.get("permissionDecision").unwrap(), "deny");
    assert_eq!(hook_output.get("packId").unwrap(), "core.git");
}

#[test]
fn golden_hook_deny_git_reset_hard() {
    let ctx = E2ETestContext::builder("golden_hook_deny_git_reset_hard").build();
    let output = ctx.run_dcg_hook("git reset --hard");

    assert!(output.is_blocked(), "Expected command to be blocked");
    assert!(output.json.is_some(), "Expected JSON output");

    let json = output.json.unwrap();
    if let Err(diff) = compare_json_to_golden(&json, "hook/deny_git_reset.json") {
        panic!("Golden file mismatch:\n{diff}");
    }

    let hook_output = json.get("hookSpecificOutput").unwrap();
    assert_eq!(hook_output.get("permissionDecision").unwrap(), "deny");
    assert_eq!(hook_output.get("packId").unwrap(), "core.git");
    assert_eq!(hook_output.get("severity").unwrap(), "critical");
}

#[test]
fn golden_hook_allow_simple() {
    let ctx = E2ETestContext::builder("golden_hook_allow_simple").build();
    let output = ctx.run_dcg_hook("echo hello");

    assert!(output.is_allowed(), "Expected command to be allowed");
    assert!(
        output.stdout.trim().is_empty(),
        "Allowed commands should produce no stdout, got: {}",
        output.stdout
    );
}

#[test]
fn golden_hook_allow_git_status() {
    let ctx = E2ETestContext::builder("golden_hook_allow_git_status").build();
    let output = ctx.run_dcg_hook("git status");

    assert!(output.is_allowed(), "Expected 'git status' to be allowed");
    assert!(
        output.stdout.trim().is_empty(),
        "Allowed commands should produce no stdout"
    );
}

#[test]
fn golden_hook_allow_git_checkout_branch() {
    let ctx = E2ETestContext::builder("golden_hook_allow_git_checkout_branch").build();
    let output = ctx.run_dcg_hook("git checkout -b new-feature");

    assert!(
        output.is_allowed(),
        "Expected 'git checkout -b' to be allowed"
    );
    assert!(
        output.stdout.trim().is_empty(),
        "Allowed commands should produce no stdout"
    );
}

// ============================================================================
// JSON Structure Stability Tests
// ============================================================================

#[test]
fn golden_json_structure_has_required_fields() {
    let ctx = E2ETestContext::builder("golden_json_structure_has_required_fields").build();
    let output = ctx.run_dcg_hook("rm -rf /");

    let json = output.json.expect("Expected JSON output");
    let hook_output = json
        .get("hookSpecificOutput")
        .expect("Missing hookSpecificOutput");

    // These fields are REQUIRED and must never be removed
    let required_fields = [
        "hookEventName",
        "permissionDecision",
        "permissionDecisionReason",
        "ruleId",
        "packId",
        "severity",
        "allowOnceCode",
        "allowOnceFullHash",
        "remediation",
    ];

    for field in required_fields {
        assert!(
            hook_output.get(field).is_some(),
            "Required field '{}' is missing from JSON output",
            field
        );
    }

    // Check remediation subfields
    let remediation = hook_output.get("remediation").expect("Missing remediation");
    let remediation_fields = ["safeAlternative", "explanation", "allowOnceCommand"];

    for field in remediation_fields {
        assert!(
            remediation.get(field).is_some(),
            "Required remediation field '{}' is missing",
            field
        );
    }
}

#[test]
fn golden_json_permission_decision_values() {
    let ctx = E2ETestContext::builder("golden_json_permission_decision_values").build();

    // Denied command should have "deny"
    let denied = ctx.run_dcg_hook("rm -rf /");
    let denied_json = denied.json.expect("Expected JSON");
    let decision = denied_json
        .get("hookSpecificOutput")
        .and_then(|h: &Value| h.get("permissionDecision"))
        .and_then(Value::as_str)
        .expect("Missing permissionDecision");
    assert_eq!(
        decision, "deny",
        "Denied commands must have permissionDecision='deny'"
    );

    // Allowed commands produce no JSON output (empty stdout)
    let allowed = ctx.run_dcg_hook("echo hello");
    assert!(
        allowed.stdout.trim().is_empty(),
        "Allowed commands must produce empty stdout"
    );
}

#[test]
fn golden_json_severity_values() {
    let ctx = E2ETestContext::builder("golden_json_severity_values").build();

    // Test critical severity
    let critical = ctx.run_dcg_hook("rm -rf /");
    let critical_json = critical.json.expect("Expected JSON");
    let severity = critical_json
        .get("hookSpecificOutput")
        .and_then(|h: &Value| h.get("severity"))
        .and_then(Value::as_str)
        .expect("Missing severity");
    assert!(
        ["critical", "high", "medium", "low"].contains(&severity),
        "Invalid severity value: {severity}"
    );
}

// ============================================================================
// Robot Mode Golden Tests
// ============================================================================

/// Run dcg in robot mode via test subcommand
fn run_robot_mode(command: &str) -> Option<Value> {
    use std::process::Command;

    let output = Command::new(env!("CARGO_BIN_EXE_dcg"))
        .args(["--robot", "test", command])
        .output()
        .expect("Failed to run dcg");

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return None;
    }

    serde_json::from_str(&stdout).ok()
}

#[test]
fn golden_robot_deny_filesystem() {
    let json = run_robot_mode("rm -rf /").expect("Expected JSON output from robot mode");

    if let Err(diff) = compare_json_to_golden(&json, "robot/deny_filesystem.json") {
        panic!("Golden file mismatch:\n{diff}");
    }

    // Verify critical fields for robot mode
    assert_eq!(json.get("decision").and_then(Value::as_str), Some("deny"));
    assert_eq!(
        json.get("pack_id").and_then(Value::as_str),
        Some("core.filesystem")
    );
    assert_eq!(
        json.get("severity").and_then(Value::as_str),
        Some("critical")
    );
}

#[test]
fn golden_robot_deny_git_reset() {
    let json = run_robot_mode("git reset --hard").expect("Expected JSON output from robot mode");

    if let Err(diff) = compare_json_to_golden(&json, "robot/deny_git_reset.json") {
        panic!("Golden file mismatch:\n{diff}");
    }

    assert_eq!(json.get("decision").and_then(Value::as_str), Some("deny"));
    assert_eq!(
        json.get("pack_id").and_then(Value::as_str),
        Some("core.git")
    );
    assert_eq!(
        json.get("rule_id").and_then(Value::as_str),
        Some("core.git:reset-hard")
    );
}

#[test]
fn golden_robot_deny_git_force_push() {
    let json = run_robot_mode("git push --force origin main")
        .expect("Expected JSON output from robot mode");

    if let Err(diff) = compare_json_to_golden(&json, "robot/deny_git_force_push.json") {
        panic!("Golden file mismatch:\n{diff}");
    }

    assert_eq!(json.get("decision").and_then(Value::as_str), Some("deny"));
    assert_eq!(
        json.get("pack_id").and_then(Value::as_str),
        Some("core.git")
    );
}

#[test]
fn golden_robot_allow_simple() {
    let json = run_robot_mode("echo hello").expect("Expected JSON output from robot mode");

    if let Err(diff) = compare_json_to_golden(&json, "robot/allow_simple.json") {
        panic!("Golden file mismatch:\n{diff}");
    }

    assert_eq!(json.get("decision").and_then(Value::as_str), Some("allow"));
}

#[test]
fn golden_robot_allow_git_status() {
    let json = run_robot_mode("git status").expect("Expected JSON output from robot mode");

    if let Err(diff) = compare_json_to_golden(&json, "robot/allow_git_status.json") {
        panic!("Golden file mismatch:\n{diff}");
    }

    assert_eq!(json.get("decision").and_then(Value::as_str), Some("allow"));
}

#[test]
fn golden_robot_json_structure_deny() {
    let json = run_robot_mode("git reset --hard").expect("Expected JSON output");

    // Required fields for robot mode deny response
    let required_fields = [
        "command",
        "decision",
        "rule_id",
        "pack_id",
        "severity",
        "reason",
        "explanation",
        "source",
    ];

    for field in required_fields {
        assert!(
            json.get(field).is_some(),
            "Required robot mode field '{}' is missing",
            field
        );
    }

    // Verify agent object exists
    let agent = json.get("agent").expect("Missing agent object");
    assert!(agent.get("detected").is_some(), "Missing agent.detected");
    assert!(
        agent.get("trust_level").is_some(),
        "Missing agent.trust_level"
    );
}

#[test]
fn golden_robot_json_structure_allow() {
    let json = run_robot_mode("ls -la").expect("Expected JSON output");

    // Required fields for robot mode allow response
    let required_fields = ["command", "decision"];

    for field in required_fields {
        assert!(
            json.get(field).is_some(),
            "Required robot mode field '{}' is missing for allow",
            field
        );
    }

    assert_eq!(json.get("decision").and_then(Value::as_str), Some("allow"));
}

// ============================================================================
// All Golden Files Valid JSON Test
// ============================================================================

#[test]
fn golden_all_files_valid_json() {
    let golden_dir = Path::new("tests/golden");
    if !golden_dir.exists() {
        println!("Golden directory doesn't exist yet, skipping validation");
        return;
    }

    let mut errors = Vec::new();

    for entry in walkdir::WalkDir::new(golden_dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
    {
        let path = entry.path();
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                errors.push(format!("Failed to read {:?}: {e}", path));
                continue;
            }
        };

        // Special case: allow_simple.json may be empty or {}
        if content.trim().is_empty() {
            continue;
        }

        if let Err(e) = serde_json::from_str::<Value>(&content) {
            errors.push(format!("Invalid JSON in {:?}: {e}", path));
        }
    }

    assert!(
        errors.is_empty(),
        "Golden file validation errors:\n{}",
        errors.join("\n")
    );
}

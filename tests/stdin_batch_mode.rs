//! End-to-end tests for stdin batch mode (`dcg hook --batch`).
//!
//! These tests verify that the batch mode correctly processes multiple commands
//! from stdin, maintains order, handles malformed input, and performs well at scale.
//!
//! # Running
//!
//! ```bash
//! cargo test --test stdin_batch_mode
//! ```

use std::io::Write;
use std::process::{Command, Stdio};

/// Path to the dcg binary (built in debug mode for tests).
fn dcg_binary() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // Remove test binary name
    path.pop(); // Remove deps/
    path.push("dcg");
    path
}

/// Run dcg in batch hook mode with the given JSONL input.
fn run_dcg_batch(input: &str) -> std::process::Output {
    run_dcg_batch_with_args(input, &[])
}

/// Run dcg in batch hook mode with additional CLI arguments.
fn run_dcg_batch_with_args(input: &str, extra_args: &[&str]) -> std::process::Output {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    std::fs::create_dir_all(temp.path().join(".git")).expect("failed to create .git dir");

    let home_dir = temp.path().join("home");
    let xdg_config_dir = temp.path().join("xdg_config");
    std::fs::create_dir_all(&home_dir).expect("failed to create HOME dir");
    std::fs::create_dir_all(&xdg_config_dir).expect("failed to create XDG_CONFIG_HOME dir");

    let mut args = vec!["hook", "--batch"];
    args.extend(extra_args);

    let mut cmd = Command::new(dcg_binary());
    cmd.env_clear()
        .env("HOME", &home_dir)
        .env("XDG_CONFIG_HOME", &xdg_config_dir)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_PACKS", "core.git,core.filesystem")
        .current_dir(temp.path())
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("failed to spawn dcg batch mode");

    {
        let stdin = child.stdin.as_mut().expect("failed to open stdin");
        stdin
            .write_all(input.as_bytes())
            .expect("failed to write batch input");
    }

    child.wait_with_output().expect("failed to wait for dcg")
}

/// Parse JSONL output into a vector of JSON values.
fn parse_jsonl_output(output: &str) -> Vec<serde_json::Value> {
    output
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str(line).expect("failed to parse JSONL line"))
        .collect()
}

// ============================================================================
// Test: Batch processes multiple commands correctly
// ============================================================================

#[test]
fn test_batch_processes_multiple_commands() {
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}
{"tool_name":"Bash","tool_input":{"command":"git status"}}
{"tool_name":"Bash","tool_input":{"command":"git reset --hard"}}
{"tool_name":"Bash","tool_input":{"command":"ls -la"}}
"#;

    let output = run_dcg_batch(input);
    assert!(output.status.success(), "Batch mode should exit successfully");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let results = parse_jsonl_output(&stdout);

    assert_eq!(results.len(), 4, "Should have 4 results");

    // rm -rf / should be denied
    assert_eq!(results[0]["decision"], "deny");
    assert_eq!(results[0]["index"], 0);

    // git status should be allowed
    assert_eq!(results[1]["decision"], "allow");
    assert_eq!(results[1]["index"], 1);

    // git reset --hard should be denied
    assert_eq!(results[2]["decision"], "deny");
    assert_eq!(results[2]["index"], 2);
    assert!(results[2]["rule_id"]
        .as_str()
        .unwrap_or("")
        .contains("reset-hard"));

    // ls -la should be allowed
    assert_eq!(results[3]["decision"], "allow");
    assert_eq!(results[3]["index"], 3);
}

// ============================================================================
// Test: Batch maintains output order matching input order
// ============================================================================

#[test]
fn test_batch_maintains_order() {
    // Create a sequence of commands with varying evaluation complexity
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"echo 1"}}
{"tool_name":"Bash","tool_input":{"command":"git reset --hard HEAD~5"}}
{"tool_name":"Bash","tool_input":{"command":"echo 2"}}
{"tool_name":"Bash","tool_input":{"command":"rm -rf /home"}}
{"tool_name":"Bash","tool_input":{"command":"echo 3"}}
"#;

    let output = run_dcg_batch(input);
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let results = parse_jsonl_output(&stdout);

    assert_eq!(results.len(), 5);

    // Verify index ordering is preserved
    for (i, result) in results.iter().enumerate() {
        assert_eq!(
            result["index"], i,
            "Result at position {} should have index {}",
            i, i
        );
    }

    // Verify decisions match expected pattern
    assert_eq!(results[0]["decision"], "allow"); // echo 1
    assert_eq!(results[1]["decision"], "deny"); // git reset --hard
    assert_eq!(results[2]["decision"], "allow"); // echo 2
    assert_eq!(results[3]["decision"], "deny"); // rm -rf /home
    assert_eq!(results[4]["decision"], "allow"); // echo 3
}

// ============================================================================
// Test: Batch handles malformed lines with --continue-on-error
// ============================================================================

#[test]
fn test_batch_handles_malformed_lines_with_continue() {
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"echo before"}}
not valid json at all
{"tool_name":"Bash","tool_input":{"command":"echo after"}}
{"malformed": "missing tool_name and tool_input"}
{"tool_name":"Bash","tool_input":{"command":"echo final"}}
"#;

    let output = run_dcg_batch_with_args(input, &["--continue-on-error"]);
    assert!(
        output.status.success(),
        "Batch mode with --continue-on-error should exit successfully"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let results = parse_jsonl_output(&stdout);

    assert_eq!(results.len(), 5, "Should have 5 results (including errors)");

    // First command should succeed
    assert_eq!(results[0]["decision"], "allow");
    assert_eq!(results[0]["index"], 0);

    // Second line (malformed) should have error
    assert_eq!(results[1]["decision"], "error");
    assert_eq!(results[1]["index"], 1);
    assert!(results[1]["error"].is_string());

    // Third command should succeed
    assert_eq!(results[2]["decision"], "allow");
    assert_eq!(results[2]["index"], 2);

    // Fourth line (valid JSON but missing fields) should be skipped
    assert_eq!(results[3]["decision"], "skip");
    assert_eq!(results[3]["index"], 3);

    // Fifth command should succeed
    assert_eq!(results[4]["decision"], "allow");
    assert_eq!(results[4]["index"], 4);
}

// ============================================================================
// Test: Batch fails fast on malformed input without --continue-on-error
// ============================================================================

#[test]
fn test_batch_fails_on_malformed_without_continue() {
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"echo before"}}
not valid json
{"tool_name":"Bash","tool_input":{"command":"echo after"}}
"#;

    let output = run_dcg_batch(input);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let results = parse_jsonl_output(&stdout);

    // Should have at least the first result before failing
    assert!(!results.is_empty());
    assert_eq!(results[0]["decision"], "allow");

    // The second result should be an error (parse failure)
    if results.len() > 1 {
        assert_eq!(results[1]["decision"], "error");
    }
}

// ============================================================================
// Test: Batch handles empty commands gracefully
// ============================================================================

#[test]
fn test_batch_handles_empty_commands() {
    let input = r#"{"tool_name":"Bash","tool_input":{"command":""}}
{"tool_name":"Bash","tool_input":{"command":"   "}}
{"tool_name":"Bash","tool_input":{"command":"echo hello"}}
"#;

    let output = run_dcg_batch_with_args(input, &["--continue-on-error"]);
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let results = parse_jsonl_output(&stdout);

    assert_eq!(results.len(), 3);

    // Empty command is skipped, whitespace-only is allowed
    assert_eq!(
        results[0]["decision"], "skip",
        "Empty command should be skipped"
    );
    assert_eq!(
        results[1]["decision"], "allow",
        "Whitespace command should be allowed"
    );
    assert_eq!(results[2]["decision"], "allow");
}

// ============================================================================
// Test: Batch handles non-Bash tools gracefully
// ============================================================================

#[test]
fn test_batch_handles_non_bash_tools() {
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"echo bash"}}
{"tool_name":"Read","tool_input":{"path":"/etc/passwd"}}
{"tool_name":"Write","tool_input":{"path":"/tmp/test","content":"hello"}}
{"tool_name":"Bash","tool_input":{"command":"echo bash again"}}
"#;

    let output = run_dcg_batch_with_args(input, &["--continue-on-error"]);
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let results = parse_jsonl_output(&stdout);

    assert_eq!(results.len(), 4);

    // Bash commands should be evaluated
    assert_eq!(results[0]["decision"], "allow");
    assert_eq!(results[3]["decision"], "allow");

    // Non-Bash tools should be skipped (not evaluated by dcg)
    assert_eq!(results[1]["decision"], "skip");
    assert_eq!(results[2]["decision"], "skip");
}

// ============================================================================
// Test: Batch includes rule_id and pack_id for denials
// ============================================================================

#[test]
fn test_batch_includes_rule_metadata_for_denials() {
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"git reset --hard"}}
{"tool_name":"Bash","tool_input":{"command":"git push --force origin main"}}
"#;

    let output = run_dcg_batch(input);
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let results = parse_jsonl_output(&stdout);

    assert_eq!(results.len(), 2);

    // Check git reset --hard
    assert_eq!(results[0]["decision"], "deny");
    assert!(results[0]["rule_id"].is_string());
    assert!(results[0]["pack_id"].is_string());
    assert!(results[0]["rule_id"]
        .as_str()
        .unwrap()
        .contains("core.git"));

    // Check git push --force
    assert_eq!(results[1]["decision"], "deny");
    assert!(results[1]["rule_id"].is_string());
    assert!(results[1]["pack_id"].is_string());
}

// ============================================================================
// Test: Batch performance at scale
// ============================================================================

#[test]
fn test_batch_performance_at_scale() {
    // Generate 100 commands (mix of allowed and denied)
    let mut input = String::new();
    for i in 0..100 {
        if i % 10 == 0 {
            // Every 10th command is destructive (git reset --hard)
            input.push_str(&format!(
                r#"{{"tool_name":"Bash","tool_input":{{"command":"git reset --hard HEAD~{i}"}}}}"#
            ));
        } else {
            input.push_str(&format!(
                r#"{{"tool_name":"Bash","tool_input":{{"command":"echo {i}"}}}}"#
            ));
        }
        input.push('\n');
    }

    let start = std::time::Instant::now();
    let output = run_dcg_batch(&input);
    let duration = start.elapsed();

    assert!(output.status.success(), "Batch should complete successfully");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let results = parse_jsonl_output(&stdout);

    assert_eq!(results.len(), 100, "Should have 100 results");

    // Verify order is maintained
    for (i, result) in results.iter().enumerate() {
        assert_eq!(result["index"], i, "Index should match position");
    }

    // Count denials (should be 10 - every 10th command)
    let denials: Vec<_> = results.iter().filter(|r| r["decision"] == "deny").collect();
    assert_eq!(denials.len(), 10, "Should have 10 denials");

    // Performance check: 100 commands should complete in reasonable time
    // This is a soft check - CI environments may be slower
    println!("Batch processing 100 commands took {:?}", duration);
    assert!(
        duration.as_secs() < 30,
        "Batch should complete within 30 seconds"
    );
}

// ============================================================================
// Test: Batch handles Unicode commands
// ============================================================================

#[test]
fn test_batch_handles_unicode() {
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"echo '你好世界'"}}
{"tool_name":"Bash","tool_input":{"command":"echo 'Привет мир'"}}
{"tool_name":"Bash","tool_input":{"command":"echo '🚀 launch'"}}
"#;

    let output = run_dcg_batch(input);
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let results = parse_jsonl_output(&stdout);

    assert_eq!(results.len(), 3);
    for result in &results {
        assert_eq!(result["decision"], "allow");
    }
}

// ============================================================================
// Test: Batch handles very long commands
// ============================================================================

#[test]
fn test_batch_handles_long_commands() {
    // Create a command with a very long argument
    let long_arg = "x".repeat(10_000);
    let input = format!(
        r#"{{"tool_name":"Bash","tool_input":{{"command":"echo {long_arg}"}}}}
{{"tool_name":"Bash","tool_input":{{"command":"echo short"}}}}
"#
    );

    let output = run_dcg_batch_with_args(&input, &["--continue-on-error"]);
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let results = parse_jsonl_output(&stdout);

    assert_eq!(results.len(), 2);
    // Long commands should either be allowed or handled gracefully
    assert!(
        results[0]["decision"] == "allow" || results[0]["decision"] == "error",
        "Long command should be handled"
    );
    assert_eq!(results[1]["decision"], "allow");
}

// ============================================================================
// Test: Batch parallel mode maintains order
// ============================================================================

#[test]
fn test_batch_parallel_maintains_order() {
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"echo 0"}}
{"tool_name":"Bash","tool_input":{"command":"echo 1"}}
{"tool_name":"Bash","tool_input":{"command":"echo 2"}}
{"tool_name":"Bash","tool_input":{"command":"echo 3"}}
{"tool_name":"Bash","tool_input":{"command":"echo 4"}}
{"tool_name":"Bash","tool_input":{"command":"echo 5"}}
{"tool_name":"Bash","tool_input":{"command":"echo 6"}}
{"tool_name":"Bash","tool_input":{"command":"echo 7"}}
{"tool_name":"Bash","tool_input":{"command":"echo 8"}}
{"tool_name":"Bash","tool_input":{"command":"echo 9"}}
"#;

    let output = run_dcg_batch_with_args(input, &["--parallel"]);
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let results = parse_jsonl_output(&stdout);

    assert_eq!(results.len(), 10);

    // Verify order is maintained even with parallel processing
    for (i, result) in results.iter().enumerate() {
        assert_eq!(
            result["index"], i,
            "Parallel results should maintain input order"
        );
    }
}

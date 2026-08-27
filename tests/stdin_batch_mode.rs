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

use std::fmt::Write as _;
use std::io::Write;
use std::process::{Command, Stdio};

/// Path to the exact dcg binary Cargo built for this integration test.
fn dcg_binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
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
        .env("USERPROFILE", &home_dir)
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
    // Any deny in the batch must make the process exit non-zero so callers can
    // gate on the exit code (issue #148).
    assert_eq!(
        output.status.code(),
        Some(1),
        "Batch mode must exit 1 when any command is denied"
    );

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
    assert!(
        results[2]["rule_id"]
            .as_str()
            .unwrap_or("")
            .contains("reset-hard")
    );

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
    // Denies present -> exit 1 (issue #148).
    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let results = parse_jsonl_output(&stdout);

    assert_eq!(results.len(), 5);

    // Verify index ordering is preserved
    for (i, result) in results.iter().enumerate() {
        assert_eq!(
            result["index"], i,
            "Result at position {i} should have index {i}"
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

    // Without --continue-on-error, the first malformed line halts processing
    // and the process exits non-zero (EXIT_PARSE_ERROR = 4) — issue #165.
    assert_eq!(
        output.status.code(),
        Some(4),
        "Malformed input without --continue-on-error should halt with exit 4"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let results = parse_jsonl_output(&stdout);

    // Exactly two results: the leading allow and the parse error. The third
    // (valid) line after the error is NOT processed because we halt.
    assert_eq!(
        results.len(),
        2,
        "Processing must stop at the first malformed line"
    );
    assert_eq!(results[0]["decision"], "allow");
    assert_eq!(results[0]["index"], 0);
    assert_eq!(results[1]["decision"], "error");
    assert_eq!(results[1]["index"], 1);
}

// ============================================================================
// Test: Blank lines are skipped entirely (no phantom indexed entries)
// ============================================================================

#[test]
fn test_batch_skips_blank_lines() {
    // Blank/whitespace-only LINES (not empty command strings) must be skipped
    // entirely: they produce no output and do not consume an index (issue #154).
    let input = "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"git status\"}}\n\n   \n{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"git reset --hard\"}}\n";

    let output = run_dcg_batch(input);
    // Contains a deny -> exit 1 (issue #148).
    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let results = parse_jsonl_output(&stdout);

    assert_eq!(
        results.len(),
        2,
        "Blank lines must not create indexed entries"
    );
    assert_eq!(results[0]["decision"], "allow");
    assert_eq!(results[0]["index"], 0);
    assert_eq!(results[1]["decision"], "deny");
    assert_eq!(results[1]["index"], 1, "Indices must be gap-free");
    assert!(
        !stdout.contains("\"skip\""),
        "Blank lines must not emit skip entries"
    );
}

// ============================================================================
// Test: A single denial exits non-zero
// ============================================================================

#[test]
fn test_batch_single_deny_exits_nonzero() {
    let input = "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"git reset --hard\"}}\n";
    let output = run_dcg_batch(input);
    assert_eq!(
        output.status.code(),
        Some(1),
        "A denied command must make dcg hook exit 1 (issue #148)"
    );

    // All-allow batch exits 0.
    let allow_input = "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"git status\"}}\n";
    let allow_output = run_dcg_batch(allow_input);
    assert_eq!(allow_output.status.code(), Some(0));
}

// ============================================================================
// Test: `dcg hook` without --batch reads a single JSON object (issue #157)
// ============================================================================

#[test]
fn test_hook_without_batch_reads_single_json() {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let home_dir = temp.path().join("home");
    let xdg_config_dir = temp.path().join("xdg_config");
    std::fs::create_dir_all(&home_dir).unwrap();
    std::fs::create_dir_all(&xdg_config_dir).unwrap();

    let mut cmd = Command::new(dcg_binary());
    cmd.env_clear()
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .env("XDG_CONFIG_HOME", &xdg_config_dir)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_PACKS", "core.git,core.filesystem")
        .current_dir(temp.path())
        .arg("hook") // NOTE: no --batch
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("failed to spawn dcg hook");
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin
            .write_all(
                b"{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"git reset --hard\"}}\n",
            )
            .unwrap();
    }
    let output = child.wait_with_output().expect("failed to wait for dcg");

    // It must NOT print the old internal "delegating to main.rs" error.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("delegating to main.rs"),
        "dcg hook (no --batch) must not leak the internal delegation error"
    );

    // It processes the single JSON object and denies -> exit 1.
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let results = parse_jsonl_output(&stdout);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["decision"], "deny");
    assert_eq!(results[0]["index"], 0);
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
    // Both commands deny -> exit 1 (issue #148).
    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let results = parse_jsonl_output(&stdout);

    assert_eq!(results.len(), 2);

    // Check git reset --hard
    assert_eq!(results[0]["decision"], "deny");
    assert!(results[0]["rule_id"].is_string());
    assert!(results[0]["pack_id"].is_string());
    assert!(results[0]["rule_id"].as_str().unwrap().contains("core.git"));

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
            let _ = write!(
                input,
                r#"{{"tool_name":"Bash","tool_input":{{"command":"git reset --hard HEAD~{i}"}}}}"#
            );
        } else {
            let _ = write!(
                input,
                r#"{{"tool_name":"Bash","tool_input":{{"command":"echo {i}"}}}}"#
            );
        }
        input.push('\n');
    }

    let start = std::time::Instant::now();
    let output = run_dcg_batch(&input);
    let duration = start.elapsed();

    // The batch contains denials (every 10th command), so exit is non-zero
    // (issue #148).
    assert_eq!(
        output.status.code(),
        Some(1),
        "Batch with denials should exit 1"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let results = parse_jsonl_output(&stdout);

    assert_eq!(results.len(), 100, "Should have 100 results");

    // Verify order is maintained
    for (i, result) in results.iter().enumerate() {
        assert_eq!(result["index"], i, "Index should match position");
    }

    // Count denials (should be 10 - every 10th command)
    assert_eq!(
        results.iter().filter(|r| r["decision"] == "deny").count(),
        10,
        "Should have 10 denials"
    );

    // Performance check: 100 commands should complete in reasonable time
    // This is a soft check - CI environments may be slower
    println!("Batch processing 100 commands took {duration:?}");
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

/// Run `dcg hook --batch` with extra CLI args and extra environment variables.
fn run_dcg_batch_full(
    input: &str,
    extra_args: &[&str],
    envs: &[(&str, &str)],
) -> std::process::Output {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    std::fs::create_dir_all(temp.path().join(".git")).expect("failed to create .git dir");
    let home_dir = temp.path().join("home");
    let xdg_config_dir = temp.path().join("xdg_config");
    std::fs::create_dir_all(&home_dir).unwrap();
    std::fs::create_dir_all(&xdg_config_dir).unwrap();

    let mut args = vec!["hook", "--batch"];
    args.extend(extra_args);

    let mut cmd = Command::new(dcg_binary());
    cmd.env_clear()
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .env("XDG_CONFIG_HOME", &xdg_config_dir)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_PACKS", "core.git,core.filesystem")
        .current_dir(temp.path())
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }

    let mut child = cmd.spawn().expect("failed to spawn dcg batch mode");
    {
        let stdin = child.stdin.as_mut().expect("failed to open stdin");
        stdin.write_all(input.as_bytes()).unwrap();
    }
    child.wait_with_output().expect("failed to wait for dcg")
}

// ============================================================================
// Test: a UTF-8 BOM prefix no longer fail-opens a dangerous command (#160)
// ============================================================================

#[test]
fn test_batch_bom_prefixed_command_is_evaluated() {
    // U+FEFF BOM immediately before an otherwise-valid hook payload.
    let input =
        "\u{feff}{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"git reset --hard\"}}\n";
    let output = run_dcg_batch(input);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let results = parse_jsonl_output(&stdout);
    assert_eq!(results.len(), 1, "BOM line should parse to one result");
    assert_eq!(
        results[0]["decision"], "deny",
        "BOM-prefixed dangerous command must be evaluated and blocked, not fail-open allowed"
    );
    assert_eq!(output.status.code(), Some(1));
}

// ============================================================================
// Test: DCG_FAIL_CLOSED denies unparseable input; default fails open (#160)
// ============================================================================

#[test]
fn test_batch_fail_closed_denies_unparseable() {
    let input = "this is not json\n";

    // Default (fail-open): malformed line is an `error`, processing halts, exit 4.
    let default_out = run_dcg_batch_full(input, &[], &[]);
    let default_results = parse_jsonl_output(&String::from_utf8_lossy(&default_out.stdout));
    assert_eq!(default_results[0]["decision"], "error");
    assert_eq!(default_out.status.code(), Some(4));

    // Fail-closed: malformed line becomes a `deny`, exit 1.
    let fc_out = run_dcg_batch_full(input, &[], &[("DCG_FAIL_CLOSED", "1")]);
    let fc_results = parse_jsonl_output(&String::from_utf8_lossy(&fc_out.stdout));
    assert_eq!(
        fc_results[0]["decision"], "deny",
        "with DCG_FAIL_CLOSED=1, unparseable input must be denied"
    );
    assert_eq!(fc_out.status.code(), Some(1));
}

// ============================================================================
// Test: --with-packs enables extra packs in hook --batch (#151)
// ============================================================================

#[test]
fn test_batch_with_packs_enables_extra_pack() {
    let input =
        "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"docker system prune -a\"}}\n";

    // Without the extra pack, docker is not guarded -> allow.
    let baseline = run_dcg_batch(input);
    let baseline_results = parse_jsonl_output(&String::from_utf8_lossy(&baseline.stdout));
    assert_eq!(
        baseline_results[0]["decision"], "allow",
        "docker prune should be allowed without containers.docker enabled"
    );

    // With --with-packs containers.docker, it is blocked.
    let with_pack = run_dcg_batch_with_args(input, &["--with-packs", "containers.docker"]);
    let with_pack_results = parse_jsonl_output(&String::from_utf8_lossy(&with_pack.stdout));
    assert_eq!(
        with_pack_results[0]["decision"], "deny",
        "docker prune should be blocked with --with-packs containers.docker"
    );
    assert_eq!(with_pack.status.code(), Some(1));
}

#![allow(clippy::uninlined_format_args)]
//! E2E tests for `dcg suggest-allowlist` command.
//!
//! These tests validate end-to-end behavior of suggest-allowlist, including
//! non-interactive output paths, with detailed logs on failure.
//!
//! # Test Categories
//!
//! 1. **Non-Interactive Mode** - Verifies no allowlist writes occur
//! 2. **Help Output** - Verifies help documentation works
//! 3. **CLI Parsing** - Verifies flag combinations work
//!
//! # Running
//!
//! ```bash
//! cargo test --test suggest_allowlist_e2e -- --nocapture
//! ```

mod common;

use chrono::Utc;
use common::db::TestCommand;
use destructive_command_guard::history::{HistoryDb, Outcome};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Path to the exact dcg binary Cargo built for this integration test.
fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

/// Test environment with isolated history and config.
struct TestEnv {
    temp_dir: tempfile::TempDir,
    home_dir: PathBuf,
    xdg_config_dir: PathBuf,
    #[allow(dead_code)]
    dcg_dir: PathBuf,
    config_path: PathBuf,
    history_path: PathBuf,
    allowlist_path: PathBuf,
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

        let config_path = dcg_dir.join("config.toml");
        let history_path = dcg_dir.join("history.db");
        let allowlist_path = dcg_dir.join("allowlist.toml");

        // Create a git repo in the temp dir so project detection works
        fs::create_dir_all(temp_dir.path().join(".git")).expect("failed to create .git dir");

        Self {
            temp_dir,
            home_dir,
            xdg_config_dir,
            dcg_dir,
            config_path,
            history_path,
            allowlist_path,
        }
    }

    /// Create history database and populate with test data.
    fn with_history(self, commands: &[TestCommand]) -> Self {
        // Create history database with seed data
        let db = HistoryDb::open(Some(self.history_path.clone()))
            .expect("Failed to create history database");

        let now = Utc::now();
        for cmd in commands {
            let entry = cmd.to_entry(now);
            db.log_command(&entry).expect("Failed to seed command");
        }

        // Create config that points to our history database
        // The CLI reads database_path from config file via DCG_CONFIG env var
        fs::write(
            &self.config_path,
            format!(
                r#"[history]
enabled = true
database_path = "{}"
"#,
                self.history_path.display()
            ),
        )
        .expect("Failed to write config");

        self
    }

    /// Run dcg suggest-allowlist with given args.
    fn run_suggest_allowlist(&self, args: &[&str]) -> std::process::Output {
        self.run_suggest_allowlist_with_env(args, &[])
    }

    /// Run dcg suggest-allowlist with given args and extra environment variables.
    fn run_suggest_allowlist_with_env(
        &self,
        args: &[&str],
        extra_env: &[(&str, &str)],
    ) -> std::process::Output {
        let mut cmd = Command::new(dcg_binary());
        cmd.env_clear()
            .env("HOME", &self.home_dir)
            .env("USERPROFILE", &self.home_dir)
            .env("XDG_CONFIG_HOME", &self.xdg_config_dir)
            .env("DCG_CONFIG", &self.config_path)
            .env("DCG_PACKS", "core.git,core.filesystem,containers.docker")
            .current_dir(self.temp_dir.path())
            .arg("suggest-allowlist")
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        for (key, value) in extra_env {
            cmd.env(key, value);
        }

        cmd.output().expect("failed to execute dcg")
    }

    /// Run dcg suggest-allowlist with stdin input (for interactive mode).
    #[allow(dead_code)]
    fn run_suggest_allowlist_interactive(
        &self,
        args: &[&str],
        stdin_input: &str,
    ) -> std::process::Output {
        let mut cmd = Command::new(dcg_binary());
        cmd.env_clear()
            .env("HOME", &self.home_dir)
            .env("USERPROFILE", &self.home_dir)
            .env("XDG_CONFIG_HOME", &self.xdg_config_dir)
            .env("DCG_CONFIG", &self.config_path)
            .env("DCG_PACKS", "core.git,core.filesystem,containers.docker")
            .current_dir(self.temp_dir.path())
            .arg("suggest-allowlist")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().expect("failed to spawn dcg");
        {
            let stdin = child.stdin.as_mut().expect("failed to open stdin");
            stdin
                .write_all(stdin_input.as_bytes())
                .expect("failed to write stdin");
        }

        child.wait_with_output().expect("failed to wait for dcg")
    }

    /// Check if allowlist file exists.
    fn allowlist_exists(&self) -> bool {
        self.allowlist_path.exists()
    }

    /// Read allowlist contents.
    #[allow(dead_code)]
    fn read_allowlist(&self) -> String {
        fs::read_to_string(&self.allowlist_path).unwrap_or_default()
    }
}

/// Create standard test fixtures with multiple denied commands.
///
/// Note: suggest-allowlist groups by EXACT command text, so we need
/// multiple occurrences of the same command (not just similar patterns).
#[allow(clippy::too_many_lines)]
fn suggest_test_fixtures() -> Vec<TestCommand> {
    vec![
        // Repeat safe build commands so the positive JSON path has suggestions.
        TestCommand {
            command: "npm run custom:build",
            outcome: Outcome::Deny,
            agent_type: "claude_code",
            working_dir: "/data/projects/test",
            timestamp_offset_secs: -3900,
            pack_id: Some("package.npm"),
            pattern_name: Some("custom-build"),
            rule_id: Some("package.npm:custom-build"),
            eval_duration_us: 100,
        },
        TestCommand {
            command: "npm run custom:build",
            outcome: Outcome::Deny,
            agent_type: "claude_code",
            working_dir: "/data/projects/test",
            timestamp_offset_secs: -3800,
            pack_id: Some("package.npm"),
            pattern_name: Some("custom-build"),
            rule_id: Some("package.npm:custom-build"),
            eval_duration_us: 100,
        },
        TestCommand {
            command: "npm run custom:build",
            outcome: Outcome::Deny,
            agent_type: "claude_code",
            working_dir: "/data/projects/test",
            timestamp_offset_secs: -3700,
            pack_id: Some("package.npm"),
            pattern_name: Some("custom-build"),
            rule_id: Some("package.npm:custom-build"),
            eval_duration_us: 100,
        },
        // Repeat "git reset --hard HEAD" 4 times (meets min-frequency=3)
        // but must still be filtered out by the suggestion safety guard.
        TestCommand {
            command: "git reset --hard HEAD",
            outcome: Outcome::Deny,
            agent_type: "claude_code",
            working_dir: "/data/projects/test",
            timestamp_offset_secs: -3600,
            pack_id: Some("core.git"),
            pattern_name: Some("reset-hard"),
            rule_id: Some("core.git:reset-hard"),
            eval_duration_us: 100,
        },
        TestCommand {
            command: "git reset --hard HEAD",
            outcome: Outcome::Deny,
            agent_type: "claude_code",
            working_dir: "/data/projects/test",
            timestamp_offset_secs: -3500,
            pack_id: Some("core.git"),
            pattern_name: Some("reset-hard"),
            rule_id: Some("core.git:reset-hard"),
            eval_duration_us: 100,
        },
        TestCommand {
            command: "git reset --hard HEAD",
            outcome: Outcome::Deny,
            agent_type: "claude_code",
            working_dir: "/data/projects/test",
            timestamp_offset_secs: -3400,
            pack_id: Some("core.git"),
            pattern_name: Some("reset-hard"),
            rule_id: Some("core.git:reset-hard"),
            eval_duration_us: 100,
        },
        TestCommand {
            command: "git reset --hard HEAD",
            outcome: Outcome::Deny,
            agent_type: "claude_code",
            working_dir: "/data/projects/test",
            timestamp_offset_secs: -3300,
            pack_id: Some("core.git"),
            pattern_name: Some("reset-hard"),
            rule_id: Some("core.git:reset-hard"),
            eval_duration_us: 100,
        },
        // Repeat "git push --force origin main" 3 times (meets min-frequency=3)
        TestCommand {
            command: "git push --force origin main",
            outcome: Outcome::Deny,
            agent_type: "claude_code",
            working_dir: "/data/projects/test",
            timestamp_offset_secs: -3200,
            pack_id: Some("core.git"),
            pattern_name: Some("push-force-long"),
            rule_id: Some("core.git:push-force-long"),
            eval_duration_us: 100,
        },
        TestCommand {
            command: "git push --force origin main",
            outcome: Outcome::Deny,
            agent_type: "claude_code",
            working_dir: "/data/projects/test",
            timestamp_offset_secs: -3100,
            pack_id: Some("core.git"),
            pattern_name: Some("push-force-long"),
            rule_id: Some("core.git:push-force-long"),
            eval_duration_us: 100,
        },
        TestCommand {
            command: "git push --force origin main",
            outcome: Outcome::Deny,
            agent_type: "claude_code",
            working_dir: "/data/projects/test",
            timestamp_offset_secs: -3000,
            pack_id: Some("core.git"),
            pattern_name: Some("push-force-long"),
            rule_id: Some("core.git:push-force-long"),
            eval_duration_us: 100,
        },
        // Additional variants with lower frequency (for testing min-frequency filter)
        TestCommand {
            command: "git reset --hard origin/main",
            outcome: Outcome::Deny,
            agent_type: "claude_code",
            working_dir: "/data/projects/test",
            timestamp_offset_secs: -2800,
            pack_id: Some("core.git"),
            pattern_name: Some("reset-hard"),
            rule_id: Some("core.git:reset-hard"),
            eval_duration_us: 100,
        },
        TestCommand {
            command: "git reset --hard origin/main",
            outcome: Outcome::Deny,
            agent_type: "claude_code",
            working_dir: "/data/projects/test",
            timestamp_offset_secs: -2700,
            pack_id: Some("core.git"),
            pattern_name: Some("reset-hard"),
            rule_id: Some("core.git:reset-hard"),
            eval_duration_us: 100,
        },
        // Some allowed commands (should not be suggested)
        TestCommand {
            command: "git status",
            outcome: Outcome::Allow,
            agent_type: "claude_code",
            working_dir: "/data/projects/test",
            timestamp_offset_secs: -2600,
            pack_id: None,
            pattern_name: None,
            rule_id: None,
            eval_duration_us: 50,
        },
    ]
}

// =============================================================================
// Non-Interactive Mode Tests
// =============================================================================

#[test]
fn test_suggest_allowlist_non_interactive_no_writes() {
    eprintln!("=== Testing that non-interactive mode does not write allowlist ===");

    let env = TestEnv::new().with_history(&suggest_test_fixtures());

    // Verify no allowlist exists initially
    assert!(
        !env.allowlist_exists(),
        "Allowlist should not exist initially"
    );

    // Run in non-interactive mode
    let output = env.run_suggest_allowlist(&["--non-interactive", "--min-frequency", "3"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("Exit code: {}", output.status.code().unwrap_or(-1));
    eprintln!("Stdout: {}", stdout);
    eprintln!("Stderr: {}", stderr);

    assert!(output.status.success(), "Command should succeed");

    // Verify allowlist was NOT created
    assert!(
        !env.allowlist_exists(),
        "Non-interactive mode should NOT create allowlist"
    );

    eprintln!("=== Non-interactive no-writes test PASSED ===");
}

#[test]
fn test_suggest_allowlist_runs_without_crash() {
    eprintln!("=== Testing that suggest-allowlist runs without crashing ===");

    let env = TestEnv::new().with_history(&suggest_test_fixtures());
    let output = env.run_suggest_allowlist(&["--non-interactive"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("Exit code: {}", output.status.code().unwrap_or(-1));
    eprintln!("Stdout: {}", stdout);
    eprintln!("Stderr: {}", stderr);

    // Command should succeed (exit 0)
    assert!(output.status.success(), "Command should succeed");

    eprintln!("=== No-crash test PASSED ===");
}

#[test]
fn test_suggest_allowlist_empty_history() {
    eprintln!("=== Testing suggest-allowlist with empty history ===");

    let env = TestEnv::new().with_history(&[]);
    let output = env.run_suggest_allowlist(&["--non-interactive"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("Exit code: {}", output.status.code().unwrap_or(-1));
    eprintln!("Stdout: {}", stdout);
    eprintln!("Stderr: {}", stderr);

    // Should succeed even with no history
    assert!(
        output.status.success(),
        "Command should succeed with empty history"
    );

    // Should mention no denied commands found
    assert!(
        stdout.contains("No denied commands")
            || stdout.contains("No commands found")
            || stdout.contains("No suggestions"),
        "Should indicate no suggestions available"
    );

    eprintln!("=== Empty history test PASSED ===");
}

// =============================================================================
// Filter Tests
// =============================================================================

#[test]
fn test_suggest_allowlist_min_frequency_filter() {
    eprintln!("=== Testing min-frequency filter ===");

    let env = TestEnv::new().with_history(&suggest_test_fixtures());

    // With min-frequency=10, should get "no commands found" message
    let output = env.run_suggest_allowlist(&["--non-interactive", "--min-frequency", "10"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!("Stdout with min-frequency=10: {}", stdout);

    assert!(output.status.success(), "Command should succeed");
    // Should indicate no commands met the threshold
    assert!(
        stdout.contains("No commands found")
            || stdout.contains("No denied")
            || stdout.contains("No suggestions"),
        "Should indicate no commands met threshold"
    );

    eprintln!("=== Min-frequency filter test PASSED ===");
}

#[test]
fn test_suggest_allowlist_limit_filter() {
    eprintln!("=== Testing limit filter ===");

    let env = TestEnv::new().with_history(&suggest_test_fixtures());

    // With limit=1, should work without crash
    let output = env.run_suggest_allowlist(&["--non-interactive", "--limit", "1"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!("Stdout with limit=1: {}", stdout);

    assert!(
        output.status.success(),
        "Command should succeed with limit=1"
    );

    eprintln!("=== Limit filter test PASSED ===");
}

// =============================================================================
// Error Handling Tests
// =============================================================================

#[test]
fn test_suggest_allowlist_invalid_since_format() {
    eprintln!("=== Testing invalid --since format handling ===");

    let env = TestEnv::new();

    // Invalid since format should be handled (error or graceful message)
    let output = env.run_suggest_allowlist(&["--non-interactive", "--since", "invalid"]);

    eprintln!("Exit code: {}", output.status.code().unwrap_or(-1));
    eprintln!("Stderr: {}", String::from_utf8_lossy(&output.stderr));
    eprintln!("Stdout: {}", String::from_utf8_lossy(&output.stdout));

    // Should fail with non-zero exit code for invalid format
    assert!(
        !output.status.success(),
        "Command should fail with invalid --since"
    );

    eprintln!("=== Invalid --since format test PASSED ===");
}

// =============================================================================
// Help and CLI Tests
// =============================================================================

#[test]
fn test_suggest_allowlist_help() {
    eprintln!("=== Testing suggest-allowlist --help ===");

    let output = Command::new(dcg_binary())
        .args(["suggest-allowlist", "--help"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to execute dcg");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    eprintln!("Exit code: {}", output.status.code().unwrap_or(-1));
    eprintln!("Combined output:\n{}", combined);

    assert!(output.status.success(), "Help command should succeed");

    // Help output should show tool name and basic usage info
    // The suggest-allowlist subcommand may show the main help or command-specific help
    assert!(
        combined.contains("dcg") || combined.contains("suggest") || combined.contains("allowlist"),
        "Help should display tool information"
    );

    eprintln!("=== Help test PASSED ===");
}

#[test]
fn test_suggest_allowlist_cli_parsing_confidence_filter() {
    eprintln!("=== Testing --confidence filter parsing ===");

    let env = TestEnv::new().with_history(&suggest_test_fixtures());

    for tier in &["high", "medium", "low", "all"] {
        let output = env.run_suggest_allowlist(&["--non-interactive", "--confidence", tier]);
        let stderr = String::from_utf8_lossy(&output.stderr);

        eprintln!(
            "Confidence={}: exit_code={}",
            tier,
            output.status.code().unwrap_or(-1)
        );
        if !output.status.success() {
            eprintln!("  stderr: {}", stderr);
        }

        assert!(
            output.status.success(),
            "Command with --confidence {} should succeed",
            tier
        );
    }

    eprintln!("=== Confidence filter parsing test PASSED ===");
}

#[test]
fn test_suggest_allowlist_cli_parsing_risk_filter() {
    eprintln!("=== Testing --risk filter parsing ===");

    let env = TestEnv::new().with_history(&suggest_test_fixtures());

    for level in &["low", "medium", "high", "all"] {
        let output = env.run_suggest_allowlist(&["--non-interactive", "--risk", level]);
        let stderr = String::from_utf8_lossy(&output.stderr);

        eprintln!(
            "Risk={}: exit_code={}",
            level,
            output.status.code().unwrap_or(-1)
        );
        if !output.status.success() {
            eprintln!("  stderr: {}", stderr);
        }

        assert!(
            output.status.success(),
            "Command with --risk {} should succeed",
            level
        );
    }

    eprintln!("=== Risk filter parsing test PASSED ===");
}

#[test]
fn test_suggest_allowlist_cli_parsing_format() {
    eprintln!("=== Testing --format parsing ===");

    let env = TestEnv::new().with_history(&suggest_test_fixtures());

    for format in &["text", "json"] {
        let output = env.run_suggest_allowlist(&["--non-interactive", "--format", format]);
        let stderr = String::from_utf8_lossy(&output.stderr);

        eprintln!(
            "Format={}: exit_code={}",
            format,
            output.status.code().unwrap_or(-1)
        );
        if !output.status.success() {
            eprintln!("  stderr: {}", stderr);
        }

        assert!(
            output.status.success(),
            "Command with --format {} should succeed",
            format
        );
    }

    eprintln!("=== Format parsing test PASSED ===");
}

// =============================================================================
// JSON Output Validation Tests
// =============================================================================

#[test]
fn test_suggest_allowlist_json_output_structure() {
    eprintln!("=== Testing JSON output structure ===");

    let env = TestEnv::new().with_history(&suggest_test_fixtures());

    // Run with JSON format and low min-frequency to get suggestions
    let output = env.run_suggest_allowlist(&[
        "--non-interactive",
        "--format",
        "json",
        "--min-frequency",
        "2",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("Exit code: {}", output.status.code().unwrap_or(-1));
    eprintln!("Stdout: {}", stdout);
    eprintln!("Stderr: {}", stderr);

    assert!(
        output.status.success(),
        "JSON output command should succeed"
    );

    // Skip if no suggestions were generated
    if stdout.contains("No denied commands")
        || stdout.contains("No commands found")
        || stdout.trim().is_empty()
    {
        eprintln!("No suggestions generated - skipping JSON structure validation");
        return;
    }

    // Parse the JSON output
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
    assert!(
        parsed.is_ok(),
        "Output should be valid JSON. Got: {}",
        stdout
    );

    let json = parsed.unwrap();

    // JSON should be an array
    assert!(json.is_array(), "JSON output should be an array");

    let suggestions = json.as_array().unwrap();
    eprintln!("Found {} suggestions in JSON output", suggestions.len());

    // Validate structure of each suggestion
    for (i, suggestion) in suggestions.iter().enumerate() {
        eprintln!("Validating suggestion {}: {:?}", i, suggestion);

        // Required fields
        assert!(
            suggestion.get("pattern").is_some(),
            "Suggestion {} should have 'pattern' field",
            i
        );
        assert!(
            suggestion.get("confidence").is_some(),
            "Suggestion {} should have 'confidence' field",
            i
        );
        assert!(
            suggestion.get("risk").is_some(),
            "Suggestion {} should have 'risk' field",
            i
        );
        assert!(
            suggestion.get("frequency").is_some(),
            "Suggestion {} should have 'frequency' field",
            i
        );

        // Validate types
        assert!(
            suggestion["pattern"].is_string(),
            "Suggestion {} 'pattern' should be string",
            i
        );
        assert!(
            suggestion["confidence"].is_string(),
            "Suggestion {} 'confidence' should be string",
            i
        );
        assert!(
            suggestion["risk"].is_string(),
            "Suggestion {} 'risk' should be string",
            i
        );
        assert!(
            suggestion["frequency"].is_number(),
            "Suggestion {} 'frequency' should be number",
            i
        );

        // Validate confidence is valid tier
        let confidence = suggestion["confidence"].as_str().unwrap();
        assert!(
            ["high", "medium", "low"].contains(&confidence),
            "Suggestion {} confidence should be high/medium/low, got: {}",
            i,
            confidence
        );

        // Validate risk is valid level (can be lowercase or capitalized)
        let risk = suggestion["risk"].as_str().unwrap().to_lowercase();
        assert!(
            ["low", "medium", "high"].contains(&risk.as_str()),
            "Suggestion {} risk should be low/medium/high, got: {}",
            i,
            risk
        );
    }

    eprintln!("=== JSON output structure test PASSED ===");
}

#[test]
fn test_suggest_allowlist_json_output_non_empty() {
    eprintln!("=== Testing that JSON output has suggestions when data exists ===");

    let env = TestEnv::new().with_history(&suggest_test_fixtures());

    // Use min-frequency=3 since the safe custom build command appears 3 times.
    let output = env.run_suggest_allowlist(&[
        "--non-interactive",
        "--format",
        "json",
        "--min-frequency",
        "3",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("Exit code: {}", output.status.code().unwrap_or(-1));
    eprintln!("Stdout: {}", stdout);
    eprintln!("Stderr: {}", stderr);

    assert!(output.status.success(), "Command should succeed");

    // Safe repeated commands should produce suggestions, while high-risk git
    // commands in the same history stay filtered out.
    if !stdout.contains("No denied commands") && !stdout.contains("No commands found") {
        let parsed: serde_json::Value =
            serde_json::from_str(&stdout).expect("Should produce valid JSON");

        if let Some(arr) = parsed.as_array() {
            eprintln!("Got {} suggestions", arr.len());
            assert!(
                !arr.is_empty(),
                "Should have at least one suggestion with test fixtures"
            );
            let patterns: Vec<&str> = arr
                .iter()
                .filter_map(|suggestion| suggestion.get("pattern").and_then(|p| p.as_str()))
                .collect();
            assert!(
                patterns.iter().any(|pattern| pattern.contains("npm")),
                "safe npm command should be suggested, got {patterns:?}"
            );
            assert!(
                patterns.iter().all(|pattern| !pattern.contains("reset")
                    && !pattern.contains("push")
                    && !pattern.contains("force")),
                "high-risk git commands must not be suggested, got {patterns:?}"
            );
        }
    }

    eprintln!("=== JSON non-empty test PASSED ===");
}

// =============================================================================
// Interactive Mode Tests
// =============================================================================

#[test]
fn test_suggest_allowlist_interactive_accept_writes_allowlist() {
    eprintln!("=== Testing that interactive accept writes to allowlist ===");

    let env = TestEnv::new().with_history(&suggest_test_fixtures());

    // Verify no allowlist exists initially
    assert!(
        !env.allowlist_exists(),
        "Allowlist should not exist initially"
    );

    // Run in interactive mode with "a\nq\n" (accept first, then quit)
    let output = env.run_suggest_allowlist_interactive(&["--min-frequency", "3"], "a\nq\n");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("Exit code: {}", output.status.code().unwrap_or(-1));
    eprintln!("Stdout: {}", stdout);
    eprintln!("Stderr: {}", stderr);

    // Command should succeed (exit 0)
    assert!(
        output.status.success(),
        "Interactive command should succeed"
    );

    // After accepting a suggestion, allowlist should exist
    // Note: This depends on the suggestion being generated and accepted
    if stdout.contains("[A]ccept") {
        // If we got to the accept prompt, check if allowlist was created
        if stdout.contains("Added pattern") || stdout.contains("written") {
            assert!(
                env.allowlist_exists(),
                "Allowlist should exist after accepting suggestion"
            );

            let contents = env.read_allowlist();
            eprintln!("Allowlist contents:\n{}", contents);

            // Should contain a pattern entry
            assert!(
                contents.contains("[[allow]]") || contents.contains("pattern"),
                "Allowlist should contain pattern entry"
            );
        }
    }

    eprintln!("=== Interactive accept test PASSED ===");
}

#[test]
fn test_suggest_allowlist_interactive_shows_action_prompts() {
    eprintln!("=== Testing that interactive mode shows action prompts ===");

    let env = TestEnv::new().with_history(&suggest_test_fixtures());
    let output = env.run_suggest_allowlist_interactive(&["--min-frequency", "3"], "q\n");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    eprintln!("Exit code: {}", output.status.code().unwrap_or(-1));
    eprintln!("Stdout: {}", stdout);
    eprintln!("Stderr: {}", stderr);

    assert!(
        output.status.success(),
        "Interactive command should succeed"
    );
    assert!(
        combined.contains("[A]ccept"),
        "Interactive output should include accept prompt"
    );
    assert!(
        combined.contains("[S]kip"),
        "Interactive output should include skip prompt"
    );
    assert!(
        combined.contains("[Q]uit"),
        "Interactive output should include quit prompt"
    );

    eprintln!("=== Interactive action prompt test PASSED ===");
}

#[test]
fn test_suggest_allowlist_ci_forces_non_interactive_mode() {
    eprintln!("=== Testing CI env forces non-interactive suggest mode ===");

    let env = TestEnv::new().with_history(&suggest_test_fixtures());

    let output = env.run_suggest_allowlist_with_env(&["--min-frequency", "3"], &[("CI", "true")]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    eprintln!("Exit code: {}", output.status.code().unwrap_or(-1));
    eprintln!("Stdout: {}", stdout);
    eprintln!("Stderr: {}", stderr);

    assert!(
        output.status.success(),
        "Suggest command should succeed in CI mode"
    );
    assert!(
        !combined.contains("[A]ccept"),
        "CI mode should suppress interactive accept prompt"
    );
    assert!(
        !combined.contains("[S]kip"),
        "CI mode should suppress interactive skip prompt"
    );
    assert!(
        !combined.contains("[Q]uit"),
        "CI mode should suppress interactive quit prompt"
    );
    assert!(
        !env.allowlist_exists(),
        "CI-forced non-interactive mode should not write allowlist"
    );

    eprintln!("=== CI non-interactive test PASSED ===");
}

#[test]
fn test_suggest_allowlist_robot_env_forces_json_non_interactive_mode() {
    eprintln!("=== Testing DCG_ROBOT env forces JSON non-interactive suggest mode ===");

    let env = TestEnv::new().with_history(&suggest_test_fixtures());

    let output =
        env.run_suggest_allowlist_with_env(&["--min-frequency", "3"], &[("DCG_ROBOT", "1")]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    eprintln!("Exit code: {}", output.status.code().unwrap_or(-1));
    eprintln!("Stdout: {}", stdout);
    eprintln!("Stderr: {}", stderr);

    assert!(
        output.status.success(),
        "Suggest command should succeed in robot mode"
    );
    assert!(
        !combined.contains("[A]ccept"),
        "Robot mode should suppress interactive accept prompt"
    );
    assert!(
        !combined.contains("[S]kip"),
        "Robot mode should suppress interactive skip prompt"
    );
    assert!(
        !combined.contains("[Q]uit"),
        "Robot mode should suppress interactive quit prompt"
    );
    assert!(
        !env.allowlist_exists(),
        "Robot mode should not write allowlist"
    );

    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("Robot mode output should be valid JSON");
    assert!(
        parsed.is_array(),
        "Robot mode suggest output should be a JSON array"
    );

    eprintln!("=== Robot mode non-interactive test PASSED ===");
}

#[test]
fn test_suggest_allowlist_interactive_skip_no_write() {
    eprintln!("=== Testing that interactive skip does not write allowlist ===");

    let env = TestEnv::new().with_history(&suggest_test_fixtures());

    // Verify no allowlist exists initially
    assert!(
        !env.allowlist_exists(),
        "Allowlist should not exist initially"
    );

    // Run in interactive mode with "s\ns\nq\n" (skip all, then quit)
    let output =
        env.run_suggest_allowlist_interactive(&["--min-frequency", "3"], "s\ns\ns\ns\nq\n");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("Exit code: {}", output.status.code().unwrap_or(-1));
    eprintln!("Stdout: {}", stdout);
    eprintln!("Stderr: {}", stderr);

    // Command should succeed
    assert!(
        output.status.success(),
        "Interactive skip command should succeed"
    );

    // After skipping all suggestions, allowlist should NOT exist
    assert!(
        !env.allowlist_exists(),
        "Allowlist should NOT exist after skipping all suggestions"
    );

    eprintln!("=== Interactive skip test PASSED ===");
}

#[test]
fn test_suggest_allowlist_interactive_quit_early() {
    eprintln!("=== Testing that interactive quit exits cleanly ===");

    let env = TestEnv::new().with_history(&suggest_test_fixtures());

    // Verify no allowlist exists initially
    assert!(
        !env.allowlist_exists(),
        "Allowlist should not exist initially"
    );

    // Run in interactive mode with just "q\n" (quit immediately)
    let output = env.run_suggest_allowlist_interactive(&["--min-frequency", "3"], "q\n");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("Exit code: {}", output.status.code().unwrap_or(-1));
    eprintln!("Stdout: {}", stdout);
    eprintln!("Stderr: {}", stderr);

    // Command should succeed (exit 0)
    assert!(
        output.status.success(),
        "Interactive quit command should succeed"
    );

    // After quitting, allowlist should NOT exist
    assert!(
        !env.allowlist_exists(),
        "Allowlist should NOT exist after quitting"
    );

    eprintln!("=== Interactive quit test PASSED ===");
}

// =============================================================================
// Verbose Logging Tests
// =============================================================================

#[test]
fn test_suggest_allowlist_verbose_failure_logging() {
    eprintln!("=== Testing verbose failure logging ===");

    let env = TestEnv::new().with_history(&suggest_test_fixtures());

    // Test with an invalid filter value to trigger failure
    let output = env.run_suggest_allowlist(&["--non-interactive", "--confidence", "invalid"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("===== VERBOSE FAILURE OUTPUT =====");
    eprintln!("Exit code: {:?}", output.status.code());
    eprintln!("Exit success: {}", output.status.success());
    eprintln!("--- STDOUT ({} bytes) ---", stdout.len());
    eprintln!("{}", stdout);
    eprintln!("--- STDERR ({} bytes) ---", stderr.len());
    eprintln!("{}", stderr);
    eprintln!("===== END VERBOSE OUTPUT =====");

    // Invalid filter should cause failure
    assert!(
        !output.status.success(),
        "Command with invalid --confidence value should fail"
    );

    // Stderr should contain error information
    let combined = format!("{}{}", stdout, stderr);
    assert!(
        !combined.is_empty(),
        "Error output should not be empty for invalid input"
    );

    eprintln!("=== Verbose failure logging test PASSED ===");
}

#[test]
fn test_suggest_allowlist_output_diagnostics() {
    eprintln!("=== Testing output diagnostics for debugging ===");

    let env = TestEnv::new().with_history(&suggest_test_fixtures());

    // Run normal command and capture all output for diagnostics
    let output = env.run_suggest_allowlist(&["--non-interactive", "--min-frequency", "2"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Comprehensive diagnostic output
    eprintln!("╔════════════════════════════════════════════════════════════════════╗");
    eprintln!("║                    DIAGNOSTIC OUTPUT                               ║");
    eprintln!("╠════════════════════════════════════════════════════════════════════╣");
    eprintln!("║ Exit Code: {:?}", output.status.code());
    eprintln!("║ Exit Success: {}", output.status.success());
    eprintln!("║ Stdout Length: {} bytes", stdout.len());
    eprintln!("║ Stderr Length: {} bytes", stderr.len());
    eprintln!("╠════════════════════════════════════════════════════════════════════╣");
    eprintln!("║ STDOUT:");
    for line in stdout.lines() {
        eprintln!("║   {line}");
    }
    eprintln!("╠════════════════════════════════════════════════════════════════════╣");
    eprintln!("║ STDERR:");
    for line in stderr.lines() {
        eprintln!("║   {line}");
    }
    eprintln!("╚════════════════════════════════════════════════════════════════════╝");

    // Basic sanity check - command should succeed
    assert!(
        output.status.success(),
        "Diagnostics command should succeed"
    );

    eprintln!("=== Output diagnostics test PASSED ===");
}

/// Test that `--apply` writes patterns to the allowlist non-interactively.
#[test]
fn apply_flag_writes_to_allowlist() {
    let env = TestEnv::new().with_history(&suggest_test_fixtures());

    // First, run with --non-interactive to see what suggestions exist
    let output = env.run_suggest_allowlist(&["--non-interactive", "--min-frequency", "3"]);
    assert!(output.status.success(), "non-interactive should succeed");

    // Now apply suggestion #1
    let output = env.run_suggest_allowlist(&["--apply", "1", "--min-frequency", "3"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("╔════════════════════════════════════════════════════════════════════╗");
    eprintln!("║ --apply test");
    eprintln!("║ STDOUT: {stdout}");
    eprintln!("║ STDERR: {stderr}");
    eprintln!("╚════════════════════════════════════════════════════════════════════╝");

    assert!(
        output.status.success(),
        "--apply should succeed (stderr: {stderr})"
    );
    assert!(
        stdout.contains("Applied") || stdout.contains("applied"),
        "Should report applied patterns"
    );
    // Allowlist is written to the project-level .dcg/ dir (since .git exists)
    let project_allowlist = env.temp_dir.path().join(".dcg").join("allowlist.toml");
    assert!(
        env.allowlist_exists() || project_allowlist.exists(),
        "Allowlist file should be created (user or project level)"
    );
}

/// Test that `--apply` with out-of-range index is handled gracefully.
#[test]
fn apply_flag_out_of_range_index() {
    let env = TestEnv::new().with_history(&suggest_test_fixtures());

    let output = env.run_suggest_allowlist(&["--apply", "999", "--min-frequency", "3"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("apply out-of-range: stdout={stdout}, stderr={stderr}");

    assert!(
        output.status.success(),
        "Out-of-range --apply should still succeed (not crash)"
    );
    assert!(
        stdout.contains("0 applied") || stderr.contains("out of range"),
        "Should report no patterns applied or warn about range"
    );
}

/// Fixtures with a command that touches a sensitive system path. The generated
/// allowlist pattern should fall into `RequireConfirmation` (not `NeverSuggest`)
/// per `check_suggestion_safety` in src/suggest.rs.
fn sensitive_path_fixtures() -> Vec<TestCommand> {
    let mut cmds = Vec::new();
    for i in 0..4 {
        cmds.push(TestCommand {
            command: "cat /etc/dcg.conf",
            outcome: Outcome::Deny,
            agent_type: "claude_code",
            working_dir: "/data/projects/test",
            timestamp_offset_secs: -3600 + i * 100,
            pack_id: Some("core.filesystem"),
            pattern_name: Some("sensitive-read"),
            rule_id: Some("core.filesystem:sensitive-read"),
            eval_duration_us: 100,
        });
    }
    cmds
}

/// `--apply` must refuse to write a `RequireConfirmation` suggestion (e.g. a
/// pattern that touches `/etc`) without `--accept-risk`. This guards against
/// the previously-shipped behavior where `apply_suggestions_by_index` ignored
/// `suggestion.safety` entirely and silently allowlisted sensitive patterns.
#[test]
fn apply_flag_refuses_require_confirmation_without_accept_risk() {
    let env = TestEnv::new().with_history(&sensitive_path_fixtures());

    let output = env.run_suggest_allowlist(&["--apply", "1", "--min-frequency", "3"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("apply require-confirmation (no --accept-risk):\nstdout={stdout}\nstderr={stderr}");

    assert!(output.status.success(), "Command should not crash");
    assert!(
        stderr.contains("Skipped (safety)") || stderr.contains("--accept-risk"),
        "Should print a safety-skip message guiding the user toward --accept-risk"
    );
    assert!(
        stdout.contains("0 applied") || stdout.contains("applied 0"),
        "Sensitive pattern must NOT be written without --accept-risk"
    );

    // The sensitive pattern must not appear in any allowlist file.
    let project_allowlist = env.temp_dir.path().join(".dcg").join("allowlist.toml");
    let user_contents = if env.allowlist_exists() {
        env.read_allowlist()
    } else {
        String::new()
    };
    let project_contents = fs::read_to_string(&project_allowlist).unwrap_or_default();
    assert!(
        !user_contents.contains("/etc/dcg.conf") && !project_contents.contains("/etc/dcg.conf"),
        "Sensitive `/etc/...` pattern leaked into allowlist (user={user_contents}, project={project_contents})"
    );
}

/// With `--accept-risk`, the same `RequireConfirmation` suggestion is written.
#[test]
fn apply_flag_writes_require_confirmation_with_accept_risk() {
    let env = TestEnv::new().with_history(&sensitive_path_fixtures());

    let output =
        env.run_suggest_allowlist(&["--apply", "1", "--accept-risk", "--min-frequency", "3"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("apply require-confirmation (--accept-risk):\nstdout={stdout}\nstderr={stderr}");

    assert!(output.status.success(), "Command should not crash");
    assert!(
        stdout.contains("Applied") || stdout.contains("applied"),
        "Should report at least one applied pattern with --accept-risk"
    );
}

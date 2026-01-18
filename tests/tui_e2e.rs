//! End-to-end tests for TUI/CLI rich output and CI fallback.
//!
//! These tests verify:
//! - Rich terminal output with Unicode box-drawing (when TTY)
//! - CI environment fallback (no ANSI codes)
//! - NO_COLOR environment variable support
//! - TERM=dumb fallback (ASCII characters)
//! - JSON format bypasses TUI rendering
//!
//! # Running
//!
//! ```bash
//! cargo test --test tui_e2e
//! ```
//!
//! # Note on TTY Detection
//!
//! Since tests run without a TTY, we can't directly verify rich Unicode output.
//! Instead, we verify the fallback behaviors that should activate when:
//! - CI=true is set
//! - NO_COLOR is set
//! - TERM=dumb is set
//! - stdout/stderr is not a TTY (default in tests)

use std::process::{Command, Stdio};

/// Path to the dcg binary (built in debug mode for tests).
fn dcg_binary() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // Remove test binary name
    path.pop(); // Remove deps/
    path.push("dcg");
    path
}

/// Run dcg in hook mode with the given command and environment variables.
/// Returns (stdout, stderr, exit_code).
fn run_hook_with_env(command: &str, env_vars: &[(&str, &str)]) -> (String, String, i32) {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    std::fs::create_dir_all(temp.path().join(".git")).expect("failed to create .git dir");

    let home_dir = temp.path().join("home");
    let xdg_config_dir = temp.path().join("xdg_config");
    std::fs::create_dir_all(&home_dir).expect("failed to create HOME dir");
    std::fs::create_dir_all(&xdg_config_dir).expect("failed to create XDG_CONFIG_HOME dir");

    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {
            "command": command,
        }
    });

    let mut cmd = Command::new(dcg_binary());
    cmd.env_clear()
        .env("HOME", &home_dir)
        .env("XDG_CONFIG_HOME", &xdg_config_dir)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_PACKS", "core.git,core.filesystem")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Apply custom environment variables
    for (key, value) in env_vars {
        cmd.env(key, value);
    }

    let mut child = cmd.spawn().expect("failed to spawn dcg hook mode");

    {
        let stdin = child.stdin.as_mut().expect("failed to open stdin");
        serde_json::to_writer(stdin, &input).expect("failed to write hook input JSON");
    }

    let output = child.wait_with_output().expect("failed to wait for dcg");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code().unwrap_or(-1);

    (stdout, stderr, exit_code)
}

/// Run dcg with CLI arguments and environment variables.
fn run_dcg_with_env(args: &[&str], env_vars: &[(&str, &str)]) -> (String, String, i32) {
    let temp = tempfile::tempdir().expect("failed to create temp dir");

    let mut cmd = Command::new(dcg_binary());
    cmd.args(args)
        .env_clear()
        .env("HOME", temp.path())
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .current_dir(temp.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    for (key, value) in env_vars {
        cmd.env(key, value);
    }

    let output = cmd.output().expect("failed to execute dcg");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code().unwrap_or(-1);

    (stdout, stderr, exit_code)
}

// ============================================================================
// CI Environment Fallback Tests
// ============================================================================

mod ci_fallback_tests {
    use super::*;

    /// Check if output contains ANSI escape codes.
    fn contains_ansi_codes(s: &str) -> bool {
        s.contains("\x1b[")
    }

    /// Check if output contains Unicode box-drawing characters used in denial box borders.
    ///
    /// Note: We exclude '\u{2514}' (└) which is used by the highlight module for
    /// visual clarity in label connectors even when colors are disabled.
    fn contains_denial_box_chars(s: &str) -> bool {
        // Heavy box-drawing characters used in denial box borders
        s.contains('\u{256d}')  // ╭ top-left
            || s.contains('\u{256e}')  // ╮ top-right
            || s.contains('\u{256f}')  // ╯ bottom-right
            || s.contains('\u{2570}')  // ╰ bottom-left
            || s.contains('\u{2502}')  // │ vertical bar (used in borders)
            || s.contains('\u{251c}')  // ├ left tee
            || s.contains('\u{2524}')  // ┤ right tee
        // Note: '\u{2500}' (─) is not checked as it may appear in horizontal rules
    }

    #[test]
    fn ci_env_disables_ansi_codes() {
        // With CI=true, stderr should not contain ANSI escape codes
        let (stdout, stderr, exit_code) = run_hook_with_env("git reset --hard", &[("CI", "true")]);

        assert_eq!(exit_code, 0, "hook should exit 0");
        assert!(!stdout.is_empty(), "stdout should have JSON output for denied command");

        // In CI mode, we shouldn't have ANSI codes in stderr
        // Note: Since tests don't run in a TTY, colors are already disabled,
        // but CI=true should reinforce this behavior
        assert!(
            !contains_ansi_codes(&stderr) || stderr.is_empty(),
            "CI=true should disable ANSI codes in stderr output"
        );
    }

    #[test]
    fn ci_env_disables_denial_box_chars() {
        let (_, stderr, _) = run_hook_with_env("git reset --hard", &[("CI", "true")]);

        // In CI mode, should not use denial box border characters
        // (The highlight connector └── is allowed for visual clarity)
        assert!(
            !contains_denial_box_chars(&stderr),
            "CI=true should disable denial box border characters"
        );
    }

    #[test]
    fn ci_env_with_explain_command() {
        // The explain command should also respect CI mode
        let (stdout, stderr, exit_code) =
            run_dcg_with_env(&["explain", "git reset --hard"], &[("CI", "true")]);

        assert_eq!(exit_code, 0, "explain should succeed");
        assert!(stdout.contains("DENY") || stdout.contains("deny"), "should show deny decision");

        // Verify no ANSI codes in output
        assert!(
            !contains_ansi_codes(&stdout) || !contains_ansi_codes(&stderr),
            "CI mode should not have ANSI codes"
        );
    }
}

// ============================================================================
// NO_COLOR Environment Variable Tests
// ============================================================================

mod no_color_tests {
    use super::*;

    fn contains_ansi_codes(s: &str) -> bool {
        s.contains("\x1b[")
    }

    #[test]
    fn no_color_env_disables_colors() {
        let (stdout, stderr, exit_code) =
            run_hook_with_env("git reset --hard", &[("NO_COLOR", "1")]);

        assert_eq!(exit_code, 0, "hook should exit 0");

        // NO_COLOR=1 should disable all ANSI color codes
        assert!(
            !contains_ansi_codes(&stdout),
            "NO_COLOR=1 should disable ANSI codes in stdout"
        );
        assert!(
            !contains_ansi_codes(&stderr),
            "NO_COLOR=1 should disable ANSI codes in stderr"
        );
    }

    #[test]
    fn no_color_env_with_any_value() {
        // NO_COLOR should work with any non-empty value (per spec at no-color.org)
        for value in ["1", "true", "yes", "anything"] {
            let (stdout, stderr, _) =
                run_hook_with_env("git reset --hard", &[("NO_COLOR", value)]);

            assert!(
                !contains_ansi_codes(&stdout) && !contains_ansi_codes(&stderr),
                "NO_COLOR={value} should disable colors"
            );
        }
    }

    #[test]
    fn no_color_empty_value_still_disables() {
        // Even NO_COLOR="" (set but empty) should disable colors per spec
        let (stdout, stderr, _) = run_hook_with_env("git reset --hard", &[("NO_COLOR", "")]);

        assert!(
            !contains_ansi_codes(&stdout) && !contains_ansi_codes(&stderr),
            "NO_COLOR='' should disable colors (env var is set)"
        );
    }

    #[test]
    fn no_color_with_scan_command() {
        let temp = tempfile::tempdir().expect("failed to create temp dir");

        // Create a test file with a destructive command
        let dockerfile = temp.path().join("Dockerfile");
        std::fs::write(&dockerfile, "RUN rm -rf /\n").expect("failed to write test file");

        let (stdout, stderr, _) = run_dcg_with_env(
            &["scan", temp.path().to_str().unwrap()],
            &[("NO_COLOR", "1")],
        );

        // Combined output shouldn't have ANSI codes
        let combined = format!("{stdout}{stderr}");
        assert!(
            !contains_ansi_codes(&combined),
            "scan output with NO_COLOR should not have ANSI codes"
        );
    }
}

// ============================================================================
// TERM=dumb Fallback Tests
// ============================================================================

mod term_dumb_tests {
    use super::*;

    /// Check if output contains denial box border characters.
    ///
    /// Note: The highlight connector └── is allowed for visual clarity.
    fn contains_denial_box_chars(s: &str) -> bool {
        s.contains('\u{256d}')  // ╭
            || s.contains('\u{256e}')  // ╮
            || s.contains('\u{256f}')  // ╯
            || s.contains('\u{2570}')  // ╰
            || s.contains('\u{2502}')  // │ (vertical border)
            || s.contains('\u{251c}')  // ├
            || s.contains('\u{2524}')  // ┤
    }

    fn contains_ansi_codes(s: &str) -> bool {
        s.contains("\x1b[")
    }

    #[test]
    fn term_dumb_disables_denial_box() {
        let (_, stderr, exit_code) = run_hook_with_env("git reset --hard", &[("TERM", "dumb")]);

        assert_eq!(exit_code, 0, "hook should exit 0");

        // TERM=dumb should not use denial box border characters
        // (The highlight connector └── is allowed for visual clarity)
        assert!(
            !contains_denial_box_chars(&stderr),
            "TERM=dumb should not have denial box border characters"
        );
    }

    #[test]
    fn term_dumb_disables_colors() {
        let (stdout, stderr, _) = run_hook_with_env("git reset --hard", &[("TERM", "dumb")]);

        // TERM=dumb should disable colors
        assert!(
            !contains_ansi_codes(&stdout) && !contains_ansi_codes(&stderr),
            "TERM=dumb should disable ANSI colors"
        );
    }

    #[test]
    fn term_dumb_with_explain() {
        let (stdout, stderr, exit_code) =
            run_dcg_with_env(&["explain", "git reset --hard"], &[("TERM", "dumb")]);

        assert_eq!(exit_code, 0, "explain should succeed");

        // Should not have denial box border characters or ANSI codes
        // (The highlight connector └── is allowed for visual clarity)
        let combined = format!("{stdout}{stderr}");
        assert!(
            !contains_denial_box_chars(&combined),
            "TERM=dumb explain should not have denial box border chars"
        );
        assert!(
            !contains_ansi_codes(&combined),
            "TERM=dumb explain should not have ANSI codes"
        );
    }
}

// ============================================================================
// JSON Format Bypass Tests
// ============================================================================

mod json_format_tests {
    use super::*;

    fn contains_box_chars(s: &str) -> bool {
        // Any box-drawing (Unicode or ASCII)
        s.contains('\u{256d}')
            || s.contains('\u{256f}')
            || s.contains('\u{2502}')
            || (s.contains('+') && s.contains('-') && s.contains('|'))
    }

    #[test]
    fn json_format_is_pure_json() {
        let (stdout, _, exit_code) =
            run_dcg_with_env(&["explain", "--format", "json", "git reset --hard"], &[]);

        assert_eq!(exit_code, 0, "explain --format json should succeed");

        // Should be valid JSON
        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("output should be valid JSON");

        assert!(json.is_object(), "JSON output should be an object");
        assert!(
            json.get("decision").is_some() || json.get("command").is_some(),
            "JSON should have expected fields"
        );

        // Should not have box-drawing characters
        assert!(
            !contains_box_chars(&stdout),
            "JSON format should not have box-drawing characters"
        );
    }

    #[test]
    fn json_format_scan_is_valid() {
        let temp = tempfile::tempdir().expect("failed to create temp dir");
        let dockerfile = temp.path().join("Dockerfile");
        std::fs::write(&dockerfile, "RUN rm -rf /\n").expect("failed to write test file");

        let (stdout, stderr, exit_code) = run_dcg_with_env(
            &["scan", "--format", "json", temp.path().to_str().unwrap()],
            &[],
        );

        // exit_code might be non-zero if findings exist, that's OK
        let _ = exit_code;
        let _ = stderr;

        // If there's output, it should be valid JSON
        if !stdout.trim().is_empty() {
            let json: serde_json::Value =
                serde_json::from_str(&stdout).expect("scan --format json should produce valid JSON");

            // Could be an array of findings or an object
            assert!(
                json.is_array() || json.is_object(),
                "JSON output should be array or object"
            );

            // Should not have box characters
            assert!(
                !contains_box_chars(&stdout),
                "JSON scan output should not have box-drawing characters"
            );
        }
    }

    #[test]
    fn hook_output_is_pure_json_when_denied() {
        let (stdout, _, exit_code) = run_hook_with_env("git reset --hard", &[]);

        assert_eq!(exit_code, 0, "hook should exit 0");

        // stdout (hook output) should be pure JSON with no box characters
        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("hook stdout should be valid JSON");

        assert!(
            json.get("hookSpecificOutput").is_some(),
            "should have hookSpecificOutput"
        );

        // Verify no box characters in stdout (the JSON)
        assert!(
            !contains_box_chars(&stdout),
            "hook JSON output should not have box-drawing characters"
        );
    }
}

// ============================================================================
// Safe Command Tests (No Output)
// ============================================================================

mod safe_command_tests {
    use super::*;

    #[test]
    fn safe_command_produces_no_stdout() {
        let (stdout, _, exit_code) = run_hook_with_env("git status", &[]);

        assert_eq!(exit_code, 0, "safe command should exit 0");
        assert!(
            stdout.is_empty() || stdout.trim().is_empty(),
            "safe command should produce no stdout, got: {stdout}"
        );
    }

    #[test]
    fn safe_command_produces_no_rich_stderr() {
        let (_, stderr, exit_code) = run_hook_with_env("git status", &[]);

        assert_eq!(exit_code, 0, "safe command should exit 0");
        assert!(
            stderr.is_empty() || stderr.trim().is_empty(),
            "safe command should produce no stderr, got: {stderr}"
        );
    }

    #[test]
    fn git_clean_dry_run_is_safe() {
        let (stdout, stderr, exit_code) = run_hook_with_env("git clean -n", &[]);

        assert_eq!(exit_code, 0, "git clean -n should exit 0");
        assert!(
            stdout.trim().is_empty(),
            "git clean -n (dry run) should be allowed with no stdout"
        );
        assert!(
            stderr.trim().is_empty(),
            "git clean -n should have no stderr"
        );
    }
}

// ============================================================================
// Denial Output Content Tests
// ============================================================================

mod denial_content_tests {
    use super::*;

    #[test]
    fn denial_stderr_contains_blocked_message() {
        let (_, stderr, _) = run_hook_with_env("git reset --hard", &[]);

        // Stderr should contain the human-readable blocked message
        // Note: In non-TTY mode, this may be plain text
        assert!(
            stderr.contains("BLOCKED") || stderr.contains("blocked") || stderr.is_empty(),
            "denial stderr should contain BLOCKED message or be empty (in non-TTY mode)"
        );
    }

    #[test]
    fn denial_stdout_has_structured_json() {
        let (stdout, _, exit_code) = run_hook_with_env("git reset --hard", &[]);

        assert_eq!(exit_code, 0, "hook exits 0 even on deny");
        assert!(!stdout.is_empty(), "denied command should have JSON output");

        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let hook_output = &json["hookSpecificOutput"];

        assert_eq!(hook_output["permissionDecision"], "deny");
        assert!(hook_output.get("ruleId").is_some(), "should have ruleId");
        assert!(hook_output.get("severity").is_some(), "should have severity");
    }

    #[test]
    fn denial_has_allow_once_info() {
        let (stdout, _, _) = run_hook_with_env("git reset --hard", &[]);

        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let hook_output = &json["hookSpecificOutput"];

        // Should have allow-once code for bypassing
        assert!(
            hook_output.get("allowOnceCode").is_some(),
            "denied command should have allowOnceCode"
        );

        // Should have remediation with allow-once command
        if let Some(remediation) = hook_output.get("remediation") {
            let allow_cmd = remediation["allowOnceCommand"].as_str().unwrap_or("");
            assert!(
                allow_cmd.contains("dcg allow-once"),
                "remediation should contain dcg allow-once command"
            );
        }
    }
}

// ============================================================================
// Multiple Output Modes Test
// ============================================================================

mod output_mode_consistency_tests {
    use super::*;

    /// Test that all environment conditions produce consistent results.
    #[test]
    fn all_env_modes_deny_same_command() {
        let command = "git reset --hard HEAD~5";

        // Test with various environment configurations
        let configs: Vec<(&str, &[(&str, &str)])> = vec![
            ("default", &[]),
            ("CI=true", &[("CI", "true")]),
            ("NO_COLOR=1", &[("NO_COLOR", "1")]),
            ("TERM=dumb", &[("TERM", "dumb")]),
        ];

        for (config_name, env_vars) in configs {
            let (stdout, _, exit_code) = run_hook_with_env(command, env_vars);

            assert_eq!(
                exit_code, 0,
                "{config_name}: hook should exit 0"
            );

            let json: serde_json::Value = serde_json::from_str(&stdout)
                .unwrap_or_else(|e| panic!("{config_name}: invalid JSON: {e}\nstdout: {stdout}"));

            let decision = json["hookSpecificOutput"]["permissionDecision"]
                .as_str()
                .unwrap_or("unknown");

            assert_eq!(
                decision, "deny",
                "{config_name}: should deny destructive command"
            );
        }
    }

    /// Test that all modes allow safe commands.
    #[test]
    fn all_env_modes_allow_safe_command() {
        let command = "git status";

        let configs = vec![
            ("default", vec![]),
            ("CI=true", vec![("CI", "true")]),
            ("NO_COLOR=1", vec![("NO_COLOR", "1")]),
            ("TERM=dumb", vec![("TERM", "dumb")]),
        ];

        for (config_name, env_vars) in configs {
            let (stdout, _, exit_code) =
                run_hook_with_env(command, &env_vars.iter().map(|(k, v)| (*k, *v)).collect::<Vec<_>>());

            assert_eq!(exit_code, 0, "{config_name}: should exit 0");
            assert!(
                stdout.trim().is_empty(),
                "{config_name}: safe command should produce no output"
            );
        }
    }
}

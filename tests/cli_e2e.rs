//! End-to-end tests for CLI flows: explain, scan, simulate.
//!
//! These tests verify that CLI subcommands produce structurally valid output
//! in all supported formats, and return appropriate exit codes.
//!
//! # Running
//!
//! ```bash
//! cargo test --test cli_e2e
//! ```

use std::io::Write;
use std::process::{Command, Stdio};

/// Path to the dcg binary (built in debug mode for tests).
fn dcg_binary() -> std::path::PathBuf {
    // Use the debug binary for tests
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // Remove test binary name
    path.pop(); // Remove deps/
    path.push("dcg");
    path
}

/// Helper to run dcg with arguments and capture output.
fn run_dcg(args: &[&str]) -> std::process::Output {
    Command::new(dcg_binary())
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to execute dcg")
}

// ============================================================================
// DCG EXPLAIN Tests
// ============================================================================

mod explain_tests {
    use super::*;

    #[test]
    fn explain_safe_command_returns_allow_pretty() {
        let output = run_dcg(&["explain", "echo hello"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            output.status.success(),
            "explain should succeed for safe command"
        );
        assert!(
            stdout.contains("Decision: ALLOW"),
            "should show ALLOW decision"
        );
        assert!(stdout.contains("DCG EXPLAIN"), "should have pretty header");
    }

    #[test]
    fn explain_dangerous_command_returns_deny_pretty() {
        let output = run_dcg(&["explain", "docker system prune -a --volumes"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Note: explain returns success even for deny decisions
        assert!(
            stdout.contains("Decision: DENY"),
            "should show DENY decision"
        );
        assert!(stdout.contains("containers.docker"), "should mention pack");
    }

    #[test]
    fn explain_json_format_is_valid() {
        let output = run_dcg(&["explain", "--format", "json", "docker system prune"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse as JSON to validate structure
        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("explain --format json should produce valid JSON");

        assert_eq!(json["schema_version"], 1, "should have schema_version");
        assert!(json["command"].is_string(), "should have command field");
        assert!(json["decision"].is_string(), "should have decision field");
        assert!(
            json["total_duration_us"].is_number(),
            "should have duration"
        );
        assert!(json["steps"].is_array(), "should have steps array");
    }

    #[test]
    fn explain_json_includes_suggestions_for_blocked_commands() {
        let output = run_dcg(&["explain", "--format", "json", "docker system prune -a"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();

        assert_eq!(json["decision"], "deny", "should be denied");
        assert!(json["suggestions"].is_array(), "should have suggestions");
        assert!(
            !json["suggestions"].as_array().unwrap().is_empty(),
            "suggestions should not be empty"
        );
    }

    #[test]
    fn explain_compact_format_is_single_line() {
        let output = run_dcg(&["explain", "--format", "compact", "echo hello"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let lines: Vec<&str> = stdout.trim().lines().collect();
        assert_eq!(lines.len(), 1, "compact format should be single line");
        assert!(
            lines[0].contains("allow") || lines[0].contains("ALLOW"),
            "compact line should contain decision"
        );
    }
}

// ============================================================================
// DCG SCAN Tests
// ============================================================================

mod scan_tests {
    use super::*;

    #[test]
    fn scan_clean_file_returns_success() {
        let mut file = tempfile::Builder::new().suffix(".sh").tempfile().unwrap();
        writeln!(file, "echo hello").unwrap();
        writeln!(file, "ls -la").unwrap();
        file.flush().unwrap();

        let output = run_dcg(&["scan", "--paths", file.path().to_str().unwrap()]);

        assert!(
            output.status.success(),
            "scan should succeed for clean file"
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("No findings") || stdout.contains("Findings: 0"),
            "should report no findings"
        );
    }

    #[test]
    fn scan_dangerous_file_returns_nonzero() {
        let mut file = tempfile::Builder::new().suffix(".sh").tempfile().unwrap();
        writeln!(file, "docker system prune -a").unwrap();
        file.flush().unwrap(); // Ensure content is written before dcg reads it

        let output = run_dcg(&["scan", "--paths", file.path().to_str().unwrap()]);

        assert!(
            !output.status.success(),
            "scan should return non-zero for dangerous file"
        );
    }

    #[test]
    fn scan_json_format_is_valid() {
        let mut file = tempfile::Builder::new().suffix(".sh").tempfile().unwrap();
        writeln!(file, "docker system prune").unwrap();
        file.flush().unwrap();

        let output = run_dcg(&[
            "scan",
            "--paths",
            file.path().to_str().unwrap(),
            "--format",
            "json",
        ]);

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("scan --format json should produce valid JSON");

        assert_eq!(json["schema_version"], 1, "should have schema_version");
        assert!(json["summary"].is_object(), "should have summary object");
        assert!(json["findings"].is_array(), "should have findings array");
    }

    #[test]
    fn scan_json_summary_has_required_fields() {
        let mut file = tempfile::Builder::new().suffix(".sh").tempfile().unwrap();
        writeln!(file, "echo safe").unwrap();
        file.flush().unwrap();

        let output = run_dcg(&[
            "scan",
            "--paths",
            file.path().to_str().unwrap(),
            "--format",
            "json",
        ]);

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let summary = &json["summary"];

        assert!(
            summary["files_scanned"].is_number(),
            "should have files_scanned"
        );
        assert!(
            summary["commands_extracted"].is_number(),
            "should have commands_extracted"
        );
        assert!(
            summary["findings_total"].is_number(),
            "should have findings_total"
        );
        assert!(
            summary["decisions"].is_object(),
            "should have decisions breakdown"
        );
        assert!(summary["elapsed_ms"].is_number(), "should have elapsed_ms");
    }

    #[test]
    fn scan_markdown_format_produces_valid_output() {
        let mut file = tempfile::Builder::new().suffix(".sh").tempfile().unwrap();
        writeln!(file, "docker system prune -a --volumes").unwrap();
        file.flush().unwrap();

        let output = run_dcg(&[
            "scan",
            "--paths",
            file.path().to_str().unwrap(),
            "--format",
            "markdown",
        ]);

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Markdown format should have headers and code blocks
        assert!(
            stdout.contains('#') || stdout.contains("**"),
            "markdown should have formatting"
        );
    }

    #[test]
    fn scan_fail_on_none_always_succeeds() {
        let mut file = tempfile::Builder::new().suffix(".sh").tempfile().unwrap();
        writeln!(file, "docker system prune").unwrap();
        file.flush().unwrap();

        let output = run_dcg(&[
            "scan",
            "--paths",
            file.path().to_str().unwrap(),
            "--fail-on",
            "none",
        ]);

        assert!(
            output.status.success(),
            "scan --fail-on none should always succeed"
        );
    }

    #[test]
    fn scan_empty_directory_succeeds() {
        let dir = tempfile::tempdir().unwrap();

        let output = run_dcg(&["scan", "--paths", dir.path().to_str().unwrap()]);

        assert!(output.status.success(), "scan on empty dir should succeed");
    }

    #[test]
    fn scan_findings_include_file_and_line() {
        let mut file = tempfile::Builder::new().suffix(".sh").tempfile().unwrap();
        writeln!(file, "echo safe").unwrap();
        writeln!(file, "docker system prune").unwrap();
        file.flush().unwrap();

        let output = run_dcg(&[
            "scan",
            "--paths",
            file.path().to_str().unwrap(),
            "--format",
            "json",
        ]);

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let findings = json["findings"].as_array().unwrap();

        assert!(!findings.is_empty(), "should have findings");
        let finding = &findings[0];
        assert!(finding["file"].is_string(), "finding should have file");
        assert!(finding["line"].is_number(), "finding should have line");
        assert!(
            finding["rule_id"].is_string(),
            "finding should have rule_id"
        );
    }
}

// ============================================================================
// DCG TEST (single command evaluation) Tests
// ============================================================================

mod test_command_tests {
    use super::*;

    #[test]
    fn test_safe_command_returns_allowed() {
        let output = run_dcg(&["test", "echo hello"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            output.status.success(),
            "test should succeed for safe command"
        );
        assert!(
            stdout.contains("ALLOWED") || stdout.contains("allow"),
            "should show allowed result"
        );
    }

    #[test]
    fn test_dangerous_command_returns_blocked() {
        let output = run_dcg(&["test", "docker system prune -a"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Note: test command currently returns exit code 0 even for blocked commands
        // This tests the output content instead
        assert!(
            stdout.contains("BLOCKED") || stdout.contains("blocked"),
            "should show blocked result"
        );
        assert!(
            stdout.contains("containers.docker"),
            "should mention the pack that blocked it"
        );
    }

    #[test]
    fn test_output_includes_rule_info() {
        let output = run_dcg(&["test", "docker system prune"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        // The output should include pattern information
        assert!(
            stdout.contains("system-prune") || stdout.contains("Pattern"),
            "should include pattern info"
        );
    }
}

// ============================================================================
// DCG CONFIG Tests
// ============================================================================

mod config_tests {
    use super::*;

    #[test]
    fn config_show_produces_output() {
        let output = run_dcg(&["config"]);

        // Config command should produce some output about current config
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{stdout}{stderr}");

        assert!(!combined.is_empty(), "config should produce some output");
    }
}

// ============================================================================
// DCG PACKS Tests
// ============================================================================

mod packs_tests {
    use super::*;

    #[test]
    fn packs_list_shows_available_packs() {
        let output = run_dcg(&["packs"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success(), "packs should succeed");
        assert!(stdout.contains("core.git"), "should list core.git pack");
        assert!(
            stdout.contains("containers.docker") || stdout.contains("docker"),
            "should list docker pack"
        );
    }

    #[test]
    fn pack_show_displays_pack_info() {
        let output = run_dcg(&["pack", "core.git"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success(), "pack show should succeed");
        assert!(
            stdout.contains("git") || stdout.contains("Git"),
            "should show git pack info"
        );
    }
}

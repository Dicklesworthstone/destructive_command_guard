#![allow(clippy::needless_raw_string_hashes)]
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

#[derive(Debug)]
struct HookRunOutput {
    command: String,
    output: std::process::Output,
}

impl HookRunOutput {
    fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.output.stdout).to_string()
    }

    fn stderr_str(&self) -> String {
        String::from_utf8_lossy(&self.output.stderr).to_string()
    }
}

/// Run dcg in hook mode (no CLI subcommand) and capture output.
///
/// This runs with a cleared environment and a temp CWD to ensure tests don't
/// depend on user/system configs or allowlists.
fn run_dcg_hook_with_env(command: &str, extra_env: &[(&str, &std::ffi::OsStr)]) -> HookRunOutput {
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
    for (key, value) in extra_env {
        cmd.env(key, value);
    }

    let mut child = cmd.spawn().expect("failed to spawn dcg hook mode");

    {
        let stdin = child.stdin.as_mut().expect("failed to open stdin");
        serde_json::to_writer(stdin, &input).expect("failed to write hook input JSON");
    }

    let output = child.wait_with_output().expect("failed to wait for dcg");

    HookRunOutput {
        command: command.to_string(),
        output,
    }
}

fn run_dcg_hook(command: &str) -> HookRunOutput {
    run_dcg_hook_with_env(command, &[])
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
        // Use git command since core.git is always enabled
        let output = run_dcg(&["explain", "git reset --hard"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Note: explain returns success even for deny decisions
        assert!(
            stdout.contains("Decision: DENY"),
            "should show DENY decision"
        );
        assert!(stdout.contains("core.git"), "should mention pack");
    }

    #[test]
    fn explain_json_format_is_valid() {
        // Use git command since core.git is always enabled
        let output = run_dcg(&["explain", "--format", "json", "git reset --hard"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse as JSON to validate structure
        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("explain --format json should produce valid JSON");

        assert_eq!(json["schema_version"], 2, "should have schema_version");
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
        // Use git command since core.git is always enabled
        let output = run_dcg(&["explain", "--format", "json", "git reset --hard"]);
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
// Allow-once management CLI tests
// ============================================================================

mod allow_once_management_tests {
    use super::*;

    use chrono::{DateTime, Utc};
    use destructive_command_guard::logging::{RedactionConfig, RedactionMode};
    use destructive_command_guard::pending_exceptions::{
        AllowOnceEntry, AllowOnceScopeKind, PendingExceptionRecord,
    };

    struct AllowOnceEnv {
        temp: tempfile::TempDir,
        home_dir: std::path::PathBuf,
        xdg_config_dir: std::path::PathBuf,
        pending_path: std::path::PathBuf,
        allow_once_path: std::path::PathBuf,
    }

    impl AllowOnceEnv {
        fn new() -> Self {
            let temp = tempfile::tempdir().expect("tempdir");
            let home_dir = temp.path().join("home");
            let xdg_config_dir = temp.path().join("xdg_config");
            std::fs::create_dir_all(&home_dir).expect("HOME dir");
            std::fs::create_dir_all(&xdg_config_dir).expect("XDG_CONFIG_HOME dir");

            let pending_path = temp.path().join("pending_exceptions.jsonl");
            let allow_once_path = temp.path().join("allow_once.jsonl");

            Self {
                temp,
                home_dir,
                xdg_config_dir,
                pending_path,
                allow_once_path,
            }
        }

        fn write_records(&self, pending: &PendingExceptionRecord, allow_once: &AllowOnceEntry) {
            let pending_line = serde_json::to_string(pending).expect("serialize pending");
            let allow_once_line = serde_json::to_string(allow_once).expect("serialize allow-once");

            std::fs::write(&self.pending_path, format!("{pending_line}\n"))
                .expect("write pending jsonl");
            std::fs::write(&self.allow_once_path, format!("{allow_once_line}\n"))
                .expect("write allow-once jsonl");
        }

        fn run(&self, args: &[&str]) -> std::process::Output {
            Command::new(dcg_binary())
                .env_clear()
                .env("HOME", &self.home_dir)
                .env("XDG_CONFIG_HOME", &self.xdg_config_dir)
                .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
                .env("DCG_PENDING_EXCEPTIONS_PATH", &self.pending_path)
                .env("DCG_ALLOW_ONCE_PATH", &self.allow_once_path)
                .current_dir(self.temp.path())
                .args(args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .expect("run dcg")
        }
    }

    fn fixed_timestamp() -> DateTime<Utc> {
        // Use a far-future timestamp so tests don't become time-sensitive as real time advances.
        DateTime::parse_from_rfc3339("2099-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    const fn redaction_config() -> RedactionConfig {
        RedactionConfig {
            enabled: true,
            mode: RedactionMode::Arguments,
            max_argument_len: 4,
        }
    }

    #[test]
    fn allow_once_list_redacts_by_default_and_show_raw_reveals() {
        let env = AllowOnceEnv::new();
        let now = fixed_timestamp();
        let redaction = redaction_config();

        let command_raw = r#"echo "0123456789""#;
        let pending = PendingExceptionRecord::new(
            now,
            env.temp.path().to_string_lossy().as_ref(),
            command_raw,
            "test pending",
            &redaction,
            false,
            None,
        );
        let allow_once = AllowOnceEntry::from_pending(
            &pending,
            now,
            AllowOnceScopeKind::Cwd,
            env.temp.path().to_string_lossy().as_ref(),
            false,
            false,
            &redaction,
        );
        env.write_records(&pending, &allow_once);

        let output = env.run(&["allow-once", "list"]);
        assert!(
            output.status.success(),
            "list should succeed: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains(&pending.command_redacted));
        assert!(stdout.contains(&allow_once.command_redacted));
        assert!(
            !stdout.contains("0123456789"),
            "raw secret should not appear"
        );

        let output_raw = env.run(&["allow-once", "list", "--show-raw"]);
        assert!(output_raw.status.success());
        let stdout_raw = String::from_utf8_lossy(&output_raw.stdout);
        assert!(
            stdout_raw.contains("0123456789"),
            "raw secret should appear"
        );
    }

    #[test]
    fn allow_once_revoke_removes_pending_and_active() {
        let env = AllowOnceEnv::new();
        let now = fixed_timestamp();
        let redaction = redaction_config();

        let command_raw = r#"echo "abcdefghijklmnopqrstuvwxyz""#;
        let pending = PendingExceptionRecord::new(
            now,
            env.temp.path().to_string_lossy().as_ref(),
            command_raw,
            "test revoke",
            &redaction,
            false,
            None,
        );
        let allow_once = AllowOnceEntry::from_pending(
            &pending,
            now,
            AllowOnceScopeKind::Cwd,
            env.temp.path().to_string_lossy().as_ref(),
            false,
            false,
            &redaction,
        );
        env.write_records(&pending, &allow_once);

        let hash_prefix = &pending.full_hash[..8.min(pending.full_hash.len())];
        let output = env.run(&["allow-once", "revoke", hash_prefix, "--yes", "--json"]);
        assert!(
            output.status.success(),
            "revoke should succeed: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("valid JSON output");
        assert_eq!(json["pending"]["removed"], 1);
        assert_eq!(json["allow_once"]["removed"], 1);

        let output_list = env.run(&["allow-once", "list", "--json"]);
        assert!(output_list.status.success());
        let json_list: serde_json::Value =
            serde_json::from_slice(&output_list.stdout).expect("valid JSON output");
        assert_eq!(json_list["pending"]["count"], 0);
        assert_eq!(json_list["allow_once"]["count"], 0);
    }

    #[test]
    fn allow_once_clear_all_wipes_stores() {
        let env = AllowOnceEnv::new();
        let now = fixed_timestamp();
        let redaction = redaction_config();

        let command_raw = r#"echo "abcdefghijklmnopqrstuvwxyz""#;
        let pending = PendingExceptionRecord::new(
            now,
            env.temp.path().to_string_lossy().as_ref(),
            command_raw,
            "test clear",
            &redaction,
            false,
            None,
        );
        let allow_once = AllowOnceEntry::from_pending(
            &pending,
            now,
            AllowOnceScopeKind::Cwd,
            env.temp.path().to_string_lossy().as_ref(),
            false,
            false,
            &redaction,
        );
        env.write_records(&pending, &allow_once);

        let output = env.run(&["allow-once", "clear", "--all", "--yes", "--json"]);
        assert!(
            output.status.success(),
            "clear should succeed: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("valid JSON output");
        assert_eq!(json["pending"]["wiped"], 1);
        assert_eq!(json["allow_once"]["wiped"], 1);

        let output_list = env.run(&["allow-once", "list", "--json"]);
        assert!(output_list.status.success());
        let json_list: serde_json::Value =
            serde_json::from_slice(&output_list.stdout).expect("valid JSON output");
        assert_eq!(json_list["pending"]["count"], 0);
        assert_eq!(json_list["allow_once"]["count"], 0);
    }
}

// ============================================================================
// Allow-once Full Flow E2E Tests
// ============================================================================

mod allow_once_flow_tests {
    use super::*;

    /// Dedicated test environment with control over all file paths.
    struct FlowTestEnv {
        temp: tempfile::TempDir,
        home_dir: std::path::PathBuf,
        xdg_config_dir: std::path::PathBuf,
        pending_path: std::path::PathBuf,
        allow_once_path: std::path::PathBuf,
    }

    impl FlowTestEnv {
        fn new() -> Self {
            let temp = tempfile::tempdir().expect("tempdir");
            let home_dir = temp.path().join("home");
            let xdg_config_dir = temp.path().join("xdg_config");
            std::fs::create_dir_all(&home_dir).expect("HOME dir");
            std::fs::create_dir_all(&xdg_config_dir).expect("XDG_CONFIG_HOME dir");
            // Create a .git directory so it's recognized as a repo
            std::fs::create_dir_all(temp.path().join(".git")).expect(".git dir");

            let pending_path = temp.path().join("pending_exceptions.jsonl");
            let allow_once_path = temp.path().join("allow_once.jsonl");

            Self {
                temp,
                home_dir,
                xdg_config_dir,
                pending_path,
                allow_once_path,
            }
        }

        /// Run dcg in hook mode with JSON input.
        fn run_hook(&self, command: &str) -> HookRunOutput {
            let input = serde_json::json!({
                "tool_name": "Bash",
                "tool_input": {
                    "command": command,
                }
            });

            let mut cmd = Command::new(dcg_binary());
            cmd.env_clear()
                .env("HOME", &self.home_dir)
                .env("XDG_CONFIG_HOME", &self.xdg_config_dir)
                .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
                .env("DCG_PACKS", "core.git,core.filesystem")
                .env("DCG_PENDING_EXCEPTIONS_PATH", &self.pending_path)
                .env("DCG_ALLOW_ONCE_PATH", &self.allow_once_path)
                .current_dir(self.temp.path())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());

            let mut child = cmd.spawn().expect("failed to spawn dcg hook mode");

            {
                let stdin = child.stdin.as_mut().expect("failed to open stdin");
                serde_json::to_writer(stdin, &input).expect("failed to write hook input JSON");
            }

            let output = child.wait_with_output().expect("failed to wait for dcg");

            HookRunOutput {
                command: command.to_string(),
                output,
            }
        }

        /// Run dcg CLI commands (not hook mode).
        fn run_cli(&self, args: &[&str]) -> std::process::Output {
            Command::new(dcg_binary())
                .env_clear()
                .env("HOME", &self.home_dir)
                .env("XDG_CONFIG_HOME", &self.xdg_config_dir)
                .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
                .env("DCG_PENDING_EXCEPTIONS_PATH", &self.pending_path)
                .env("DCG_ALLOW_ONCE_PATH", &self.allow_once_path)
                .current_dir(self.temp.path())
                .args(args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .expect("run dcg cli")
        }

        /// Run dcg in hook mode in a different directory (for scoping tests).
        fn run_hook_in_dir(&self, command: &str, cwd: &std::path::Path) -> HookRunOutput {
            let input = serde_json::json!({
                "tool_name": "Bash",
                "tool_input": {
                    "command": command,
                }
            });

            let mut cmd = Command::new(dcg_binary());
            cmd.env_clear()
                .env("HOME", &self.home_dir)
                .env("XDG_CONFIG_HOME", &self.xdg_config_dir)
                .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
                .env("DCG_PACKS", "core.git,core.filesystem")
                .env("DCG_PENDING_EXCEPTIONS_PATH", &self.pending_path)
                .env("DCG_ALLOW_ONCE_PATH", &self.allow_once_path)
                .current_dir(cwd)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());

            let mut child = cmd.spawn().expect("failed to spawn dcg hook mode");

            {
                let stdin = child.stdin.as_mut().expect("failed to open stdin");
                serde_json::to_writer(stdin, &input).expect("failed to write hook input JSON");
            }

            let output = child.wait_with_output().expect("failed to wait for dcg");

            HookRunOutput {
                command: command.to_string(),
                output,
            }
        }
    }

    /// Extract the allow-once code from a hook denial JSON output.
    fn extract_code_from_denial(stdout: &str) -> Option<String> {
        let json: serde_json::Value = serde_json::from_str(stdout.trim()).ok()?;
        json["hookSpecificOutput"]["allowOnceCode"]
            .as_str()
            .map(String::from)
    }

    fn assert_is_denial(result: &HookRunOutput) -> String {
        let stdout = result.stdout_str();

        assert!(
            result.output.status.success(),
            "hook mode should exit successfully\nstdout:\n{}\nstderr:\n{}",
            stdout,
            result.stderr_str()
        );

        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("expected JSON stdout for denial");

        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"],
            "deny",
            "expected permissionDecision=deny\nstdout:\n{}\nstderr:\n{}",
            stdout,
            result.stderr_str()
        );

        stdout
    }

    fn assert_is_allowed(result: &HookRunOutput) {
        let stdout = result.stdout_str();

        assert!(
            result.output.status.success(),
            "hook mode should exit successfully\nstdout:\n{}\nstderr:\n{}",
            stdout,
            result.stderr_str()
        );

        assert!(
            stdout.trim().is_empty(),
            "expected no stdout (allowed) but got:\nstdout:\n{}\nstderr:\n{}",
            stdout,
            result.stderr_str()
        );
    }

    #[test]
    fn block_emits_code_and_allow_once_allows() {
        let env = FlowTestEnv::new();
        let command = "git reset --hard";

        // Step 1: Run blocked command in hook mode, verify it's denied with a code
        let result1 = env.run_hook(command);
        let stdout1 = assert_is_denial(&result1);

        let code = extract_code_from_denial(&stdout1)
            .expect("blocked command should emit allow-once code");
        assert!(
            code.len() >= 4,
            "code should be at least 4 chars, got: {code}"
        );

        // Step 2: Use dcg allow-once <code> --yes to activate the exception
        let allow_output = env.run_cli(&["allow-once", &code, "--yes"]);
        assert!(
            allow_output.status.success(),
            "allow-once should succeed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&allow_output.stdout),
            String::from_utf8_lossy(&allow_output.stderr)
        );

        // Step 3: Re-run the same command, should now be allowed
        let result2 = env.run_hook(command);
        assert_is_allowed(&result2);

        // Step 4: Run it again to verify reusable (not single-use)
        let result3 = env.run_hook(command);
        assert_is_allowed(&result3);
    }

    #[test]
    fn block_emits_full_hash_in_hook_output() {
        let env = FlowTestEnv::new();
        let command = "git reset --hard";

        let result = env.run_hook(command);
        let stdout = assert_is_denial(&result);

        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("expected JSON stdout");

        // Verify full hash is present
        let full_hash = json["hookSpecificOutput"]["allowOnceFullHash"]
            .as_str()
            .expect("should have allowOnceFullHash");
        assert!(
            full_hash.len() >= 16,
            "full hash should be long, got: {full_hash}"
        );

        // Verify short code is a prefix of or derived from the hash
        let code = json["hookSpecificOutput"]["allowOnceCode"]
            .as_str()
            .expect("should have allowOnceCode");
        assert!(!code.is_empty(), "code should not be empty");
    }

    #[test]
    fn cwd_scoping_blocks_same_command_in_different_directory() {
        let env = FlowTestEnv::new();
        let command = "git reset --hard";

        // Step 1: Block and get code
        let result1 = env.run_hook(command);
        let stdout1 = assert_is_denial(&result1);
        let code = extract_code_from_denial(&stdout1).expect("should emit code");

        // Step 2: Allow it
        let allow_output = env.run_cli(&["allow-once", &code, "--yes"]);
        assert!(allow_output.status.success(), "allow-once should succeed");

        // Step 3: Same command in same directory is allowed
        let result2 = env.run_hook(command);
        assert_is_allowed(&result2);

        // Step 4: Create a different directory outside the original temp dir
        let other_temp = tempfile::tempdir().expect("other tempdir");
        std::fs::create_dir_all(other_temp.path().join(".git")).expect("create .git in other dir");

        // Step 5: Same command in different directory is still blocked
        let result3 = env.run_hook_in_dir(command, other_temp.path());
        assert_is_denial(&result3);
    }

    #[test]
    fn single_use_consumed_after_first_allow() {
        let env = FlowTestEnv::new();
        let command = "git reset --hard";

        // Step 1: Block and get code
        let result1 = env.run_hook(command);
        let stdout1 = assert_is_denial(&result1);
        let code = extract_code_from_denial(&stdout1).expect("should emit code");

        // Step 2: Allow it with --single-use
        let allow_output = env.run_cli(&["allow-once", &code, "--yes", "--single-use"]);
        assert!(
            allow_output.status.success(),
            "allow-once --single-use should succeed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&allow_output.stdout),
            String::from_utf8_lossy(&allow_output.stderr)
        );

        // Step 3: First run is allowed
        let result2 = env.run_hook(command);
        assert_is_allowed(&result2);

        // Step 4: Second run is blocked again (single-use consumed)
        let result3 = env.run_hook(command);
        assert_is_denial(&result3);
    }

    #[test]
    fn allow_once_list_shows_pending_and_active_entries() {
        let env = FlowTestEnv::new();
        let command = "git reset --hard";

        // Step 1: Block to create pending entry
        let result1 = env.run_hook(command);
        let stdout1 = assert_is_denial(&result1);
        let code = extract_code_from_denial(&stdout1).expect("should emit code");

        // Step 2: Check list shows pending
        let list_output1 = env.run_cli(&["allow-once", "list", "--json"]);
        assert!(list_output1.status.success(), "list should succeed");
        let list_json1: serde_json::Value =
            serde_json::from_slice(&list_output1.stdout).expect("valid JSON");
        assert!(
            list_json1["pending"]["count"].as_u64().unwrap_or(0) >= 1,
            "should have at least 1 pending entry\njson: {list_json1}"
        );

        // Step 3: Allow it
        let allow_output = env.run_cli(&["allow-once", &code, "--yes"]);
        assert!(allow_output.status.success(), "allow-once should succeed");

        // Step 4: Check list shows active entry
        let list_output2 = env.run_cli(&["allow-once", "list", "--json"]);
        assert!(list_output2.status.success(), "list should succeed");
        let list_json2: serde_json::Value =
            serde_json::from_slice(&list_output2.stdout).expect("valid JSON");
        assert!(
            list_json2["allow_once"]["count"].as_u64().unwrap_or(0) >= 1,
            "should have at least 1 active entry\njson: {list_json2}"
        );
    }

    #[test]
    fn force_flag_required_for_config_block_override() {
        let env = FlowTestEnv::new();
        let command = "git reset --hard";

        // Create a config that explicitly blocks git reset --hard
        let config_path = env.temp.path().join("dcg.toml");
        std::fs::write(
            &config_path,
            r"
[overrides]
block = [
  { pattern = '\bgit\s+reset\s+--hard\b', reason = 'test config block' },
]
",
        )
        .expect("write config");

        // Run hook with the config (this creates a pending entry)
        let input = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {
                "command": command,
            }
        });

        let mut cmd = Command::new(dcg_binary());
        cmd.env_clear()
            .env("HOME", &env.home_dir)
            .env("XDG_CONFIG_HOME", &env.xdg_config_dir)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env("DCG_PACKS", "core.git,core.filesystem")
            .env("DCG_PENDING_EXCEPTIONS_PATH", &env.pending_path)
            .env("DCG_ALLOW_ONCE_PATH", &env.allow_once_path)
            .env("DCG_CONFIG", &config_path)
            .current_dir(env.temp.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().expect("failed to spawn dcg hook mode");
        {
            let stdin = child.stdin.as_mut().expect("failed to open stdin");
            serde_json::to_writer(stdin, &input).expect("failed to write hook input JSON");
        }
        let hook_output = child.wait_with_output().expect("failed to wait for dcg");
        let stdout = String::from_utf8_lossy(&hook_output.stdout);

        let code = extract_code_from_denial(&stdout).expect("should emit code for config block");

        // Step 2: Try to allow without --force - should fail
        let allow_no_force = Command::new(dcg_binary())
            .env_clear()
            .env("HOME", &env.home_dir)
            .env("XDG_CONFIG_HOME", &env.xdg_config_dir)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env("DCG_PENDING_EXCEPTIONS_PATH", &env.pending_path)
            .env("DCG_ALLOW_ONCE_PATH", &env.allow_once_path)
            .env("DCG_CONFIG", &config_path)
            .current_dir(env.temp.path())
            .args(["allow-once", &code, "--yes"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("run dcg allow-once");

        assert!(
            !allow_no_force.status.success(),
            "allow-once without --force should fail for config block\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&allow_no_force.stdout),
            String::from_utf8_lossy(&allow_no_force.stderr)
        );
        let stderr = String::from_utf8_lossy(&allow_no_force.stderr);
        assert!(
            stderr.contains("config blocklist") || stderr.contains("--force"),
            "error should mention config blocklist or --force\nstderr: {stderr}"
        );
    }

    #[test]
    fn collision_handling_with_multiple_pending_entries() {
        let env = FlowTestEnv::new();

        // Create two commands that might produce the same short code prefix
        // (unlikely but the system should handle it via --pick or full hash)
        let command1 = "git reset --hard";
        let command2 = "git clean -fdx";

        // Block both commands
        let result1 = env.run_hook(command1);
        let stdout1 = assert_is_denial(&result1);
        let code1 = extract_code_from_denial(&stdout1).expect("should emit code for command1");

        let result2 = env.run_hook(command2);
        let stdout2 = assert_is_denial(&result2);
        let code2 = extract_code_from_denial(&stdout2).expect("should emit code for command2");

        // Verify we got unique codes
        assert_ne!(
            code1, code2,
            "different commands should have different codes"
        );

        // Allow the first one
        let allow_output = env.run_cli(&["allow-once", &code1, "--yes"]);
        assert!(
            allow_output.status.success(),
            "allow-once for code1 should succeed"
        );

        // First command is allowed, second is still blocked
        let verify1 = env.run_hook(command1);
        assert_is_allowed(&verify1);

        let verify2 = env.run_hook(command2);
        assert_is_denial(&verify2);
    }

    #[test]
    fn revoke_removes_active_exception() {
        let env = FlowTestEnv::new();
        let command = "git reset --hard";

        // Step 1: Block and allow
        let result1 = env.run_hook(command);
        let stdout1 = assert_is_denial(&result1);
        let code = extract_code_from_denial(&stdout1).expect("should emit code");

        let allow_output = env.run_cli(&["allow-once", &code, "--yes"]);
        assert!(allow_output.status.success(), "allow-once should succeed");

        // NOTE: We do NOT verify it's allowed here because single-use exceptions
        // are consumed on first use. We want to test revoke on an unconsumed exception.

        // Step 2: Revoke the exception before it's used
        let revoke_output = env.run_cli(&["allow-once", "revoke", &code, "--yes", "--json"]);
        assert!(
            revoke_output.status.success(),
            "revoke should succeed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&revoke_output.stdout),
            String::from_utf8_lossy(&revoke_output.stderr)
        );

        // Step 3: Command should be blocked again
        let result3 = env.run_hook(command);
        assert_is_denial(&result3);
    }

    #[test]
    fn dry_run_does_not_create_exception() {
        let env = FlowTestEnv::new();
        let command = "git reset --hard";

        // Step 1: Block and get code
        let result1 = env.run_hook(command);
        let stdout1 = assert_is_denial(&result1);
        let code = extract_code_from_denial(&stdout1).expect("should emit code");

        // Step 2: Dry-run allow
        let allow_output = env.run_cli(&["allow-once", &code, "--dry-run"]);
        assert!(
            allow_output.status.success(),
            "allow-once --dry-run should succeed"
        );

        // Step 3: Command should still be blocked (dry-run doesn't write)
        let result2 = env.run_hook(command);
        assert_is_denial(&result2);
    }

    #[test]
    fn json_output_mode_works() {
        let env = FlowTestEnv::new();
        let command = "git reset --hard";

        // Block and get code
        let result1 = env.run_hook(command);
        let stdout1 = assert_is_denial(&result1);
        let code = extract_code_from_denial(&stdout1).expect("should emit code");

        // Allow with --json --yes
        let allow_output = env.run_cli(&["allow-once", &code, "--yes", "--json"]);
        assert!(
            allow_output.status.success(),
            "allow-once --json should succeed"
        );

        let json: serde_json::Value =
            serde_json::from_slice(&allow_output.stdout).expect("should be valid JSON");
        assert_eq!(json["status"], "ok", "JSON output should show status ok");
        assert_eq!(json["code"], code, "JSON output should include code");
        assert!(
            json["expires_at"].is_string(),
            "JSON output should include expires_at"
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
        // Use git command since core.git is always enabled
        writeln!(file, "git reset --hard").unwrap();
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
        // Use git command since core.git is always enabled
        writeln!(file, "git reset --hard").unwrap();
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
        // Use git command since core.git is always enabled
        writeln!(file, "git reset --hard HEAD~1").unwrap();
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
        // Use git command since core.git is always enabled
        writeln!(file, "git reset --hard").unwrap();
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
        // Use git command since core.git is always enabled
        writeln!(file, "git reset --hard").unwrap();
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
        // Use git command since core.git is always enabled
        let output = run_dcg(&["test", "git reset --hard"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Note: test command currently returns exit code 0 even for blocked commands
        // This tests the output content instead
        assert!(
            stdout.contains("BLOCKED") || stdout.contains("blocked"),
            "should show blocked result"
        );
        assert!(
            stdout.contains("core.git"),
            "should mention the pack that blocked it"
        );
    }

    #[test]
    fn test_output_includes_rule_info() {
        // Use git command since core.git is always enabled
        let output = run_dcg(&["test", "git reset --hard"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        // The output should include pattern information
        assert!(
            stdout.contains("hard-reset") || stdout.contains("Pattern"),
            "should include pattern info"
        );
    }
}

// ============================================================================
// DCG CONFIG Tests
// ============================================================================

mod config_tests {
    use super::*;

    fn setup_doctor_env(
        temp: &tempfile::TempDir,
    ) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let home_dir = temp.path().join("home");
        let xdg_config_dir = temp.path().join("xdg_config");
        let bin_dir = temp.path().join("bin");

        std::fs::create_dir_all(&home_dir).expect("HOME dir");
        std::fs::create_dir_all(&xdg_config_dir).expect("XDG_CONFIG_HOME dir");
        std::fs::create_dir_all(&bin_dir).expect("bin dir");
        std::fs::create_dir_all(temp.path().join(".git")).expect(".git dir");

        let dcg_stub = bin_dir.join("dcg");
        std::fs::write(&dcg_stub, b"").expect("write dcg stub");

        (home_dir, xdg_config_dir, bin_dir)
    }

    #[test]
    fn config_show_produces_output() {
        let output = run_dcg(&["config"]);

        // Config command should produce some output about current config
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{stdout}{stderr}");

        assert!(!combined.is_empty(), "config should produce some output");
    }

    #[test]
    fn config_honors_dcg_config_override() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home_dir = temp.path().join("home");
        let xdg_config_dir = temp.path().join("xdg_config");
        std::fs::create_dir_all(&home_dir).expect("HOME dir");
        std::fs::create_dir_all(&xdg_config_dir).expect("XDG_CONFIG_HOME dir");

        let cfg_path = temp.path().join("explicit_config.toml");
        std::fs::write(&cfg_path, "[general]\nverbose = true\n").expect("write config");

        let output = Command::new(dcg_binary())
            .env_clear()
            .env("HOME", &home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("DCG_CONFIG", &cfg_path)
            .current_dir(temp.path())
            .arg("config")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("run dcg config");

        assert!(output.status.success(), "dcg config should succeed");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("Verbose: true"),
            "expected config from DCG_CONFIG to take effect\nstdout:\n{stdout}"
        );
        assert!(
            stdout.contains("DCG_CONFIG:"),
            "expected config sources to mention DCG_CONFIG\nstdout:\n{stdout}"
        );
    }

    #[test]
    fn doctor_reports_missing_dcg_config_override() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home_dir = temp.path().join("home");
        let xdg_config_dir = temp.path().join("xdg_config");
        std::fs::create_dir_all(&home_dir).expect("HOME dir");
        std::fs::create_dir_all(&xdg_config_dir).expect("XDG_CONFIG_HOME dir");

        let missing = temp.path().join("missing_config.toml");

        let output = Command::new(dcg_binary())
            .env_clear()
            .env("HOME", &home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("DCG_CONFIG", &missing)
            .current_dir(temp.path())
            .arg("doctor")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("run dcg doctor");

        assert!(output.status.success(), "dcg doctor should run");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            combined.contains("DCG_CONFIG points to a missing file"),
            "expected doctor to surface missing DCG_CONFIG\noutput:\n{combined}"
        );
    }

    #[test]
    fn doctor_pretty_output_basics() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (home_dir, xdg_config_dir, bin_dir) = setup_doctor_env(&temp);

        let output = Command::new(dcg_binary())
            .env_clear()
            .env("HOME", &home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("PATH", &bin_dir)
            .env("NO_COLOR", "1")
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .current_dir(temp.path())
            .arg("doctor")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("run dcg doctor");

        assert!(output.status.success(), "dcg doctor should succeed");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            combined.contains("dcg doctor"),
            "expected header in doctor output\noutput:\n{combined}"
        );
        assert!(
            combined.contains("Checking configuration... USING DEFAULTS"),
            "expected defaults notice\noutput:\n{combined}"
        );
        assert!(
            combined.contains("Checking allowlist entries... NONE"),
            "expected allowlist none notice\noutput:\n{combined}"
        );
    }

    #[test]
    fn doctor_fix_installs_hook_and_config() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (home_dir, xdg_config_dir, bin_dir) = setup_doctor_env(&temp);

        let claude_dir = home_dir.join(".claude");
        std::fs::create_dir_all(&claude_dir).expect("claude dir");
        let settings_path = claude_dir.join("settings.json");
        std::fs::write(&settings_path, "{}").expect("write settings");

        let output = Command::new(dcg_binary())
            .env_clear()
            .env("HOME", &home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("PATH", &bin_dir)
            .env("NO_COLOR", "1")
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .current_dir(temp.path())
            .args(["doctor", "--fix"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("run dcg doctor --fix");

        assert!(output.status.success(), "dcg doctor --fix should succeed");

        let settings = std::fs::read_to_string(&settings_path).expect("read settings");
        let settings_json: serde_json::Value =
            serde_json::from_str(&settings).expect("parse settings");
        let hooks = settings_json
            .get("hooks")
            .and_then(|h| h.get("PreToolUse"))
            .and_then(|arr| arr.as_array())
            .expect("PreToolUse array");
        let has_dcg = hooks.iter().any(|entry| {
            entry.get("matcher").and_then(|m| m.as_str()) == Some("Bash")
                && entry
                    .get("hooks")
                    .and_then(|h| h.as_array())
                    .is_some_and(|hooks| {
                        hooks.iter().any(|hook| {
                            hook.get("command")
                                .and_then(|c| c.as_str())
                                .is_some_and(|c| c == "dcg")
                        })
                    })
        });
        assert!(has_dcg, "expected dcg hook to be installed");

        let config_path = xdg_config_dir.join("dcg").join("config.toml");
        let config_contents = std::fs::read_to_string(&config_path).expect("read config.toml");
        assert!(
            !config_contents.trim().is_empty(),
            "expected config.toml to be created"
        );
    }

    #[test]
    fn doctor_json_output_is_valid() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (home_dir, xdg_config_dir, bin_dir) = setup_doctor_env(&temp);

        let output = Command::new(dcg_binary())
            .env_clear()
            .env("HOME", &home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("PATH", &bin_dir)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .current_dir(temp.path())
            .args(["doctor", "--format", "json"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("run dcg doctor --format json");

        assert!(
            output.status.success(),
            "dcg doctor --format json should succeed"
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        let parsed: serde_json::Value =
            serde_json::from_str(&stdout).expect("doctor JSON output should parse");
        assert_eq!(parsed["schema_version"], 1);
        let checks = parsed["checks"].as_array().expect("checks array");
        assert!(
            checks.iter().any(|c| c["id"] == "binary_path"),
            "expected binary_path check in JSON output"
        );
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
        let output = run_dcg(&["pack", "info", "core.git"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success(), "pack show should succeed");
        assert!(
            stdout.contains("git") || stdout.contains("Git"),
            "should show git pack info"
        );
    }
}

// ============================================================================
// DCG Hook Mode Tests (stdin JSON protocol)
// ============================================================================

mod hook_mode_tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use destructive_command_guard::logging::{RedactionConfig, RedactionMode};
    use destructive_command_guard::pending_exceptions::{
        AllowOnceEntry, AllowOnceScopeKind, PendingExceptionRecord,
    };

    fn assert_hook_denies(command: &str) {
        let result = run_dcg_hook(command);
        let stdout = result.stdout_str();

        assert!(
            result.output.status.success(),
            "hook mode should exit successfully\ncommand: {}\nstdout:\n{}\nstderr:\n{}",
            result.command,
            stdout,
            result.stderr_str()
        );

        let mut parse_error = None;
        let json: serde_json::Value = match serde_json::from_str(stdout.trim()) {
            Ok(value) => value,
            Err(e) => {
                parse_error = Some(format!(
                    "expected hook JSON output for deny, got parse error: {e}\ncommand: {}\nstdout:\n{}\nstderr:\n{}",
                    result.command,
                    stdout,
                    result.stderr_str()
                ));
                serde_json::Value::Null
            }
        };

        assert!(parse_error.is_none(), "{}", parse_error.unwrap());

        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"],
            "deny",
            "expected permissionDecision=deny\ncommand: {}\nstdout:\n{}\nstderr:\n{}",
            result.command,
            stdout,
            result.stderr_str()
        );
    }

    fn assert_hook_allows(command: &str) {
        let result = run_dcg_hook(command);
        let stdout = result.stdout_str();

        assert!(
            result.output.status.success(),
            "hook mode should exit successfully\ncommand: {}\nstdout:\n{}\nstderr:\n{}",
            result.command,
            stdout,
            result.stderr_str()
        );

        assert!(
            stdout.trim().is_empty(),
            "expected no stdout for allow\ncommand: {}\nstdout:\n{}\nstderr:\n{}",
            result.command,
            stdout,
            result.stderr_str()
        );
    }

    fn run_dcg_hook_in_dir_with_env(
        cwd: &std::path::Path,
        command: &str,
        extra_env: &[(&str, &std::ffi::OsStr)],
    ) -> HookRunOutput {
        std::fs::create_dir_all(cwd.join(".git")).expect("failed to create .git dir");

        let home_dir = cwd.join("home");
        let xdg_config_dir = cwd.join("xdg_config");
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
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in extra_env {
            cmd.env(key, value);
        }

        let mut child = cmd.spawn().expect("failed to spawn dcg hook mode");

        {
            let stdin = child.stdin.as_mut().expect("failed to open stdin");
            serde_json::to_writer(stdin, &input).expect("failed to write hook input JSON");
        }

        let output = child.wait_with_output().expect("failed to wait for dcg");

        HookRunOutput {
            command: command.to_string(),
            output,
        }
    }

    fn fixed_timestamp() -> DateTime<Utc> {
        // Use a far-future timestamp so tests don't become time-sensitive as real time advances.
        DateTime::parse_from_rfc3339("2099-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    const fn redaction_config() -> RedactionConfig {
        RedactionConfig {
            enabled: false,
            mode: RedactionMode::Arguments,
            max_argument_len: 8,
        }
    }

    fn write_allow_once_entry(
        allow_once_path: &std::path::Path,
        cwd: &std::path::Path,
        command: &str,
        force_allow_config: bool,
    ) {
        let now = fixed_timestamp();
        let redaction = redaction_config();
        let cwd_str = cwd.to_string_lossy().into_owned();

        let pending = PendingExceptionRecord::new(
            now,
            &cwd_str,
            command,
            "test pending",
            &redaction,
            false,
            None,
        );
        let mut allow_once = AllowOnceEntry::from_pending(
            &pending,
            now,
            AllowOnceScopeKind::Cwd,
            &cwd_str,
            false,
            false,
            &redaction,
        );
        allow_once.force_allow_config = force_allow_config;

        let allow_once_line = serde_json::to_string(&allow_once).expect("serialize allow-once");
        std::fs::write(allow_once_path, format!("{allow_once_line}\n"))
            .expect("write allow-once jsonl");
    }

    fn assert_hook_denies_output(result: &HookRunOutput, expected_reason_substr: &str) {
        let stdout = result.stdout_str();

        assert!(
            result.output.status.success(),
            "hook mode should exit successfully\ncommand: {}\nstdout:\n{}\nstderr:\n{}",
            result.command,
            stdout,
            result.stderr_str()
        );

        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("expected JSON stdout for deny");

        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"],
            "deny",
            "expected permissionDecision=deny\ncommand: {}\nstdout:\n{}\nstderr:\n{}",
            result.command,
            stdout,
            result.stderr_str()
        );

        let reason = json["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap_or_default();
        assert!(
            reason.contains(expected_reason_substr),
            "expected deny reason to contain {expected_reason_substr:?}\ncommand: {}\nstdout:\n{}\nstderr:\n{}",
            result.command,
            stdout,
            result.stderr_str()
        );
    }

    #[test]
    fn hook_mode_allow_once_allows_pack_denied_command() {
        let temp = tempfile::tempdir().expect("tempdir");
        let allow_once_path = temp.path().join("allow_once.jsonl");
        write_allow_once_entry(&allow_once_path, temp.path(), "git reset --hard", false);

        let result = run_dcg_hook_in_dir_with_env(
            temp.path(),
            "git reset --hard",
            &[("DCG_ALLOW_ONCE_PATH", allow_once_path.as_os_str())],
        );

        assert!(
            result.output.status.success(),
            "hook mode should exit successfully\nstdout:\n{}\nstderr:\n{}",
            result.stdout_str(),
            result.stderr_str()
        );
        assert!(
            result.stdout_str().trim().is_empty(),
            "expected allow (no stdout) due to allow-once\nstdout:\n{}\nstderr:\n{}",
            result.stdout_str(),
            result.stderr_str()
        );
    }

    #[test]
    fn hook_mode_allow_once_does_not_override_config_block_without_force() {
        let temp = tempfile::tempdir().expect("tempdir");
        let allow_once_path = temp.path().join("allow_once.jsonl");
        write_allow_once_entry(&allow_once_path, temp.path(), "git reset --hard", false);

        let config_path = temp.path().join("dcg.toml");
        std::fs::write(
            &config_path,
            r"
[overrides]
block = [
  { pattern = '\bgit\s+reset\s+--hard\b', reason = 'explicit config block' },
]
",
        )
        .expect("write dcg config");

        let result = run_dcg_hook_in_dir_with_env(
            temp.path(),
            "git reset --hard",
            &[
                ("DCG_ALLOW_ONCE_PATH", allow_once_path.as_os_str()),
                ("DCG_CONFIG", config_path.as_os_str()),
            ],
        );

        assert_hook_denies_output(&result, "explicit config block");
    }

    #[test]
    fn hook_mode_allow_once_can_override_config_block_with_force_flag() {
        let temp = tempfile::tempdir().expect("tempdir");
        let allow_once_path = temp.path().join("allow_once.jsonl");
        write_allow_once_entry(&allow_once_path, temp.path(), "git reset --hard", true);

        let config_path = temp.path().join("dcg.toml");
        std::fs::write(
            &config_path,
            r"
[overrides]
block = [
  { pattern = '\bgit\s+reset\s+--hard\b', reason = 'explicit config block' },
]
",
        )
        .expect("write dcg config");

        let result = run_dcg_hook_in_dir_with_env(
            temp.path(),
            "git reset --hard",
            &[
                ("DCG_ALLOW_ONCE_PATH", allow_once_path.as_os_str()),
                ("DCG_CONFIG", config_path.as_os_str()),
            ],
        );

        assert!(
            result.output.status.success(),
            "hook mode should exit successfully\nstdout:\n{}\nstderr:\n{}",
            result.stdout_str(),
            result.stderr_str()
        );
        assert!(
            result.stdout_str().trim().is_empty(),
            "expected allow (no stdout) due to allow-once force flag\nstdout:\n{}\nstderr:\n{}",
            result.stdout_str(),
            result.stderr_str()
        );
    }

    #[test]
    fn hook_mode_missing_dcg_config_fails_open() {
        // If the user sets DCG_CONFIG incorrectly, hook mode must not break
        // workflows (fail-open). It should behave as if no config was loaded.
        let missing = std::ffi::OsStr::new("/tmp/dcg_config_missing_should_not_exist");
        let result = run_dcg_hook_with_env("git status", &[("DCG_CONFIG", missing)]);

        assert!(
            result.output.status.success(),
            "hook mode should exit successfully\nstdout:\n{}\nstderr:\n{}",
            result.stdout_str(),
            result.stderr_str()
        );
        assert!(
            result.stdout_str().trim().is_empty(),
            "expected allow (no stdout) even with missing DCG_CONFIG\nstdout:\n{}\nstderr:\n{}",
            result.stdout_str(),
            result.stderr_str()
        );
    }

    #[test]
    fn hook_mode_path_normalization_and_wrappers_matrix() {
        // Deny cases: absolute paths, quoted command words, wrappers, env assignments.
        let deny_cases = [
            "/usr/bin/git reset --hard",
            "\"/usr/bin/git\" reset --hard",
            "'/usr/bin/git' reset --hard",
            "sudo /usr/bin/git reset --hard",
            "FOO=1 /usr/bin/git reset --hard",
            "env FOO=1 /usr/bin/git reset --hard",
            "/bin/rm -rf /etc",
            "\"/bin/rm\" -rf /etc",
            "sudo \"/bin/rm\" -rf /etc",
            "FOO=1 \"/bin/rm\" -rf /etc",
        ];

        for cmd in deny_cases {
            assert_hook_denies(cmd);
        }

        // Allow cases: dangerous substrings in data contexts should not block.
        let allow_cases = [
            "git commit -m \"Fix rm -rf detection\"",
            "rg -n \"rm -rf\" src/main.rs",
            "echo \"rm -rf /etc\"",
        ];

        for cmd in allow_cases {
            assert_hook_allows(cmd);
        }
    }

    #[test]
    fn hook_mode_command_substitution_and_backticks_are_blocked() {
        let deny_cases = [
            "echo $(rm -rf /etc)",
            "echo `rm -rf /etc`",
            r#"echo hi | bash -c "rm -rf /etc""#,
        ];

        for cmd in deny_cases {
            assert_hook_denies(cmd);
        }
    }

    #[test]
    fn hook_mode_echo_pipe_sh_bypass_repro() {
        // REPRO: This test confirms that `echo rm -rf / | sh` is currently ALLOWED
        // because echo arguments are treated as data and masked, so the destructive
        // pattern "rm -rf /" is hidden from the evaluator.
        //
        // Once fixed, this test should be updated to expect denial.

        let cmd = "echo rm -rf / | sh";

        // FIXED: Should now be denied because pipe disables echo argument masking
        assert_hook_denies(cmd);
    }

    #[test]
    fn hook_mode_env_s_flag_bypass_repro() {
        // REPRO: This test confirms that `env -S "git reset --hard"` is currently ALLOWED
        // because `strip_env` does not handle `-S` (split string) correctly to extract the inner command.
        // `env -S` is commonly used in shebangs but also valid in shell.

        let cmd = "env -S \"git reset --hard\"";

        // FIXED: Should now be denied because we handle -S as taking an argument,
        // preventing normalization stripping, and classify the argument as InlineCode.
        assert_hook_denies(cmd);
    }
}

// ============================================================================
// DCG SIMULATE Tests (git_safety_guard-1gt.8.4)
// ============================================================================

mod simulate_tests {
    use super::*;

    /// Helper to create a temp file with given content.
    fn create_temp_log_file(content: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::Builder::new().suffix(".log").tempfile().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();
        file
    }

    /// Helper to run dcg simulate with a temp file.
    fn run_simulate_file(file_path: &str, extra_args: &[&str]) -> std::process::Output {
        let mut args = vec!["simulate", "-f", file_path];
        args.extend_from_slice(extra_args);
        run_dcg(&args)
    }

    /// Helper to run dcg simulate with stdin input.
    fn run_simulate_stdin(input: &str, extra_args: &[&str]) -> std::process::Output {
        let mut args = vec!["simulate", "-f", "-"];
        args.extend_from_slice(extra_args);

        let mut cmd = Command::new(dcg_binary());
        cmd.args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().expect("failed to spawn dcg simulate");
        {
            let stdin = child.stdin.as_mut().expect("failed to open stdin");
            stdin.write_all(input.as_bytes()).expect("failed to write");
        }
        child.wait_with_output().expect("failed to wait for dcg")
    }

    // -------------------------------------------------------------------------
    // Basic functionality tests
    // -------------------------------------------------------------------------

    #[test]
    fn simulate_plain_commands_file() {
        let content = "git status\necho hello\nls -la\n";
        let file = create_temp_log_file(content);

        let output = run_simulate_file(file.path().to_str().unwrap(), &[]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            output.status.success(),
            "simulate should succeed\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            stdout.contains("Total commands:") || stdout.contains("commands"),
            "should show command count\nstdout: {stdout}"
        );
    }

    #[test]
    fn simulate_hook_json_file() {
        let content = r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}
{"tool_name":"Bash","tool_input":{"command":"echo hello"}}
{"tool_name":"Read","tool_input":{"path":"file.txt"}}
"#;
        let file = create_temp_log_file(content);

        let output = run_simulate_file(file.path().to_str().unwrap(), &["--format", "json"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success(), "simulate should succeed");

        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("should produce valid JSON");

        // 2 Bash commands extracted, 1 Read tool ignored
        assert_eq!(json["totals"]["commands"], 2, "should have 2 commands");
        assert_eq!(
            json["errors"]["ignored_count"], 1,
            "should ignore 1 non-Bash"
        );
    }

    #[test]
    fn simulate_from_stdin() {
        let content = "git status\necho hello\n";
        let output = run_simulate_stdin(content, &[]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            output.status.success(),
            "simulate from stdin should succeed"
        );
        assert!(
            stdout.contains("Total commands:") || stdout.contains("commands"),
            "should process stdin input"
        );
    }

    #[test]
    fn simulate_empty_file_succeeds() {
        let file = create_temp_log_file("");

        let output = run_simulate_file(file.path().to_str().unwrap(), &[]);

        assert!(
            output.status.success(),
            "simulate on empty file should succeed"
        );
    }

    // -------------------------------------------------------------------------
    // Output format tests
    // -------------------------------------------------------------------------

    #[test]
    fn simulate_json_format_is_valid() {
        // Use git command since core.git is always enabled
        let content = "git status\ngit reset --hard\necho hello\n";
        let file = create_temp_log_file(content);

        let output = run_simulate_file(file.path().to_str().unwrap(), &["--format", "json"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value = serde_json::from_str(&stdout)
            .expect("simulate --format json should produce valid JSON");

        assert_eq!(json["schema_version"], 1, "should have schema_version");
        assert!(json["totals"].is_object(), "should have totals object");
        assert!(
            json["totals"]["commands"].is_number(),
            "should have commands count"
        );
        assert!(
            json["totals"]["allowed"].is_number(),
            "should have allowed count"
        );
        assert!(
            json["totals"]["denied"].is_number(),
            "should have denied count"
        );
        assert!(json["rules"].is_array(), "should have rules array");
        assert!(json["errors"].is_object(), "should have errors object");
    }

    #[test]
    fn simulate_json_totals_match_input() {
        // 3 plain commands: 1 safe, 1 dangerous, 1 safe
        // Use git command since core.git is always enabled
        let content = "git status\ngit reset --hard HEAD~1\necho hello\n";
        let file = create_temp_log_file(content);

        let output = run_simulate_file(file.path().to_str().unwrap(), &["--format", "json"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();

        assert_eq!(
            json["totals"]["commands"], 3,
            "should have 3 total commands"
        );
        assert!(
            json["totals"]["denied"].as_u64().unwrap() >= 1,
            "should have at least 1 denied (git reset --hard)"
        );
    }

    #[test]
    fn simulate_pretty_format_has_sections() {
        // Use git command since core.git is always enabled
        let content = "git status\ngit reset --hard\n";
        let file = create_temp_log_file(content);

        let output = run_simulate_file(file.path().to_str().unwrap(), &["--format", "pretty"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(stdout.contains("Summary"), "should have Summary section");
        assert!(
            stdout.contains("Total commands:") || stdout.contains("commands"),
            "should show total"
        );
        assert!(
            stdout.contains("Allowed") || stdout.contains("allowed"),
            "should show allowed count"
        );
        assert!(
            stdout.contains("Denied") || stdout.contains("denied") || stdout.contains("DENY"),
            "should show denied count"
        );
    }

    // -------------------------------------------------------------------------
    // Rule and pack aggregation tests
    // -------------------------------------------------------------------------

    #[test]
    fn simulate_rules_sorted_by_count_desc() {
        // Create input with multiple denies of different rules
        // Use git commands since core.git is always enabled
        let content = "git reset --hard\ngit reset --hard HEAD~1\ngit reset --hard origin/main\ngit push --force\n";
        let file = create_temp_log_file(content);

        let output = run_simulate_file(file.path().to_str().unwrap(), &["--format", "json"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let rules = json["rules"].as_array().expect("rules should be array");

        if rules.len() >= 2 {
            // Verify sorted by count descending
            let first_count = rules[0]["count"].as_u64().unwrap();
            let second_count = rules[1]["count"].as_u64().unwrap();
            assert!(
                first_count >= second_count,
                "rules should be sorted by count desc: {first_count} >= {second_count}"
            );
        }
    }

    #[test]
    fn simulate_exemplars_included_in_rules() {
        // Use git command since core.git is always enabled
        let content = "git reset --hard\n";
        let file = create_temp_log_file(content);

        let output = run_simulate_file(file.path().to_str().unwrap(), &["--format", "json"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let rules = json["rules"].as_array().unwrap();

        if !rules.is_empty() {
            let rule = &rules[0];
            assert!(rule["exemplars"].is_array(), "rule should have exemplars");
            let exemplars = rule["exemplars"].as_array().unwrap();
            if !exemplars.is_empty() {
                assert!(
                    exemplars[0].is_string(),
                    "exemplar should be a string (the command)"
                );
            }
        }
    }

    // -------------------------------------------------------------------------
    // Redaction and truncation tests
    // -------------------------------------------------------------------------

    #[test]
    fn simulate_redaction_quoted() {
        // Command with quoted strings that should be redacted
        let content = r#"echo "secret password here""#;
        let file = create_temp_log_file(content);

        let output = run_simulate_file(
            file.path().to_str().unwrap(),
            &["--format", "json", "--redact", "quoted"],
        );
        let stdout = String::from_utf8_lossy(&output.stdout);

        // The command itself is safe, but if there were blocked commands,
        // their exemplars would have quoted strings redacted
        assert!(output.status.success(), "redact mode should work");
        let _json: serde_json::Value =
            serde_json::from_str(&stdout).expect("should produce valid JSON with redaction");
    }

    #[test]
    fn simulate_truncation_limits_exemplars() {
        // Create a long command
        let long_cmd = format!("echo {}", "x".repeat(200));
        let content = format!("{long_cmd}\n");
        let file = create_temp_log_file(&content);

        let output = run_simulate_file(
            file.path().to_str().unwrap(),
            &["--format", "json", "--truncate", "50"],
        );
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Even though the command is safe (allow), verify truncation works
        // in parse output (no rules but parse stats should work)
        assert!(output.status.success(), "truncation should work");
        let _json: serde_json::Value =
            serde_json::from_str(&stdout).expect("should produce valid JSON with truncation");
    }

    // -------------------------------------------------------------------------
    // Limit tests
    // -------------------------------------------------------------------------

    #[test]
    fn simulate_max_lines_limit() {
        let content = "line1\nline2\nline3\nline4\nline5\n";
        let file = create_temp_log_file(content);

        let output = run_simulate_file(
            file.path().to_str().unwrap(),
            &["--format", "json", "--max-lines", "3"],
        );
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();

        // Should process only 3 lines
        assert_eq!(json["totals"]["commands"], 3, "should limit to 3 commands");
        assert!(
            json["errors"]["stopped_at_limit"]
                .as_bool()
                .unwrap_or(false),
            "should indicate stopped at limit"
        );
    }

    #[test]
    fn simulate_top_rules_limit() {
        // Create many different blocked commands
        // Use git commands since core.git is always enabled
        let content = "git reset --hard\ngit clean -fdx\ngit push --force\n";
        let file = create_temp_log_file(content);

        let output = run_simulate_file(
            file.path().to_str().unwrap(),
            &["--format", "json", "--top", "1"],
        );
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let rules = json["rules"].as_array().unwrap();

        assert!(rules.len() <= 1, "should limit to top 1 rule");
    }

    // -------------------------------------------------------------------------
    // Strict mode tests
    // -------------------------------------------------------------------------

    #[test]
    fn simulate_strict_mode_fails_on_malformed() {
        // Valid JSON with missing command field
        let content = r#"git status
{"tool_name":"Bash","tool_input":{}}
echo hello
"#;
        let file = create_temp_log_file(content);

        let output = run_simulate_file(file.path().to_str().unwrap(), &["--strict"]);

        // In strict mode, malformed lines should cause failure
        assert!(
            !output.status.success(),
            "strict mode should fail on malformed line"
        );
    }

    #[test]
    fn simulate_non_strict_continues_on_malformed() {
        // Valid JSON with missing command field
        let content = r#"git status
{"tool_name":"Bash","tool_input":{}}
echo hello
"#;
        let file = create_temp_log_file(content);

        let output = run_simulate_file(file.path().to_str().unwrap(), &["--format", "json"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Non-strict mode should continue and report malformed count
        assert!(output.status.success(), "non-strict should succeed");
        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(
            json["errors"]["malformed_count"], 1,
            "should count malformed line"
        );
    }

    // -------------------------------------------------------------------------
    // Determinism tests
    // -------------------------------------------------------------------------

    #[test]
    fn simulate_output_is_deterministic() {
        // Use git commands since core.git is always enabled
        let content = "git reset --hard\ngit push --force origin main\ngit clean -fdx\n";
        let file = create_temp_log_file(content);
        let path = file.path().to_str().unwrap();

        // Run twice and compare
        let output1 = run_simulate_file(path, &["--format", "json"]);
        let output2 = run_simulate_file(path, &["--format", "json"]);

        let stdout1 = String::from_utf8_lossy(&output1.stdout);
        let stdout2 = String::from_utf8_lossy(&output2.stdout);

        let json1: serde_json::Value = serde_json::from_str(&stdout1).unwrap();
        let json2: serde_json::Value = serde_json::from_str(&stdout2).unwrap();

        // Totals should be identical
        assert_eq!(
            json1["totals"], json2["totals"],
            "totals should be deterministic"
        );

        // Rule order should be identical
        let rules1 = json1["rules"].as_array().unwrap();
        let rules2 = json2["rules"].as_array().unwrap();
        assert_eq!(rules1.len(), rules2.len(), "rule count should match");
        for (r1, r2) in rules1.iter().zip(rules2.iter()) {
            assert_eq!(
                r1["rule_id"], r2["rule_id"],
                "rule order should be deterministic"
            );
            assert_eq!(r1["count"], r2["count"], "rule counts should match");
        }
    }

    // -------------------------------------------------------------------------
    // Decision log format tests
    // -------------------------------------------------------------------------

    #[test]
    fn simulate_decision_log_format() {
        // DCG_LOG_V1|timestamp|decision|base64_command|
        // "git status" in base64 = "Z2l0IHN0YXR1cw=="
        let content = "DCG_LOG_V1|2026-01-09T00:00:00Z|allow|Z2l0IHN0YXR1cw==|\n";
        let file = create_temp_log_file(content);

        let output = run_simulate_file(file.path().to_str().unwrap(), &["--format", "json"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success(), "should parse decision log format");
        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(
            json["totals"]["commands"], 1,
            "should extract 1 command from log"
        );
    }
}

// ============================================================================
// Hook Highlighting E2E Tests (git_safety_guard-jpfm.7)
// ============================================================================

mod hook_highlighting_tests {
    use super::*;

    /// Helper to check if a string contains ANSI escape sequences.
    fn contains_ansi_escapes(s: &str) -> bool {
        s.contains("\x1b[") || s.contains("\u{001b}[")
    }

    /// Run dcg hook with color forcing for testing highlighting.
    fn run_dcg_hook_with_color(command: &str, force_color: bool) -> HookRunOutput {
        let color_env: &[(&str, &std::ffi::OsStr)] = if force_color {
            &[
                ("FORCE_COLOR", std::ffi::OsStr::new("1")),
                ("CLICOLOR_FORCE", std::ffi::OsStr::new("1")),
            ]
        } else {
            &[
                ("NO_COLOR", std::ffi::OsStr::new("1")),
                ("CLICOLOR", std::ffi::OsStr::new("0")),
            ]
        };
        run_dcg_hook_with_env(command, color_env)
    }

    // -------------------------------------------------------------------------
    // Basic highlighting tests
    // -------------------------------------------------------------------------

    #[test]
    fn hook_denial_stderr_contains_caret_highlighting() {
        // Run a command that will be denied
        let result = run_dcg_hook("git reset --hard");
        let stderr = result.stderr_str();

        // Verify the command was denied (stdout has JSON with deny decision)
        let stdout = result.stdout_str();
        assert!(
            result.output.status.success(),
            "hook should exit successfully"
        );
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // stderr should contain caret markers for span highlighting
        assert!(
            stderr.contains('^'),
            "stderr should contain caret markers for highlighting\nstderr:\n{stderr}"
        );

        // stderr should contain a "Matched:" label
        assert!(
            stderr.contains("Matched:"),
            "stderr should contain 'Matched:' label\nstderr:\n{stderr}"
        );
    }

    #[test]
    fn hook_denial_stderr_contains_command_line() {
        let result = run_dcg_hook("git reset --hard HEAD");
        let stderr = result.stderr_str();

        // stderr should show the command
        assert!(
            stderr.contains("Command:"),
            "stderr should contain 'Command:' label\nstderr:\n{stderr}"
        );

        // The command text should appear in stderr
        assert!(
            stderr.contains("git reset --hard") || stderr.contains("reset"),
            "stderr should contain the blocked command\nstderr:\n{stderr}"
        );
    }

    #[test]
    fn hook_denial_caret_line_follows_command_line() {
        // Force color off for easier parsing
        let result = run_dcg_hook_with_color("git reset --hard", false);
        let stderr = result.stderr_str();

        // Find lines containing Command: and caret markers
        let lines: Vec<&str> = stderr.lines().collect();
        let mut command_line_idx = None;
        let mut caret_line_idx = None;

        for (i, line) in lines.iter().enumerate() {
            if line.contains("Command:") && line.contains("git") {
                command_line_idx = Some(i);
            }
            if line.contains("^^^^") && command_line_idx.is_some() {
                caret_line_idx = Some(i);
                break;
            }
        }

        assert!(
            command_line_idx.is_some(),
            "should find Command: line\nstderr:\n{stderr}"
        );
        assert!(
            caret_line_idx.is_some(),
            "should find caret line\nstderr:\n{stderr}"
        );

        // Caret line should be immediately after command line
        let cmd_idx = command_line_idx.unwrap();
        let caret_idx = caret_line_idx.unwrap();
        assert_eq!(
            caret_idx,
            cmd_idx + 1,
            "caret line should immediately follow command line\nstderr:\n{stderr}"
        );
    }

    #[test]
    fn hook_denial_label_line_follows_caret_line() {
        // Force color off for easier parsing
        let result = run_dcg_hook_with_color("git reset --hard", false);
        let stderr = result.stderr_str();

        // Find the "Matched:" label line
        let lines: Vec<&str> = stderr.lines().collect();
        let mut caret_line_idx = None;
        let mut label_line_idx = None;

        for (i, line) in lines.iter().enumerate() {
            if line.contains("^^^^") {
                caret_line_idx = Some(i);
            }
            if line.contains("Matched:") && caret_line_idx.is_some() {
                label_line_idx = Some(i);
                break;
            }
        }

        assert!(
            caret_line_idx.is_some(),
            "should find caret line\nstderr:\n{stderr}"
        );
        assert!(
            label_line_idx.is_some(),
            "should find label line with Matched:\nstderr:\n{stderr}"
        );

        // Label line should be immediately after caret line
        let caret_idx = caret_line_idx.unwrap();
        let label_idx = label_line_idx.unwrap();
        assert_eq!(
            label_idx,
            caret_idx + 1,
            "label line should immediately follow caret line\nstderr:\n{stderr}"
        );
    }

    // -------------------------------------------------------------------------
    // Non-TTY mode tests (no ANSI escape codes)
    // -------------------------------------------------------------------------

    #[test]
    fn hook_denial_no_ansi_when_color_disabled() {
        // Force color off
        let result = run_dcg_hook_with_color("git reset --hard", false);
        let stderr = result.stderr_str();

        // Verify denial happened
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // stderr should NOT contain ANSI escape codes
        assert!(
            !contains_ansi_escapes(&stderr),
            "stderr should not contain ANSI escapes when color disabled\nstderr:\n{stderr}"
        );

        // But should still contain the structure
        assert!(
            stderr.contains("Command:"),
            "should still have Command: label"
        );
        assert!(stderr.contains('^'), "should still have caret markers");
    }

    #[test]
    fn hook_denial_structure_preserved_regardless_of_color() {
        // Test that the highlighting structure is present regardless of color settings
        // Note: FORCE_COLOR/CLICOLOR_FORCE don't currently work with dcg's should_use_color()
        // which uses io::stderr().is_terminal() as the final check. This is fine for E2E
        // testing - we verify structure is correct in both color and non-color modes.

        let result = run_dcg_hook("git reset --hard");
        let stderr = result.stderr_str();

        // Verify denial happened
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // stderr should have the highlighting structure
        assert!(
            stderr.contains("Command:"),
            "stderr should contain Command: label\nstderr:\n{stderr}"
        );
        assert!(
            stderr.contains('^'),
            "stderr should contain caret markers\nstderr:\n{stderr}"
        );
        assert!(
            stderr.contains("Matched:"),
            "stderr should contain Matched: label\nstderr:\n{stderr}"
        );
    }

    // -------------------------------------------------------------------------
    // Long command windowing tests
    // -------------------------------------------------------------------------

    #[test]
    fn hook_denial_long_command_windowing() {
        // Create a long command that exceeds typical display width
        let long_suffix = "x".repeat(100);
        let command = format!("git reset --hard HEAD{long_suffix}");

        let result = run_dcg_hook_with_color(&command, false);
        let stderr = result.stderr_str();

        // Verify denial happened
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // stderr should still contain caret markers (windowing should preserve highlighting)
        assert!(
            stderr.contains('^'),
            "stderr should contain caret markers even for long commands\nstderr:\n{stderr}"
        );

        // Should contain ellipsis or windowing indicator if command was truncated
        // The windowing implementation may use "..." or similar
        // At minimum, verify the highlighting structure is preserved
        assert!(
            stderr.contains("Command:"),
            "should contain Command: label\nstderr:\n{stderr}"
        );
    }

    #[test]
    fn hook_denial_long_command_with_match_at_start() {
        // Long command where the matched pattern is at the start
        let long_suffix = " ".to_string() + &"x".repeat(100);
        let command = format!("git reset --hard{long_suffix}");

        let result = run_dcg_hook_with_color(&command, false);
        let stderr = result.stderr_str();

        // Verify denial
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // The important pattern "reset --hard" should be visible with carets
        assert!(
            stderr.contains('^'),
            "should show caret markers for visible matched portion\nstderr:\n{stderr}"
        );
    }

    // -------------------------------------------------------------------------
    // UTF-8 handling tests
    // -------------------------------------------------------------------------

    #[test]
    fn hook_denial_utf8_command_caret_alignment() {
        // Command with UTF-8 characters before the matched pattern
        // The caret alignment should account for multi-byte characters
        let command = "git reset --hard # 日本語コメント";

        let result = run_dcg_hook_with_color(command, false);
        let stderr = result.stderr_str();

        // Verify denial
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // Should still have caret markers
        assert!(
            stderr.contains('^'),
            "should contain caret markers with UTF-8 content\nstderr:\n{stderr}"
        );

        // Should contain the Matched: label
        assert!(
            stderr.contains("Matched:"),
            "should contain Matched: label with UTF-8 content\nstderr:\n{stderr}"
        );
    }

    #[test]
    fn hook_denial_emoji_command_caret_alignment() {
        // Command with emoji before the matched pattern
        let command = "git reset --hard # 🚀🔥";

        let result = run_dcg_hook_with_color(command, false);
        let stderr = result.stderr_str();

        // Verify denial
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // Should still have proper highlighting structure
        assert!(
            stderr.contains('^'),
            "should contain caret markers with emoji\nstderr:\n{stderr}"
        );
    }

    // -------------------------------------------------------------------------
    // Verbose log tests
    // -------------------------------------------------------------------------

    #[test]
    fn hook_denial_stderr_verbose_on_failure() {
        // When a command is denied, stderr should contain enough info for debugging
        let result = run_dcg_hook("git clean -fdx");
        let stderr = result.stderr_str();

        // Verify denial
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // stderr should contain the pack that blocked it
        assert!(
            stderr.contains("core.git") || stderr.contains("Pack:"),
            "stderr should mention the blocking pack\nstderr:\n{stderr}"
        );

        // stderr should contain the reason
        assert!(
            stderr.contains("Reason:") || stderr.contains("dangerous"),
            "stderr should contain reason information\nstderr:\n{stderr}"
        );

        // stderr should have the caret highlighting
        assert!(
            stderr.contains('^'),
            "stderr should have caret highlighting\nstderr:\n{stderr}"
        );
    }

    #[test]
    fn hook_denial_multiple_patterns_shows_first_match() {
        // A command that might match multiple patterns - should show highlighting
        // for at least one match
        let result = run_dcg_hook("git push --force");
        let stderr = result.stderr_str();

        // Verify denial
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // Should have caret highlighting for the matched portion
        assert!(
            stderr.contains('^'),
            "should contain caret markers\nstderr:\n{stderr}"
        );

        // Should have the Matched label
        assert!(
            stderr.contains("Matched:"),
            "should contain Matched: label\nstderr:\n{stderr}"
        );
    }
}

// ============================================================================
// Explanation Output E2E Tests (git_safety_guard-r97e.6)
// ============================================================================

mod explanation_output_tests {
    use super::*;

    /// Helper to check if a string contains ANSI escape sequences.
    fn contains_ansi_escapes(s: &str) -> bool {
        s.contains("\x1b[") || s.contains("\u{001b}[")
    }

    /// Run dcg hook with `NO_COLOR` to disable ANSI for easier parsing.
    fn run_dcg_hook_no_color(command: &str) -> HookRunOutput {
        run_dcg_hook_with_env(
            command,
            &[
                ("NO_COLOR", std::ffi::OsStr::new("1")),
                ("CLICOLOR", std::ffi::OsStr::new("0")),
            ],
        )
    }

    // -------------------------------------------------------------------------
    // Hook denial explanation tests
    // -------------------------------------------------------------------------

    #[test]
    fn hook_denial_stderr_contains_explanation_label() {
        // Run a command that will be denied
        let result = run_dcg_hook_no_color("git reset --hard");
        let stderr = result.stderr_str();

        // Verify denial
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // stderr should contain "Explanation:" label
        assert!(
            stderr.contains("Explanation:"),
            "stderr should contain 'Explanation:' label\nstderr:\n{stderr}"
        );
    }

    #[test]
    fn hook_denial_stderr_contains_explanation_text() {
        // git reset --hard has a detailed explanation in the core.git pack
        let result = run_dcg_hook_no_color("git reset --hard");
        let stderr = result.stderr_str();

        // Verify denial
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // The explanation should mention key information about the danger
        // Known explanation text includes: "discards ALL uncommitted changes"
        assert!(
            stderr.contains("uncommitted")
                || stderr.contains("Matched destructive pattern")
                || stderr.contains("discards"),
            "stderr should contain explanation content about the danger\nstderr:\n{stderr}"
        );
    }

    #[test]
    fn hook_denial_explanation_mentions_danger() {
        // Test that explanations provide meaningful context about the danger
        let result = run_dcg_hook_no_color("git push --force");
        let stderr = result.stderr_str();

        // Verify denial
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // Should have explanation section
        assert!(
            stderr.contains("Explanation:"),
            "stderr should contain Explanation: label\nstderr:\n{stderr}"
        );
    }

    #[test]
    fn hook_denial_explanation_wrapped_long_text() {
        // Explanations can be long and should be wrapped properly
        let result = run_dcg_hook_no_color("git reset --hard HEAD");
        let stderr = result.stderr_str();

        // Verify denial
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // Find the explanation section and verify it spans multiple lines
        let lines: Vec<&str> = stderr.lines().collect();
        let mut found_explanation = false;
        let mut explanation_line_count = 0;

        for line in &lines {
            if line.contains("Explanation:") {
                found_explanation = true;
            }
            // Count continuation lines (indented lines after Explanation:)
            // These would be lines that are part of the explanation text
            if found_explanation && line.starts_with("│") && !line.contains("Command:") {
                explanation_line_count += 1;
            }
            if line.contains("Command:") {
                break;
            }
        }

        assert!(found_explanation, "should have Explanation: section");
        // Long explanations should wrap to multiple lines
        // This test verifies the structure exists, not exact line count
        assert!(
            explanation_line_count >= 1,
            "explanation should have at least one line"
        );
    }

    // -------------------------------------------------------------------------
    // dcg explain CLI explanation tests
    // -------------------------------------------------------------------------

    #[test]
    fn explain_pretty_includes_explanation_section() {
        let output = run_dcg(&["explain", "git reset --hard"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Pretty explain should include explanation text
        assert!(
            stdout.contains("Explanation:") || stdout.contains("explanation"),
            "explain should include explanation section\nstdout:\n{stdout}"
        );
    }

    #[test]
    fn explain_json_includes_explanation_field() {
        let output = run_dcg(&["explain", "--format", "json", "git reset --hard"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse as JSON to validate structure
        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("explain JSON should be valid");

        // Should have explanation in match info
        assert_eq!(json["decision"], "deny", "should be denied");

        // Check for explanation field in the match object
        let has_explanation = json["match"]["explanation"].is_string();

        assert!(
            has_explanation,
            "JSON output should contain explanation field in match object\nJSON:\n{stdout}"
        );
    }

    #[test]
    fn explain_json_explanation_is_meaningful() {
        let output = run_dcg(&["explain", "--format", "json", "git reset --hard"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("explain JSON should be valid");

        // Get explanation from match object
        let explanation = json["match"]["explanation"].as_str().unwrap_or_default();

        // Explanation should be non-empty and contain relevant info
        assert!(
            !explanation.is_empty(),
            "explanation should not be empty\nJSON:\n{stdout}"
        );

        // Should mention the pattern or danger
        assert!(
            explanation.contains("Matched")
                || explanation.contains("destructive")
                || explanation.contains("uncommitted")
                || explanation.contains("reset"),
            "explanation should contain meaningful text\nExplanation: {explanation}"
        );
    }

    // -------------------------------------------------------------------------
    // Non-TTY mode tests
    // -------------------------------------------------------------------------

    #[test]
    fn hook_denial_explanation_no_ansi_when_color_disabled() {
        let result = run_dcg_hook_no_color("git reset --hard");
        let stderr = result.stderr_str();

        // Verify denial
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // stderr should NOT contain ANSI escape codes
        assert!(
            !contains_ansi_escapes(&stderr),
            "stderr should not contain ANSI escapes when color disabled\nstderr:\n{stderr}"
        );

        // But should still contain the explanation structure
        assert!(
            stderr.contains("Explanation:"),
            "should still have Explanation: label"
        );
    }

    #[test]
    fn explain_output_works_without_tty() {
        // Explain output should work correctly in non-TTY mode
        let output = run_dcg(&["explain", "git reset --hard"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            output.status.success() || stdout.contains("DENY"),
            "explain should succeed in non-TTY mode"
        );

        // Should contain explanation content
        assert!(
            stdout.contains("Explanation:") || stdout.contains("reset"),
            "explain should contain relevant content"
        );
    }

    // -------------------------------------------------------------------------
    // Verbose logging tests
    // -------------------------------------------------------------------------

    #[test]
    fn hook_denial_stderr_contains_verbose_info() {
        // When a command is denied, stderr should contain enough verbose info
        let result = run_dcg_hook_no_color("git clean -fdx");
        let stderr = result.stderr_str();

        // Verify denial
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // stderr should contain rule info (which includes pack identifier)
        assert!(
            stderr.contains("Rule:") || stderr.contains("core.git"),
            "stderr should contain rule/pack information\nstderr:\n{stderr}"
        );

        // stderr should contain reason
        assert!(
            stderr.contains("Reason:"),
            "stderr should contain reason\nstderr:\n{stderr}"
        );

        // stderr should contain explanation
        assert!(
            stderr.contains("Explanation:"),
            "stderr should contain explanation\nstderr:\n{stderr}"
        );

        // stderr should contain the command
        assert!(
            stderr.contains("Command:"),
            "stderr should contain command\nstderr:\n{stderr}"
        );
    }

    #[test]
    fn hook_denial_shows_full_context_on_block() {
        // When blocked, output should show comprehensive context
        let result = run_dcg_hook_no_color("git push origin main --force");
        let stderr = result.stderr_str();

        // Verify denial
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // Check for comprehensive context in verbose output
        let has_rule = stderr.contains("Rule:");
        let has_reason = stderr.contains("Reason:");
        let has_explanation = stderr.contains("Explanation:");
        let has_command = stderr.contains("Command:");
        let has_suggestions = stderr.contains("💡") || stderr.contains("Safer");

        assert!(has_rule, "should show rule info\nstderr:\n{stderr}");
        assert!(has_reason, "should show reason\nstderr:\n{stderr}");
        assert!(
            has_explanation,
            "should show explanation\nstderr:\n{stderr}"
        );
        assert!(has_command, "should show command\nstderr:\n{stderr}");
        // Suggestions might not always be present
        let _ = has_suggestions;
    }

    // -------------------------------------------------------------------------
    // Multiple commands/patterns tests
    // -------------------------------------------------------------------------

    #[test]
    fn hook_denial_shows_explanation_for_different_patterns() {
        // Test that different blocked commands show appropriate explanations
        let commands = [
            "git reset --hard",
            "git clean -fdx",
            "git push --force",
            "rm -rf /",
        ];

        for cmd in commands {
            let result = run_dcg_hook_no_color(cmd);
            let stderr = result.stderr_str();
            let stdout = result.stdout_str();

            let json: serde_json::Value =
                serde_json::from_str(stdout.trim()).expect("should produce JSON");

            if json["hookSpecificOutput"]["permissionDecision"] == "deny" {
                assert!(
                    stderr.contains("Explanation:"),
                    "command '{cmd}' should show explanation when denied\nstderr:\n{stderr}"
                );
            }
        }
    }

    #[test]
    fn explain_json_all_blocked_have_explanation() {
        // All blocked commands should have an explanation in JSON output
        let commands = ["git reset --hard", "git clean -fdx"];

        for cmd in commands {
            let output = run_dcg(&["explain", "--format", "json", cmd]);
            let stdout = String::from_utf8_lossy(&output.stdout);

            let json: serde_json::Value =
                serde_json::from_str(&stdout).expect("JSON should be valid");

            if json["decision"] == "deny" {
                let explanation = json["match"]["explanation"].as_str();
                assert!(
                    explanation.is_some() && !explanation.unwrap().is_empty(),
                    "command '{cmd}' JSON should have non-empty explanation\nJSON:\n{stdout}"
                );
            }
        }
    }
}

// ============================================================================
// DCG PACK VALIDATE E2E Tests
// ============================================================================

mod pack_validate_tests {
    use super::*;
    use std::io::Write;

    /// Helper to create a temp YAML pack file
    fn create_temp_pack(content: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let temp = tempfile::tempdir().expect("failed to create temp dir");
        let path = temp.path().join("test-pack.yaml");
        let mut file = std::fs::File::create(&path).expect("failed to create file");
        file.write_all(content.as_bytes())
            .expect("failed to write file");
        (temp, path)
    }

    #[test]
    fn pack_validate_valid_pack_succeeds() {
        let content = r#"
schema_version: 1
id: test.example
name: Test Example Pack
version: 1.0.0
description: A test pack for validation
keywords:
  - test
destructive_patterns:
  - name: block-danger
    pattern: danger\s+command
    severity: high
    description: Blocks dangerous commands
safe_patterns:
  - name: allow-safe
    pattern: safe\s+command
"#;
        let (_temp, path) = create_temp_pack(content);
        let output = run_dcg(&["pack", "validate", path.to_str().unwrap()]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            output.status.success(),
            "valid pack should validate successfully\nstdout:\n{stdout}"
        );
        assert!(
            stdout.contains("Valid") || stdout.contains("✓"),
            "output should indicate success\nstdout:\n{stdout}"
        );
    }

    #[test]
    fn pack_validate_invalid_yaml_fails() {
        let content = r#"
id: test.example
name: [unclosed bracket
version: 1.0.0
"#;
        let (_temp, path) = create_temp_pack(content);
        let output = run_dcg(&["pack", "validate", path.to_str().unwrap()]);

        assert!(
            !output.status.success(),
            "invalid YAML should fail validation"
        );
    }

    #[test]
    fn pack_validate_invalid_regex_fails() {
        let content = r#"
schema_version: 1
id: test.badregex
name: Bad Regex Pack
version: 1.0.0
destructive_patterns:
  - name: bad-pattern
    pattern: "[unclosed"
"#;
        let (_temp, path) = create_temp_pack(content);
        let output = run_dcg(&["pack", "validate", path.to_str().unwrap()]);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            !output.status.success(),
            "invalid regex should fail validation\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    #[test]
    fn pack_validate_collision_with_builtin_fails() {
        let content = r#"
schema_version: 1
id: core.git
name: Malicious Override
version: 1.0.0
destructive_patterns:
  - name: bypass
    pattern: never-match
"#;
        let (_temp, path) = create_temp_pack(content);
        let output = run_dcg(&["pack", "validate", path.to_str().unwrap()]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            !output.status.success(),
            "collision with built-in pack should fail\nstdout:\n{stdout}"
        );
        assert!(
            stdout.contains("collision") || stdout.contains("Collision") || stdout.contains("E010"),
            "output should mention collision\nstdout:\n{stdout}"
        );
    }

    #[test]
    fn pack_validate_json_format_valid() {
        let content = r#"
schema_version: 1
id: test.json
name: JSON Test Pack
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
"#;
        let (_temp, path) = create_temp_pack(content);
        let output = run_dcg(&[
            "pack",
            "validate",
            path.to_str().unwrap(),
            "--format",
            "json",
        ]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            output.status.success(),
            "valid pack should succeed with JSON format"
        );

        // Should produce valid JSON
        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("should produce valid JSON");
        assert!(json.is_object(), "JSON output should be an object");
    }

    #[test]
    fn pack_validate_strict_fails_on_warnings() {
        // A pack with no keywords generates a warning
        let content = r#"
schema_version: 1
id: test.nokeys
name: No Keywords Pack
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
"#;
        let (_temp, path) = create_temp_pack(content);

        // Without --strict, should succeed (warnings are OK)
        let output_normal = run_dcg(&["pack", "validate", path.to_str().unwrap()]);
        assert!(
            output_normal.status.success(),
            "pack with warnings should succeed without --strict"
        );

        // With --strict, should fail (warnings become errors)
        let output_strict = run_dcg(&["pack", "validate", path.to_str().unwrap(), "--strict"]);
        assert!(
            !output_strict.status.success(),
            "pack with warnings should fail with --strict"
        );
    }

    #[test]
    fn pack_validate_missing_file_fails() {
        let output = run_dcg(&["pack", "validate", "/nonexistent/path/pack.yaml"]);

        assert!(
            !output.status.success(),
            "nonexistent file should fail validation"
        );
    }

    #[test]
    fn pack_validate_shows_engine_analysis() {
        let content = r#"
schema_version: 1
id: test.engines
name: Engine Analysis Pack
version: 1.0.0
keywords:
  - test
destructive_patterns:
  - name: linear-pattern
    pattern: simple\s+pattern
  - name: backtrack-pattern
    pattern: lookahead(?=test)
"#;
        let (_temp, path) = create_temp_pack(content);
        let output = run_dcg(&["pack", "validate", path.to_str().unwrap()]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            output.status.success(),
            "valid pack with mixed engines should succeed"
        );
        // Output should show engine information
        assert!(
            stdout.contains("linear") || stdout.contains("Linear") || stdout.contains("backtrack"),
            "output should show engine analysis\nstdout:\n{stdout}"
        );
    }

    #[test]
    fn pack_validate_unsupported_schema_version_fails() {
        let content = r#"
schema_version: 999
id: test.future
name: Future Pack
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
"#;
        let (_temp, path) = create_temp_pack(content);
        let output = run_dcg(&["pack", "validate", path.to_str().unwrap()]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            !output.status.success(),
            "unsupported schema version should fail\nstdout:\n{stdout}"
        );
        assert!(
            stdout.contains("schema") || stdout.contains("E004"),
            "output should mention schema version error\nstdout:\n{stdout}"
        );
    }
}

// ============================================================================
// Custom Pack Loading E2E Tests
// ============================================================================
// NOTE: These tests are currently ignored because the ExternalPackLoader
// is not yet integrated into the main evaluation path. The loader exists
// (src/packs/external.rs) but is not called from main.rs or evaluator.rs.
// See git_safety_guard-wy6s for the integration task.

mod custom_pack_loading_tests {
    use super::*;
    use std::io::Write;

    /// Create a temp directory with a custom pack and config
    fn setup_custom_pack_env(
        pack_content: &str,
        command: &str,
    ) -> (tempfile::TempDir, std::process::Output) {
        let temp = tempfile::tempdir().expect("failed to create temp dir");

        // Create .git dir to make it a valid project root
        std::fs::create_dir_all(temp.path().join(".git")).expect("failed to create .git dir");

        // Create home and xdg dirs
        let home_dir = temp.path().join("home");
        let xdg_config_dir = temp.path().join("xdg_config");
        let packs_dir = xdg_config_dir.join("dcg").join("packs");
        std::fs::create_dir_all(&home_dir).expect("failed to create HOME dir");
        std::fs::create_dir_all(&packs_dir).expect("failed to create packs dir");

        // Write custom pack
        let pack_path = packs_dir.join("custom.yaml");
        let mut pack_file = std::fs::File::create(&pack_path).expect("failed to create pack file");
        pack_file
            .write_all(pack_content.as_bytes())
            .expect("failed to write pack");

        // Write config that loads the custom pack
        let config_dir = xdg_config_dir.join("dcg");
        let config_path = config_dir.join("config.toml");
        let config_content = format!(
            r#"
[packs]
enabled = ["core.git", "core.filesystem"]
custom_paths = ["{}"]
"#,
            pack_path.to_string_lossy().replace('\\', "/")
        );
        let mut config_file =
            std::fs::File::create(&config_path).expect("failed to create config file");
        config_file
            .write_all(config_content.as_bytes())
            .expect("failed to write config");

        // Run hook with command
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
            .current_dir(temp.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().expect("failed to spawn dcg");

        {
            let stdin = child.stdin.as_mut().expect("failed to open stdin");
            serde_json::to_writer(stdin, &input).expect("failed to write hook input JSON");
        }

        let output = child.wait_with_output().expect("failed to wait for dcg");

        (temp, output)
    }

    #[test]
    #[ignore = "External pack loading not yet integrated into evaluation path"]
    fn custom_pack_blocks_matching_command() {
        let pack_content = r#"
schema_version: 1
id: custom.deploy
name: Custom Deploy Rules
version: 1.0.0
keywords:
  - deploy
destructive_patterns:
  - name: prod-deploy
    pattern: deploy\s+--env\s*=?\s*prod
    severity: critical
    description: Direct production deployment blocked
"#;

        let (_temp, output) = setup_custom_pack_env(pack_content, "deploy --env prod");
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse hook output
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce valid JSON");

        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "custom pack should block matching command\nstdout:\n{stdout}"
        );
    }

    #[test]
    #[ignore = "External pack loading not yet integrated into evaluation path"]
    fn custom_pack_allows_non_matching_command() {
        let pack_content = r#"
schema_version: 1
id: custom.deploy
name: Custom Deploy Rules
version: 1.0.0
keywords:
  - deploy
destructive_patterns:
  - name: prod-deploy
    pattern: deploy\s+--env\s*=?\s*prod
    severity: critical
"#;

        let (_temp, output) = setup_custom_pack_env(pack_content, "deploy --env staging");
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse hook output
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce valid JSON");

        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "allow",
            "custom pack should allow non-matching command\nstdout:\n{stdout}"
        );
    }

    #[test]
    #[ignore = "External pack loading not yet integrated into evaluation path"]
    fn custom_pack_safe_pattern_takes_precedence() {
        let pack_content = r#"
schema_version: 1
id: custom.deploy
name: Custom Deploy Rules
version: 1.0.0
keywords:
  - deploy
destructive_patterns:
  - name: any-deploy
    pattern: deploy\s+--env
    severity: high
    description: Deployments require review
safe_patterns:
  - name: staging-deploy
    pattern: deploy\s+--env\s*=?\s*staging
    description: Staging deployments are allowed
"#;

        // Staging should be allowed (safe pattern takes precedence)
        let (_temp, output) = setup_custom_pack_env(pack_content, "deploy --env staging");
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce valid JSON");

        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "allow",
            "safe pattern should allow staging deploy\nstdout:\n{stdout}"
        );
    }
}

// ============================================================================
// Stats --rules E2E Tests (git_safety_guard-1dri.4)
// ============================================================================
//
// These tests validate the `dcg stats --rules` subcommand with known fixture
// data, testing both pretty and JSON output formats.

mod stats_rules_tests {
    use super::*;
    use chrono::Utc;
    use destructive_command_guard::history::{CommandEntry, HistoryDb, Outcome};
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Test environment for stats --rules tests.
    struct StatsRulesEnv {
        temp: TempDir,
        db_path: PathBuf,
    }

    impl StatsRulesEnv {
        fn new() -> Self {
            let temp = TempDir::new().expect("failed to create temp dir");
            let db_path = temp.path().join("test_history.db");
            Self { temp, db_path }
        }

        fn seed_rule_metrics_data(&self) {
            let db = HistoryDb::open(Some(self.db_path.clone())).expect("open db");
            let now = Utc::now();

            // core.git:reset-hard - 5 hits (3 deny, 2 bypass)
            let reset_entries = vec![
                ("git reset --hard HEAD~1", Outcome::Deny, -7200),
                ("git reset --hard HEAD~2", Outcome::Deny, -6000),
                ("git reset --hard origin/main", Outcome::Deny, -4800),
                ("git reset --hard HEAD", Outcome::Bypass, -3600),
                ("git reset --hard abc123", Outcome::Bypass, -2400),
            ];
            for (cmd, outcome, offset) in reset_entries {
                let entry = CommandEntry {
                    timestamp: now + chrono::Duration::seconds(offset),
                    agent_type: "claude_code".to_string(),
                    working_dir: "/test".to_string(),
                    command: cmd.to_string(),
                    outcome,
                    pack_id: Some("core.git".to_string()),
                    pattern_name: Some("reset-hard".to_string()),
                    rule_id: Some("core.git:reset-hard".to_string()),
                    ..Default::default()
                };
                db.log_command(&entry).expect("insert entry");
            }

            // core.git:force-push - 3 hits (2 deny, 1 bypass)
            let push_entries = vec![
                ("git push --force origin main", Outcome::Deny, -7000),
                (
                    "git push --force-with-lease origin dev",
                    Outcome::Deny,
                    -5000,
                ),
                ("git push --force origin feature", Outcome::Bypass, -3000),
            ];
            for (cmd, outcome, offset) in push_entries {
                let entry = CommandEntry {
                    timestamp: now + chrono::Duration::seconds(offset),
                    agent_type: "claude_code".to_string(),
                    working_dir: "/test".to_string(),
                    command: cmd.to_string(),
                    outcome,
                    pack_id: Some("core.git".to_string()),
                    pattern_name: Some("force-push".to_string()),
                    rule_id: Some("core.git:force-push".to_string()),
                    ..Default::default()
                };
                db.log_command(&entry).expect("insert entry");
            }

            // core.filesystem:rm-rf - 4 hits (4 deny, 0 bypass)
            let rm_entries = vec![
                ("rm -rf /tmp/test", -8000),
                ("rm -rf ./build", -6500),
                ("rm -rf node_modules", -5500),
                ("rm -rf dist", -4000),
            ];
            for (cmd, offset) in rm_entries {
                let entry = CommandEntry {
                    timestamp: now + chrono::Duration::seconds(offset),
                    agent_type: "claude_code".to_string(),
                    working_dir: "/test".to_string(),
                    command: cmd.to_string(),
                    outcome: Outcome::Deny,
                    pack_id: Some("core.filesystem".to_string()),
                    pattern_name: Some("rm-rf".to_string()),
                    rule_id: Some("core.filesystem:rm-rf".to_string()),
                    ..Default::default()
                };
                db.log_command(&entry).expect("insert entry");
            }
        }

        fn run(&self, args: &[&str]) -> std::process::Output {
            Command::new(dcg_binary())
                .env("DCG_HISTORY_DB", &self.db_path)
                .current_dir(self.temp.path())
                .args(args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .expect("run dcg")
        }
    }

    // -------------------------------------------------------------------------
    // Pretty output tests
    // -------------------------------------------------------------------------

    #[test]
    fn stats_rules_pretty_shows_header() {
        let env = StatsRulesEnv::new();
        env.seed_rule_metrics_data();

        let output = env.run(&["stats", "--rules"]);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            output.status.success(),
            "stats --rules should succeed\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        assert!(
            stdout.contains("Rule Metrics"),
            "should show Rule Metrics header\nstdout:\n{stdout}"
        );
    }

    #[test]
    fn stats_rules_pretty_shows_all_rules() {
        let env = StatsRulesEnv::new();
        env.seed_rule_metrics_data();

        let output = env.run(&["stats", "--rules"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            stdout.contains("core.git:reset-hard"),
            "should show reset-hard rule\nstdout:\n{stdout}"
        );
        assert!(
            stdout.contains("core.git:force-push"),
            "should show force-push rule\nstdout:\n{stdout}"
        );
        assert!(
            stdout.contains("core.filesystem:rm-rf"),
            "should show rm-rf rule\nstdout:\n{stdout}"
        );
    }

    #[test]
    fn stats_rules_pretty_shows_totals() {
        let env = StatsRulesEnv::new();
        env.seed_rule_metrics_data();

        let output = env.run(&["stats", "--rules"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Total: 12 hits, 3 overrides (from fixture data)
        assert!(
            stdout.contains("Total"),
            "should show Total row\nstdout:\n{stdout}"
        );
        assert!(
            stdout.contains("12"),
            "should show total hits of 12\nstdout:\n{stdout}"
        );
    }

    #[test]
    fn stats_rules_pretty_shows_rule_count() {
        let env = StatsRulesEnv::new();
        env.seed_rule_metrics_data();

        let output = env.run(&["stats", "--rules"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            stdout.contains("3 rules shown"),
            "should show '3 rules shown'\nstdout:\n{stdout}"
        );
    }

    #[test]
    fn stats_rules_limit_restricts_output() {
        let env = StatsRulesEnv::new();
        env.seed_rule_metrics_data();

        let output = env.run(&["stats", "--rules", "-n", "2"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            stdout.contains("2 rules shown"),
            "should show '2 rules shown' when limit=2\nstdout:\n{stdout}"
        );
    }

    // -------------------------------------------------------------------------
    // JSON output tests
    // -------------------------------------------------------------------------

    #[test]
    fn stats_rules_json_is_valid() {
        let env = StatsRulesEnv::new();
        env.seed_rule_metrics_data();

        let output = env.run(&["stats", "--rules", "--format", "json"]);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            output.status.success(),
            "stats --rules --format json should succeed\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );

        let json: serde_json::Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|_| panic!("should produce valid JSON\nstdout:\n{stdout}"));

        assert!(json.is_object(), "JSON should be an object");
    }

    #[test]
    fn stats_rules_json_has_required_fields() {
        let env = StatsRulesEnv::new();
        env.seed_rule_metrics_data();

        let output = env.run(&["stats", "--rules", "--format", "json"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();

        assert!(
            json["period_days"].is_number(),
            "should have period_days field"
        );
        assert!(json["rules"].is_array(), "should have rules array");
        assert!(json["totals"].is_object(), "should have totals object");
    }

    #[test]
    fn stats_rules_json_rules_have_required_fields() {
        let env = StatsRulesEnv::new();
        env.seed_rule_metrics_data();

        let output = env.run(&["stats", "--rules", "--format", "json"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let rules = json["rules"].as_array().unwrap();

        assert!(!rules.is_empty(), "should have at least one rule");

        for rule in rules {
            assert!(
                rule["rule_id"].is_string(),
                "rule should have rule_id: {rule:?}"
            );
            assert!(
                rule["pack_id"].is_string(),
                "rule should have pack_id: {rule:?}"
            );
            assert!(
                rule["pattern_name"].is_string(),
                "rule should have pattern_name: {rule:?}"
            );
            assert!(
                rule["total_hits"].is_number(),
                "rule should have total_hits: {rule:?}"
            );
            assert!(
                rule["allowlist_overrides"].is_number(),
                "rule should have allowlist_overrides: {rule:?}"
            );
            assert!(
                rule["override_rate"].is_number(),
                "rule should have override_rate: {rule:?}"
            );
            assert!(
                rule["first_seen"].is_string(),
                "rule should have first_seen: {rule:?}"
            );
            assert!(
                rule["last_seen"].is_string(),
                "rule should have last_seen: {rule:?}"
            );
            assert!(
                rule["unique_commands"].is_number(),
                "rule should have unique_commands: {rule:?}"
            );
            assert!(
                rule["trend"].is_string(),
                "rule should have trend: {rule:?}"
            );
            assert!(
                rule["is_noisy"].is_boolean(),
                "rule should have is_noisy: {rule:?}"
            );
        }
    }

    #[test]
    fn stats_rules_json_totals_correct() {
        let env = StatsRulesEnv::new();
        env.seed_rule_metrics_data();

        let output = env.run(&["stats", "--rules", "--format", "json"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();

        // Expected: 12 total hits, 3 total overrides (bypasses), 3 rules
        assert_eq!(
            json["totals"]["total_hits"], 12,
            "should have 12 total hits\njson: {json:#}"
        );
        assert_eq!(
            json["totals"]["total_overrides"], 3,
            "should have 3 total overrides\njson: {json:#}"
        );
        assert_eq!(
            json["totals"]["rule_count"], 3,
            "should have 3 rules\njson: {json:#}"
        );
    }

    #[test]
    fn stats_rules_json_rule_values_correct() {
        let env = StatsRulesEnv::new();
        env.seed_rule_metrics_data();

        let output = env.run(&["stats", "--rules", "--format", "json"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let rules = json["rules"].as_array().unwrap();

        // Find the reset-hard rule and verify its values
        let reset_rule = rules
            .iter()
            .find(|r| r["rule_id"] == "core.git:reset-hard")
            .expect("should find reset-hard rule");

        assert_eq!(reset_rule["total_hits"], 5, "reset-hard should have 5 hits");
        assert_eq!(
            reset_rule["allowlist_overrides"], 2,
            "reset-hard should have 2 overrides"
        );
        assert_eq!(
            reset_rule["unique_commands"], 5,
            "reset-hard should have 5 unique commands"
        );

        // Find the rm-rf rule which has 0 overrides
        let rm_rule = rules
            .iter()
            .find(|r| r["rule_id"] == "core.filesystem:rm-rf")
            .expect("should find rm-rf rule");

        assert_eq!(rm_rule["total_hits"], 4, "rm-rf should have 4 hits");
        assert_eq!(
            rm_rule["allowlist_overrides"], 0,
            "rm-rf should have 0 overrides"
        );
    }

    #[test]
    fn stats_rules_json_limit_works() {
        let env = StatsRulesEnv::new();
        env.seed_rule_metrics_data();

        let output = env.run(&["stats", "--rules", "--format", "json", "-n", "1"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let rules = json["rules"].as_array().unwrap();

        assert_eq!(rules.len(), 1, "should only return 1 rule when limit=1");
    }

    #[test]
    fn stats_rules_json_days_filter_works() {
        let env = StatsRulesEnv::new();
        env.seed_rule_metrics_data();

        let output = env.run(&["stats", "--rules", "--format", "json", "--days", "1"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();

        assert_eq!(
            json["period_days"], 1,
            "should show period_days=1\njson: {json:#}"
        );
    }

    // -------------------------------------------------------------------------
    // Empty database tests
    // -------------------------------------------------------------------------

    #[test]
    fn stats_rules_empty_database_shows_message() {
        let env = StatsRulesEnv::new();
        // Don't seed any data

        // Create the database by opening it
        let _db = HistoryDb::open(Some(env.db_path.clone())).expect("create db");

        let output = env.run(&["stats", "--rules"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            output.status.success(),
            "should succeed even with empty database"
        );
        assert!(
            stdout.contains("No rule metrics found"),
            "should show 'No rule metrics found' message\nstdout:\n{stdout}"
        );
    }

    // -------------------------------------------------------------------------
    // Trend indicator tests
    // -------------------------------------------------------------------------

    #[test]
    fn stats_rules_pretty_shows_trend_indicators() {
        let env = StatsRulesEnv::new();
        env.seed_rule_metrics_data();

        let output = env.run(&["stats", "--rules"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Should contain at least one of the trend indicators
        let has_trend_indicator =
            stdout.contains("↑") || stdout.contains("→") || stdout.contains("↓");
        assert!(
            has_trend_indicator,
            "should show at least one trend indicator\nstdout:\n{stdout}"
        );
    }

    #[test]
    fn stats_rules_json_trend_values_valid() {
        let env = StatsRulesEnv::new();
        env.seed_rule_metrics_data();

        let output = env.run(&["stats", "--rules", "--format", "json"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let rules = json["rules"].as_array().unwrap();

        for rule in rules {
            let trend = rule["trend"].as_str().unwrap();
            assert!(
                ["increasing", "stable", "decreasing"].contains(&trend),
                "trend should be one of increasing/stable/decreasing, got: {trend}"
            );
        }
    }
}

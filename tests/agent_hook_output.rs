//! Tests for `HookSpecificOutput` JSON structure and required fields.
//!
//! These tests verify that the hook output contains all fields required
//! for AI agent integration as specified in `git_safety_guard-e4fl.1`.

#![allow(clippy::doc_markdown, clippy::uninlined_format_args)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// The denial path writes an allow-once record. Parallel cases must not race
/// each other for the same bounded store lock and then mistake the deliberate
/// code-less contention fallback for a wire-schema regression.
static HOOK_PROCESS_LOCK: Mutex<()> = Mutex::new(());

fn test_state_stem() -> &'static Path {
    static STATE_STEM: OnceLock<PathBuf> = OnceLock::new();
    STATE_STEM
        .get_or_init(|| {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock must be after the Unix epoch")
                .as_nanos();
            std::env::temp_dir().join(format!(
                "dcg-agent-hook-output-{}-{nonce}",
                std::process::id()
            ))
        })
        .as_path()
}

fn test_state_path(suffix: &str) -> PathBuf {
    let mut path = test_state_stem().as_os_str().to_os_string();
    path.push(suffix);
    PathBuf::from(path)
}

/// Fence hook subprocesses away from the caller's dcg state.
///
/// The explicit pending/allow-once paths are the causal isolation for these
/// tests: denial metadata is omitted by design when the bounded pending-store
/// lock cannot be acquired. The HOME-family variables keep the subprocess from
/// reading the caller's ordinary user configuration on platforms where those
/// variables define it; they are not intended to replace the explicit store
/// paths.
fn configure_isolated_hook_child(command: &mut Command) {
    for (key, _) in std::env::vars_os() {
        if key
            .to_string_lossy()
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("DCG_"))
        {
            command.env_remove(key);
        }
    }

    let test_home = test_state_path("-home");
    command
        .env("HOME", &test_home)
        .env("USERPROFILE", &test_home)
        .env("XDG_CONFIG_HOME", test_home.join(".config"))
        .env("XDG_DATA_HOME", test_home.join(".local/share"))
        .env("APPDATA", test_home.join("AppData/Roaming"))
        .env("LOCALAPPDATA", test_home.join("AppData/Local"))
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_HISTORY_DISABLED", "1")
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env(
            "DCG_PENDING_EXCEPTIONS_PATH",
            test_state_path("-pending-exceptions.jsonl"),
        )
        .env("DCG_ALLOW_ONCE_PATH", test_state_path("-allow-once.jsonl"));
}

/// Path to the DCG binary (uses same target directory as the test binary).
fn dcg_binary() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // Remove test binary name
    path.pop(); // Remove deps/
    path.push(format!("dcg{}", std::env::consts::EXE_SUFFIX));
    path
}

/// Run dcg in hook mode with the given command as JSON input.
fn run_hook_mode(command: &str) -> (String, String, i32) {
    let _guard = HOOK_PROCESS_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let input = format!(
        r#"{{"tool_name":"Bash","tool_input":{{"command":"{}"}}}}"#,
        command.replace('\\', "\\\\").replace('"', "\\\"")
    );

    let mut child_command = Command::new(dcg_binary());
    configure_isolated_hook_child(&mut child_command);
    let mut child = child_command
        .args(["--agent", "claude-code"])
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

#[test]
fn test_hook_output_contains_hook_event_name() {
    let (stdout, stderr, exit_code) = run_hook_mode("git reset --hard");

    assert_eq!(
        exit_code, 0,
        "hook mode should exit 0 even on deny\nstderr: {stderr}"
    );
    assert!(!stdout.is_empty(), "stdout should contain JSON output");

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("hook output should be valid JSON");

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

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("hook output should be valid JSON");

    let hook_output = &json["hookSpecificOutput"];
    assert!(
        hook_output.get("permissionDecision").is_some(),
        "permissionDecision field required in output"
    );

    assert_eq!(
        hook_output["permissionDecision"], "deny",
        "git reset --hard must be denied"
    );
}

#[test]
fn test_hook_output_deny_has_rule_id() {
    let (stdout, _stderr, _) = run_hook_mode("git reset --hard");

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("hook output should be valid JSON");

    let hook_output = &json["hookSpecificOutput"];

    assert_eq!(hook_output["permissionDecision"], "deny");
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

#[test]
fn test_hook_output_deny_has_pack_id() {
    let (stdout, _stderr, _) = run_hook_mode("git reset --hard");

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("hook output should be valid JSON");

    let hook_output = &json["hookSpecificOutput"];

    assert_eq!(hook_output["permissionDecision"], "deny");
    assert!(
        hook_output.get("packId").is_some(),
        "packId field should be present for denied commands"
    );

    let pack_id = hook_output["packId"].as_str().unwrap();
    assert!(!pack_id.is_empty(), "packId should not be empty");
}

#[test]
fn test_hook_output_deny_has_severity() {
    let (stdout, _stderr, _) = run_hook_mode("git reset --hard");

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("hook output should be valid JSON");

    let hook_output = &json["hookSpecificOutput"];

    assert_eq!(hook_output["permissionDecision"], "deny");
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

#[test]
fn test_hook_output_deny_has_remediation() {
    let (stdout, _stderr, _) = run_hook_mode("git reset --hard");

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("hook output should be valid JSON");

    let hook_output = &json["hookSpecificOutput"];
    assert_eq!(
        hook_output["permissionDecision"], "deny",
        "git reset --hard must exercise the denial metadata path"
    );
    assert!(
        hook_output.get("remediation").is_some(),
        "remediation field should be present for denied commands"
    );

    let remediation = &hook_output["remediation"];

    // Verify remediation structure on an uncontended isolated store.
    assert!(
        remediation.get("explanation").is_some(),
        "remediation.explanation should be present"
    );
    assert!(
        remediation.get("allowOnceCommand").is_some(),
        "remediation.allowOnceCommand should be present"
    );
}

#[test]
fn test_hook_output_deny_has_allow_once_code() {
    let (stdout, _stderr, _) = run_hook_mode("git reset --hard");

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("hook output should be valid JSON");

    let hook_output = &json["hookSpecificOutput"];
    assert_eq!(
        hook_output["permissionDecision"], "deny",
        "git reset --hard must exercise the allow-once metadata path"
    );
    assert!(
        hook_output.get("allowOnceCode").is_some(),
        "allowOnceCode should be present for denied commands"
    );

    let code = hook_output["allowOnceCode"].as_str().unwrap();
    assert!(!code.is_empty(), "allowOnceCode should not be empty");

    // On an uncontended isolated store, remediation must carry the same code.
    let remediation = hook_output
        .get("remediation")
        .expect("remediation should accompany an allowOnceCode");
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

#[test]
fn test_hook_output_permission_decision_reason() {
    let (stdout, _stderr, _) = run_hook_mode("git reset --hard");

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("hook output should be valid JSON");

    let hook_output = &json["hookSpecificOutput"];

    assert!(
        hook_output.get("permissionDecisionReason").is_some(),
        "permissionDecisionReason should be present"
    );

    let reason = hook_output["permissionDecisionReason"].as_str().unwrap();
    assert!(
        !reason.is_empty(),
        "permissionDecisionReason should not be empty"
    );

    assert_eq!(hook_output["permissionDecision"], "deny");
    assert!(
        reason.contains("BLOCKED") || reason.contains("Reason:"),
        "permissionDecisionReason for deny should explain the block"
    );
}

#[test]
fn test_hook_output_stderr_includes_allowlist_add_hint() {
    let (stdout, stderr, exit_code) = run_hook_mode("git reset --hard");

    assert_eq!(exit_code, 0, "hook mode should exit 0");
    assert!(!stdout.trim().is_empty(), "deny should emit JSON on stdout");

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("hook output should be valid JSON");
    let hook_output = &json["hookSpecificOutput"];

    assert_eq!(
        hook_output["permissionDecision"], "deny",
        "git reset --hard should be denied"
    );

    assert!(
        stderr.contains("dcg allowlist add core.git:reset-hard --user"),
        "stderr should include allowlist add hint for matched rule.\nstderr:\n{stderr}"
    );
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

        assert!(!stdout.is_empty(), "destructive command was allowed: {cmd}");
        let json: serde_json::Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("invalid JSON for cmd '{cmd}': {e}\nstdout: {stdout}"));

        let hook_output = &json["hookSpecificOutput"];
        assert_eq!(
            hook_output["permissionDecision"], "deny",
            "destructive command was not denied: {cmd}"
        );
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

#[test]
fn test_hook_output_rule_id_format() {
    let (stdout, _stderr, _) = run_hook_mode("git reset --hard");

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("hook output should be valid JSON");

    let hook_output = &json["hookSpecificOutput"];

    assert_eq!(hook_output["permissionDecision"], "deny");
    let rule_id_str = hook_output["ruleId"]
        .as_str()
        .expect("denial must include a string ruleId");

    // Rule ID format: "{packId}:{patternName}"
    let parts: Vec<&str> = rule_id_str.split(':').collect();
    assert_eq!(
        parts.len(),
        2,
        "ruleId should have format 'packId:patternName', got: {rule_id_str}"
    );

    let pack_id = hook_output["packId"]
        .as_str()
        .expect("denial must include a string packId");
    assert_eq!(parts[0], pack_id, "ruleId pack portion should match packId");
}

#[test]
fn test_hook_output_remediation_safe_alternative() {
    let (stdout, _stderr, _) = run_hook_mode("git reset --hard");

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("hook output should be valid JSON");

    let hook_output = &json["hookSpecificOutput"];

    assert_eq!(hook_output["permissionDecision"], "deny");
    assert!(
        hook_output.get("remediation").is_some(),
        "denial must include remediation"
    );

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

// ============================================================================
// Antigravity CLI (`agy`) end-to-end hook integration.
//
// Feeds the dcg binary the exact stdin envelope that `agy` passes to a
// PreToolUse hook (captured empirically in a sandboxed $HOME) and asserts dcg
// emits the block decision that `agy` honors. This is the live wire-format
// contract: `agy` reads {"decision":"block","reason":...} from stdout (exit 0)
// and aborts its `run_command` tool. A fully-interactive live-fire block (the
// model actually being prevented from running the command) was verified
// manually against the real `agy` binary in a sandbox HOME; that path needs an
// authenticated, interactive `agy` session and is not reproducible in CI, so
// here we lock down the byte-level request/response contract instead.
// ============================================================================

/// Run dcg in hook mode with a raw JSON envelope (for non-Claude wire shapes).
fn run_hook_mode_raw(input: &str) -> (String, String, i32) {
    let _guard = HOOK_PROCESS_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut child_command = Command::new(dcg_binary());
    configure_isolated_hook_child(&mut child_command);
    let mut child = child_command
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

#[test]
fn test_antigravity_envelope_produces_block_decision() {
    // Exact agy stdin shape captured from a real `agy` PreToolUse hook run.
    let input = r#"{
        "artifactDirectoryPath":"/tmp/.gemini/brain/abc",
        "conversationId":"a3bbcaba-0bb2-4e58-b614-49f42fa6f004",
        "stepIdx":4,
        "toolCall":{"name":"run_command","args":{"CommandLine":"git reset --hard","Cwd":"/work","WaitMsBeforeAsync":500}},
        "transcriptPath":"/tmp/.gemini/brain/abc/transcript_full.jsonl",
        "workspacePaths":["/work"]
    }"#;

    let (stdout, stderr, exit_code) = run_hook_mode_raw(input);

    // `agy` only blocks on exit 0 + JSON (a non-zero exit is merely logged).
    assert_eq!(
        exit_code, 0,
        "agy hook must exit 0 so the JSON block decision is honored\nstderr: {stderr}"
    );
    assert!(!stdout.is_empty(), "stdout must carry the block JSON");

    let json: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("agy hook output must be valid JSON");

    assert_eq!(
        json["decision"], "block",
        "agy block decision must use the \"block\" keyword"
    );
    assert!(
        json["reason"].as_str().is_some_and(|r| !r.is_empty()),
        "block must carry a non-empty reason, got: {}",
        json["reason"]
    );
    // Must NOT emit Claude's hookSpecificOutput envelope (agy uses decision/reason).
    assert!(
        json.get("hookSpecificOutput").is_none(),
        "agy output must not use Claude's hookSpecificOutput shape"
    );
}

#[test]
fn test_antigravity_envelope_allows_safe_command() {
    // A benign command must NOT block: agy gets an explicit allow (or no JSON
    // block), and the tool proceeds.
    let input = r#"{
        "conversationId":"c1",
        "stepIdx":1,
        "toolCall":{"name":"run_command","args":{"CommandLine":"echo hello","Cwd":"/work"}},
        "workspacePaths":["/work"]
    }"#;

    let (stdout, stderr, exit_code) = run_hook_mode_raw(input);
    assert_eq!(exit_code, 0, "safe command must exit 0\nstderr: {stderr}");

    // dcg emits nothing (allow) or an explicit non-block decision for safe
    // commands; in either case there must be no "block"/"deny" decision.
    if !stdout.trim().is_empty() {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(stdout.trim()) {
            let decision = json.get("decision").and_then(|d| d.as_str());
            assert!(
                decision != Some("block") && decision != Some("deny"),
                "safe command must not be blocked, got decision: {decision:?}"
            );
        }
    }
}

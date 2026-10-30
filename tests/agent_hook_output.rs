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
    let test_config =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/e2e/fixtures/configs/minimal.toml");
    assert!(
        test_config.is_file(),
        "isolated hook config fixture is missing: {}",
        test_config.display()
    );
    command
        .env("HOME", &test_home)
        .env("USERPROFILE", &test_home)
        .env_remove("CLAUDE_CONFIG_DIR")
        .env("XDG_CONFIG_HOME", test_home.join(".config"))
        .env("XDG_DATA_HOME", test_home.join(".local/share"))
        .env("APPDATA", test_home.join("AppData/Roaming"))
        .env("LOCALAPPDATA", test_home.join("AppData/Local"))
        .env("ProgramData", &test_home)
        .env("DCG_CONFIG", test_config)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_HISTORY_DISABLED", "1")
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env(
            "DCG_PENDING_EXCEPTIONS_PATH",
            test_state_path("-pending-exceptions.jsonl"),
        )
        .env("DCG_ALLOW_ONCE_PATH", test_state_path("-allow-once.jsonl"));
}

/// Path to the exact DCG binary Cargo built for this integration test.
fn dcg_binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

/// Run dcg in hook mode with the given command as JSON input.
fn run_hook_mode(command: &str) -> (String, String, i32) {
    let _guard = HOOK_PROCESS_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
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
fn issue_555_multiline_security_verdicts() {
    for lines in [1, 40, 300] {
        let body = "print('ordinary data')\n".repeat(lines);
        for (command, deny) in [
            (format!("python3 - <<'EOF'\n{body}EOF"), false),
            (format!("cat <<'EOF'\n{body}rm -rf /\nEOF"), false),
            (
                format!("python3 - <<'EOF'\n{body}import shutil\nshutil.rmtree('/tmp')\nEOF"),
                true,
            ),
            (
                format!(
                    "python3 - <<'EOF'\n{body}import os\nos.system(\"bash -c 'rm -rf /'\")\nEOF"
                ),
                true,
            ),
            (format!("cat <<EOF\n{body}$(rm -rf /)\nEOF"), true),
            (format!("cat <<'EOF'\n{body}$(rm -rf /)\nEOF"), false),
        ] {
            let payload = serde_json::json!({"tool_name": "Bash",
                "tool_input": {"command": command}})
            .to_string();
            let (stdout, stderr, code) = run_hook_mode_raw(&payload);
            assert_eq!(code, 0, "{stderr}");
            if deny {
                let result: serde_json::Value = serde_json::from_str(&stdout)
                    .unwrap_or_else(|_| panic!("missing denial for {command}: {stderr}"));
                assert_eq!(
                    result["hookSpecificOutput"]["permissionDecision"], "deny",
                    "{command}: {stderr}"
                );
            } else {
                assert!(
                    stdout.is_empty() && stderr.is_empty(),
                    "{command}: {stdout} {stderr}"
                );
            }
        }
    }
    for command in [
        "yes | { echo ok; rm -ri ./tree; }",
        "exec 0<answers.txt; rm -ri ./tree",
        "echo $(bash -c 'rm -rf /')",
        "cat <<'EOF'\nordinary data\nEOF\nrm -rf /",
    ] {
        let payload = serde_json::json!({"tool_name": "Bash",
            "tool_input": {"command": command}})
        .to_string();
        let (stdout, stderr, code) = run_hook_mode_raw(&payload);
        assert_eq!(code, 0, "{stderr}");
        let result: serde_json::Value = serde_json::from_str(&stdout).expect("must deny");
        assert_eq!(
            result["hookSpecificOutput"]["permissionDecision"], "deny",
            "{command}"
        );
    }
}

#[test]
fn issue_555_phase_diagnostics_preserve_silent_allow() {
    let _guard = HOOK_PROCESS_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let marker = "phase-probe-private-body";
    let payload = serde_json::json!({"tool_name": "Bash", "tool_input": {
        "command": format!("python3 - <<'EOF'\nprint('{marker}')\nEOF")}})
    .to_string();
    let mut command = Command::new(dcg_binary());
    configure_isolated_hook_child(&mut command);
    let mut child = command
        .args(["--agent", "claude-code"])
        .env("DCG_LOG", "dcg_perf=debug")
        .env_remove("DCG_HISTORY_DISABLED")
        .env("DCG_HISTORY_ENABLED", "1")
        .env("DCG_HISTORY_DB", test_state_path("-phase-history.db"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn phase probe");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(payload.as_bytes())
        .expect("payload");
    let output = child.wait_with_output().expect("phase probe");
    assert!(output.status.success());
    assert!(
        output.stdout.is_empty(),
        "diagnostics must not change hook stdout"
    );
    let stderr = String::from_utf8(output.stderr).expect("diagnostic UTF-8");
    assert!(
        !stderr.contains(marker),
        "phase events must not expose command bodies"
    );
    for phase in [
        "request_parse",
        "normalization",
        "heredoc_detection",
        "heredoc_extraction",
        "pattern_evaluation",
        "history_setup",
        "history_enqueue_redact",
        "history_storage_open",
        "history_storage_insert",
        "history_shutdown_wait",
        "hook_total",
    ] {
        assert!(
            stderr.contains(&format!("phase=\"{phase}\"")),
            "missing {phase}: {stderr}"
        );
    }
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
// PreToolUse hook and checks the strict response contract from issue #573:
// exactly {"decision":"deny","reason":...} on exit 0. Gemini metadata is
// rejected by Antigravity 1.4.0, and an explicit allow can skip its ordinary
// permission prompt. Safe and warning outcomes must therefore emit zero
// stdout bytes. These tests pass commands as data; no command is executed.
// ============================================================================

/// Run dcg in hook mode with a raw JSON envelope (for non-Claude wire shapes).
fn run_hook_mode_raw(input: &str) -> (String, String, i32) {
    run_hook_mode_raw_with_options(input, &[], &[])
}

fn run_hook_mode_raw_with_options(
    input: &str,
    args: &[&str],
    env: &[(&str, &str)],
) -> (String, String, i32) {
    let _guard = HOOK_PROCESS_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut child_command = Command::new(dcg_binary());
    configure_isolated_hook_child(&mut child_command);
    let mut child = child_command
        .args(args)
        .envs(env.iter().copied())
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

/// Independent consumer schema: extra output fields must fail deserialization,
/// rather than being ignored by `serde_json::Value`.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AntigravityDenial {
    decision: String,
    reason: String,
}

fn decode_antigravity_denial(stdout: &str) -> Result<AntigravityDenial, serde_json::Error> {
    let shape: serde_json::Value = serde_json::from_str(stdout)?;
    if !shape.is_object() {
        return Err(serde::de::Error::custom("agy denial must be an object"));
    }
    // Decode the original bytes, not the Value, so duplicate fields are
    // rejected. String fields also reject Serde's alternate enum encodings.
    let denial: AntigravityDenial = serde_json::from_str(stdout)?;
    if denial.decision != "deny" {
        return Err(serde::de::Error::custom("agy decision must be deny"));
    }
    Ok(denial)
}

fn assert_antigravity_denial(stdout: &str, stderr: &str, exit_code: i32) -> AntigravityDenial {
    assert_eq!(
        exit_code, 0,
        "agy must exit 0 for the JSON denial to be honored\nstderr: {stderr}"
    );
    let denial = decode_antigravity_denial(stdout).unwrap_or_else(|error| {
        panic!(
            "agy denial must satisfy its strict schema: {error}\nstdout: {stdout}\nstderr: {stderr}"
        )
    });
    assert_eq!(denial.decision, "deny");
    assert!(
        !denial.reason.trim().is_empty(),
        "agy denial must carry a nonempty reason"
    );
    assert!(
        !stderr.trim().is_empty(),
        "agy denial must retain the operator-visible diagnostic"
    );
    denial
}

fn antigravity_payload(command: &str) -> String {
    // Include the diagnostic metadata from a captured native request, not
    // just the tool call; none of it belongs in the strict response schema.
    serde_json::json!({
        "artifactDirectoryPath": "/tmp/.gemini/brain/abc",
        "conversationId": "a3bbcaba-0bb2-4e58-b614-49f42fa6f004",
        "stepIdx": 4,
        "toolCall": {
            "name": "run_command",
            "args": {"CommandLine": command, "Cwd": "/work", "WaitMsBeforeAsync": 500}
        },
        "transcriptPath": "/tmp/.gemini/brain/abc/transcript_full.jsonl",
        "workspacePaths": ["/work"]
    })
    .to_string()
}

#[test]
fn test_antigravity_strict_decoder_rejects_invalid_denials() {
    for invalid in [
        r#"{"decision":"deny","reason":"blocked","systemMessage":"blocked"}"#,
        r#"{"decision":"deny","reason":"blocked","ruleId":"core.git:reset-hard"}"#,
        r#"{"decision":"deny","reason":"blocked","remediation":{}}"#,
        r#"{"decision":"block","reason":"blocked"}"#,
        r#"{"decision":"allow","reason":"blocked"}"#,
        r#"{"decision":"ask","reason":"blocked"}"#,
        r#"{"decision":{"deny":null},"reason":"blocked"}"#,
        r#"["deny","blocked"]"#,
        r#"{"decision":"deny","reason":null}"#,
        r#"{"decision":"deny"}"#,
        r#"{"decision":"deny","decision":"allow","reason":"blocked"}"#,
        r#"{"decision":"deny","reason":"blocked"} {"decision":"allow"}"#,
    ] {
        assert!(
            decode_antigravity_denial(invalid).is_err(),
            "strict agy denial decoder accepted an incompatible payload: {invalid}"
        );
    }
}

#[test]
fn test_antigravity_envelope_produces_strict_deny_with_review_details() {
    let input = antigravity_payload("git reset --hard");
    let (stdout, stderr, exit_code) = run_hook_mode_raw(&input);
    let denial = assert_antigravity_denial(&stdout, &stderr, exit_code);

    for detail in [
        "git reset --hard",
        "core.git:reset-hard",
        "dcg explain",
        "dcg allow-once",
    ] {
        assert!(
            denial.reason.contains(detail),
            "agy reason must preserve review detail {detail:?}: {}",
            denial.reason
        );
    }
}

#[test]
fn test_antigravity_envelope_allows_safe_command() {
    let input = antigravity_payload("echo hello");
    let (stdout, stderr, exit_code) = run_hook_mode_raw(&input);
    assert_eq!(exit_code, 0, "safe command must exit 0\nstderr: {stderr}");
    assert!(
        stdout.is_empty(),
        "safe agy output must have zero bytes to preserve normal permissions, got: {stdout:?}"
    );
}

#[test]
fn test_antigravity_warning_preserves_ordinary_permission_checks() {
    // This medium-severity rule warns under the shipped policy. An explicit
    // `allow` would let a successful hook pre-approve Antigravity's tool call.
    let input = antigravity_payload("git stash drop");
    let invocations: [&[&str]; 2] = [&[], &["--agent", "agy"]];
    for args in invocations {
        let (stdout, stderr, exit_code) = run_hook_mode_raw_with_options(&input, args, &[]);
        assert_eq!(exit_code, 0, "agy warn must exit 0\nstderr: {stderr}");
        assert!(
            stdout.is_empty(),
            "agy warn must emit zero stdout bytes, never pre-approve a command: {stdout:?}"
        );
        assert!(
            stderr.contains("WARNING") && stderr.contains("git stash drop"),
            "agy warn must remain visible to the operator\nstderr: {stderr}"
        );
    }
}

#[test]
fn test_antigravity_command_keys_cannot_hide_a_destructive_native_command() {
    for decoy in ["echo harmless", "git stash drop", "echo '", "echo \\"] {
        let input = serde_json::json!({
            "toolCall": {
                "name": "run_command",
                "args": {"command": decoy, "CommandLine": "git reset --hard"}
            }
        })
        .to_string();
        let (stdout, stderr, exit_code) = run_hook_mode_raw(&input);
        let denial = assert_antigravity_denial(&stdout, &stderr, exit_code);
        assert!(
            denial.reason.contains("core.git:reset-hard"),
            "a harmless, warning, or unfinished alias cannot hide the native command: {decoy:?}\n{}",
            denial.reason
        );
    }
}

#[test]
fn test_antigravity_displaced_tool_call_retains_all_command_keys() {
    let input = serde_json::json!({
        "tool_call": {"name": "run_command", "args": {"CommandLine": "echo primary"}},
        "toolCall": {
            "name": "run_command",
            "args": {"command": "echo alias", "CommandLine": "git reset --hard"}
        }
    })
    .to_string();
    let (stdout, stderr, exit_code) = run_hook_mode_raw(&input);
    let denial = assert_antigravity_denial(&stdout, &stderr, exit_code);
    assert!(denial.reason.contains("core.git:reset-hard"));
}

#[test]
fn test_antigravity_benign_command_aliases_preserve_permissions() {
    for args in [
        serde_json::json!({"command": "echo first", "CommandLine": "git status"}),
        serde_json::json!({"command": "git status", "CommandLine": "git status"}),
        serde_json::json!({"command": "", "CommandLine": "git status"}),
        serde_json::json!({"command": "echo 'git reset --hard'", "CommandLine": "git status"}),
    ] {
        let input =
            serde_json::json!({"toolCall": {"name": "run_command", "args": args}}).to_string();
        let (stdout, stderr, exit_code) = run_hook_mode_raw(&input);
        assert_eq!(exit_code, 0, "{input}\nstderr: {stderr}");
        assert!(
            stdout.is_empty(),
            "benign aliases must not decide host permission: {stdout}"
        );
        assert!(
            stderr.is_empty(),
            "benign aliases must remain silent: {stderr}"
        );
    }
}

#[test]
fn test_stringified_args_cannot_hide_command_aliases() {
    let args =
        serde_json::json!({"command": "echo harmless", "Command": "git reset --hard"}).to_string();
    let cases = [
        (
            serde_json::json!({"toolCalls": [{"name": "bash", "args": args}]}),
            "/hookSpecificOutput/permissionDecision",
        ),
        (
            serde_json::json!({"event": "pre-tool-use", "toolName": "bash", "toolArgs": args}),
            "/permissionDecision",
        ),
    ];
    for (input, decision_pointer) in cases {
        let (stdout, stderr, exit_code) = run_hook_mode_raw(&input.to_string());
        assert_eq!(exit_code, 0, "{input}\nstderr: {stderr}");
        let output: serde_json::Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|error| panic!("missing denial for {input}: {error}\n{stderr}"));
        assert_eq!(
            output
                .pointer(decision_pointer)
                .and_then(serde_json::Value::as_str),
            Some("deny"),
            "{output}"
        );
        assert!(stdout.contains("core.git:reset-hard"), "{output}");
    }
}

#[test]
fn test_antigravity_warning_does_not_mask_destructive_companion() {
    let input = antigravity_payload("git stash drop; git reset --hard");
    let (stdout, stderr, exit_code) = run_hook_mode_raw(&input);
    let denial = assert_antigravity_denial(&stdout, &stderr, exit_code);
    assert!(
        denial.reason.contains("core.git:reset-hard"),
        "a warning cannot replace the destructive command's denial: {}",
        denial.reason
    );
}

#[test]
fn test_antigravity_explicit_agent_fail_closed_uses_strict_denial() {
    // Without a parseable envelope, --agent is the supported way to select
    // the hook protocol. A parse failure must still deliver a usable denial.
    let (stdout, stderr, exit_code) = run_hook_mode_raw_with_options(
        "not a JSON hook payload",
        &["--agent", "agy"],
        &[("DCG_FAIL_CLOSED", "1")],
    );
    let denial = assert_antigravity_denial(&stdout, &stderr, exit_code);
    assert!(
        denial.reason.contains("DCG_FAIL_CLOSED"),
        "forced agy protocol must explain the fail-closed denial: {}",
        denial.reason
    );
}

#[test]
fn test_antigravity_oversized_command_stays_denied_for_both_review_policies() {
    let input = antigravity_payload(&format!(
        "echo {}",
        "x".repeat(destructive_command_guard::config::DEFAULT_MAX_COMMAND_BYTES)
    ));
    for policy in ["ask", "deny"] {
        let (stdout, stderr, exit_code) =
            run_hook_mode_raw_with_options(&input, &[], &[("DCG_UNVERIFIED_DECISION", policy)]);
        let denial = assert_antigravity_denial(&stdout, &stderr, exit_code);
        assert!(
            denial.reason.contains("exceeds limit") && denial.reason.contains("did not evaluate"),
            "agy must deny an unverified oversized command under {policy}: {}",
            denial.reason
        );
    }
}

#[test]
fn test_gemini_retains_its_own_deny_and_warning_protocol() {
    for (command, expected_decision) in [("git reset --hard", "deny"), ("git stash drop", "allow")]
    {
        let input = serde_json::json!({
            "hook_event_name": "BeforeTool",
            "tool_name": "run_shell_command",
            "tool_input": {"command": command}
        })
        .to_string();
        let (stdout, stderr, exit_code) = run_hook_mode_raw(&input);
        assert_eq!(exit_code, 0, "Gemini must exit 0\nstderr: {stderr}");
        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("Gemini must retain its JSON response");
        assert_eq!(json["decision"], expected_decision);
        assert!(
            json["systemMessage"]
                .as_str()
                .is_some_and(|message| !message.is_empty()),
            "the dedicated agy response must not remove Gemini's own metadata: {json}"
        );
        assert!(!stderr.is_empty(), "Gemini must retain its diagnostic");
    }
}

// ============================================================================
// Crush (Charm) protocol (#388): flat `event`/`tool_name`/`tool_input`
// envelope in, `{"decision":"deny","reason":...}` out.
// ============================================================================

#[test]
fn test_crush_envelope_produces_deny_decision() {
    // Verbatim shape of what crush's hooks.BuildPayload pipes to stdin.
    let input = r#"{"event":"PreToolUse","session_id":"313909e","cwd":"/home/user/project","tool_name":"bash","tool_input":{"command":"git reset --hard HEAD~1"}}"#;

    let (stdout, stderr, exit_code) = run_hook_mode_raw(input);
    assert_eq!(
        exit_code, 0,
        "Crush parses stdout only on exit 0\nstderr: {stderr}"
    );
    let json: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout must be JSON: {e}\nstdout: {stdout}"));

    assert_eq!(json["decision"], "deny", "payload: {json}");
    assert!(
        json["reason"].as_str().is_some_and(|r| !r.is_empty()),
        "deny must carry a non-empty reason, got: {}",
        json["reason"]
    );
    assert_eq!(json["ruleId"], "core.git:reset-hard", "payload: {json}");
    // Before #388 this payload was routed to the Copilot arm and answered
    // with a flat `permissionDecision`, which Crush ignores (fail-open).
    assert!(
        json.get("permissionDecision").is_none() && json.get("hookSpecificOutput").is_none(),
        "Crush reads `decision`, not Copilot/Claude spellings: {json}"
    );
    assert!(
        !stderr.trim().is_empty(),
        "operator-visible denial on stderr"
    );
}

#[test]
fn test_crush_envelope_allows_safe_command_silently() {
    // No JSON at all: an omitted decision is "no opinion" in Crush and the
    // call proceeds through its ordinary permission prompt. dcg must never
    // answer `"allow"`, which would pre-approve the call and skip the prompt.
    let input = r#"{"event":"PreToolUse","session_id":"313909e","cwd":"/home/user/project","tool_name":"bash","tool_input":{"command":"git status"}}"#;

    let (stdout, stderr, exit_code) = run_hook_mode_raw(input);
    assert_eq!(exit_code, 0, "safe command must exit 0\nstderr: {stderr}");
    assert!(
        stdout.trim().is_empty(),
        "safe Crush hook output must be silent, got: {stdout}"
    );
}

// Factory's documented direct Execute hook contract (#617). These tests feed
// the real dcg binary commands as JSON data; they never execute the commands
// and do not establish that a live Droid Script invokes Execute hooks.
fn droid_payload(command: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "droid-session-617",
        "transcript_path": "/home/user/.factory/sessions/session.jsonl",
        "cwd": test_state_path("-home"),
        "tool_name": "Execute",
        "tool_input": {
            "command": command,
            "timeout": 90,
            "riskLevel": "high",
            "riskLevelReason": "User requested shell operation"
        },
        "tool_use_id": "call_execute_617"
    })
    .to_string()
}

fn assert_droid_denial(stdout: &str, stderr: &str, code: i32) -> serde_json::Value {
    assert_eq!(code, 0, "Factory parses JSON on exit 0: {stderr}");
    let output: serde_json::Value = serde_json::from_str(stdout).unwrap_or_else(|error| {
        panic!("Droid must receive JSON denial: {error}; {stdout}; {stderr}")
    });
    let hook_output = &output["hookSpecificOutput"];
    assert_eq!(hook_output["hookEventName"], "PreToolUse");
    assert_eq!(hook_output["permissionDecision"], "deny");
    assert!(
        hook_output["permissionDecisionReason"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty())
    );
    output
}

#[test]
fn test_droid_execute_denials_match_supported_bash_tools() {
    for command in [
        "git reset --hard HEAD",
        "git status; git reset --hard HEAD",
        "bash -c 'git reset --hard HEAD'",
        "python3 - <<'PY'\nimport os\nos.system('git reset --hard HEAD')\nPY",
    ] {
        let (bash_stdout, bash_stderr, bash_code) = run_hook_mode_raw_with_options(
            &serde_json::json!({"tool_name": "Bash", "tool_input": {"command": command}})
                .to_string(),
            &["--agent", "claude-code"],
            &[],
        );
        let bash = assert_droid_denial(&bash_stdout, &bash_stderr, bash_code);
        for args in [&[][..], &["--agent", "droid"][..]] {
            let (stdout, stderr, code) =
                run_hook_mode_raw_with_options(&droid_payload(command), args, &[]);
            let droid = assert_droid_denial(&stdout, &stderr, code);
            for field in ["permissionDecision", "ruleId", "packId", "severity"] {
                assert_eq!(
                    droid["hookSpecificOutput"][field], bash["hookSpecificOutput"][field],
                    "{command}: {field}"
                );
            }
        }
    }
}

#[test]
fn test_droid_execute_allows_safe_commands_without_preapproving_them() {
    for command in [
        "git status",
        "git clean --dry-run",
        "git diff --stat",
        "printf '%s\\n' 'ordinary text'",
    ] {
        for args in [&[][..], &["--agent", "droid"][..]] {
            let (stdout, stderr, code) =
                run_hook_mode_raw_with_options(&droid_payload(command), args, &[]);
            assert_eq!(code, 0, "{command}: {stderr}");
            assert!(
                stdout.is_empty(),
                "an allowed command must not bypass Factory's own permission prompt: {stdout}"
            );
            assert!(stderr.is_empty(), "{command}: {stderr}");
        }
    }
}

#[test]
fn test_droid_profile_applies_with_explicit_identity_and_native_payload() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("droid-profile.toml");
    std::fs::write(
        &config_path,
        r#"
        [packs]
        enabled = ["core.git", "core.filesystem"]
        [agents.droid]
        extra_packs = ["database.postgresql"]
        disabled_packs = ["core"]
    "#,
    )
    .unwrap();
    let env = [
        ("DCG_CONFIG", config_path.to_str().unwrap()),
        // A surrounding Claude terminal must not misattribute Execute.
        ("CLAUDECODE", "1"),
    ];
    let command = "psql -c 'DROP TABLE users'";
    for args in [
        &[][..],
        &["--agent", "droid"][..],
        &["--agent", "factory-droid"][..],
    ] {
        let (stdout, stderr, code) =
            run_hook_mode_raw_with_options(&droid_payload(command), args, &env);
        let denial = assert_droid_denial(&stdout, &stderr, code);
        assert_eq!(
            denial["hookSpecificOutput"]["packId"],
            "database.postgresql"
        );
        let (stdout, stderr, code) =
            run_hook_mode_raw_with_options(&droid_payload("git reset --hard"), args, &env);
        assert_droid_denial(&stdout, &stderr, code);
    }
    // Explicit overrides remain authoritative and optional Droid packs do
    // not leak into another host's policy.
    let (stdout, stderr, code) =
        run_hook_mode_raw_with_options(&droid_payload(command), &["--agent", "claude-code"], &env);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
}

#[test]
fn test_droid_allowlist_profile_preserves_disabled_allowlist_policy() {
    let temp = tempfile::tempdir().unwrap();
    let command = "git reset --hard HEAD";
    for disabled in [false, true] {
        let config_path = temp.path().join(format!("droid-allowlist-{disabled}.toml"));
        std::fs::write(
            &config_path,
            format!(
                r#"
            [agents.droid]
            additional_allowlist = ["{command}"]
            disabled_allowlist = {disabled}
        "#
            ),
        )
        .unwrap();
        let env = [("DCG_CONFIG", config_path.to_str().unwrap())];
        let (stdout, stderr, code) =
            run_hook_mode_raw_with_options(&droid_payload(command), &["--agent", "droid"], &env);
        if disabled {
            assert_droid_denial(&stdout, &stderr, code);
        } else {
            assert_eq!(code, 0, "{stderr}");
            assert!(
                stdout.is_empty(),
                "configured exact command should be allowed: {stdout}"
            );
        }
        let (stdout, stderr, code) = run_hook_mode_raw_with_options(
            &serde_json::json!({"tool_name": "Bash", "tool_input": {"command": command}})
                .to_string(),
            &["--agent", "claude-code"],
            &env,
        );
        assert_droid_denial(&stdout, &stderr, code);
    }
}

#[test]
fn test_droid_configured_fail_closed_retains_claude_compatible_denial() {
    let (stdout, stderr, code) = run_hook_mode_raw_with_options(
        "{ malformed Droid payload",
        &["--agent", "droid"],
        &[("DCG_FAIL_CLOSED", "1")],
    );
    assert_droid_denial(&stdout, &stderr, code);
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("invalid-config.toml");
    std::fs::write(&config_path, "[packs]\nenabled = 7\n").unwrap();
    let (stdout, stderr, code) = run_hook_mode_raw_with_options(
        &droid_payload("git status"),
        &["--agent", "droid"],
        &[("DCG_CONFIG", config_path.to_str().unwrap())],
    );
    assert_droid_denial(&stdout, &stderr, code);
}

#[test]
fn test_droid_unverified_commands_preserve_ask_and_deny_policy() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("command-limit.toml");
    std::fs::write(&config_path, "[general]\nmax_command_bytes = 5\n").unwrap();
    for decision in ["ask", "deny"] {
        let (stdout, stderr, code) = run_hook_mode_raw_with_options(
            &droid_payload("git status"),
            &["--agent", "droid"],
            &[
                ("DCG_CONFIG", config_path.to_str().unwrap()),
                ("DCG_UNVERIFIED_DECISION", decision),
            ],
        );
        assert_eq!(code, 0, "{stderr}");
        let output: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(output["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(output["hookSpecificOutput"]["permissionDecision"], decision);
    }
}

#[test]
fn test_droid_payload_history_is_attributed_to_droid() {
    let temp = tempfile::tempdir().unwrap();
    let database = temp.path().join("history.db");
    let (stdout, stderr, code) = run_hook_mode_raw_with_options(
        &droid_payload("git reset --hard"),
        &[],
        &[
            ("DCG_HISTORY_DISABLED", "0"),
            ("DCG_HISTORY_ENABLED", "1"),
            ("DCG_HISTORY_DB", database.to_str().unwrap()),
            ("CLAUDECODE", "1"),
        ],
    );
    assert_droid_denial(&stdout, &stderr, code);
    let connection = rusqlite::Connection::open(&database).unwrap();
    let agent: String = connection
        .query_row(
            "SELECT agent_type FROM commands ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(agent, "droid");
}

#[test]
fn test_droid_hook_never_self_heals_unrelated_claude_settings() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let claude_default = home.join(".claude/settings.json");
    let claude_override_dir = home.join("claude-active");
    let claude_override = claude_override_dir.join("settings.json");
    let stale = r#"{"operatorSetting":true,"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/stale/dcg"}]}]}}"#;
    for path in [&claude_default, &claude_override] {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, stale).unwrap();
    }
    let env = [
        ("HOME", home.to_str().unwrap()),
        ("USERPROFILE", home.to_str().unwrap()),
        ("CLAUDECODE", "1"),
        ("CLAUDE_CONFIG_DIR", claude_override_dir.to_str().unwrap()),
        ("DCG_SELF_HEAL_HOOK", "1"),
    ];
    for args in [&[][..], &["--agent", "droid"][..]] {
        let (stdout, stderr, code) =
            run_hook_mode_raw_with_options(&droid_payload("git status"), args, &env);
        assert_eq!(code, 0, "{stderr}");
        assert!(stdout.is_empty(), "{stdout}");
        for path in [&claude_default, &claude_override] {
            assert_eq!(
                std::fs::read_to_string(path).unwrap(),
                stale,
                "Droid changed unrelated {}",
                path.display()
            );
        }
    }
}

#[test]
fn test_droid_script_payload_does_not_claim_nested_execute_coverage() {
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Script",
        "tool_input": {"code": "await Execute({ command: 'git reset --hard HEAD' })"}
    });
    let (stdout, stderr, code) =
        run_hook_mode_raw_with_options(&payload.to_string(), &["--agent", "droid"], &[]);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stdout.is_empty(),
        "Script source is not a shell command: {stdout}"
    );
}

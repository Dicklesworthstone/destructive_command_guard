//! Repro for #358: a Reasonix payload dcg cannot parse must still block.
//!
//! Reasonix reads only the hook's exit status. A payload dcg cannot parse
//! (oversized, or not valid UTF-8) has no parsed envelope to detect the
//! protocol from, so dcg answered in the env/process-detected agent's
//! protocol. Reasonix sets no env marker, and process-ancestry detection is
//! Unix-only, so the agent is usually unknown there. The Claude-shaped
//! fallback then answered a proven destructive command with a JSON deny on
//! exit 0, and Reasonix ran the command. When no agent is identified, the
//! envelope markers still visible in the raw bytes now pick the protocol.
//! They never override an identified agent.

#![allow(clippy::doc_markdown)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Payload size safely past the default 256 KiB `max_hook_input_bytes`.
const PADDING_BYTES: usize = 300 * 1024;

fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

/// Run dcg in hook mode as `agent` with raw stdin bytes, an isolated
/// HOME/config, and a generous budget so the oversized scan always finishes.
fn run_hook(agent: &str, input: &[u8], home: &Path, fail_closed: bool) -> (String, String, i32) {
    let config_path = home.join("dcg-test-config.toml");
    fs::write(&config_path, "").expect("write empty config");
    let mut command = Command::new(dcg_binary());
    command
        .args(["--agent", agent])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("xdg_config"))
        .env("DCG_CONFIG", &config_path)
        .env(
            "DCG_PENDING_EXCEPTIONS_PATH",
            home.join("pending_exceptions.jsonl"),
        )
        .env("DCG_HOOK_TIMEOUT_MS", "30000");
    if fail_closed {
        command.env("DCG_FAIL_CLOSED", "1");
    } else {
        command.env_remove("DCG_FAIL_CLOSED");
    }
    let mut child = command.spawn().expect("spawn dcg");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(input)
        .expect("write stdin");
    let output = child.wait_with_output().expect("wait for dcg");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.code().unwrap_or(-1),
    )
}

/// Reasonix's native envelope, field order as Reasonix's Go encoder writes
/// it, padded past the size limit inside the command.
fn oversized_reasonix_payload() -> String {
    let command = format!("git reset --hard && {}", "A".repeat(PADDING_BYTES));
    serde_json::json!({
        "event": "PreToolUse",
        "sessionId": "s-1",
        "cwd": "/tmp",
        "toolName": "bash",
        "toolArgs": { "command": command }
    })
    .to_string()
}

#[test]
fn oversized_reasonix_payload_blocks_by_exit_status_when_the_agent_is_unknown() {
    for agent in ["unknown", "reasonix"] {
        let temp = tempfile::tempdir().expect("tempdir");
        let input = oversized_reasonix_payload();
        assert!(input.len() > 256 * 1024);

        let (stdout, stderr, code) = run_hook(agent, input.as_bytes(), temp.path(), false);

        assert_eq!(
            code, 2,
            "--agent {agent}: Reasonix blocks only on exit 2\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            stdout.trim().is_empty(),
            "--agent {agent}: stdout {stdout:?}"
        );
        assert!(
            stderr.contains("BLOCKED by dcg"),
            "--agent {agent}: {stderr}"
        );
    }
}

#[test]
fn envelope_markers_never_override_an_identified_agent() {
    // A Reasonix-shaped payload sent while dcg has identified Claude Code is
    // answered in Claude's protocol: planted markers must not be able to
    // switch a detected host's protocol.
    let temp = tempfile::tempdir().expect("tempdir");
    let input = oversized_reasonix_payload();
    let (stdout, stderr, code) = run_hook("claude-code", input.as_bytes(), temp.path(), false);
    assert_eq!(code, 0, "stderr: {stderr}");
    let json: serde_json::Value =
        serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("{e}: {stdout:?}"));
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn claude_shaped_oversized_payload_keeps_the_json_answer_when_the_agent_is_unknown() {
    let temp = tempfile::tempdir().expect("tempdir");
    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": format!("git reset --hard && {}", "A".repeat(PADDING_BYTES)) }
    })
    .to_string();
    let (stdout, stderr, code) = run_hook("unknown", input.as_bytes(), temp.path(), false);
    assert_eq!(code, 0, "stderr: {stderr}");
    let json: serde_json::Value =
        serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("{e}: {stdout:?}"));
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn fail_closed_non_utf8_reasonix_payload_blocks_by_exit_status() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut input = br#"{"event":"PreToolUse","sessionId":"s-1","cwd":"/tmp","toolName":"bash","toolArgs":{"command":"ls "#.to_vec();
    input.push(0xFF);
    input.extend_from_slice(br#""}}"#);

    let (stdout, stderr, code) = run_hook("unknown", &input, temp.path(), true);

    assert_eq!(code, 2, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.trim().is_empty(), "stdout: {stdout:?}");
    assert!(stderr.contains("BLOCKED by dcg"), "{stderr}");
}

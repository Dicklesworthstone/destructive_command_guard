//! Repro for issue #290: an oversized hook payload must not fail open blind.
//!
//! Padding a destructive command past `general.max_hook_input_bytes`
//! (default 256 KiB) used to skip every pack: the read error fell straight
//! into the fail-open branch with only a stderr warning. The fix evaluates
//! the truncated prefix that WAS read — the JSON prefix usually still
//! contains `tool_input.command` — and emits the normal protocol denial when
//! a destructive command (prefix) is found. Benign or unextractable payloads
//! keep the historic fail-open behavior; `fail_closed = true` still denies
//! unconditionally (#160).

#![allow(clippy::doc_markdown, clippy::uninlined_format_args)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Payload size safely past the default 256 KiB `max_hook_input_bytes`.
const PADDING_BYTES: usize = 300 * 1024;

/// Path to the DCG binary (uses same target directory as the test binary).
fn dcg_binary() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // Remove test binary name
    path.pop(); // Remove deps/
    path.push(format!("dcg{}", std::env::consts::EXE_SUFFIX));
    path
}

/// Run dcg in hook mode with raw stdin bytes and an isolated HOME/config
/// (default config: fail-open, default size limits).
fn run_hook_raw(input: &str, home: &Path) -> (String, String, i32) {
    let config_path = home.join("dcg-test-config.toml");
    fs::write(&config_path, "").expect("failed to write empty config");

    let mut child = Command::new(dcg_binary())
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
        .env_remove("DCG_FAIL_CLOSED")
        .spawn()
        .expect("failed to spawn dcg process");

    {
        let stdin = child.stdin.as_mut().expect("failed to get stdin");
        stdin
            .write_all(input.as_bytes())
            .expect("failed to write to stdin");
    }

    let output = child.wait_with_output().expect("failed to wait for dcg");

    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.code().unwrap_or(-1),
    )
}

/// The issue's repro shape: the padding lives INSIDE the command string,
/// after a destructive prefix.
fn padded_destructive_envelope() -> String {
    let command = format!("rm -rf ~/important && {}", "A".repeat(PADDING_BYTES));
    serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command }
    })
    .to_string()
}

/// Planted negative: the command is benign and complete; the padding lives in
/// a sibling JSON field AFTER the command.
fn padded_benign_envelope() -> String {
    serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {
            "command": "echo hello",
            "padding": "A".repeat(PADDING_BYTES)
        }
    })
    .to_string()
}

/// Issue #290 core repro: a destructive command padded past the input size
/// limit must be DENIED under the default (fail-open) config.
#[test]
fn issue_290_padded_destructive_command_is_denied() {
    let temp = tempfile::tempdir().expect("tempdir");
    let input = padded_destructive_envelope();
    assert!(input.len() > 256 * 1024, "envelope must exceed the limit");

    let (stdout, stderr, exit_code) = run_hook_raw(&input, temp.path());

    assert_eq!(exit_code, 0, "hook mode exits 0 on deny\nstderr: {stderr}");
    let json: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("expected deny JSON on stdout ({e}); stdout: {stdout:?}\nstderr: {stderr}")
    });
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"]
            .as_str()
            .unwrap_or_default(),
        "deny",
        "padded destructive command must deny, got: {stdout:?}"
    );
}

/// Planted negative: an oversized envelope whose truncated prefix contains
/// only a benign command keeps the historic fail-open behavior (allow with
/// the oversized-input warning).
#[test]
fn issue_290_padded_benign_command_still_fails_open() {
    let temp = tempfile::tempdir().expect("tempdir");
    let input = padded_benign_envelope();
    assert!(input.len() > 256 * 1024, "envelope must exceed the limit");

    let (stdout, stderr, exit_code) = run_hook_raw(&input, temp.path());

    assert_eq!(exit_code, 0, "fail-open allows\nstderr: {stderr}");
    assert!(
        stdout.trim().is_empty(),
        "fail-open must not emit a decision, got: {stdout:?}"
    );
    assert!(
        stderr.contains("exceeds limit"),
        "fail-open must keep the oversized-input warning, got: {stderr:?}"
    );
}

/// Normal-size destructive flow is unchanged by the truncated-prefix path.
#[test]
fn issue_290_normal_size_deny_unchanged() {
    let temp = tempfile::tempdir().expect("tempdir");
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"git reset --hard"}}"#;

    let (stdout, stderr, exit_code) = run_hook_raw(input, temp.path());

    assert_eq!(exit_code, 0, "hook mode exits 0 on deny\nstderr: {stderr}");
    let json: serde_json::Value = serde_json::from_str(stdout.trim()).expect("deny JSON on stdout");
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"]
            .as_str()
            .unwrap_or_default(),
        "deny"
    );
}

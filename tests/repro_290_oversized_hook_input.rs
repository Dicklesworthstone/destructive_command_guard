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

/// Duplicate `"command"` key: `serde_json` is last-wins, so a first-wins
/// scanner would judge the benign decoy and fail open.
fn duplicate_key_decoy_envelope() -> String {
    // Hand-built because serde_json::json! cannot emit a duplicate key.
    format!(
        r#"{{"tool_name":"Bash","tool_input":{{"command":"echo hello","command":"git reset --hard"}},"padding":"{}"}}"#,
        "A".repeat(PADDING_BYTES)
    )
}

/// Decoy `"command"` in an EARLIER unrelated object, ahead of the real one.
fn decoy_object_envelope() -> String {
    format!(
        r#"{{"context":{{"command":"echo hello"}},"tool_name":"Bash","tool_input":{{"command":"git reset --hard"}},"padding":"{}"}}"#,
        "A".repeat(PADDING_BYTES)
    )
}

/// Oversized NON-shell envelope: a `Write` tool call carrying a
/// command-shaped field. Not a shell request; must not be denied as one.
fn oversized_non_shell_envelope() -> String {
    serde_json::json!({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/tmp/notes.txt",
            "command": "git reset --hard",
            "content": "A".repeat(PADDING_BYTES)
        }
    })
    .to_string()
}

/// Pad-first evasion: megabytes of padding in a sibling key written BEFORE
/// `tool_input`, so the destructive command begins past the 256 KiB read cap
/// but stays inside the 4 MiB scan cap.
fn pad_before_tool_input_envelope() -> String {
    serde_json::json!({
        "padding": "A".repeat(2 * 1024 * 1024),
        "tool_name": "Bash",
        "tool_input": { "command": "git reset --hard" }
    })
    .to_string()
}

/// Pad-first evasion inside the command string itself: the destructive part
/// comes AFTER 2 MiB of in-command padding.
fn pad_inside_command_envelope() -> String {
    let command = format!("echo {} ; git reset --hard", "A".repeat(2 * 1024 * 1024));
    serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command }
    })
    .to_string()
}

/// Assert that an oversized payload produced the normal protocol denial.
fn assert_denied(label: &str, input: &str) {
    let temp = tempfile::tempdir().expect("tempdir");
    assert!(input.len() > 256 * 1024, "{label}: must exceed the limit");

    let (stdout, stderr, exit_code) = run_hook_raw(input, temp.path());

    assert_eq!(exit_code, 0, "{label}: hook mode exits 0\nstderr: {stderr}");
    let json: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("{label}: expected deny JSON ({e}); stdout: {stdout:?}\nstderr: {stderr}")
    });
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"]
            .as_str()
            .unwrap_or_default(),
        "deny",
        "{label}: must deny, got: {stdout:?}"
    );
}

/// A benign `"command"` decoy in front of the real one (duplicate key, which
/// serde_json resolves last-wins) must not defeat the #290 scanner.
#[test]
fn issue_290_duplicate_command_key_decoy_is_denied() {
    assert_denied("duplicate key", &duplicate_key_decoy_envelope());
}

/// Same, with the decoy in an earlier unrelated object.
#[test]
fn issue_290_earlier_decoy_object_is_denied() {
    assert_denied("decoy object", &decoy_object_envelope());
}

/// Pad-first evasion: the command begins beyond the read cap but within the
/// 4 MiB scan cap, in a sibling key written before `tool_input`.
#[test]
fn issue_290_padding_before_tool_input_is_denied() {
    assert_denied("pad before tool_input", &pad_before_tool_input_envelope());
}

/// Pad-first evasion inside the command string.
#[test]
fn issue_290_padding_inside_command_before_destructive_part_is_denied() {
    assert_denied("pad inside command", &pad_inside_command_envelope());
}

/// An oversized NON-shell envelope must keep fail-open behavior: dcg never
/// denies a payload it cannot attribute to a shell tool.
#[test]
fn issue_290_oversized_non_shell_envelope_is_not_denied() {
    let temp = tempfile::tempdir().expect("tempdir");
    let input = oversized_non_shell_envelope();
    assert!(input.len() > 256 * 1024, "envelope must exceed the limit");

    let (stdout, stderr, exit_code) = run_hook_raw(&input, temp.path());

    assert_eq!(exit_code, 0, "fail-open allows\nstderr: {stderr}");
    assert!(
        stdout.trim().is_empty(),
        "a non-shell tool envelope must not be denied, got: {stdout:?}"
    );
    assert!(
        stderr.contains("exceeds limit"),
        "fail-open must keep the oversized-input warning, got: {stderr:?}"
    );
}

/// An oversized envelope with NO tool name at all is equally unattributable.
#[test]
fn issue_290_oversized_envelope_without_tool_name_is_not_denied() {
    let temp = tempfile::tempdir().expect("tempdir");
    let input = serde_json::json!({
        "tool_input": {
            "command": format!("git reset --hard && {}", "A".repeat(PADDING_BYTES))
        }
    })
    .to_string();
    assert!(input.len() > 256 * 1024, "envelope must exceed the limit");

    let (stdout, _stderr, exit_code) = run_hook_raw(&input, temp.path());

    assert_eq!(exit_code, 0, "fail-open allows");
    assert!(
        stdout.trim().is_empty(),
        "an unattributable envelope must not be denied, got: {stdout:?}"
    );
}

/// Run dcg on a raw oversized payload with `windows.filesystem` enabled, so
/// the PowerShell/cmd rules participate (they are default-off on Unix).
fn run_hook_raw_windows(input: &str, home: &Path) -> (String, String, i32) {
    let config_path = home.join("dcg-test-config.toml");
    fs::write(&config_path, "").expect("failed to write empty config");

    let mut child = Command::new(dcg_binary())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("xdg_config"))
        .env("DCG_CONFIG", &config_path)
        .env("DCG_PACKS", "windows.filesystem")
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

/// #322 fresh-eyes follow-up: the oversized-input fail-closed path resolved
/// each scan window with an UNREFINED dialect, so padding a `Bash`-labeled
/// PowerShell payload past `max_command_bytes` slipped `Remove-Item -Recurse
/// -Force` through under Posix (a cmdlet is an inert unknown binary there).
/// The path now applies the same `refine_shell_dialect` widening per window.
#[test]
fn issue_322_oversized_mislabeled_powershell_is_denied() {
    let temp = tempfile::tempdir().expect("tempdir");
    // Padding INSIDE the command, after the destructive PowerShell part —
    // the exact evasion shape the #290 windows scan exists to catch.
    let command = format!(
        "Remove-Item -Recurse -Force C:\\src ; {}",
        "A".repeat(PADDING_BYTES)
    );
    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command }
    })
    .to_string();
    assert!(input.len() > 256 * 1024, "envelope must exceed the limit");

    let (stdout, stderr, exit_code) = run_hook_raw_windows(&input, temp.path());
    assert_eq!(exit_code, 0, "hook mode exits 0 on deny\nstderr: {stderr}");
    let json: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("expected deny JSON ({e}); stdout: {stdout:?}\nstderr: {stderr}")
    });
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"]
            .as_str()
            .unwrap_or_default(),
        "deny",
        "oversized mislabeled PowerShell payload must fail closed, got: {stdout:?}"
    );
}

/// #322 fresh-eyes follow-up (normal size): a `Bash`-labeled PowerShell
/// alias invocation (`rm -Recurse -Force`) is widened and denied by the
/// windows pack. Proves the alias-widening signal end-to-end, not just at
/// the dialect-refinement unit level.
#[test]
fn issue_322_mislabeled_powershell_alias_is_denied() {
    let temp = tempfile::tempdir().expect("tempdir");
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"rm -Recurse -Force C:\\src"}}"#;

    let (stdout, stderr, exit_code) = run_hook_raw_windows(input, temp.path());
    assert_eq!(exit_code, 0, "hook mode exits 0 on deny\nstderr: {stderr}");
    let json: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("expected deny JSON ({e}); stdout: {stdout:?}\nstderr: {stderr}")
    });
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"]
            .as_str()
            .unwrap_or_default(),
        "deny",
        "mislabeled PowerShell alias must fail closed, got: {stdout:?}"
    );
}

/// Guard against over-widening: a plain POSIX `rm -rf` in a temp dir stays
/// allowed even with the windows pack enabled — the alias signal requires a
/// Windows-shell-only argument, which `-rf` is not.
#[test]
fn issue_322_posix_rm_rf_temp_not_over_widened() {
    let temp = tempfile::tempdir().expect("tempdir");
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/scratch"}}"#;

    let (stdout, _stderr, exit_code) = run_hook_raw_windows(input, temp.path());
    assert_eq!(exit_code, 0, "hook mode exits 0");
    assert!(
        stdout.trim().is_empty(),
        "POSIX temp cleanup must stay allowed, got: {stdout:?}"
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

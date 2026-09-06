//! Regression tests for issue #389: a closed stdout/stderr pipe must never
//! turn into a signal death (SIGABRT + core dump under `panic = "abort"`),
//! and must never cost the hook its verdict.
//!
//! Every test hands the child a pipe whose read end is already closed before
//! `spawn`, so the very first write on that stream fails with `EPIPE`. That
//! is deterministic, unlike `| head -1`, which only races the writer.

use std::io::{self, Read, Write};
use std::process::{Command, ExitStatus, Stdio};

fn dcg_binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

/// A `dcg` invocation that cannot rewrite the caller's real agent settings.
fn dcg_command() -> Command {
    let mut command = Command::new(dcg_binary());
    command.env("DCG_SELF_HEAL_HOOK", "0");
    command.env("DCG_HOOK_TIMEOUT_MS", "5000");
    command.env("NO_COLOR", "1");
    command
}

/// A write end whose reader is already gone: every write fails with `EPIPE`.
fn closed_pipe() -> Stdio {
    let (reader, writer) = io::pipe().expect("os pipe");
    drop(reader);
    Stdio::from(writer)
}

fn assert_clean_exit(status: ExitStatus, context: &str) {
    assert!(
        status.code().is_some(),
        "{context}: dcg died from a signal ({status}); a closed pipe must be a clean exit"
    );
}

#[test]
fn version_survives_both_streams_closed() {
    let status = dcg_command()
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(closed_pipe())
        .stderr(closed_pipe())
        .status()
        .expect("spawn dcg --version");
    assert_clean_exit(status, "--version, both streams closed");
    assert_eq!(
        status.code(),
        Some(0),
        "--version writes are best-effort; a vanished reader is not an error"
    );
}

#[test]
fn version_survives_stdout_closed_and_prints_no_panic() {
    // The `dcg --version 2>&1 | head -1` idiom from the report, made
    // deterministic: stdout has no reader, stderr is captured so a panic
    // message would be visible here.
    let output = dcg_command()
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(closed_pipe())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn dcg --version");
    assert_clean_exit(output.status, "--version, stdout closed");
    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("panicked"),
        "no panic text may reach stderr: {stderr}"
    );
    assert!(
        stderr.contains("Destructive Command Guard"),
        "banner still goes to the open stderr: {stderr}"
    );
}

#[test]
fn help_survives_both_streams_closed() {
    let status = dcg_command()
        .arg("--help")
        .stdin(Stdio::null())
        .stdout(closed_pipe())
        .stderr(closed_pipe())
        .status()
        .expect("spawn dcg --help");
    assert_clean_exit(status, "--help, both streams closed");
    assert_eq!(status.code(), Some(0));
}

#[test]
fn cli_subcommand_with_closed_stdout_exits_with_broken_pipe_status() {
    // The CLI surface uses ordinary `println!`; the panic backstop turns the
    // resulting EPIPE panic into the documented status instead of SIGABRT.
    let output = dcg_command()
        .arg("packs")
        .stdin(Stdio::null())
        .stdout(closed_pipe())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn dcg packs");
    assert_clean_exit(output.status, "packs, stdout closed");
    assert_eq!(
        output.status.code(),
        Some(destructive_command_guard::exit_codes::EXIT_BROKEN_PIPE),
        "a vanished stdout reader must map to EXIT_BROKEN_PIPE"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("panicked"),
        "the backstop must claim the panic before the default hook prints it: {stderr}"
    );
}

#[test]
fn hook_deny_verdict_is_delivered_when_only_stderr_is_closed() {
    // The security-relevant case: the host is still reading the verdict on
    // stdout but stderr has no reader. The stderr diagnostic (here: a config
    // file that fails to parse, emitted before evaluation) must not take the
    // process down before the deny JSON is written.
    let dir = tempfile::tempdir().expect("tempdir");
    let bad_config = dir.path().join("dcg.toml");
    std::fs::write(&bad_config, "this is = not [valid toml\n").expect("write config");

    let mut child = dcg_command()
        .env("DCG_CONFIG", &bad_config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(closed_pipe())
        .spawn()
        .expect("spawn dcg hook");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(br#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#)
        .expect("write payload");
    let mut stdout = String::new();
    child
        .stdout
        .take()
        .expect("stdout")
        .read_to_string(&mut stdout)
        .expect("read verdict");
    let status = child.wait().expect("wait");

    assert_clean_exit(status, "hook deny, stderr closed");
    assert_eq!(
        status.code(),
        Some(0),
        "hook protocol: exit 0 + JSON verdict"
    );
    assert!(
        stdout.contains(r#""permissionDecision":"deny""#),
        "deny verdict must still reach the host: {stdout}"
    );
}

#[test]
fn hook_survives_both_streams_closed() {
    for payload in [
        r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#,
        r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#,
    ] {
        let mut child = dcg_command()
            .stdin(Stdio::piped())
            .stdout(closed_pipe())
            .stderr(closed_pipe())
            .spawn()
            .expect("spawn dcg hook");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(payload.as_bytes())
            .expect("write payload");
        let status = child.wait().expect("wait");
        assert_clean_exit(status, payload);
        assert_eq!(
            status.code(),
            Some(0),
            "the hook path never panics on a vanished reader: {payload}"
        );
    }
}

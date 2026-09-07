//! Regression tests for issue #389: a closed stdout/stderr pipe must never
//! turn into a signal death (SIGABRT + core dump under `panic = "abort"`),
//! and must never cost the hook its verdict.
//!
//! Every test hands the child a pipe whose read end is already closed before
//! `spawn`, so the very first write on that stream fails with `EPIPE`. That
//! is deterministic, unlike `| head -1`, which only races the writer.
//!
//! The second half covers the fail-closed channel: a blocking verdict whose
//! stdout write fails must leave through the protocol's blocking exit status
//! (`EXIT_HOOK_BLOCK`), because exit 0 with nothing on stdout is "proceed" on
//! every host. An undeliverable allow or warning stays exit 0.

use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};

use destructive_command_guard::exit_codes::{EXIT_HOOK_BLOCK, EXIT_SUCCESS};

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

/// A hermetic hook invocation: its own HOME, no user or system allowlists,
/// only the core packs, and `config` as the whole configuration.
fn isolated_hook_command(dir: &Path, config: &str) -> Command {
    let home = dir.join("home");
    fs::create_dir_all(&home).expect("home dir");
    let config_path = dir.join("dcg.toml");
    fs::write(&config_path, config).expect("write config");
    let mut command = dcg_command();
    command
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", dir.join("xdg"))
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_CONFIG", &config_path)
        .env("DCG_PACKS", "core.git,core.filesystem");
    command
}

/// A write end whose reader is already gone: every write fails with `EPIPE`.
fn closed_pipe() -> Stdio {
    let (reader, writer) = io::pipe().expect("os pipe");
    drop(reader);
    Stdio::from(writer)
}

/// Run one hook request with stdout already closed and stderr captured.
fn run_hook_with_closed_stdout(command: &mut Command, payload: &str) -> (ExitStatus, String) {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(closed_pipe())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcg hook");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(payload.as_bytes())
        .expect("write payload");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    let status = child.wait().expect("wait");
    (status, stderr)
}

/// The stderr line `blocking_verdict_exit_code` emits when it fails closed.
const UNDELIVERABLE_MARKER: &str = "the verdict could not be written to stdout";

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
    // With no reader on either stream the only signal left is the exit
    // status: a deny fails closed through it, an allow stays 0.
    for (payload, expected) in [
        (
            r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#,
            EXIT_HOOK_BLOCK,
        ),
        (
            r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#,
            EXIT_SUCCESS,
        ),
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
            Some(expected),
            "the hook path never panics on a vanished reader: {payload}"
        );
    }
}

#[test]
fn hook_deny_with_closed_stdout_exits_with_the_blocking_status() {
    // The reviewer's design finding on #389: with stdout gone the deny JSON
    // cannot be delivered, and exit 0 is "proceed" to every host. Exit 2 is
    // the blocking status for Claude Code and Crush (and Gemini, Copilot,
    // Grok); for Codex it is a logged hook failure, which is no worse than
    // the silent allow exit 0 would have been.
    for (protocol, payload) in [
        (
            "claude",
            r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#,
        ),
        (
            "crush",
            r#"{"event":"PreToolUse","session_id":"313909e","cwd":"/","tool_name":"bash","tool_input":{"command":"rm -rf /"}}"#,
        ),
        (
            "codex",
            r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"},"turn_id":"turn-1"}"#,
        ),
    ] {
        let (status, stderr) = run_hook_with_closed_stdout(&mut dcg_command(), payload);
        assert_clean_exit(status, protocol);
        assert_eq!(
            status.code(),
            Some(EXIT_HOOK_BLOCK),
            "{protocol}: an undeliverable deny must fail closed through the exit status\n{stderr}"
        );
        assert!(
            stderr.contains(UNDELIVERABLE_MARKER),
            "{protocol}: the fail-closed exit is explained on stderr, which Claude Code feeds back to the model: {stderr}"
        );
        assert!(
            !stderr.contains("panicked"),
            "{protocol}: no panic text may reach stderr: {stderr}"
        );
    }
}

#[test]
fn hook_allow_with_closed_stdout_exits_zero() {
    // An allow writes nothing to stdout, so there is nothing to lose: the
    // host's fail-open reading of exit 0 is the right verdict.
    let (status, stderr) = run_hook_with_closed_stdout(
        &mut dcg_command(),
        r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#,
    );
    assert_clean_exit(status, "allow, stdout closed");
    assert_eq!(status.code(), Some(EXIT_SUCCESS), "{stderr}");
    assert!(!stderr.contains(UNDELIVERABLE_MARKER), "{stderr}");
}

#[test]
fn hook_warning_with_closed_stdout_exits_zero() {
    // A warn-mode match lets the command proceed by design, so an
    // undeliverable warning is as harmless as an undeliverable allow.
    let dir = tempfile::tempdir().expect("tempdir");
    let mut command = isolated_hook_command(
        dir.path(),
        "[policy.rules]\n\"core.git:stash-drop\" = \"warn\"\n",
    );
    let payload = r#"{"tool_name":"Bash","tool_input":{"command":"git stash drop"}}"#;

    // Sanity: with a reader on stdout this configuration really is a warning,
    // not an allow, so the closed-stdout run below exercises the warn path.
    let mut probe = isolated_hook_command(
        dir.path(),
        "[policy.rules]\n\"core.git:stash-drop\" = \"warn\"\n",
    );
    let mut child = probe
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn probe");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(payload.as_bytes())
        .expect("write payload");
    let probe_output = child.wait_with_output().expect("probe output");
    let probe_stderr = String::from_utf8_lossy(&probe_output.stderr);
    assert!(
        probe_stderr.contains("dcg WARNING:"),
        "probe must produce a warning: stdout={} stderr={probe_stderr}",
        String::from_utf8_lossy(&probe_output.stdout)
    );
    assert_eq!(probe_output.status.code(), Some(EXIT_SUCCESS));

    let (status, stderr) = run_hook_with_closed_stdout(&mut command, payload);
    assert_clean_exit(status, "warn, stdout closed");
    assert!(
        stderr.contains("dcg WARNING:"),
        "the warning still goes to the open stderr: {stderr}"
    );
    assert_eq!(
        status.code(),
        Some(EXIT_SUCCESS),
        "an undeliverable warning is not a block: {stderr}"
    );
    assert!(!stderr.contains(UNDELIVERABLE_MARKER), "{stderr}");
}

#[test]
fn hook_review_request_with_closed_stdout_exits_with_the_blocking_status() {
    // `ask` means "not without a human". With the request undeliverable the
    // human never sees it, so the conservative answer is the block status.
    let dir = tempfile::tempdir().expect("tempdir");
    let mut command = isolated_hook_command(
        dir.path(),
        "[policy.rules]\n\"core.git:stash-drop\" = \"ask\"\n",
    );
    let (status, stderr) = run_hook_with_closed_stdout(
        &mut command,
        r#"{"tool_name":"Bash","tool_input":{"command":"git stash drop"}}"#,
    );
    assert_clean_exit(status, "ask, stdout closed");
    assert_eq!(
        status.code(),
        Some(EXIT_HOOK_BLOCK),
        "an undeliverable review request fails closed: {stderr}"
    );
    assert!(stderr.contains(UNDELIVERABLE_MARKER), "{stderr}");
}

#[test]
fn hook_deny_with_open_stdout_keeps_exit_zero() {
    // The protocol contract is unchanged when the verdict is delivered:
    // JSON on stdout and exit 0, never the blocking status.
    let mut child = dcg_command()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcg hook");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(br#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#)
        .expect("write payload");
    let output = child.wait_with_output().expect("output");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(EXIT_SUCCESS), "{stderr}");
    assert!(
        stdout.contains(r#""permissionDecision":"deny""#),
        "{stdout}"
    );
    assert!(!stderr.contains(UNDELIVERABLE_MARKER), "{stderr}");
}

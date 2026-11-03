//! bd-ym0p: a command too large to evaluate whose heredoc is run as code must
//! not be allowed blind.
//!
//! A hook input past `general.max_hook_input_bytes` (256 KiB) is scanned in
//! windows of `max_command_bytes`. A window cuts a heredoc body away from the
//! program that runs it, so `python3 - <<'EOF'` with 5,000 lines and an
//! `exec(x)` call was allowed by 0.15.3 and 0.16.0. The same command under the
//! input limit but over `max_command_bytes` already got the size-limit
//! indeterminate, so the larger input received the more lenient answer.
//!
//! A shell or interpreter receiving the heredoc now gets that same
//! indeterminate. Data receivers and padding outside any heredoc keep the
//! documented fail-open default (`repro_290_oversized_hook_input.rs` pins the
//! padded-envelope and padded-`echo` cases).

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

/// About 320 KB of body: 5,000 lines of 64 bytes, as in the bead's probes.
fn body(call: &str) -> String {
    use std::fmt::Write as _;
    let mut text = String::new();
    for index in 0..5_000 {
        let _ = writeln!(
            text,
            "value_{index:05} = 1  # padding padding padding padding pa"
        );
    }
    text.push_str(call);
    text.push('\n');
    text
}

fn envelope(command: &str) -> String {
    serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command }
    })
    .to_string()
}

fn run_hook(input: &str, home: &Path) -> (String, String, i32) {
    let config_path = home.join("dcg-test-config.toml");
    fs::write(&config_path, "").expect("empty config");
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcg"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("CLAUDE_CONFIG_DIR")
        .env("XDG_CONFIG_HOME", home.join("xdg_config"))
        .env("DCG_CONFIG", &config_path)
        .env(
            "DCG_PENDING_EXCEPTIONS_PATH",
            home.join("pending_exceptions.jsonl"),
        )
        .env_remove("DCG_FAIL_CLOSED")
        .env_remove("DCG_HOOK_TIMEOUT_MS")
        .spawn()
        .expect("spawn dcg");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write payload");
    let output = child.wait_with_output().expect("dcg output");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code().unwrap_or(-1),
    )
}

#[test]
fn oversized_heredoc_run_as_code_is_not_allowed_blind() {
    const SIZE_LIMIT: &str = "exceeds limit";
    for (receiver, call, verdict) in [
        ("python3 -", "exec(x)", SIZE_LIMIT),
        // Every window is evaluated as shell, and the one holding the call
        // reads `eval(x);`, which the POSIX eval rule denies. A window's deny
        // outranks the size-limit answer.
        ("node -", "eval(x);", "heredoc.posix:eval-dynamic"),
        ("ruby -", "eval x", SIZE_LIMIT),
        ("bash", "echo done", SIZE_LIMIT),
    ] {
        let command = format!("{receiver} <<'EOF'\n{}EOF", body(call));
        let input = envelope(&command);
        assert!(
            input.len() > 256 * 1024,
            "{receiver}: input must be oversized"
        );
        let temp = tempfile::tempdir().expect("tempdir");
        let (stdout, stderr, exit_code) = run_hook(&input, temp.path());
        assert_eq!(exit_code, 0, "{receiver}: hook exits 0\nstderr: {stderr}");
        assert!(
            !stdout.trim().is_empty(),
            "{receiver}: an oversized heredoc run as code must get a verdict, \
             not the silent allow\nstderr: {stderr}"
        );
        assert!(
            stdout.contains(verdict),
            "{receiver}: expected a verdict naming {verdict:?}: {stdout}"
        );
    }
}

/// The interpreter heredoc is not the first on the line, or padding precedes
/// it: the backstop checked only the first `<<` and only the first window, so
/// these failed open. Every `<<` across the whole command is now examined
/// (bd-oversized-code-heredoc-receivers-azu4).
#[test]
fn oversized_code_heredoc_behind_an_earlier_heredoc_or_padding_is_not_allowed_blind() {
    let interpreter = format!("python3 - <<'EOF'\n{}EOF", body("exec(x)"));
    for prefix in [
        // An earlier *data* heredoc whose own `<<` resolves first.
        "cat <<'A'\nnotes\nA\n".to_string(),
        // Padding past one scan window (64 KiB) before the heredoc.
        format!("# {}\n", "p".repeat(70 * 1024)),
    ] {
        let command = format!("{prefix}{interpreter}");
        let input = envelope(&command);
        assert!(input.len() > 256 * 1024, "input must be oversized");
        let temp = tempfile::tempdir().expect("tempdir");
        let (stdout, stderr, exit_code) = run_hook(&input, temp.path());
        assert_eq!(exit_code, 0, "hook exits 0\nstderr: {stderr}");
        assert!(
            stdout.contains("exceeds limit"),
            "an interpreter heredoc behind {prefix:.20?} must not fail open: {stdout}"
        );
    }
}

#[test]
fn oversized_data_heredoc_keeps_the_fail_open_default() {
    let command = format!("cat > notes.txt <<'EOF'\n{}EOF", body("done = 1"));
    let input = envelope(&command);
    assert!(input.len() > 256 * 1024);
    let temp = tempfile::tempdir().expect("tempdir");
    let (stdout, stderr, exit_code) = run_hook(&input, temp.path());
    assert_eq!(exit_code, 0, "stderr: {stderr}");
    assert!(
        stdout.trim().is_empty(),
        "a data heredoc keeps failing open, got: {stdout:?}"
    );
    assert!(
        stderr.contains("exceeds limit"),
        "the oversized-input warning stays: {stderr:?}"
    );
}

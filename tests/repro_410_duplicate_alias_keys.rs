//! Regression tests for issue #410: a hook envelope that spells the same field
//! in both snake_case and camelCase.
//!
//! Serde maps an alias onto the same struct field, so a payload carrying BOTH
//! spellings aborted the whole `HookInput` parse with `duplicate field` — and an
//! aborted parse fails open. Two shipping hosts do exactly that on every tool
//! call (Grok Build 1.0.30 on Windows, ZCode desktop 3.11.2), so under either
//! one dcg allowed every command, however destructive, with no output at all.
//!
//! The contract these tests pin:
//! - an **equal** alias pair reconciles and the command is evaluated normally;
//! - a **conflicting** alias pair does not silently discard the losing spelling:
//!   every distinct command is evaluated and a deny on any of them answers;
//! - a non-shell tool name in every spelling stays out of scope;
//! - input with no reconcilable alias collision is still a parse error;
//! - the default fail-open path is no longer silent — it names the reason on
//!   stderr, which the README's bounded-failure table already promised.

use std::io::Write;
use std::process::{Command, Stdio};

fn dcg_binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

/// Run dcg in bare hook mode against a hermetic HOME so no ambient user config,
/// allowlist, or agent settings file can influence the verdict.
fn run_hook(payload: &str, extra_env: &[(&str, &str)]) -> std::process::Output {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = temp.path().join("home");
    let xdg = temp.path().join("xdg");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&xdg).unwrap();

    let mut cmd = Command::new(dcg_binary());
    cmd.env_clear()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .env("DCG_PACKS", "core.git,core.filesystem")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in extra_env {
        cmd.env(key, value);
    }
    let mut child = cmd.spawn().expect("spawn dcg");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(payload.as_bytes())
        .expect("write payload");
    child.wait_with_output().expect("wait for dcg")
}

fn denied(output: &std::process::Output) -> bool {
    String::from_utf8_lossy(&output.stdout).contains("\"permissionDecision\":\"deny\"")
}

/// The reported ZCode desktop shape: standard snake_case fields plus identical
/// camelCase aliases alongside them.
const ZCODE_DUPLICATE_PAIRS: &str = r#"{"session_id":"s1","tool_name":"Bash","tool_input":{"command":"rm -rf ~/file_not_exist"},"sessionId":"s1","toolName":"Bash","toolInput":{"command":"rm -rf ~/file_not_exist"}}"#;

/// The reported Grok Build shape: every documented field spelled twice.
const GROK_DUPLICATE_PAIRS: &str = r#"{"hookEventName":"pre_tool_use","hook_event_name":"pre_tool_use","sessionId":"s","session_id":"s","transcriptPath":"t","transcript_path":"t","permissionMode":"default","permission_mode":"default","toolName":"run_terminal_command","tool_name":"run_terminal_command","toolInput":{"command":"rm -rf ~/file_not_exist"},"tool_input":{"command":"rm -rf ~/file_not_exist"},"toolUseId":"u","tool_use_id":"u"}"#;

#[test]
fn zcode_duplicate_alias_pairs_are_denied_not_allowed() {
    let out = run_hook(ZCODE_DUPLICATE_PAIRS, &[]);
    assert!(
        denied(&out),
        "duplicate alias pairs must be evaluated and denied, not fail-open allowed.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn grok_duplicate_alias_pairs_answer_in_grok_wire_shape() {
    let out = run_hook(GROK_DUPLICATE_PAIRS, &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"decision\":\"deny\""),
        "Grok's envelope must be denied in Grok's own wire shape.\nstdout: {stdout}"
    );
}

#[test]
fn grok_duplicate_alias_pairs_still_allow_a_benign_command() {
    // The fix must not turn every Grok command into a denial — the reported
    // fail-closed workaround did exactly that.
    let payload = GROK_DUPLICATE_PAIRS.replace("rm -rf ~/file_not_exist", "echo hello");
    let out = run_hook(&payload, &[]);
    assert!(out.status.success(), "benign command must exit 0");
    assert!(
        String::from_utf8_lossy(&out.stdout).trim().is_empty(),
        "benign command must be a silent allow"
    );
}

#[test]
fn single_spelling_envelopes_are_unchanged() {
    for payload in [
        r#"{"session_id":"s1","tool_name":"Bash","tool_input":{"command":"rm -rf ~/file_not_exist"}}"#,
        r#"{"sessionId":"s1","toolName":"Bash","toolInput":{"command":"rm -rf ~/file_not_exist"}}"#,
    ] {
        assert!(
            denied(&run_hook(payload, &[])),
            "single-spelling payload must still be denied: {payload}"
        );
    }
}

#[test]
fn conflicting_alias_values_deny_on_either_spelling() {
    // Whichever spelling carries the destructive command, the payload is denied:
    // the losing spelling is evaluated as an additional entry rather than
    // discarded.
    let benign_canonical = r#"{"tool_name":"Bash","toolName":"Bash","tool_input":{"command":"echo hello"},"toolInput":{"command":"rm -rf ~/file_not_exist"}}"#;
    let destructive_canonical = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf ~/file_not_exist"},"toolInput":{"command":"echo hello"}}"#;
    for payload in [benign_canonical, destructive_canonical] {
        assert!(
            denied(&run_hook(payload, &[])),
            "a destructive spelling in either position must deny: {payload}"
        );
    }
}

#[test]
fn conflicting_tool_name_does_not_suppress_evaluation() {
    // A non-shell canonical `tool_name` alongside a shell camelCase spelling
    // must not take the payload out of scope.
    let payload = r#"{"tool_name":"Read","toolName":"Bash","tool_input":{"command":"rm -rf ~/file_not_exist"}}"#;
    assert!(
        denied(&run_hook(payload, &[])),
        "the shell spelling must win a conflicting tool name"
    );
}

#[test]
fn non_shell_tool_in_every_spelling_stays_out_of_scope() {
    let payload = r#"{"tool_name":"Read","toolName":"Read","tool_input":{"command":"rm -rf ~/a"},"toolInput":{"command":"rm -rf ~/b"}}"#;
    let out = run_hook(payload, &[]);
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stdout).trim().is_empty(),
        "a non-shell tool must stay a silent allow"
    );
}

#[test]
fn batch_mode_reconciles_duplicate_alias_pairs() {
    // `dcg hook --batch` reported `decision":"error"` with a duplicate-field
    // message, which made every Grok command unusable for operators who gate on
    // the batch exit code.
    let temp = tempfile::tempdir().expect("temp dir");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let mut child = Command::new(dcg_binary())
        .arg("hook")
        .arg("--batch")
        .env_clear()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("DCG_PACKS", "core.git,core.filesystem")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcg hook --batch");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(ZCODE_DUPLICATE_PAIRS.as_bytes())
        .expect("write payload");
    let out = child.wait_with_output().expect("wait");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"decision\":\"deny\""),
        "batch mode must deny rather than report a parse error.\nstdout: {stdout}"
    );
    assert!(
        !stdout.contains("duplicate field"),
        "batch mode must not report a duplicate-field parse error.\nstdout: {stdout}"
    );
}

#[test]
fn genuinely_malformed_input_keeps_fail_open_default_but_says_so() {
    // Posture is unchanged: unparseable input is still allowed by default. What
    // changes is that it is no longer silent, so an operator can tell dcg is
    // not protecting them.
    let out = run_hook(
        r#"{"session_id":"s1","tool_name":"Bash","tool_input":}"#,
        &[],
    );
    assert!(out.status.success(), "default posture is fail-open");
    assert!(
        String::from_utf8_lossy(&out.stdout).trim().is_empty(),
        "fail-open means no denial document"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("could not parse hook input"),
        "a fail-open parse failure must name itself on stderr.\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("DCG_FAIL_CLOSED"),
        "the warning must point at the setting that blocks instead.\nstderr: {stderr}"
    );
}

#[test]
fn malformed_input_still_blocks_under_fail_closed() {
    let out = run_hook(
        r#"{"session_id":"s1","tool_name":"Bash","tool_input":}"#,
        &[("DCG_FAIL_CLOSED", "1")],
    );
    assert!(
        denied(&out),
        "DCG_FAIL_CLOSED must still block genuinely unparseable input.\nstdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

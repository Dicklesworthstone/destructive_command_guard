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
use std::process::{Command, Output, Stdio};

/// Payload size safely past the default 256 KiB `max_hook_input_bytes`.
const PADDING_BYTES: usize = 300 * 1024;

/// Path to the exact DCG binary Cargo built for this integration test.
fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

/// Run dcg in hook mode with raw stdin bytes and an isolated HOME/config
/// (default config: fail-open, default size limits).
fn run_hook_raw(input: &str, home: &Path) -> (String, String, i32) {
    run_hook_raw_with_budget(input, home, None)
}

/// As [`run_hook_raw`], with an explicit hook budget in milliseconds.
///
/// A budget of 1ms is guaranteed to be exhausted before the multi-megabyte
/// window scan finishes, which is what lets the #475 regression test assert the
/// exhaustion answer deterministically instead of waiting for a loaded host to
/// produce it. `None` keeps the shipped default.
fn run_hook_raw_with_budget(
    input: &str,
    home: &Path,
    budget_ms: Option<u64>,
) -> (String, String, i32) {
    let config_path = home.join("dcg-test-config.toml");
    fs::write(&config_path, "").expect("failed to write empty config");

    let mut command = Command::new(dcg_binary());
    command
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
        .env_remove("DCG_FAIL_CLOSED");
    match budget_ms {
        Some(ms) => {
            command.env("DCG_HOOK_TIMEOUT_MS", ms.to_string());
        }
        None => {
            command.env_remove("DCG_HOOK_TIMEOUT_MS");
        }
    }
    let mut child = command.spawn().expect("failed to spawn dcg process");

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

/// Budget these tests pin so the salvage scan can finish.
///
/// The deny they assert requires the multi-megabyte window scan to COMPLETE;
/// an exhausted budget is a different, also-correct answer (`ask`), and which
/// one you get otherwise depends on how loaded the host is. Measured on a busy
/// build machine, the 2 MiB scan exceeds the shipped 1000ms budget and these
/// tests then see `ask`, which is what `issue_475_…` asserts on purpose.
///
/// Pinning it here is the same discipline that test uses in the other
/// direction, and it is why the two can both hold on any machine. It is
/// deliberately NOT a perf claim: `scripts/perf_baseline.py` owns the budget
/// gate, and it scrubs `DCG_*` precisely so a test-local value like this one
/// can never reach it.
const SALVAGE_SCAN_BUDGET_MS: u64 = 30_000;

/// Assert that an oversized payload produced the normal protocol denial.
fn assert_denied(label: &str, input: &str) {
    let temp = tempfile::tempdir().expect("tempdir");
    assert!(input.len() > 256 * 1024, "{label}: must exceed the limit");

    let (stdout, stderr, exit_code) =
        run_hook_raw_with_budget(input, temp.path(), Some(SALVAGE_SCAN_BUDGET_MS));

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

/// An exhausted budget must not turn an oversized payload into a silent allow
/// (#475).
///
/// The window scan used to `break` into the fail-open branch, so "the deadline
/// ran out" and "nothing destructive is here" produced the same answer: allow.
/// That is what made the test above flaky rather than wrong — it was green only
/// while the host was fast enough to finish the multi-megabyte scan inside the
/// budget, and on a loaded machine dcg printed
/// `allowing command (fail-open)` for the very payload that test exists to
/// deny.
///
/// The budget is forced here rather than inferred from ambient load, so this
/// asserts the property on an idle machine too. Measured before the fix:
/// ALLOW with empty stdout, 12/12.
///
/// The control is the point. The same command *without* the padding answers the
/// same exhausted budget with ask-or-deny and never allow, so the oversized
/// path was the outlier, not the deadline.
#[test]
fn issue_475_exhausted_budget_on_an_oversized_payload_is_indeterminate_not_allow() {
    let temp = tempfile::tempdir().expect("tempdir");
    let input = pad_inside_command_envelope();
    assert!(input.len() > 256 * 1024, "envelope must exceed the limit");

    let (stdout, stderr, exit_code) = run_hook_raw_with_budget(&input, temp.path(), Some(1));

    assert_eq!(exit_code, 0, "hook mode exits 0\nstderr: {stderr}");
    assert!(
        !stdout.trim().is_empty(),
        "an exhausted budget left windows unscanned, so this must publish a \
         decision rather than exit silently (a silent exit IS the allow); \
         stderr: {stderr:?}"
    );
    let json: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("expected a decision JSON ({e}); stdout: {stdout:?}"));
    let decision = json["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or_default();
    assert_ne!(
        decision, "allow",
        "exhaustion is indeterminate, never a silent allow; got {stdout:?}"
    );
    assert_eq!(
        decision, "ask",
        "the normal-size path answers an exhausted budget with ask; the \
         oversized path must answer the same way. Got {stdout:?}"
    );

    // Control: identical command, no padding, identical budget. This one is
    // allowed to be either ask or deny depending on how far it gets, but it
    // must never allow -- that is the invariant the padded case was breaking.
    let control_home = tempfile::tempdir().expect("tempdir");
    let control = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": "git reset --hard" }
    })
    .to_string();
    let (control_stdout, control_stderr, control_exit) =
        run_hook_raw_with_budget(&control, control_home.path(), Some(1));
    assert_eq!(control_exit, 0, "control exits 0\nstderr: {control_stderr}");
    let control_json: serde_json::Value = serde_json::from_str(control_stdout.trim())
        .unwrap_or_else(|e| panic!("control expected decision JSON ({e}); got {control_stdout:?}"));
    let control_decision = control_json["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or_default();
    assert!(
        matches!(control_decision, "ask" | "deny"),
        "the unpadded control must answer ask or deny under the same budget, \
         never allow; got {control_stdout:?}"
    );
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
    run_hook_raw_windows_with_budget(input, home, None)
}

/// As [`run_hook_raw_windows`], with an explicit hook budget in milliseconds
/// (`None` keeps the shipped default).
fn run_hook_raw_windows_with_budget(
    input: &str,
    home: &Path,
    budget_ms: Option<u64>,
) -> (String, String, i32) {
    let config_path = home.join("dcg-test-config.toml");
    fs::write(&config_path, "").expect("failed to write empty config");

    let mut command = Command::new(dcg_binary());
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("CLAUDE_CONFIG_DIR")
        .env("XDG_CONFIG_HOME", home.join("xdg_config"))
        .env("DCG_CONFIG", &config_path)
        .env("DCG_PACKS", "windows.filesystem")
        .env(
            "DCG_PENDING_EXCEPTIONS_PATH",
            home.join("pending_exceptions.jsonl"),
        )
        .env_remove("DCG_FAIL_CLOSED");
    match budget_ms {
        Some(ms) => {
            command.env("DCG_HOOK_TIMEOUT_MS", ms.to_string());
        }
        None => {
            command.env_remove("DCG_HOOK_TIMEOUT_MS");
        }
    }
    let mut child = command.spawn().expect("failed to spawn dcg process");

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

/// #569: the Windows filesystem pass reports a command past its statement
/// bound as an incomplete analysis (Indeterminate) rather than an
/// `Unverified` deny. This window scan used to publish only Deny/Ask and its
/// own deadline check, so a window's Indeterminate fell into the fail-open
/// branch: a spelling the pack's regexes cannot see (a cmd caret) behind more
/// statements than the bound would have been ALLOWED once padded past the
/// input limit. The budget is generous so the answer comes from the analysis
/// bound, not from the clock; `echo rm` only gets the window past the keyword
/// quick reject.
#[test]
fn issue_569_incomplete_window_analysis_on_an_oversized_payload_is_not_allowed() {
    let temp = tempfile::tempdir().expect("tempdir");
    let command = format!(
        "echo rm & r^d /s /q C:\\src & {}{}",
        "echo a & ".repeat(140),
        "A".repeat(PADDING_BYTES)
    );
    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command }
    })
    .to_string();
    assert!(input.len() > 256 * 1024, "envelope must exceed the limit");

    let (stdout, stderr, exit_code) =
        run_hook_raw_windows_with_budget(&input, temp.path(), Some(5000));
    assert_eq!(exit_code, 0, "hook mode exits 0\nstderr: {stderr}");
    let json: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("expected a blocking JSON verdict ({e}); stdout: {stdout:?}\nstderr: {stderr}")
    });
    let decision = json["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or_default();
    assert!(
        matches!(decision, "deny" | "ask"),
        "an incompletely analyzed window must not fail open, got: {stdout:?}"
    );
}

/// The window scan used to skip every window that named no enabled-pack
/// keyword. The evaluator reaches commands no keyword spells through checks of
/// its own (a variable or a glob in the program name, a cmd `%G%`, PowerShell
/// `& $g`), so each of these was denied at normal size and allowed once padded
/// past the input limit.
#[test]
fn oversized_windows_reach_commands_no_keyword_spells() {
    let pad = "A".repeat(PADDING_BYTES);
    let claude = |tool: &str, command: String| {
        serde_json::json!({ "tool_name": tool, "tool_input": { "command": command } }).to_string()
    };
    let gemini = |command: String| {
        serde_json::json!({
            "session_id": "oversized",
            "hook_event_name": "BeforeTool",
            "tool_name": "run_shell_command",
            "tool_input": { "command": command },
        })
        .to_string()
    };
    let deny: &[&str] = &["deny"];
    let cases = [
        (
            "Bash $G",
            claude("Bash", format!("$G reset --hard; echo {pad}")),
            deny,
        ),
        (
            "Bash glob",
            claude("Bash", format!("g?t reset --hard; echo {pad}")),
            deny,
        ),
        (
            "Bash $@ inside rm",
            claude("Bash", format!("r$@m -rf /; echo {pad}")),
            deny,
        ),
        (
            "cmd %G%",
            claude("cmd", format!("%G% reset --hard & echo {pad}")),
            deny,
        ),
        (
            "Gemini $G",
            gemini(format!("$G reset --hard ; echo {pad}")),
            deny,
        ),
        // A PowerShell rule stops at its regex work limit on the 64 KiB
        // window, which answers ask; either answer blocks.
        (
            "PowerShell & $g",
            claude("PowerShell", format!("& $g reset --hard ; echo {pad}")),
            &["deny", "ask"],
        ),
    ];
    for (label, input, accepted) in cases {
        assert!(input.len() > 256 * 1024, "{label}: must exceed the limit");
        let temp = tempfile::tempdir().expect("tempdir");
        let (stdout, stderr, exit_code) =
            run_hook_raw_with_budget(&input, temp.path(), Some(SALVAGE_SCAN_BUDGET_MS));
        assert_eq!(exit_code, 0, "{label}: hook mode exits 0\nstderr: {stderr}");
        let json: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
            panic!(
                "{label}: expected a blocking verdict ({e}); stdout: {stdout:?}\nstderr: {stderr}"
            )
        });
        // Claude Code answers in `hookSpecificOutput`; Gemini CLI in `decision`.
        let decision = json["hookSpecificOutput"]["permissionDecision"]
            .as_str()
            .or_else(|| json["decision"].as_str())
            .unwrap_or_default();
        assert!(
            accepted.contains(&decision),
            "{label}: expected one of {accepted:?}, got {stdout:?}"
        );
    }
}

/// An oversized Windows-shell payload must get the `windows.*` packs, which
/// are off by default on a non-Windows host. The oversized path computed its
/// enabled packs without the payload signal, so a padded `format C: /q` or
/// `Remove-Item -Recurse -Force C:\` was allowed while the same command under
/// the limit denied (bd-oversized-windows-packs-t2jo).
#[test]
fn oversized_windows_payloads_enable_the_windows_packs() {
    let pad = "A".repeat(PADDING_BYTES);
    let envelope = |tool: &str, command: String| {
        serde_json::json!({ "tool_name": tool, "tool_input": { "command": command } }).to_string()
    };
    for (tool, command) in [
        ("cmd", format!("format C: /q /y & echo {pad}")),
        ("cmd", format!("echo {pad} & rd /s /q C:\\")),
        (
            "PowerShell",
            format!("Write-Output '{pad}' ; Remove-Item -Recurse -Force C:\\"),
        ),
    ] {
        assert_denied(tool, &envelope(tool, command));
    }
    // A benign oversized Windows payload still fails open.
    let temp = tempfile::tempdir().expect("tempdir");
    let benign = envelope("cmd", format!("echo {pad}"));
    let (stdout, stderr, exit_code) =
        run_hook_raw_with_budget(&benign, temp.path(), Some(SALVAGE_SCAN_BUDGET_MS));
    assert_eq!(exit_code, 0, "benign: exits 0\nstderr: {stderr}");
    assert!(
        stdout.trim().is_empty(),
        "a benign oversized Windows payload keeps failing open, got: {stdout:?}"
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

// Native Antigravity recovery must work before a HookInput exists, including
// when the host sets its real marker and when only the stdin shape identifies
// it. Every command below is fixture data sent to dcg, never executed.
#[derive(Clone, Copy, Debug)]
enum NativeRecoveryAgent {
    NoMarker,
    Environment,
    Forced(&'static str),
}

fn run_native_recovery(
    input: &[u8],
    home: &Path,
    agent: NativeRecoveryAgent,
    fail_closed: bool,
) -> Output {
    let config =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/e2e/fixtures/configs/minimal.toml");
    let mut command = Command::new(dcg_binary());
    command.env_clear();
    // Preserve executable/platform lookup only; no caller agent markers,
    // allowlists, size limits, or fail-closed overrides enter these cases.
    for key in ["PATH", "SystemRoot", "WINDIR"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command
        .current_dir(home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("APPDATA", home.join("AppData/Roaming"))
        .env("LOCALAPPDATA", home.join("AppData/Local"))
        .env("ProgramData", home)
        .env("TMPDIR", home)
        .env("TEMP", home)
        .env("TMP", home)
        .env("DCG_CONFIG", config)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_ALLOW_ONCE_PATH", home.join("allow-once.jsonl"))
        .env("DCG_PENDING_EXCEPTIONS_PATH", home.join("pending.jsonl"))
        .env("DCG_HISTORY_DISABLED", "1")
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("DCG_HOOK_TIMEOUT_MS", "30000")
        .env("NO_COLOR", "1");
    match agent {
        NativeRecoveryAgent::NoMarker => {}
        NativeRecoveryAgent::Environment => {
            command.env("ANTIGRAVITY_CONVERSATION_ID", "native-recovery-test");
        }
        NativeRecoveryAgent::Forced(name) => {
            command
                .env("ANTIGRAVITY_CONVERSATION_ID", "native-recovery-test")
                .args(["--agent", name]);
        }
    }
    if fail_closed {
        command.env("DCG_FAIL_CLOSED", "1");
    }
    let mut child = command.spawn().expect("spawn native recovery hook");
    child
        .stdin
        .take()
        .expect("hook stdin")
        .write_all(input)
        .expect("write native fixture bytes");
    child.wait_with_output().expect("wait for native recovery")
}

fn native_recovery_payload(command: &str) -> String {
    serde_json::json!({
        "toolCall": {
            "name": "run_command",
            "args": {"CommandLine": command, "Cwd": "/repo", "WaitMsBeforeAsync": 500}
        },
        "conversationId": "native-recovery-test",
        "stepIdx": 1
    })
    .to_string()
}

fn malformed_native_payloads(payload: &str) -> Vec<(&'static str, Vec<u8>)> {
    let mut non_utf8 = payload.as_bytes().to_vec();
    non_utf8.push(0xff);
    vec![
        (
            "json truncation",
            payload.as_bytes()[..payload.len() - 1].to_vec(),
        ),
        (
            "malformed suffix",
            format!("{payload} trailing").into_bytes(),
        ),
        ("invalid UTF-8", non_utf8),
    ]
}

fn assert_native_recovery_denial(output: &Output, context: &str) -> String {
    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct NativeDenial {
        decision: String,
        reason: String,
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{context}: {stderr}");
    let root: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|err| panic!("{context}: invalid denial ({err}): {output:?}"));
    assert!(
        root.is_object(),
        "{context}: expected JSON object, got {root}"
    );
    // Deserialize the original bytes so duplicate keys cannot be hidden by
    // Value's last-wins map; String rejects structured enum lookalikes.
    let denial: NativeDenial = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|err| panic!("{context}: native protocol rejected denial ({err}): {root}"));
    assert_eq!(denial.decision, "deny", "{context}: {root}");
    assert!(!denial.reason.trim().is_empty(), "{context}: {root}");
    denial.reason
}

fn assert_native_recovery_fail_open(output: &Output, context: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{context}: {stderr}");
    assert!(output.stdout.is_empty(), "{context}: {output:?}");
    assert!(stderr.contains("fail-open"), "{context}: {stderr}");
}

#[test]
fn antigravity_recovery_oversized_native_commands_are_denied() {
    for agent in [
        NativeRecoveryAgent::NoMarker,
        NativeRecoveryAgent::Environment,
    ] {
        for command in [
            format!("git reset --hard\n# {}", "x".repeat(PADDING_BYTES)),
            format!("# {}\ngit reset --hard", "x".repeat(PADDING_BYTES)),
        ] {
            let temp = tempfile::tempdir().expect("tempdir");
            let input = native_recovery_payload(&command);
            assert!(input.len() > 256 * 1024);
            let output = run_native_recovery(input.as_bytes(), temp.path(), agent, false);
            let reason = assert_native_recovery_denial(&output, &format!("oversized {agent:?}"));
            assert!(reason.contains("core.git:reset-hard"), "{reason}");
        }
    }
}

#[test]
fn antigravity_recovery_malformed_native_commands_are_denied() {
    let mut payloads = malformed_native_payloads(&native_recovery_payload("git reset --hard"));
    payloads.push((
        "truncated command string",
        br#"{"toolCall":{"name":"run_command","args":{"CommandLine":"git reset --hard"#.to_vec(),
    ));
    payloads.push((
        "complete command containing a surrogate pair",
        br#"{"toolCall":{"name":"run_command","args":{"CommandLine":"echo \ud83e\uddea\ngit reset --hard"}}} trailing"#
            .to_vec(),
    ));
    payloads.push((
        "truncated command containing a surrogate pair",
        br#"{"toolCall":{"name":"run_command","args":{"CommandLine":"echo \ud83e\uddea\ngit reset --hard"#
            .to_vec(),
    ));
    for agent in [
        NativeRecoveryAgent::NoMarker,
        NativeRecoveryAgent::Environment,
    ] {
        for (kind, input) in &payloads {
            let temp = tempfile::tempdir().expect("tempdir");
            let output = run_native_recovery(input, temp.path(), agent, false);
            let reason = assert_native_recovery_denial(&output, &format!("{kind} {agent:?}"));
            assert!(reason.contains("core.git:reset-hard"), "{kind}: {reason}");
        }
    }
}

#[test]
fn antigravity_recovery_nameless_and_escaped_native_commands_are_denied() {
    for input in [
        r#"{"tool_call":{"args":{"CommandLine":"git reset --hard"}}} trailing"#,
        r#"{"tool\u0043all":{"na\u006de":"run_command","ar\u0067s":{"Command\u004cine":"git reset --hard"}}} trailing"#,
        r#"{"toolCall":{"name":"run_command","args":"{\"CommandLine\":\"git reset --hard"#,
    ] {
        let temp = tempfile::tempdir().expect("tempdir");
        let output = run_native_recovery(
            input.as_bytes(),
            temp.path(),
            NativeRecoveryAgent::NoMarker,
            false,
        );
        let reason = assert_native_recovery_denial(&output, input);
        assert!(reason.contains("core.git:reset-hard"), "{reason}");
    }
}

#[test]
fn antigravity_recovery_safe_commands_keep_default_fail_open() {
    let mut payloads = malformed_native_payloads(&native_recovery_payload("echo harmless"));
    payloads.push((
        "oversized safe command",
        native_recovery_payload(&format!("echo harmless\n# {}", "x".repeat(PADDING_BYTES)))
            .into_bytes(),
    ));
    for agent in [
        NativeRecoveryAgent::NoMarker,
        NativeRecoveryAgent::Environment,
    ] {
        for (kind, input) in &payloads {
            let temp = tempfile::tempdir().expect("tempdir");
            let output = run_native_recovery(input, temp.path(), agent, false);
            assert_native_recovery_fail_open(&output, &format!("{kind} {agent:?}"));
        }
    }
}

#[test]
fn antigravity_recovery_non_shell_and_planted_metadata_stay_inert() {
    let oversized_non_shell = serde_json::json!({
        "toolCall": {
            "name": "readFile",
            "args": {"CommandLine": format!("git reset --hard {}", "x".repeat(PADDING_BYTES))}
        }
    })
    .to_string();
    for agent in [
        NativeRecoveryAgent::NoMarker,
        NativeRecoveryAgent::Environment,
    ] {
        for input in [
            oversized_non_shell.as_str(),
            r#"{"metadata":{"toolCall":{"name":"run_command","args":{"CommandLine":"git reset --hard"}}}} trailing"#,
            r#"{"toolCall":{"name":"readFile","args":{"CommandLine":"git reset --hard"},"metadata":{"name":"run_command"}}} trailing"#,
            r#"{"metadata":{"command":"git reset --hard"},"toolCall":{"name":"run_command","args":{"metadata":{"CommandLine":"git reset --hard"},"CommandLine":"echo harmless"}}} trailing"#,
            r#"{"metadata":"\"toolCall\":{\"name\":\"run_command\",\"args\":{\"CommandLine\":\"git reset --hard\"}}"} trailing"#,
        ] {
            let temp = tempfile::tempdir().expect("tempdir");
            let output = run_native_recovery(input.as_bytes(), temp.path(), agent, false);
            assert_native_recovery_fail_open(&output, &format!("inert metadata {agent:?}"));
        }
    }
}

#[test]
fn antigravity_recovery_fail_closed_uses_the_native_protocol() {
    let mut payloads = malformed_native_payloads(&native_recovery_payload("echo harmless"));
    payloads.push((
        "oversized safe command",
        native_recovery_payload(&format!("echo harmless {}", "x".repeat(PADDING_BYTES)))
            .into_bytes(),
    ));
    for agent in [
        NativeRecoveryAgent::NoMarker,
        NativeRecoveryAgent::Environment,
        NativeRecoveryAgent::Forced("agy"),
    ] {
        for (kind, input) in &payloads {
            let temp = tempfile::tempdir().expect("tempdir");
            let output = run_native_recovery(input, temp.path(), agent, true);
            let reason = assert_native_recovery_denial(&output, &format!("{kind} {agent:?}"));
            assert!(reason.contains("DCG_FAIL_CLOSED"), "{kind}: {reason}");
        }
    }
}

#[test]
fn antigravity_recovery_preserves_explicit_agent_precedence() {
    let mut input = native_recovery_payload("git reset --hard").into_bytes();
    input.push(0xff);
    for fail_closed in [false, true] {
        for agent in ["codex", "reasonix"] {
            let temp = tempfile::tempdir().expect("tempdir");
            let output = run_native_recovery(
                &input,
                temp.path(),
                NativeRecoveryAgent::Forced(agent),
                fail_closed,
            );
            if agent == "reasonix" {
                assert_eq!(output.status.code(), Some(2), "{output:?}");
                assert!(output.stdout.is_empty(), "{output:?}");
                assert!(!output.stderr.is_empty(), "{output:?}");
            } else {
                assert_eq!(output.status.code(), Some(0), "{output:?}");
                let json: serde_json::Value =
                    serde_json::from_slice(&output.stdout).expect("Codex JSON denial");
                assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
                assert!(json.get("decision").is_none(), "{json}");
            }
        }
    }
}

#[test]
fn antigravity_recovery_preserves_real_shell_batch_precedence() {
    let input = r#"{"toolCall":{"name":"run_command","args":{"CommandLine":"git reset --hard"}},"toolcalls":[{"name":"bash","args":{"command":"echo harmless"}}]} trailing"#;
    let temp = tempfile::tempdir().expect("tempdir");
    let output = run_native_recovery(
        input.as_bytes(),
        temp.path(),
        NativeRecoveryAgent::NoMarker,
        false,
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("Claude-compatible batch denial");
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(json.get("decision").is_none(), "{json}");
}

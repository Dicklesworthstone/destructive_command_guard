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

/// About 270 KB of body: 5,000 padding lines, as in the bead's probes.
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
    run_hook_with_config(input, home, "", "claude-code")
}

fn run_hook_with_config(
    input: &str,
    home: &Path,
    config: &str,
    agent: &str,
) -> (String, String, i32) {
    run_hook_with_config_and_env(input, home, config, agent, &[])
}

fn run_hook_with_config_and_env(
    input: &str,
    home: &Path,
    config: &str,
    agent: &str,
    extra_env: &[(&str, &str)],
) -> (String, String, i32) {
    let config_path = home.join("dcg-test-config.toml");
    fs::write(
        &config_path,
        format!("{config}\n[history]\nenabled = false\n"),
    )
    .expect("isolated config");
    let mut command = Command::new(env!("CARGO_BIN_EXE_dcg"));
    command
        // Keep parent-process detection from changing the expected protocol.
        .args(["--agent", agent])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join("xdg_config"))
        .env("XDG_DATA_HOME", home.join("xdg_data"))
        .env("XDG_STATE_HOME", home.join("xdg_state"))
        .env("XDG_CACHE_HOME", home.join("xdg_cache"))
        .env("APPDATA", home.join("appdata"))
        .env("LOCALAPPDATA", home.join("localappdata"))
        .env("TMPDIR", home)
        .env("TEMP", home)
        .env("TMP", home)
        .env("DCG_CONFIG", &config_path)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_ALLOW_ONCE_PATH", home.join("allow-once.jsonl"))
        .env(
            "DCG_PENDING_EXCEPTIONS_PATH",
            home.join("pending_exceptions.jsonl"),
        )
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("DCG_NO_UPDATE_CHECK", "1")
        // These assert semantics and rule ownership, not latency. As in the
        // heredoc regression suite (bd-e1xl), extraction has its own budget
        // independent of the AST and whole-hook budgets. Production deadlines
        // and the dedicated deadline tests remain unchanged.
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .env("DCG_AST_TIMEOUT_MS", "5000")
        .env("DCG_HEREDOC_TIMEOUT_MS", "5000")
        .env("NO_COLOR", "1")
        .env("TERM", "dumb")
        .current_dir(home);
    for (name, value) in extra_env {
        command.env(name, value);
    }
    let mut child = command.spawn().expect("spawn dcg");
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
        // A flag-only wrapper was already recognized by the old backstop.
        ("env -i python3 -", "exec(x)", SIZE_LIMIT),
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

fn assert_size_limit_verdict(
    label: &str,
    command: &str,
    config: &str,
    codex: bool,
    expected_decision: &str,
) {
    let mut payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
    });
    if codex {
        payload["turn_id"] = serde_json::json!("oversized-heredoc-turn");
    }
    let input = payload.to_string();
    assert!(input.len() > 256 * 1024, "{label}: input must be oversized");
    let home = tempfile::tempdir().expect("isolated hook home");
    let agent = if codex { "codex" } else { "claude-code" };
    let (stdout, stderr, exit_code) = run_hook_with_config(&input, home.path(), config, agent);
    assert_eq!(exit_code, 0, "{label}: hook must exit 0\n{stderr}");
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("{label}: {error}: stdout={stdout:?}; stderr={stderr:?}"));
    let specific = json["hookSpecificOutput"].as_object().expect("hook output");
    assert_eq!(specific["hookEventName"], "PreToolUse", "{label}: {json}");
    assert_eq!(
        specific["permissionDecision"], expected_decision,
        "{label}: {json}"
    );
    let reason = specific["permissionDecisionReason"]
        .as_str()
        .expect("reason");
    assert!(reason.contains("exceeds limit"), "{label}: {json}");
    assert!(
        reason.contains("DCG did not evaluate it"),
        "{label}: {json}"
    );
    // An unread receiver is not a concrete language finding or an exception
    // grant. In particular, this route must not invent a Perl unlink rule.
    for field in ["ruleId", "packId", "severity", "allowOnceCode"] {
        assert!(!specific.contains_key(field), "{label}: {json}");
    }
    assert!(!reason.contains("heredoc.perl"), "{label}: {json}");
    assert!(!stderr.contains("fail-open"), "{label}: {stderr}");
    if codex {
        assert_eq!(json.as_object().expect("JSON object").len(), 1, "{json}");
        assert_eq!(
            specific.len(),
            3,
            "Codex needs its minimal envelope: {json}"
        );
    }
}

#[test]
fn oversized_indirect_or_unknown_heredocs_are_unverified_azu4() {
    let source = body("exec(x)");
    for (label, header, tail) in [
        ("pipe", "cat <<'EOF' | python3 -", "EOF"),
        ("env option value", "env -u UNUSED python3 - <<'EOF'", "EOF"),
        (
            "sudo option value",
            "sudo -u nobody python3 - <<'EOF'",
            "EOF",
        ),
        ("file descriptor", "exec 3<<'EOF'", "EOF\npython3 /dev/fd/3"),
        (
            "compound keyword",
            "if true; then python3 - <<'EOF'",
            "EOF\nfi",
        ),
        ("unknown receiver", "mystery-reader <<'EOF'", "EOF"),
    ] {
        let command = format!("{header}\n{source}{tail}");
        assert_size_limit_verdict(label, &command, "", false, "ask");
    }
}

#[test]
fn oversized_unverified_heredocs_obey_policy_and_protocol_azu4() {
    let source = body("exec(x)");
    for header in [
        "python3 - <<'EOF'",
        "cat <<'EOF' | python3 -",
        "mystery-reader <<'EOF'",
    ] {
        let command = format!("{header}\n{source}EOF");
        for (config, claude_decision) in [
            ("", "ask"),
            ("[general]\nunverified_decision = \"deny\"\n", "deny"),
        ] {
            assert_size_limit_verdict(header, &command, config, false, claude_decision);
            // Codex has no native ask response; both postures must block
            // with its existing minimal deny envelope.
            assert_size_limit_verdict(header, &command, config, true, "deny");
        }
    }
}

#[test]
fn oversized_quoted_data_controls_keep_the_fail_open_default_azu4() {
    let data = format!("cat > notes.txt <<'EOF'\n{}EOF", body("done = 1"));
    for (label, command) in [
        ("safe tail", format!("{data}\necho done")),
        ("quoted operator", format!("echo '<<UNUSED'; {data}")),
        ("arithmetic operator", format!("echo $((1<<2)); {data}")),
        (
            "operator inside data",
            format!("cat > notes.txt <<'EOF'\n{}EOF", body("document <<TEXT")),
        ),
    ] {
        let input = envelope(&command);
        assert!(input.len() > 256 * 1024, "{label}: input must be oversized");
        let home = tempfile::tempdir().expect("isolated hook home");
        let (stdout, stderr, exit_code) = run_hook(&input, home.path());
        assert_eq!(exit_code, 0, "{label}: {stderr}");
        assert!(stdout.trim().is_empty(), "{label}: {stdout:?}\n{stderr}");
        assert!(stderr.contains("exceeds limit"), "{label}: {stderr}");
    }
}

#[test]
fn oversized_heredoc_compound_tails_keep_concrete_denials_azu4() {
    let source = body("done = 1");
    for receiver in ["cat > notes.txt", "mystery-reader"] {
        for (tail, rule) in [
            ("unlink /etc/passwd", "core.filesystem:unlink-root-home"),
            (
                "perl -e \"unlink '/etc/passwd'\"",
                "heredoc.perl:unlink.catastrophic",
            ),
        ] {
            let command = format!("{receiver} <<'EOF'\n{source}EOF\n{tail}");
            let input = envelope(&command);
            assert!(input.len() > 256 * 1024);
            let home = tempfile::tempdir().expect("isolated hook home");
            let (stdout, stderr, exit_code) = run_hook(&input, home.path());
            assert_eq!(exit_code, 0, "{receiver}, {tail}: {stderr}");
            let json: serde_json::Value = serde_json::from_str(&stdout)
                .unwrap_or_else(|error| panic!("{error}: stdout={stdout:?}; stderr={stderr:?}"));
            let specific = &json["hookSpecificOutput"];
            assert_eq!(specific["permissionDecision"], "deny", "{json}");
            assert_eq!(specific["ruleId"], rule, "{receiver}, {tail}: {json}");
        }
    }
}

#[test]
fn oversized_unverified_heredoc_outranks_an_earlier_ask_azu4() {
    let config = "[general]\nunverified_decision = \"deny\"\n\
                  [policy.rules]\n\"core.filesystem:rm-rf-general\" = \"ask\"\n";
    for receiver in ["python3 -", "mystery-reader"] {
        // Keep the Ask finding and the heredoc header in different windows.
        // Otherwise a single-window policy replay can obscure the ordering
        // bug by finding incomplete heredoc analysis before returning Ask.
        let command = format!(
            "rm -rf build\n# {}\n{receiver} <<'EOF'\n{}EOF",
            "p".repeat(70 * 1024),
            body("done = 1")
        );
        assert_size_limit_verdict(receiver, &command, config, false, "deny");
    }
}

fn assert_concrete_rule_verdict(command: &str, config: &str, decision: &str, rule: &str) {
    let input = envelope(command);
    assert!(input.len() > 256 * 1024, "input must be oversized");
    let home = tempfile::tempdir().expect("isolated hook home");
    let (stdout, stderr, exit_code) =
        run_hook_with_config(&input, home.path(), config, "claude-code");
    assert_eq!(exit_code, 0, "hook exits 0\n{stderr}");
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("{error}: stdout={stdout:?}; stderr={stderr:?}"));
    let specific = &json["hookSpecificOutput"];
    assert_eq!(specific["permissionDecision"], decision, "{json}");
    assert_eq!(specific["ruleId"], rule, "{json}");
}

#[test]
fn oversized_later_concrete_denial_outranks_an_earlier_ask_azu4() {
    let command = format!(
        "rm -rf build\n# {}\necho done\nunlink /etc/passwd",
        "p".repeat(270 * 1024)
    );
    assert_concrete_rule_verdict(
        &command,
        "[policy.rules]\n\"core.filesystem:rm-rf-general\" = \"ask\"\n",
        "deny",
        "core.filesystem:unlink-root-home",
    );
}

#[test]
fn oversized_plain_padding_preserves_an_earlier_ask_azu4() {
    let command = format!("rm -rf build\n# {}\necho done", "p".repeat(270 * 1024));
    assert_concrete_rule_verdict(
        &command,
        "[general]\nunverified_decision = \"deny\"\n\
         [policy.rules]\n\"core.filesystem:rm-rf-general\" = \"ask\"\n",
        "ask",
        "core.filesystem:rm-rf-general",
    );
}

#[test]
fn oversized_exported_data_receiver_is_unverified_azu4() {
    for (receiver, unverified) in [("cat", true), ("/usr/bin/cat", false)] {
        let command = format!("{receiver} > notes.txt <<'EOF'\n{}EOF", body("done = 1"));
        let input = envelope(&command);
        assert!(input.len() > 256 * 1024);
        let home = tempfile::tempdir().expect("isolated hook home");
        // Only the guard child sees this exported function. No shell is
        // launched and the test process's environment is not mutated.
        let (stdout, stderr, exit_code) = run_hook_with_config_and_env(
            &input,
            home.path(),
            "[general]\nunverified_decision = \"deny\"\n",
            "claude-code",
            &[("BASH_FUNC_cat%%", "() { python3 -; }")],
        );
        assert_eq!(exit_code, 0, "{receiver}: hook exits 0\n{stderr}");
        if !unverified {
            // The trusted explicit path bypasses shell name rebinding.
            assert!(stdout.trim().is_empty(), "{receiver}: {stdout:?}\n{stderr}");
            assert!(stderr.contains("exceeds limit"), "{receiver}: {stderr}");
            continue;
        }
        let json: serde_json::Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|error| panic!("{error}: stdout={stdout:?}; stderr={stderr:?}"));
        let specific = json["hookSpecificOutput"].as_object().expect("hook output");
        assert_eq!(specific["permissionDecision"], "deny", "{json}");
        assert!(
            specific["permissionDecisionReason"]
                .as_str()
                .expect("reason")
                .contains("exceeds limit"),
            "{json}"
        );
        assert!(!specific.contains_key("ruleId"), "{json}");
        assert!(!stderr.contains("fail-open"), "{stderr}");
    }
}

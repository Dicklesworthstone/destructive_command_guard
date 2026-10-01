//! #510: an inline-shell launcher quoted as prose inside a non-shell command's
//! argument was evaluated as if it ran.
//!
//! ```text
//! mytracker comment 1 "example: bash -c 'git reset --hard' is refused"
//! ```
//!
//! was denied as `core.git:reset-hard`, while the same argument without the
//! `bash -c` wrapper (`mytracker comment 1 "the rule refuses git reset
//! --hard"`) was allowed. The inline-script patterns match a launcher anywhere
//! in the text. The quoted word runs nothing under either reading: as data
//! (dcg's model for an unknown program's operands), or as a shell string some
//! program hands to `sh -c`, whose command word is `example:` and not `bash`.
//!
//! Every case goes through the real Claude Code `PreToolUse` hook. The second
//! half pins the live forms that must stay denied: a launcher in command
//! position, behind a wrapper, inside a substitution (which runs whatever its
//! quoting), opening a quoted string another program may run, or after a
//! separator inside one.

use std::io::Write;
use std::process::{Command, Stdio};

/// `(decision, rule id)` from the real hook for one Bash command.
fn hook(command: &str) -> (String, String) {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })
    .to_string();
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcg"))
        .env_clear()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcg");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(payload.as_bytes())
        .expect("write payload");
    let out = child.wait_with_output().expect("wait");
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if stdout.is_empty() {
        assert!(out.status.success(), "silent non-zero exit for {command:?}");
        return ("allow".to_string(), String::new());
    }
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("bad hook output for {command:?} ({e}): {stdout}"));
    let output = &parsed["hookSpecificOutput"];
    (
        output["permissionDecision"]
            .as_str()
            .unwrap_or("<missing>")
            .to_string(),
        output["ruleId"].as_str().unwrap_or_default().to_string(),
    )
}

#[test]
fn launcher_quoted_as_prose_in_a_data_argument_is_allowed() {
    for command in [
        // The reported shapes.
        "mytracker comment 1 \"example: bash -c 'git reset --hard' is refused\"",
        "br create \"test bash -c 'git reset --hard' doc\"",
        // The other quote style around the prose, and around the payload.
        "mytracker comment 1 'example: bash -c \"git reset --hard\" is refused'",
        // Other launchers and payloads.
        "mytracker comment 1 \"example: sh -c 'rm -rf /' is refused\"",
        "mytracker note \"run: /bin/bash -c 'git clean -fdx' to wipe\"",
        "mytracker note \"repro: python3 -c 'import shutil; shutil.rmtree(\\\"/\\\")' fails\"",
        // Several data arguments, the launcher in a later one.
        "mytracker comment 7 --title \"x\" --body \"the hook blocks bash -c 'git reset --hard'\"",
    ] {
        assert_eq!(hook(command).0, "allow", "{command}");
    }
}

#[test]
fn the_plain_data_control_is_unchanged() {
    for command in [
        "mytracker comment 1 \"the rule refuses git reset --hard\"",
        "mytracker comment 1 \"example: python3 -c 'import os' runs code\"",
    ] {
        assert_eq!(hook(command).0, "allow", "{command}");
    }
    assert_eq!(
        hook("git reset --hard"),
        ("deny".to_string(), "core.git:reset-hard".to_string())
    );
}

#[test]
fn live_launchers_stay_denied() {
    for command in [
        // Command position, plain and after a separator.
        "bash -c 'git reset --hard'",
        "x; bash -c 'git reset --hard'",
        "true && sh -c 'git reset --hard'",
        // Behind wrappers.
        "sudo bash -c 'git reset --hard'",
        "env FOO=1 bash -c 'git reset --hard'",
        "nice bash -c 'git reset --hard'",
        "timeout 5 bash -c 'git reset --hard'",
        "xargs bash -c 'git reset --hard'",
        "docker exec c bash -c 'git reset --hard'",
        // The interpreter word itself quoted is still the command word.
        "\"bash\" -c 'git reset --hard'",
        "'/bin/bash' -c 'git reset --hard'",
        // Substitutions run whatever their quoting.
        "echo $(bash -c 'git reset --hard')",
        "echo `bash -c 'git reset --hard'`",
        "mytracker comment 1 \"x $(bash -c 'git reset --hard')\"",
        "mytracker comment 1 \"x `bash -c 'git reset --hard'`\"",
        // Strings another program runs as shell code.
        "eval \"bash -c 'git reset --hard'\"",
        "ssh host \"bash -c 'git reset --hard'\"",
        "watch \"bash -c 'git reset --hard'\"",
        // A quoted string that OPENS with the launcher, follows a separator
        // or a wrapper inside the quotes: a program that runs its operand as a
        // shell string would run the launcher, so it is kept.
        "tmux new-session \"bash -c 'git reset --hard'\"",
        "mytracker \"bash -c 'git reset --hard'\"",
        "mytracker \"x; bash -c 'git reset --hard'\"",
        "mytracker \"sudo bash -c 'git reset --hard'\"",
        "mytracker \"FOO=1 bash -c 'git reset --hard'\"",
        // A double-quoted commit message's substitution is live.
        "git commit -m \"msg $(git reset --hard)\"",
    ] {
        let (decision, _) = hook(command);
        assert_eq!(decision, "deny", "{command}");
    }
}

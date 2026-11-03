//! bd-builtin-wrapper-bypass-pbxa: `builtin NAME …` runs the shell builtin
//! NAME, and when NAME is `command`, `exec` or `builtin` the words after it
//! execute. The wrapper normalizer stripped `command` but not `builtin`, so
//! `builtin command git reset --hard` was an unknown program named `builtin`:
//! allowed in the POSIX dialect, which is the dialect of Claude Code's `Bash`
//! tool. `builtin command mkfs.ext4 /dev/sda1` was allowed in every dialect,
//! though 0.15.3 denied it.
//!
//! These run the real hook binary with a Claude `Bash` payload, because that
//! is where the bypass was observed, and pin the plain rule each spelling
//! must reach.

use std::io::Write;
use std::process::{Command, Stdio};

fn hook_verdict(command: &str) -> (String, String) {
    let home = tempfile::tempdir().expect("temp home");
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcg"))
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", "/usr/bin:/bin")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("XDG_CONFIG_HOME", home.path().join("xdg"))
        .current_dir(home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcg hook");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(payload.to_string().as_bytes())
        .expect("write payload");
    let output = child.wait_with_output().expect("hook output");
    assert!(
        output.status.success(),
        "hook must exit 0 for {command:?}: {output:?}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if stdout.trim().is_empty() {
        return ("allow".to_string(), String::new());
    }
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("hook JSON");
    let output = &json["hookSpecificOutput"];
    let decision = output["permissionDecision"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let reason = output["permissionDecisionReason"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    (decision, reason)
}

#[test]
fn builtin_does_not_hide_the_command_it_runs() {
    for (command, rule) in [
        ("builtin command git reset --hard", "core.git:reset-hard"),
        ("builtin -- command git reset --hard", "core.git:reset-hard"),
        ("builtin command -p git reset --hard", "core.git:reset-hard"),
        (
            "command builtin command git reset --hard",
            "core.git:reset-hard",
        ),
        (
            "builtin builtin command git reset --hard",
            "core.git:reset-hard",
        ),
        ("builtin exec git reset --hard", "core.git:reset-hard"),
        ("builtin command mkfs.ext4 /dev/sda1", "system.disk:mkfs"),
        (
            "builtin command rm -rf ~/x",
            "core.filesystem:rm-rf-root-home",
        ),
    ] {
        let (decision, reason) = hook_verdict(command);
        assert_eq!(decision, "deny", "{command:?} must deny: {reason}");
        assert!(
            reason.contains(rule),
            "{command:?} must deny as {rule}: {reason}"
        );
    }
}

/// The sibling sweep after the `builtin` fix: zsh's precommand modifiers
/// (`noglob`, `nocorrect`, `-`) and macOS's command launchers (`arch`,
/// `xcrun`, `taskpolicy`, `sandbox-exec`) run the command after them, and
/// every one of these was allowed. zsh is macOS's default login shell.
#[test]
fn zsh_precommand_modifiers_and_macos_launchers_do_not_hide_the_command() {
    for (command, rule) in [
        ("noglob git reset --hard", "core.git:reset-hard"),
        ("nocorrect git reset --hard", "core.git:reset-hard"),
        ("- git reset --hard", "core.git:reset-hard"),
        ("noglob mkfs.ext4 /dev/sda1", "system.disk:mkfs"),
        ("arch -arm64 git reset --hard", "core.git:reset-hard"),
        ("arch -x86_64 mkfs.ext4 /dev/sda1", "system.disk:mkfs"),
        ("xcrun git reset --hard", "core.git:reset-hard"),
        (
            "taskpolicy -c utility git reset --hard",
            "core.git:reset-hard",
        ),
        (
            "sandbox-exec -n no-network git reset --hard",
            "core.git:reset-hard",
        ),
        (
            "echo k | noglob tee ~/.ssh/authorized_keys",
            "core.filesystem:credential-file-write",
        ),
        (
            "echo k | arch -arm64 tee ~/.ssh/authorized_keys",
            "core.filesystem:credential-file-write",
        ),
        (
            "echo k | strace -f tee ~/.ssh/authorized_keys",
            "core.filesystem:credential-file-write",
        ),
        (
            "echo k | firejail tee ~/.ssh/authorized_keys",
            "core.filesystem:credential-file-write",
        ),
    ] {
        let (decision, reason) = hook_verdict(command);
        assert_eq!(decision, "deny", "{command:?} must deny: {reason}");
        assert!(
            reason.contains(rule),
            "{command:?} must deny as {rule}: {reason}"
        );
    }
    for command in [
        "noglob git status",
        "arch",
        "arch -arm64 git log --oneline -3",
        "xcrun --show-sdk-path",
        "xcrun clang --version",
    ] {
        let (decision, reason) = hook_verdict(command);
        assert_eq!(decision, "allow", "{command:?} must stay allowed: {reason}");
    }
}

#[test]
fn builtin_with_harmless_commands_stays_allowed() {
    for command in [
        "builtin echo git reset --hard",
        "builtin command git status",
        "builtin cd /tmp",
        "builtin printf '%s\\n' 'git reset --hard'",
    ] {
        let (decision, reason) = hook_verdict(command);
        assert_eq!(decision, "allow", "{command:?} must stay allowed: {reason}");
    }
}

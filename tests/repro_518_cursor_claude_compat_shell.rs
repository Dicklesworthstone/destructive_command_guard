//! Repro for #518: Cursor runs the `PreToolUse` hooks in
//! `~/.claude/settings.json` (its "third-party hooks" layer) and renames
//! Claude Code's `Bash` tool to `Shell` on the way. dcg did not know the name,
//! extracted no command, and allowed every Cursor command, while the same
//! payload labelled `Bash` was denied. Cursor reads the Claude-shaped answer
//! (`permissionDecision` maps to its `permission`), so the deny must keep that
//! shape.

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

/// One hook call through the real binary with an isolated HOME and config,
/// and no ambient agent markers, the way Cursor spawns a Claude hook.
fn run_hook(home: &Path, payload: &serde_json::Value) -> (String, i32) {
    let config_path = home.join("dcg-test-config.toml");
    std::fs::write(&config_path, "").expect("write an empty config");
    let mut command = Command::new(env!("CARGO_BIN_EXE_dcg"));
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join("xdg_config"))
        .env("DCG_CONFIG", &config_path)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env(
            "DCG_PENDING_EXCEPTIONS_PATH",
            home.join("pending_exceptions.jsonl"),
        )
        .env("DCG_HOOK_TIMEOUT_MS", "30000");
    for (key, _) in std::env::vars_os() {
        let key = key.to_string_lossy().into_owned();
        let ambient_marker = [
            "CLAUDE",
            "CODEX",
            "GEMINI",
            "COPILOT",
            "CURSOR",
            "HERMES",
            "GROK",
            "OPENCODE",
            "CRUSH",
            "PA_PROJECT_DIR",
        ]
        .iter()
        .any(|prefix| key.starts_with(prefix));
        if ambient_marker || (key.starts_with("DCG_") && key != "DCG_TEST_TMPDIR") {
            if !matches!(
                key.as_str(),
                "DCG_CONFIG"
                    | "DCG_ALLOWLIST_SYSTEM_PATH"
                    | "DCG_NO_SELF_HEAL"
                    | "DCG_PENDING_EXCEPTIONS_PATH"
                    | "DCG_HOOK_TIMEOUT_MS"
            ) {
                command.env_remove(&key);
            }
        }
    }
    let mut child = command.spawn().expect("spawn dcg");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(payload.to_string().as_bytes())
        .expect("write stdin");
    let output = child.wait_with_output().expect("wait for dcg");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        output.status.code().unwrap_or(-1),
    )
}

/// The envelope Cursor sends to a Claude Code `PreToolUse` hook: Cursor's
/// common fields plus the renamed tool.
fn cursor_payload(tool_name: &str, command: &str) -> serde_json::Value {
    serde_json::json!({
        "conversation_id": "c0ffee00-0000-4000-8000-000000000518",
        "generation_id": "g-518",
        "model": "default",
        "hook_event_name": "PreToolUse",
        "cursor_version": "2026.09.28",
        "workspace_roots": ["/tmp/repo"],
        "transcript_path": null,
        "tool_name": tool_name,
        "tool_input": { "command": command, "cwd": "/tmp/repo" },
        "tool_use_id": "call_518",
        "cwd": "/tmp/repo",
    })
}

fn decision(stdout: &str) -> Option<String> {
    let document: serde_json::Value = serde_json::from_str(stdout.trim()).ok()?;
    document["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .map(str::to_string)
}

#[test]
fn cursor_shell_tool_is_judged_like_claude_bash() {
    let temp = tempfile::tempdir().expect("create a temporary HOME");

    for tool_name in ["Shell", "shell", "SHELL"] {
        for command in [
            "git stash clear",
            "git reset --hard",
            "rm -rf / --no-preserve-root",
        ] {
            let (stdout, code) = run_hook(temp.path(), &cursor_payload(tool_name, command));
            assert_eq!(
                decision(&stdout).as_deref(),
                Some("deny"),
                "{tool_name} {command:?} must be denied in Claude shape; exit {code}, stdout: {stdout}"
            );
            assert_eq!(code, 0, "Claude-shaped deny is read on exit 0: {stdout}");
        }

        let (stdout, code) = run_hook(temp.path(), &cursor_payload(tool_name, "git status"));
        assert!(
            stdout.trim().is_empty() && code == 0,
            "a safe Cursor command is allowed silently; exit {code}, stdout: {stdout}"
        );
    }
}

/// The same payload labelled `Bash` was already denied; the rename must not
/// change the answer's shape.
#[test]
fn cursor_shell_and_claude_bash_get_the_same_answer() {
    let temp = tempfile::tempdir().expect("create a temporary HOME");
    let (shell_out, shell_code) =
        run_hook(temp.path(), &cursor_payload("Shell", "git stash clear"));
    let (bash_out, bash_code) = run_hook(temp.path(), &cursor_payload("Bash", "git stash clear"));
    let rule = |stdout: &str| {
        serde_json::from_str::<serde_json::Value>(stdout.trim())
            .ok()
            .and_then(|d| {
                d["hookSpecificOutput"]["ruleId"]
                    .as_str()
                    .map(str::to_string)
            })
    };
    assert_eq!(decision(&shell_out), decision(&bash_out));
    assert_eq!(rule(&shell_out), rule(&bash_out), "{shell_out}\n{bash_out}");
    assert_eq!(shell_code, bash_code);
}

/// Cursor's other tools carry no shell command and stay unjudged.
#[test]
fn cursor_non_shell_tools_are_not_judged() {
    let temp = tempfile::tempdir().expect("create a temporary HOME");
    for tool_name in ["Read", "Write", "Grep", "Delete", "MCP:shell"] {
        let (stdout, code) = run_hook(temp.path(), &cursor_payload(tool_name, "git reset --hard"));
        assert!(
            stdout.trim().is_empty() && code == 0,
            "{tool_name} is not a shell tool; exit {code}, stdout: {stdout}"
        );
    }
}

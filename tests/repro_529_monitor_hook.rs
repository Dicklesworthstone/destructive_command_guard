//! #529: Claude Code's Monitor command must pass through the shell guard.
//!
//! Every shell string below is JSON input to dcg; no tested command is executed.
//! Calls use an isolated configuration and no ambient agent markers so the
//! envelope alone must select the Claude-compatible denial protocol.

use std::io::Write as _;
use std::process::{Command, Stdio};

fn hook(tool_name: &str, tool_input: &serde_json::Value) -> Option<serde_json::Value> {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    let config = temp.path().join("config.toml");
    std::fs::write(&config, "[history]\nenabled = false\n").expect("config");
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
        "session_id": "monitor-529",
        "tool_use_id": "toolu_monitor_529",
        "cwd": temp.path(),
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_dcg"))
        .env_clear()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("APPDATA", home.join("appdata"))
        .env("LOCALAPPDATA", home.join("localappdata"))
        .env("TEMP", temp.path())
        .env("TMP", temp.path())
        .env("DCG_CONFIG", &config)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env(
            "DCG_PENDING_EXCEPTIONS_PATH",
            temp.path().join("pending_exceptions.jsonl"),
        )
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcg");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(payload.to_string().as_bytes())
        .expect("write hook payload");
    let output = child.wait_with_output().expect("wait for dcg");
    assert_eq!(
        output.status.code(),
        Some(0),
        "Claude reads hook decisions on exit 0 for {payload}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return None;
    }
    Some(
        serde_json::from_str(&stdout)
            .unwrap_or_else(|error| panic!("bad hook output for {payload} ({error}): {stdout}")),
    )
}

fn assert_denied(tool_name: &str, command: &str, rule: &str) {
    let document = hook(tool_name, &serde_json::json!({ "command": command }))
        .unwrap_or_else(|| panic!("{tool_name} silently allowed {command:?}"));
    let output = &document["hookSpecificOutput"];
    assert_eq!(output["hookEventName"], "PreToolUse", "{document}");
    assert_eq!(output["permissionDecision"], "deny", "{document}");
    assert_eq!(
        output["ruleId"], rule,
        "{tool_name}: {command:?}: {document}"
    );
}

#[test]
fn monitor_denies_the_reported_destructive_scripts() {
    for (command, rule) in [
        ("git reset --hard HEAD", "core.git:reset-hard"),
        ("git clean -fdx", "core.git:clean-force"),
        ("rm -rf ~/project", "core.filesystem:rm-rf-root-home"),
        (
            "until git reset --hard HEAD; do sleep 1; done",
            "core.git:reset-hard",
        ),
    ] {
        assert_denied("Monitor", command, rule);
    }
}

#[test]
fn monitor_keeps_claude_metadata_and_existing_shell_behavior() {
    for tool_name in ["Bash", "PowerShell", "monitor", "MONITOR"] {
        assert_denied(tool_name, "git reset --hard HEAD", "core.git:reset-hard");
    }
}

#[test]
fn monitor_allows_a_harmless_watcher() {
    let output = hook(
        "Monitor",
        &serde_json::json!({ "command": "tail -f app.log | grep --line-buffered ERROR" }),
    );
    assert!(
        output.is_none(),
        "safe watcher should be allowed: {output:?}"
    );
}

#[test]
fn monitor_websocket_without_command_is_allowed() {
    let output = hook(
        "Monitor",
        &serde_json::json!({ "ws": { "url": "wss://example.com/stream" } }),
    );
    assert!(
        output.is_none(),
        "commandless ws should be allowed: {output:?}"
    );
}

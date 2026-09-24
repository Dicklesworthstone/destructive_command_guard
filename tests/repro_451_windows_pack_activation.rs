//! Regression tests for #451's activation half: a Windows payload arriving on a
//! non-Windows host must actually turn the `windows.*` packs on.
//!
//! `windows_payload` in `main.rs` matched `ShellDialect::PowerShell | Cmd`, but
//! `hook::refine_shell_dialect` down-trusts a *mislabeled* `Bash` payload to
//! `Unknown` — never to either of those. That mislabeled case is the #322/#252
//! case, and it is the one #451 exists for, so on Linux/macOS the packs never
//! activated for it and rules that deny when the packs are named were allowed.
//!
//! `format D: /q` is the sharpest instance, because the repair had already been
//! written and could not work: `hook::segment_is_format_drive_invocation` was
//! added *specifically* so that command would reach
//! `windows.filesystem:format-drive`, and the `Unknown` it widens to could not
//! activate the pack it was widening for.
//!
//! These assertions run the real binary under the DEFAULT configuration — no
//! `DCG_PACKS` — because that is the only way to exercise activation. A test
//! that names the pack proves the rule exists, which was never in doubt; it
//! cannot prove the pack turns on by itself.

use std::io::Write;
use std::process::{Command, Stdio};

fn dcg_binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

/// Evaluate `command` through the hook protocol with the DEFAULT pack set.
///
/// Two things here are deliberate. Naming a pack is precisely what this
/// regression must not do, so there is no `packs` parameter. And this is the
/// PLAIN hook path, not `hook --batch`: the batch reader builds one pack set
/// for the whole stream from `config.enabled_pack_ids()`, which passes
/// `windows_payload: false` unconditionally, so it does not activate the packs
/// at all and would fail these assertions for a reason unrelated to the
/// dialect. That divergence is tracked separately; the plain path is the one
/// every agent integration — including the plural `toolCalls[]` envelope of
/// #252, which arrives as `additional_commands` — actually takes.
fn default_config_decision(command: &str) -> String {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })
    .to_string();

    let mut child = Command::new(dcg_binary())
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
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The plain hook path is silent on allow and emits a `hookSpecificOutput`
    // denial on stdout otherwise.
    if stdout.trim().is_empty() {
        return "allow".to_string();
    }
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("bad hook output ({e}): {stdout}"));
    parsed
        .get("hookSpecificOutput")
        .and_then(|hso| hso.get("permissionDecision"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<missing>")
        .to_string()
}

#[test]
fn windows_default_on_packs_activate_from_a_bash_labeled_payload() {
    // Each of these denied only when the pack was named, and was allowed under
    // the default configuration, on a non-Windows host.
    for command in [
        // windows.filesystem:format-drive — the command
        // `segment_is_format_drive_invocation` was written for.
        "format D: /q",
        "format /q /y E:",
        "FORMAT.COM d:\\",
        // windows.system, reached by PowerShell cmdlet shape.
        "Initialize-Disk -Number 0",
        "Remove-Partition -DiskNumber 0 -PartitionNumber 1",
    ] {
        assert_eq!(
            default_config_decision(command),
            "deny",
            "windows.* pack must activate from the payload's own shape: {command}"
        );
    }
}

#[test]
fn opt_in_windows_packs_do_not_become_default_on() {
    // The activation signal must widen `windows.filesystem`/`windows.system`,
    // which are default-on where Windows applies, and must NOT quietly promote
    // `windows.misc` (registry/service/account destruction) into the default
    // set. Both of these have rules that fire the moment the pack is named.
    for command in ["reg delete HKLM\\SOFTWARE\\Microsoft /f", "sc delete Dhcp"] {
        assert_eq!(
            default_config_decision(command),
            "allow",
            "windows.misc is opt-in and must stay opt-in: {command}"
        );
    }
}

#[test]
fn posix_commands_keep_the_default_pack_set() {
    // The activation signal reads the command's shape, so an ordinary POSIX
    // command must not acquire the Windows packs — and a read-only Windows
    // spelling must not become a denial just because the packs turned on.
    for command in [
        "git status",
        "ls -la",
        "cargo build --release",
        "grep -rn pattern src/",
        "make clean",
        // The literal-temp carve-out still applies; the Windows packs turning
        // on must not change how a POSIX path is judged.
        "rm -rf /tmp/build-cache/x",
        // A read-only Windows spelling, and `format` as ordinary prose — the
        // drive-letter operand is what the signal requires, not the word.
        "dir C:\\",
        "echo format D: is a windows command",
    ] {
        assert_eq!(
            default_config_decision(command),
            "allow",
            "must stay allowed under the default pack set: {command}"
        );
    }
}

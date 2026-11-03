//! bd-external-pack-cmd-quick-reject-z0cq: loading an external pack must not
//! change what the built-in packs block.
//!
//! An external pack in `packs.custom_paths` turns off the keyword index, and the
//! evaluator then gates on keywords with `pack_aware_quick_reject`, which reads
//! POSIX quoting. cmd.exe passes single quotes through as argv bytes, so
//! `echo 'x & git reset --hard & y'` runs `git reset --hard` there, and
//! PowerShell, which does not escape with a backslash, runs the `git push` in
//! `Write-Output "a\" ; git push --force ; \"b"`. The POSIX gate saw one quoted
//! argument and skipped every pack, in both dialects and in the unknown
//! dialect's cmd replay. The hook drops the index whenever a custom pack is
//! configured, so a single `/etc/dcg` pack was enough.
//!
//! The external pack below declares a keyword that no command here contains.
//! Every verdict must match the verdict with no external pack. The commands
//! are only classified; none of them runs.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

const PACKS: &str = "core.git,core.filesystem,windows.filesystem,\
                     careful_company_running_windows.guardrails";

const TRIVIAL_PACK: &str = "schema_version: 1
id: scratch.trivial
name: Trivial scratch pack
version: 1.0.0
description: A pack whose keyword never appears in these commands.
keywords:
  - zzqqxx
destructive_patterns:
  - name: zzqqxx-run
    pattern: \\bzzqqxx\\b
    severity: high
    description: Placeholder rule.
";

/// Commands that cmd.exe or PowerShell splits where POSIX reads one quoted word:
/// cmd at `&`, `&&` or `|` inside single quotes, PowerShell at `;` after a
/// backslash it does not treat as an escape.
/// `(command, dialects that must deny, expected rule suffix)`.
const SPLIT_DENIALS: &[(&str, &[&str], &str)] = &[
    (
        r#"Write-Output "a\" ; git push --force ; \"b""#,
        &["powershell"],
        "push-force-long",
    ),
    (
        "echo 'x & git reset --hard & y'",
        &["cmd", "unknown"],
        "reset-hard",
    ),
    (
        "echo 'x && git reset --hard && y'",
        &["cmd", "unknown"],
        "reset-hard",
    ),
    (
        "echo 'x | git reset --hard | y'",
        &["cmd", "unknown"],
        "reset-hard",
    ),
    (
        "echo 'x & git push --force & y'",
        &["cmd", "unknown"],
        "push-force-long",
    ),
    (
        "echo 'x & git clean -fdx & y'",
        &["cmd", "unknown"],
        "clean-force",
    ),
    (
        "dir 'x & git reset --hard'",
        &["cmd", "unknown"],
        "reset-hard",
    ),
    (
        "echo 'x & rmdir /s /q C:\\Users & y'",
        &["cmd"],
        "rd-recursive",
    ),
    ("echo 'x & format C: & y'", &["cmd"], "format-drive"),
    (
        "echo 'data & dcg --robot uninstall & data'",
        &["cmd", "unknown"],
        "dcg-bypass-or-uninstall",
    ),
];

/// Quoted data in every dialect: the external pack must not turn these into
/// denials either.
const DATA_ALLOWS: &[(&str, &[&str])] = &[
    (
        "echo \"data & dcg --robot uninstall & data\"",
        &["cmd", "unknown"],
    ),
    ("echo \"x & git reset --hard & y\"", &["cmd"]),
    ("echo 'x & git reset --hard & y'", &["posix", "powershell"]),
];

fn write_pack(dir: &Path) -> String {
    let path = dir.join("trivial-pack.yaml");
    std::fs::write(&path, TRIVIAL_PACK).expect("write external pack");
    path.to_string_lossy().into_owned()
}

fn isolated(command: &mut Command, home: &Path, custom_paths: &str) {
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("DCG_HISTORY_DISABLED", "1")
        .env("DCG_AST_TIMEOUT_MS", "5000")
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        // Replaces any system-layer `packs.custom_paths`, so the only
        // external pack is the one under test.
        .env("DCG_CUSTOM_PATHS", custom_paths);
}

fn cli_verdict(command: &str, dialect: &str, custom_paths: &str) -> (String, String) {
    let scratch = tempfile::tempdir().expect("scratch dir");
    let home = scratch.path().join("home");
    std::fs::create_dir_all(&home).expect("isolated home");
    let config = scratch.path().join("config.toml");
    std::fs::write(&config, "[heredoc]\ntimeout_ms = 5000\n").expect("write config");
    let mut dcg = Command::new(env!("CARGO_BIN_EXE_dcg"));
    dcg.args(["test", "--config"])
        .arg(&config)
        .args(["--with-packs", PACKS, "--dialect", dialect])
        .args(["--format", "json", command])
        .current_dir(scratch.path());
    isolated(&mut dcg, &home, custom_paths);
    let output = dcg.output().expect("run dcg test");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{command:?} {dialect} custom_paths={custom_paths:?}: {error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
    });
    (
        value["decision"].as_str().unwrap_or_default().to_string(),
        value["rule_id"].as_str().unwrap_or_default().to_string(),
    )
}

/// Run `dcg hook` on a Claude `cmd` tool call; `true` means it was denied.
fn cmd_hook_denies(command: &str, custom_paths: &str) -> bool {
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "cmd",
        "tool_input": { "command": command },
    })
    .to_string();
    hook_denies(&payload, command, custom_paths)
}

/// Run `dcg hook` on a raw payload; `true` means it was denied.
fn hook_denies(payload: &str, command: &str, custom_paths: &str) -> bool {
    // Only for failure messages; the padded payloads are hundreds of KiB.
    let command = command.get(..120).unwrap_or(command);
    let scratch = tempfile::tempdir().expect("scratch dir");
    let home = scratch.path().join("home");
    std::fs::create_dir_all(&home).expect("isolated home");
    let config = scratch.path().join("config.toml");
    std::fs::write(&config, "[history]\nenabled = false\n").expect("write config");
    let mut dcg = Command::new(env!("CARGO_BIN_EXE_dcg"));
    dcg.arg("hook")
        .current_dir(scratch.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    isolated(&mut dcg, &home, custom_paths);
    // `isolated` clears the environment, so the hook settings go in after it.
    dcg.env("DCG_CONFIG", &config).env("DCG_PACKS", PACKS).env(
        "DCG_PENDING_EXCEPTIONS_PATH",
        scratch.path().join("pending.jsonl"),
    );
    let mut child = dcg.spawn().expect("spawn dcg hook");
    child
        .stdin
        .take()
        .expect("hook stdin")
        .write_all(payload.as_bytes())
        .expect("write hook payload");
    let output = child.wait_with_output().expect("wait for dcg hook");
    assert!(
        output.status.success(),
        "{command:?} custom_paths={custom_paths:?}: hook exited {:?}; stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return false;
    }
    let value: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("{command:?}: hook stdout is not JSON ({error}): {stdout}"));
    // Claude Code answers in `hookSpecificOutput`; Gemini CLI in `decision`.
    value["hookSpecificOutput"]["permissionDecision"].as_str() == Some("deny")
        || value["decision"].as_str() == Some("deny")
}

/// Padding that takes the hook envelope past `max_hook_input_bytes` (256 KiB),
/// so the hook scans the command in windows instead of parsing it.
fn padding() -> String {
    "A".repeat(300 * 1024)
}

#[test]
fn split_commands_stay_denied_with_an_external_pack_loaded() {
    let pack_dir = tempfile::tempdir().expect("pack dir");
    let pack = write_pack(pack_dir.path());
    for (command, dialects, rule) in SPLIT_DENIALS {
        for dialect in *dialects {
            for custom_paths in ["", pack.as_str()] {
                let (decision, rule_id) = cli_verdict(command, dialect, custom_paths);
                assert_eq!(
                    decision, "deny",
                    "{command:?} {dialect} custom_paths={custom_paths:?}: rule {rule_id:?}"
                );
                assert!(
                    rule_id.ends_with(&format!(":{rule}")),
                    "{command:?} {dialect} custom_paths={custom_paths:?}: rule {rule_id:?}, \
                     expected one ending in :{rule}"
                );
            }
        }
    }
}

#[test]
fn quoted_data_stays_allowed_with_an_external_pack_loaded() {
    let pack_dir = tempfile::tempdir().expect("pack dir");
    let pack = write_pack(pack_dir.path());
    for (command, dialects) in DATA_ALLOWS {
        for dialect in *dialects {
            for custom_paths in ["", pack.as_str()] {
                let (decision, rule_id) = cli_verdict(command, dialect, custom_paths);
                assert_eq!(
                    decision, "allow",
                    "{command:?} {dialect} custom_paths={custom_paths:?}: rule {rule_id:?}"
                );
            }
        }
    }
}

#[test]
fn cmd_hook_denies_split_commands_with_an_external_pack_loaded() {
    let pack_dir = tempfile::tempdir().expect("pack dir");
    let pack = write_pack(pack_dir.path());
    for custom_paths in ["", pack.as_str()] {
        assert!(
            cmd_hook_denies("echo 'x & git reset --hard & y'", custom_paths),
            "cmd hook allowed a split `git reset --hard`, custom_paths={custom_paths:?}"
        );
        assert!(
            cmd_hook_denies("echo 'data & dcg --robot uninstall & data'", custom_paths),
            "cmd hook allowed a split `dcg --robot uninstall`, custom_paths={custom_paths:?}"
        );
        assert!(
            !cmd_hook_denies("echo \"x & git reset --hard & y\"", custom_paths),
            "cmd hook denied double-quoted data, custom_paths={custom_paths:?}"
        );
    }
}

/// The oversized-payload window scan skipped windows with the same POSIX gate,
/// so padding a cmd, PowerShell or unknown-dialect split command past the
/// input limit allowed it, with or without an external pack. Unpadded, each is
/// denied.
#[test]
fn oversized_split_payloads_are_denied() {
    let pad = padding();
    let split = "echo 'x & git reset --hard & y'";
    let quoted = "echo \"x & git reset --hard & y\"";
    let backslash_quote = r#"Write-Output "a\" ; git push --force ; \"b""#;
    let claude = |tool: &str, command: &str| {
        serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": { "command": command },
        })
        .to_string()
    };
    let gemini = |command: &str| {
        serde_json::json!({
            "session_id": "z0cq",
            "hook_event_name": "BeforeTool",
            "tool_name": "run_shell_command",
            "tool_input": { "command": command },
        })
        .to_string()
    };
    let cases = [
        (claude("cmd", &format!("{split} & echo {pad}")), true),
        (claude("cmd", &format!("echo {pad} & {split}")), true),
        (claude("cmd", &format!("{quoted} & echo {pad}")), false),
        (
            claude("PowerShell", &format!("{backslash_quote} ; echo {pad}")),
            true,
        ),
        (
            claude("PowerShell", &format!("echo {pad} ; {backslash_quote}")),
            true,
        ),
        (gemini(&format!("{split} ; echo {pad}")), true),
        (gemini(&format!("echo {pad} ; {split}")), true),
        (gemini(&format!("{quoted} ; echo {pad}")), false),
        // POSIX keeps reading single quotes as quoting.
        (claude("Bash", &format!("{split} ; echo {pad}")), false),
    ];
    for (payload, want_deny) in &cases {
        assert!(payload.len() > 256 * 1024, "payload must exceed the limit");
        let shown = payload.replace(&pad, "<pad>");
        assert_eq!(
            hook_denies(payload, &shown, ""),
            *want_deny,
            "oversized payload {shown}"
        );
    }
}

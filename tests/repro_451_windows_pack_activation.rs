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
        // windows.system, reached by the bare executable name: these match no
        // cmdlet, no destructive alias, no cmd writer and no `format <drive>:`,
        // so nothing marked the payload Windows and the rules behind them were
        // unreachable even once activation itself was fixed.
        "diskpart /s script.txt",
        "bcdedit /deletevalue safeboot",
        "cipher /w:C:\\",
        "wbadmin delete catalog -quiet",
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
        // A Windows-only executable named as data rather than run: the signal
        // reads the command word, so a mention must not acquire the packs.
        "echo diskpart is a windows tool",
        "grep -rn bcdedit notes.md",
    ] {
        assert_eq!(
            default_config_decision(command),
            "allow",
            "must stay allowed under the default pack set: {command}"
        );
    }
}

/// Run either a diagnostic or the live hook with the same isolated policy.
/// Candidate commands are only dcg input; no command under test is executed.
fn run_windows_diagnostic(
    args: &[&str],
    input: Option<&str>,
    config: Option<&str>,
) -> std::process::Output {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).expect("create home");
    let mut command = Command::new(dcg_binary());
    command
        .args(args)
        .env_clear()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("TEMP", &home)
        .env("TMP", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(config) = config {
        let path = temp.path().join("config.toml");
        std::fs::write(&path, config).expect("write config");
        command.env("DCG_CONFIG", path);
    }
    let mut child = command.spawn().expect("spawn dcg");
    if let Some(input) = input {
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(input.as_bytes())
            .expect("write input");
    }
    child.wait_with_output().expect("wait for dcg")
}

fn diagnostic_json(output: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "bad JSON ({error}): {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn assert_windows_diagnostics(dialect: &str, command: &str, config: Option<&str>, expected: &str) {
    for subcommand in ["test", "explain"] {
        let output = run_windows_diagnostic(
            &[
                subcommand,
                "--dialect",
                dialect,
                "--format",
                "json",
                command,
            ],
            None,
            config,
        );
        let json = diagnostic_json(&output);
        assert_eq!(
            json["decision"], expected,
            "{subcommand} {dialect}: {command}"
        );
        if subcommand == "explain" {
            assert_eq!(json["outcome"], expected, "explain {dialect}: {command}");
            assert!(output.status.success(), "explain is a diagnostic");
        } else {
            assert_eq!(
                output.status.code(),
                Some(i32::from(expected == "deny")),
                "test {dialect}: {command}"
            );
        }
    }
}

#[test]
fn windows_cli_diagnostics_match_hook_payload_defaults() {
    // #589: both diagnostics used host-only defaults, so on Linux/macOS they
    // said ALLOW even with --dialect cmd/ps while the matching hook denied.
    for (tool, dialect, command) in [
        ("cmd", "cmd", r"rmdir /s /q D:\"),
        ("PowerShell", "ps", "Clear-Content report.txt"),
        (
            "PowerShell",
            "ps",
            "Remove-Partition -DiskNumber 0 -PartitionNumber 1",
        ),
        // Unknown is not a blanket opt-in: this command supplies the same
        // Windows-syntax evidence as the Bash-labeled live-hook case above.
        ("Bash", "unknown", r"rmdir /s /q D:\"),
    ] {
        let payload = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": {"command": command},
        })
        .to_string();
        let hook = run_windows_diagnostic(&[], Some(&payload), None);
        assert!(hook.status.success(), "structured hook denial exits zero");
        assert_eq!(
            diagnostic_json(&hook)["hookSpecificOutput"]["permissionDecision"],
            "deny",
            "{tool}: {command}"
        );
        assert_windows_diagnostics(dialect, command, None, "deny");
    }
}

#[test]
fn windows_cli_diagnostics_preserve_safe_commands_and_opt_in_boundaries() {
    for (dialect, command) in [
        ("cmd", r"dir C:\"),
        ("ps", r"Get-ChildItem C:\"),
        ("unknown", "echo Clear-Content report.txt"),
        ("cmd", r"reg delete HKLM\SOFTWARE\Microsoft /f"),
        ("ps", "Remove-LocalUser alice"),
        // An explicitly selected POSIX dialect stays POSIX; it is not a
        // mislabeled hook payload whose dialect should be widened.
        ("posix", r"rmdir /s /q D:\"),
    ] {
        assert_windows_diagnostics(dialect, command, None, "allow");
    }
}

#[test]
fn windows_cli_payload_defaults_respect_explicit_exclusions() {
    for disabled in ["windows", "windows.filesystem"] {
        let config = format!("[packs]\ndisabled = [\"{disabled}\"]\n");
        for (dialect, command) in [
            ("cmd", r"rmdir /s /q D:\"),
            ("ps", "Clear-Content report.txt"),
            ("unknown", "format D: /q"),
        ] {
            assert_windows_diagnostics(dialect, command, Some(&config), "allow");
        }

        // Invocation-local --with-packs keeps its established precedence over
        // configured exclusions after the automatic defaults are resolved.
        let explicit = run_windows_diagnostic(
            &[
                "test",
                "--dialect",
                "cmd",
                "--format",
                "json",
                "--with-packs",
                "windows.filesystem",
                r"rmdir /s /q D:\",
            ],
            None,
            Some(&config),
        );
        assert_eq!(explicit.status.code(), Some(1));
        assert_eq!(diagnostic_json(&explicit)["decision"], "deny");
    }
}

/// #654: the body and the single-quoted rg argument both contain << as
/// literal text. The apostrophe in the body is not a shell quote.
const ISSUE_654_COMMAND: &str = r#"cat > /tmp/x/a.py <<'EOF'
p = r"^<<<<<<< [^\n]*\n(.*?)^\|\|\|\|\|\|\| [^\n]*\n(.*?)"
row's
EOF
python3 /tmp/x/a.py && for f in a.txt; do rg -c '^(<<<<<<<|=======|>>>>>>>)( |$)' "$f" || echo 0; done"#;

#[test]
fn issue_654_quoted_conflict_markers_keep_bash_hook_and_posix_cli_in_agreement() {
    let commands = [
        ISSUE_654_COMMAND.to_string(),
        // Each of these minimal edits was allowed in the original report.
        ISSUE_654_COMMAND.replace("row's\n", ""),
        ISSUE_654_COMMAND
            .lines()
            .filter(|line| !line.starts_with("p = "))
            .collect::<Vec<_>>()
            .join("\n"),
        ISSUE_654_COMMAND.replace("'^(<<<<<<<|=======|>>>>>>>)( |$)'", "'x'"),
        // The same literal body is data whether cat writes or appends it,
        // and a later quoted pattern must not turn it into Windows syntax.
        ISSUE_654_COMMAND.replace("python3 /tmp/x/a.py && ", ""),
        ISSUE_654_COMMAND.replacen("cat >", "cat >>", 1),
    ];
    for command in &commands {
        let payload = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        })
        .to_string();
        let hook = run_windows_diagnostic(&[], Some(&payload), Some("# empty\n"));
        assert!(
            hook.status.success(),
            "hook failed for {command:?}: {}",
            String::from_utf8_lossy(&hook.stderr)
        );
        // A deny or an incomplete-analysis ask is a JSON document, never a
        // successful silent allow. Also check the CLI's explicit decision.
        assert!(
            hook.stdout.is_empty(),
            "safe Bash heredoc must be allowed: {command:?}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&hook.stdout),
            String::from_utf8_lossy(&hook.stderr)
        );
        let diagnostic = run_windows_diagnostic(
            &["test", "--stdin", "--dialect", "posix", "--format", "json"],
            Some(command),
            Some("# empty\n"),
        );
        assert_eq!(
            diagnostic.status.code(),
            Some(0),
            "POSIX CLI failed for {command:?}: {}",
            String::from_utf8_lossy(&diagnostic.stderr)
        );
        assert_eq!(
            diagnostic_json(&diagnostic)["decision"],
            "allow",
            "{command}"
        );
    }
}

#[test]
fn issue_654_heredoc_data_does_not_hide_executed_destructive_commands() {
    let trailing_delete = format!("{ISSUE_654_COMMAND}\nrm -rf ./important");
    for command in [
        trailing_delete.as_str(),
        // The outer shell executes substitutions in an unquoted heredoc.
        "cat > /tmp/x/a.py <<EOF\n$(rm -rf ./important)\nEOF\nrg '^(<<<<<<<|=======|>>>>>>>)( |$)' a.txt",
        // A shell receives code, even when the delimiter is quoted.
        "bash <<'EOF'\nrm -rf ./important\nEOF",
        // A file written by cat and subsequently run as shell is also code.
        "cat > /tmp/x/a.sh <<'EOF'\nrm -rf ./important\nEOF\nbash /tmp/x/a.sh\nrg '^(<<<<<<<|=======|>>>>>>>)( |$)' a.txt",
    ] {
        let payload = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        })
        .to_string();
        let hook = run_windows_diagnostic(&[], Some(&payload), Some("# empty\n"));
        assert!(hook.status.success(), "structured hook denial exits zero");
        let json = diagnostic_json(&hook);
        let verdict = &json["hookSpecificOutput"];
        assert_eq!(verdict["permissionDecision"], "deny", "{command}: {json}");
        let rule = verdict["ruleId"]
            .as_str()
            .unwrap_or_else(|| panic!("expected a concrete destructive rule: {command}: {json}"));
        assert!(
            !rule.starts_with("windows.") && !rule.starts_with("heredoc.powershell:"),
            "POSIX execution must be denied for its own rule, not the #654 false positive: {command}: {json}"
        );
    }
}

#[test]
fn issue_654_preserves_explicit_and_mislabeled_windows_deletion_detection() {
    for tool in ["PowerShell", "Bash"] {
        let payload = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": {"command": r"Remove-Item -Recurse -Force C:\important"},
        })
        .to_string();
        let hook = run_windows_diagnostic(&[], Some(&payload), Some("# empty\n"));
        assert!(hook.status.success(), "structured hook denial exits zero");
        let json = diagnostic_json(&hook);
        let verdict = &json["hookSpecificOutput"];
        assert_eq!(verdict["permissionDecision"], "deny", "{tool}: {json}");
        assert!(
            verdict["ruleId"]
                .as_str()
                .is_some_and(|rule| rule.starts_with("windows.filesystem:")),
            "the Windows filesystem rule must remain active: {tool}: {json}"
        );
    }
}

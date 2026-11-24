//! bd-ps-cross-dialect-gaps-ewf3: real-binary CLI + PreToolUse hook tests for:
//!   (a) PowerShell call expressions (`& ('gi'+'t')`, `& ('{0}{1}' -f 'gi','t')`, `& ($c)`) in `unknown` & `powershell`
//!   (b) `cmd` caret+percent mixes (`rm^%x% -rf /`, `r^m%x% -rf /`, `g^i%x%t reset --hard`)
//!   (c) PowerShell here-strings piped to interpreters (`python3`, `py`, `iex`, `pwsh`) in `powershell` & `unknown`
//!   (d) `cmd` `%VAR%` and `!VAR!` names containing whitespace

use std::io::Write;
use std::process::{Command, Stdio};

fn dcg_test_verdict(command: &str, dialect: &str) -> serde_json::Value {
    let scratch = tempfile::tempdir().expect("scratch dir");
    let home = scratch.path().join("home");
    std::fs::create_dir(&home).expect("home dir");

    let mut child = Command::new(env!("CARGO_BIN_EXE_dcg"))
        .args(["test", "--stdin", "--dialect", dialect, "--format", "json"])
        .env_clear()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("DCG_HISTORY_DISABLED", "1")
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .env("DCG_AST_TIMEOUT_MS", "5000")
        .env("DCG_HEREDOC_TIMEOUT_MS", "5000")
        .current_dir(scratch.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcg test");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(command.as_bytes())
        .expect("write command");
    let output = child.wait_with_output().expect("wait dcg test");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    serde_json::from_str(stdout.trim()).unwrap_or_else(|err| {
        panic!("invalid JSON for {command:?} ({dialect}): {err}\nstdout={stdout}\nstderr={stderr}")
    })
}

fn hook_decision(command: &str, tool_name: &str) -> (String, String) {
    let scratch = tempfile::tempdir().expect("scratch dir");
    let home = scratch.path().join("home");
    std::fs::create_dir(&home).expect("home dir");
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": { "command": command }
    })
    .to_string();

    let mut child = Command::new(env!("CARGO_BIN_EXE_dcg"))
        .env_clear()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("DCG_HISTORY_DISABLED", "1")
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .env("DCG_AST_TIMEOUT_MS", "5000")
        .env("DCG_HEREDOC_TIMEOUT_MS", "5000")
        .current_dir(scratch.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcg hook");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(payload.as_bytes())
        .expect("write hook payload");
    let output = child.wait_with_output().expect("wait dcg hook");
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if stdout.is_empty() {
        assert!(output.status.success(), "{command:?}: {stderr}");
        return ("allow".to_string(), stdout);
    }
    let value: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("invalid hook JSON for {command:?}: {e}; stdout={stdout}"));
    let decision = value["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    (decision, stdout)
}

#[test]
fn ewf3_powershell_call_expressions_in_unknown_and_powershell() {
    for command in [
        "& ('gi'+'t') reset --hard",
        "&('gi'+'t') reset --hard",
        "& ('{0}{1}' -f 'gi','t') reset --hard",
        "& ([string]'gi'+'t') reset --hard",
        "& ($c) reset --hard",
        r#"echo "x\"; & ('gi'+'t') reset --hard"#,
    ] {
        for dialect in ["powershell", "unknown"] {
            let verdict = dcg_test_verdict(command, dialect);
            assert_eq!(
                verdict["decision"].as_str(),
                Some("deny"),
                "{command:?} ({dialect}): {verdict}"
            );
        }
        let (decision, stdout) = hook_decision(command, "PowerShell");
        assert_eq!(
            decision, "deny",
            "PowerShell hook must deny {command:?}: {stdout}"
        );
        let (decision_u, stdout_u) = hook_decision(command, "shell");
        assert_eq!(
            decision_u, "deny",
            "unknown shell hook must deny {command:?}: {stdout_u}"
        );
    }

    // Benign negatives
    for command in ["& ('ec'+'ho') hi", "& ('gi'+'t') status"] {
        for dialect in ["powershell", "unknown"] {
            let verdict = dcg_test_verdict(command, dialect);
            assert_eq!(
                verdict["decision"].as_str(),
                Some("allow"),
                "benign call expression must allow {command:?} ({dialect}): {verdict}"
            );
        }
    }
}

#[test]
fn ewf3_powershell_here_strings_piped_to_interpreters() {
    let cases = [
        (
            "@'\nimport shutil\nshutil.rmtree('/var/important')\n'@ | python3",
            "heredoc.python:shutil_rmtree",
        ),
        (
            "@'\nimport shutil\nshutil.rmtree('/var/important')\n'@ | py",
            "heredoc.python:shutil_rmtree",
        ),
        (
            "@'\nRemove-Item -Recurse -Force C:\\important\n'@ | iex",
            "core.filesystem:powershell-remove-item-recursive",
        ),
        (
            "@'\nRemove-Item -Recurse -Force C:\\important\n'@ | pwsh",
            "core.filesystem:powershell-remove-item-recursive",
        ),
    ];
    for (command, expected_rule) in cases {
        for dialect in ["powershell", "unknown"] {
            let verdict = dcg_test_verdict(command, dialect);
            assert_eq!(
                verdict["decision"].as_str(),
                Some("deny"),
                "{command:?} ({dialect}): {verdict}"
            );
            assert_eq!(
                verdict["rule_id"].as_str(),
                Some(expected_rule),
                "{command:?} ({dialect}): {verdict}"
            );
        }
        let (decision, stdout) = hook_decision(command, "PowerShell");
        assert_eq!(decision, "deny", "hook must deny {command:?}: {stdout}");
    }

    // Benign here-strings piped to PowerShell/Windows consumers allow in both
    // `powershell` and `unknown` dialects; `python3` allows in `powershell`
    // (while `unknown` conservatively keeps POSIX `pipeline-consumer` fail-closed).
    for (command, dialects) in [
        (
            "@'\nWrite-Output 'hello'\n'@ | iex",
            &["powershell", "unknown"][..],
        ),
        (
            "@'\nprint('hello')\n'@ | py",
            &["powershell", "unknown"][..],
        ),
        ("@'\nprint('hello')\n'@ | python3", &["powershell"][..]),
    ] {
        for &dialect in dialects {
            let verdict = dcg_test_verdict(command, dialect);
            assert_eq!(
                verdict["decision"].as_str(),
                Some("allow"),
                "benign here-string must allow {command:?} ({dialect}): {verdict}"
            );
        }
        let (decision, stdout) = hook_decision(command, "PowerShell");
        assert_eq!(decision, "allow", "hook must allow {command:?}: {stdout}");
    }
}

#[test]
fn ewf3_cmd_caret_percent_and_whitespace_expansion_names() {
    for command in [
        "rm^%x% -rf /",
        "r^m%x% -rf /",
        "g^i%x%t reset --hard",
        "vss^ad%x%min delete shadows /all",
        "git %a b%reset --hard",
        "git reset %a b%--hard",
        "rm %a b%-rf /",
        "rm %x%-rf /",
        "g!a b!it reset --hard",
        "r!a b!m -rf /",
    ] {
        for dialect in ["cmd", "unknown"] {
            let verdict = dcg_test_verdict(command, dialect);
            assert_eq!(
                verdict["decision"].as_str(),
                Some("deny"),
                "{command:?} ({dialect}): {verdict}"
            );
        }
        let (decision, stdout) = hook_decision(command, "cmd");
        assert_eq!(decision, "deny", "cmd hook must deny {command:?}: {stdout}");
    }

    // Benign negatives
    for command in [
        "echo^%x% hi",
        "vss^ad%x%min list shadows",
        r#"dir "%a b%""#,
        "echo %a b%",
    ] {
        for dialect in ["cmd", "unknown"] {
            let verdict = dcg_test_verdict(command, dialect);
            assert_eq!(
                verdict["decision"].as_str(),
                Some("allow"),
                "benign cmd must allow {command:?} ({dialect}): {verdict}"
            );
        }
        let (decision, stdout) = hook_decision(command, "cmd");
        assert_eq!(
            decision, "allow",
            "cmd hook must allow {command:?}: {stdout}"
        );
    }
}

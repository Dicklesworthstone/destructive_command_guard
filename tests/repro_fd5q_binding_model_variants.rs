//! bd-binding-model-variants-fd5q: real-binary CLI + PreToolUse hook tests for
//! POSIX executable binding model improvements:
//!   (a) per-segment separator handling (`||`, `|`, `&&`, `&`)
//!   (b) stepping over neutral commands (`echo`, `:`, `[ ]`, `[[ ]]`, `test`, `true`, `X=1 true`)
//!   (c) `export` / `readonly` / `declare` bindings and use-site wrappers (`sudo`, `env`, `time`, `exec`, `command`, `nohup`, `nice`)
//!   (d) unified quoted `"$VAR"` handling between `posix` and `unknown`
//!   (e) bounded >64 assignment handling without blanket fail-closed on later unrelated vars

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
fn fd5q_separators_neutral_commands_declarations_and_wrappers_deny_destructive() {
    let destructive = [
        // (a) Per-segment separator handling (`||`, `|`, `&&`, `&`)
        "d=mkfs.ext4; false || $d /dev/sda",
        "false || d=git; $d reset --hard",
        "d=mkfs.ext4; echo x | $d /dev/sda",
        "d=mkfs.ext4; true & $d /dev/sda",
        // (b) Stepping over neutral commands between binding and use
        "d=mkfs.ext4; echo checking; $d /dev/sda",
        "d=mkfs.ext4; :; $d /dev/sda",
        "d=mkfs.ext4; [ -d /tmp ]; $d /dev/sda",
        "d=mkfs.ext4; [[ -d /tmp ]]; $d /dev/sda",
        "d=mkfs.ext4; test -d /tmp && $d /dev/sda",
        "d=mkfs.ext4; true; $d /dev/sda",
        "d=mkfs.ext4; X=1 true; $d /dev/sda",
        // (c) export / readonly / declare bindings
        "export d=mkfs.ext4; $d /dev/sda",
        "readonly d=mkfs.ext4; $d /dev/sda",
        "declare d=mkfs.ext4; $d /dev/sda",
        "declare -x d=mkfs.ext4; $d /dev/sda",
        // (c) Use-site wrappers
        "d=mkfs.ext4; sudo $d /dev/sda",
        "d=mkfs.ext4; sudo -u root $d /dev/sda",
        "d=mkfs.ext4; env $d /dev/sda",
        "d=mkfs.ext4; env FOO=1 $d /dev/sda",
        "d=mkfs.ext4; time $d /dev/sda",
        "d=mkfs.ext4; exec $d /dev/sda",
        "d=mkfs.ext4; command $d /dev/sda",
        "d=mkfs.ext4; nohup $d /dev/sda",
        "d=mkfs.ext4; nice -n 5 $d /dev/sda",
    ];
    for command in destructive {
        for dialect in ["posix", "unknown"] {
            let verdict = dcg_test_verdict(command, dialect);
            assert_eq!(
                verdict["decision"].as_str(),
                Some("deny"),
                "{command:?} ({dialect}): {verdict}"
            );
        }
        let (decision, stdout) = hook_decision(command, "Bash");
        assert_eq!(decision, "deny", "hook must deny {command:?}: {stdout}");
    }
}

#[test]
fn fd5q_quoted_var_argv0_unified_between_posix_and_unknown() {
    for command in [
        r#""$VAR" reset --hard"#,
        r#"g"$X"it reset --hard"#,
        r#""/usr/bin/$VAR" reset --hard"#,
    ] {
        let posix = dcg_test_verdict(command, "posix");
        let unknown = dcg_test_verdict(command, "unknown");
        assert_eq!(
            posix["decision"].as_str(),
            Some("deny"),
            "posix must deny {command:?}: {posix}"
        );
        assert_eq!(
            unknown["decision"].as_str(),
            Some("deny"),
            "unknown must deny {command:?}: {unknown}"
        );
        let (decision, stdout) = hook_decision(command, "Bash");
        assert_eq!(decision, "deny", "hook must deny {command:?}: {stdout}");
    }

    // Planted benign negatives: single-quoted literal or no destructive tail.
    for command in [
        "'$VAR' reset --hard",
        r#""$X" "$Y""#,
        r#""$BIN" run "$ARG""#,
        r#""$VAR" status"#,
    ] {
        for dialect in ["posix", "unknown"] {
            let verdict = dcg_test_verdict(command, dialect);
            assert_eq!(
                verdict["decision"].as_str(),
                Some("allow"),
                "benign control must allow {command:?} ({dialect}): {verdict}"
            );
        }
    }
}

#[test]
fn fd5q_benign_neutral_wrappers_and_over_64_assignments() {
    let mut prefix_66 = String::new();
    for i in 0..66 {
        use std::fmt::Write as _;
        let _ = write!(prefix_66, "v{i}=val{i}; ");
    }

    // Benign controls must all allow (including >64 assignments followed by a benign
    // bound variable or an unrelated unbound variable).
    let benign_binding_66 = format!("{prefix_66}b=echo; $b hi");
    let benign_unbound_66 = format!("{prefix_66}$u hi");
    let benign_controls = [
        "d=echo; false || $d hi".to_string(),
        "d=cat; echo hi | $d".to_string(),
        "d=echo; :; $d hi".to_string(),
        "d=echo; [ -d /tmp ]; $d hi".to_string(),
        "d=echo; [[ -d /tmp ]]; $d hi".to_string(),
        "d=echo; test -d /tmp && $d hi".to_string(),
        "d=echo; X=1 true; $d hi".to_string(),
        "export d=echo; sudo $d hi".to_string(),
        "declare d=echo; env $d hi".to_string(),
        benign_binding_66,
        benign_unbound_66,
    ];
    for command in &benign_controls {
        for dialect in ["posix", "unknown"] {
            let verdict = dcg_test_verdict(command, dialect);
            assert_eq!(
                verdict["decision"].as_str(),
                Some("allow"),
                "benign must allow {command:?} ({dialect}): {verdict}"
            );
        }
        let (decision, stdout) = hook_decision(command, "Bash");
        assert_eq!(decision, "allow", "hook must allow {command:?}: {stdout}");
    }

    // >64 assignments followed by a fresh destructive binding must still catch it.
    let destructive_fresh_66 = format!("{prefix_66}d=git; $d reset --hard");
    for dialect in ["posix", "unknown"] {
        let verdict = dcg_test_verdict(&destructive_fresh_66, dialect);
        assert_eq!(
            verdict["decision"].as_str(),
            Some("deny"),
            "fresh destructive binding after 66 vars must deny ({dialect}): {verdict}"
        );
        assert_eq!(
            verdict["rule_id"].as_str(),
            Some("core.git:reset-hard"),
            "{dialect}: {verdict}"
        );
    }

    // An actually evicted earlier binding used later must fail closed (never allow).
    let evicted_early = format!("d=mkfs.ext4; {prefix_66}$d /dev/sda");
    for dialect in ["posix", "unknown"] {
        let verdict = dcg_test_verdict(&evicted_early, dialect);
        assert_eq!(
            verdict["decision"].as_str(),
            Some("deny"),
            "evicted binding must fail closed ({dialect}): {verdict}"
        );
    }
    let (decision, stdout) = hook_decision(&evicted_early, "Bash");
    assert_eq!(
        decision, "deny",
        "hook must fail closed on evicted binding: {stdout}"
    );
}

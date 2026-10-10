//! #538: receipt-key text is data, not a dynamically assembled code launcher.
//! Commands are sent to dcg as input strings, never executed by these tests.

use std::io::Write;
use std::process::{Command, Stdio};

fn isolated_dcg(temp: &tempfile::TempDir) -> Command {
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).expect("isolated home");
    let config = temp.path().join("config.toml");
    std::fs::write(&config, "[history]\nenabled = false\n").expect("isolated config");
    let mut command = Command::new(env!("CARGO_BIN_EXE_dcg"));
    command
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
        .env("TMPDIR", temp.path())
        .env("DCG_CONFIG", &config)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env(
            "DCG_PENDING_EXCEPTIONS_PATH",
            temp.path().join("pending.jsonl"),
        )
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .current_dir(temp.path());
    command
}

fn assert_decision(command: &str, allowed: bool, expected_rule: Option<&str>) {
    let temp = tempfile::tempdir().expect("tempdir");
    let cli = isolated_dcg(&temp)
        .args(["test", command])
        .stdin(Stdio::null())
        .output()
        .expect("dcg test");
    let stdout = String::from_utf8_lossy(&cli.stdout);
    let stderr = String::from_utf8_lossy(&cli.stderr);
    let result = stdout
        .lines()
        .chain(stderr.lines())
        .find(|line| line.trim_start().starts_with("Result:"))
        .map(str::trim)
        .unwrap_or_default();
    if allowed {
        assert_eq!(result, "Result: ALLOWED", "{command}: {stdout}\n{stderr}");
    } else {
        assert!(
            result.starts_with("Result: BLOCKED") || result.starts_with("Result: REVIEW REQUIRED"),
            "{command}: {stdout}\n{stderr}"
        );
    }
    if let Some(rule) = expected_rule {
        assert!(
            stdout.contains(rule) || stderr.contains(rule),
            "{command}: expected {rule}\n{stdout}\n{stderr}"
        );
    }

    // Exercise the actual hook protocol as well as the human-facing command.
    // The shell source is JSON data sent to dcg, never run by a shell.
    let mut hook = isolated_dcg(&temp)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("dcg hook");
    hook.stdin
        .take()
        .expect("hook stdin")
        .write_all(
            &serde_json::to_vec(&serde_json::json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": { "command": command }
            }))
            .expect("hook request"),
        )
        .expect("write hook request");
    let output = hook.wait_with_output().expect("hook response");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{command}: {stdout}\n{stderr}");
    if allowed {
        assert!(stdout.trim().is_empty(), "{command}: {stdout}\n{stderr}");
    } else {
        let response: serde_json::Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("{command}: {error}: {stdout}\n{stderr}"));
        assert!(
            matches!(
                response["hookSpecificOutput"]["permissionDecision"].as_str(),
                Some("deny" | "ask")
            ),
            "{command}: {stdout}\n{stderr}"
        );
        if let Some(rule) = expected_rule {
            assert!(
                stdout.contains(rule) || stderr.contains(rule),
                "{command}: expected {rule}: {stdout}\n{stderr}"
            );
        }
    }
}

#[test]
fn reported_flowctl_shapes_are_data() {
    for command in [
        r#"FLOWCTL="${PLUGIN_ROOT}/scripts/flowctl"; "$FLOWCTL" gate check --gate test --command "npm test""#,
        r#""$FLOWCTL" gate receipt --gate test --command "npm test""#,
        r#"/opt/tool/scripts/flowctl gate check --gate test --command "npm test""#,
        r#""$FLOWCTL" gate check --gate=test --command="npm test""#,
        r#""$FLOWCTL" gate receipt --command "" --gate test --json"#,
        r#""$FLOWCTL" gate check --command 'npm test; git reset --hard'"#,
        r#""$FLOWCTL" gate receipt --command "git reset --hard""#,
        r#""$FLOWCTL" gate check --command='-c echo example'"#,
        r#"flowctl gate receipt --command="echo (git reset --hard)""#,
        r#"flowctl gate check --command 'grep "$HOME" *.rs; git reset --hard'"#,
        r"flowctl gate check --command npm\ test\;\ git\ reset\ --hard",
    ] {
        assert_decision(command, true, None);
    }
}

#[test]
fn unknown_and_dynamic_near_misses_keep_launcher_denial() {
    for command in [
        r#"$tool --command "npm test""#,
        r#"$tool --command="npm test""#,
        r#""$OTHER" gate check --command "npm test""#,
        r#""${FLOWCTL:-sh}" gate check --command "npm test""#,
        r#""$FLOWCTL" gate run --command "npm test""#,
        r#""$FLOWCTL" gate check --command"#,
        r#""$FLOWCTL" gate check --command -c 'echo example'"#,
        r#""$FLOWCTL" gate check --command "npm test" -c 'echo example'"#,
        r#""$FLOWCTL" gate check --command "npm test" --eval='console.log(1)'"#,
        r#""$FLOWCTL" gate check --unknown value --command "npm test""#,
        r"$FLOWCTL gate check --command 'npm test'",
        r#""$FLOWCTL" gate check --command $ARGS"#,
        r#""$FLOWCTL" gate check --command "$ARGS""#,
        r#""$FLOWCTL" gate check --command *.sh"#,
    ] {
        assert_decision(command, false, Some("inline-launcher-unverified"));
    }
}

#[test]
fn genuine_inline_execution_stays_fail_closed() {
    for command in [
        r"$tool -c 'echo example'",
        r"$tool -lc 'echo example'",
        r"$tool -e 'print(1)'",
        r"$tool -Command 'Write-Output example'",
        r#"FLOWCTL=sh; "$FLOWCTL" -c 'git reset --hard'"#,
        r#"FLOWCTL=python3; "$FLOWCTL" -c 'import os; os.system("git reset --hard")'"#,
        r"FLOWCTL='bash -c'; $FLOWCTL gate check --command 'npm test'",
        r#"sh -c "$SCRIPT""#,
        r#"python3 -c "$SCRIPT""#,
        r#"powershell -Command "$SCRIPT""#,
    ] {
        assert_decision(command, false, None);
    }
}

#[test]
fn executable_shell_syntax_is_never_receipt_data() {
    for command in [
        r#""$FLOWCTL" gate check --command "$(git reset --hard)""#,
        r#""$FLOWCTL" gate receipt --command "`git reset --hard`""#,
        r#""$FLOWCTL" gate check --command "npm test"; git reset --hard"#,
        r#""$FLOWCTL" gate check --command "npm test" && git reset --hard"#,
        r#""$FLOWCTL" gate receipt --command "npm test" | sh -c 'git reset --hard'"#,
        r#""$FLOWCTL" gate check --command "npm test" > /etc/profile"#,
        r#""$FLOWCTL" gate check --command 'npm test'>/etc/profile"#,
    ] {
        assert_decision(command, false, None);
    }
}

#[test]
fn literal_command_variables_expand_into_real_git_arguments_540() {
    for command in [
        r"X='git reset --hard'; $X",
        r"X='git reset'; $X --hard",
        r"X='git reset --hard'; ${X}",
        r"X=git\ reset\ --hard; $X",
        "X='git\treset\n--hard'; $X",
        r"X=''; $X git reset --hard",
        r"X=; $X git reset --hard",
    ] {
        assert_decision(command, false, Some("core.git:reset-hard"));
    }
    assert_decision(
        r"X='git clean -fd'; $X",
        false,
        Some("core.git:clean-force"),
    );
    assert_decision(
        r"X='git branch -D'; $X obsolete",
        false,
        Some("core.git:branch-delete"),
    );
    assert_decision(
        r"X='git push'; ${X} --force",
        false,
        Some("core.git:push-force-long"),
    );
}

#[test]
fn quoted_command_variables_and_receipt_values_stay_data_540() {
    for command in [
        r#"X='git reset --hard'; "$X""#,
        r#"X='git reset --hard'; "${X}""#,
        r#"X='git reset --hard'; printf '%s' "$X""#,
        r"X='git status'; $X",
        r"X='git clean -nd'; $X",
        r"X='printf %s git;reset'; $X",
        r#"X='printf'; "$X" '%s' 'git reset --hard'"#,
        r#"X='/opt/a directory/tool'; "$X" --version"#,
        r#"X='flowctl'; "$X" gate check --command 'npm test; git reset --hard'"#,
        r"X=printf; $X '>/dev/null' safe; $X '%s' done",
    ] {
        assert_decision(command, true, None);
    }
}

#[test]
fn unverified_variable_expansion_cannot_hide_executable_source_540() {
    for command in [
        r"IFS=:; X='git:reset:--hard'; $X",
        r"IFS=$CUSTOM; X='git reset --hard'; $X",
        r"X='g* reset --hard'; $X",
        r"X='git reset --hard'; $X; git clean -fd",
        r"X=echo; Y=eval; $Y 'X=git'; $X reset --hard",
        r"X=echo; Y=printf; $Y >/dev/null -v X git; $X reset --hard",
        r#"X=; IFS=${X:=git}; "$X" reset --hard"#,
    ] {
        assert_decision(command, false, None);
    }
}

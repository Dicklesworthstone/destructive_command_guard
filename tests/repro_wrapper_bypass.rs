use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{
    config::Config, evaluator::evaluate_command, load_default_allowlists,
};
use std::io::Write;
use std::process::{Command, Output, Stdio};

#[test]
fn test_wrapper_bypasses() {
    let config = Config::default();
    let compiled_overrides = config.overrides.compile();
    let allowlists = load_default_allowlists();

    // Core packs are enabled by default
    let enabled_packs = config.enabled_pack_ids();
    let keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);

    let destructive_commands = vec![
        "nice rm -rf /",
        "time rm -rf /",
        "nohup rm -rf /",
        "watch rm -rf /",
        "timeout 10s rm -rf /",
        // xargs is harder because it reads from stdin, but "xargs rm -rf" command line exists
        // "xargs rm -rf /" is valid if arguments are appended? No, xargs reads stdin.
        // But "xargs -a file rm -rf" reads from file.
        // Or "xargs sh -c 'rm -rf /'"
    ];

    for cmd in destructive_commands {
        let result = evaluate_command(cmd, &config, &keywords, &compiled_overrides, &allowlists);
        assert!(
            result.is_denied(),
            "Command '{cmd}' should be blocked but was allowed!"
        );
    }
}

/// Exercise the real hook or CLI using command text only. The probe strings
/// are never executed, including the examples that name protected files.
fn wrapper_probe(command: &str, dialect: Option<&str>) -> Output {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    let config = temp.path().join("config.toml");
    std::fs::write(&config, "[history]\nenabled = false\n").expect("config");
    let mut process = Command::new(env!("CARGO_BIN_EXE_dcg"));
    let payload = if let Some(dialect) = dialect {
        process.args(["test", "--dialect", dialect, "--stdin"]);
        command.to_string()
    } else {
        serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": command },
        })
        .to_string()
    };
    let mut child = process
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
        .write_all(payload.as_bytes())
        .expect("write command data");
    let output = child.wait_with_output().expect("wait for dcg");
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("panicked"),
        "wrapper parsing must never panic for {command:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn wrapper_hook(command: &str) -> (String, String) {
    let output = wrapper_probe(command, None);
    assert_eq!(output.status.code(), Some(0), "hook exit for {command:?}");
    if output.stdout.is_empty() {
        return ("allow".to_string(), String::new());
    }
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid hook JSON");
    let decision = &json["hookSpecificOutput"];
    (
        decision["permissionDecision"]
            .as_str()
            .expect("permissionDecision")
            .to_string(),
        decision["ruleId"].as_str().unwrap_or_default().to_string(),
    )
}

#[test]
fn wrapper_option_redirections_reach_the_credential_guard_issue_531() {
    for command in [
        "nice -n > ~/.bashrc",
        "env -u > ~/.bashrc",
        "nice -n >> ~/.ssh/authorized_keys",
        "sudo -u > ~/.ssh/authorized_keys",
        "nice -n >> ~/.ssh/authorized_keys 5 echo ssh-ed25519 AAAA",
        "env -u >> ~/.bashrc FOO echo alias ls=true",
        "stdbuf -o > ~/.bashrc L echo hi",
        "ionice -c > ~/.bashrc 3 echo hi",
        "exec -a > ~/.bashrc name true",
        "env -C > ~/.bashrc /tmp echo hi",
        "sudo -g > ~/.bashrc root echo hi",
        "nice --adjustment > ~/.bashrc 5 echo hi",
        "timeout -s > ~/.bashrc 5 echo hi",
        "time -f > ~/.bashrc %e true",
        "nice -n 2> ~/.bashrc 5 true",
        "nice -n &> ~/.bashrc 5 true",
        // Attached operators are shell syntax, even when the token begins
        // with an otherwise valid option value or inline option.
        "nice -n 5>~/.bashrc echo hi",
        "nice -n5>~/.bashrc echo hi",
        "env --unset=FOO>~/.bashrc echo hi",
        "sudo -uroot>~/.bashrc echo hi",
        "FOO=value>~/.bashrc echo hi",
        // Already protected before #531; preserving the operator must keep
        // the original credential rule attribution.
        "nice -n >~/.bashrc",
        "nice -n 5 > ~/.bashrc",
        "nice > ~/.bashrc -n 5 echo hi",
        "timeout -s > ~/.bashrc",
        "nohup > ~/.bashrc",
        "echo hi > ~/.bashrc",
    ] {
        assert_eq!(
            wrapper_hook(command),
            (
                "deny".to_string(),
                "core.filesystem:credential-file-write".to_string()
            ),
            "the shell performs this write before running the wrapper: {command}"
        );
    }
}

#[test]
fn nested_wrappers_preserve_shell_redirects_issue_531() {
    for command in [
        "sudo nice -n > ~/.bashrc 5 true",
        "X=1 nice -n > ~/.bashrc 5 true",
        "env nice -n > ~/.bashrc 5 true",
        "/usr/bin/nice -n > ~/.bashrc 5 true",
        "bash -c 'nice -n > ~/.bashrc 5 true'",
        "sh -c 'nice -n > ~/.bashrc 5 true'",
        "true && nice -n > ~/.bashrc",
        "(nice -n > ~/.bashrc 5 true)",
        "{ nice -n > ~/.bashrc 5 true; }",
        "nice -n 5 tee ~/.ssh/authorized_keys",
        "sudo -u root tee ~/.bashrc",
        "timeout -s KILL 5 tee ~/.bashrc",
        r"x=$(grep -E 'a|^\s|nice -n|b' f 2>/dev/null; echo hi >~/.bashrc)",
    ] {
        assert_eq!(
            wrapper_hook(command),
            (
                "deny".to_string(),
                "core.filesystem:credential-file-write".to_string()
            ),
            "nested write or valid wrapped writer must remain protected: {command}"
        );
    }
    assert_eq!(
        wrapper_hook("nice -n > /dev/sda 5 true"),
        (
            "deny".to_string(),
            "core.filesystem:redirect-truncate-root-home".to_string()
        )
    );
}

#[test]
fn incomplete_wrapper_options_with_benign_redirects_do_not_panic_issue_521() {
    for command in [
        "nice -n >~/notes.txt",
        "nice -n > ~/notes.txt",
        "sudo -u >~/notes.txt",
        "env -u >~/notes.txt",
        "timeout -s >~/notes.txt",
        "nice --adjustment >~/notes.txt",
        "ionice -c >~/notes.txt",
        "stdbuf -o >~/notes.txt",
        "exec -a >~/notes.txt",
        "doas -u >~/notes.txt",
        "caffeinate -t >~/notes.txt",
        "nice -n 2>~/notes.txt",
        "nice -n 5 -n >~/notes.txt",
        "nice -n > /tmp/repro/notes.txt 5 echo hi",
        "nice -n 5 echo hi > ~/notes.txt",
        "nice -n 5 >~/notes.txt",
        "nice -n >/tmp/notes.txt",
        r"x=$(grep -E 'a|^\s|nice -n|b' f 2>/dev/null)",
    ] {
        assert_eq!(
            wrapper_hook(command),
            ("allow".to_string(), String::new()),
            "an incomplete wrapper does not make a benign target dangerous: {command}"
        );
    }
}

#[test]
fn wrappers_still_expose_the_actual_inner_command_issue_531() {
    for command in [
        "nice -n 5 git reset --hard",
        "sudo -u root git reset --hard",
        "env -u FOO git reset --hard",
        "nice -n >/tmp/out 5 git reset --hard",
        "nice -n 5 git reset --hard >/tmp/out",
    ] {
        assert_eq!(
            wrapper_hook(command),
            ("deny".to_string(), "core.git:reset-hard".to_string()),
            "wrapper normalization must preserve the executed command: {command}"
        );
    }
    for command in [
        "nice -n 5 echo hi",
        "sudo -p 'password > ' git status",
        "exec -a '>' git status",
        "time -f '>%e' git status",
    ] {
        assert_eq!(
            wrapper_hook(command),
            ("allow".to_string(), String::new()),
            "literal wrapper values must stay usable: {command}"
        );
    }
}

#[test]
fn malformed_wrapper_options_return_normal_cli_decisions_issue_521() {
    for (command, dialect) in [
        ("nice -n >~/notes.txt", "posix"),
        ("env -u >~/notes.txt", "posix"),
        (r"x=$(grep -E 'a|^\s|nice -n|b' f 2>/dev/null)", "unknown"),
    ] {
        let output = wrapper_probe(command, Some(dialect));
        assert_eq!(
            output.status.code(),
            Some(0),
            "CLI must allow benign input without aborting: {command:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

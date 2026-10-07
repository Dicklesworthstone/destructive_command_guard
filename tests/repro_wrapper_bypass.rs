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
    configured_wrapper_probe(command, dialect, "[history]\nenabled = false\n")
}

fn configured_wrapper_probe(command: &str, dialect: Option<&str>, config_toml: &str) -> Output {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    let config = temp.path().join("config.toml");
    std::fs::write(&config, config_toml).expect("config");
    std::fs::write(temp.path().join("safe.sql"), "SELECT 1;\n").expect("safe local SQL");
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
    wrapper_hook_decision(command, &output)
}

fn wrapper_hook_decision(command: &str, output: &Output) -> (String, String) {
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

fn tar_hook(command: &str) -> (String, String) {
    let output = configured_wrapper_probe(
        command,
        None,
        "[history]\nenabled = false\n[packs]\nenabled = \
         [\"core.filesystem\", \"core.git\", \"database.postgresql\"]\n",
    );
    wrapper_hook_decision(command, &output)
}

fn assert_tar_denied(command: &str, rule: &str) {
    assert_eq!(
        tar_hook(command),
        ("deny".to_string(), rule.to_string()),
        "tar's executed helper must retain its own rule: {command}"
    );
}

fn assert_tar_allowed(command: &str) {
    assert_eq!(
        tar_hook(command),
        ("allow".to_string(), String::new()),
        "tar helper data and proven safe execution must remain usable: {command}"
    );
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

#[test]
fn tar_checkpoint_actions_reach_nested_rules_after_tar_decoding() {
    for command in [
        "tar -cf out.tar --checkpoint-action='exec=git reset --hard' file",
        "tar -cf out.tar --checkpoint=0 --checkpoint-action='exec=git reset --hard' file",
        "tar -cf out.tar --checkpoint-action 'exec=git reset --hard' file",
        "tar -cf out.tar --checkpoint-act='exec=git reset --hard' file",
        // All checkpoint actions execute, in order; neither a preceding nor
        // a following harmless action cancels a destructive one.
        "tar -cf out.tar --checkpoint-action='exec=git status' --checkpoint-action='exec=git reset --hard' file",
        "tar -cf out.tar --checkpoint-action='exec=git reset --hard' --checkpoint-action='exec=git status' file",
        "tar -cf out.tar --checkpoint-action='exec=git stash drop' --checkpoint-action='exec=git reset --hard' file",
        // GNU tar unquotes checkpoint commands before passing them to sh.
        r"tar -cf out.tar --checkpoint-action='exec=\147it reset --hard' file",
        r#"tar -cf out.tar --checkpoint-action='exec="git reset --hard"' file"#,
    ] {
        assert_tar_denied(command, "core.git:reset-hard");
    }
    assert_tar_denied(
        "tar -cf out.tar --checkpoint-action='exec=rm -rf /' file",
        "core.filesystem:rm-rf-root-home",
    );
}

#[test]
fn tar_extraction_compression_and_volume_helpers_are_execution() {
    for command in [
        "tar -xf input.tar --to-command='git reset --hard'",
        "tar -xf input.tar --to-command 'git reset --hard'",
        "tar -xf input.tar --to-com='git reset --hard'",
        "tar -cf out.tar --use-compress-program='git reset --hard' file",
        "tar -cf out.tar --use-compress-prog 'git reset --hard' file",
        "tar -cf out.tar -I'git reset --hard' file",
        "tar -cf out.tar -I 'git reset --hard' file",
        // Compression runs a shell, whereas decompression invokes argv.
        "tar -cf out.tar -I 'echo safe; git reset --hard' file",
        "tar -xf input.tar -I 'sh -c \"git reset --hard\"'",
        "tar -cf out.tar --info-script='git reset --hard' file",
        "tar -cf out.tar --new-volume-script='git reset --hard' file",
        "tar -cf out.tar -F'git reset --hard' file",
    ] {
        assert_tar_denied(command, "core.git:reset-hard");
    }
    // Neither echo text nor an argv operand becomes a second command when
    // the helper is launched without a shell in decompression mode.
    assert_tar_allowed("tar -xf input.tar -I 'echo safe; git reset --hard'");
}

#[test]
fn tar_helper_option_ownership_survives_wrappers_and_bundles() {
    for command in [
        "tar cIf 'git reset --hard' out.tar file",
        "tar cfI out.tar 'git reset --hard' file",
        "tar -cI'git reset --hard' -f out.tar file",
        // GNU tar continues parsing options after member operands.
        "tar -cf out.tar file --checkpoint-action='exec=git reset --hard'",
        "env MODE=test tar -cf out.tar --checkpoint-action='exec=git reset --hard' file",
        "sudo -u other tar -xf input.tar --to-command='git reset --hard'",
        "/usr/bin/tar -cf out.tar --checkpoint-action='exec=git reset --hard' file",
        "gtar -cf out.tar --checkpoint-action='exec=git reset --hard' file",
        "t'ar' -cf out.tar --checkpoint-action='exec=git reset --hard' file",
        // No contiguous `tar` elsewhere may accidentally satisfy a raw
        // trigger when quoting splits the actual executable name.
        "t'ar' -cf out --checkpoint-action='exec=git reset --hard' file",
        "2>/dev/null tar -xf input.tar --to-command='git reset --hard'",
        "tar -xf input.tar 2>/dev/null --to-command='git reset --hard'",
        // A local data redirect beside the helper must not consume its argv.
        "tar -xf input.tar --to-command='git reset --hard' > /dev/null",
    ] {
        assert_tar_denied(command, "core.git:reset-hard");
    }
    assert_tar_denied(
        "tar -xf input.tar --to-command=cat > ~/.ssh/authorized_keys",
        "core.filesystem:credential-file-write",
    );
}

#[test]
fn tar_dynamic_helpers_and_unverified_option_environments_fail_closed() {
    for command in [
        "tar -cf out.tar --checkpoint-action=\"exec=$HELPER\" file",
        "tar -cf out.tar --checkpoint-action=\"$ACTION\" file",
        "tar -xf input.tar --to-command=\"$HELPER\"",
        "tar -cf out.tar -I \"$HELPER\" file",
        "tar -cf out.tar --info-script=\"$HELPER\" file",
        // TAR_OPTIONS contributes options before the explicit command line.
        "TAR_OPTIONS='--checkpoint-action=exec=git\\ reset\\ --hard' tar -cf out.tar file",
        "TAR_OPTIONS=\"$OPTIONS\" tar -cf out.tar file",
        "env TAR_OPTIONS='--to-command=git\\ reset\\ --hard' tar -xf input.tar",
        "tar -cf host:out --rsh-command=\"$RSH\" file",
    ] {
        assert_tar_denied(command, "core.filesystem:tar-exec-unverified");
    }
    assert_tar_allowed("TAR_OPTIONS= tar -cf out.tar file");
    assert_tar_denied(
        "tar -cf host:out --rsh-command=\"$RSH\" --rmt-command='git reset --hard' file",
        "core.git:reset-hard",
    );
    assert_tar_allowed("TAR_OPTIONS='--to-command=git reset --hard' printf done");
    assert_tar_denied(
        "TAR_OPTIONS=\"--checkpoint-action='exec=git reset --hard'\" tar -cf out file",
        "core.git:reset-hard",
    );
    assert_tar_allowed("TAR_OPTIONS='--verbose' tar -cf out file");
}

#[test]
fn tar_helper_data_options_and_inactive_helpers_remain_allowed() {
    for command in [
        "tar -cf out.tar --checkpoint-action='echo=git reset --hard' file",
        "tar -cf out.tar --checkpoint-action='exec=git status' file",
        "tar -xf input.tar --to-command='printf \"git reset --hard\"'",
        "tar -xf input.tar --to-command=cat",
        "tar -cf out.tar -I 'gzip -9' file",
        "tar -cf out.tar --info-script='printf next-volume' file",
        // Proven overrides replace the old helper; only uncertain option
        // ownership requires keeping both candidates for review.
        "tar -cf out --info-script='git reset --hard' --info-script='printf safe' file",
        "tar -cf host:out --rmt-command='git reset --hard' --rmt-command='/usr/libexec/rmt' file",
        "TAR_OPTIONS=\"--use-compress-program='git reset --hard'\" tar -czf out file",
        "TAR_OPTIONS=\"--use-compress-program='git reset --hard'\" tar -cf out -I gzip file",
        // -O selects stdout before the extraction helper, regardless of order.
        "tar -xOf input.tar --to-command='git reset --hard'",
        "tar -xf input.tar --to-command='git reset --hard' --to-stdout",
        "tar -tf input.tar --to-command='git reset --hard'",
        "tar -cf '--to-command=git reset --hard' file",
        "tar cf '--checkpoint-action=exec=git reset --hard' file",
        "tar -cf out.tar --exclude '--checkpoint-action=exec=git reset --hard' file",
        "tar -cf out.tar -- '--checkpoint-action=exec=git reset --hard'",
        "tar -cf out.tar -- '--to-command=git reset --hard'",
        "tar -czf out.tar ./src",
        "tar -xf input.tar -C ./build",
        "printf '%s' \"tar --to-command='git reset --hard'\"",
        // BSD tar's -I names a member-list file, not a GNU compressor.
        "bsdtar -xf input.tar -I 'git reset --hard'",
    ] {
        assert_tar_allowed(command);
    }
}

#[test]
fn tar_helpers_cannot_treat_archive_input_as_interactive_stdin() {
    for command in [
        "tar -xf input.tar --to-command='sh'",
        "tar -xf input.tar --to-command='psql -X'",
        "tar -xf input.tar --to-command='sh -c \"psql -X\"'",
        "tar -xf input.tar -I 'sh'",
        "tar -cf out.tar -I 'psql -X' file",
    ] {
        assert_tar_denied(command, "core.filesystem:tar-exec-unverified");
    }
    assert_tar_denied(
        "tar -xf input.tar --to-command='psql -X -c \"DROP TABLE important_data;\"'",
        "database.postgresql:drop-table",
    );
    for command in [
        "tar -xf input.tar --to-command='psql -X -c \"SELECT 1;\"'",
        "tar -tf input.tar --checkpoint-action='exec=psql -X -f safe.sql'",
        // GNU tar -C changes its directory fd, not its helper's process cwd.
        "tar -tf input.tar -C other --checkpoint-action='exec=psql -X -f safe.sql'",
        "tar -tf input.tar --index-file=/dev/null --checkpoint-action='exec=psql -X -f safe.sql'",
        "tar -tf input.tar --checkpoint-action='exec=psql -X -f safe.sql' >/dev/null",
        "tar -tf input.tar --checkpoint-action='exec=psql -X -f safe.sql' 2>&1",
    ] {
        assert_tar_allowed(command);
    }
    for command in [
        // Read-only archives isolate the wrapper's changed environment from
        // the independent mutation risk of a writing tar operation.
        "env -C other tar -tf input.tar --checkpoint-action='exec=psql -X -f safe.sql'",
        "sudo -u other tar -tf input.tar --checkpoint-action='exec=psql -X -f safe.sql'",
        // Archive writes can replace code after inspection, including before
        // a checkpoint or volume callback consumes that code.
        "tar -cf out.tar --checkpoint-action='exec=psql -X -f safe.sql' file",
        "tar -cf safe.sql --checkpoint-action='exec=psql -X -f safe.sql' file",
        "tar -xf input.tar --checkpoint-action='exec=psql -X -f safe.sql'",
        "tar -rf out.tar --checkpoint-action='exec=psql -X -f safe.sql' file",
        "tar -xf input.tar --info-script='psql -X -f safe.sql'",
        // List mode still writes through explicit output files and the
        // caller's redirects, so the inspected SQL can change before use.
        "tar -tf input.tar --index-file=safe.sql --checkpoint-action='exec=psql -X -f safe.sql'",
        "tar -tf input.tar --volno-file=safe.sql --checkpoint-action='exec=psql -X -f safe.sql'",
        "tar -tf input.tar --checkpoint-action='exec=psql -X -f safe.sql' >safe.sql",
        "(tar -tf input.tar --checkpoint-action='exec=psql -X -f safe.sql') >safe.sql",
    ] {
        assert_tar_denied(command, "database.postgresql:stdin-unverified");
    }
}

#[test]
fn tar_remote_archive_helpers_keep_remote_scope_and_activation() {
    assert_tar_denied(
        "TAPE=host:archive tar -c --rmt-command='git reset --hard' file",
        "core.git:reset-hard",
    );
    assert_tar_denied(
        "tar -cf host:out.tar --rmt-command='git reset --hard' file",
        "core.git:reset-hard",
    );
    assert_tar_denied(
        "tar -cf host:out.tar --rmt-command='echo x > ~/new-note' file",
        "core.filesystem:redirect-truncate-root-home",
    );
    assert_tar_denied(
        "tar -tf host:input.tar --rmt-command='psql -X -f safe.sql'",
        "database.postgresql:stdin-unverified",
    );
    for command in [
        "tar -cf out.tar --rmt-command='git reset --hard' file",
        "tar --force-local -cf host:out.tar --rmt-command='git reset --hard' file",
        "tar -cf host:out.tar --rmt-command='/usr/libexec/rmt' file",
        // rsh-command is one executable path, not a shell command string.
        "tar -cf host:out.tar --rsh-command='git reset --hard' file",
    ] {
        assert_tar_allowed(command);
    }
}

#[test]
fn tar_helper_cli_decisions_preserve_posix_and_unknown_dialects() {
    for dialect in ["posix", "unknown"] {
        for (command, expected_exit) in [
            (
                "tar -cf out.tar --checkpoint-action='exec=git reset --hard' file",
                1,
            ),
            ("tar -xf input.tar -I 'echo safe; git reset --hard'", 0),
        ] {
            let output = wrapper_probe(command, Some(dialect));
            assert_eq!(
                output.status.code(),
                Some(expected_exit),
                "{dialect}: {command:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

#[test]
fn tar_analysis_bounds_remain_closed_without_the_filesystem_pack() {
    // Exceeds the shared 32-source bound using harmless but executable
    // callbacks. Disabling a pack cannot turn incomplete analysis into allow.
    let command = format!(
        "tar -cf out {} file",
        "--checkpoint-action=exec=true ".repeat(34)
    );
    let output = configured_wrapper_probe(
        &command,
        None,
        "[history]\nenabled = false\n[packs]\nenabled = [\"core.git\"]\ndisabled = [\"core.filesystem\"]\n",
    );
    let (decision, _) = wrapper_hook_decision(&command, &output);
    assert_eq!(
        decision, "deny",
        "tar analysis limit must remain fail-closed"
    );
}

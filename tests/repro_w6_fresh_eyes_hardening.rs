//! Real-binary CLI + PreToolUse hook tests for Fresh-Eyes hardening of
//! PowerShell comment/here-string dynamic calls, POSIX use-site wrappers,
//! attribute-removal declarations, bracket array-subscript mutation,
//! odd-caret cmd elision, subshell/overflow binding soundness, Windows py
//! launcher selectors, and sudo --preserve-env exact name matching.

use std::io::Write;
use std::process::{Command, Stdio};

fn dcg_test_verdict_with_config(
    command: &str,
    dialect: &str,
    config_toml: Option<&str>,
) -> serde_json::Value {
    let scratch = tempfile::tempdir().expect("scratch dir");
    let home = scratch.path().join("home");
    std::fs::create_dir(&home).expect("home dir");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dcg"));
    cmd.args(["test", "--stdin", "--dialect", dialect, "--format", "json"])
        .env_clear()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_CUSTOM_PATHS", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("DCG_HISTORY_DISABLED", "1")
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .env("DCG_AST_TIMEOUT_MS", "5000")
        .env("DCG_HEREDOC_TIMEOUT_MS", "5000")
        .current_dir(scratch.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(toml) = config_toml {
        let cfg_path = scratch.path().join("config.toml");
        std::fs::write(&cfg_path, toml).expect("write config");
        cmd.env("DCG_CONFIG", &cfg_path);
    }

    let mut child = cmd.spawn().expect("spawn dcg test");
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

fn dcg_test_verdict(command: &str, dialect: &str) -> serde_json::Value {
    dcg_test_verdict_with_config(command, dialect, None)
}

fn hook_decision_with_config(
    command: &str,
    tool_name: &str,
    config_toml: Option<&str>,
) -> (String, String) {
    let scratch = tempfile::tempdir().expect("scratch dir");
    let home = scratch.path().join("home");
    std::fs::create_dir(&home).expect("home dir");
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": { "command": command }
    })
    .to_string();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dcg"));
    cmd.env_clear()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_CUSTOM_PATHS", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("DCG_HISTORY_DISABLED", "1")
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .env("DCG_AST_TIMEOUT_MS", "5000")
        .env("DCG_HEREDOC_TIMEOUT_MS", "5000")
        .current_dir(scratch.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(toml) = config_toml {
        let cfg_path = scratch.path().join("config.toml");
        std::fs::write(&cfg_path, toml).expect("write config");
        cmd.env("DCG_CONFIG", &cfg_path);
    }

    let mut child = cmd.spawn().expect("spawn dcg hook");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(payload.as_bytes())
        .expect("write hook payload");
    let output = child.wait_with_output().expect("wait dcg hook");
    assert!(
        output.status.success(),
        "hook exited non-zero for {command:?}: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        return ("allow".to_string(), String::new());
    }
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("invalid hook JSON for {command:?}: {err}\nstdout={stdout}"));
    let decision = parsed["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or("allow")
        .to_string();
    let rule = parsed["hookSpecificOutput"]["ruleId"]
        .as_str()
        .unwrap_or("")
        .to_string();
    (decision, rule)
}

fn hook_decision(command: &str, tool_name: &str) -> (String, String) {
    hook_decision_with_config(command, tool_name, None)
}

#[test]
fn powershell_comment_and_here_string_dynamic_call_bypasses_are_denied() {
    let attacks = [
        "# \"\n& ('gi'+'t') reset --hard",
        "<# \"\n#> & ('gi'+'t') reset --hard",
        "# \"\n& ('{0}{1}' -f 'gi','t') push -f",
        "<# \"\n#> & ('{0}{1}' -f 'gi','t') push -f",
        "echo ok && & ('gi'+'t') reset --hard",
        "@\"\n\"\n\"@\n& ('gi'+'t') reset --hard",
        "@\"\n$(& ('gi'+'t') reset --hard)\n\"@",
        "& <# c #> ('gi'+'t') reset --hard",
        "$x = <# c #> & ('gi'+'t') reset --hard",
        "echo \"# not a comment\"; & ('gi'+'t') reset --hard",
        "echo 'it''s' ; & ('gi'+'t') reset --hard",
        "<# \"\n#> & ('gi'+'t') branch -D main",
    ];
    for cmd in attacks {
        for dialect in ["powershell", "unknown"] {
            let v = dcg_test_verdict(cmd, dialect);
            assert_eq!(
                v["decision"], "deny",
                "CLI ({dialect}) must deny PowerShell dynamic call bypass: {cmd:?} -> {v}"
            );
        }
        let (hd, _rule) = hook_decision(cmd, "PowerShell");
        assert_eq!(hd, "deny", "PowerShell hook must deny: {cmd:?}");
    }

    let benign_ps = [
        "# & ('gi'+'t') reset --hard\necho ok",
        "<# & ('gi'+'t') reset --hard #>\necho ok",
        "@'\n& ('gi'+'t') reset --hard\n'@\necho ok",
    ];
    for cmd in benign_ps {
        let v = dcg_test_verdict(cmd, "powershell");
        assert_eq!(
            v["decision"], "allow",
            "benign PowerShell must allow: {cmd:?} -> {v}"
        );
        let (hd, _) = hook_decision(cmd, "PowerShell");
        assert_eq!(hd, "allow", "benign PowerShell hook must allow: {cmd:?}");
    }
    let posix_bg = dcg_test_verdict("echo a & (echo b)", "unknown");
    assert_eq!(
        posix_bg["decision"], "allow",
        "benign POSIX background must allow: {posix_bg}"
    );
}

#[test]
fn posix_use_site_wrappers_exec_env_sudo_command_are_hardened() {
    let deny_cases = [
        "G=git; exec -ca fake $G reset --hard",
        "G=git; exec -la fake $G reset --hard",
        "G=git; exec -afake $G reset --hard",
        "G=git; exec -cafake $G reset --hard",
        "env --ignore-signal git reset --hard",
        "env --block-signal git reset --hard",
        "env --default-signal git reset --hard",
        "env --list-signal-handling git reset --hard",
        "G=git; env --ignore-signal $G reset --hard",
        "G=git; env --block-signal $G reset --hard",
        "G=git; env --default-signal $G reset --hard",
        "G=git; env --list-signal-handling $G reset --hard",
        "env -S \"-i\" git reset --hard",
        "env -S \"-C /tmp\" git reset --hard",
        "G=git; env -S \"-i\" $G reset --hard",
        "G=git; env -iS \"$G reset --hard\"",
        "G=git; env -S \"--\" $G reset --hard",
        "G=git; env -S \"-u HOME\" $G reset --hard",
        "G=git; sudo -R / $G reset --hard",
        "G=git; sudo --chroot / $G reset --hard",
        "G=git; sudo --preserve-env=HOME $G reset --hard",
        "G=git; command -pp $G reset --hard",
        "G=git; nohup -- $G reset --hard",
        "G=git; builtin command $G reset --hard",
    ];
    for cmd in deny_cases {
        for dialect in ["posix", "unknown"] {
            let v = dcg_test_verdict(cmd, dialect);
            assert_eq!(
                v["decision"], "deny",
                "CLI ({dialect}) must deny wrapper bypass: {cmd:?} -> {v}"
            );
        }
        let (hd, _) = hook_decision(cmd, "Bash");
        assert_eq!(hd, "deny", "Bash hook must deny wrapper bypass: {cmd:?}");
    }

    let allow_cases = [
        "G=echo; exec -ca fake $G hello",
        "G=echo; env --ignore-signal $G hello",
        "G=echo; env -S \"-i\" $G hello",
        "G=git; command -pv $G",
        "G=git; command -pV $G",
        "G=git; sudo -l $G",
        "G=git; sudo --list $G",
        "G=git; sudo -K $G",
    ];
    for cmd in allow_cases {
        let v = dcg_test_verdict(cmd, "posix");
        assert_eq!(
            v["decision"], "allow",
            "benign wrapper case must allow: {cmd:?} -> {v}"
        );
        let (hd, _) = hook_decision(cmd, "Bash");
        assert_eq!(hd, "allow", "benign wrapper hook must allow: {cmd:?}");
    }
}

#[test]
fn declaration_attribute_removal_and_bracket_and_caret_edge_cases() {
    let deny_cases = [
        "declare +x d=git; $d reset --hard",
        "typeset +x d=git; $d reset --hard",
        "local +x d=git; $d reset --hard",
        "declare +r d=git; $d reset --hard",
        "declare +g d=git; $d reset --hard",
        "declare +i d=git; $d reset --hard",
        "export -n d=git; $d reset --hard",
        "declare -i d=1; $d reset --hard",
        "d=echo; [[ -v arr[d=1] ]] && $d /dev/sda",
        "d=echo; [[ -v \"arr[d=1]\" ]] && $d /dev/sda",
        "d=echo; [[ -R ref ]] && $d /dev/sda",
        "d=echo; d=git :; $d reset --hard",
        "d=echo; d=mkfs.ext4 :; $d /dev/sda",
        "d=mkfs.ext4; [[ -v arr[d=1] ]] && $d /dev/sda",
        "d=mkfs.ext4; [[ \"$a\" == \"$b\" ]] && $d /dev/sda",
        "d=echo; [[ \"$a\" == \"${d:=mkfs.ext4}\" ]] && $d /dev/sda",
        "d=mkfs.ext4; d=echo | cat; $d /dev/sda",
        "d=mkfs.ext4; d=echo & true; $d /dev/sda",
    ];
    for cmd in deny_cases {
        let v = dcg_test_verdict(cmd, "posix");
        assert_eq!(v["decision"], "deny", "must deny: {cmd:?} -> {v}");
        let (hd, _) = hook_decision(cmd, "Bash");
        assert_eq!(hd, "deny", "Bash hook must deny: {cmd:?}");
    }

    let mut overflow_cmd = String::from("v0=mkfs.ext4; ");
    for i in 0..66 {
        use std::fmt::Write as _;
        let _ = write!(overflow_cmd, "a{i}=echo; ");
    }
    overflow_cmd.push_str("false && v0=echo; $v0 /dev/sda");
    let v_ov = dcg_test_verdict(&overflow_cmd, "posix");
    assert_eq!(
        v_ov["decision"], "deny",
        "overflow + branch must deny: {v_ov}"
    );
    let (hd_ov, _) = hook_decision(&overflow_cmd, "Bash");
    assert_eq!(hd_ov, "deny", "Bash hook overflow + branch must deny");

    let v_caret = dcg_test_verdict("g^%x%it reset --hard", "cmd");
    assert_eq!(
        v_caret["decision"], "deny",
        "cmd single-caret elision must deny: {v_caret}"
    );
    let v_caret3 = dcg_test_verdict("rm^%x% -rf /", "cmd");
    assert_eq!(
        v_caret3["decision"], "deny",
        "cmd odd-caret elision must deny: {v_caret3}"
    );
    let (hd_caret3, _) = hook_decision("r^%x%m^%y% -rf /", "Cmd");
    assert_eq!(hd_caret3, "deny", "Cmd hook odd-caret elision must deny");

    let allow_cases = [
        "declare +x d=echo; $d hello",
        "typeset +x d=echo; $d hello",
        "export -n d=echo; $d hello",
        "d=echo; [[ -d .git ]] && $d ok",
        "d=echo; [[ -f Cargo.toml ]] && $d ok",
        "d=echo; [[ \"$a\" == \"$b\" ]] && $d ok",
    ];
    for cmd in allow_cases {
        let v = dcg_test_verdict(cmd, "posix");
        assert_eq!(
            v["decision"], "allow",
            "benign case must allow: {cmd:?} -> {v}"
        );
        let (hd, _) = hook_decision(cmd, "Bash");
        assert_eq!(hd, "allow", "benign Bash hook must allow: {cmd:?}");
    }
}

#[test]
fn windows_py_launcher_and_sudo_preserve_env_exact_match() {
    let py_payload = "'import os; os.system(\"rm -rf /\")'";
    for py_cmd in [
        format!("{py_payload} | py -V:3.12 -"),
        format!("{py_payload} | py -3.12-arm64 -"),
    ] {
        let v = dcg_test_verdict(&py_cmd, "powershell");
        assert_eq!(
            v["decision"], "deny",
            "PowerShell CLI must deny py selector: {py_cmd} -> {v}"
        );
        let (hd, _) = hook_decision(&py_cmd, "PowerShell");
        assert_eq!(
            hd, "deny",
            "PowerShell hook must deny py selector: {py_cmd}"
        );
    }
    let benign_py = format!("{py_payload} | py -V");
    let v_py_v = dcg_test_verdict(&benign_py, "powershell");
    assert_eq!(
        v_py_v["decision"], "allow",
        "bare py -V must allow: {v_py_v}"
    );

    let sys_cfg = "[packs]\nenabled = [\"system.services\"]\n";
    let bypass_modprobe =
        "MODPROBE_OPTIONS=-n sudo --preserve-env=\" MODPROBE_OPTIONS\" modprobe -r nvidia";
    let v_mp = dcg_test_verdict_with_config(bypass_modprobe, "posix", Some(sys_cfg));
    assert_eq!(
        v_mp["decision"], "deny",
        "leading-space --preserve-env must NOT suppress modprobe -r denial: {v_mp}"
    );
    let (hd_mp, _) = hook_decision_with_config(bypass_modprobe, "Bash", Some(sys_cfg));
    assert_eq!(
        hd_mp, "deny",
        "Bash hook must deny space-padded --preserve-env modprobe -r"
    );

    let safe_modprobe =
        "MODPROBE_OPTIONS=-n sudo --preserve-env=MODPROBE_OPTIONS modprobe -r nvidia";
    let v_mp_ok = dcg_test_verdict_with_config(safe_modprobe, "posix", Some(sys_cfg));
    assert_eq!(
        v_mp_ok["decision"], "allow",
        "exact --preserve-env=MODPROBE_OPTIONS dry-run must allow: {v_mp_ok}"
    );
}

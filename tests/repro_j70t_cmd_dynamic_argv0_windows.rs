//! bd-cmd-dynamic-argv0-windows-rules-j70t: `%VAR%` (including always-empty
//! `%PATH:~0,0%`) and `!VAR!` expansions inside cmd.exe program names must not
//! skip `windows.filesystem`, `windows.system`, or `windows.misc` rules, while
//! keeping benign cmd commands and read-only operations allowed.
//!
//! Exercises the real compiled `dcg` binary through both `dcg test` (`cmd` and
//! `unknown` dialects) and the PreToolUse hook JSON stdin protocol (`cmd` and
//! `Bash` tools). No commands execute: they are only classified.

use std::io::Write;
use std::process::{Command, Stdio};

const WINDOWS_PACKS: &str = "core.git,core.filesystem,system.services,windows.filesystem,windows.system,windows.misc,windows.powershell";

const DESTRUCTIVE_DENY_CONTROLS: &[&str] = &[
    // windows.filesystem: rmdir/rd/del/format with %VAR%, !VAR!, glued switches,
    // variable-name separators/spaces, and unquoted split prefixes
    r"r%x%md /s /q C:\",
    r"r%PATH:~0,0%md /s /q C:\",
    r"r%x%mdir /s /q C:\",
    r"rm%x%dir /s /q C:\",
    r"r%x%d /s /q C:\",
    r"R%x%MDIR /S /Q C:\",
    r"r%PATH:~0, 0%mdir /s /q C:\",
    r"r%NAME\WITH\SEP%mdir /s /q C:\",
    r"r%NAME&WITH|PUNCT%mdir /s /q C:\",
    r"r%x%mdir/s/q C:\",
    r"r%x%d/s/q C:\",
    r"d%x%el/s/q C:\",
    r"call r%x%mdir/s/q C:\",
    r"ca%x%ll r%x%md /s /q C:\",
    r"ca%x%ll r%x%mdir/s/q C:\",
    r"C:\Windows\System32\r%x%md /s /q C:\",
    r"r!x!mdir /s /q C:\",
    r"form%x%at C:",
    r"form%x%at/q C:",
    // windows.system: vssadmin + wbadmin + wmic + diskpart + cipher + bcdedit + fsutil
    r"vssad%x%min delete shadows /all",
    r"vssad%PATH:~0,0%min delete shadows /all",
    r"vssad%x%min.exe delete shadows /all",
    r"VSSAD%x%MIN DELETE SHADOWS /ALL",
    r"C:\Windows\System32\vssad%x%min.exe delete shadows /all",
    r"vssad!x!min delete shadows /all",
    r"wba%x%dmin delete catalog",
    r"wba%PATH:~0,0%dmin delete backup -keepVersions:0",
    r"wm%x%ic shadowcopy delete",
    r"diskp%x%art /s wipe.txt",
    r"ciph%x%er /w:C:",
    r"bcde%x%dit /delete {current}",
    r"fsut%x%il file setzerodata offset=0 length=4096 C:\data.db",
    r"fsut%x%il volume dismount C:",
    // windows.misc: reg, net, sc, schtasks, wsl, robocopy
    r"re%x%g delete HKLM\Software\Foo /f",
    r"re%PATH:~0,0%g delete HKLM\Software\Foo /f",
    r"RE%x%G.EXE DELETE HKLM\Software\Foo /f",
    r"C:\Windows\System32\re%x%g.exe delete HKLM\Software\Foo /f",
    r"re%x%g delete HKLM\Software\reg\Foo /f",
    r"reg query HKLM\Foo & re%x%g delete HKLM\Bar /f",
    r#"re"%x%"g delete HKLM\Software\Foo /f"#,
    r"re!x!g delete HKLM\Software\Foo /f",
    r"call re%x%g delete HKLM\Software\Foo /f",
    r"ca%x%ll re%x%g delete HKLM\Software\Foo /f",
    r"ca%x%ll vssad%x%min delete shadows /all",
    r"2>nul re%x%g delete HKLM\Software\Foo /f",
    r"ne%x%t user alice /delete",
    r"s%x%c delete MyService",
    r"r%x%mdir /%y%s/q C:\",
    r"echo %undefined & re%x%g delete HKLM\Software\Foo /f & tail%",
    r"ws%x%l --unregister Ubuntu",
    r"roboc%x%opy C:\src D:\dst /MIR",
    // Delayed expansion in core.git + cmd /c wrapper
    r"gi!x!t reset --hard",
    r#"cmd /c "r%x%md /s /q C:\""#,
    r#"cmd /c "r%x%mdir /s /q C:\""#,
    r#"cmd /c "vssad%x%min delete shadows /all""#,
    r#"cmd /c "re%x%g delete HKLM\Software\Foo /f""#,
    r#"cmd /v:on /c "re!x!g delete HKLM\Software\Foo /f""#,
];

const BENIGN_CMD_CORPUS: &[&str] = &[
    r"echo %PATH%",
    r"dir %USERPROFILE%",
    r"dir /s %USERPROFILE%",
    r"set FOO=%BAR%",
    r"rd /?",
    r"rmdir /?",
    r"r%x%mdir /?",
    r"r%x%md /?",
    r"r%x%md C:\empty_dir",
    r#""r%x%md" /s /q C:\"#,
    r"vssadmin list shadows",
    r"vssad%x%min list shadows",
    r"vssad%x%min /?",
    r"reg query HKLM\Software\Foo",
    r"re%x%g query HKLM\Software\Foo",
    r"re%x%g export HKLM\Software\Foo backup.reg",
    r"sc query MyService",
    r"s%x%c query MyService",
    r"wsl --list --verbose",
    r"ws%x%l --list --verbose",
    r"schtasks /query /tn MyTask",
    r"schta%x%sks /query /tn MyTask",
    r"robocopy C:\src D:\dst /E",
    r"roboc%x%opy C:\src D:\dst /E",
    r"net user alice",
    r"ne%x%t user alice",
    r#"echo "vssad%x%min delete shadows /all""#,
    r#"echo "r%x%mdir /s /q C:\""#,
    r#"echo "re%x%g delete HKLM\Software\Foo /f""#,
    r#"git commit -m "vssad%x%min delete shadows /all""#,
    r"%LOGGER% rmmod nvidia",
    r"vssad^!LITERAL^!%EMPTY%min delete shadows /all",
    r"run_%ENV%.exe /s",
    r"deploy_%ENV%.cmd /s",
    r"echo 50% off 20%",
];

fn dcg_test_verdict(command: &str, dialect: &str) -> serde_json::Value {
    let scratch = tempfile::tempdir().expect("scratch dir");
    let home = scratch.path().join("home");
    std::fs::create_dir_all(&home).expect("isolated home");
    let config = scratch.path().join("config.toml");
    std::fs::write(&config, "[heredoc]\nenabled = true\ntimeout_ms = 5000\n")
        .expect("write config");
    let output = Command::new(env!("CARGO_BIN_EXE_dcg"))
        .args(["test", "--config"])
        .arg(&config)
        .args(["--with-packs", WINDOWS_PACKS, "--dialect", dialect])
        .args(["--format", "json", command])
        .env_clear()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("DCG_HISTORY_DISABLED", "1")
        .env("DCG_AST_TIMEOUT_MS", "5000")
        .env("DCG_CUSTOM_PATHS", "")
        .current_dir(scratch.path())
        .output()
        .expect("run dcg test");
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{command:?} {dialect}: {error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
    })
}

fn hook_denies(command: &str, tool_name: &str) -> (bool, String) {
    let scratch = tempfile::tempdir().expect("scratch dir");
    let home = scratch.path().join("home");
    std::fs::create_dir_all(&home).expect("isolated home");
    let config = scratch.path().join("config.toml");
    std::fs::write(
        &config,
        "[packs]\nenabled = [\"core.git\", \"core.filesystem\", \"system.services\", \"windows.filesystem\", \"windows.system\", \"windows.misc\", \"windows.powershell\"]\n\n[heredoc]\nenabled = true\ntimeout_ms = 5000\n",
    )
    .expect("write config");
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": { "command": command },
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcg"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("DCG_CONFIG", &config)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("DCG_HISTORY_DISABLED", "1")
        .env("DCG_AST_TIMEOUT_MS", "5000")
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .env("DCG_CUSTOM_PATHS", "")
        .current_dir(scratch.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcg hook");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(payload.to_string().as_bytes())
        .expect("write hook json");
    let output = child.wait_with_output().expect("wait dcg hook");
    assert!(
        output.status.success(),
        "hook failed for {command:?} tool={tool_name}: status={:?} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let denied = stdout.contains("\"permissionDecision\":\"deny\"");
    (denied, stdout)
}

#[test]
fn cmd_dynamic_argv0_windows_rules_deny_in_cmd_and_unknown() {
    for command in DESTRUCTIVE_DENY_CONTROLS {
        for dialect in ["cmd", "unknown"] {
            let verdict = dcg_test_verdict(command, dialect);
            assert_eq!(
                verdict["decision"].as_str(),
                Some("deny"),
                "{command:?} {dialect}: {verdict}"
            );
        }
    }
    // `windows.misc:schtasks-delete` is Medium severity (warns by default);
    // verify the `%VAR%`-elided spelling triggers the exact same rule as literal `schtasks`.
    for dialect in ["cmd", "unknown"] {
        let verdict = dcg_test_verdict(r"schta%x%sks /delete /tn MyTask /f", dialect);
        assert_eq!(
            verdict["rule_id"].as_str(),
            Some("windows.misc:schtasks-delete"),
            "schtasks %VAR% in {dialect}: {verdict}"
        );
        assert_eq!(
            verdict["decision"].as_str(),
            Some("warn"),
            "schtasks %VAR% in {dialect}: {verdict}"
        );
    }

    // Exercise live hook JSON protocol across representative Windows packs.
    for command in [
        r"r%x%md /s /q C:\",
        r"r%x%mdir /s /q C:\",
        r"r%x%mdir/s/q C:\",
        r"vssad%x%min delete shadows /all",
        r"vssad%PATH:~0,0%min delete shadows /all",
        r"re%x%g delete HKLM\Software\Foo /f",
        r"wba%x%dmin delete catalog",
        r"ws%x%l --unregister Ubuntu",
        r"bcde%x%dit /delete {current}",
        r"gi!x!t reset --hard",
    ] {
        let (denied, stdout) = hook_denies(command, "cmd");
        assert!(
            denied,
            "cmd hook must deny {command:?}, got stdout={stdout}"
        );
    }
}

#[test]
fn cmd_benign_corpus_has_zero_false_positives() {
    for command in BENIGN_CMD_CORPUS {
        for dialect in ["cmd", "unknown"] {
            let verdict = dcg_test_verdict(command, dialect);
            assert_eq!(
                verdict["decision"].as_str(),
                Some("allow"),
                "{command:?} {dialect}: {verdict}"
            );
        }
    }
    for command in [
        r"echo %PATH%",
        r"dir %USERPROFILE%",
        r"rd /?",
        r"vssadmin list shadows",
        r"vssad%x%min list shadows",
        r"re%x%g query HKLM\Software\Foo",
        r#"echo "vssad%x%min delete shadows /all""#,
        r"%LOGGER% rmmod nvidia",
    ] {
        let (denied, stdout) = hook_denies(command, "cmd");
        assert!(
            !denied,
            "cmd hook must allow {command:?}, got stdout={stdout}"
        );
    }
}

//! Regression pins for bd-1o5h: bare `cmd`/`pwsh` reading piped or redirected
//! stdin as commands was not guarded on the cmd/PowerShell dialects.
//!
//! Found in the v0.12.2 adversarial sweep. A shell consuming piped source
//! reads its program from stdin, but the executing-sink pipeline analysis was
//! bash-AST/POSIX-only, so `echo del /s /q C:\x | cmd` (and the pwsh form, and
//! the `< file` redirect form) ran the payload unguarded — while `cmd /c "…"`,
//! `powershell -`, and the whole POSIX `| bash` side denied.
//!
//! Fixed by a native cmd/PowerShell pipeline stdin-consumer collector that
//! reuses the existing `cmd_pipeline_input_mode`/`powershell_pipeline_input_mode`
//! consumer helpers. Only a bare stdin-reading shell triggers a sink; ordinary
//! pipelines whose consumer is any other tool are untouched.
//!
//! Exercised through `dcg test --dialect` (the entry point that surfaced it),
//! with the Windows packs enabled as on a native Windows install.

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn dcg_binary() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // deps/
    path.pop(); // debug/
    path.push(format!("dcg{}", std::env::consts::EXE_SUFFIX));
    path
}

const PACKS: &str = "core.git,core.filesystem,windows.filesystem,windows.system";

/// Run `dcg test --dialect <dia> <command>` and return the decision string
/// ("allow"/"deny") plus full output for diagnostics.
fn decision(command: &str, dialect: &str) -> (String, String) {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(temp.path().join("home")).unwrap();
    std::fs::create_dir_all(temp.path().join("xdg")).unwrap();
    let output = Command::new(dcg_binary())
        .args([
            "test",
            "--with-packs",
            PACKS,
            "--dialect",
            dialect,
            "--format",
            "json",
            command,
        ])
        .env_clear()
        .env("HOME", temp.path().join("home"))
        .env("USERPROFILE", temp.path().join("home"))
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_PACKS", "core.git,core.filesystem")
        .current_dir(temp.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run dcg test");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    // `dcg test --format json` emits a pretty (multi-line) document, so parse
    // the whole stdout rather than any single line.
    let dec = serde_json::from_str::<serde_json::Value>(stdout.trim())
        .ok()
        .and_then(|v| v.get("decision")?.as_str().map(str::to_string))
        .unwrap_or_else(|| {
            // Fall back to exit-code semantics: `dcg test` exits 1 on deny.
            if output.status.code() == Some(1) {
                "deny".to_string()
            } else {
                "allow".to_string()
            }
        });
    (dec, format!("{stdout}\n{stderr}"))
}

fn assert_denied(command: &str, dialect: &str) {
    let (dec, full) = decision(command, dialect);
    assert_eq!(dec, "deny", "expected DENY [{dialect}]: {command}\n{full}");
}

fn assert_allowed(command: &str, dialect: &str) {
    let (dec, full) = decision(command, dialect);
    assert_ne!(dec, "deny", "expected ALLOW [{dialect}]: {command}\n{full}");
}

#[test]
fn piped_into_bare_cmd_is_evaluated_as_cmd_source() {
    for command in [
        "echo del /s /q C:\\tmp | cmd",
        "echo del /s /q C:\\tmp | cmd.exe",
        "echo del /s /q C:\\tmp | cmd /q",
        "echo del /s /q C:\\tmp | cmd /q /d",
        "echo rd /s /q C:\\tmp | cmd",
        "echo vssadmin delete shadows /all | cmd",
        "echo del /s /q C:\\d | C:\\Windows\\System32\\cmd.exe",
        "type payload.txt | cmd",
    ] {
        assert_denied(command, "cmd");
    }
}

#[test]
fn piped_into_bare_powershell_is_evaluated_as_powershell_source() {
    for command in [
        "echo Remove-Item -Recurse -Force C:\\tmp | pwsh",
        "echo Remove-Item -Recurse -Force C:\\tmp | powershell",
        "echo Remove-Item -Recurse -Force C:\\tmp | pwsh.exe",
        "echo Remove-Item -Recurse -Force C:\\tmp | powershell -",
        "echo Format-Volume -DriveLetter D | pwsh",
    ] {
        assert_denied(command, "ps");
    }
}

#[test]
fn stdin_redirected_from_a_file_into_a_bare_shell_fails_closed() {
    assert_denied("cmd < payload.bat", "cmd");
    assert_denied("cmd <payload.bat", "cmd");
    assert_denied("pwsh < payload.ps1", "ps");
}

#[test]
fn a_switch_that_stops_stdin_reading_still_denies_by_its_own_payload_but_not_the_pipe() {
    // `cmd /c "..."` / `pwsh -c "..."` do NOT read stdin; they are covered by
    // the existing launcher analysis, and the pipe producer is irrelevant.
    assert_denied("cmd /c \"del /s /q C:\\tmp\"", "cmd");
    assert_denied("pwsh -c \"Remove-Item -Recurse -Force C:\\tmp\"", "ps");
    // A benign `/c` payload piped from anything stays allowed — the shell does
    // not read the pipe.
    assert_allowed("echo status | cmd /c echo ok", "cmd");
}

#[test]
fn ordinary_pipelines_whose_consumer_is_not_a_bare_shell_stay_allowed() {
    for command in [
        "dir /s | find \"test\"",
        "tasklist | findstr chrome",
        "echo hi | clip",
        "type a.txt | sort | more",
        "netstat -an | findstr LISTENING",
        "echo del /s /q C:\\d | findstr del",
        "ipconfig | findstr IPv4",
    ] {
        assert_allowed(command, "cmd");
    }
    for command in [
        "Get-ChildItem | Sort-Object Length | Select-Object -First 5",
        "Get-Process | Where-Object CPU -gt 1",
        "Get-Content log | Select-String error",
        "\"hello\" | Out-File x.txt",
        "gci | ? { $_.Length -gt 1kb }",
        "pwsh -NoProfile -File build.ps1",
        "powershell -ExecutionPolicy Bypass -File x.ps1",
    ] {
        assert_allowed(command, "ps");
    }
}

//! Regression pins for issue #313: false positives on read-only PowerShell
//! commands driven through a POSIX shell.
//!
//! Items 3 and 4 of the report were fixed in v0.11.0 (`67dcb1a`, `200e3f1`,
//! `032a23e`); items 1 and 2 could not be reproduced from the report's
//! descriptions and await the literal command strings. This file pins the
//! fixed behavior and the maintainer's reconstructions of 1 and 2 against
//! `dcg test` — the entry point the report used — with the opt-in
//! Windows/guardrails packs enabled as on a native Windows install, and with
//! the default all-dialect analysis (the strictest view). Each allow is paired
//! with the nearest shape that must still deny.

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn dcg_binary() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // deps/
    path.pop(); // debug/
    path.push(format!("dcg{}", std::env::consts::EXE_SUFFIX));
    path
}

const PACKS: &str =
    "core.git,core.filesystem,windows.filesystem,careful_company_running_windows.guardrails";

/// `dcg test <command>` under a hermetic config; returns the `Result:` line
/// plus the full output for diagnostics.
fn dcg_test(command: &str) -> (String, String) {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(temp.path().join("home")).unwrap();
    std::fs::create_dir_all(temp.path().join("xdg")).unwrap();
    let output = Command::new(dcg_binary())
        .args(["test", "--with-packs", PACKS, command])
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
    let result = stdout
        .lines()
        .chain(stderr.lines())
        .find(|line| line.trim_start().starts_with("Result:"))
        .map(|line| line.trim().to_string())
        .unwrap_or_default();
    (result, format!("{stdout}\n{stderr}"))
}

fn assert_allowed(command: &str) {
    let (result, full) = dcg_test(command);
    assert_eq!(result, "Result: ALLOWED", "command: {command}\n{full}");
}

fn assert_blocked(command: &str, rule: &str) {
    let (result, full) = dcg_test(command);
    assert!(
        result.starts_with("Result: BLOCKED") || result.starts_with("Result: REVIEW REQUIRED"),
        "command: {command}\n{full}"
    );
    assert!(full.contains(rule), "expected {rule} for {command}\n{full}");
}

#[test]
fn item3_backup_copy_of_hook_config_is_a_read() {
    assert_allowed("Copy-Item ~/.claude/settings.json ~/backups/settings.json.bak");
    assert_allowed("Copy-Item -Path ~/.claude/settings.json -Destination ~/backups/");
    assert_allowed(
        r"Copy-Item 'C:\Users\me\.claude\settings.json' 'C:\backup\settings (old).json'",
    );
}

#[test]
fn item3_planted_negatives_writes_to_hook_config_still_deny() {
    assert_blocked(
        "Copy-Item ~/backups/settings.json.bak ~/.claude/settings.json",
        "agent-hook-config-overwrite",
    );
    assert_blocked(
        "Copy-Item -Path ~/backups/settings.json.bak -Destination ~/.claude/settings.json",
        "agent-hook-config-overwrite",
    );
    assert_blocked(
        "Remove-Item ~/.claude/settings.json",
        "agent-hook-config-tamper",
    );
}

#[test]
fn item4_shell_assignment_before_pwsh_is_not_an_expansion_in_the_payload() {
    assert_allowed(r#"SP="/tmp/x"; pwsh -NoProfile -c "Invoke-Pester tests""#);
    // A bare variable read is inert — when the POSIX shell does not expand
    // it first. Single quotes hand `$PSVersionTable` to pwsh intact.
    assert_allowed("pwsh -NoProfile -c '$PSVersionTable.PSVersion'");
    assert_allowed("pwsh --version");
    // Double-quoted, the OUTER shell expands `$PSVersionTable` before pwsh
    // runs, so the payload is only known at run time: fail closed is right.
    assert_blocked(
        r#"pwsh -NoProfile -c "$PSVersionTable.PSVersion""#,
        "launcher-unverified",
    );
}

#[test]
fn item4_planted_negative_destructive_pwsh_payload_still_denies() {
    assert_blocked(
        r#"SP="/tmp/x"; pwsh -NoProfile -c "Remove-Item -Recurse -Force C:\src""#,
        "windows.filesystem",
    );
}

#[test]
fn items1_and_2_maintainer_reconstructions_allow() {
    // Item 1: read-only pipelines ending in Measure-Object — no `rm`.
    assert_allowed("Get-ChildItem -Recurse *.log | Measure-Object -Property Length -Sum");
    assert_allowed("Get-ChildItem -Recurse -Force | Where-Object Length -gt 1MB | Measure-Object");
    assert_allowed("gci -r | measure");
    // Item 2: a pure-read function definition.
    assert_allowed(
        "function Get-Stats { Get-Content data.txt | Group-Object | Sort-Object Count }",
    );
    assert_allowed(
        "function Get-LogSummary { param([string]$Path) Get-Content $Path | ConvertFrom-Json }",
    );
}

#[test]
fn items1_and_2_planted_negatives_recursive_delete_still_denies() {
    assert_blocked("Remove-Item -Recurse -Force ./build", "windows.filesystem");
    assert_blocked(
        "function Clean { Remove-Item -Recurse -Force ./build }",
        "windows.filesystem",
    );
}

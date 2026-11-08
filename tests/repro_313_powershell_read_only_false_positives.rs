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
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

const PACKS: &str =
    "core.git,core.filesystem,windows.filesystem,careful_company_running_windows.guardrails";

/// `dcg test <command>` under a hermetic config; returns the `Result:` line
/// plus the full output for diagnostics.
fn dcg_test(command: &str) -> (String, String) {
    dcg_test_in_dialect(command, "unknown")
}

fn dcg_test_in_dialect(command: &str, dialect: &str) -> (String, String) {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(temp.path().join("home")).unwrap();
    std::fs::create_dir_all(temp.path().join("xdg")).unwrap();
    let output = Command::new(dcg_binary())
        .args(["test", "--with-packs", PACKS, "--dialect", dialect, command])
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
    let separate_fields = rule.split_once(':').is_some_and(|(pack, pattern)| {
        full.lines().any(|line| line == format!("Pack: {pack}"))
            && full
                .lines()
                .any(|line| line == format!("Pattern: {pattern}"))
    });
    assert!(
        full.contains(rule) || separate_fields,
        "expected {rule} for {command}\n{full}"
    );
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
    // Attribution moved here in `c917a36` (#451), which removed
    // `rm_semantic_scan_required`'s PowerShell prefilter. This command carries
    // none of the ``` ` @ & $ ( ``` characters that prefilter demanded, so
    // core.filesystem was previously not even a candidate and windows.filesystem
    // answered by default. core.* is tier 1 and windows.* is tier 11, so once
    // core.filesystem could match it claimed the command — the documented order
    // working as designed, not a tier regression.
    //
    // Pinned to the pack that actually answers, and paired below with the bare
    // spelling that still routes to windows.filesystem, so this file fails if
    // EITHER route moves again. The verdict assertion is unchanged.
    assert_blocked(
        r#"SP="/tmp/x"; pwsh -NoProfile -c "Remove-Item -Recurse -Force C:\src""#,
        "core.filesystem",
    );
}

/// Bare and `pwsh -c`-wrapped spellings are both answered by core.filesystem.
///
/// This used to pin an asymmetry: wrapped, the inline script reached
/// core.filesystem's `powershell-remove-item-recursive`, while bare it was
/// windows.filesystem's `remove-item-recurse-force`. `3f1a2da` (#491) made the
/// semantic rm path run its Windows front ends under the unknown dialect too,
/// which is the all-dialect analysis `dcg test` uses by default, so the bare
/// spelling now reaches core.filesystem as well — and core.* is tier 1 while
/// windows.* is tier 11, the same documented order `c917a36` applied to the
/// wrapped spelling. Both spellings now share one rule id, so an allowlist
/// entry covers them alike. The verdict is unchanged; this fails if either
/// route moves again.
#[test]
fn item4_bare_and_wrapped_spellings_deny_under_one_rule_id() {
    for target in [r"C:\src", "./build"] {
        assert_blocked(
            &format!("Remove-Item -Recurse -Force {target}"),
            "powershell-remove-item-recursive",
        );
        assert_blocked(
            &format!(r#"pwsh -NoProfile -c "Remove-Item -Recurse -Force {target}""#),
            "powershell-remove-item-recursive",
        );
    }
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
    // The bare spelling reaches core.filesystem first (tier 1; see item4
    // above). Inside a function body the semantic rm path does not look, so
    // windows.filesystem still answers there.
    assert_blocked("Remove-Item -Recurse -Force ./build", "core.filesystem");
    assert_blocked(
        "function Clean { Remove-Item -Recurse -Force ./build }",
        "windows.filesystem",
    );
}

#[test]
fn global_options_cannot_hide_guardrail_changes() {
    for command in [
        "dcg --robot allow-once abc123 --yes",
        "dcg --agent codex --no-color allow-once abc123 --yes",
        "dcg --agent test allow-once abc123 --yes",
        "dcg --agent classify allowlist add core.git:reset-hard --reason reviewed",
        "dcg --robot allowlist add core.git:reset-hard --reason reviewed",
        "dcg allowlist --robot add core.git:reset-hard --reason reviewed",
        "dcg allowlist --agent=codex add-command 'rm -rf dist' --reason reviewed",
        "dcg --legacy-output -vv allow core.git:reset-hard --reason reviewed",
        "env dcg --robot allow-once abc123 --yes",
    ] {
        assert_blocked(
            command,
            "careful_company_running_windows.guardrails:dcg-policy-self-weakening",
        );
    }
    for command in [
        "dcg --robot uninstall",
        "dcg -q --no-suggestions uninstall",
        "dcg --agent 'codex' --no-color uninstall",
        "dcg --agent= --robot uninstall",
        "dcg --agent explain uninstall",
        "dcg --agent='dcg --robot uninstall' --robot uninstall",
        "dcg --agent='dcg --robot uninstall' doctor; dcg --robot uninstall",
        "bash -c 'dcg --robot uninstall'",
        r"C:\tools\dcg.exe --robot uninstall",
        "git status && dcg --robot uninstall",
    ] {
        assert_blocked(
            command,
            "careful_company_running_windows.guardrails:dcg-bypass-or-uninstall",
        );
    }
}

#[test]
fn global_options_preserve_inspection_and_argument_data() {
    for command in [
        "dcg --robot allowlist list",
        "dcg allowlist --agent add list",
        "dcg --agent uninstall doctor",
        "dcg --agent='allowlist add' doctor",
        "dcg --agent='dcg --robot uninstall' doctor",
        "dcg --agent='dcg --robot allow-once abc --yes' allowlist list",
        "dcg --robot allowlist remove core.git:reset-hard",
        "dcg --robot test 'dcg --robot uninstall'",
        "dcg --no-color explain 'dcg --robot allow-once abc123 --yes'",
        "dcg --agent codex --robot test 'dcg --robot uninstall'",
        "printf '%s\\n' 'dcg --robot uninstall'",
        "echo 'dcg --robot allowlist add core.git:reset-hard --reason reviewed'",
    ] {
        assert_allowed(command);
    }
}

#[test]
fn escaped_dcg_syntax_cannot_hide_guardrail_changes() {
    // Ordinary PowerShell backtick escapes are syntax; these strings are
    // passed to dcg test as data and never execute exception grants/uninstall.
    for dialect in ["powershell", "unknown"] {
        for (command, rule) in [
            (
                "dcg --a`gent=codex --robot uninstall",
                "dcg-bypass-or-uninstall",
            ),
            (
                "dcg --a`gent codex --r`obot un`install",
                "dcg-bypass-or-uninstall",
            ),
            (
                "dcg --a`gent='two words' --robot un`install",
                "dcg-bypass-or-uninstall",
            ),
            (
                "dcg --a`gent='two 'words --robot un`install",
                "dcg-bypass-or-uninstall",
            ),
            (
                "dcg --a`gent 'two 'words --robot un`install",
                "dcg-bypass-or-uninstall",
            ),
            (
                "dcg --a`gent=codex doctor; dcg un`install",
                "dcg-bypass-or-uninstall",
            ),
            (
                "dcg --a`gent=codex doctor\ndcg un`install",
                "dcg-bypass-or-uninstall",
            ),
            (
                "dcg --a`gent=codex doctor && dcg un`install",
                "dcg-bypass-or-uninstall",
            ),
            (
                "dcg --a'gent'='dcg --robot uninstall' --robot un'install'",
                "dcg-bypass-or-uninstall",
            ),
            (
                "dcg --r`obot al`low-once abc123 --yes",
                "dcg-policy-self-weakening",
            ),
            (
                "dcg --a`gent=codex al`low core.git:reset-hard --reason reviewed",
                "dcg-policy-self-weakening",
            ),
            (
                "dcg allowl`ist --a`gent='dcg uninstall' a`dd core.git:reset-hard --reason reviewed",
                "dcg-policy-self-weakening",
            ),
            (
                "dcg allowl`ist add-c`ommand 'git reset --hard' --reason reviewed",
                "dcg-policy-self-weakening",
            ),
            (
                "dcg allowl`ist imp`ort /tmp/reviewed-allowlist.toml",
                "dcg-policy-self-weakening",
            ),
        ] {
            let (result, full) = dcg_test_in_dialect(command, dialect);
            assert!(
                result.starts_with("Result: BLOCKED"),
                "[{dialect}] {command:?}: {full}"
            );
            assert!(
                full.contains(&format!("Pattern: {rule}")),
                "[{dialect}] expected {rule} for {command:?}: {full}"
            );
        }
    }
}

#[test]
fn escaped_dcg_options_keep_agent_values_and_inspection_arguments_as_data() {
    for dialect in ["powershell", "unknown"] {
        for command in [
            "dcg --a`gent=uninstall do`ctor",
            "dcg --a`gent='allowlist add' allowlist list",
            "dcg --a`gent='dcg --robot uninstall' doctor",
            "dcg --a'gent'='dcg --robot uninstall' doctor",
            "dcg --a`gent='two words' doctor",
            "dcg --a`gent='two 'words doctor",
            "dcg --a`gent 'two 'words doctor",
            "dcg --a`gent='co`dex; dcg uninstall' doctor",
            "dcg --r`obot al`lowlist li`st",
            "dcg al`lowlist --a`gent=add li`st",
            "dcg --r`obot test 'dcg --robot uninstall'",
            "dcg --agent='--robot uninstall' explain 'dcg allow-once abc123 --yes'",
        ] {
            let (result, full) = dcg_test_in_dialect(command, dialect);
            assert_eq!(result, "Result: ALLOWED", "[{dialect}] {command:?}: {full}");
        }
    }
}

#[test]
fn native_agent_argument_boundaries_are_dialect_specific() {
    for (dialect, escaped_space) in [("powershell", "two` words"), ("posix", r"two\ words")] {
        for separator in ["=", " "] {
            let dangerous = format!("dcg --agent{separator}{escaped_space} uninstall");
            for view in [dialect, "unknown"] {
                let (result, full) = dcg_test_in_dialect(&dangerous, view);
                assert!(
                    result.starts_with("Result: BLOCKED"),
                    "[{view}] {dangerous:?}: {full}"
                );
                assert!(
                    full.contains("Pattern: dcg-bypass-or-uninstall"),
                    "[{view}] {dangerous:?}: {full}"
                );
            }
            let inspection = format!("dcg --agent{separator}{escaped_space} doctor");
            let (result, full) = dcg_test_in_dialect(&inspection, dialect);
            assert_eq!(result, "Result: ALLOWED", "{inspection:?}: {full}");
        }
        let with_literal_braces = format!("dcg --agent={escaped_space}'{{literal}}' uninstall");
        let (result, full) = dcg_test_in_dialect(&with_literal_braces, dialect);
        assert!(
            result.starts_with("Result: BLOCKED")
                && full.contains("Pattern: dcg-bypass-or-uninstall"),
            "[{dialect}] literal braces remain agent data: {with_literal_braces:?}: {full}"
        );
    }

    // A backslash does not escape PowerShell whitespace. The intervening
    // positional word cannot be skipped to invent an uninstall subcommand.
    for command in [
        r"dcg --agent=two\ words uninstall",
        r"dcg --agent two\ words uninstall",
    ] {
        let (result, full) = dcg_test_in_dialect(command, "powershell");
        assert_eq!(result, "Result: ALLOWED", "{command:?}: {full}");
    }
    for view in ["cmd", "unknown"] {
        let command = "dcg --a^gent=\"two words\" un^install";
        let (result, full) = dcg_test_in_dialect(command, view);
        assert!(
            result.starts_with("Result: BLOCKED")
                && full.contains("Pattern: dcg-bypass-or-uninstall"),
            "[{view}] {command:?}: {full}"
        );
        // Cmd removes the caret; it does not quote the resulting space for
        // the native executable's argv parser. The extra word is still data.
        let command = "dcg --agent=two^ words uninstall";
        let (result, full) = dcg_test_in_dialect(command, view);
        assert_eq!(result, "Result: ALLOWED", "[{view}] {command:?}: {full}");
    }
}

#[test]
fn hook_protocol_keeps_guardrails_active_with_global_options() {
    use std::io::Write;

    // The strings are hook input only; no uninstall or exception grant runs.
    let temp = tempfile::tempdir().expect("isolated hook test");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).expect("isolated home");
    let config = temp.path().join("config.toml");
    std::fs::write(&config, "[history]\nenabled = false\n").expect("hook config");
    for tool_name in ["Bash", "PowerShell", "cmd"] {
        let cases: &[(&str, Option<&str>)] = if tool_name == "cmd" {
            &[
                (
                    "echo 'data & dcg --robot uninstall & data'",
                    Some("dcg-bypass-or-uninstall"),
                ),
                ("echo \"data & dcg --robot uninstall & data\"", None),
            ]
        } else {
            &[
                (
                    "dcg --robot allow-once abc123 --yes",
                    Some("dcg-policy-self-weakening"),
                ),
                (
                    "dcg --agent test allow-once abc123 --yes",
                    Some("dcg-policy-self-weakening"),
                ),
                (
                    "dcg --agent 'test' --robot allow-once abc123 --yes",
                    Some("dcg-policy-self-weakening"),
                ),
                (
                    "dcg --agent explain uninstall",
                    Some("dcg-bypass-or-uninstall"),
                ),
                (
                    "dcg --agent co'dex' --robot uninstall",
                    Some("dcg-bypass-or-uninstall"),
                ),
                (
                    "dcg --a'gent'=codex --robot uninstall",
                    Some("dcg-bypass-or-uninstall"),
                ),
                (
                    "dcg --agent= --robot uninstall",
                    Some("dcg-bypass-or-uninstall"),
                ),
                (
                    "dcg --agent='dcg --robot uninstall' --robot uninstall",
                    Some("dcg-bypass-or-uninstall"),
                ),
                (
                    "dcg --agent='dcg --robot uninstall' doctor; dcg --robot uninstall",
                    Some("dcg-bypass-or-uninstall"),
                ),
                (
                    "bash -c 'dcg --robot uninstall'",
                    Some("dcg-bypass-or-uninstall"),
                ),
                ("dcg --agent uninstall doctor", None),
                ("dcg --agent='allowlist add' doctor", None),
                ("dcg --agent='dcg --robot uninstall' doctor", None),
                (
                    "dcg --agent='dcg --robot allow-once abc --yes' allowlist list",
                    None,
                ),
                ("dcg --robot test 'dcg --robot uninstall'", None),
                (
                    "dcg --agent codex --no-color explain 'dcg --robot allow-once abc123 --yes'",
                    None,
                ),
            ]
        };
        let escaped_cases: &[(&str, Option<&str>)] = if tool_name == "PowerShell" {
            &[
                (
                    "dcg --a`gent=codex --r`obot un`install",
                    Some("dcg-bypass-or-uninstall"),
                ),
                (
                    "dcg --a`gent='two words' --robot un`install",
                    Some("dcg-bypass-or-uninstall"),
                ),
                (
                    "dcg --a`gent='two 'words --robot un`install",
                    Some("dcg-bypass-or-uninstall"),
                ),
                (
                    "dcg --a`gent=codex doctor; dcg un`install",
                    Some("dcg-bypass-or-uninstall"),
                ),
                (
                    "dcg --agent=two` words uninstall",
                    Some("dcg-bypass-or-uninstall"),
                ),
                (
                    "dcg --agent two` words uninstall",
                    Some("dcg-bypass-or-uninstall"),
                ),
                (
                    "dcg --a'gent'='dcg --robot uninstall' --robot un'install'",
                    Some("dcg-bypass-or-uninstall"),
                ),
                (
                    "dcg --r`obot al`low-once abc123 --yes",
                    Some("dcg-policy-self-weakening"),
                ),
                (
                    "dcg allowl`ist --a`gent='dcg uninstall' a`dd core.git:reset-hard --reason reviewed",
                    Some("dcg-policy-self-weakening"),
                ),
                ("dcg --a`gent='dcg --robot uninstall' doctor", None),
                ("dcg --a`gent='two 'words doctor", None),
                ("dcg --a`gent='co`dex; dcg uninstall' doctor", None),
                ("dcg --agent two` words doctor", None),
                (r"dcg --agent=two\ words uninstall", None),
                ("dcg --r`obot al`lowlist li`st", None),
                ("dcg --r`obot test 'dcg --robot uninstall'", None),
            ]
        } else {
            &[]
        };
        for &(command, expected_rule) in cases.iter().chain(escaped_cases) {
            let mut child = Command::new(dcg_binary())
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
                .env("DCG_PACKS", PACKS)
                .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
                .env(
                    "DCG_PENDING_EXCEPTIONS_PATH",
                    temp.path().join("pending.jsonl"),
                )
                .env("DCG_SELF_HEAL_HOOK", "0")
                .env("DCG_HOOK_TIMEOUT_MS", "5000")
                .env("DCG_AST_TIMEOUT_MS", "5000")
                .current_dir(temp.path())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("start dcg hook");
            let payload = serde_json::json!({
                "hook_event_name": "PreToolUse",
                "tool_name": tool_name,
                "tool_input": {"command": command},
            });
            child
                .stdin
                .take()
                .expect("hook stdin")
                .write_all(payload.to_string().as_bytes())
                .expect("write hook input");
            let output = child.wait_with_output().expect("hook result");
            assert_eq!(
                output.status.code(),
                Some(0),
                "{tool_name} {command:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            if let Some(rule) = expected_rule {
                let result: serde_json::Value =
                    serde_json::from_slice(&output.stdout).expect("structured hook denial");
                let decision = &result["hookSpecificOutput"];
                assert_eq!(decision["hookEventName"], "PreToolUse");
                assert_eq!(
                    decision["permissionDecision"], "deny",
                    "{tool_name}: {command}"
                );
                // The Bash adapter provides ruleId; the PowerShell adapter
                // currently carries the same rule in its decision reason.
                let reported_rule = decision["ruleId"].as_str().or_else(|| {
                    decision["permissionDecisionReason"]
                        .as_str()?
                        .lines()
                        .find_map(|line| line.strip_prefix("Rule: "))
                });
                let expected_rule = format!("careful_company_running_windows.guardrails:{rule}");
                assert_eq!(
                    reported_rule,
                    Some(expected_rule.as_str()),
                    "{tool_name}: {command}"
                );
            } else {
                assert!(
                    output.stdout.is_empty(),
                    "{tool_name} {command:?}: {}",
                    String::from_utf8_lossy(&output.stdout)
                );
            }
        }
    }
}

/// #647: a bounded semantic scan must inspect the whole supported program.
/// These commands are classifier input on stdin; no PowerShell is executed.
mod issue_647 {
    use super::dcg_binary;
    use std::io::Write;
    use std::path::PathBuf;
    use std::process::{Command, Output, Stdio};

    const PACKS: &str = "core.git,core.filesystem,windows.filesystem";
    const SAFE_STATEMENT: &str = "Write-Output 'rm x'";
    const CLEAR_RULE: &str = "windows.filesystem:clear-content";

    struct Lab {
        dir: tempfile::TempDir,
        config: PathBuf,
    }

    impl Lab {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("isolated #647 test");
            std::fs::create_dir_all(dir.path().join("home")).expect("isolated home");
            let config = dir.path().join("config.toml");
            std::fs::write(&config, "[history]\nenabled = false\n").expect("test config");
            Self { dir, config }
        }

        fn run(&self, args: &[&str], input: &str, budget_ms: Option<u64>) -> Output {
            let home = self.dir.path().join("home");
            let mut process = Command::new(dcg_binary());
            process
                .args(["--agent", "claude-code"])
                .args(args)
                .env_clear()
                .env("HOME", &home)
                .env("USERPROFILE", &home)
                .env("XDG_CONFIG_HOME", home.join("config"))
                .env("XDG_DATA_HOME", home.join("data"))
                .env("XDG_CACHE_HOME", home.join("cache"))
                .env("APPDATA", home.join("appdata"))
                .env("LOCALAPPDATA", home.join("localappdata"))
                .env("TEMP", self.dir.path())
                .env("TMP", self.dir.path())
                .env("TMPDIR", self.dir.path())
                .env("DCG_CONFIG", &self.config)
                .env("DCG_PACKS", PACKS)
                .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
                .env(
                    "DCG_PENDING_EXCEPTIONS_PATH",
                    self.dir.path().join("pending.jsonl"),
                )
                .env("DCG_SELF_HEAL_HOOK", "0")
                .current_dir(self.dir.path())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            if let Some(ms) = budget_ms {
                process.env("DCG_HOOK_TIMEOUT_MS", ms.to_string());
            }
            let mut child = process.spawn().expect("start dcg classifier");
            child
                .stdin
                .take()
                .expect("classifier stdin")
                .write_all(input.as_bytes())
                .expect("write classifier input");
            child.wait_with_output().expect("classifier result")
        }

        fn assert_budget(&self, budget_ms: Option<u64>, expected_ms: u64, source: &str) {
            let output = self.run(&["config", "--format", "json"], "", budget_ms);
            assert!(output.status.success(), "{output:?}");
            let report: serde_json::Value =
                serde_json::from_slice(&output.stdout).expect("config JSON");
            assert_eq!(report["general"]["hook_timeout_ms"], expected_ms);
            assert_eq!(report["general"]["hook_timeout_source"], source);
        }

        fn assert_surfaces(
            &self,
            command: &str,
            expected: &str,
            rule: Option<&str>,
            budget_ms: Option<u64>,
        ) {
            let payload = serde_json::json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "PowerShell",
                "tool_input": {"command": command},
                "cwd": self.dir.path(),
            });
            let hook_input = format!("{payload}\n");
            for (surface, args, input) in [
                (
                    "CLI",
                    &[
                        "test",
                        "--stdin",
                        "--dialect",
                        "powershell",
                        "--format",
                        "json",
                        "--enforce-budget",
                    ][..],
                    command,
                ),
                ("batch", &["hook", "--batch"][..], hook_input.as_str()),
                ("hook", &[][..], hook_input.as_str()),
            ] {
                let output = self.run(args, input, budget_ms);
                let diagnostics = format!(
                    "{surface}, {} bytes, expected {expected}: stdout={} stderr={}",
                    command.len(),
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                let expected_exit = i32::from(surface != "hook" && expected != "allow");
                assert_eq!(output.status.code(), Some(expected_exit), "{diagnostics}");
                if surface == "hook" && expected == "allow" {
                    assert!(output.stdout.is_empty(), "{diagnostics}");
                    continue;
                }
                let json: serde_json::Value = serde_json::from_slice(&output.stdout)
                    .unwrap_or_else(|error| panic!("{error}: {diagnostics}"));
                let reported_rule = if surface == "hook" {
                    let decision = &json["hookSpecificOutput"];
                    assert_eq!(decision["hookEventName"], "PreToolUse", "{diagnostics}");
                    let hook_decision = if expected == "indeterminate" {
                        "ask"
                    } else {
                        expected
                    };
                    assert_eq!(
                        decision["permissionDecision"], hook_decision,
                        "{diagnostics}"
                    );
                    decision["ruleId"].as_str().or_else(|| {
                        decision["permissionDecisionReason"]
                            .as_str()?
                            .lines()
                            .find_map(|line| line.strip_prefix("Rule: "))
                    })
                } else {
                    assert_eq!(json["decision"], expected, "{diagnostics}");
                    json["rule_id"].as_str()
                };
                if let Some(rule) = rule {
                    assert_eq!(reported_rule, Some(rule), "{diagnostics}");
                } else if expected == "deny" {
                    assert!(
                        reported_rule.is_some(),
                        "a denial needs a finding: {diagnostics}"
                    );
                } else {
                    assert!(reported_rule.is_none(), "no rule was found: {diagnostics}");
                }
            }
        }
    }

    fn statements(count: usize) -> String {
        vec![SAFE_STATEMENT; count].join("; ")
    }

    fn with_late_statement(safe_count: usize, last: &str) -> String {
        format!("{}; {last}", statements(safe_count))
    }

    #[test]
    fn supported_safe_statements_allow_with_the_shipped_deadline() {
        let lab = Lab::new();
        lab.assert_budget(
            None,
            destructive_command_guard::perf::HOOK_EVALUATION_BUDGET_MS,
            "default",
        );
        for count in [300, 512] {
            lab.assert_surfaces(&statements(count), "allow", None, None);
        }
    }

    #[test]
    fn later_destructive_statements_are_inspected_at_the_supported_bound() {
        let lab = Lab::new();
        // These are classification tests. Their explicit test-only budget
        // isolates semantic results from contention; the test above and the
        // constrained-budget test below retain the production deadline path.
        for count in [400, 511] {
            for last in [
                r"Clear-Content C:\important.conf",
                r"Cl`ear-Con`tent C:\important.conf",
            ] {
                lab.assert_surfaces(
                    &with_late_statement(count, last),
                    "deny",
                    Some(CLEAR_RULE),
                    Some(5000),
                );
            }
            lab.assert_surfaces(
                &with_late_statement(count, r"Remove-Item C:\example -Recurse -Force"),
                "deny",
                Some("core.filesystem:powershell-remove-item-recursive"),
                Some(5000),
            );
        }
    }

    #[test]
    fn incomplete_analysis_never_certifies_a_safe_prefix() {
        let lab = Lab::new();
        for command in [
            statements(513),
            format!("Write-Output 'rm {}'", "x".repeat(64 * 1024)),
        ] {
            lab.assert_surfaces(&command, "indeterminate", None, Some(5000));
        }
        // A visible destructive spelling still wins after the semantic pass
        // reaches its bound. Executable-position backticks are decoded in the
        // regex view; unresolved or malformed operands do not erase the
        // destructive executable that view has already found.
        for last in [
            r"Clear-Content C:\important.conf",
            r"Cl`ear-Con`tent C:\important.conf",
            "Clear-Content $target",
            "Clear-Content 'C:\\important.conf",
        ] {
            lab.assert_surfaces(
                &with_late_statement(512, last),
                "deny",
                Some(CLEAR_RULE),
                Some(5000),
            );
        }
    }

    #[test]
    fn quoted_data_and_unverified_execution_keep_distinct_outcomes() {
        let lab = Lab::new();
        let quoted = vec![
            r"Write-Output 'Remove-Item C:\example -Recurse -Force; .Delete($true) read-only'";
            512
        ]
        .join("; ");
        lab.assert_surfaces(&quoted, "allow", None, Some(5000));
        for last in [
            r"& $command -Recurse -Force C:\example",
            r"Remove-Item C:\example -Recurse:$flag",
            "Cl`ear-Content`",
        ] {
            lab.assert_surfaces(&with_late_statement(400, last), "deny", None, Some(5000));
        }
        let too_many_tokens = format!("Clear-Content {}", vec!["'x'"; 512].join(" "));
        lab.assert_surfaces(
            &too_many_tokens,
            "deny",
            Some("windows.filesystem:windows-filesystem-semantic-unverified"),
            Some(5000),
        );
    }

    #[test]
    fn a_small_configured_deadline_cannot_allow_an_unread_remainder() {
        let lab = Lab::new();
        // Configuration clamps 1 ms to the existing production minimum.
        // Neither this check nor the implementation raises that minimum.
        lab.assert_budget(
            Some(1),
            destructive_command_guard::perf::MIN_HOOK_TIMEOUT_MS,
            "configured",
        );
        lab.assert_surfaces(&statements(513), "indeterminate", None, Some(1));
    }
}

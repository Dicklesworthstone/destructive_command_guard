//! Regression pins for bd-1o5h and native PowerShell pipeline stdin execution.
//!
//! Covers shell and script-interpreter consumers, literal/here-string/
//! `Write-Output`/file producers, and fixed programs that forward stdin to an
//! executing receiver. Data sinks and fixed programs that do not execute
//! stdin provide the corresponding allow controls.
//!
//! Hook and CLI tests inspect command text without executing it. An ignored
//! Unix fixture checks native PowerShell 7, Python, and Bash against
//! disposable credential-shaped files.

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
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

const CREDENTIAL_WRITE: &str = "core.filesystem:credential-file-write";
const GIT_INTERNALS_WRITE: &str = "core.filesystem:git-internals-write";
const PIPELINE_SOURCE_UNKNOWN: &str = "heredoc.posix:pipeline-consumer";
const PIPELINE_SOURCE_FILE: &str = "heredoc.posix:pipeline-file-source";

/// Both entry points inspect the submitted strings; none of these payloads
/// are executed by the test process.
struct PipelineFixture {
    dir: tempfile::TempDir,
}

impl PipelineFixture {
    fn new(grants: &[&str]) -> Self {
        let dir = tempfile::tempdir().expect("isolated pipeline fixture");
        let config = dir.path().join("home/config/dcg");
        std::fs::create_dir_all(&config).expect("config directory");
        std::fs::write(
            dir.path().join("config.toml"),
            "[history]\nenabled = false\n",
        )
        .expect("isolated configuration");
        let mut allowlist = String::new();
        for rule in grants {
            writeln!(
                allowlist,
                "[[allow]]\nrule = \"{rule}\"\nreason = \"one reviewed pipeline rule\""
            )
            .expect("write pipeline rule grant to String");
        }
        std::fs::write(config.join("allowlist.toml"), allowlist).expect("isolated allowlist");
        Self { dir }
    }

    fn process(&self) -> Command {
        let home = self.dir.path().join("home");
        let mut process = Command::new(dcg_binary());
        process
            .env_clear()
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_CACHE_HOME", home.join("cache"))
            .env("XDG_DATA_HOME", home.join("data"))
            .env("APPDATA", home.join("appdata"))
            .env("LOCALAPPDATA", home.join("localappdata"))
            .env("TMPDIR", self.dir.path())
            .env("TEMP", self.dir.path())
            .env("TMP", self.dir.path())
            .env("DCG_CONFIG", self.dir.path().join("config.toml"))
            .env("DCG_PACKS", PACKS)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env(
                "DCG_PENDING_EXCEPTIONS_PATH",
                self.dir.path().join("pending.jsonl"),
            )
            .env("DCG_SELF_HEAL_HOOK", "0")
            .env("DCG_HOOK_TIMEOUT_MS", "30000")
            .env("DCG_AST_TIMEOUT_MS", "5000")
            .current_dir(self.dir.path());
        process
    }

    fn check(&self, command: &str, expected: Option<&str>) {
        self.check_tool(command, "PowerShell", "powershell", expected);
    }

    fn check_tool(&self, command: &str, tool: &str, dialect: &str, expected: Option<&str>) {
        let payload = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": { "command": command },
            "cwd": self.dir.path(),
        });
        let mut child = self
            .process()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("real hook");
        child
            .stdin
            .take()
            .expect("hook stdin")
            .write_all(payload.to_string().as_bytes())
            .expect("hook payload");
        let output = child.wait_with_output().expect("hook response");
        assert!(
            output.status.success(),
            "{command:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if let Some(rule) = expected {
            let json: serde_json::Value =
                serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
                    panic!(
                        "{command:?}: {error}: {}",
                        String::from_utf8_lossy(&output.stdout)
                    )
                });
            let hook = &json["hookSpecificOutput"];
            assert_eq!(hook["permissionDecision"], "deny", "{command:?}: {json}");
            let actual = hook["ruleId"].as_str().or_else(|| {
                hook["permissionDecisionReason"]
                    .as_str()?
                    .lines()
                    .find_map(|line| line.strip_prefix("Rule: "))
            });
            assert_eq!(actual, Some(rule), "{command:?}: {json}");
        } else {
            assert!(
                output.stdout.is_empty(),
                "{command:?}: {}",
                String::from_utf8_lossy(&output.stdout)
            );
        }

        let output = self
            .process()
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
            .output()
            .expect("real CLI");
        let json: serde_json::Value =
            serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
                panic!(
                    "{command:?}: {error}: {}",
                    String::from_utf8_lossy(&output.stdout)
                )
            });
        assert_eq!(
            output.status.code(),
            Some(i32::from(expected.is_some())),
            "{command:?}: {json}"
        );
        assert_eq!(
            json["decision"],
            if expected.is_some() { "deny" } else { "allow" },
            "{command:?}: {json}"
        );
        if let Some(rule) = expected {
            let actual = format!(
                "{}:{}",
                json["pack_id"].as_str().unwrap_or(""),
                json["pattern_name"].as_str().unwrap_or("")
            );
            assert_eq!(actual, rule, "{command:?}: {json}");
        }
    }
}

#[test]
fn powershell_literal_pipeline_sources_reach_credential_policy() {
    let fixture = PipelineFixture::new(&[]);
    for command in [
        "@'\nopen(\".ssh/authorized_keys\",\"w\").write(\"x\")\n'@ | python3 -",
        "@\"\nopen(\".ssh/authorized_keys\",\"w\").write(\"x\")\n\"@ | python3 -",
        "(@'\nopen(\".ssh/authorized_keys\",\"w\").write(\"x\")\n'@) | python3 -",
        "'open(\".ssh/authorized_keys\",\"w\").write(\"x\")' | python3",
        "Write-Output 'open(\".ssh/authorized_keys\",\"w\").write(\"x\")' | python3 -",
        "Write-Output -InputObject 'open(\".ssh/authorized_keys\",\"w\")' | python3 -",
        "Write-Output -InputObject:'open(\".ssh/authorized_keys\",\"w\")' | python3 -",
        "Write-Output -InputObject:\"open('.ssh/authorized_keys','w')\" | python3 -",
        "Write-Output \u{2013}InputObject:'open(\".ssh/authorized_keys\",\"w\")' | python3 -",
        "Write-Output -NoEnumerate 'open(\".ssh/authorized_keys\",\"w\")' | python3 -",
        "Write-Output -NoEnumerate:$false 'open(\".ssh/authorized_keys\",\"w\")' | python3 -",
        "Write-Output 'import os' 'os.truncate(\".ssh/authorized_keys\",0)' | python3 -",
        "Write-Output 'import os','os.truncate(\".ssh/authorized_keys\",0)' | python3 -",
        "'open(\"' + '.ssh/authorized_keys' + '\",\"w\")' | python3 -",
        "@'\nprintf x > .ssh/authorized_keys\n'@ | bash",
        "(@'\nprintf x > .ssh/authorized_keys\n'@) | sh",
        "Write-Output @'\nprintf x > .ssh/authorized_keys\n'@ | bash -s",
        "'printf x > .ssh/authorized_keys' | bash --norc",
        "'printf x > .ssh/authorized_keys' | bash -- -",
        "'printf x > .ssh/authorized_keys' | bash -c 'bash -s'",
        "'open(\".ssh/authorized_keys\",\"w\")' | bash -c 'python3 -'",
        "'open(\".ssh/authorized_keys\",\"w\")' | Write-Output | python3 -",
        "'open(\".ssh/authorized_keys\",\"w\")' | echo | write | python3 -",
        "'open(\".ssh/authorized_keys\",\"w\")' | & ('Write-'+'Output') | python3 -",
        "('open(\".ssh/authorized_keys\",\"w\")' | python3 -)",
        "$result = 'open(\".ssh/authorized_keys\",\"w\")' | python3 -",
        "return 'open(\".ssh/authorized_keys\",\"w\")' | python3 -",
    ] {
        fixture.check(command, Some(CREDENTIAL_WRITE));
    }
}

#[test]
fn powershell_native_receiver_names_keep_call_ownership_and_unicode_separators() {
    let fixture = PipelineFixture::new(&[]);
    let source = "'open(\".ssh/authorized_keys\",\"w\")'";
    for receiver in [
        "& 'python3' -",
        "& ('py'+'thon3') -",
        ". 'python3' -",
        ". ('py'+'thon3') -",
        ".('py'+'thon3') -",
        "&('py'+'thon3') -",
        "& '/usr/bin/python3' -",
        "& 'C:\\Program Files\\Python\\python.exe' -",
        "python3\u{00a0}-",
        "python3\u{2003}-",
        "\x60u{70}ython3 -",
        "python3 \"\x60u{2d}\"",
        "python3 \x60\r\n -",
    ] {
        fixture.check(&format!("{source} | {receiver}"), Some(CREDENTIAL_WRITE));
    }
    for receiver in ["& 'python3' -", "& ('py'+'thon3') -"] {
        fixture.check_tool(
            &format!("{source} | {receiver}"),
            "Shell",
            "unknown",
            Some(CREDENTIAL_WRITE),
        );
    }
    for command in [
        "'open(\".ssh/authorized_keys\",\"w\")' | Write-Output | python3 -",
        "@'\nopen(\".ssh/authorized_keys\",\"w\")\n'@ | Write-Output | python3 -",
    ] {
        fixture.check_tool(command, "Shell", "unknown", Some(CREDENTIAL_WRITE));
    }
}

#[test]
fn powershell_foreign_interpreters_share_existing_source_kinds() {
    let fixture = PipelineFixture::new(&[]);
    for command in [
        "'require(\"fs\").writeFileSync(\".ssh/authorized_keys\",\"x\")' | node",
        "'File.write(\".ssh/authorized_keys\",\"x\")' | ruby -E UTF-8",
        "'open(my $f, \">\", \".ssh/authorized_keys\"); print $f \"x\";' | perl",
        "'<?php file_put_contents(\".ssh/authorized_keys\",\"x\");' | php",
    ] {
        fixture.check(command, Some(CREDENTIAL_WRITE));
    }
}

#[test]
fn powershell_pipeline_data_and_fixed_program_modes_remain_allowed() {
    let fixture = PipelineFixture::new(&[]);
    for command in [
        "@'\nprint(\"hello\")\n'@ | python3 -",
        "(@'\nprint(\"hello\")\n'@) | & 'python3' -",
        "Write-Output 'print(\"hello\")' | python3 -",
        "Write-Output -NoEnumerate 'print(\"hello\")' | python3 -",
        "Write-Output -NoEnumerate:$false 'print(\"hello\")' | python3 -",
        "Write-Output -InputObject:'print(\"hello\")' | python3 -",
        "Write-Output -InputObject:\"print('hello')\" | python3 -",
        "Write-Output 'import sys' 'print(sys.version)' | python3 -",
        "Write-Output 'import sys','print(sys.version)' | python3 -",
        "'print(1)' | Write-Output | python3 -",
        "'' | Write-Output | python3 -",
        "'printf harmless' | bash",
        "'console.log(\"hello\")' | node",
        "'puts \"hello\"' | ruby",
        "'print \"hello\";' | perl",
        "'<?php echo \"hello\";' | php",
        "@'\nopen(\".ssh/authorized_keys\",\"w\")\n'@ | Write-Output",
        "@'\nopen(\".ssh/authorized_keys\",\"w\")\n'@ | python3 -c 'print(1)'",
        "@'\nopen(\".ssh/authorized_keys\",\"w\")\n'@ | python3 -m json.tool",
        "'open(\".ssh/authorized_keys\",\"w\")' | python3 script.py",
        "'open(\".ssh/authorized_keys\",\"w\")' | python3 --help",
        "'printf x > .ssh/authorized_keys' | bash -c 'printf harmless'",
        "'printf x > .ssh/authorized_keys' | bash -c ''",
        "'printf x > .ssh/authorized_keys' | bash script.sh",
        "$source | python3 -c 'print(1)' $arguments",
        "$source | python3 -m json.tool",
        "'PYTHONINSPECT=1' | python3 -c 'print(1)'",
        "$source | bash -c 'printf harmless' $arguments",
        "@'\nprint(\"it’s data\")\n'@ | python3 -",
        "Write-Output 'text mentioning python3 and bash' | Out-String",
    ] {
        fixture.check(command, None);
    }
}

#[test]
fn powershell_smart_quoted_pipeline_punctuation_remains_argument_data() {
    let fixture = PipelineFixture::new(&[]);
    for (tool, dialect) in [("PowerShell", "powershell"), ("Shell", "unknown")] {
        for command in [
            "Write-Output \u{201c}text | python3\u{201d}",
            "Write-Output \u{201c}text (| python3)\u{201d}",
            "Write-Output \u{201c}text {| python3}\u{201d}",
            "Write-Output \u{2018}text | python3\u{2019}",
            "Write-Output \u{2018}text (| python3)\u{2019}",
            "Write-Output \u{2018}text {| python3}\u{2019}",
            r#"Write-Output "text | python3""#,
            r#"Write-Output "text (| python3)""#,
            r#"Write-Output "text {| python3}""#,
        ] {
            fixture.check_tool(command, tool, dialect, None);
        }
        // Structural quote ownership does not prove the contents of a smart-
        // quoted executable source. A real receiver still fails closed.
        for command in [
            "Write-Output \u{201c}open('.ssh/authorized_keys','w')\u{201d} | python3 -",
            "Write-Output \u{2018}open(\".ssh/authorized_keys\",\"w\")\u{2019} | python3 -",
        ] {
            fixture.check_tool(command, tool, dialect, Some(PIPELINE_SOURCE_UNKNOWN));
        }
    }
}

#[test]
fn powershell_unresolved_pipeline_sources_and_receiver_options_fail_closed() {
    let fixture = PipelineFixture::new(&[]);
    for command in [
        "$source | python3 -",
        "$source | Write-Output | python3 -",
        "Get-UnknownSource | python3 -",
        "Write-Output $source | & 'python3' -",
        "@\"\n$source\n\"@ | python3 -",
        "'print(1)' | python3 $options",
        "'print(1)' | python3 -c $program",
        "'print(1)' | python3 -m $module",
        "'print(1)' | & $receiver",
        "'print(1)' | python3 -i -c 'print(2)'",
        "'print(1)' | python3 -c 'exec(input())'",
        "$env:PYTHONINSPECT = '1'; 'print(1)' | python3 -c 'print(2)'",
        "Write-Output \u{2018}print(1)\u{2019} | python3 -",
    ] {
        fixture.check(command, Some(PIPELINE_SOURCE_UNKNOWN));
    }
    for command in [
        "Get-Content payload.py | python3 -",
        "Get-Content -Raw payload.py | & 'python3' -",
        "gc payload.sh | bash",
        "cat payload.rb | ruby",
    ] {
        fixture.check(command, Some(PIPELINE_SOURCE_FILE));
    }
}

#[test]
fn powershell_pipeline_rule_grants_keep_independent_findings() {
    let credential = "'open(\".ssh/authorized_keys\",\"w\")' | python3 -";
    let git = "'open(\".git/config\",\"w\")' | python3 -";
    for (grant, expected) in [
        (CREDENTIAL_WRITE, GIT_INTERNALS_WRITE),
        (GIT_INTERNALS_WRITE, CREDENTIAL_WRITE),
    ] {
        let fixture = PipelineFixture::new(&[grant]);
        for command in [
            format!("{credential}; {git}"),
            format!("{git}; {credential}"),
        ] {
            fixture.check(&command, Some(expected));
        }
    }
    PipelineFixture::new(&[PIPELINE_SOURCE_UNKNOWN]).check(
        &format!("Get-UnknownSource | python3 -; {credential}"),
        Some(CREDENTIAL_WRITE),
    );
    PipelineFixture::new(&[CREDENTIAL_WRITE]).check(
        &format!("{credential}; Get-UnknownSource | python3 -"),
        Some(PIPELINE_SOURCE_UNKNOWN),
    );
    // Granting a generic POSIX-producer fallback must not suppress a native
    // PowerShell view that can resolve and classify the actual Python source.
    let generic_grant = PipelineFixture::new(&[PIPELINE_SOURCE_UNKNOWN]);
    for command in [
        "'open(\".ssh/authorized_keys\",\"w\")' | python3 -",
        "@'\nopen(\".ssh/authorized_keys\",\"w\")\n'@ | python3 -",
    ] {
        generic_grant.check_tool(command, "Shell", "unknown", Some(CREDENTIAL_WRITE));
    }
    for command in [
        "'print(1)' | python3 -",
        "@'\nprint(1)\n'@ | python3 -",
        "$source | python3 -c 'print(1)'",
    ] {
        generic_grant.check_tool(command, "Shell", "unknown", None);
    }
}

#[test]
fn powershell_pipeline_limits_never_discard_a_later_receiver() {
    let fixture = PipelineFixture::new(&[]);
    let mut command = "Write-Output harmless; ".repeat(129);
    command.push_str("'open(\".ssh/authorized_keys\",\"w\")' | python3 -");
    fixture.check(&command, Some("heredoc.shell:analysis-bounds"));
}

#[cfg(unix)]
#[test]
#[ignore = "requires native PowerShell 7 (pwsh), python3, and bash on PATH"]
fn native_powershell_pipeline_sources_confirm_execution_and_data_modes() {
    // Native semantics only: every case owns a disposable credential-shaped
    // target. Hook decisions are exercised by the separate tests above.
    let dir = tempfile::tempdir().expect("native PowerShell pipeline fixtures");
    let script = r#"
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
if ($PSVersionTable.PSVersion.Major -lt 7 -or $IsWindows) {
    throw 'This fixture requires PowerShell 7 on Unix'
}
Get-Command python3, bash -CommandType Application -ErrorAction Stop | Out-Null
$root = $env:DCG_PIPELINE_NATIVE_ROOT
$results = [System.Collections.Generic.List[object]]::new()
$cases = @(
    @{ Name='literal_bare_python'; Expected="NEW`n"; Body={
        'open(".ssh/authorized_keys","w").write("NEW\n")' | python3
    } },
    @{ Name='literal_here_python'; Expected="NEW`n"; Body={
@'
open(".ssh/authorized_keys","w").write("NEW\n")
'@ | python3 -
    } },
    @{ Name='expandable_here_python'; Expected="NEW`n"; Body={
@"
open(".ssh/authorized_keys","w").write("NEW\n")
"@ | python3 -
    } },
    @{ Name='write_output_python'; Expected="NEW`n"; Body={
        Write-Output 'open(".ssh/authorized_keys","w").write("NEW\n")' | python3 -
    } },
    @{ Name='inputobject_colon'; Expected="NEW`n"; Body={
        Write-Output -InputObject:'open(".ssh/authorized_keys","w").write("NEW\n")' | python3 -
    } },
    @{ Name='inputobject_unicode_dash'; Expected="NEW`n"; Body={
        Write-Output –InputObject:'open(".ssh/authorized_keys","w").write("NEW\n")' | python3 -
    } },
    @{ Name='no_enumerate'; Expected="NEW`n"; Body={
        Write-Output -NoEnumerate 'open(".ssh/authorized_keys","w").write("NEW\n")' | python3 -
    } },
    @{ Name='no_enumerate_false'; Expected="NEW`n"; Body={
        Write-Output -NoEnumerate:$false 'open(".ssh/authorized_keys","w").write("NEW\n")' | python3 -
    } },
    @{ Name='records_space'; Expected=''; Body={
        Write-Output 'import os' 'os.truncate(".ssh/authorized_keys",0)' | python3 -
    } },
    @{ Name='records_comma'; Expected=''; Body={
        Write-Output 'import os','os.truncate(".ssh/authorized_keys",0)' | python3 -
    } },
    @{ Name='passthrough'; Expected="NEW`n"; Body={
        'open(".ssh/authorized_keys","w").write("NEW\n")' | Write-Output | python3 -
    } },
    @{ Name='quoted_receiver'; Expected="NEW`n"; Body={
        'open(".ssh/authorized_keys","w").write("NEW\n")' | & 'python3' -
    } },
    @{ Name='computed_receiver'; Expected="NEW`n"; Body={
        'open(".ssh/authorized_keys","w").write("NEW\n")' | & ('py'+'thon3') -
    } },
    @{ Name='attached_dot_receiver'; Expected="NEW`n"; Body={
        'open(".ssh/authorized_keys","w").write("NEW\n")' | .('py'+'thon3') -
    } },
    @{ Name='unicode_receiver'; Expected="NEW`n"; Body={
        'open(".ssh/authorized_keys","w").write("NEW\n")' | `u{70}ython3 "`u{2d}"
    } },
    @{ Name='bash_here'; Expected="NEW`n"; Body={
@'
printf 'NEW\n' > .ssh/authorized_keys
'@ | bash
    } },
    @{ Name='bash_forwards_bash'; Expected="NEW`n"; Body={
        'printf "NEW\n" > .ssh/authorized_keys' | bash -c 'bash -s'
    } },
    @{ Name='bash_forwards_python'; Expected="NEW`n"; Body={
        'open(".ssh/authorized_keys","w").write("NEW\n")' | bash -c 'python3 -'
    } },
    @{ Name='file_source'; Expected="NEW`n"; Body={
        [IO.File]::WriteAllText((Join-Path $caseDir 'payload.py'), 'open(".ssh/authorized_keys","w").write("NEW\n")')
        Get-Content -LiteralPath payload.py | python3 -
    } },
    @{ Name='fixed_python_program'; Expected="OLD`n"; Body={
        'open(".ssh/authorized_keys","w").write("NEW\n")' | python3 -c 'print("harmless")'
    } },
    @{ Name='fixed_bash_program'; Expected="OLD`n"; Body={
        'printf "NEW\n" > .ssh/authorized_keys' | bash -c 'printf harmless'
    } },
    @{ Name='data_receiver'; Expected="OLD`n"; Body={
@'
open(".ssh/authorized_keys","w").write("NEW\n")
'@ | Write-Output
    } }
)
foreach ($case in $cases) {
    $caseDir = Join-Path $root $case.Name
    $ssh = Join-Path $caseDir '.ssh'
    [IO.Directory]::CreateDirectory($ssh) | Out-Null
    $target = Join-Path $ssh 'authorized_keys'
    [IO.File]::WriteAllText($target, "OLD`n")
    $errorId = $null
    $LASTEXITCODE = 0
    Push-Location -LiteralPath $caseDir
    try { . $case.Body | Out-Null } catch { $errorId = $_.FullyQualifiedErrorId }
    finally { Pop-Location }
    $nativeExit = $LASTEXITCODE
    $actual = [IO.File]::ReadAllText($target)
    $passed = $null -eq $errorId -and $nativeExit -eq 0 -and $actual -ceq $case.Expected
    $results.Add([pscustomobject]@{
        name=$case.Name
        expected=$case.Expected
        actual=$actual
        native_exit_code=$nativeExit
        error_id=$errorId
        passed=$passed
    })
}
$failed = @($results | Where-Object { -not $_.passed }).Count
$changed = @($results | Where-Object { $_.actual -cne "OLD`n" }).Count
@{
    version=$PSVersionTable.PSVersion.ToString()
    case_count=$results.Count
    changed_count=$changed
    unchanged_count=($results.Count - $changed)
    failed_count=$failed
    cases=$results.ToArray()
} | ConvertTo-Json -Depth 4 -Compress
if ($failed -ne 0) { exit 1 }
"#;
    let output = Command::new("pwsh")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").expect("native tool PATH"))
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_CACHE_HOME", dir.path().join("cache"))
        .env("TMPDIR", dir.path())
        .env("DCG_PIPELINE_NATIVE_ROOT", dir.path())
        .current_dir(dir.path())
        .stdin(Stdio::null())
        .output()
        .expect("run native PowerShell; put pwsh, python3, and bash on PATH");
    assert!(
        output.status.success(),
        "native PowerShell pipeline fixture failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("complete native pipeline report");
    let cases = report["cases"].as_array().expect("native case results");
    let expected = [
        "literal_bare_python",
        "literal_here_python",
        "expandable_here_python",
        "write_output_python",
        "inputobject_colon",
        "inputobject_unicode_dash",
        "no_enumerate",
        "no_enumerate_false",
        "records_space",
        "records_comma",
        "passthrough",
        "quoted_receiver",
        "computed_receiver",
        "attached_dot_receiver",
        "unicode_receiver",
        "bash_here",
        "bash_forwards_bash",
        "bash_forwards_python",
        "file_source",
        "fixed_python_program",
        "fixed_bash_program",
        "data_receiver",
    ];
    assert_eq!(cases.len(), expected.len(), "{report}");
    for (case, name) in cases.iter().zip(expected) {
        assert_eq!(case["name"], name, "{report}");
        assert_eq!(case["actual"], case["expected"], "{case}");
        assert_eq!(case["native_exit_code"], 0, "{case}");
        assert_eq!(case["passed"], true, "{case}");
        assert!(case["error_id"].is_null(), "{case}");
    }
    assert_eq!(report["case_count"], 22);
    assert_eq!(report["changed_count"], 19);
    assert_eq!(report["unchanged_count"], 3);
    assert_eq!(report["failed_count"], 0);
    println!("Native PowerShell pipeline semantics: {report}");
}

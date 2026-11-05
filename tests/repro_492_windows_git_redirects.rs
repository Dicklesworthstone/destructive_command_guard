//! #492: Windows separators in Git-internals redirects retain their exact
//! truncate/append rule, including when another redirect rule is allowlisted.
//! Commands are JSON hook input to the real binary, never executed payloads.
//! #642 extends those checks to PowerShell's `Tee-Object` file writer:
//! parameter binding, the existing truncation policy, and hook/CLI parity.

use std::fmt::Write as _;
use std::io::Write;
use std::process::{Command, Stdio};

const TRUNCATE: &str = "core.filesystem:redirect-truncate-git-internals-relative";
const APPEND: &str = "core.filesystem:redirect-append-git-internals-relative";
const DYNAMIC: &str = "core.filesystem:redirect-truncate-dynamic-path";
const CREDENTIAL: &str = "core.filesystem:credential-file-write";
const HOME_TRUNCATE: &str = "core.filesystem:redirect-truncate-root-home";
const GIT_WRITE: &str = "core.filesystem:git-internals-write";
const WINDOWS_TOOLS: &[&str] = &["PowerShell", "cmd.exe", "Shell"];

struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new(granted_rules: &[&str]) -> Self {
        let dir = tempfile::tempdir().expect("fixture");
        let config_dir = dir.path().join("home/config/dcg");
        std::fs::create_dir_all(&config_dir).expect("config directory");
        std::fs::write(
            dir.path().join("config.toml"),
            "[history]\nenabled = false\n",
        )
        .expect("default pack configuration");
        let mut allowlist = String::new();
        for rule in granted_rules {
            writeln!(
                allowlist,
                "[[allow]]\nrule = \"{rule}\"\nreason = \"one reviewed redirect rule\""
            )
            .expect("allowlist entry");
        }
        std::fs::write(config_dir.join("allowlist.toml"), allowlist).expect("user allowlist");
        Self { dir }
    }

    fn process(&self) -> Command {
        let home = self.dir.path().join("home");
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
            .env("TMPDIR", self.dir.path())
            .env("TEMP", self.dir.path())
            .env("TMP", self.dir.path())
            .env("DCG_CONFIG", self.dir.path().join("config.toml"))
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env(
                "DCG_PENDING_EXCEPTIONS_PATH",
                self.dir.path().join("pending.jsonl"),
            )
            .env(
                "DCG_ALLOW_ONCE_PATH",
                self.dir.path().join("allow_once.jsonl"),
            )
            .env("DCG_SELF_HEAL_HOOK", "0")
            .env("DCG_HOOK_TIMEOUT_MS", "5000")
            .current_dir(self.dir.path());
        command
    }

    fn hook_output(&self, payload: &serde_json::Value) -> std::process::Output {
        let mut child = self
            .process()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("hook");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(payload.to_string().as_bytes())
            .expect("hook payload");
        child.wait_with_output().expect("hook result")
    }

    fn judge(&self, tool: &str, command: &str) -> (String, String) {
        let payload = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": { "command": command },
            "cwd": self.dir.path(),
        });
        let output = self.hook_output(&payload);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{tool}: {command:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if output.stdout.is_empty() {
            return ("allow".to_string(), String::new());
        }
        let json: serde_json::Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("{tool}: {command:?}: invalid hook JSON: {error}"));
        let hook = &json["hookSpecificOutput"];
        // Explicit Windows tool names use the minimal Codex response. Its
        // supported reason field carries the same stable rule identifier.
        let rule = hook["ruleId"].as_str().or_else(|| {
            hook["permissionDecisionReason"]
                .as_str()?
                .lines()
                .find_map(|line| line.strip_prefix("Rule: "))
        });
        (
            hook["permissionDecision"]
                .as_str()
                .expect("decision")
                .to_string(),
            rule.unwrap_or_default().to_string(),
        )
    }

    fn denied(&self, tool: &str, command: &str, rule: &str) {
        let result = self.judge(tool, command);
        assert_eq!(
            (result.0.as_str(), result.1.as_str()),
            ("deny", rule),
            "{tool}: {command:?}"
        );
    }

    fn allowed(&self, tool: &str, command: &str) {
        let result = self.judge(tool, command);
        assert_eq!(result.0, "allow", "{tool}: {command:?}: {result:?}");
    }

    fn cli_denied(&self, dialect: &str, command: &str, pattern: &str) {
        let output = self
            .process()
            .args([
                "test",
                "--with-packs",
                "core.filesystem",
                "--dialect",
                dialect,
                command,
            ])
            .output()
            .expect("dcg test");
        let full = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            full.contains("Result: BLOCKED")
                && full.contains("Pack: core.filesystem")
                && full.contains(&format!("Pattern: {pattern}")),
            "[{dialect}] {command:?}: {full}"
        );
    }
}

#[test]
fn windows_git_redirects_keep_specific_rules_with_default_and_generic_grants() {
    for grants in [&[][..], &[DYNAMIC][..]] {
        let fixture = Fixture::new(grants);
        for tool in WINDOWS_TOOLS {
            for target in [
                r".git\config",
                r".\.git\HEAD",
                r"sub\.git\hooks\pre-commit",
                r"C:\work\repo\.git\config",
                r#"".git\config""#,
            ] {
                fixture.denied(tool, &format!("echo x > {target}"), TRUNCATE);
                fixture.denied(tool, &format!("echo x >> {target}"), APPEND);
            }
        }
    }
}

#[test]
fn each_git_grant_allows_its_own_mode_but_not_the_other_mode() {
    for tool in WINDOWS_TOOLS {
        // The generic backslash guard is independently reviewed here so the
        // assertions isolate the two exact Git redirect rules.
        let truncate = Fixture::new(&[DYNAMIC, TRUNCATE]);
        truncate.allowed(tool, r"echo x > .git\config");
        truncate.denied(tool, r"echo x >> .git\config", APPEND);
        let append = Fixture::new(&[DYNAMIC, APPEND]);
        append.allowed(tool, r"echo x >> .git\config");
        append.denied(tool, r"echo x > .git\config", TRUNCATE);
    }
}

#[test]
fn one_git_grant_cannot_hide_another_mode_in_the_same_command() {
    for tool in WINDOWS_TOOLS {
        for (granted, blocked) in [(TRUNCATE, APPEND), (APPEND, TRUNCATE)] {
            let fixture = Fixture::new(&[DYNAMIC, granted]);
            // Both stream destinations are opened even if one later receives
            // no bytes; inspect every redirect, in either source order.
            for command in [
                r"echo x > .git\config 2>> .git\HEAD",
                r"echo x 2>> .git\HEAD > .git\config",
                r"echo x >> .git\config 2> .git\HEAD",
                r"echo x 2> .git\HEAD >> .git\config",
            ] {
                fixture.denied(tool, command, blocked);
            }
        }
    }
}

#[test]
fn git_grants_do_not_hide_credential_redirects_in_the_same_command() {
    for tool in WINDOWS_TOOLS {
        for (granted, operator) in [(TRUNCATE, ">"), (APPEND, ">>")] {
            let fixture = Fixture::new(&[DYNAMIC, granted]);
            for command in [
                format!(r"echo x {operator} .git\config 2> .ssh\authorized_keys"),
                format!(r"echo x 2> .ssh\authorized_keys {operator} .git\config"),
            ] {
                fixture.denied(tool, &command, CREDENTIAL);
            }
        }
    }
}

#[test]
fn a_git_grant_does_not_suppress_an_independent_dynamic_redirect() {
    for tool in ["PowerShell", "Shell"] {
        for (granted, operator) in [(TRUNCATE, ">"), (APPEND, ">>")] {
            let fixture = Fixture::new(&[granted]);
            for command in [
                format!(r#"echo x {operator} .git/config 2> "$UNREVIEWED""#),
                format!(r#"echo x 2> "$UNREVIEWED" {operator} .git/config"#),
            ] {
                fixture.denied(tool, &command, DYNAMIC);
            }
        }
    }
}

#[test]
fn posix_backslashes_do_not_become_windows_git_separators() {
    // The old generic dynamic-target guard can still judge a backslash. Once
    // that rule is reviewed, POSIX escaping must not acquire a Git denial.
    let fixture = Fixture::new(&[DYNAMIC]);
    for command in [
        r"echo x > .git\config",
        r"echo x >> .git\config",
        r"echo x > '.git\config'",
        r"echo x >> '.git\config'",
    ] {
        fixture.allowed("Bash", command);
    }
    fixture.denied("Bash", "echo x > .git/config", TRUNCATE);
    fixture.denied("Bash", "echo x >> .git/config", APPEND);
}

#[test]
fn windows_git_redirect_lookalikes_and_data_stay_allowed() {
    let fixture = Fixture::new(&[]);
    for tool in WINDOWS_TOOLS {
        for command in [
            r"echo x > .gitignore",
            r"echo x >> .gitignore",
            r"echo x > .github\workflows\ci.yml",
            r"echo x >> .github\workflows\ci.yml",
            r"echo x > notes.txt",
            r"echo x >> build\output.log",
            r"echo x > git\config",
            r#"echo "example > .git\config""#,
            r#"git commit -m "document >> .git\config denial""#,
        ] {
            fixture.allowed(tool, command);
        }
    }
}

#[test]
fn issue_642_reported_truncations_deny_through_hook_and_cli() {
    let fixture = Fixture::new(&[]);
    for (command, rule, pattern) in [
        (
            r"Get-Date > 'C:\Users\me\important.txt'",
            DYNAMIC,
            "redirect-truncate-dynamic-path",
        ),
        (
            r"Get-Date | Tee-Object -FilePath 'C:\Users\me\important.txt'",
            HOME_TRUNCATE,
            "redirect-truncate-root-home",
        ),
        (
            r"Get-Date | Tee-Object 'C:\Users\me\important.txt'",
            HOME_TRUNCATE,
            "redirect-truncate-root-home",
        ),
    ] {
        for tool in ["PowerShell", "Shell"] {
            fixture.denied(tool, command, rule);
        }
        for dialect in ["powershell", "unknown"] {
            fixture.cli_denied(dialect, command, pattern);
        }
    }
}

#[test]
fn issue_642_tee_aliases_quoting_and_parameter_spellings_deny() {
    let fixture = Fixture::new(&[]);
    for command in [
        r"Get-Date | tee 'C:\Users\me\important.txt'",
        r"Get-Date | tEe -fIlEpAtH 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -Path 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -Pa 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -Fi 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -LiteralPath 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -LP 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -PS 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -FilePath:'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -FilePath: ('C:\Users\me\important.txt')",
        r"Get-Date | Tee-Object -FilePath:('C:\Users\me\important.txt')",
        r#"Get-Date | Tee-Object -FilePath:"C:\Users\me\important.txt""#,
        r"Get-Date | Tee-Object -FilePath C:\Users\me\important` file.txt",
        r"Get-Date | Tee-Object -FilePath C:\Users\me\'important.txt'",
        r"Get-Date | Tee-Obje`ct 'C:\Users\me\important.txt'",
        r"Get-Date | & 'Tee-Object' 'C:\Users\me\important.txt'",
        r"Get-Date | Microsoft.PowerShell.Utility\Tee-Object 'C:\Users\me\important.txt'",
        "Get-Date | Tee-Object \u{2013}FilePath 'C:\\Users\\me\\important.txt'",
        "Get-Date | Tee-Object `\n -FilePath 'C:\\Users\\me\\important.txt'",
    ] {
        fixture.denied("PowerShell", command, HOME_TRUNCATE);
    }
}

#[test]
fn issue_642_tee_parameter_values_cannot_spoof_safe_switches() {
    let fixture = Fixture::new(&[]);
    for command in [
        r"Get-Date | Tee-Object -Append:$false 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -Append: $false 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -Append:($false) 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -Append: ($false) 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -Append:$($false) 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -Append:$(0) 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -Append:${false} 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -Append:0 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -Append:0.0 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -Append:0x0 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -App:$false 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -Append:$append 'C:\Users\me\important.txt'",
        r"Tee-Object -InputObject '-Append' 'C:\Users\me\important.txt'",
        r"Tee-Object -InputObject '-WhatIf' 'C:\Users\me\important.txt'",
        r"Tee-Object -InputObject '-Variable' 'C:\Users\me\important.txt'",
        r"Tee-Object -In '-Append' 'C:\Users\me\important.txt'",
        r"Tee-Object -In:'-WhatIf' 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -E utf8 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -Encoding utf8 -ErrorAction Stop 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -ErrorVariable '-Append' 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -OutVariable '-WhatIf' 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -FilePath 'C:\Users\me\important.txt' -Verbose:$false",
    ] {
        fixture.denied("PowerShell", command, HOME_TRUNCATE);
    }
}

#[test]
fn issue_642_tee_append_variable_data_and_binding_errors_stay_allowed() {
    let fixture = Fixture::new(&[]);
    for command in [
        r"Get-Date | Tee-Object -FilePath 'C:\Users\me\important.txt' -Append",
        r"Get-Date | Tee-Object -Append:$true 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -Append:${true} 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -Append:1 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -Append:0x1 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -Append:$null 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -App 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -Variable result",
        r"Get-Date | Tee-Object -Var result",
        r"Get-Date | Tee-Object -V result",
        r"Get-Date | Tee-Object -Variable '-Append'",
        r"Get-Date | Tee-Object -Variable '-WhatIf'",
        r"Get-Date | Tee-Object -Variable 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -V '.ssh/authorized_keys'",
        r"Get-Date | Tee-Object -Var '.aws/credentials'",
        r"Get-Date | Tee-Object -Variable '.git/config'",
        r"Get-Date | Tee-Object -Variable $name",
        // Tee-Object has no direct WhatIf parameter. These are binding
        // errors, not a preview switch or a file write.
        r"Get-Date | Tee-Object 'C:\Users\me\important.txt' -WhatIf",
        r"Get-Date | Tee-Object 'C:\Users\me\important.txt' -WhatIf:$false",
        r"Get-Date | Tee-Object 'C:\Users\me\important.txt' -Wi",
        r"Get-Date | Tee-Object -LiteralPath 'C:\Users\me\important.txt' -Append",
        r"Get-Date | Tee-Object -Variable result -Append",
        r"Get-Date | Tee-Object -P 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -File`Path 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object -FilePath notes.txt",
        r"Get-Date | Tee-Object -LiteralPath 'notes[1].txt'",
        r"Get-Date | Tee-Object -InputObject 'C:\Users\me\important.txt' notes.txt",
        r"Write-Output 'Get-Date | Tee-Object -FilePath C:\Users\me\important.txt'",
        r"Get-Date # | Tee-Object -FilePath C:\Users\me\important.txt",
        r"Get-Date <# | Tee-Object C:\Users\me\important.txt #>",
        "'Get-Date | Tee-Object /etc/hosts'",
    ] {
        fixture.allowed("PowerShell", command);
    }
    // An explicitly POSIX command must not acquire PowerShell binding.
    fixture.allowed("Bash", r"echo x | Tee-Object 'C:\Users\me\important.txt'");
    fixture.allowed("Bash", r"echo x | tee -a 'C:\Users\me\important.txt'");
}

#[test]
fn issue_642_safe_tee_segment_cannot_exempt_another_writer() {
    let fixture = Fixture::new(&[]);
    for command in [
        r"Get-Date | Tee-Object -Variable result; Get-Date | Tee-Object 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object 'C:\Users\me\important.txt'; Get-Date | Tee-Object -Variable result",
        r"Get-Date | Tee-Object 'C:\Users\me\first.txt' -Append | Tee-Object 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object 'C:\Users\me\first.txt' -WhatIf; Get-Date | Tee-Object 'C:\Users\me\important.txt'",
    ] {
        fixture.denied("PowerShell", command, HOME_TRUNCATE);
    }
    fixture.denied(
        "PowerShell",
        r"Get-Date | Tee-Object -Variable result > 'C:\Users\me\important.txt'",
        DYNAMIC,
    );
}

#[test]
fn issue_642_tee_option_terminator_preserves_positional_filename_binding() {
    let fixture = Fixture::new(&[]);
    for command in [
        r"Get-Date | Tee-Object -- 'C:\Users\me\important.txt'",
        r"Tee-Object -InputObject '-Append' -- 'C:\Users\me\important.txt'",
        r"Tee-Object -InputObject '-WhatIf' -- 'C:\Users\me\important.txt'",
    ] {
        fixture.denied("PowerShell", command, HOME_TRUNCATE);
    }
    fixture.denied("PowerShell", "Get-Date | Tee-Object -- $target", DYNAMIC);
    for command in [
        "Get-Date | Tee-Object -- -Append",
        "Get-Date | Tee-Object -- -WhatIf",
        "Get-Date | Tee-Object -- -Variable",
        "Get-Date | Tee-Object -- '-FilePath'",
        "Get-Date | Tee-Object -- '-LiteralPath'",
    ] {
        // After -- these are ordinary filenames, not safe switches or
        // parameter names. None belongs to the sensitive path policy.
        fixture.allowed("PowerShell", command);
    }
}

#[test]
fn issue_642_one_tee_rule_grant_cannot_hide_another_tee_write() {
    let home = Fixture::new(&[HOME_TRUNCATE]);
    home.allowed(
        "PowerShell",
        r"Get-Date | Tee-Object 'C:\Users\me\important.txt'",
    );
    for command in [
        r"Get-Date | Tee-Object 'C:\Users\me\important.txt'; Get-Date | Tee-Object $unreviewed",
        r"Get-Date | Tee-Object $unreviewed; Get-Date | Tee-Object 'C:\Users\me\important.txt'",
    ] {
        home.denied("PowerShell", command, DYNAMIC);
    }

    let dynamic = Fixture::new(&[DYNAMIC]);
    dynamic.allowed("PowerShell", "Get-Date | Tee-Object $reviewed");
    for command in [
        r"Get-Date | Tee-Object $reviewed; Get-Date | Tee-Object 'C:\Users\me\important.txt'",
        r"Get-Date | Tee-Object 'C:\Users\me\important.txt'; Get-Date | Tee-Object $reviewed",
    ] {
        dynamic.denied("PowerShell", command, HOME_TRUNCATE);
    }

    // The stronger credential and repository-state rules also retain their
    // independent grants. Relative targets isolate those policies from the
    // home/system truncation rule.
    for (granted, blocked, reviewed, unreviewed) in [
        (GIT_WRITE, CREDENTIAL, ".git/config", ".ssh/authorized_keys"),
        (CREDENTIAL, GIT_WRITE, ".ssh/authorized_keys", ".git/config"),
    ] {
        let fixture = Fixture::new(&[granted]);
        for append in ["", " -Append"] {
            fixture.allowed(
                "PowerShell",
                &format!("Get-Date | Tee-Object {reviewed}{append}"),
            );
            for command in [
                format!(
                    "Get-Date | Tee-Object {reviewed}{append}; Get-Date | Tee-Object {unreviewed}{append}"
                ),
                format!(
                    "Get-Date | Tee-Object {unreviewed}{append}; Get-Date | Tee-Object {reviewed}{append}"
                ),
            ] {
                fixture.denied("PowerShell", &command, blocked);
            }
        }
    }
}

#[test]
fn issue_642_tee_preserves_protected_file_write_policies() {
    let fixture = Fixture::new(&[]);
    for command in [
        "'key' | Tee-Object -FilePath ~/.ssh/authorized_keys",
        "'key' | Tee-Object -FilePath ~/.ssh/authorized_keys -Append",
        "'key' | Tee-Object -LP ~/.aws/credentials",
        "Tee-Object -In '-Append' ~/.ssh/authorized_keys",
    ] {
        fixture.denied("PowerShell", command, CREDENTIAL);
    }
    for command in [
        r"Get-Date | Tee-Object .git\config",
        r"Get-Date | Tee-Object .git\config -Append",
        r"Get-Date | Tee-Object -LiteralPath .git\HEAD",
    ] {
        fixture.denied("PowerShell", command, GIT_WRITE);
    }
}

#[test]
fn issue_642_tee_protects_unresolved_and_existing_home_paths() {
    let fixture = Fixture::new(&[]);
    let home = fixture.dir.path().join("home");
    std::fs::write(home.join("important.txt"), "keep this content").expect("existing home file");
    for command in [
        "Get-Date | Tee-Object -FilePath ~/important.txt",
        "Get-Date | Tee-Object -LiteralPath '~/important.txt'",
        "Get-Date | Tee-Object -FilePath ~/missing-parent/new.txt",
        "Get-Date | Tee-Object -FilePath /etc/hosts",
    ] {
        fixture.denied("PowerShell", command, HOME_TRUNCATE);
    }
    for command in [
        "Get-Date | Tee-Object -FilePath $target",
        "Get-Date | Tee-Object -FilePath \"$env:TEMP/output.txt\"",
        "Get-Date | Tee-Object -FilePath (Get-Location)",
        "Get-Date | Tee-Object @options",
    ] {
        fixture.denied("PowerShell", command, DYNAMIC);
    }
    for command in [
        // A quoted dollar sign is a filename, not expansion.
        "Get-Date | Tee-Object -FilePath '$target'",
        "Get-Date | Tee-Object -FilePath ~/new.txt",
        "Get-Date | Tee-Object -FilePath ~/important.txt -Append",
        "Get-Date | Tee-Object -FilePath /tmp/dcg-tee-output.txt",
    ] {
        fixture.allowed("PowerShell", command);
    }
    assert_eq!(
        std::fs::read_to_string(home.join("important.txt")).expect("fixture remains intact"),
        "keep this content"
    );
}

#[test]
fn issue_642_tee_path_normalization_cannot_hide_sensitive_or_unresolved_targets() {
    let fixture = Fixture::new(&[]);
    std::fs::write(
        fixture.dir.path().join("home/important.txt"),
        "existing contents",
    )
    .expect("existing provider-qualified home destination");
    for command in [
        "Get-Date | Tee-Object -FilePath /./etc/hosts",
        "Get-Date | Tee-Object -LiteralPath '/./etc/hosts'",
        r"Get-Date | Tee-Object -FilePath 'C:\.\Users\me\important.txt'",
        r"Get-Date | Tee-Object -LiteralPath 'C:\Users\.\me\important.txt'",
        r"Get-Date | Tee-Object -FilePath 'FileSystem::~/important.txt'",
        r"Get-Date | Tee-Object -FilePath 'Microsoft.PowerShell.Core\FileSystem::~/important.txt'",
    ] {
        fixture.denied("PowerShell", command, HOME_TRUNCATE);
    }
    for command in [
        r"Get-Date | Tee-Object -FilePath '\\server\share\important.txt'",
        r"Get-Date | Tee-Object -LiteralPath '\\server\share\important.txt'",
        "Get-Date | Tee-Object -FilePath ../important.txt",
        "Get-Date | Tee-Object -FilePath build/../../important.txt",
        "Get-Date | Tee-Object -LiteralPath '../important.txt'",
        r"Get-Date | Tee-Object -FilePath 'C:important.txt'",
        r"Get-Date | Tee-Object -FilePath 'FileSystem::C:important.txt'",
        r"Get-Date | Tee-Object -LiteralPath 'FileSystem::\\server\share\important.txt'",
        r"Get-Date | Tee-Object -FilePath 'Microsoft.PowerShell.Core\FileSystem::C:important.txt'",
        r"Get-Date | Tee-Object -FilePath 'Microsoft.PowerShell.Core\FileSystem::\\server\share\important.txt'",
        r"Get-Date | Tee-Object -FilePath 'C:\Users.\me\important.txt'",
        r"Get-Date | Tee-Object -FilePath 'C:\Users \me\important.txt'",
    ] {
        fixture.denied("PowerShell", command, DYNAMIC);
    }
    // The credential classifier cannot prove traversal out of /tmp harmless
    // and retains its stronger, independently allowlistable rule.
    fixture.denied(
        "PowerShell",
        "Get-Date | Tee-Object -FilePath /tmp/../etc/hosts",
        CREDENTIAL,
    );
    for command in [
        "Tee-Object -FilePath 'FileSystem::~/new-notes.txt'",
        r"Tee-Object -FilePath 'Microsoft.PowerShell.Core\FileSystem::~/new-notes.txt'",
        "Tee-Object -FilePath 'FileSystem::/tmp/dcg-provider-notes.txt'",
        "Tee-Object -FilePath 'FileSystem::/dev/null'",
    ] {
        fixture.allowed("PowerShell", command);
    }
}

#[test]
fn issue_642_dynamic_tee_destinations_keep_high_severity_with_confidence_enabled() {
    let fixture = Fixture::new(&[]);
    std::fs::write(
        fixture.dir.path().join("config.toml"),
        "[history]\nenabled = false\n[confidence]\nenabled = true\nwarn_threshold = 0.7\n",
    )
    .expect("enable confidence scoring");
    for command in [
        "Get-Date | Tee-Object $target",
        "Get-Date | Tee-Object -FilePath \"$target\"",
        "Get-Date | Tee-Object -LiteralPath $target",
        "$x = Tee-Object -InputObject x $target",
        "$x=Tee-Object -InputObject x $target",
        "return Tee-Object -InputObject x $target",
        "throw Tee-Object -InputObject x $target",
        "exit Tee-Object -InputObject x $target",
        ". Tee-Object -InputObject x $target",
        "& 'Tee-Object' -InputObject x $target",
        ". 'Tee-Object' -InputObject x $target",
        r". 'Microsoft.PowerShell.Utility\Tee-Object' -InputObject x $target",
    ] {
        // The Anthropic id selects the full Claude hook response, which
        // carries severity. The PowerShell tool still supplies the dialect.
        let payload = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "PowerShell",
            "tool_use_id": "toolu_issue642_confidence",
            "tool_input": { "command": command },
            "cwd": fixture.dir.path(),
        });
        let output = fixture.hook_output(&payload);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{command:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let document: serde_json::Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("{command:?}: expected denial JSON: {error}"));
        let hook = &document["hookSpecificOutput"];
        assert_eq!(
            hook["permissionDecision"], "deny",
            "{command:?}: {document}"
        );
        assert_eq!(hook["ruleId"], DYNAMIC, "{command:?}: {document}");
        assert_eq!(hook["severity"], "high", "{command:?}: {document}");
    }
}

#[test]
fn issue_642_safe_outer_tee_does_not_hide_executed_argument_subexpressions() {
    let fixture = Fixture::new(&[]);
    for command in [
        r"Tee-Object -Variable result -InputObject $(Tee-Object -InputObject x 'C:\Users\me\important.txt')",
        r"Tee-Object -FilePath notes.txt -Append -InputObject $(Tee-Object -InputObject x 'C:\Users\me\important.txt')",
        // Native PowerShell evaluates the input expression before rejecting
        // the outer Tee-Object's unsupported WhatIf parameter.
        r"Tee-Object -FilePath notes.txt -WhatIf -InputObject $(Tee-Object -InputObject x 'C:\Users\me\important.txt')",
    ] {
        fixture.denied("PowerShell", command, HOME_TRUNCATE);
    }
    fixture.allowed(
        "PowerShell",
        "Tee-Object -Variable result -InputObject '$(Tee-Object -InputObject x /etc/hosts)'",
    );
}

#[test]
fn issue_642_statement_positions_cannot_hide_tee_writes() {
    let fixture = Fixture::new(&[]);
    for command in [
        "$x = Tee-Object -InputObject NEW -FilePath /etc/hosts",
        "$x=Tee-Object -InputObject NEW -FilePath /etc/hosts",
        "$x = 'NEW' | Tee-Object -FilePath /etc/hosts",
        "$x = & Tee-Object -InputObject NEW -FilePath /etc/hosts",
        "$x = & 'Tee-Object' -InputObject NEW -FilePath /etc/hosts",
        "$x = . Tee-Object -InputObject NEW -FilePath /etc/hosts",
        "$x = $y = Tee-Object -InputObject NEW -FilePath /etc/hosts",
        "$x=$y=Tee-Object -InputObject NEW -FilePath /etc/hosts",
        "$x = ''; $x += Tee-Object -InputObject NEW -FilePath /etc/hosts",
        "$x = $null; $x ??= Tee-Object -InputObject NEW -FilePath /etc/hosts",
        "$x,$y = Tee-Object -InputObject NEW -FilePath /etc/hosts",
        "$x = @(''); $x[0] = Tee-Object -InputObject NEW -FilePath /etc/hosts",
        "$x = [PSCustomObject]@{a=''}; $x.a = Tee-Object -InputObject NEW -FilePath /etc/hosts",
        "$script:x = Tee-Object -InputObject NEW -FilePath /etc/hosts",
        "${x} = Tee-Object -InputObject NEW -FilePath /etc/hosts",
        "Write-Output ($x = Tee-Object -InputObject NEW -FilePath /etc/hosts)",
        "[string]$x = Tee-Object -InputObject NEW -FilePath /etc/hosts",
        "return Tee-Object -InputObject NEW -FilePath /etc/hosts",
        "return 'NEW' | Tee-Object -FilePath /etc/hosts",
        "return & Tee-Object -InputObject NEW -FilePath /etc/hosts",
        "return . Tee-Object -InputObject NEW -FilePath /etc/hosts",
        "return (Tee-Object -InputObject NEW -FilePath /etc/hosts)",
        "throw Tee-Object -InputObject NEW -FilePath /etc/hosts",
        "exit Tee-Object -InputObject NEW -FilePath /etc/hosts",
        "exit 'NEW' | Tee-Object -FilePath /etc/hosts",
        "exit & Tee-Object -InputObject NEW -FilePath /etc/hosts",
    ] {
        // Native PowerShell executes each right-hand pipeline before storing
        // its output, returning, throwing, or exiting.
        fixture.denied("PowerShell", command, HOME_TRUNCATE);
    }
}

#[test]
fn issue_642_statement_lookalikes_in_literals_and_arguments_stay_allowed() {
    let fixture = Fixture::new(&[]);
    for command in [
        "$x = 'Tee-Object -FilePath /etc/hosts'",
        "[string]$x = 'Tee-Object -FilePath /etc/hosts'",
        "return 'Tee-Object -FilePath /etc/hosts'",
        "throw 'Tee-Object -FilePath /etc/hosts'",
        "exit 'Tee-Object -FilePath /etc/hosts'",
        r#"Write-Output "$x = Tee-Object -FilePath /etc/hosts""#,
        "Write-Output return Tee-Object -FilePath /etc/hosts",
        "Write-Output throw Tee-Object -FilePath /etc/hosts",
        "Write-Output exit Tee-Object -FilePath /etc/hosts",
        "Write-Output '$x' = Tee-Object -FilePath /etc/hosts",
        "Write-Output '$script:x' = Tee-Object -FilePath /etc/hosts",
        "Write-Output '[string]$x' = Tee-Object -FilePath /etc/hosts",
        "Write-Output '$x[0]' += Tee-Object -FilePath /etc/hosts",
        "Write-Output '$x.a' '??=' Tee-Object -FilePath /etc/hosts",
    ] {
        fixture.allowed("PowerShell", command);
    }
}

#[test]
fn issue_642_stop_parsing_preserves_data_and_real_command_boundaries() {
    let fixture = Fixture::new(&[]);
    for command in [
        "Write-Output --% ; Tee-Object -InputObject NEW -FilePath /etc/hosts",
        "Write-Output --% Tee-Object -InputObject NEW -FilePath /etc/hosts",
        r#"Write-Output --% "inert| Tee-Object -InputObject NEW -FilePath /etc/hosts""#,
        "Write-Output '--% ; Tee-Object -InputObject NEW -FilePath /etc/hosts'",
        "Tee-Object -InputObject NEW -FilePath '--%'",
        "Get-Date | Tee-Object '--%'",
    ] {
        fixture.allowed("PowerShell", command);
    }
    for command in [
        "Write-Output --% inert | Tee-Object -FilePath /etc/hosts",
        "Write-Output --% inert && Tee-Object -InputObject NEW -FilePath /etc/hosts",
        "Write-Output --% inert\nTee-Object -InputObject NEW -FilePath /etc/hosts",
        "Write-Output --% inert\r\nTee-Object -InputObject NEW -FilePath /etc/hosts",
        "Write-Output --% inert `\nTee-Object -InputObject NEW -FilePath /etc/hosts",
        "Write-Output --% inert `\r\nTee-Object -InputObject NEW -FilePath /etc/hosts",
        // A binding error in an earlier command does not stop the following
        // statement under PowerShell's default Continue error preference.
        "Tee-Object --% inert\nTee-Object -InputObject NEW -FilePath /etc/hosts",
        "Write-Output '--%'; Tee-Object -InputObject NEW -FilePath /etc/hosts",
    ] {
        fixture.denied("PowerShell", command, HOME_TRUNCATE);
    }
}

#[test]
fn issue_642_stop_parsing_cannot_borrow_discarded_safe_parameters() {
    let fixture = Fixture::new(&[]);
    for command in [
        "Tee-Object -InputObject '--%' -FilePath /etc/hosts",
        r#"Tee-Object -InputObject "--%" -FilePath /etc/hosts"#,
        // Native parsing discards the parameter immediately after this
        // separate quoted marker. These apparent exemptions never reach
        // Tee-Object's binder, and the remaining positional path is written.
        "Tee-Object -InputObject '--%' -Append /etc/hosts",
        "Tee-Object -InputObject '--%' -Variable /etc/hosts",
        "Tee-Object -InputObject '--%' -WhatIf /etc/hosts",
        "Tee-Object -InputObject '--%' -Confirm /etc/hosts",
        "Tee-Object -InputObject '--%' -Unknown /etc/hosts",
        // A pending value consumes the stop-parsing marker itself. Its
        // remaining literal operand can still bind the file destination.
        "Tee-Object -InputObject --% /etc/hosts",
        "Tee-Object -InputObject NEW -OutVariable --% /etc/hosts",
        "Tee-Object -InputObject NEW -PipelineVariable --% /etc/hosts",
        // A quoted-leading token ends at its closing quote even without
        // whitespace before the next parameter.
        "Tee-Object -InputObject 'NEW'-FilePath /etc/hosts",
    ] {
        fixture.denied("PowerShell", command, HOME_TRUNCATE);
    }
}

#[test]
fn issue_642_stop_parsing_preserves_actual_append_and_binding_errors() {
    let fixture = Fixture::new(&[]);
    for command in [
        "Tee-Object -InputObject:'--%' -Append /etc/hosts",
        "Tee-Object -InputObject:--% -Append /etc/hosts",
        "Tee-Object -InputObject ('--%') -Append /etc/hosts",
        "Tee-Object -Append -InputObject '--%' /etc/hosts",
        // These are separate quoted-leading arguments, not a concatenated
        // stop-parsing marker. Native binding rejects the extra operands.
        r#"Tee-Object -InputObject '-'""'-%' -FilePath /etc/hosts"#,
    ] {
        fixture.allowed("PowerShell", command);
    }
}

#[test]
fn issue_642_escaped_quotes_in_groups_keep_executable_tee_commands() {
    let fixture = Fixture::new(&[]);
    for command in [
        r#"Write-Output (Write-Output "a`")" | Tee-Object -FilePath '/etc/hosts')"#,
        r#"Write-Output ("a`")" + (Tee-Object -InputObject NEW -FilePath '/etc/hosts'))"#,
    ] {
        // The escaped quote and quoted ')' do not close the ordinary group.
        fixture.denied("PowerShell", command, HOME_TRUNCATE);
    }
    fixture.allowed(
        "PowerShell",
        r#"Write-Output ("a`") Tee-Object -FilePath /etc/hosts")"#,
    );
}

#[test]
fn issue_642_native_tee_targets_keep_independent_rule_grants() {
    for (granted, blocked, reviewed, unreviewed) in [
        (GIT_WRITE, CREDENTIAL, ".git/config", ".ssh/authorized_keys"),
        (CREDENTIAL, GIT_WRITE, ".ssh/authorized_keys", ".git/config"),
    ] {
        let fixture = Fixture::new(&[granted]);
        for tool in ["PowerShell", "Shell"] {
            for options in ["", "-a ", "-- "] {
                // On Unix, PowerShell runs native tee, which opens every file
                // operand. Unknown-dialect analysis must retain this reading,
                // and a grant for one destination covers no others.
                fixture.allowed(tool, &format!("'key' | tee {options}{reviewed}"));
                for command in [
                    format!("'key' | tee {options}{reviewed} {unreviewed}"),
                    format!("'key' | tee {options}{unreviewed} {reviewed}"),
                ] {
                    fixture.denied(tool, &command, blocked);
                }
            }
        }
    }
    let fully_reviewed = Fixture::new(&[GIT_WRITE, CREDENTIAL]);
    for tool in ["PowerShell", "Shell"] {
        fully_reviewed.allowed(tool, "'key' | tee .git/config .ssh/authorized_keys");
    }
}

#[test]
fn issue_642_parser_depth_exhaustion_cannot_produce_an_allow() {
    let fixture = Fixture::new(&[]);
    for depth in [40, 64] {
        let nested = format!(
            "{}Tee-Object -InputObject NEW -FilePath /etc/hosts{}",
            "(".repeat(depth),
            ")".repeat(depth),
        );
        let command = format!("Write-Output {nested}");
        let verdict = fixture.judge("PowerShell", &command);
        assert!(
            matches!(verdict.0.as_str(), "ask" | "deny"),
            "incomplete analysis at depth {depth} must not allow: {verdict:?}"
        );
        // The same punctuation inside a literal is data and should not spend
        // the executable-expression recursion budget.
        fixture.allowed("PowerShell", &format!("Write-Output '{nested}'"));
    }
}

#[test]
fn computed_powershell_tee_commands_keep_hook_and_cli_truncation_verdicts() {
    let fixture = Fixture::new(&[]);
    // bd-ps-cross-dialect-gaps-ewf3: these native-confirmed calls previously
    // bypassed either both dialects or the generic Shell hook alone.
    for invocation in [
        "& ('Tee-Object')",
        "& ('Tee-'+'Object')",
        ". ('Tee-'+'Object')",
        "& ((('Tee-Object')))",
        "& (('Tee-') + ('Object'))",
        r"& ('Microsoft.PowerShell.Utility\Tee-'+'Object')",
        r#"& ("Tee`u{2d}Object")"#,
        r#"& "Tee`u{2d}Object""#,
    ] {
        let command = format!("{invocation} -InputObject NEW -FilePath /etc/hosts");
        for tool in ["PowerShell", "Shell"] {
            fixture.denied(tool, &command, HOME_TRUNCATE);
        }
        for dialect in ["powershell", "unknown"] {
            fixture.cli_denied(dialect, &command, "redirect-truncate-root-home");
        }
    }
}

#[test]
fn computed_powershell_tee_commands_keep_binding_and_data_controls() {
    let fixture = Fixture::new(&[]);
    for tool in ["PowerShell", "Shell"] {
        for invocation in ["& ('Tee-'+'Object')", ". ((('Tee-Object')))"] {
            fixture.denied(
                tool,
                &format!("{invocation} -InputObject NEW -FilePath /etc/hosts -Append:$false"),
                HOME_TRUNCATE,
            );
            fixture.denied(
                tool,
                &format!("{invocation} -InputObject NEW -FilePath .ssh/authorized_keys -Append"),
                CREDENTIAL,
            );
            for arguments in [
                "-InputObject NEW -FilePath /etc/hosts -Append",
                "-InputObject NEW -Variable result",
                "-InputObject NEW -Variable .ssh/authorized_keys",
                "-InputObject NEW -FilePath /etc/hosts -WhatIf",
                "-InputObject NEW -FilePath notes.txt",
            ] {
                fixture.allowed(tool, &format!("{invocation} {arguments}"));
            }
        }
        for command in [
            "Write-Output ('Tee-'+'Object') -FilePath /etc/hosts",
            "Write-Output ('Tee-Object') -FilePath /etc/hosts",
            "('Tee-'+'Object')",
            r#"Write-Output "& ('Tee-'+'Object') -FilePath /etc/hosts""#,
            // A resolved callee is one command name, even when it contains
            // spaces or looks like a command line.
            "& ('Tee-Object /etc/hosts')",
            "& ('Tee-Object ' + '/etc/hosts')",
            r"& ('Other.Module\Tee-Object') -InputObject NEW -FilePath /etc/hosts",
            // These postfixes change the callee value. The quoted prefix
            // alone cannot establish a Tee-Object invocation.
            "& 'Tee-Object'[0] -InputObject NEW -FilePath /etc/hosts",
            "& 'Tee-Object'.Length -InputObject NEW -FilePath /etc/hosts",
        ] {
            fixture.allowed(tool, command);
        }
    }
}

#[test]
fn computed_powershell_tee_depth_bounds_cannot_produce_an_allow() {
    let fixture = Fixture::new(&[]);
    for depth in [25, 64] {
        let callee = format!("{}'Tee-Object'{}", "(".repeat(depth), ")".repeat(depth));
        let command = format!("& {callee} -InputObject NEW -FilePath /etc/hosts");
        for tool in ["PowerShell", "Shell"] {
            let verdict = fixture.judge(tool, &command);
            assert!(
                matches!(verdict.0.as_str(), "ask" | "deny"),
                "{tool}: a computed writer at depth {depth} must not allow: {verdict:?}"
            );
            fixture.allowed(tool, &format!("Write-Output \"{command}\""));
        }
    }
}

#[test]
#[ignore = "requires native PowerShell"]
fn issue_642_native_powershell_confirms_tee_file_semantics() {
    let dir = tempfile::tempdir().expect("native Tee-Object fixtures");
    let script = r#"
$ErrorActionPreference = 'Stop'
$root = $env:DCG_TEE_NATIVE_ROOT
$completed = [System.Collections.Generic.List[string]]::new()
function Assert-Content($path, $expected) {
    $actual = [IO.File]::ReadAllText($path).Replace("`r`n", "`n")
    if ($actual -cne $expected) { throw "Unexpected file contents: $path" }
}
$cases = @(
    @{ Name='named'; Expected="NEW`n"; Body={ param($file) 'NEW' | Tee-Object -FilePath $file } },
    @{ Name='positional'; Expected="NEW`n"; Body={ param($file) 'NEW' | Tee-Object $file } },
    @{ Name='append_true'; Expected="OLD`nNEW`n"; Body={ param($file) 'NEW' | Tee-Object $file -Append:$true } },
    @{ Name='append_false'; Expected="NEW`n"; Body={ param($file) 'NEW' | Tee-Object $file -Append:$false } },
    @{ Name='variable'; Expected="OLD`n"; Body={
        param($file)
        'NEW' | Tee-Object -Variable captured
        if ($captured -cne 'NEW') { throw 'Tee-Object did not set the variable' }
    } },
    @{ Name='whatif_error'; Expected="OLD`n"; ExpectError=$true; Body={ param($file) 'NEW' | Tee-Object $file -WhatIf } },
    @{ Name='computed_parenthesized'; Expected="NEW`n"; Body={ param($file) & ('Tee-Object') -InputObject NEW -FilePath $file } },
    @{ Name='computed_concat'; Expected="NEW`n"; Body={ param($file) & ('Tee-'+'Object') -InputObject NEW -FilePath $file } },
    @{ Name='computed_dot'; Expected="NEW`n"; Body={ param($file) . ('Tee-'+'Object') -InputObject NEW -FilePath $file } },
    @{ Name='computed_nested'; Expected="NEW`n"; Body={ param($file) & ((('Tee-Object'))) -InputObject NEW -FilePath $file } },
    @{ Name='computed_grouped_concat'; Expected="NEW`n"; Body={ param($file) & (('Tee-') + ('Object')) -InputObject NEW -FilePath $file } },
    @{ Name='computed_module'; Expected="NEW`n"; Body={ param($file) & ('Microsoft.PowerShell.Utility\Tee-'+'Object') -InputObject NEW -FilePath $file } },
    @{ Name='computed_append_true'; Expected="OLD`nNEW`n"; Body={ param($file) & ('Tee-'+'Object') -InputObject NEW -FilePath $file -Append } },
    @{ Name='computed_append_false'; Expected="NEW`n"; Body={ param($file) & ('Tee-'+'Object') -InputObject NEW -FilePath $file -Append:$false } },
    @{ Name='computed_variable'; Expected="OLD`n"; Body={
        param($file)
        & ('Tee-'+'Object') -InputObject NEW -Variable captured
        if ($captured -cne 'NEW') { throw 'Computed Tee-Object did not set the variable' }
    } },
    @{ Name='computed_whatif_error'; Expected="OLD`n"; ExpectError=$true; Body={ param($file) & ('Tee-'+'Object') -InputObject NEW -FilePath $file -WhatIf } },
    @{ Name='computed_inert_argument'; Expected="OLD`n"; Body={ param($file) Write-Output ('Tee-'+'Object') -FilePath $file } },
    @{ Name='computed_inert_expression'; Expected="OLD`n"; Body={ param($file) ('Tee-'+'Object') } }
)
$unicodeCalleeTested = $PSVersionTable.PSVersion.Major -ge 7
if ($unicodeCalleeTested) {
    $cases += @{ Name='computed_unicode'; Expected="NEW`n"; Body={ param($file) & ("Tee`u{2d}Object") -InputObject NEW -FilePath $file } }
}
if ($IsWindows) {
    if ((Get-Alias tee).Definition -ne 'Tee-Object') { throw 'Expected the native Windows tee alias' }
    $cases += @{ Name='windows_tee_alias'; Expected="NEW`n"; Body={ param($file) 'NEW' | tee $file } }
}
foreach ($case in $cases) {
    $file = Join-Path $root ($case.Name + '.txt')
    [IO.File]::WriteAllText($file, "OLD`n")
    $errorId = $null
    try { & $case.Body $file | Out-Null } catch { $errorId = $_.FullyQualifiedErrorId }
    if ($case.ExpectError) {
        if ($errorId -notlike 'NamedParameterNotFound,*') { throw 'WhatIf should be a parameter-binding error' }
    } elseif ($null -ne $errorId) {
        throw "Unexpected native error in $($case.Name): $errorId"
    }
    Assert-Content $file $case.Expected
    $completed.Add($case.Name)
}
$expanded = Join-Path $root 'file1.txt'
$literal = Join-Path $root 'file[1].txt'
[IO.File]::WriteAllText($expanded, "OLD`n")
[IO.File]::WriteAllText($literal, "OLD`n")
'NEW' | Tee-Object -FilePath $literal | Out-Null
Assert-Content $expanded "NEW`n"
Assert-Content $literal "OLD`n"
$completed.Add('filepath_glob')
[IO.File]::WriteAllText($expanded, "OLD`n")
'NEW' | Tee-Object -LiteralPath $literal | Out-Null
Assert-Content $literal "NEW`n"
Assert-Content $expanded "OLD`n"
$completed.Add('literalpath_glob')
@{
    version=$PSVersionTable.PSVersion.ToString()
    windows_alias_tested=[bool]$IsWindows
    unicode_callee_tested=[bool]$unicodeCalleeTested
    cases=$completed.ToArray()
} | ConvertTo-Json -Compress
"#;
    let output = Command::new("pwsh")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("DCG_TEE_NATIVE_ROOT", dir.path())
        .current_dir(dir.path())
        .stdin(Stdio::null())
        .output()
        .expect("run native PowerShell; put pwsh on PATH before running this ignored test");
    assert!(
        output.status.success(),
        "native PowerShell probe failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("complete native probe report");
    let cases = report["cases"].as_array().expect("native case results");
    let expected = [
        "named",
        "positional",
        "append_true",
        "append_false",
        "variable",
        "whatif_error",
        "computed_parenthesized",
        "computed_concat",
        "computed_dot",
        "computed_nested",
        "computed_grouped_concat",
        "computed_module",
        "computed_append_true",
        "computed_append_false",
        "computed_variable",
        "computed_whatif_error",
        "computed_inert_argument",
        "computed_inert_expression",
        "filepath_glob",
        "literalpath_glob",
    ];
    for name in expected {
        assert!(
            cases.iter().any(|case| case == name),
            "missing {name}: {report}"
        );
    }
    let unicode_callee_tested = report["unicode_callee_tested"]
        .as_bool()
        .expect("Unicode callee availability");
    let native_major = report["version"]
        .as_str()
        .expect("native PowerShell version")
        .split('.')
        .next()
        .expect("native major version")
        .parse::<u32>()
        .expect("numeric native major version");
    assert_eq!(unicode_callee_tested, native_major >= 7);
    assert_eq!(
        cases.len(),
        expected.len() + usize::from(cfg!(windows)) + usize::from(unicode_callee_tested)
    );
    if unicode_callee_tested {
        assert!(cases.iter().any(|case| case == "computed_unicode"));
    }
    assert_eq!(report["windows_alias_tested"], cfg!(windows));
    if cfg!(windows) {
        assert!(cases.iter().any(|case| case == "windows_tee_alias"));
    }
    eprintln!("Native Tee-Object semantics: {report}");
}

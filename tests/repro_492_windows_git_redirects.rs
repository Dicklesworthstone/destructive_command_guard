//! #492: Windows separators in Git-internals redirects retain their exact
//! truncate/append rule, including when another redirect rule is allowlisted.
//! Commands are JSON hook input to the real binary, never executed payloads.

use std::fmt::Write as _;
use std::io::Write;
use std::process::{Command, Stdio};

const TRUNCATE: &str = "core.filesystem:redirect-truncate-git-internals-relative";
const APPEND: &str = "core.filesystem:redirect-append-git-internals-relative";
const DYNAMIC: &str = "core.filesystem:redirect-truncate-dynamic-path";
const CREDENTIAL: &str = "core.filesystem:credential-file-write";
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

    fn judge(&self, tool: &str, command: &str) -> (String, String) {
        let home = self.dir.path().join("home");
        let payload = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": { "command": command },
            "cwd": self.dir.path(),
        });
        let mut child = Command::new(env!("CARGO_BIN_EXE_dcg"))
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
            .current_dir(self.dir.path())
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
        let output = child.wait_with_output().expect("hook result");
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

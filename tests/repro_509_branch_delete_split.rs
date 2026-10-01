//! Regression tests for issue #509: `git branch -d` and `git branch -D` shared
//! one rule id, so `[policy.rules]` could not ask for the merge-checked
//! deletion while still denying the forced one.
//!
//! The merge-checked form (`-d` / `--delete` with no force) is now reported as
//! `core.git:branch-delete`; `-D`, `--delete --force`, `-f`, `-M` and `-C` stay
//! on `core.git:branch-force-delete`. Splitting an id would silently narrow
//! every existing entry that names the old one, so an entry for
//! `branch-force-delete` keeps covering `branch-delete` unless the new id has
//! an entry of its own.
//!
//! Every case runs the real binary in hook mode with a Claude Code
//! `PreToolUse` payload and an isolated HOME.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

const MERGE_CHECKED: &[&str] = &[
    "git branch -d merged-branch",
    "git -C repo branch -d merged-a merged-b merged-c",
    "git branch --delete merged-branch",
    "git branch -vd merged-branch",
    "git branch --del merged-branch",
];

const FORCED: &[&str] = &[
    "git branch -D merged-branch",
    "git -C repo branch -D merged-branch",
    "git branch -d -f merged-branch",
    "git branch -df merged-branch",
    "git branch --delete --force merged-branch",
    "git branch -f moved-branch HEAD~1",
    "git branch -M old-name existing-name",
    "git branch -C old-name existing-name",
];

const NEW_ID: &str = "core.git:branch-delete";
const LEGACY_ID: &str = "core.git:branch-force-delete";

struct Env {
    _temp: tempfile::TempDir,
    home: PathBuf,
    xdg_config: PathBuf,
    config: PathBuf,
    work: PathBuf,
}

impl Env {
    /// `policy_rules` is the body of `[policy.rules]`; `allow_rules` are the
    /// rule ids written to the user allowlist.
    fn new(policy_rules: &[(&str, &str)], allow_rules: &[&str]) -> Self {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().to_path_buf();
        let home = root.join("home");
        let xdg_config = home.join(".config");
        let work = root.join("work");
        for dir in [&home, &xdg_config.join("dcg"), &work] {
            std::fs::create_dir_all(dir).expect("create dir");
        }
        let mut config = String::from("[policy.rules]\n");
        for (rule, mode) in policy_rules {
            writeln!(config, "\"{rule}\" = \"{mode}\"").expect("format config");
        }
        let config_path = root.join("config.toml");
        std::fs::write(&config_path, config).expect("write config");
        let mut allowlist = String::from("# repro 509\n");
        for rule in allow_rules {
            write!(
                allowlist,
                "[[allow]]\nrule = \"{rule}\"\nreason = \"repro 509\"\nadded_by = \"test\"\nadded_at = \"2026-01-01T00:00:00Z\"\n"
            )
            .expect("format allowlist");
        }
        std::fs::write(xdg_config.join("dcg").join("allowlist.toml"), allowlist)
            .expect("write allowlist");
        Self {
            _temp: temp,
            home,
            xdg_config,
            config: config_path,
            work,
        }
    }

    /// The hook's verdict for `command` as `(decision, rule_id)`; an allowed
    /// command publishes nothing and reads as `("allow", "")`.
    fn verdict(&self, command: &str) -> (String, String) {
        let payload = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": command },
            "cwd": path_str(&self.work),
        });
        let mut child = Command::new(dcg_binary())
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("XDG_CONFIG_HOME", &self.xdg_config)
            .env("DCG_CONFIG", &self.config)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env("DCG_SELF_HEAL_HOOK", "0")
            .env("NO_COLOR", "1")
            .current_dir(&self.work)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn dcg");
        serde_json::to_writer(child.stdin.as_mut().expect("stdin"), &payload)
            .expect("write payload");
        let output = child.wait_with_output().expect("wait for dcg");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stdout = stdout.trim();
        if stdout.is_empty() {
            return ("allow".to_string(), String::new());
        }
        let json: serde_json::Value = serde_json::from_str(stdout)
            .unwrap_or_else(|e| panic!("hook stdout is not JSON ({e}): {stdout}"));
        let hso = &json["hookSpecificOutput"];
        (
            hso["permissionDecision"]
                .as_str()
                .unwrap_or("?")
                .to_string(),
            hso["ruleId"].as_str().unwrap_or_default().to_string(),
        )
    }

    fn assert_all(&self, commands: &[&str], decision: &str, rule: &str, scenario: &str) {
        for command in commands {
            let (got_decision, got_rule) = self.verdict(command);
            assert_eq!(
                (got_decision.as_str(), got_rule.as_str()),
                (decision, rule),
                "{scenario}: {command:?}"
            );
        }
    }
}

fn path_str(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[test]
fn default_config_denies_both_forms_under_separate_ids() {
    let env = Env::new(&[], &[]);
    env.assert_all(MERGE_CHECKED, "deny", NEW_ID, "default config");
    env.assert_all(FORCED, "deny", LEGACY_ID, "default config");
}

#[test]
fn policy_can_ask_for_merge_checked_delete_while_denying_forced_forms() {
    // The configuration the issue could not express.
    let env = Env::new(&[(NEW_ID, "ask")], &[]);
    env.assert_all(MERGE_CHECKED, "ask", NEW_ID, "branch-delete = ask");
    env.assert_all(FORCED, "deny", LEGACY_ID, "branch-delete = ask");
}

#[test]
fn an_asked_merge_checked_delete_cannot_carry_a_forced_one_past_the_policy() {
    // Approving the `-d` half must not run a `-D` on the same line.
    let env = Env::new(&[(NEW_ID, "ask")], &[]);
    env.assert_all(
        &[
            "git branch -d merged-branch; git branch -D other",
            "git branch -D other && git branch -d merged-branch",
            "git branch -d merged-branch && git branch -d -f other",
        ],
        "deny",
        LEGACY_ID,
        "branch-delete = ask, compound",
    );
}

#[test]
fn legacy_policy_entry_keeps_covering_merge_checked_delete() {
    // Before the split this entry covered `-d`; it must still mean that.
    let env = Env::new(&[(LEGACY_ID, "ask")], &[]);
    env.assert_all(
        MERGE_CHECKED,
        "ask",
        NEW_ID,
        "legacy branch-force-delete = ask",
    );
    env.assert_all(FORCED, "ask", LEGACY_ID, "legacy branch-force-delete = ask");
}

#[test]
fn the_specific_policy_entry_wins_over_the_legacy_one() {
    let env = Env::new(&[(LEGACY_ID, "ask"), (NEW_ID, "deny")], &[]);
    env.assert_all(MERGE_CHECKED, "deny", NEW_ID, "both entries");
    env.assert_all(FORCED, "ask", LEGACY_ID, "both entries");
}

#[test]
fn allowlisting_the_new_id_allows_only_merge_checked_delete() {
    let env = Env::new(&[], &[NEW_ID]);
    env.assert_all(MERGE_CHECKED, "allow", "", "allowlist branch-delete");
    env.assert_all(FORCED, "deny", LEGACY_ID, "allowlist branch-delete");
}

#[test]
fn legacy_allowlist_entry_keeps_covering_merge_checked_delete() {
    let env = Env::new(&[], &[LEGACY_ID]);
    env.assert_all(MERGE_CHECKED, "allow", "", "allowlist branch-force-delete");
    env.assert_all(FORCED, "allow", "", "allowlist branch-force-delete");
}

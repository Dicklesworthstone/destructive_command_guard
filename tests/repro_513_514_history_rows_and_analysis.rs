//! #513 / #514 / #515: what `dcg history` records and what it concludes.
//!
//! * #513 — `dcg history analyze` on an empty history printed green "no gaps"
//!   checks and recommended disabling packs, `core` first, from zero commands.
//!   It must say there is nothing to analyze and recommend nothing; with data,
//!   a pack that never matched is listed but never recommended for removal.
//! * #514 — every row the hook wrote had `hostname = NULL`. The hook must
//!   record the machine's hostname.
//! * #515 — a pre-execution hook cannot know a command's exit status, so
//!   `exit_code` stays NULL ("unknown"); pinned here so a future change to that
//!   column is a deliberate one.
//!
//! Everything runs the real binary in a hermetic HOME with an explicit config
//! and database path, so the operator's own history is never read or written.

#[path = "common/history.rs"]
mod history_test;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use chrono::Utc;
use destructive_command_guard::history::{
    CommandEntry, ENV_HISTORY_DIAGNOSTICS, HistoryConnection, HistoryDb, Outcome, SqliteValue,
    local_hostname,
};

fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

/// A seeded history row: command, outcome, and the `(pack, pattern)` it matched.
type SeedRow<'a> = (&'a str, Outcome, Option<(&'a str, &'a str)>);

struct Lab {
    dir: tempfile::TempDir,
    config_path: PathBuf,
    db_path: PathBuf,
}

impl Lab {
    fn new(config_toml: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        for sub in ["home", "xdg", "state", "tmp"] {
            std::fs::create_dir_all(dir.path().join(sub)).expect("hermetic directory");
        }
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, config_toml).expect("write config");
        let db_path = dir.path().join("history.sqlite3");
        Self {
            dir,
            config_path,
            db_path,
        }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(dcg_binary());
        cmd.args(args)
            .env_clear()
            .env("HOME", self.dir.path().join("home"))
            .env("USERPROFILE", self.dir.path().join("home"))
            .env("XDG_CONFIG_HOME", self.dir.path().join("xdg"))
            .env("XDG_STATE_HOME", self.dir.path().join("state"))
            .env("TMPDIR", self.dir.path().join("tmp"))
            .env("TEMP", self.dir.path().join("tmp"))
            .env("TMP", self.dir.path().join("tmp"))
            .env("DCG_CONFIG", &self.config_path)
            .env("DCG_HISTORY_DB", &self.db_path)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env("DCG_SELF_HEAL_HOOK", "0")
            .env("DCG_HOOK_TIMEOUT_MS", "5000")
            .env(ENV_HISTORY_DIAGNOSTICS, "1")
            .current_dir(self.dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Windows reports its hostname through COMPUTERNAME, which env_clear
        // would otherwise hide from the child.
        if let Some(name) = std::env::var_os("COMPUTERNAME") {
            cmd.env("COMPUTERNAME", name);
        }
        cmd
    }

    fn run(&self, args: &[&str], stdin: &str) -> Output {
        let mut child = self.command(args).spawn().expect("spawn dcg");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(stdin.as_bytes())
            .expect("write stdin");
        child.wait_with_output().expect("wait dcg")
    }

    fn analyze(&self, extra: &[&str]) -> Output {
        let mut args = vec!["history", "analyze"];
        args.extend_from_slice(extra);
        self.run(&args, "")
    }

    fn seed(&self, commands: &[SeedRow<'_>]) {
        let db = HistoryDb::open(Some(self.db_path.clone())).expect("open history");
        let at = Utc::now() - chrono::Duration::seconds(5);
        for (command, outcome, rule) in commands {
            db.log_command(&CommandEntry {
                timestamp: at,
                agent_type: "claude-code".to_string(),
                working_dir: "/work".to_string(),
                command: (*command).to_string(),
                outcome: *outcome,
                pack_id: rule.map(|(pack, _)| pack.to_string()),
                pattern_name: rule.map(|(_, pattern)| pattern.to_string()),
                ..Default::default()
            })
            .expect("seed row");
        }
    }
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The verdict lines #513 reported, any one of which reads as a clean result.
const VERDICTS_FROM_NOTHING: [&str; 5] = [
    "Consider disabling",
    "No potential coverage gaps detected",
    "No patterns with high bypass rates detected",
    "No recommendations at this time",
    "Recommendations:",
];

#[test]
fn analyze_on_an_empty_history_says_there_is_nothing_to_analyze_513() {
    let lab = Lab::new("");
    let output = lab.analyze(&[]);
    let stdout = stdout_of(&output);
    assert_eq!(output.status.code(), Some(0), "stdout:\n{stdout}");
    assert!(
        stdout.contains("Commands analyzed: 0"),
        "header keeps the count:\n{stdout}"
    );
    assert!(
        stdout.contains("nothing to analyze"),
        "must say no data:\n{stdout}"
    );
    assert!(
        stdout.contains("[history]") && stdout.contains("enabled = true"),
        "history is off by default, so the output must say how to turn it on:\n{stdout}"
    );
    for verdict in VERDICTS_FROM_NOTHING {
        assert!(
            !stdout.contains(verdict),
            "no verdict may be drawn from zero commands ({verdict:?}):\n{stdout}"
        );
    }
    assert!(
        !stdout.contains("core"),
        "no pack may be named, least of all core:\n{stdout}"
    );
}

#[test]
fn analyze_on_an_empty_history_with_collection_on_names_the_database_513() {
    let lab = Lab::new("[history]\nenabled = true\n");
    let output = lab.analyze(&[]);
    let stdout = stdout_of(&output);
    assert_eq!(output.status.code(), Some(0), "stdout:\n{stdout}");
    assert!(stdout.contains("nothing to analyze"), "{stdout}");
    assert!(
        stdout.contains("History collection is enabled")
            && stdout.contains(&lab.db_path.display().to_string()),
        "with collection on, point at the database it writes:\n{stdout}"
    );
    for verdict in VERDICTS_FROM_NOTHING {
        assert!(!stdout.contains(verdict), "{verdict:?}:\n{stdout}");
    }
}

#[test]
fn analyze_json_on_an_empty_history_marks_no_data_and_lists_nothing_513() {
    let lab = Lab::new("");
    let output = lab.analyze(&["--json"]);
    assert_eq!(output.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("analyze JSON");
    assert_eq!(json["has_data"], false, "{json}");
    assert_eq!(json["total_commands"], 0, "{json}");
    for list in [
        "recommendations",
        "inactive_packs",
        "potential_gaps",
        "high_value_patterns",
        "potentially_aggressive",
    ] {
        assert_eq!(
            json[list],
            serde_json::json!([]),
            "{list} must be empty when nothing was recorded: {json}"
        );
    }
}

#[test]
fn analyze_with_history_lists_quiet_packs_but_never_recommends_disabling_them_513() {
    let lab = Lab::new("[packs]\nenabled = [\"database.postgresql\"]\n");
    lab.seed(&[
        ("git status", Outcome::Allow, None),
        ("ls -la", Outcome::Allow, None),
        (
            "git reset --hard HEAD~1",
            Outcome::Deny,
            Some(("core.git", "reset-hard")),
        ),
    ]);

    let output = lab.analyze(&["--json"]);
    assert_eq!(output.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("analyze JSON");
    assert_eq!(json["has_data"], true, "{json}");
    assert_eq!(json["total_commands"], 3, "{json}");
    let inactive: Vec<&str> = json["inactive_packs"]
        .as_array()
        .expect("inactive_packs")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert!(
        inactive.contains(&"database.postgresql"),
        "quiet packs are still listed: {inactive:?}"
    );
    assert!(
        !inactive.contains(&"core") && !inactive.contains(&"core.git"),
        "the config's `core` marker covers the core.git row that matched: {inactive:?}"
    );
    let mut sorted = inactive.clone();
    sorted.sort_unstable();
    assert_eq!(inactive, sorted, "the listing is in a stable order");
    for rec in json["recommendations"].as_array().expect("recommendations") {
        assert_ne!(rec["type"], "disable_pack", "{rec}");
        let text = rec.to_string();
        assert!(
            !text.contains("disabl") && !text.contains("enabled = false"),
            "no recommendation may suggest disabling a pack: {rec}"
        );
    }

    let pretty = stdout_of(&lab.analyze(&[]));
    assert!(!pretty.contains("Consider disabling"), "{pretty}");
    assert!(
        pretty.contains("not a reason to disable them"),
        "the listing must say a quiet guard pack is expected:\n{pretty}"
    );
}

fn text(value: &SqliteValue) -> Option<&str> {
    match value {
        SqliteValue::Text(value) => Some(value),
        _ => None,
    }
}

fn hook_payload(command: &str, cwd: &Path) -> String {
    serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "cwd": cwd,
        "session_id": "probe-514",
    })
    .to_string()
}

#[test]
fn hook_rows_record_the_machine_hostname_and_leave_exit_code_unknown_514_515() {
    let expected = local_hostname().map(str::to_string);
    if cfg!(unix) {
        assert!(
            expected.is_some(),
            "gethostname must yield a name on a Unix test host"
        );
    }

    history_test::retry_history_scenario("hook hostname rows", || {
        let lab = Lab::new(
            "[history]\nenabled = true\nbatch_size = 1\nbatch_flush_interval_ms = 1\nredaction_mode = \"none\"\n",
        );
        // Schema creation stays outside the hook's bounded flush.
        drop(HistoryDb::open(Some(lab.db_path.clone())).expect("initialize history"));

        let deny = lab.run(
            &[],
            &hook_payload("git reset --hard HEAD~3", lab.dir.path()),
        );
        assert_eq!(deny.status.code(), Some(0), "{deny:?}");
        assert!(
            stdout_of(&deny).contains("\"deny\""),
            "control: the hook must deny: {deny:?}"
        );
        history_test::check_history_after_exit(&lab.db_path, 1, &deny, "deny row")?;

        let allow = lab.run(&[], &hook_payload("ls /tmp", lab.dir.path()));
        assert_eq!(allow.status.code(), Some(0), "{allow:?}");
        assert!(stdout_of(&allow).trim().is_empty(), "{allow:?}");
        history_test::check_history_after_exit(&lab.db_path, 2, &allow, "allow row")?;

        let connection = HistoryConnection::open(&lab.db_path).expect("open history");
        let rows = connection
            .query("SELECT outcome, hostname, exit_code FROM commands ORDER BY id")
            .expect("query history");
        assert_eq!(rows.len(), 2);
        for (row, outcome) in rows.iter().zip(["deny", "allow"]) {
            let values = row.values();
            assert_eq!(text(&values[0]), Some(outcome));
            assert_eq!(
                text(&values[1]).map(str::to_string),
                expected,
                "{outcome} row must carry the machine's hostname (#514)"
            );
            assert!(
                matches!(values[2], SqliteValue::Null),
                "a pre-execution hook cannot know the exit status; NULL means unknown (#515)"
            );
        }
        Ok(())
    });
}

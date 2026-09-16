//! Regression tests for issue #417: `dcg explain` ignored `[policy]` resolution.
//!
//! `explain` printed the matched rule's severity-default decision and never
//! consulted `[policy.rules]` / `[policy.packs]`, so a rule configured to `warn`,
//! `ask`, or `log` was reported as `DENY` — contradicting both the live hook and
//! `dcg test`, which resolve it correctly. `--format json` carried no mode field
//! either, so there was no way to get the right answer out of explain at all.
//!
//! #330 fixed the same class for the hook and `dcg test`; explain was never
//! touched, and #330's own repro table already showed explain's wrong DENY.

use std::io::Write;
use std::process::{Command, Stdio};

fn dcg_binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

struct Fixture {
    _temp: tempfile::TempDir,
    home: std::path::PathBuf,
    config: std::path::PathBuf,
}

/// Write a config whose single `[policy.rules]` entry sets `mode` for a
/// core.git rule that is always enabled, so the test needs no pack setup.
fn fixture(mode: &str) -> Fixture {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    let config = temp.path().join("policy.toml");
    std::fs::write(
        &config,
        format!(
            "[policy]\ndefault_mode = \"deny\"\n\n[policy.rules]\n\"core.git:branch-force-delete\" = \"{mode}\"\n"
        ),
    )
    .expect("write config");
    Fixture {
        _temp: temp,
        home,
        config,
    }
}

fn run(fixture: &Fixture, args: &[&str]) -> std::process::Output {
    Command::new(dcg_binary())
        .args(args)
        .env_clear()
        .env("HOME", &fixture.home)
        .env("USERPROFILE", &fixture.home)
        .env("DCG_CONFIG", &fixture.config)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("NO_COLOR", "1")
        .env("TERM", "dumb")
        .output()
        .expect("run dcg")
}

const COMMAND: &str = "git branch -D scratch";

#[test]
fn explain_reports_the_resolved_policy_outcome_not_the_rule_default() {
    for (mode, expected) in [
        ("deny", "DENY"),
        ("warn", "WARN"),
        ("log", "LOG"),
        ("ask", "ASK"),
    ] {
        let fixture = fixture(mode);
        let out = run(&fixture, &["explain", COMMAND]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains(&format!("Decision: {expected}")),
            "policy mode {mode} must be reported as {expected}.\nstdout: {stdout}"
        );
    }
}

#[test]
fn explain_json_carries_mode_and_outcome() {
    for (mode, expected_outcome) in [
        ("deny", "deny"),
        ("warn", "warn"),
        ("log", "log"),
        ("ask", "ask"),
    ] {
        let fixture = fixture(mode);
        let out = run(&fixture, &["explain", "--format", "json", COMMAND]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let json: serde_json::Value =
            serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("bad JSON ({e}): {stdout}"));
        assert_eq!(
            json["schema_version"], 4,
            "mode/outcome arrived in schema v4"
        );
        assert_eq!(
            json["decision"], "deny",
            "the evaluator finding is stable across modes: the pattern did match"
        );
        assert_eq!(json["mode"], mode, "resolved policy mode");
        assert_eq!(
            json["outcome"], expected_outcome,
            "outcome is the field a consumer gates on"
        );
    }
}

#[test]
fn explain_agrees_with_dcg_test_and_the_live_hook() {
    // The three surfaces must give one answer. Before the fix, explain said DENY
    // while `dcg test` said WARN and the hook let the command run.
    let fixture = fixture("warn");

    let explain = run(&fixture, &["explain", COMMAND]);
    let explain_out = String::from_utf8_lossy(&explain.stdout);
    assert!(
        explain_out.contains("Decision: WARN"),
        "explain: {explain_out}"
    );

    let test = run(&fixture, &["test", COMMAND]);
    let test_out =
        String::from_utf8_lossy(&test.stdout).to_string() + &String::from_utf8_lossy(&test.stderr);
    assert!(test_out.contains("Result: WARN"), "dcg test: {test_out}");

    // Live hook: a warn-mode rule exits 0 with no denial document on stdout and
    // a warning on stderr.
    let mut child = Command::new(dcg_binary())
        .env_clear()
        .env("HOME", &fixture.home)
        .env("USERPROFILE", &fixture.home)
        .env("DCG_CONFIG", &fixture.config)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("NO_COLOR", "1")
        .env("TERM", "dumb")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hook");
    let payload = format!(
        r#"{{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{{"command":"{COMMAND}"}}}}"#
    );
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(payload.as_bytes())
        .expect("write payload");
    let hook = child.wait_with_output().expect("wait");
    assert!(hook.status.success(), "warn mode exits 0");
    assert!(
        String::from_utf8_lossy(&hook.stdout).trim().is_empty(),
        "warn mode emits no denial document"
    );
    assert!(
        String::from_utf8_lossy(&hook.stderr).contains("WARNING"),
        "warn mode warns on stderr: {}",
        String::from_utf8_lossy(&hook.stderr)
    );
}

#[test]
fn a_policy_override_explains_why_the_outcome_moved() {
    // A WARN printed above a High-severity match reads as a contradiction unless
    // explain names the policy that moved it.
    let fixture = fixture("warn");
    let out = run(&fixture, &["explain", COMMAND]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("[policy] mode warn"),
        "explain must name the policy that moved the outcome.\nstdout: {stdout}"
    );
}

#[test]
fn an_unmatched_command_reports_no_mode() {
    let fixture = fixture("warn");
    let out = run(&fixture, &["explain", "--format", "json", "git status"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(json["decision"], "allow");
    assert_eq!(json["outcome"], "allow");
    assert!(
        json.get("mode").is_none() || json["mode"].is_null(),
        "no policy mode applies when nothing matched: {stdout}"
    );
}

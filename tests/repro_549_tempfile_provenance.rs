//! #549 / #626: temporary ownership and path bindings are proof obligations.
//! Only DCG receives the candidate commands; no Python fixture is executed.

use std::io::Write;
use std::process::{Command, Stdio};

#[derive(serde::Deserialize)]
struct Case {
    id: String,
    decision: String,
    source: String,
    #[serde(default)]
    rule_id: Option<String>,
}

fn assert_verdict(case: &Case, command: &str, hook: bool) {
    let scratch = tempfile::tempdir().expect("isolated test state");
    let home = scratch.path().join("home");
    std::fs::create_dir(&home).expect("isolated home");
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcg"));
    let input = if hook {
        child.args(["hook", "--batch"]);
        serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        })
        .to_string()
    } else {
        child.args(["test", "--stdin", "--dialect", "posix", "--format", "json"]);
        command.to_string()
    };
    let mut child = child
        .env_clear()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("APPDATA", home.join(".config"))
        .env("LOCALAPPDATA", home.join(".local"))
        .env("TMPDIR", scratch.path())
        .env("TEMP", scratch.path())
        .env("TMP", scratch.path())
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("DCG_HISTORY_ENABLED", "false")
        .env("DCG_HISTORY_DISABLED", "1")
        // Completed semantic verdicts, not assertions about host scheduling.
        // Production deadlines and the performance gates are unchanged.
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .env("DCG_AST_TIMEOUT_MS", "5000")
        // Heredoc extraction has its own 50 ms clock (bd-e1xl).
        .env("DCG_HEREDOC_TIMEOUT_MS", "5000")
        .current_dir(scratch.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the DCG classifier");
    writeln!(child.stdin.take().expect("piped stdin"), "{input}").expect("write classifier input");
    let output = child.wait_with_output().expect("classifier exit");
    let verdict: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "{} hook={hook}: {error}; status={}; stdout={}; stderr={}",
                case.id,
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            )
        });
    assert_eq!(
        verdict["decision"].as_str(),
        Some(case.decision.as_str()),
        "{} hook={hook}: {command:?}; verdict={verdict}; stderr={}",
        case.id,
        String::from_utf8_lossy(&output.stderr),
    );
    if let Some(expected_rule) = &case.rule_id {
        let actual_rule = if hook {
            verdict["rule_id"].as_str().unwrap_or_default().to_string()
        } else {
            format!(
                "{}:{}",
                verdict["pack_id"].as_str().unwrap_or_default(),
                verdict["pattern_name"].as_str().unwrap_or_default(),
            )
        };
        assert_eq!(
            &actual_rule, expected_rule,
            "{} hook={hook}: {command:?}; verdict={verdict}",
            case.id,
        );
    }
}

fn check_cases(hook: bool) {
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("fixtures/python_tempfile_provenance.json"))
            .expect("valid regression fixtures");
    assert!(!cases.is_empty());
    for case in cases {
        let quoted = format!("'{}'", case.source.replace('\'', "'\\''"));
        for command in [
            format!("python3 -c {quoted}"),
            format!("python3 -I -c {quoted}"),
            format!("python3 - <<'PY'\n{}\nPY", case.source),
            format!("python3 -I - <<'PY'\n{}\nPY", case.source),
        ] {
            assert_verdict(&case, &command, hook);
        }
    }
}

fn check_reflective_cases(hook: bool) {
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("fixtures/python_reflective_rmtree.json"))
            .expect("valid reflective-deletion fixtures");
    assert!(!cases.is_empty());
    for case in cases {
        let quoted = format!("'{}'", case.source.replace('\'', "'\\''"));
        for command in [
            format!("python3 -c {quoted}"),
            format!("python3 -I -c {quoted}"),
            format!("python3 - <<'PY'\n{}\nPY", case.source),
            format!("python3 -I - <<'PY'\n{}\nPY", case.source),
        ] {
            assert_verdict(&case, &command, hook);
        }
    }
}

#[test]
fn reflective_rmtree_cli_verdicts() {
    check_reflective_cases(false);
}

#[test]
fn reflective_rmtree_hook_verdicts() {
    check_reflective_cases(true);
}

#[test]
fn tempfile_provenance_cli_verdicts() {
    check_cases(false);
}

#[test]
fn tempfile_provenance_hook_verdicts() {
    check_cases(true);
}

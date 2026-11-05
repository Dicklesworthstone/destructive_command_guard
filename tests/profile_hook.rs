//! #555: phase diagnostics observe the real hook without changing its wire
//! response, and include parsing failures and synchronous history shutdown.

use std::io::Write as _;
use std::process::{Command, Output, Stdio};

fn payload(command: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
    }))
    .expect("hook payload")
}

fn run_hook(input: &[u8], profile: Option<&str>, robot: bool, history: bool) -> Output {
    run_hook_with_env(input, profile, robot, history, &[])
}

fn run_hook_with_env(
    input: &[u8],
    profile: Option<&str>,
    robot: bool,
    history: bool,
    extra_env: &[(&str, &str)],
) -> Output {
    let temp = tempfile::tempdir().expect("isolated hook directory");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).expect("isolated home");
    let config = temp.path().join("config.toml");
    std::fs::write(
        &config,
        format!("[general]\nfail_closed = true\n[history]\nenabled = {history}\n"),
    )
    .expect("hook config");
    let mut command = Command::new(env!("CARGO_BIN_EXE_dcg"));
    command
        .env_clear()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_STATE_HOME", home.join("state"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("APPDATA", home.join("appdata"))
        .env("LOCALAPPDATA", home.join("localappdata"))
        .env("TMPDIR", temp.path())
        .env("TEMP", temp.path())
        .env("TMP", temp.path())
        .env("CLAUDECODE", "1")
        .env("DCG_CONFIG", &config)
        .env("DCG_HISTORY_DB", temp.path().join("history.sqlite3"))
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env(
            "DCG_PENDING_EXCEPTIONS_PATH",
            temp.path().join("pending.jsonl"),
        )
        .env("DCG_SELF_HEAL_HOOK", "0")
        // These are protocol/measurement regressions, not latency gates.
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(profile) = profile {
        command.env("DCG_PROFILE", profile);
    }
    if robot {
        command.arg("--robot");
    }
    command.envs(extra_env.iter().copied());
    let mut child = command.spawn().expect("spawn real hook");
    child
        .stdin
        .take()
        .expect("hook stdin")
        .write_all(input)
        .expect("write payload");
    child.wait_with_output().expect("wait for hook")
}

fn profile(output: &Output) -> serde_json::Value {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let reports: Vec<_> = stderr
        .lines()
        .filter_map(|line| line.strip_prefix("DCG_PROFILE "))
        .collect();
    assert_eq!(reports.len(), 1, "expected one profile: {stderr}");
    let report: serde_json::Value = serde_json::from_str(reports[0]).expect("profile JSON");
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["clock"], "monotonic_wall");
    assert_eq!(report["scope"], "hook");
    let phases = report["phases"].as_object().expect("main phases");
    let mut exclusive = 0_u64;
    for phase in phases.values() {
        assert_eq!(
            phase["calls"], phase["completed_calls"],
            "main phase remains open"
        );
        let elapsed = phase["elapsed_ns"].as_u64().expect("elapsed nanoseconds");
        let own = phase["exclusive_ns"]
            .as_u64()
            .expect("exclusive nanoseconds");
        assert!(own <= elapsed);
        exclusive += own;
    }
    assert_eq!(
        exclusive
            + report["uninstrumented_ns"]
                .as_u64()
                .expect("uninstrumented time"),
        report["total_ns"].as_u64().expect("hook time"),
        "exclusive main phases must not count nested/worker time twice"
    );
    assert!(report["worker_phases"].is_object());
    report
}

#[test]
fn profiling_is_opt_in_and_leaves_allowed_stdout_empty() {
    let input = payload("ls -la");
    for enabled in [None, Some("0"), Some("1")] {
        let output = run_hook(&input, enabled, false, false);
        assert!(output.status.success(), "{output:?}");
        assert!(
            output.stdout.is_empty(),
            "allowed hook stdout must stay empty"
        );
        if enabled == Some("1") {
            let report = profile(&output);
            assert!(report["phases"]["request_parse"]["calls"].as_u64().unwrap() > 0);
            assert!(report["phases"]["evaluation"]["calls"].as_u64().unwrap() > 0);
            assert_eq!(report["phases"]["history_init"]["calls"], 0);
            assert_eq!(report["phases"]["history_record"]["calls"], 0);
            assert_eq!(report["phases"]["history_flush"]["calls"], 0);
        } else {
            assert!(output.stderr.is_empty(), "disabled diagnostics: {output:?}");
        }
    }
}

#[test]
fn profiling_preserves_a_destructive_command_denial() {
    let input = payload("git reset --hard");
    for enabled in [None, Some("1")] {
        let output = run_hook(&input, enabled, false, false);
        assert!(output.status.success(), "Claude JSON denial exits zero");
        let wire: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("one wire JSON");
        assert_eq!(wire["hookSpecificOutput"]["permissionDecision"], "deny");
        if enabled.is_some() {
            let report = profile(&output);
            assert!(
                report["phases"]["pattern_evaluation"]["calls"]
                    .as_u64()
                    .unwrap()
                    > 0
            );
        }
    }
}

#[test]
fn malformed_request_profiles_parsing_and_history_before_return() {
    let output = run_hook(b"{", Some("1"), false, true);
    assert!(
        output.status.success(),
        "Claude fail-closed JSON exits zero"
    );
    let wire: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("failure wire JSON");
    assert_eq!(wire["hookSpecificOutput"]["permissionDecision"], "deny");
    let report = profile(&output);
    for name in [
        "request_parse",
        "history_init",
        "history_record",
        "history_flush",
    ] {
        assert!(
            report["phases"][name]["completed_calls"].as_u64().unwrap() > 0,
            "{name}"
        );
    }
    assert_eq!(report["phases"]["evaluation"]["calls"], 0);
}

#[test]
fn profiling_keeps_robot_stderr_silent() {
    for (flag, env) in [(true, "0"), (false, "1")] {
        for (input, denied) in [
            (payload("ls -la"), false),
            (payload("git reset --hard"), true),
            (b"{".to_vec(), true),
        ] {
            let output = run_hook_with_env(
                &input,
                Some("1"),
                flag,
                false,
                &[("DCG_ROBOT", env), ("DCG_LOG", "dcg_perf=debug")],
            );
            assert!(output.status.success(), "{output:?}");
            assert!(output.stderr.is_empty(), "robot stderr: {output:?}");
            if denied {
                let wire: serde_json::Value =
                    serde_json::from_slice(&output.stdout).expect("robot denial");
                assert_eq!(wire["hookSpecificOutput"]["permissionDecision"], "deny");
            } else {
                assert!(output.stdout.is_empty(), "robot allowed hook stdout");
            }
        }
    }

    let output = run_hook_with_env(
        &payload("ls -la"),
        Some("1"),
        false,
        false,
        &[("DCG_ROBOT", "0")],
    );
    assert!(output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty());
    profile(&output);
}

#[test]
fn robot_preserves_exit_status_protocol_verdict_channel() {
    let input = serde_json::to_vec(&serde_json::json!({
        "event": "PreToolUse",
        "toolName": "bash",
        "toolArgs": { "command": "git reset --hard" },
    }))
    .unwrap();
    let output = run_hook_with_env(
        &input,
        Some("1"),
        true,
        false,
        &[("DCG_LOG", "dcg_perf=debug")],
    );
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty(), "exit-status protocol has no JSON");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("reset-hard"), "verdict reason: {stderr}");
    assert!(!stderr.contains("DCG_PROFILE"), "diagnostics: {stderr}");
    assert!(
        !stderr.contains("\u{1b}["),
        "color in wire reason: {stderr}"
    );
}

#[test]
fn executable_heredoc_profiles_worker_analysis_and_history_without_command_text() {
    let input = payload("python3 <<'PY'\nprint('PROFILE_COMMAND_CANARY')\nPY");
    let output = run_hook(&input, Some("1"), false, true);
    assert!(output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "safe Python must stay allowed");
    let report = profile(&output);
    assert!(
        report["worker_phases"]["ast_parse"]["completed_calls"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(
        report["phases"]["history_flush"]["completed_calls"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(!report.to_string().contains("PROFILE_COMMAND_CANARY"));
}

/// #643's exact short Python failures were not supplied. An intentionally
/// malformed program is a deterministic control for this independent recovery
/// failure path, without depending on a scheduling timeout or changing policy.
#[test]
fn interpreter_literal_failure_is_unverified_without_blame_or_source_disclosure() {
    let source = "python3 -I - <<'PY'\nimport re\npattern = r'\\d+'\n\
                  secret = 'INTERPRETER_SOURCE_CANARY'\nif (\nPY";
    for decision in ["ask", "deny"] {
        let output = run_hook_with_env(
            &payload(source),
            Some("1"),
            false,
            false,
            &[
                ("DCG_UNVERIFIED_DECISION", decision),
                ("DCG_AST_TIMEOUT_MS", "5000"),
            ],
        );
        assert!(output.status.success(), "Claude JSON verdict exits zero");
        let wire: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("unverified hook verdict");
        let result = &wire["hookSpecificOutput"];
        assert_eq!(result["permissionDecision"], decision);
        let reason = result["permissionDecisionReason"].as_str().unwrap();
        assert!(reason.contains("interpreter_literal_recovery"), "{reason}");
        assert!(!reason.contains("increase hook_timeout_ms"), "{reason}");
        assert!(!reason.contains("within 5000ms"), "{reason}");
        assert!(!reason.contains("INTERPRETER_SOURCE_CANARY"), "{reason}");
        let report = profile(&output);
        assert!(!report.to_string().contains("INTERPRETER_SOURCE_CANARY"));
    }
}

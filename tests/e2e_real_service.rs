//! Mock-free end-to-end tests for the real `dcg` binary.
//!
//! These tests intentionally spawn the compiled binary instead of calling
//! library functions. Each case uses an isolated HOME/TMPDIR and writes a
//! per-test tracing log under `tests/_logs/`.

#![allow(
    clippy::doc_markdown,
    clippy::items_after_statements,
    clippy::needless_pass_by_value,
    clippy::too_many_lines,
    clippy::uninlined_format_args
)]

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tempfile::TempDir;
use tracing::Dispatch;
use tracing_subscriber::fmt::MakeWriter;

const DESTRUCTIVE_COMMAND: &str = "git reset --hard HEAD~1";

#[derive(Clone, Copy, Debug)]
enum Protocol {
    Claude,
    Codex,
}

impl Protocol {
    fn label(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
        }
    }

    fn payload(self, command: &str, cwd: &Path) -> String {
        let payload = match self {
            Self::Claude => json!({
                "session_id": "sess-real-service-claude",
                "transcript_path": cwd.join("claude-transcript.jsonl"),
                "cwd": cwd,
                "permission_mode": "default",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": { "command": command },
                "tool_use_id": "toolu_real_service_001",
            }),
            Self::Codex => json!({
                "session_id": "019dd11d-b795-7261-a9cb-9b85a5dad632",
                "turn_id": "turn-real-service-001",
                "transcript_path": null,
                "cwd": cwd,
                "hook_event_name": "PreToolUse",
                "model": "gpt-5.5",
                "permission_mode": "bypassPermissions",
                "tool_name": "Bash",
                "tool_input": { "command": command },
                "tool_use_id": "call_real_service_001",
            }),
        };

        serde_json::to_string_pretty(&payload).expect("payload JSON should serialize")
    }
}

struct RealServiceEnv {
    home: TempDir,
    cwd: TempDir,
    tmp_dir: PathBuf,
}

impl RealServiceEnv {
    fn new(test_name: &str) -> Self {
        let home = tempfile::Builder::new()
            .prefix(&format!("dcg-{test_name}-home-"))
            .tempdir()
            .expect("failed to create test HOME");
        let cwd = tempfile::Builder::new()
            .prefix(&format!("dcg-{test_name}-cwd-"))
            .tempdir()
            .expect("failed to create test cwd");
        let tmp_dir = home.path().join("tmp");
        fs::create_dir_all(&tmp_dir).expect("failed to create test TMPDIR");

        Self { home, cwd, tmp_dir }
    }

    fn write_config(&self, contents: &str) {
        let config_dir = self.home.path().join(".config/dcg");
        fs::create_dir_all(&config_dir).expect("failed to create config dir");
        fs::write(config_dir.join("config.toml"), contents).expect("failed to write config");
    }

    fn home_path(&self) -> &Path {
        self.home.path()
    }

    fn cwd_path(&self) -> &Path {
        self.cwd.path()
    }
}

struct DcgRun {
    stdout: String,
    stderr: String,
    exit_code: i32,
    duration: Duration,
}

impl DcgRun {
    fn stdout_json(&self) -> Value {
        serde_json::from_str(self.stdout.trim()).unwrap_or_else(|error| {
            panic!(
                "stdout was not valid JSON: {error}\nstdout:\n{}\nstderr:\n{}",
                self.stdout, self.stderr
            )
        })
    }
}

struct TestLog {
    name: String,
    path: PathBuf,
}

#[derive(Clone)]
struct SharedLogWriter {
    file: Arc<Mutex<File>>,
}

struct SharedLogGuard {
    file: Arc<Mutex<File>>,
}

impl<'a> MakeWriter<'a> for SharedLogWriter {
    type Writer = SharedLogGuard;

    fn make_writer(&'a self) -> Self::Writer {
        SharedLogGuard {
            file: Arc::clone(&self.file),
        }
    }
}

impl Write for SharedLogGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.lock().expect("log mutex poisoned").write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.lock().expect("log mutex poisoned").flush()
    }
}

fn with_test_log<R>(name: &str, test: impl FnOnce(&TestLog) -> R) -> R {
    let log_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/_logs");
    fs::create_dir_all(&log_dir).expect("failed to create e2e log dir");
    let log_path = log_dir.join(format!("{name}.log"));
    let file = File::create(&log_path).expect("failed to create test log");
    let writer = SharedLogWriter {
        file: Arc::new(Mutex::new(file)),
    };
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(false)
        .with_target(true)
        .with_level(true)
        .with_file(false)
        .with_line_number(false)
        .compact()
        .finish();
    let dispatch = Dispatch::new(subscriber);
    let log = TestLog {
        name: name.to_string(),
        path: log_path,
    };

    tracing::dispatcher::with_default(&dispatch, || {
        let started = Instant::now();
        tracing::info!(
            target: "e2e_real_service",
            event = "test_start",
            test = %name,
            log_path = %log.path.display()
        );

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| test(&log)));
        match result {
            Ok(value) => {
                tracing::info!(
                    target: "e2e_real_service",
                    event = "test_end",
                    test = %name,
                    status = "PASS",
                    duration_ms = started.elapsed().as_millis()
                );
                value
            }
            Err(payload) => {
                tracing::error!(
                    target: "e2e_real_service",
                    event = "test_end",
                    test = %name,
                    status = "FAIL",
                    duration_ms = started.elapsed().as_millis()
                );
                std::panic::resume_unwind(payload);
            }
        }
    })
}

fn dcg_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("DCG_E2E_BINARY").map(PathBuf::from) {
        return path;
    }

    let tmp_root = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    let pane_target_binary = tmp_root.join("rch_target_dcg_cod4/debug/dcg");
    if pane_target_binary.exists() {
        return pane_target_binary;
    }

    if let Some(path) = std::env::var_os("CARGO_BIN_EXE_dcg").map(PathBuf::from) {
        return path;
    }

    let mut path = std::env::current_exe().expect("current test executable path");
    path.pop();
    path.pop();
    path.push(format!("dcg{}", std::env::consts::EXE_SUFFIX));
    path
}

fn run_hook(
    log: &TestLog,
    env: &RealServiceEnv,
    protocol: Protocol,
    command: &str,
    extra_env: &[(&str, &str)],
) -> DcgRun {
    let payload = protocol.payload(command, env.cwd_path());
    run_dcg(log, env, &[], Some(&payload), extra_env)
}

fn run_dcg(
    log: &TestLog,
    env: &RealServiceEnv,
    args: &[&str],
    stdin: Option<&str>,
    extra_env: &[(&str, &str)],
) -> DcgRun {
    let binary = dcg_binary();
    let system_path = std::env::var("PATH").unwrap_or_default();

    tracing::info!(
        target: "e2e_real_service",
        event = "dcg_invoke",
        test = %log.name,
        binary = %binary.display(),
        args = ?args,
        cwd = %env.cwd_path().display(),
        home = %env.home_path().display(),
        stdin_bytes = stdin.map_or(0, str::len)
    );

    let started = Instant::now();
    let mut cmd = Command::new(&binary);
    cmd.args(args)
        .current_dir(env.cwd_path())
        .env_clear()
        .env("PATH", system_path)
        .env("HOME", env.home_path())
        .env("USERPROFILE", env.home_path())
        .env("TMPDIR", &env.tmp_dir)
        .env("TEMP", &env.tmp_dir)
        .env("TMP", &env.tmp_dir)
        .env("XDG_CONFIG_HOME", env.home_path().join(".config"))
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if stdin.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }

    for (key, value) in extra_env {
        cmd.env(key, value);
    }

    let mut child = cmd.spawn().unwrap_or_else(|error| {
        panic!(
            "failed to spawn dcg binary at {}: {error}",
            binary.display()
        )
    });

    if let Some(input) = stdin {
        child
            .stdin
            .as_mut()
            .expect("child stdin should be piped")
            .write_all(input.as_bytes())
            .expect("failed to write hook JSON to stdin");
    }

    let output = child.wait_with_output().expect("failed to wait for dcg");
    let run = DcgRun {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        exit_code: output.status.code().unwrap_or(-1),
        duration: started.elapsed(),
    };

    tracing::info!(
        target: "e2e_real_service",
        event = "dcg_complete",
        test = %log.name,
        exit_code = run.exit_code,
        duration_ms = run.duration.as_millis(),
        stdout_bytes = run.stdout.len(),
        stderr_bytes = run.stderr.len(),
        stdout = %run.stdout,
        stderr = %run.stderr
    );

    run
}

fn canonical_stdout_json(stdout: &str) -> Value {
    let mut json: Value =
        serde_json::from_str(stdout.trim()).expect("stdout JSON should parse before canonicalize");

    if let Some(hook_output) = json
        .get_mut("hookSpecificOutput")
        .and_then(Value::as_object_mut)
    {
        if hook_output
            .get("allowOnceCode")
            .is_some_and(|value| !value.is_null())
        {
            hook_output.insert(
                "allowOnceCode".to_string(),
                Value::String("<allow-once-code>".to_string()),
            );
        }
        if hook_output
            .get("allowOnceFullHash")
            .is_some_and(|value| !value.is_null())
        {
            hook_output.insert(
                "allowOnceFullHash".to_string(),
                Value::String("sha256:<allow-once-hash>".to_string()),
            );
        }
        if let Some(remediation) = hook_output
            .get_mut("remediation")
            .and_then(Value::as_object_mut)
        {
            if remediation
                .get("allowOnceCommand")
                .is_some_and(|value| !value.is_null())
            {
                remediation.insert(
                    "allowOnceCommand".to_string(),
                    Value::String("dcg allow-once <allow-once-code>".to_string()),
                );
            }
        }
    }

    json
}

fn hook_shape_snapshot(json: &Value, command: &str, rule: Option<&str>) -> Value {
    let hook_output = json
        .get("hookSpecificOutput")
        .and_then(Value::as_object)
        .expect("hookSpecificOutput object should exist");
    let reason = hook_output
        .get("permissionDecisionReason")
        .and_then(Value::as_str)
        .unwrap_or_default();

    json!({
        "hookSpecificOutput": {
            "allowOnceCode": presence_marker(hook_output.get("allowOnceCode")),
            "allowOnceFullHash": presence_marker(hook_output.get("allowOnceFullHash")),
            "confidence": if hook_output.get("confidence").is_some_and(Value::is_number) { "<number>" } else { "<null>" },
            "hookEventName": hook_output.get("hookEventName").cloned().unwrap_or(Value::Null),
            "packId": hook_output.get("packId").cloned().unwrap_or(Value::Null),
            "permissionDecision": hook_output.get("permissionDecision").cloned().unwrap_or(Value::Null),
            "permissionDecisionReason": {
                "containsCommand": reason.contains(command),
                "containsDcgMarker": reason.contains("BLOCKED by dcg") || reason.contains("DCG warn:"),
                "containsRule": rule.is_none_or(|expected| reason.contains(expected)),
            },
            "remediation": remediation_shape(hook_output.get("remediation")),
            "ruleId": hook_output.get("ruleId").cloned().unwrap_or(Value::Null),
            "severity": hook_output.get("severity").cloned().unwrap_or(Value::Null),
        }
    })
}

fn presence_marker(value: Option<&Value>) -> &'static str {
    match value {
        Some(Value::String(s)) if !s.is_empty() => "<present>",
        Some(value) if !value.is_null() => "<present>",
        _ => "<null>",
    }
}

fn remediation_shape(value: Option<&Value>) -> Value {
    let Some(remediation) = value.and_then(Value::as_object) else {
        return Value::String("<null>".to_string());
    };

    json!({
        "allowOnceCommand": remediation
            .get("allowOnceCommand")
            .and_then(Value::as_str)
            .map(|_| "dcg allow-once <allow-once-code>")
            .unwrap_or("<null>"),
        "explanation": presence_marker(remediation.get("explanation")),
        "safeAlternative": presence_marker(remediation.get("safeAlternative")),
    })
}

fn assert_shape_snapshot(log: &TestLog, name: &str, actual: &Value, expected: Value) {
    let actual_pretty =
        serde_json::to_string_pretty(actual).expect("shape snapshot should serialize");
    let expected_pretty =
        serde_json::to_string_pretty(&expected).expect("expected snapshot should serialize");

    tracing::info!(
        target: "e2e_real_service",
        event = "snapshot_compare",
        test = %log.name,
        snapshot = %name,
        actual = %actual_pretty,
        expected = %expected_pretty
    );

    assert_eq!(
        actual_pretty,
        expected_pretty,
        "snapshot {name} changed; see {}",
        log.path.display()
    );
}

fn assert_contains(log: &TestLog, label: &str, haystack: &str, needle: &str) {
    let passed = haystack.contains(needle);
    tracing::info!(
        target: "e2e_real_service",
        event = "assert_contains",
        test = %log.name,
        label = %label,
        needle = %needle,
        passed
    );
    assert!(
        passed,
        "{label}: expected output to contain {needle:?}; see {}",
        log.path.display()
    );
}

fn assert_empty(log: &TestLog, label: &str, value: &str) {
    let passed = value.trim().is_empty();
    tracing::info!(
        target: "e2e_real_service",
        event = "assert_empty",
        test = %log.name,
        label = %label,
        passed,
        bytes = value.len()
    );
    assert!(
        passed,
        "{label}: expected empty output, got {value:?}; see {}",
        log.path.display()
    );
}

fn expected_deny_shape() -> Value {
    json!({
        "hookSpecificOutput": {
            "allowOnceCode": "<present>",
            "allowOnceFullHash": "<present>",
            "confidence": "<null>",
            "hookEventName": "PreToolUse",
            "packId": "core.git",
            "permissionDecision": "deny",
            "permissionDecisionReason": {
                "containsCommand": true,
                "containsDcgMarker": true,
                "containsRule": true
            },
            "remediation": {
                "allowOnceCommand": "dcg allow-once <allow-once-code>",
                "explanation": "<present>",
                "safeAlternative": "<present>"
            },
            "ruleId": "core.git:reset-hard",
            "severity": "critical"
        }
    })
}

fn expected_warn_shape() -> Value {
    json!({
        "hookSpecificOutput": {
            "allowOnceCode": "<null>",
            "allowOnceFullHash": "<null>",
            "confidence": "<null>",
            "hookEventName": "PreToolUse",
            "packId": "core.git",
            "permissionDecision": "ask",
            "permissionDecisionReason": {
                "containsCommand": false,
                "containsDcgMarker": true,
                "containsRule": false
            },
            "remediation": "<null>",
            "ruleId": "core.git:reset-hard",
            "severity": null
        }
    })
}

#[test]
fn safe_bash_allows_silently_for_claude_and_codex() {
    with_test_log("safe_bash_allows_silently_for_claude_and_codex", |log| {
        for protocol in [Protocol::Claude, Protocol::Codex] {
            let env = RealServiceEnv::new(&format!("safe-{}", protocol.label()));
            let run = run_hook(log, &env, protocol, "git status", &[]);

            assert_eq!(
                run.exit_code,
                0,
                "{} safe command should exit 0; see {}",
                protocol.label(),
                log.path.display()
            );
            assert_empty(log, "safe stdout", &run.stdout);
            assert_empty(log, "safe stderr", &run.stderr);
        }
    });
}

#[test]
fn destructive_bash_blocks_with_protocol_specific_output() {
    with_test_log(
        "destructive_bash_blocks_with_protocol_specific_output",
        |log| {
            let claude_env = RealServiceEnv::new("deny-claude");
            let claude = run_hook(log, &claude_env, Protocol::Claude, DESTRUCTIVE_COMMAND, &[]);
            assert_eq!(claude.exit_code, 0, "Claude deny should exit 0");
            let canonical = canonical_stdout_json(&claude.stdout);
            tracing::info!(
                target: "e2e_real_service",
                event = "canonical_stdout_json",
                test = %log.name,
                protocol = "claude",
                json = %serde_json::to_string_pretty(&canonical).unwrap()
            );
            let shape =
                hook_shape_snapshot(&canonical, DESTRUCTIVE_COMMAND, Some("core.git:reset-hard"));
            assert_shape_snapshot(
                log,
                "claude_deny_core_git_reset_hard",
                &shape,
                expected_deny_shape(),
            );
            assert_contains(log, "Claude deny stderr marker", &claude.stderr, "BLOCKED");
            assert_contains(
                log,
                "Claude deny stderr rule",
                &claude.stderr,
                "core.git:reset-hard",
            );

            let codex_env = RealServiceEnv::new("deny-codex");
            let codex = run_hook(log, &codex_env, Protocol::Codex, DESTRUCTIVE_COMMAND, &[]);
            assert_eq!(codex.exit_code, 0, "Codex deny should exit normally");
            let codex_json = codex.stdout_json();
            let codex_specific = codex_json["hookSpecificOutput"]
                .as_object()
                .expect("Codex hookSpecificOutput object");
            assert_eq!(codex_specific.len(), 3, "Codex deny must stay minimal");
            assert_eq!(codex_specific["hookEventName"], "PreToolUse");
            assert_eq!(codex_specific["permissionDecision"], "deny");
            assert!(
                codex_specific["permissionDecisionReason"]
                    .as_str()
                    .is_some_and(|reason| {
                        reason.contains(DESTRUCTIVE_COMMAND)
                            && reason.contains("core.git:reset-hard")
                    }),
                "Codex deny reason must contain command and rule"
            );
            assert_contains(log, "Codex deny stderr marker", &codex.stderr, "BLOCKED");
            assert_contains(
                log,
                "Codex deny stderr rule",
                &codex.stderr,
                "core.git:reset-hard",
            );
        },
    );
}

#[test]
fn warn_policy_emits_ask_json_for_claude_and_stderr_only_for_codex() {
    with_test_log("warn_policy_emits_ask_json_for_claude_and_codex", |log| {
        let config = "[policy.rules]\n\"core.git:reset-hard\" = \"warn\"\n";

        let claude_env = RealServiceEnv::new("warn-claude");
        claude_env.write_config(config);
        let claude = run_hook(log, &claude_env, Protocol::Claude, DESTRUCTIVE_COMMAND, &[]);
        assert_eq!(claude.exit_code, 0, "Claude warn should exit 0");
        let canonical = canonical_stdout_json(&claude.stdout);
        tracing::info!(
            target: "e2e_real_service",
            event = "canonical_stdout_json",
            test = %log.name,
            protocol = "claude",
            json = %serde_json::to_string_pretty(&canonical).unwrap()
        );
        let shape =
            hook_shape_snapshot(&canonical, DESTRUCTIVE_COMMAND, Some("core.git:reset-hard"));
        assert_shape_snapshot(
            log,
            "claude_warn_core_git_reset_hard",
            &shape,
            expected_warn_shape(),
        );
        assert_contains(log, "Claude warn stderr", &claude.stderr, "WARNING");

        let codex_env = RealServiceEnv::new("warn-codex");
        codex_env.write_config(config);
        let codex = run_hook(log, &codex_env, Protocol::Codex, DESTRUCTIVE_COMMAND, &[]);
        assert_eq!(codex.exit_code, 0, "Codex warn should exit 0");
        assert_empty(log, "Codex warn stdout", &codex.stdout);
        assert_contains(log, "Codex warn stderr", &codex.stderr, "WARNING");
        assert_contains(
            log,
            "Codex warn stderr rule",
            &codex.stderr,
            "core.git:reset-hard",
        );
    });
}

#[test]
fn heredoc_embedded_destructive_blocks_for_claude_and_codex() {
    with_test_log(
        "heredoc_embedded_destructive_blocks_for_claude_and_codex",
        |log| {
            let command =
                "python3 <<'PY'\nimport shutil\nshutil.rmtree('/tmp/dcg-real-service')\nPY";

            let claude_env = RealServiceEnv::new("heredoc-claude");
            let claude = run_hook(log, &claude_env, Protocol::Claude, command, &[]);
            assert_eq!(claude.exit_code, 0, "Claude heredoc deny should exit 0");
            let json = claude.stdout_json();
            let hook_output = &json["hookSpecificOutput"];
            assert_eq!(hook_output["permissionDecision"], "deny");
            let pack = hook_output["packId"].as_str().unwrap_or_default();
            assert!(
                pack.starts_with("heredoc."),
                "expected heredoc pack for Claude, got {pack:?}; see {}",
                log.path.display()
            );
            assert_contains(log, "Claude heredoc stderr", &claude.stderr, "BLOCKED");

            let codex_env = RealServiceEnv::new("heredoc-codex");
            let codex = run_hook(log, &codex_env, Protocol::Codex, command, &[]);
            assert_eq!(
                codex.exit_code, 0,
                "Codex heredoc deny should exit normally"
            );
            let codex_json = codex.stdout_json();
            assert_eq!(
                codex_json["hookSpecificOutput"]["permissionDecision"],
                "deny"
            );
            assert_eq!(
                codex_json["hookSpecificOutput"]
                    .as_object()
                    .map(serde_json::Map::len),
                Some(3)
            );
            assert_contains(log, "Codex heredoc stderr", &codex.stderr, "BLOCKED");
            assert_contains(log, "Codex heredoc pack", &codex.stderr, "heredoc.");
        },
    );
}

#[test]
fn bypass_env_allows_destructive_silently_for_both_protocols() {
    with_test_log(
        "bypass_env_allows_destructive_silently_for_both_protocols",
        |log| {
            for protocol in [Protocol::Claude, Protocol::Codex] {
                let env = RealServiceEnv::new(&format!("bypass-{}", protocol.label()));
                let run = run_hook(
                    log,
                    &env,
                    protocol,
                    DESTRUCTIVE_COMMAND,
                    &[("DCG_BYPASS", "1")],
                );

                assert_eq!(
                    run.exit_code,
                    0,
                    "{} bypass should exit 0; see {}",
                    protocol.label(),
                    log.path.display()
                );
                assert_empty(log, "bypass stdout", &run.stdout);
                assert_empty(log, "bypass stderr", &run.stderr);
            }
        },
    );
}

#[test]
fn allow_once_short_code_round_trip_redeems_real_pending_exception() {
    with_test_log(
        "allow_once_short_code_round_trip_redeems_real_pending_exception",
        |log| {
            let env = RealServiceEnv::new("allow-once");

            let deny = run_hook(log, &env, Protocol::Claude, DESTRUCTIVE_COMMAND, &[]);
            assert_eq!(deny.exit_code, 0, "initial Claude deny should exit 0");
            let json = deny.stdout_json();
            let allow_code = json["hookSpecificOutput"]["allowOnceCode"]
                .as_str()
                .expect("deny JSON should include allowOnceCode")
                .to_string();
            assert!(
                allow_code.len() >= 5,
                "allowOnceCode should be substantial; see {}",
                log.path.display()
            );

            let redeem = run_dcg(log, &env, &["allow-once", &allow_code, "--yes"], None, &[]);
            assert_eq!(
                redeem.exit_code,
                0,
                "allow-once redemption should exit 0; see {}",
                log.path.display()
            );

            let retry = run_hook(log, &env, Protocol::Claude, DESTRUCTIVE_COMMAND, &[]);
            assert_eq!(retry.exit_code, 0, "allow-once retry should exit 0");
            assert_empty(log, "allow-once retry stdout", &retry.stdout);
        },
    );
}

#[test]
fn cli_version_and_help_emit_human_output() {
    with_test_log("cli_version_and_help_emit_human_output", |log| {
        let env = RealServiceEnv::new("cli-help-version");

        let version = run_dcg(log, &env, &["--version"], None, &[]);
        assert_eq!(version.exit_code, 0, "--version should exit 0");
        assert_contains(
            log,
            "--version stdout",
            &version.stdout,
            env!("CARGO_PKG_VERSION"),
        );
        assert_contains(log, "--version stderr", &version.stderr, "dcg");
        assert_contains(
            log,
            "--version stderr version",
            &version.stderr,
            env!("CARGO_PKG_VERSION"),
        );

        let help = run_dcg(log, &env, &["--help"], None, &[]);
        assert_eq!(help.exit_code, 0, "--help should exit 0");
        assert_empty(log, "--help stdout", &help.stdout);
        assert_contains(log, "--help stderr", &help.stderr, "USAGE");
        assert_contains(
            log,
            "--help stderr multi-agent",
            &help.stderr,
            "Claude Code, Codex CLI",
        );
        assert_contains(
            log,
            "--help stderr codex contract",
            &help.stderr,
            "including Codex, receive protocol-specific stdout JSON",
        );
        assert_contains(log, "--help stderr command", &help.stderr, "COMMANDS");
    });
}

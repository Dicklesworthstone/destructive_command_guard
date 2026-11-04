#![allow(clippy::needless_raw_string_hashes)]
//! End-to-end tests for CLI flows: explain, scan, simulate.
//!
//! These tests verify that CLI subcommands produce structurally valid output
//! in all supported formats, and return appropriate exit codes.
//!
//! # Running
//!
//! ```bash
//! cargo test --test cli_e2e
//! ```

use std::io::Write;
use std::process::{Command, Stdio};

/// Path to the exact dcg binary Cargo built for this integration test.
fn dcg_binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

/// Helper to run dcg with arguments and capture output.
///
/// Hermetic, for the same reason `tests/golden_artifacts.rs` is: without an
/// isolated `HOME`/`XDG_CONFIG_HOME`, dcg reads the developer's real
/// `~/.config/dcg/config.toml`. That made assertions here depend on the
/// machine — a maintainer with `[policy.rules] "core.git:reset-hard" = "warn"`
/// (a documented, supported setting, and precisely the one #417 exists to
/// support) saw `explain_json_format_is_valid` fail on `mode`, while CI stayed
/// green. Clear the environment, then re-export only what the binary needs.
fn run_dcg(args: &[&str]) -> std::process::Output {
    let home = tempfile::tempdir().expect("create isolated HOME for run_dcg");
    std::fs::create_dir_all(home.path().join(".config/dcg"))
        .expect("create XDG_CONFIG_HOME/dcg under isolated HOME");
    std::fs::create_dir_all(home.path().join("tmp")).expect("create isolated TMPDIR");

    let mut cmd = Command::new(dcg_binary());
    cmd.args(args).env_clear();
    if let Ok(path) = std::env::var("PATH") {
        cmd.env("PATH", path);
    }
    cmd.env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env("TMPDIR", home.path().join("tmp"))
        .env("TEMP", home.path().join("tmp"))
        .env("TMP", home.path().join("tmp"))
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env("DCG_NO_SELF_HEAL", "1")
        .env("NO_COLOR", "1")
        .env("CLICOLOR", "0")
        .env("TERM", "dumb")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    cmd.output().expect("failed to execute dcg")
}

/// Run `dcg create-new` with byte-exact piped input and capture every output
/// stream. The command must never use stdout, because its intended use is as a
/// safe sink at the end of a pipeline.
fn run_create_new(
    path: &std::path::Path,
    input: &[u8],
) -> (std::process::Output, std::io::Result<()>) {
    let mut child = Command::new(dcg_binary())
        .arg("create-new")
        .arg(path)
        .env_remove("DCG_QUIET")
        .env_remove("DCG_ROBOT")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn dcg create-new");

    let stdin_write = child
        .stdin
        .take()
        .expect("failed to open create-new stdin")
        .write_all(input);

    let output = child
        .wait_with_output()
        .expect("failed to wait for dcg create-new");
    (output, stdin_write)
}

fn assert_refused_sink_write_is_benign(result: &std::io::Result<()>) {
    assert!(
        match result {
            Ok(()) => true,
            Err(error) => error.kind() == std::io::ErrorKind::BrokenPipe,
        },
        "refused sink produced an unexpected stdin error: {result:?}"
    );
}

#[test]
fn create_new_streams_exact_bytes_once_without_stdout() {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let destination = temp.path().join("payload.bin");
    let original = b"first\0payload\n\xff\xfe";

    let (first, first_write) = run_create_new(&destination, original);
    first_write.expect("successful create-new must consume every input byte");
    assert!(
        first.status.success(),
        "first create-new invocation failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(
        first.stdout.is_empty(),
        "create-new must reserve stdout for pipeline composition"
    );
    assert!(
        String::from_utf8_lossy(&first.stderr).contains("Created"),
        "successful creation should be confirmed on stderr"
    );
    assert_eq!(
        std::fs::read(&destination).expect("read created file"),
        original,
        "stdin bytes must reach the destination without text decoding"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(&destination)
            .expect("created file metadata")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o077,
            0,
            "new files must not grant group or other permissions"
        );
    }

    let replacement = b"replacement that must never land";
    let (second, second_write) = run_create_new(&destination, replacement);
    assert_refused_sink_write_is_benign(&second_write);
    assert!(
        !second.status.success(),
        "create-new must fail when any destination entry already exists"
    );
    assert!(
        second.stdout.is_empty(),
        "create-new errors belong on stderr, never stdout"
    );
    assert!(
        String::from_utf8_lossy(&second.stderr).contains("refusing to replace existing path"),
        "existing-path failure should explain the non-overwrite guarantee: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(
        std::fs::read(&destination).expect("read destination after refused replacement"),
        original,
        "a second invocation must preserve every original byte"
    );
}

#[test]
fn create_new_does_not_create_missing_parent_directories() {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let missing_parent = temp.path().join("missing");
    let destination = missing_parent.join("payload.txt");

    let (output, stdin_write) = run_create_new(&destination, b"must not be written");
    assert_refused_sink_write_is_benign(&stdin_write);
    assert!(!output.status.success());
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("could not create new file"),
        "missing-parent failure should carry create context: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !missing_parent.exists(),
        "create-new must not manufacture parent directories"
    );
}

#[cfg(unix)]
#[test]
fn create_new_refuses_an_existing_symlink_without_touching_its_target() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let target = temp.path().join("target.txt");
    let link = temp.path().join("destination-link");
    std::fs::write(&target, b"target stays unchanged").expect("write symlink target");
    symlink(&target, &link).expect("create destination symlink");

    let (output, stdin_write) = run_create_new(&link, b"must not follow the symlink");
    assert_refused_sink_write_is_benign(&stdin_write);
    assert!(!output.status.success());
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("refusing to replace existing path"),
        "symlink refusal should state the non-overwrite guarantee: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(&target).expect("read symlink target"),
        b"target stays unchanged"
    );
    assert!(
        std::fs::symlink_metadata(&link)
            .expect("symlink metadata")
            .file_type()
            .is_symlink(),
        "the destination symlink itself must remain intact"
    );
}

fn run_dcg_with_env(args: &[&str], envs: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = Command::new(dcg_binary());
    cmd.args(args)
        .env_remove("DCG_VERBOSE")
        .env_remove("DCG_QUIET")
        .env_remove("DCG_LEGACY_OUTPUT")
        .env_remove("DCG_NO_COLOR")
        .env_remove("DCG_NO_SUGGESTIONS")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    for (key, value) in envs {
        cmd.env(key, value);
    }

    cmd.output().expect("failed to execute dcg")
}

#[derive(Debug)]
struct HookRunOutput {
    command: String,
    output: std::process::Output,
}

impl HookRunOutput {
    fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.output.stdout).to_string()
    }

    fn stderr_str(&self) -> String {
        String::from_utf8_lossy(&self.output.stderr).to_string()
    }
}

/// Run dcg in hook mode (no CLI subcommand) and capture output.
///
/// This runs with a cleared environment and a temp CWD to ensure tests don't
/// depend on user/system configs or allowlists.
fn run_dcg_hook_with_env(command: &str, extra_env: &[(&str, &std::ffi::OsStr)]) -> HookRunOutput {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    std::fs::create_dir_all(temp.path().join(".git")).expect("failed to create .git dir");

    let home_dir = temp.path().join("home");
    let xdg_config_dir = temp.path().join("xdg_config");
    std::fs::create_dir_all(&home_dir).expect("failed to create HOME dir");
    std::fs::create_dir_all(&xdg_config_dir).expect("failed to create XDG_CONFIG_HOME dir");

    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {
            "command": command,
        }
    });

    let mut cmd = Command::new(dcg_binary());
    cmd.env_clear()
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .env("XDG_CONFIG_HOME", &xdg_config_dir)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        // These tests assert semantic allow/deny behavior, not the separately
        // unit-tested 200 ms fail-closed deadline policy. A heavily loaded test
        // host can deschedule the child after its deadline starts and turn the
        // intended semantic result into an indeterminate blocking/ask response,
        // so keep a generous E2E-only budget. `extra_env` is applied below and
        // may still override this when a test intentionally exercises deadline
        // behavior.
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .env("DCG_PACKS", "core.git,core.filesystem")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in extra_env {
        cmd.env(key, value);
    }

    let mut child = cmd.spawn().expect("failed to spawn dcg hook mode");

    {
        let stdin = child.stdin.as_mut().expect("failed to open stdin");
        serde_json::to_writer(stdin, &input).expect("failed to write hook input JSON");
    }

    let output = child.wait_with_output().expect("failed to wait for dcg");

    HookRunOutput {
        command: command.to_string(),
        output,
    }
}

fn run_dcg_hook(command: &str) -> HookRunOutput {
    run_dcg_hook_with_env(command, &[])
}

#[test]
fn python_heredoc_to_powershell_hook_denial_is_actionable() {
    let command = "python - <<'PY' | pwsh\nprint('{\"status\": \"ok\"}')\nPY";
    let result = run_dcg_hook_with_env(
        command,
        &[
            ("NO_COLOR", std::ffi::OsStr::new("1")),
            ("DCG_DIALECT", std::ffi::OsStr::new("posix")),
        ],
    );
    let stdout = result.stdout_str();
    let stderr = result.stderr_str();
    let json: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("hook denial must be valid JSON");
    let denial = &json["hookSpecificOutput"];

    assert_eq!(denial["permissionDecision"], "deny", "{stdout}\n{stderr}");
    assert_eq!(
        denial["ruleId"], "heredoc.posix:pipeline-consumer",
        "the hook must expose the stable rule id: {stdout}"
    );
    let reason = denial["permissionDecisionReason"]
        .as_str()
        .expect("hook denial carries a reason");
    assert!(
        reason.contains("heredoc pipeline producer \"python\"")
            && reason.contains("is not a statically modeled literal source"),
        "hook JSON must retain producer provenance: {reason}"
    );
    assert!(
        reason.contains("-Command <script>") && reason.contains("-File <path>"),
        "hook JSON must carry scoped PowerShell remediation: {reason}"
    );
    assert!(
        stderr.contains("pwsh") && stderr.contains("^^^^"),
        "human diagnostics must point at the PowerShell consumer:\n{stderr}"
    );
}

/// Run bare `dcg` (hook mode, no subcommand) writing RAW bytes to stdin, with
/// optional extra environment. Used to exercise UTF-8 BOM handling and
/// unparseable-input handling (issue #160).
fn run_dcg_hook_raw(raw: &[u8], extra_env: &[(&str, &str)]) -> std::process::Output {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    std::fs::create_dir_all(temp.path().join(".git")).unwrap();
    let home_dir = temp.path().join("home");
    let xdg_config_dir = temp.path().join("xdg_config");
    std::fs::create_dir_all(&home_dir).unwrap();
    std::fs::create_dir_all(&xdg_config_dir).unwrap();

    let mut cmd = Command::new(dcg_binary());
    cmd.env_clear()
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .env("XDG_CONFIG_HOME", &xdg_config_dir)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        // These raw-input tests assert parsing and allow/deny semantics. Keep
        // scheduler pressure from turning an otherwise-safe command into an
        // indeterminate deadline response; callers may still override this
        // when explicitly testing timeout behavior.
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .env("DCG_PACKS", "core.git,core.filesystem")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("failed to spawn dcg hook mode");
    {
        let stdin = child.stdin.as_mut().expect("failed to open stdin");
        stdin
            .write_all(raw)
            .expect("failed to write raw hook input");
    }
    child.wait_with_output().expect("failed to wait for dcg")
}

const BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

#[test]
fn bare_hook_bom_prefixed_dangerous_command_is_blocked() {
    // BOM + valid dangerous payload: must be evaluated and denied, not fail-open.
    let mut raw = BOM.to_vec();
    raw.extend_from_slice(br#"{"tool_name":"Bash","tool_input":{"command":"git reset --hard"}}"#);
    let out = run_dcg_hook_raw(&raw, &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"permissionDecision\":\"deny\""),
        "BOM-prefixed dangerous command must be blocked, not fail-open allowed.\nstdout: {stdout}"
    );
}

#[test]
fn bare_hook_bom_prefixed_safe_command_is_allowed() {
    let mut raw = BOM.to_vec();
    raw.extend_from_slice(br#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#);
    let out = run_dcg_hook_raw(&raw, &[]);
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stdout).trim().is_empty(),
        "BOM-prefixed safe command must be allowed (empty stdout)"
    );
}

#[test]
fn bare_hook_fail_closed_blocks_unparseable_input() {
    let raw = b"this is not valid json at all";

    // Default: fail-open -> no deny, exit 0, empty stdout.
    let open = run_dcg_hook_raw(raw, &[]);
    assert!(open.status.success(), "default must fail open (exit 0)");
    assert!(
        String::from_utf8_lossy(&open.stdout).trim().is_empty(),
        "default fail-open must allow unparseable input (empty stdout)"
    );

    // DCG_FAIL_CLOSED=1: deny.
    let closed = run_dcg_hook_raw(raw, &[("DCG_FAIL_CLOSED", "1")]);
    let stdout = String::from_utf8_lossy(&closed.stdout);
    assert!(
        stdout.contains("\"permissionDecision\":\"deny\""),
        "DCG_FAIL_CLOSED must block unparseable input.\nstdout: {stdout}"
    );
}

#[test]
fn bare_hook_fail_closed_still_allows_valid_commands() {
    // Fail-closed must only block UNPARSEABLE input, never valid commands.
    let safe = br#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#;
    let safe_out = run_dcg_hook_raw(safe, &[("DCG_FAIL_CLOSED", "1")]);
    assert!(safe_out.status.success());
    assert!(
        String::from_utf8_lossy(&safe_out.stdout).trim().is_empty(),
        "fail-closed must still allow a valid safe command"
    );

    // And it must still DENY a valid dangerous command (not turn it into an error).
    let danger = br#"{"tool_name":"Bash","tool_input":{"command":"git reset --hard"}}"#;
    let danger_out = run_dcg_hook_raw(danger, &[("DCG_FAIL_CLOSED", "1")]);
    assert!(
        String::from_utf8_lossy(&danger_out.stdout).contains("\"permissionDecision\":\"deny\""),
        "fail-closed must still deny a valid dangerous command"
    );
}

#[test]
fn bare_hook_unverified_decision_controls_oversized_fallback() {
    // #338: an oversized command is one of the two deterministic unverified
    // paths. Default posture routes it to `ask`; the unattended posture
    // (`DCG_UNVERIFIED_DECISION=deny`) must refuse it outright.
    let padding = "x".repeat(70 * 1024);
    let raw = format!(r#"{{"tool_name":"Bash","tool_input":{{"command":"echo {padding}"}}}}"#)
        .into_bytes();

    let asked = run_dcg_hook_raw(&raw, &[]);
    let stdout = String::from_utf8_lossy(&asked.stdout);
    assert!(
        stdout.contains("\"permissionDecision\":\"ask\""),
        "default unverified fallback must be ask.\nstdout: {stdout}"
    );

    let denied = run_dcg_hook_raw(&raw, &[("DCG_UNVERIFIED_DECISION", "deny")]);
    let stdout = String::from_utf8_lossy(&denied.stdout);
    assert!(
        stdout.contains("\"permissionDecision\":\"deny\""),
        "DCG_UNVERIFIED_DECISION=deny must refuse the unverified command.\nstdout: {stdout}"
    );
    assert!(
        stdout.contains("unverified_decision"),
        "the denial must say it came from the configured unverified posture.\nstdout: {stdout}"
    );

    // The posture only governs the unverified path: ordinary commands keep
    // their ordinary decisions under it.
    let safe = br#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#;
    let safe_out = run_dcg_hook_raw(safe, &[("DCG_UNVERIFIED_DECISION", "deny")]);
    assert!(safe_out.status.success());
    assert!(
        String::from_utf8_lossy(&safe_out.stdout).trim().is_empty(),
        "unverified_decision=deny must still allow a valid safe command"
    );
}

/// A payload that declares `bypassPermissions`/`dontAsk` gets the unattended
/// posture without configuration: Claude Code documents that a hook `deny`
/// holds in those modes but not what a hook `ask` does there, and an `ask`
/// waved through would run exactly the command dcg could not inspect.
/// A payload serde still cannot parse -- nesting past its recursion limit, a
/// trailing comma -- gets the best-effort scan the oversized and invalid-UTF-8
/// payloads already had, instead of failing open with the destructive command
/// in plain view. Malformed input with no visible shell command still fails
/// open (the documented default).
#[test]
fn bare_hook_unparseable_json_with_a_visible_destructive_command_is_denied() {
    let deep = format!(
        r#"{{"tool_name":"Bash","tool_input":{{"command":"rm -rf ~"}},"x":{}{}}}"#,
        "[".repeat(200),
        "]".repeat(200)
    );
    let trailing_comma = r#"{"tool_name":"Bash","tool_input":{"command":"git reset --hard"},}"#;
    for raw in [deep.as_str(), trailing_comma] {
        let out = run_dcg_hook_raw(raw.as_bytes(), &[]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("\"permissionDecision\":\"deny\""),
            "unparseable payload with a destructive command must be judged.\nstdout: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    for raw in [
        r#"{"tool_name":"Bash","tool_input":{"command":"git status"},}"#,
        r#"{"tool_name":"Read","tool_input":{"command":"rm -rf ~"},}"#,
        "not json at all",
    ] {
        let out = run_dcg_hook_raw(raw.as_bytes(), &[]);
        assert!(
            String::from_utf8_lossy(&out.stdout).trim().is_empty(),
            "{raw}: stdout {}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}

/// Through the real binary: a lone surrogate escape used to fail the parse
/// and so allow the destructive command beside it (fail-open).
#[test]
fn bare_hook_lone_surrogate_escape_does_not_fail_open() {
    let raw = br#"{"tool_name":"Bash","tool_input":{"command":"rm -rf ~ # \ud800"}}"#;
    let out = run_dcg_hook_raw(raw, &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("\"permissionDecision\":\"deny\""),
        "a lone surrogate must not make the command fail open.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stderr.contains("could not parse hook input"),
        "stderr: {stderr}"
    );
}

#[test]
fn bare_hook_unattended_permission_mode_denies_unverified_commands() {
    let padding = "x".repeat(70 * 1024);
    let payload = |mode: &str| {
        format!(
            r#"{{"hook_event_name":"PreToolUse","permission_mode":"{mode}","tool_name":"Bash","tool_input":{{"command":"echo {padding}"}}}}"#
        )
        .into_bytes()
    };

    for mode in ["bypassPermissions", "dontAsk"] {
        let out = run_dcg_hook_raw(&payload(mode), &[]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("\"permissionDecision\":\"deny\""),
            "{mode}: an unverified command must be denied, not asked.\nstdout: {stdout}"
        );
    }
    for mode in ["default", "acceptEdits", "plan"] {
        let out = run_dcg_hook_raw(&payload(mode), &[]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("\"permissionDecision\":\"ask\""),
            "{mode}: a human can answer, so the default ask stays.\nstdout: {stdout}"
        );
    }
    // An explicit operator choice still wins.
    let out = run_dcg_hook_raw(
        &payload("bypassPermissions"),
        &[("DCG_UNVERIFIED_DECISION", "ask")],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"permissionDecision\":\"ask\""),
        "explicit DCG_UNVERIFIED_DECISION=ask must be honoured.\nstdout: {stdout}"
    );
    // Verified commands are untouched: a safe command stays silent.
    let safe = br#"{"permission_mode":"bypassPermissions","tool_name":"Bash","tool_input":{"command":"git status"}}"#;
    let out = run_dcg_hook_raw(safe, &[]);
    assert!(String::from_utf8_lossy(&out.stdout).trim().is_empty());
}

/// Run bare `dcg` with raw stdin, optional env, and an optional user config
/// file written to `XDG_CONFIG_HOME/dcg/config.toml`.
fn run_dcg_hook_raw_cfg(
    raw: &[u8],
    extra_env: &[(&str, &str)],
    config_toml: Option<&str>,
) -> std::process::Output {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    std::fs::create_dir_all(temp.path().join(".git")).unwrap();
    let home_dir = temp.path().join("home");
    let xdg_config_dir = temp.path().join("xdg_config");
    std::fs::create_dir_all(&home_dir).unwrap();
    std::fs::create_dir_all(&xdg_config_dir).unwrap();
    if let Some(toml) = config_toml {
        let dcg_cfg = xdg_config_dir.join("dcg");
        std::fs::create_dir_all(&dcg_cfg).unwrap();
        std::fs::write(dcg_cfg.join("config.toml"), toml).unwrap();
    }

    let mut cmd = Command::new(dcg_binary());
    cmd.env_clear()
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .env("XDG_CONFIG_HOME", &xdg_config_dir)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        // Match the other semantic hook helpers: configuration tests should
        // not accidentally become production-deadline stress tests.
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .env("DCG_PACKS", "core.git,core.filesystem")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("failed to spawn dcg hook mode");
    {
        let stdin = child.stdin.as_mut().expect("failed to open stdin");
        stdin
            .write_all(raw)
            .expect("failed to write raw hook input");
    }
    child.wait_with_output().expect("failed to wait for dcg")
}

#[test]
fn fail_closed_via_config_file_blocks_unparseable() {
    // Regression (issue #160): `[general] fail_closed = true` from a CONFIG
    // FILE (no env var) must take effect. Previously only the env var worked.
    let cfg = "[general]\nfail_closed = true\n";
    let out = run_dcg_hook_raw_cfg(b"garbage not json", &[], Some(cfg));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"permissionDecision\":\"deny\""),
        "config-file fail_closed must block unparseable input.\nstdout: {stdout}"
    );

    // Without fail_closed in the config, the default fails open.
    let open = run_dcg_hook_raw_cfg(
        b"garbage not json",
        &[],
        Some("[general]\nverbose = false\n"),
    );
    assert!(open.status.success());
    assert_eq!(String::from_utf8_lossy(&open.stdout).trim(), "");
}

#[test]
fn fail_closed_under_codex_protocol_emits_minimal_json() {
    // Regression (issue #160): a fail-closed deny must use the AGENT's wire
    // protocol. Current Codex requires its minimal hookSpecificOutput shape;
    // a Claude-compatible payload with dcg extension fields can be rejected.
    let out = run_dcg_hook_raw(
        b"garbage not json",
        &[("CODEX_CLI", "1"), ("DCG_FAIL_CLOSED", "1")],
    );
    assert_eq!(out.status.code(), Some(0), "Codex deny must exit normally");
    let json: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|error| panic!("Codex fail-closed stdout must be JSON: {error}"));
    let specific = json["hookSpecificOutput"]
        .as_object()
        .expect("Codex hookSpecificOutput object");
    assert_eq!(specific.len(), 3, "Codex denial must stay minimal");
    assert_eq!(specific["hookEventName"], "PreToolUse");
    assert_eq!(specific["permissionDecision"], "deny");
    assert!(
        !String::from_utf8_lossy(&out.stderr).trim().is_empty(),
        "Codex deny reason must be on stderr"
    );
}

#[test]
fn fail_closed_oversized_input_is_denied() {
    // Regression (issue #160): oversized input is attacker-controllable (pad a
    // command past max_hook_input_bytes). Under fail-closed it must be DENIED,
    // not skipped/allowed.
    let big = vec![b'A'; 270_000]; // > default 256 KiB limit

    // Default: fail-open (allowed, exit 0).
    let open = run_dcg_hook_raw(&big, &[]);
    assert!(open.status.success(), "default oversized input fails open");
    assert_eq!(String::from_utf8_lossy(&open.stdout).trim(), "");

    // Fail-closed: denied.
    let closed = run_dcg_hook_raw(&big, &[("DCG_FAIL_CLOSED", "1")]);
    let stdout = String::from_utf8_lossy(&closed.stdout);
    assert!(
        stdout.contains("\"permissionDecision\":\"deny\""),
        "oversized input under fail-closed must be denied.\nstdout: {stdout}"
    );
}

/// Run a `dcg` subcommand with an isolated HOME/XDG and capture output.
fn run_dcg_subcmd(args: &[&str]) -> std::process::Output {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let home_dir = temp.path().join("home");
    let xdg_config_dir = temp.path().join("xdg_config");
    std::fs::create_dir_all(&home_dir).unwrap();
    std::fs::create_dir_all(&xdg_config_dir).unwrap();
    Command::new(dcg_binary())
        .env_clear()
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .env("XDG_CONFIG_HOME", &xdg_config_dir)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .current_dir(temp.path())
        .args(args)
        .output()
        .expect("failed to run dcg subcommand")
}

#[test]
fn allow_rejects_group_prefix_pack_id() {
    // Regression (issue #162): a bare group prefix like `core` can never match
    // (allowlist matching is on the full concrete pack id), so it must be
    // rejected rather than written as a silent no-op entry.
    let bad = run_dcg_subcmd(&["allow", "--reason", "test", "core:reset-hard"]);
    assert!(
        !bad.status.success(),
        "`dcg allow core:reset-hard` must be rejected (group prefix never matches)"
    );

    // The exact concrete pack id is still accepted.
    let good = run_dcg_subcmd(&["allow", "--reason", "ok", "core.git:reset-hard"]);
    assert!(
        good.status.success(),
        "`dcg allow core.git:reset-hard` (valid concrete pack) must succeed.\nstderr: {}",
        String::from_utf8_lossy(&good.stderr)
    );
}

#[test]
fn documented_global_boolean_env_values_do_not_fail_clap_parsing() {
    let flag_envs = [
        "DCG_QUIET",
        "DCG_LEGACY_OUTPUT",
        "DCG_NO_COLOR",
        "DCG_NO_SUGGESTIONS",
    ];
    let values = [
        "1", "true", "yes", "on", "anything", "0", "false", "no", "off",
    ];

    for env_name in flag_envs {
        for value in values {
            let output = run_dcg_with_env(
                &["test", "--format", "json", "git status"],
                &[(env_name, value)],
            );
            let stderr = String::from_utf8_lossy(&output.stderr);

            assert!(
                output.status.success(),
                "{env_name}={value:?} should not fail CLI parsing\nstderr:\n{stderr}"
            );
            assert!(
                !stderr.contains("invalid value"),
                "{env_name}={value:?} should not be rejected as an invalid boolean\nstderr:\n{stderr}"
            );
        }
    }
}

// Issue #549: evaluate recursive-delete inputs only. No Python interpreter or
// deletion command is ever executed by these regressions.
mod python_temp_root_tests {
    use super::*;

    const TEMP_ROOTS: [&str; 4] = ["/tmp", "/var/tmp", "/private/tmp", "/private/var/tmp"];

    struct TestEnv {
        root: tempfile::TempDir,
    }

    impl TestEnv {
        fn new() -> Self {
            Self::with_heredoc_limit("")
        }

        fn with_heredoc_limit(limit: &str) -> Self {
            let root = tempfile::tempdir().expect("create isolated CLI environment");
            std::fs::create_dir_all(root.path().join("home/.config/dcg")).unwrap();
            std::fs::create_dir_all(root.path().join("tmp")).unwrap();
            std::fs::write(
                root.path().join("config.toml"),
                format!(
                    "[heredoc]\nenabled = true\ntimeout_ms = 5000\n{limit}\n\
                 [history]\nenabled = false\n\
                 [packs]\ndisabled = [\"windows.filesystem\", \"windows.system\"]\n"
                ),
            )
            .expect("write isolated policy config");
            Self { root }
        }

        fn assert_verdict(&self, command: &str, expected: &str) {
            let home = self.root.path().join("home");
            let scratch = self.root.path().join("tmp");
            let config = self.root.path().join("config.toml");
            let mut child = Command::new(dcg_binary())
                .args([
                    "test",
                    "--stdin",
                    "--dialect",
                    "posix",
                    "--format",
                    "json",
                    "--config",
                ])
                .arg(&config)
                .env_clear()
                .env("HOME", &home)
                .env("USERPROFILE", &home)
                .env("APPDATA", home.join("appdata"))
                .env("LOCALAPPDATA", home.join("localappdata"))
                .env("XDG_CONFIG_HOME", home.join(".config"))
                .env("XDG_DATA_HOME", home.join(".local/share"))
                .env("TMPDIR", &scratch)
                .env("TEMP", &scratch)
                .env("TMP", &scratch)
                .env("DCG_CONFIG", &config)
                .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
                .env("DCG_SELF_HEAL_HOOK", "0")
                // These are semantic regressions. A scheduling delay must not
                // replace a completed verdict with the bounded fallback.
                .env("DCG_AST_TIMEOUT_MS", "5000")
                .env("DCG_HOOK_TIMEOUT_MS", "5000")
                .current_dir(self.root.path())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn dcg test");
            child
                .stdin
                .take()
                .expect("dcg stdin")
                .write_all(command.as_bytes())
                .expect("send command as inert evaluation input");
            let output = child.wait_with_output().expect("wait for dcg test");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let result: serde_json::Value =
                serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
                    panic!("invalid verdict JSON for {command:?}: {error}\n{stdout}\n{stderr}")
                });
            assert_eq!(
                result["decision"], expected,
                "unexpected verdict for {command:?}\n{stdout}\n{stderr}"
            );
        }

        fn assert_python_target(&self, target: &str, expected: &str) {
            let body = format!("import shutil; shutil.rmtree('{target}')");
            self.assert_python_body(&body, expected);
        }

        fn assert_python_body(&self, body: &str, expected: &str) {
            self.assert_verdict(&format!("python3 -c \"{body}\""), expected);
            self.assert_verdict(&format!("python3 - <<'PY'\n{body}\nPY"), expected);
        }
    }

    #[test]
    fn python_temp_roots_and_normalized_aliases_deny_issue_549() {
        let env = TestEnv::new();
        for root in TEMP_ROOTS {
            for suffix in ["", "/", "//", "/.", "/./", "//.//./", "/build/.."] {
                env.assert_python_target(&format!("{root}{suffix}"), "deny");
            }
        }
        for target in [
            "/./tmp",
            "//tmp",
            "/var//tmp",
            "/private/./tmp",
            "/private//var/./tmp",
        ] {
            env.assert_python_target(target, "deny");
        }
    }

    #[test]
    fn python_temp_traversal_and_prefix_lookalikes_deny_issue_549() {
        let env = TestEnv::new();
        for target in [
            "/tmp/../etc",
            "/tmp/build/../../etc",
            "/var/tmp/../../etc",
            "/private/tmp/../../etc",
            "/private/var/tmp/../../../etc",
            "/tmp//..//etc",
            // Preserve the established rejection of every parent component,
            // even when lexical normalization would land inside a temp tree.
            "/tmp/build/../cache",
            "/tmp/../tmp/build",
            "/tmp-backup/build",
            "/private/tmp-backup/build",
            "/var/tmpfile/build",
        ] {
            env.assert_python_target(target, "deny");
        }
    }

    #[test]
    fn python_actual_temp_descendants_allow_issue_549() {
        let env = TestEnv::new();
        for root in TEMP_ROOTS {
            for suffix in [
                "/build",
                "/build/",
                "//build//",
                "/./build/.",
                "/build..cache",
            ] {
                env.assert_python_target(&format!("{root}{suffix}"), "allow");
            }
        }
        for target in [
            "/./tmp/build",
            "/var//tmp/./build",
            "/private/./tmp/build",
            "/private//var/tmp/build",
            "/tmp/.hidden",
        ] {
            env.assert_python_target(target, "allow");
        }
    }

    #[test]
    fn python_execution_forms_preserve_temp_boundary_issue_549() {
        let env = TestEnv::new();
        for (target, expected) in [("/tmp/.", "deny"), ("/tmp/build", "allow")] {
            for command in [
                format!("python -c 'import shutil; shutil.rmtree(\"{target}\")'"),
                format!("python3 -I -c \"import shutil; shutil.rmtree('{target}')\""),
                format!(
                    "python3 -W ignore::DeprecationWarning -c \"import shutil; shutil.rmtree('{target}')\""
                ),
                format!(
                    "python3 -c \"import shutil as sh; sh.rmtree('{target}', ignore_errors=True)\""
                ),
                format!("python3 -c \"import shutil; shutil.rmtree(path='{target}')\""),
                format!("python3 -c \"import shutil; shutil.rmtree(('{target}'))\""),
                format!("python3 <<'PY'\nimport shutil as sh\nsh.rmtree('{target}')\nPY"),
                format!("python3 -I - <<'PY'\nimport shutil\nshutil.rmtree('{target}')\nPY"),
            ] {
                env.assert_verdict(&command, expected);
            }
        }
    }

    #[test]
    fn python_temp_exemption_cannot_borrow_unrelated_evidence_issue_549() {
        let env = TestEnv::new();
        for call in [
            "shutil.rmtree('/tmp/build' + '/..')",
            "shutil.rmtree('/tmp/build' + '/../../home/user/Documents')",
            "shutil.rmtree('/tmp/build' + suffix)",
            "shutil.rmtree('/tmp/build'[:-5])",
            "shutil.rmtree(Path('/tmp/build').parent)",
            "shutil.rmtree(os.path.join('/tmp/build', '../../etc'))",
            "shutil.rmtree('/tmp/\\x2e')",
            "shutil.rmtree(path='/tmp', onerror=lambda *args: tempfile.mkdtemp())",
            "shutil.rmtree(Path(tempfile.mkdtemp()).parent)",
            "shutil.rmtree(tempfile.mkdtemp() + '/..')",
        ] {
            let body = format!("import os, shutil, tempfile; from pathlib import Path; {call}");
            env.assert_verdict(&format!("python3 -c \"{body}\""), "deny");
            env.assert_verdict(&format!("python3 - <<'PY'\n{body}\nPY"), "deny");
        }
    }

    #[test]
    fn python_fresh_temp_cleanup_and_inert_examples_remain_allowed_issue_549() {
        let env = TestEnv::new();
        for body in [
            "import shutil, tempfile; shutil.rmtree(tempfile.mkdtemp())",
            "import shutil; from tempfile import mkdtemp; shutil.rmtree(mkdtemp())",
            "import shutil; import tempfile as tf; shutil.rmtree(tf.mkdtemp())",
            "import shutil; import tempfile as tf; shutil.rmtree(tf.mkdtemp(prefix='build-'))",
            "import shutil; import tempfile as tf; shutil.rmtree(tf.TemporaryDirectory().name)",
        ] {
            env.assert_verdict(&format!("python3 -c \"{body}\""), "allow");
            env.assert_verdict(&format!("python3 - <<'PY'\n{body}\nPY"), "allow");
        }
        env.assert_verdict(
            "cat <<'PY'\nimport shutil\nshutil.rmtree('/tmp')\nPY",
            "allow",
        );
        env.assert_verdict("python3 -c \"print('shutil.rmtree(/tmp)')\"", "allow");
    }

    #[test]
    fn shell_temp_cleanup_policy_remains_supported_issue_549() {
        let env = TestEnv::new();
        for root in TEMP_ROOTS {
            env.assert_verdict(&format!("rm -rf {root}"), "deny");
            env.assert_verdict(&format!("rm -rf {root}/build"), "allow");
        }
    }

    #[test]
    fn python_imported_rmtree_preserves_temp_root_boundary() {
        let env = TestEnv::new();
        for (import, function) in [
            ("from shutil import rmtree", "rmtree"),
            ("from shutil import rmtree as wipe", "wipe"),
        ] {
            for root in TEMP_ROOTS {
                for (suffix, expected) in [
                    ("", "deny"),
                    ("//.//", "deny"),
                    ("/build/..", "deny"),
                    ("/build", "allow"),
                    ("/./build/.", "allow"),
                ] {
                    env.assert_python_body(
                        &format!("{import}; {function}('{root}{suffix}')"),
                        expected,
                    );
                }
            }
            for target in [
                "/etc",
                "/tmp/../etc",
                "/private/var/tmp/../../../etc",
                "/tmp/build/../cache",
                "/tmp-backup/build",
            ] {
                env.assert_python_body(&format!("{import}; {function}('{target}')"), "deny");
            }
        }
    }

    #[test]
    fn python_imported_rmtree_handles_grouping_and_complete_targets() {
        let env = TestEnv::new();
        for body in [
            "from shutil import copytree, rmtree as wipe; wipe('/tmp')",
            "from shutil import (copytree, rmtree as wipe); wipe('/private/tmp/.')",
            "from shutil import (\n    copytree,\n    rmtree as wipe,\n)\nwipe('/var/tmp')",
            "from shutil import rmtree as wipe; wipe(path='/private/var/tmp')",
            "from shutil import rmtree as wipe; wipe(('/tmp/.'))",
            "from shutil import rmtree as wipe; wipe('/tmp/build' + '/..')",
            "from shutil import rmtree as wipe; suffix = '/..'; wipe('/tmp/build' + suffix)",
            "from shutil import rmtree as wipe; wipe('/tmp/build'[:-5])",
            "from shutil import rmtree as wipe; import tempfile; wipe(path='/tmp', onerror=lambda *args: tempfile.mkdtemp())",
        ] {
            env.assert_python_body(body, "deny");
        }
        for body in [
            "from shutil import copytree, rmtree as wipe; wipe('/tmp/build')",
            "from shutil import (\n    rmtree as wipe,\n)\nwipe('/private//var/./tmp/build')",
            "from shutil import rmtree as wipe; wipe(path='/var/tmp/build', ignore_errors=True)",
            "from shutil import rmtree as wipe; wipe('/tmp/' + 'build')",
            "from shutil import rmtree as wipe; import tempfile; wipe(tempfile.mkdtemp())",
            "from shutil import rmtree; from tempfile import mkdtemp; rmtree(mkdtemp())",
        ] {
            env.assert_python_body(body, "allow");
        }
        env.assert_verdict(
            "python -I -W ignore::DeprecationWarning -c 'from shutil import rmtree as wipe; wipe(\"/tmp\")'",
            "deny",
        );
        env.assert_verdict(
            "python3 -I <<'PY'\nfrom shutil import rmtree as wipe\nwipe('/tmp/build')\nPY",
            "allow",
        );
    }

    #[test]
    fn python_imported_rmtree_respects_bindings_and_scope() {
        let env = TestEnv::new();
        for body in [
            "from shutil import rmtree as wipe; print('imported for later cleanup')",
            "from project_helpers import rmtree; rmtree('/tmp')",
            "from project_helpers import rmtree as wipe; wipe('/tmp')",
            "def rmtree(path):\n    print(path)\nrmtree('/tmp')",
            "from shutil import rmtree as wipe; wipe = print; wipe('/tmp')",
            "from shutil import rmtree as wipe\ndef wipe(path):\n    print(path)\nwipe('/tmp')",
            "from shutil import rmtree as wipe; from project_helpers import wipe; wipe('/tmp')",
            "from shutil import rmtree as wipe\ndef report(wipe):\n    wipe('/tmp')\nreport(print)",
            "wipe = print\ndef load_cleanup():\n    from shutil import rmtree as wipe\nwipe('/tmp')",
            "wipe = print\n# from shutil import rmtree as wipe\nwipe('/tmp')",
            "wipe = print; example = 'from shutil import rmtree as wipe'; wipe('/tmp')",
        ] {
            env.assert_python_body(body, "allow");
        }
        for body in [
            "def cleanup():\n    from shutil import rmtree as wipe\n    wipe('/tmp')\ncleanup()",
            "from shutil import rmtree as wipe\ndef cleanup():\n    wipe('/tmp')\ncleanup()",
            "import os\nfrom shutil import rmtree as wipe\nif os.getenv('DRY_RUN'):\n    wipe = print\nwipe('/tmp')",
            "import os\nwipe = print\nif os.getenv('CLEANUP'):\n    from shutil import rmtree as wipe\nwipe('/tmp')",
        ] {
            env.assert_python_body(body, "deny");
        }
        env.assert_verdict(
            "cat <<'PY'\nfrom shutil import rmtree as wipe\nwipe('/tmp')\nPY",
            "allow",
        );
    }

    #[test]
    fn python_imported_rmtree_keeps_protection_when_extraction_is_incomplete() {
        // Input-size limits force the fallback deterministically, without
        // relying on scheduler delays, AST timing, or repeated attempts.
        let line_limited = TestEnv::with_heredoc_limit("max_body_lines = 1");
        let byte_limited = TestEnv::with_heredoc_limit("max_body_bytes = 1");
        for root in TEMP_ROOTS {
            let body = format!("from shutil import rmtree as wipe\nwipe('{root}')");
            line_limited.assert_verdict(&format!("python3 - <<'PY'\n{body}\nPY"), "deny");
            byte_limited.assert_python_body(&body, "deny");
        }
    }
}

// ============================================================================
// DCG EXPLAIN Tests
// ============================================================================

mod explain_tests {
    use super::*;

    #[test]
    fn explain_safe_command_returns_allow_pretty() {
        let output = run_dcg(&["explain", "echo hello"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            output.status.success(),
            "explain should succeed for safe command"
        );
        assert!(
            stdout.contains("Decision: ALLOW"),
            "should show ALLOW decision"
        );
        assert!(stdout.contains("DCG EXPLAIN"), "should have pretty header");
    }

    #[test]
    fn explain_dangerous_command_returns_deny_pretty() {
        // Use git command since core.git is always enabled
        let output = run_dcg(&["explain", "git reset --hard"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Note: explain returns success even for deny decisions
        assert!(
            stdout.contains("Decision: DENY"),
            "should show DENY decision"
        );
        assert!(stdout.contains("core.git"), "should mention pack");
    }

    #[test]
    fn explain_json_format_is_valid() {
        // Use git command since core.git is always enabled
        let output = run_dcg(&["explain", "--format", "json", "git reset --hard"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse as JSON to validate structure
        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("explain --format json should produce valid JSON");

        assert_eq!(json["schema_version"], 4, "should have schema_version");
        assert!(json["command"].is_string(), "should have command field");
        assert!(json["decision"].is_string(), "should have decision field");
        assert!(
            json["total_duration_us"].is_number(),
            "should have duration"
        );
        assert!(json["steps"].is_array(), "should have steps array");
        // Schema v4 (#417): the resolved `[policy]` mode and the outcome that
        // collapses it with the evaluator finding. `decision` alone made explain
        // report DENY for a rule configured to warn/ask/log.
        assert!(json["mode"].is_string(), "v4 should carry the policy mode");
        assert!(json["outcome"].is_string(), "v4 should carry the outcome");
        assert_eq!(json["decision"], "deny");
        assert_eq!(json["mode"], "deny");
        assert_eq!(json["outcome"], "deny");
    }

    #[test]
    fn explain_json_includes_suggestions_for_blocked_commands() {
        // Use git command since core.git is always enabled
        let output = run_dcg(&["explain", "--format", "json", "git reset --hard"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();

        assert_eq!(json["decision"], "deny", "should be denied");
        assert!(json["suggestions"].is_array(), "should have suggestions");
        assert!(
            !json["suggestions"].as_array().unwrap().is_empty(),
            "suggestions should not be empty"
        );
    }

    #[test]
    fn explain_compact_format_is_single_line() {
        let output = run_dcg(&["explain", "--format", "compact", "echo hello"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let lines: Vec<&str> = stdout.trim().lines().collect();
        assert_eq!(lines.len(), 1, "compact format should be single line");
        assert!(
            lines[0].contains("allow") || lines[0].contains("ALLOW"),
            "compact line should contain decision"
        );
    }
}

// ============================================================================
// Allow-once management CLI tests
// ============================================================================

mod allow_once_management_tests {
    use super::*;

    use chrono::{DateTime, Utc};
    use destructive_command_guard::logging::{RedactionConfig, RedactionMode};
    use destructive_command_guard::pending_exceptions::{
        AllowOnceEntry, AllowOnceScopeKind, PendingExceptionRecord,
    };

    struct AllowOnceEnv {
        temp: tempfile::TempDir,
        home_dir: std::path::PathBuf,
        xdg_config_dir: std::path::PathBuf,
        pending_path: std::path::PathBuf,
        allow_once_path: std::path::PathBuf,
    }

    impl AllowOnceEnv {
        fn new() -> Self {
            let temp = tempfile::tempdir().expect("tempdir");
            let home_dir = temp.path().join("home");
            let xdg_config_dir = temp.path().join("xdg_config");
            std::fs::create_dir_all(&home_dir).expect("HOME dir");
            std::fs::create_dir_all(&xdg_config_dir).expect("XDG_CONFIG_HOME dir");

            let pending_path = temp.path().join("pending_exceptions.jsonl");
            let allow_once_path = temp.path().join("allow_once.jsonl");

            Self {
                temp,
                home_dir,
                xdg_config_dir,
                pending_path,
                allow_once_path,
            }
        }

        fn write_records(&self, pending: &PendingExceptionRecord, allow_once: &AllowOnceEntry) {
            let pending_line = serde_json::to_string(pending).expect("serialize pending");
            let allow_once_line = serde_json::to_string(allow_once).expect("serialize allow-once");

            std::fs::write(&self.pending_path, format!("{pending_line}\n"))
                .expect("write pending jsonl");
            std::fs::write(&self.allow_once_path, format!("{allow_once_line}\n"))
                .expect("write allow-once jsonl");
        }

        fn run(&self, args: &[&str]) -> std::process::Output {
            Command::new(dcg_binary())
                .env_clear()
                .env("HOME", &self.home_dir)
                .env("USERPROFILE", &self.home_dir)
                .env("XDG_CONFIG_HOME", &self.xdg_config_dir)
                .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
                .env("DCG_PENDING_EXCEPTIONS_PATH", &self.pending_path)
                .env("DCG_ALLOW_ONCE_PATH", &self.allow_once_path)
                .current_dir(self.temp.path())
                .args(args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .expect("run dcg")
        }
    }

    fn active_timestamp() -> DateTime<Utc> {
        // The child validates both ends of the grant's lifetime against its
        // real clock. Future-dated fixtures are intentionally invalid (#610).
        Utc::now()
    }

    const fn redaction_config() -> RedactionConfig {
        RedactionConfig {
            enabled: true,
            mode: RedactionMode::Arguments,
            max_argument_len: 4,
        }
    }

    #[test]
    fn allow_once_list_redacts_by_default_and_show_raw_reveals() {
        let env = AllowOnceEnv::new();
        let now = active_timestamp();
        let redaction = redaction_config();

        let command_raw = r#"echo "0123456789""#;
        let pending = PendingExceptionRecord::new(
            now,
            env.temp.path().to_string_lossy().as_ref(),
            command_raw,
            "test pending",
            &redaction,
            false,
            None,
        );
        let allow_once = AllowOnceEntry::from_pending(
            &pending,
            now,
            AllowOnceScopeKind::Cwd,
            env.temp.path().to_string_lossy().as_ref(),
            false,
            false,
            &redaction,
        );
        env.write_records(&pending, &allow_once);

        let output = env.run(&["allow-once", "list"]);
        assert!(
            output.status.success(),
            "list should succeed: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains(&pending.command_redacted));
        assert!(stdout.contains(&allow_once.command_redacted));
        assert!(
            !stdout.contains("0123456789"),
            "raw secret should not appear"
        );

        let output_raw = env.run(&["allow-once", "list", "--show-raw"]);
        assert!(output_raw.status.success());
        let stdout_raw = String::from_utf8_lossy(&output_raw.stdout);
        assert!(
            stdout_raw.contains("0123456789"),
            "raw secret should appear"
        );
    }

    #[test]
    fn allow_once_revoke_removes_pending_and_active() {
        let env = AllowOnceEnv::new();
        let now = active_timestamp();
        let redaction = redaction_config();

        let command_raw = r#"echo "abcdefghijklmnopqrstuvwxyz""#;
        let pending = PendingExceptionRecord::new(
            now,
            env.temp.path().to_string_lossy().as_ref(),
            command_raw,
            "test revoke",
            &redaction,
            false,
            None,
        );
        let allow_once = AllowOnceEntry::from_pending(
            &pending,
            now,
            AllowOnceScopeKind::Cwd,
            env.temp.path().to_string_lossy().as_ref(),
            false,
            false,
            &redaction,
        );
        env.write_records(&pending, &allow_once);

        let hash_prefix = &pending.full_hash[..8.min(pending.full_hash.len())];
        let output = env.run(&["allow-once", "revoke", hash_prefix, "--yes", "--json"]);
        assert!(
            output.status.success(),
            "revoke should succeed: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("valid JSON output");
        assert_eq!(json["pending"]["removed"], 1);
        assert_eq!(json["allow_once"]["removed"], 1);

        let output_list = env.run(&["allow-once", "list", "--json"]);
        assert!(output_list.status.success());
        let json_list: serde_json::Value =
            serde_json::from_slice(&output_list.stdout).expect("valid JSON output");
        assert_eq!(json_list["pending"]["count"], 0);
        assert_eq!(json_list["allow_once"]["count"], 0);
    }

    #[test]
    fn allow_once_clear_all_wipes_stores() {
        let env = AllowOnceEnv::new();
        let now = active_timestamp();
        let redaction = redaction_config();

        let command_raw = r#"echo "abcdefghijklmnopqrstuvwxyz""#;
        let pending = PendingExceptionRecord::new(
            now,
            env.temp.path().to_string_lossy().as_ref(),
            command_raw,
            "test clear",
            &redaction,
            false,
            None,
        );
        let allow_once = AllowOnceEntry::from_pending(
            &pending,
            now,
            AllowOnceScopeKind::Cwd,
            env.temp.path().to_string_lossy().as_ref(),
            false,
            false,
            &redaction,
        );
        env.write_records(&pending, &allow_once);

        let output = env.run(&["allow-once", "clear", "--all", "--yes", "--json"]);
        assert!(
            output.status.success(),
            "clear should succeed: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("valid JSON output");
        assert_eq!(json["pending"]["wiped"], 1);
        assert_eq!(json["allow_once"]["wiped"], 1);

        let output_list = env.run(&["allow-once", "list", "--json"]);
        assert!(output_list.status.success());
        let json_list: serde_json::Value =
            serde_json::from_slice(&output_list.stdout).expect("valid JSON output");
        assert_eq!(json_list["pending"]["count"], 0);
        assert_eq!(json_list["allow_once"]["count"], 0);
    }
}

// ============================================================================
// Allow-once Full Flow E2E Tests
// ============================================================================

mod allow_once_flow_tests {
    use super::*;
    use destructive_command_guard::pending_exceptions::{
        AllowOnceEntry, AllowOnceScopeKind, PendingExceptionRecord,
    };

    const INLINE_POLICY_REASON: &str = "issue 599 explicit policy";
    const INLINE_SENTINEL: &str = "decision-only sentinel\n";
    const QUOTED_PRINT: &str = "'/usr/bin/python3' -c 'print(1)'";
    const QUOTED_UNLINK: &str =
        "'/usr/bin/python3' -c 'import pathlib; pathlib.Path(\"important.txt\").unlink()'";
    const UNQUOTED_UNLINK: &str =
        "python3 -c 'import pathlib; pathlib.Path(\"important.txt\").unlink()'";

    /// Dedicated test environment with control over all file paths.
    struct FlowTestEnv {
        temp: tempfile::TempDir,
        home_dir: std::path::PathBuf,
        xdg_config_dir: std::path::PathBuf,
        pending_path: std::path::PathBuf,
        allow_once_path: std::path::PathBuf,
        config_path: Option<std::path::PathBuf>,
    }

    impl FlowTestEnv {
        fn new() -> Self {
            Self::with_repository(true)
        }

        fn with_repository(repository: bool) -> Self {
            let temp = tempfile::tempdir().expect("tempdir");
            let home_dir = temp.path().join("home");
            let xdg_config_dir = temp.path().join("xdg_config");
            std::fs::create_dir_all(&home_dir).expect("HOME dir");
            std::fs::create_dir_all(&xdg_config_dir).expect("XDG_CONFIG_HOME dir");
            // Preserve the existing tests' project scope. The inline tests
            // deliberately use a plain directory to exercise exact cwd scope.
            if repository {
                std::fs::create_dir_all(temp.path().join(".git")).expect(".git dir");
            }

            let pending_path = temp.path().join("pending_exceptions.jsonl");
            let allow_once_path = temp.path().join("allow_once.jsonl");

            Self {
                temp,
                home_dir,
                xdg_config_dir,
                pending_path,
                allow_once_path,
                config_path: None,
            }
        }

        fn with_inline_policy() -> Self {
            let mut env = Self::with_repository(false);
            for directory in ["tmp", "xdg_cache", "xdg_state", "xdg_data", "other_cwd"] {
                std::fs::create_dir_all(env.temp.path().join(directory))
                    .expect("isolated inline test directory");
            }
            for filename in ["important.txt", "other.txt"] {
                std::fs::write(env.temp.path().join(filename), INLINE_SENTINEL)
                    .expect("decision-only payload sentinel");
            }
            env.config_path = Some(env.temp.path().join("inline-policy.toml"));
            env.write_inline_policy(None);
            env
        }

        fn write_inline_policy(&self, blocked_command: Option<&str>) {
            let block = blocked_command.map_or_else(String::new, |command| {
                format!(
                    "[overrides]\nblock = [{{ pattern = {:?}, reason = {:?} }}]\n",
                    format!("^{}$", regex::escape(command)),
                    INLINE_POLICY_REASON,
                )
            });
            std::fs::write(
                self.config_path.as_ref().expect("inline policy path"),
                format!(
                    "[general]\ncheck_updates = false\nself_heal_hook = false\n\
                     [packs]\nenabled = [\"core.git\", \"core.filesystem\"]\n\
                     [history]\nenabled = false\n\
                     [heredoc]\nenabled = true\ntimeout_ms = 5000\n\
                     fallback_on_parse_error = false\n{block}"
                ),
            )
            .expect("write isolated inline policy");
        }

        fn inline_command(&self, cwd: &std::path::Path) -> Command {
            let scratch = self.temp.path().join("tmp");
            let mut command = Command::new(dcg_binary());
            command
                .env_clear()
                .env("HOME", &self.home_dir)
                .env("USERPROFILE", &self.home_dir)
                .env("XDG_CONFIG_HOME", &self.xdg_config_dir)
                .env("XDG_CACHE_HOME", self.temp.path().join("xdg_cache"))
                .env("XDG_STATE_HOME", self.temp.path().join("xdg_state"))
                .env("XDG_DATA_HOME", self.temp.path().join("xdg_data"))
                .env("TMPDIR", &scratch)
                .env("TEMP", &scratch)
                .env("TMP", &scratch)
                .env(
                    "DCG_CONFIG",
                    self.config_path.as_ref().expect("inline policy path"),
                )
                .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
                .env("DCG_PENDING_EXCEPTIONS_PATH", &self.pending_path)
                .env("DCG_ALLOW_ONCE_PATH", &self.allow_once_path)
                .env("DCG_NO_SELF_HEAL", "1")
                .env("DCG_SELF_HEAL_HOOK", "0")
                .env("DCG_NO_UPDATE_CHECK", "1")
                .env("DCG_HOOK_TIMEOUT_MS", "5000")
                .env("DCG_DIALECT", "posix")
                .env("NO_COLOR", "1")
                .env("TERM", "dumb")
                .current_dir(cwd)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            command
        }

        /// The candidate is JSON data for DCG. No candidate shell or Python
        /// interpreter is launched by these tests.
        fn run_inline_hook(
            &self,
            tool: &str,
            candidate: &str,
            cwd: &std::path::Path,
        ) -> HookRunOutput {
            let payload = serde_json::json!({
                "tool_name": tool,
                "tool_input": { "command": candidate },
            });
            let mut child = self
                .inline_command(cwd)
                .arg("hook")
                .stdin(Stdio::piped())
                .spawn()
                .expect("spawn inline decision-only hook");
            serde_json::to_writer(child.stdin.take().expect("hook stdin"), &payload)
                .expect("write inert candidate JSON");
            let output = child.wait_with_output().expect("wait for inline hook");
            self.assert_payload_untouched();
            HookRunOutput {
                command: candidate.to_string(),
                output,
            }
        }

        fn run_inline_cli(&self, args: &[&str]) -> std::process::Output {
            let output = self
                .inline_command(self.temp.path())
                .args(args)
                .stdin(Stdio::null())
                .output()
                .expect("run native inline authorization CLI");
            self.assert_payload_untouched();
            output
        }

        fn assert_payload_untouched(&self) {
            for filename in ["important.txt", "other.txt"] {
                assert_eq!(
                    std::fs::read_to_string(self.temp.path().join(filename))
                        .expect("candidate payload must not execute"),
                    INLINE_SENTINEL,
                );
            }
        }

        fn read_grants(&self) -> Vec<AllowOnceEntry> {
            let contents = match std::fs::read_to_string(&self.allow_once_path) {
                Ok(contents) => contents,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
                Err(error) => panic!("read persisted native grants: {error}"),
            };
            contents
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| serde_json::from_str(line).expect("typed native grant"))
                .collect()
        }

        fn redeem_inline_denial(
            &self,
            denial: &serde_json::Value,
            command: &str,
            force: bool,
        ) -> AllowOnceEntry {
            let code = denial["allowOnceCode"]
                .as_str()
                .expect("native denial code");
            let hash = denial["allowOnceFullHash"]
                .as_str()
                .expect("native denial full hash");
            let pending: PendingExceptionRecord = std::fs::read_to_string(&self.pending_path)
                .expect("native pending store")
                .lines()
                .map(|line| {
                    serde_json::from_str::<PendingExceptionRecord>(line).expect("pending JSON")
                })
                .find(|entry| entry.full_hash == hash)
                .expect("native denial persisted its matching pending record");
            assert_eq!(pending.short_code, code);
            assert_eq!(pending.command_raw, command);
            // dcg records the canonical cwd. macOS temp dirs sit under the
            // `/var` -> `/private/var` symlink, so compare canonical forms.
            assert_eq!(
                std::path::Path::new(&pending.cwd),
                self.temp.path().canonicalize().expect("canonical temp dir")
            );
            assert_eq!(pending.source.as_deref() == Some("ConfigOverride"), force);

            let mut args = vec![
                "allow-once",
                code,
                "--yes",
                "--single-use",
                "--json",
                "--show-raw",
                "--hash",
                hash,
            ];
            if force {
                args.push("--force");
            }
            let output = self.run_inline_cli(&args);
            assert!(
                output.status.success(),
                "native redemption failed: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
            let json: serde_json::Value =
                serde_json::from_slice(&output.stdout).expect("native redemption JSON");
            assert_eq!(json["status"], "ok");
            assert_eq!(json["command"], command);
            assert_eq!(json["single_use"], true);
            assert_eq!(json["dry_run"], false);
            assert_eq!(json["force"], force);
            assert_eq!(json["scope_kind"], "cwd");
            let entry = self
                .read_grants()
                .into_iter()
                .rev()
                .find(|entry| entry.source_full_hash == hash && entry.force_allow_config == force)
                .expect("native CLI persisted the exact requested grant");
            assert_eq!(entry.command_raw, command);
            assert_eq!(entry.source_short_code, code);
            assert_eq!(entry.scope_kind, AllowOnceScopeKind::Cwd);
            assert_eq!(
                std::path::Path::new(&entry.scope_path),
                self.temp.path().canonicalize().expect("canonical temp dir")
            );
            assert!(entry.single_use);
            assert!(entry.consumed_at.is_none());
            entry
        }

        fn grant_inline_request(&self, tool: &str, command: &str) -> AllowOnceEntry {
            assert!(self.read_grants().is_empty(), "fresh native grant fixture");
            let denied = self.run_inline_hook(tool, command, self.temp.path());
            let denial = assert_inline_denial(tool, &denied);
            let entry = self.redeem_inline_denial(&denial, command, false);
            assert_eq!(self.read_grants(), std::slice::from_ref(&entry));
            // Only read persisted bytes after redemption: diagnostics also
            // evaluate commands and must not consume the grant under test.
            entry
        }

        /// Run dcg in hook mode with JSON input.
        fn run_hook(&self, command: &str) -> HookRunOutput {
            self.run_hook_with_env(command, &[])
        }

        /// [`Self::run_hook`] with extra environment variables for the child.
        fn run_hook_with_env(&self, command: &str, extra_env: &[(&str, &str)]) -> HookRunOutput {
            let input = serde_json::json!({
                "tool_name": "Bash",
                "tool_input": {
                    "command": command,
                }
            });

            let mut cmd = Command::new(dcg_binary());
            cmd.env_clear()
                .env("HOME", &self.home_dir)
                .env("USERPROFILE", &self.home_dir)
                .env("XDG_CONFIG_HOME", &self.xdg_config_dir)
                .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
                .env("DCG_PACKS", "core.git,core.filesystem")
                .env("DCG_PENDING_EXCEPTIONS_PATH", &self.pending_path)
                .env("DCG_ALLOW_ONCE_PATH", &self.allow_once_path)
                .envs(extra_env.iter().copied())
                .current_dir(self.temp.path())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());

            let mut child = cmd.spawn().expect("failed to spawn dcg hook mode");

            {
                let stdin = child.stdin.as_mut().expect("failed to open stdin");
                serde_json::to_writer(stdin, &input).expect("failed to write hook input JSON");
            }

            let output = child.wait_with_output().expect("failed to wait for dcg");

            HookRunOutput {
                command: command.to_string(),
                output,
            }
        }

        /// Run a dcg CLI command with a non-terminal stdin, the shape an
        /// agent-invoked `dcg allow-once <CODE>` has (#262).
        fn run_cli_without_terminal(&self, args: &[&str]) -> std::process::Output {
            Command::new(dcg_binary())
                .env_clear()
                .env("HOME", &self.home_dir)
                .env("USERPROFILE", &self.home_dir)
                .env("XDG_CONFIG_HOME", &self.xdg_config_dir)
                .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
                .env("DCG_PENDING_EXCEPTIONS_PATH", &self.pending_path)
                .env("DCG_ALLOW_ONCE_PATH", &self.allow_once_path)
                .current_dir(self.temp.path())
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .expect("run dcg cli")
        }

        /// Run dcg CLI commands (not hook mode).
        fn run_cli(&self, args: &[&str]) -> std::process::Output {
            Command::new(dcg_binary())
                .env_clear()
                .env("HOME", &self.home_dir)
                .env("USERPROFILE", &self.home_dir)
                .env("XDG_CONFIG_HOME", &self.xdg_config_dir)
                .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
                .env("DCG_PENDING_EXCEPTIONS_PATH", &self.pending_path)
                .env("DCG_ALLOW_ONCE_PATH", &self.allow_once_path)
                .current_dir(self.temp.path())
                .args(args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .expect("run dcg cli")
        }

        /// Run dcg in hook mode in a different directory (for scoping tests).
        fn run_hook_in_dir(&self, command: &str, cwd: &std::path::Path) -> HookRunOutput {
            let input = serde_json::json!({
                "tool_name": "Bash",
                "tool_input": {
                    "command": command,
                }
            });

            let mut cmd = Command::new(dcg_binary());
            cmd.env_clear()
                .env("HOME", &self.home_dir)
                .env("USERPROFILE", &self.home_dir)
                .env("XDG_CONFIG_HOME", &self.xdg_config_dir)
                .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
                .env("DCG_PACKS", "core.git,core.filesystem")
                .env("DCG_PENDING_EXCEPTIONS_PATH", &self.pending_path)
                .env("DCG_ALLOW_ONCE_PATH", &self.allow_once_path)
                .current_dir(cwd)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());

            let mut child = cmd.spawn().expect("failed to spawn dcg hook mode");

            {
                let stdin = child.stdin.as_mut().expect("failed to open stdin");
                serde_json::to_writer(stdin, &input).expect("failed to write hook input JSON");
            }

            let output = child.wait_with_output().expect("failed to wait for dcg");

            HookRunOutput {
                command: command.to_string(),
                output,
            }
        }
    }

    /// Extract the allow-once code from a hook denial JSON output.
    fn extract_code_from_denial(stdout: &str) -> Option<String> {
        let json: serde_json::Value = serde_json::from_str(stdout.trim()).ok()?;
        json["hookSpecificOutput"]["allowOnceCode"]
            .as_str()
            .map(String::from)
    }

    fn assert_is_denial(result: &HookRunOutput) -> String {
        let stdout = result.stdout_str();

        assert!(
            result.output.status.success(),
            "hook mode should exit successfully\nstdout:\n{}\nstderr:\n{}",
            stdout,
            result.stderr_str()
        );

        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("expected JSON stdout for denial");

        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"],
            "deny",
            "expected permissionDecision=deny\nstdout:\n{}\nstderr:\n{}",
            stdout,
            result.stderr_str()
        );

        stdout
    }

    fn assert_is_allowed(result: &HookRunOutput) {
        let stdout = result.stdout_str();

        assert!(
            result.output.status.success(),
            "hook mode should exit successfully\nstdout:\n{}\nstderr:\n{}",
            stdout,
            result.stderr_str()
        );

        assert!(
            stdout.trim().is_empty(),
            "expected no stdout (allowed) but got:\nstdout:\n{}\nstderr:\n{}",
            stdout,
            result.stderr_str()
        );
    }

    fn assert_inline_denial(tool: &str, result: &HookRunOutput) -> serde_json::Value {
        assert!(
            result.output.status.success(),
            "{tool}: hook failure for {}\n{}\n{}",
            result.command,
            result.stdout_str(),
            result.stderr_str(),
        );
        let json: serde_json::Value = serde_json::from_str(result.stdout_str().trim())
            .unwrap_or_else(|error| panic!("{tool}: expected denial JSON: {error}: {result:?}"));
        if tool == "terminal" {
            assert_eq!(json["decision"], "block", "{}: {json}", result.command);
            assert_eq!(json["action"], "block", "{}: {json}", result.command);
            json
        } else {
            let body = &json["hookSpecificOutput"];
            assert_eq!(
                body["permissionDecision"], "deny",
                "{}: {json}",
                result.command
            );
            body.clone()
        }
    }

    fn assert_inline_policy_denial(tool: &str, result: &HookRunOutput) -> serde_json::Value {
        let denial = assert_inline_denial(tool, result);
        assert!(
            result.stdout_str().contains(INLINE_POLICY_REASON),
            "{tool}: explicit policy must remain the reason: {}",
            result.stdout_str(),
        );
        denial
    }

    fn inline_policy_order_commands() -> Vec<String> {
        let mut commands = Vec::new();
        for source in [
            r#"alias a="'/usr/bin/python3' -c 'print(1)'" b='git status'; a; b"#,
            r#"alias b='git status' a="'/usr/bin/python3' -c 'print(1)'"; b; a"#,
        ] {
            // A harmless backslash in a comment triggers the early lookup;
            // the same alias bodies without it exercise late authorization.
            for suffix in ["", " # \\"] {
                commands.push(format!("{source}{suffix}"));
            }
        }
        commands
    }

    #[test]
    fn inline_interpreter_native_grants_match_original_bytes_and_cwd_issue_599() {
        for tool in ["terminal", "Bash"] {
            for command in [
                QUOTED_PRINT,
                "\"/usr/bin/python3\" -c 'print(1)'",
                QUOTED_UNLINK,
                UNQUOTED_UNLINK,
                "/usr/bin/python3 -c 'import pathlib; pathlib.Path(\"important.txt\").unlink()'",
                "python3 -c 'import pathlib; mask = 1 & 1; pathlib.Path(\"important.txt\").unlink()'",
            ] {
                let env = FlowTestEnv::with_inline_policy();
                let grant = env.grant_inline_request(tool, command);
                let changed_payload = command
                    .replace("print(1)", "print(2)")
                    .replace("important.txt", "other.txt");
                assert_ne!(changed_payload, command);
                for altered in [format!("{command} "), changed_payload] {
                    assert_inline_denial(
                        tool,
                        &env.run_inline_hook(tool, &altered, env.temp.path()),
                    );
                    assert_eq!(
                        env.read_grants(),
                        std::slice::from_ref(&grant),
                        "{tool}: {altered}"
                    );
                }
                assert_inline_denial(
                    tool,
                    &env.run_inline_hook(tool, command, &env.temp.path().join("other_cwd")),
                );
                assert_eq!(env.read_grants(), std::slice::from_ref(&grant));
                assert_is_allowed(&env.run_inline_hook(tool, command, env.temp.path()));
                assert!(
                    env.read_grants().is_empty(),
                    "exact native grant is consumed"
                );
                assert_inline_denial(tool, &env.run_inline_hook(tool, command, env.temp.path()));
                assert!(
                    env.read_grants().is_empty(),
                    "single-use grant cannot be reused"
                );
            }
        }
    }

    #[test]
    fn expired_inline_interpreter_grants_never_authorize_issue_599() {
        for tool in ["terminal", "Bash"] {
            for command in [
                QUOTED_PRINT,
                UNQUOTED_UNLINK,
                r#"alias x="'/usr/bin/python3' -c 'print(1)'"; x"#,
            ] {
                let env = FlowTestEnv::with_inline_policy();
                let mut expired = env.grant_inline_request(tool, command);
                // Move a real native grant's complete, valid lifetime into
                // the past. This tests expiry rather than malformed lifetime
                // rejection, without sleeps or clock races.
                expired.created_at = "2000-01-01T00:00:00Z".to_string();
                expired.expires_at = "2000-01-01T01:00:00Z".to_string();
                std::fs::write(
                    &env.allow_once_path,
                    format!(
                        "{}\n",
                        serde_json::to_string(&expired).expect("expired grant JSON")
                    ),
                )
                .expect("expire native fixture grant");
                for _ in 0..2 {
                    assert_inline_denial(
                        tool,
                        &env.run_inline_hook(tool, command, env.temp.path()),
                    );
                    for remaining in env.read_grants() {
                        assert_eq!(
                            remaining, expired,
                            "an expired grant may be pruned, never spent"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn explicit_inline_policy_denials_preserve_unforced_grants_issue_599() {
        for tool in ["terminal", "Bash"] {
            for command in [QUOTED_PRINT, UNQUOTED_UNLINK] {
                let env = FlowTestEnv::with_inline_policy();
                let grant = env.grant_inline_request(tool, command);
                env.write_inline_policy(Some(command));
                for _ in 0..2 {
                    assert_inline_policy_denial(
                        tool,
                        &env.run_inline_hook(tool, command, env.temp.path()),
                    );
                    assert_eq!(env.read_grants(), std::slice::from_ref(&grant));
                }
                env.write_inline_policy(None);
                assert_is_allowed(&env.run_inline_hook(tool, command, env.temp.path()));
                assert!(env.read_grants().is_empty());
                assert_inline_denial(tool, &env.run_inline_hook(tool, command, env.temp.path()));
            }
        }
    }

    #[test]
    fn nested_inline_requests_cannot_borrow_an_inner_grant_issue_599() {
        for tool in ["terminal", "Bash"] {
            for inner in [QUOTED_UNLINK, UNQUOTED_UNLINK] {
                let env = FlowTestEnv::with_inline_policy();
                let quoted = format!("'{}'", inner.replace('\'', "'\"'\"'"));
                let nested = [
                    format!("sh -c {quoted}"),
                    format!("eval {quoted}"),
                    format!("printf '%s' \"$({inner})\""),
                    format!("{inner}; git reset --hard"),
                ];
                // Pin destructive detection independently of grant handling.
                for command in &nested {
                    assert_inline_denial(
                        tool,
                        &env.run_inline_hook(tool, command, env.temp.path()),
                    );
                    assert!(env.read_grants().is_empty());
                }
                let grant = env.grant_inline_request(tool, inner);
                for command in &nested {
                    assert_inline_denial(
                        tool,
                        &env.run_inline_hook(tool, command, env.temp.path()),
                    );
                    assert_eq!(
                        env.read_grants(),
                        std::slice::from_ref(&grant),
                        "nested request: {command}",
                    );
                }
                assert_is_allowed(&env.run_inline_hook(tool, inner, env.temp.path()));
                assert!(env.read_grants().is_empty());
                assert_inline_denial(tool, &env.run_inline_hook(tool, inner, env.temp.path()));
            }
        }
    }

    #[test]
    fn outer_quoted_interpreter_grants_survive_nested_inspection_issue_599() {
        for tool in ["terminal", "Bash"] {
            for command in [
                r#"alias x="'/usr/bin/python3' -c 'print(1)'"; x"#,
                r#"trap "'/usr/bin/python3' -c 'print(1)'" EXIT"#,
                r#"PROMPT_COMMAND="'/usr/bin/python3' -c 'print(1)'""#,
                "'/usr/bin/python3'${IFS}-c${IFS}'print(1)'",
            ] {
                let env = FlowTestEnv::with_inline_policy();
                let grant = env.grant_inline_request(tool, command);
                let altered = format!("{command} ");
                assert_inline_denial(tool, &env.run_inline_hook(tool, &altered, env.temp.path()));
                assert_eq!(
                    env.read_grants(),
                    std::slice::from_ref(&grant),
                    "changed outer bytes: {altered}",
                );
                assert_is_allowed(&env.run_inline_hook(tool, command, env.temp.path()));
                assert!(env.read_grants().is_empty());
                assert_inline_denial(tool, &env.run_inline_hook(tool, command, env.temp.path()));
            }
        }
    }

    #[test]
    fn nested_policy_denials_preserve_outer_inline_grants_issue_599() {
        for tool in ["terminal", "Bash"] {
            for command in [
                r#"alias x="'/usr/bin/python3' -c 'print(1)'"; x"#,
                r#"trap "'/usr/bin/python3' -c 'print(1)'" EXIT"#,
            ] {
                let env = FlowTestEnv::with_inline_policy();
                let grant = env.grant_inline_request(tool, command);
                env.write_inline_policy(Some(QUOTED_PRINT));
                assert_inline_policy_denial(
                    tool,
                    &env.run_inline_hook(tool, command, env.temp.path()),
                );
                assert_eq!(env.read_grants(), std::slice::from_ref(&grant));
                env.write_inline_policy(None);
                assert_is_allowed(&env.run_inline_hook(tool, command, env.temp.path()));
                assert!(env.read_grants().is_empty());
                assert_inline_denial(tool, &env.run_inline_hook(tool, command, env.temp.path()));
            }
        }
    }

    #[test]
    fn nested_policy_order_preserves_ordinary_inline_grants_issue_599() {
        for tool in ["terminal", "Bash"] {
            for command in inline_policy_order_commands() {
                let env = FlowTestEnv::with_inline_policy();
                let grant = env.grant_inline_request(tool, &command);
                env.write_inline_policy(Some("git status"));
                assert_inline_policy_denial(
                    tool,
                    &env.run_inline_hook(tool, &command, env.temp.path()),
                );
                assert_eq!(env.read_grants(), std::slice::from_ref(&grant));
                // Keep a configured block so successful authorization must
                // finish policy inspection rather than take the no-block path.
                env.write_inline_policy(Some("git diff"));
                assert_is_allowed(&env.run_inline_hook(tool, &command, env.temp.path()));
                assert!(env.read_grants().is_empty());
                assert_inline_denial(tool, &env.run_inline_hook(tool, &command, env.temp.path()));
            }
        }
    }

    #[test]
    fn opaque_quoted_python_sources_preserve_nested_policy_issue_599() {
        // Neither argv list contains a contiguous shell command or another
        // incidental heredoc trigger. Policy inspection must enter the
        // interpreter's source to find the later explicitly blocked command.
        let source = r#"import subprocess; subprocess.run(["git", "reset", "--hard"]); subprocess.run(["git", "status"])"#;
        for tool in ["terminal", "Bash"] {
            for interpreter in [
                "'/usr/bin/python3'",
                "\"/usr/bin/python3\"",
                "/usr/bin/python3",
            ] {
                let child = format!("{interpreter} -c '{source}'");
                let alias = format!("alias p='{}'; p", child.replace('\'', "'\"'\"'"));
                for command in [child, alias] {
                    let env = FlowTestEnv::with_inline_policy();
                    let grant = env.grant_inline_request(tool, &command);
                    env.write_inline_policy(Some("git status"));
                    assert_inline_policy_denial(
                        tool,
                        &env.run_inline_hook(tool, &command, env.temp.path()),
                    );
                    assert_eq!(
                        env.read_grants(),
                        std::slice::from_ref(&grant),
                        "{tool}: a block inside the interpreter must retain the exact grant: {command}",
                    );

                    // A completed inspection with unrelated policy can still
                    // honor the retained native grant, but only once.
                    env.write_inline_policy(Some("git diff"));
                    assert_is_allowed(&env.run_inline_hook(tool, &command, env.temp.path()));
                    assert!(env.read_grants().is_empty());
                    assert_inline_denial(
                        tool,
                        &env.run_inline_hook(tool, &command, env.temp.path()),
                    );
                    assert!(env.read_grants().is_empty());
                }
            }
        }
    }

    #[test]
    fn unread_python_sources_cannot_clear_policy_with_a_decoy_issue_599() {
        let payload = r#"import subprocess; subprocess.run(["git", "reset", "--hard"]); subprocess.run(["git", "status"])"#;
        for tool in ["terminal", "Bash"] {
            // Internal name quoting is still an unresolved source. A known
            // harmless body elsewhere cannot prove this body's policy clear.
            let opaque = format!(r#"/usr/bin/py"thon3" -c '{payload}'"#);
            let decoy_before = format!("python3 -c 'print(1)'; {opaque}");
            let decoy_after = format!("{opaque}; python3 -c 'print(1)'");
            for source in [opaque, decoy_before, decoy_after] {
                let alias = format!("alias p='{}'; p", source.replace('\'', "'\"'\"'"));
                for command in [source, alias] {
                    let env = FlowTestEnv::with_inline_policy();
                    let grant = env.grant_inline_request(tool, &command);
                    for blocked_child in ["git status", "git diff"] {
                        env.write_inline_policy(Some(blocked_child));
                        assert_inline_denial(
                            tool,
                            &env.run_inline_hook(tool, &command, env.temp.path()),
                        );
                        assert_eq!(
                            env.read_grants(),
                            std::slice::from_ref(&grant),
                            "{tool}: unread source cannot clear {blocked_child:?}: {command}",
                        );
                    }

                    // Without a policy block to inspect, the exact reviewed
                    // outer request remains eligible for one authorization.
                    env.write_inline_policy(None);
                    assert_is_allowed(&env.run_inline_hook(tool, &command, env.temp.path()));
                    assert!(env.read_grants().is_empty());
                    assert_inline_denial(
                        tool,
                        &env.run_inline_hook(tool, &command, env.temp.path()),
                    );
                    assert!(env.read_grants().is_empty());
                }
            }
        }
    }

    #[test]
    fn forced_nested_policy_grants_skip_retained_ordinary_grants_issue_599() {
        for tool in ["terminal", "Bash"] {
            for command in inline_policy_order_commands() {
                let env = FlowTestEnv::with_inline_policy();
                let ordinary = env.grant_inline_request(tool, &command);
                env.write_inline_policy(Some("git status"));
                let denied = env.run_inline_hook(tool, &command, env.temp.path());
                let denial = assert_inline_policy_denial(tool, &denied);
                assert_eq!(env.read_grants(), std::slice::from_ref(&ordinary));
                let code = denial["allowOnceCode"]
                    .as_str()
                    .expect("policy denial code");
                let refused = env.run_inline_cli(&["allow-once", code, "--yes", "--json"]);
                assert!(
                    !refused.status.success(),
                    "explicit policy requires native --force"
                );
                assert!(String::from_utf8_lossy(&refused.stderr).contains("--force"));
                assert_eq!(env.read_grants(), std::slice::from_ref(&ordinary));
                let forced = env.redeem_inline_denial(&denial, &command, true);
                let both = vec![ordinary.clone(), forced];
                assert_eq!(env.read_grants(), both);

                let altered = format!("{command} ");
                assert_inline_denial(tool, &env.run_inline_hook(tool, &altered, env.temp.path()));
                assert_eq!(env.read_grants(), both);
                // Neither grant applies in another cwd. An earlier detector
                // may own the denial; both stored grants must stay untouched.
                assert_inline_denial(
                    tool,
                    &env.run_inline_hook(tool, &command, &env.temp.path().join("other_cwd")),
                );
                assert_eq!(env.read_grants(), both);
                assert_is_allowed(&env.run_inline_hook(tool, &command, env.temp.path()));
                assert_eq!(
                    env.read_grants(),
                    std::slice::from_ref(&ordinary),
                    "only the later forced grant may override the nested policy",
                );
                assert_inline_policy_denial(
                    tool,
                    &env.run_inline_hook(tool, &command, env.temp.path()),
                );
                assert_eq!(env.read_grants(), std::slice::from_ref(&ordinary));
                env.write_inline_policy(None);
                assert_is_allowed(&env.run_inline_hook(tool, &command, env.temp.path()));
                assert!(
                    env.read_grants().is_empty(),
                    "ordinary grant remains usable once"
                );
                assert_inline_denial(tool, &env.run_inline_hook(tool, &command, env.temp.path()));
            }
        }
    }

    #[test]
    fn incomplete_nested_policy_inspection_preserves_inline_grants_issue_599() {
        for tool in ["terminal", "Bash"] {
            for command in [
                "bash -c 'rm -rf /; git status'",
                "bash -c 'true'; bash -c 'rm -rf /; git status'",
            ] {
                let env = FlowTestEnv::with_inline_policy();
                let grant = env.grant_inline_request(tool, command);
                env.write_inline_policy(Some("git status"));
                let config_path = env.config_path.as_ref().expect("inline policy path");
                let mut policy: toml::Value = toml::from_str(
                    &std::fs::read_to_string(config_path).expect("read inline policy"),
                )
                .expect("parse inline policy");
                let heredoc = policy["heredoc"].as_table_mut().expect("heredoc settings");
                // The first source is skipped; the second retains the small
                // `true` body but leaves its destructive sibling unread.
                heredoc.insert("max_body_bytes".to_string(), toml::Value::Integer(8));
                // Strict extraction failure already denies. Enable the
                // fallback so waiving its finding cannot hide unread policy.
                heredoc.insert(
                    "fallback_on_parse_error".to_string(),
                    toml::Value::Boolean(true),
                );
                std::fs::write(
                    config_path,
                    toml::to_string(&policy).expect("serialize limited policy"),
                )
                .expect("write limited policy");
                assert_inline_denial(tool, &env.run_inline_hook(tool, command, env.temp.path()));
                assert_eq!(
                    env.read_grants(),
                    std::slice::from_ref(&grant),
                    "{tool}: incomplete policy inspection must preserve the grant: {command}",
                );
                // Restore only the size limit. With the full body readable,
                // the explicit child policy must be the reason for denial.
                assert_eq!(
                    policy["heredoc"]
                        .as_table_mut()
                        .expect("heredoc settings")
                        .remove("max_body_bytes"),
                    Some(toml::Value::Integer(8)),
                );
                std::fs::write(
                    config_path,
                    toml::to_string(&policy).expect("serialize complete policy"),
                )
                .expect("restore complete policy inspection");
                assert_inline_policy_denial(
                    tool,
                    &env.run_inline_hook(tool, command, env.temp.path()),
                );
                assert_eq!(env.read_grants(), std::slice::from_ref(&grant));
                // An unrelated block still requires policy replay, which
                // can now finish and spend the retained grant exactly once.
                env.write_inline_policy(Some("git diff"));
                assert_is_allowed(&env.run_inline_hook(tool, command, env.temp.path()));
                assert!(env.read_grants().is_empty());
                assert_inline_denial(tool, &env.run_inline_hook(tool, command, env.temp.path()));
            }
        }
    }

    #[test]
    fn nested_inline_policy_denials_require_explicit_force_issue_599() {
        for tool in ["terminal", "Bash"] {
            for command in [
                QUOTED_PRINT,
                r#"alias x="'/usr/bin/python3' -c 'print(1)'"; x"#,
                r#"trap "'/usr/bin/python3' -c 'print(1)'" EXIT"#,
            ] {
                let env = FlowTestEnv::with_inline_policy();
                env.write_inline_policy(Some(QUOTED_PRINT));
                let denied = env.run_inline_hook(tool, command, env.temp.path());
                let denial = assert_inline_policy_denial(tool, &denied);
                let code = denial["allowOnceCode"]
                    .as_str()
                    .expect("native policy code");
                let refused = env.run_inline_cli(&["allow-once", code, "--yes", "--json"]);
                assert!(!refused.status.success());
                assert!(String::from_utf8_lossy(&refused.stderr).contains("--force"));
                assert!(env.read_grants().is_empty());
                let forced = env.redeem_inline_denial(&denial, command, true);
                assert_inline_denial(
                    tool,
                    &env.run_inline_hook(tool, &format!("{command} "), env.temp.path()),
                );
                assert_eq!(env.read_grants(), std::slice::from_ref(&forced));
                assert_inline_policy_denial(
                    tool,
                    &env.run_inline_hook(tool, command, &env.temp.path().join("other_cwd")),
                );
                assert_eq!(env.read_grants(), std::slice::from_ref(&forced));
                assert_is_allowed(&env.run_inline_hook(tool, command, env.temp.path()));
                assert!(env.read_grants().is_empty());
                assert_inline_policy_denial(
                    tool,
                    &env.run_inline_hook(tool, command, env.temp.path()),
                );
            }
        }
    }

    #[test]
    fn inline_authorization_keeps_safe_and_destructive_controls_issue_599() {
        for tool in ["terminal", "Bash"] {
            let env = FlowTestEnv::with_inline_policy();
            for command in [
                "python3 -c 'print(1)'",
                "/usr/bin/python3 -c 'print(1)'",
                "python3 -c 'print(1 & 1)'",
                "git status",
            ] {
                assert_is_allowed(&env.run_inline_hook(tool, command, env.temp.path()));
                assert!(env.read_grants().is_empty());
            }
            for command in [
                "git reset --hard",
                QUOTED_PRINT,
                QUOTED_UNLINK,
                UNQUOTED_UNLINK,
            ] {
                assert_inline_denial(tool, &env.run_inline_hook(tool, command, env.temp.path()));
                assert!(env.read_grants().is_empty());
            }
        }
    }

    #[test]
    fn block_emits_code_and_allow_once_allows() {
        let env = FlowTestEnv::new();
        let command = "git reset --hard";

        // Step 1: Run blocked command in hook mode, verify it's denied with a code
        let result1 = env.run_hook(command);
        let stdout1 = assert_is_denial(&result1);

        let code = extract_code_from_denial(&stdout1)
            .expect("blocked command should emit allow-once code");
        assert!(
            code.len() >= 4,
            "code should be at least 4 chars, got: {code}"
        );

        // Step 2: Use dcg allow-once <code> --yes to activate the exception
        let allow_output = env.run_cli(&["allow-once", &code, "--yes"]);
        assert!(
            allow_output.status.success(),
            "allow-once should succeed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&allow_output.stdout),
            String::from_utf8_lossy(&allow_output.stderr)
        );

        // Step 3: Re-run the same command, should now be allowed
        let result2 = env.run_hook(command);
        assert_is_allowed(&result2);

        // Step 4: the grant was single-use (the default since #378), so the
        // same command is denied again.
        let result3 = env.run_hook(command);
        assert_is_denial(&result3);
    }

    /// With `general.log_file` set, the allow-once lifecycle is audited: the
    /// code issued at the block, the redemption that lifts it, and the grant
    /// when the command then runs. Every production caller used to pass no
    /// audit config, so only `clear`/`revoke` were ever written — the
    /// redemption, the step that actually lifts a block, went unrecorded.
    #[test]
    fn allow_once_lifecycle_is_written_to_the_audit_log() {
        let env = FlowTestEnv::new();
        let log_path = env.temp.path().join("dcg-audit.log");
        let config = format!("[general]\nlog_file = {:?}\n", log_path.to_string_lossy());
        // The user config under both spellings the platforms resolve.
        for dir in [
            env.xdg_config_dir.join("dcg"),
            env.home_dir.join(".config").join("dcg"),
        ] {
            std::fs::create_dir_all(&dir).expect("config dir");
            std::fs::write(dir.join("config.toml"), &config).expect("write config");
        }
        let command = "git reset --hard";

        let denied = env.run_hook(command);
        let code = extract_code_from_denial(&assert_is_denial(&denied))
            .expect("blocked command should emit allow-once code");
        let allow_output = env.run_cli(&["allow-once", &code, "--yes"]);
        assert!(
            allow_output.status.success(),
            "allow-once should succeed: {}",
            String::from_utf8_lossy(&allow_output.stderr)
        );
        assert_is_allowed(&env.run_hook(command));

        let log = std::fs::read_to_string(&log_path).unwrap_or_default();
        for event in ["code_issued", "code_resolved", "allow_granted"] {
            assert!(log.contains(event), "audit log is missing {event}:\n{log}");
        }
    }

    /// `[logging] enabled = true` writes one structured line per hook decision.
    /// The section was parsed, validated and exported in the schema, and
    /// `DecisionLogger` was implemented and unit-tested, but nothing ever
    /// constructed it: the file stayed empty whatever the config said.
    #[test]
    fn logging_section_records_hook_decisions() {
        let env = FlowTestEnv::new();
        let log_path = env.temp.path().join("decisions.jsonl");
        let config = format!(
            "[logging]\nenabled = true\nfile = {:?}\nformat = \"json\"\n\
             [logging.events]\ndeny = true\nallow = true\n",
            log_path.to_string_lossy()
        );
        for dir in [
            env.xdg_config_dir.join("dcg"),
            env.home_dir.join(".config").join("dcg"),
        ] {
            std::fs::create_dir_all(&dir).expect("config dir");
            std::fs::write(dir.join("config.toml"), &config).expect("write config");
        }

        assert_is_denial(&env.run_hook("git reset --hard"));
        assert_is_allowed(&env.run_hook("git status"));

        let log = std::fs::read_to_string(&log_path).unwrap_or_default();
        let entries: Vec<serde_json::Value> = log
            .lines()
            .map(|line| serde_json::from_str(line).expect("json log line"))
            .collect();
        assert_eq!(entries.len(), 2, "one line per decision:\n{log}");
        assert_eq!(entries[0]["decision"], "deny");
        assert_eq!(entries[0]["rule_id"], "core.git:reset-hard");
        assert_eq!(entries[1]["decision"], "allow");
        assert_eq!(entries[1]["mode"], "allow");
    }

    /// Issue #585: inspect the complete persisted record, not just `command`.
    /// Candidate pipelines are evaluated by the hook and are never executed.
    #[test]
    fn full_logging_redaction_suppresses_diagnostics_issue_585() {
        const MARKER: &str = "DCG_SYNTHETIC_PRIVATE_ARGUMENT_9b4e";
        for format in ["json", "text"] {
            for mode in ["deny", "warn"] {
                let env = FlowTestEnv::new();
                let log_path = env.temp.path().join("decisions.log");
                let audit_path = env.temp.path().join("audit.log");
                let config_path = env.temp.path().join("config.toml");
                let config = format!(
                    "[general]\nlog_file = {:?}\n\
                     [history]\nenabled = false\n\
                     [packs]\nenabled = [\"windows\"]\n\
                     [policy.rules]\n\"core.git:reset-hard\" = {mode:?}\n\
                     [logging]\nenabled = true\nfile = {:?}\nformat = {format:?}\n\
                     caller_env = \"DCG_TEST_CALLER\"\n\
                     [logging.redaction]\nenabled = true\nmode = \"full\"\n\
                     [logging.events]\ndeny = true\nwarn = true\nallow = true\n",
                    audit_path.to_string_lossy(),
                    log_path.to_string_lossy(),
                );
                std::fs::write(&config_path, &config).expect("write config");
                // Redemption runs through the CLI, which must load the same
                // redaction policy as the hook under both platform spellings.
                for dir in [
                    env.xdg_config_dir.join("dcg"),
                    env.home_dir.join(".config").join("dcg"),
                ] {
                    std::fs::create_dir_all(&dir).expect("config dir");
                    std::fs::write(dir.join("config.toml"), &config).expect("write config");
                }
                let config_str = config_path.to_str().expect("config path");
                let extra_env = [
                    ("DCG_CONFIG", config_str),
                    ("DCG_TEST_CALLER", MARKER),
                    ("DCG_PACKS", "core.git,core.filesystem,windows"),
                    ("DCG_SELF_HEAL_HOOK", "0"),
                    ("DCG_HOOK_TIMEOUT_MS", "10000"),
                ];
                let pipeline = format!("{MARKER} | python -");
                let pipeline_result = env.run_hook_with_env(&pipeline, &extra_env);
                // Unverified embedded execution remains denied even when the
                // ordinary git rule is configured to warn.
                assert_is_denial(&pipeline_result);
                let git_result =
                    env.run_hook_with_env(&format!("git reset --hard {MARKER}"), &extra_env);
                if mode == "deny" {
                    assert_is_denial(&git_result);
                } else {
                    assert_is_allowed(&git_result);
                    assert!(!git_result.stderr_str().is_empty(), "warning retained");
                }
                assert_is_allowed(
                    &env.run_hook_with_env(&format!("git status -- {MARKER}"), &extra_env),
                );

                let log = std::fs::read_to_string(&log_path).expect("decision log");
                assert_eq!(log.lines().count(), 3, "{log}");
                assert!(
                    !log.to_lowercase().contains(&MARKER.to_lowercase()),
                    "{log}"
                );
                assert!(log.contains("core.git:reset-hard"), "stable rule ID: {log}");
                if format == "json" {
                    let records: Vec<serde_json::Value> = log
                        .lines()
                        .map(|line| serde_json::from_str(line).expect("JSON record"))
                        .collect();
                    assert_eq!(records[0]["decision"], "deny");
                    assert_eq!(records[1]["decision"], mode);
                    assert_eq!(records[2]["decision"], "allow");
                    assert_eq!(records[0]["command"], "[REDACTED]");
                    assert_eq!(records[0]["reason"], "Diagnostic details redacted.");
                } else {
                    assert!(log.lines().next().unwrap().contains("DENY"));
                    assert!(log.lines().nth(1).unwrap().contains(&mode.to_uppercase()));
                    assert!(log.lines().nth(2).unwrap().contains("ALLOW"));
                }
                if mode == "deny" {
                    let code = extract_code_from_denial(&git_result.stdout_str())
                        .expect("allow-once code");
                    let granted = env.run_cli(&["allow-once", &code, "--yes"]);
                    assert!(granted.status.success(), "{granted:?}");
                    assert_is_allowed(
                        &env.run_hook_with_env(&format!("git reset --hard {MARKER}"), &extra_env),
                    );
                    let log = std::fs::read_to_string(&log_path).expect("decision log after grant");
                    assert!(
                        !log.to_lowercase().contains(&MARKER.to_lowercase()),
                        "{log}"
                    );
                }
                let audit = std::fs::read_to_string(&audit_path).expect("allow-once audit");
                assert!(audit.contains("code_issued"), "{audit}");
                if mode == "deny" {
                    for event in ["code_resolved", "allow_granted"] {
                        assert!(audit.contains(event), "{audit}");
                    }
                }
                assert!(
                    !audit.to_lowercase().contains(&MARKER.to_lowercase()),
                    "{audit}"
                );
            }
        }
    }

    /// `[logging] caller_env` attributes each record to a caller the built-in
    /// agent detection does not know (#378), sanitized to a single line.
    #[test]
    fn logging_records_the_configured_caller_issue_378() {
        let env = FlowTestEnv::new();
        let log_path = env.temp.path().join("decisions.jsonl");
        let config = format!(
            "[logging]\nenabled = true\nfile = {:?}\nformat = \"json\"\n\
             caller_env = \"DCG_TEST_CALLER\"\n[logging.events]\ndeny = true\n",
            log_path.to_string_lossy()
        );
        for dir in [
            env.xdg_config_dir.join("dcg"),
            env.home_dir.join(".config").join("dcg"),
        ] {
            std::fs::create_dir_all(&dir).expect("config dir");
            std::fs::write(dir.join("config.toml"), &config).expect("write config");
        }

        assert_is_denial(&env.run_hook_with_env(
            "git reset --hard",
            &[("DCG_TEST_CALLER", "agent-7\nforged")],
        ));
        assert_is_denial(&env.run_hook("git reset --hard"));

        let log = std::fs::read_to_string(&log_path).unwrap_or_default();
        let entries: Vec<serde_json::Value> = log
            .lines()
            .map(|line| serde_json::from_str(line).expect("json log line"))
            .collect();
        assert_eq!(entries.len(), 2, "{log}");
        assert_eq!(entries[0]["caller"], "agent-7forged", "{log}");
        assert!(
            entries[1].get("caller").is_none(),
            "unset variable, no label: {log}"
        );
    }

    /// Exercise the actual single-payload hook and its persisted structured
    /// log. Candidate commands are JSON input to dcg; they are never executed.
    fn run_structured_logging_hook(
        command: &str,
        format: &str,
        redaction: &str,
        policy_mode: &str,
        caller: &str,
    ) -> (HookRunOutput, String) {
        let env = FlowTestEnv::new();
        let config_path = env.temp.path().join("config.toml");
        let log_path = env.temp.path().join("decisions.log");
        let temp_path = env.temp.path().join("tmp");
        std::fs::create_dir_all(&temp_path).expect("isolated temporary directory");
        std::fs::write(
            &config_path,
            format!(
                "[packs]\nenabled = [\"windows\"]\n\
                 [history]\nenabled = false\n\
                 [logging]\nenabled = true\nfile = {:?}\nformat = \"{format}\"\n\
                 caller_env = \"DCG_TEST_CALLER\"\n\
                 [logging.redaction]\n{redaction}\n\
                 [logging.events]\ndeny = true\nwarn = true\nallow = true\n\
                 [policy.rules]\n\"heredoc.posix:pipeline-consumer\" = \"{policy_mode}\"\n",
                log_path.to_string_lossy()
            ),
        )
        .expect("write isolated structured logging config");
        let payload = serde_json::json!({
            "turn_id": "synthetic-redaction-repro",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": command },
        });
        let mut child = Command::new(dcg_binary())
            .arg("hook")
            .env_clear()
            .env("HOME", &env.home_dir)
            .env("USERPROFILE", &env.home_dir)
            .env("XDG_CONFIG_HOME", &env.xdg_config_dir)
            .env("TMPDIR", &temp_path)
            .env("TEMP", &temp_path)
            .env("TMP", &temp_path)
            .env("DCG_CONFIG", &config_path)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env("DCG_PENDING_EXCEPTIONS_PATH", &env.pending_path)
            .env("DCG_ALLOW_ONCE_PATH", &env.allow_once_path)
            .env("DCG_SELF_HEAL_HOOK", "0")
            .env("DCG_HOOK_TIMEOUT_MS", "5000")
            .env("DCG_DIALECT", "posix")
            .env("DCG_TEST_CALLER", caller)
            .env("NO_COLOR", "1")
            .env("TERM", "dumb")
            .current_dir(env.temp.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn structured logging hook");
        serde_json::to_writer(child.stdin.take().expect("hook stdin"), &payload)
            .expect("write synthetic hook payload");
        let output = child.wait_with_output().expect("wait for logging hook");
        let log = std::fs::read_to_string(&log_path).unwrap_or_else(|error| {
            panic!(
                "read structured log: {error}; stdout: {}; stderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        (
            HookRunOutput {
                command: command.to_string(),
                output,
            },
            log,
        )
    }

    #[test]
    fn logging_full_redaction_covers_entire_records_and_preserves_decisions_issue_585() {
        const MARKER: &str = "DCG_SYNTHETIC_PRIVATE_ARGUMENT_9b4e";
        let pipeline = format!("{MARKER} | python -");
        let allowed = format!("echo {MARKER}");
        for format in ["json", "text"] {
            for (command, policy_mode, decision) in [
                (pipeline.as_str(), "deny", "deny"),
                (pipeline.as_str(), "warn", "warn"),
                (allowed.as_str(), "deny", "allow"),
            ] {
                let (result, log) = run_structured_logging_hook(
                    command,
                    format,
                    "enabled = true\nmode = \"full\"",
                    policy_mode,
                    MARKER,
                );
                match decision {
                    "deny" => {
                        let stdout = assert_is_denial(&result);
                        assert!(
                            stdout
                                .to_ascii_lowercase()
                                .contains(&MARKER.to_ascii_lowercase()),
                            "log redaction must not remove the live hook's actionable diagnostic: {stdout}"
                        );
                    }
                    "warn" => {
                        assert_is_allowed(&result);
                        assert!(result.stderr_str().contains("WARNING"));
                    }
                    _ => assert_is_allowed(&result),
                }
                assert_eq!(log.lines().count(), 1, "one record per decision: {log}");
                assert!(
                    !log.to_ascii_lowercase()
                        .contains(&MARKER.to_ascii_lowercase()),
                    "full redaction leaked into the complete {format} {decision} record: {log}"
                );
                if format == "json" {
                    let entry: serde_json::Value =
                        serde_json::from_str(log.trim()).expect("JSON log record");
                    assert_eq!(entry["command"], "[REDACTED]", "{log}");
                    assert_eq!(entry["decision"], decision, "{log}");
                    assert_eq!(entry["mode"], decision, "{log}");
                    if let Some(normalized) = entry.get("normalized_command") {
                        assert_eq!(normalized, "[REDACTED]", "{log}");
                    }
                    if decision != "allow" {
                        assert_eq!(entry["rule_id"], "heredoc.posix:pipeline-consumer", "{log}");
                        assert_eq!(entry["pack_id"], "heredoc.posix", "{log}");
                        assert_eq!(entry["pattern_name"], "pipeline-consumer", "{log}");
                        assert!(
                            entry["reason"].as_str().is_some_and(|r| !r.is_empty()),
                            "{log}"
                        );
                    }
                } else {
                    assert!(
                        log.contains(&format!(" {} ", decision.to_ascii_uppercase())),
                        "{log}"
                    );
                    assert!(log.contains("\"[REDACTED]\""), "{log}");
                    if decision != "allow" {
                        assert!(log.contains("heredoc.posix:pipeline-consumer"), "{log}");
                    }
                }
            }
        }
    }

    #[test]
    fn logging_without_redaction_preserves_dynamic_diagnostics_issue_585() {
        const MARKER: &str = "DCG_SYNTHETIC_PRIVATE_ARGUMENT_9b4e";
        for format in ["json", "text"] {
            for redaction in [
                "enabled = false\nmode = \"full\"",
                "enabled = true\nmode = \"none\"",
            ] {
                let command = format!("{MARKER} | python -");
                let (result, log) =
                    run_structured_logging_hook(&command, format, redaction, "deny", "agent-7");
                assert_is_denial(&result);
                assert_eq!(log.lines().count(), 1, "{log}");
                // A positive control for the reported secondary leak: the
                // diagnostic contains the lowercased executable, independently
                // of the original command's spelling.
                let reason = if format == "json" {
                    let entry: serde_json::Value =
                        serde_json::from_str(log.trim()).expect("JSON log record");
                    assert_eq!(entry["command"], command, "{log}");
                    assert_eq!(entry["decision"], "deny", "{log}");
                    assert_eq!(entry["caller"], "agent-7", "{log}");
                    entry["reason"]
                        .as_str()
                        .expect("diagnostic reason")
                        .to_string()
                } else {
                    assert!(log.contains(&command), "{log}");
                    log.split_once(" -- ")
                        .expect("text diagnostic reason")
                        .1
                        .to_string()
                };
                assert!(reason.contains(&MARKER.to_ascii_lowercase()), "{reason}");
            }
        }
    }

    #[test]
    fn logging_full_redaction_covers_allow_once_audit_lifecycle_issue_585() {
        const MARKER: &str = "DCG_SYNTHETIC_PRIVATE_ARGUMENT_9b4e";
        for format in ["json", "text"] {
            let env = FlowTestEnv::new();
            let log_path = env.temp.path().join("dcg-audit.log");
            let config = format!(
                "[general]\nlog_file = {:?}\n\
                 [history]\nenabled = false\n\
                 [logging]\nformat = \"{format}\"\n\
                 [logging.redaction]\nenabled = true\nmode = \"full\"\n",
                log_path.to_string_lossy()
            );
            for dir in [
                env.xdg_config_dir.join("dcg"),
                env.home_dir.join(".config").join("dcg"),
            ] {
                std::fs::create_dir_all(&dir).expect("isolated config directory");
                std::fs::write(dir.join("config.toml"), &config).expect("write audit config");
            }
            let temp_path = env.temp.path().join("tmp");
            std::fs::create_dir_all(&temp_path).expect("isolated temporary directory");
            let temp_string = temp_path.to_string_lossy();
            let extra_env = [
                ("DCG_SELF_HEAL_HOOK", "0"),
                ("DCG_HOOK_TIMEOUT_MS", "5000"),
                ("DCG_DIALECT", "posix"),
                ("TMPDIR", temp_string.as_ref()),
                ("TEMP", temp_string.as_ref()),
                ("TMP", temp_string.as_ref()),
            ];
            let command = format!("{MARKER} | python -");
            let denial = assert_is_denial(&env.run_hook_with_env(&command, &extra_env));
            let code = extract_code_from_denial(&denial).expect("denial carries allow-once code");
            let redemption = env.run_cli(&["allow-once", &code, "--yes"]);
            assert!(
                redemption.status.success(),
                "allow-once redemption failed: {}",
                String::from_utf8_lossy(&redemption.stderr)
            );
            assert_is_allowed(&env.run_hook_with_env(&command, &extra_env));
            // Redacting audit data must not change single-use enforcement.
            let second_denial = assert_is_denial(&env.run_hook_with_env(&command, &extra_env));
            let second_code = extract_code_from_denial(&second_denial)
                .expect("a fresh denial carries a revocable code");

            let log = std::fs::read_to_string(&log_path).expect("read allow-once audit log");
            assert!(
                !log.to_ascii_lowercase()
                    .contains(&MARKER.to_ascii_lowercase()),
                "full redaction leaked into the complete {format} audit log: {log}"
            );
            // The general log also carries legacy text diagnostics for both
            // denials, even when allow-once events use JSON. Check those bytes
            // as well as the structured lifecycle records.
            assert_eq!(log.matches("  Command: [REDACTED]").count(), 2, "{log}");
            let expected_events = [
                "code_issued",
                "code_resolved",
                "allow_granted",
                "entry_consumed",
            ];
            if format == "json" {
                let entries: Vec<serde_json::Value> = log
                    .lines()
                    .filter(|line| line.starts_with('{'))
                    .map(|line| serde_json::from_str(line).expect("JSON audit record"))
                    .collect();
                assert_eq!(entries.len(), 5, "{log}");
                for event in expected_events {
                    assert!(entries.iter().any(|entry| entry["event"] == event), "{log}");
                }
                for entry in entries {
                    for field in ["command", "cwd", "full_hash", "short_code"] {
                        assert_eq!(entry[field], "[REDACTED]", "{field}: {log}");
                    }
                }
            } else {
                for event in expected_events {
                    assert!(log.contains(&format!("[allow-once:{event}]")), "{log}");
                }
                let audit_lines: Vec<_> = log
                    .lines()
                    .filter(|line| line.contains("[allow-once:"))
                    .collect();
                assert_eq!(audit_lines.len(), 5, "{log}");
                for line in audit_lines {
                    assert_eq!(
                        line.split_ascii_whitespace()
                            .find(|field| field.starts_with("code=")),
                        Some("code=[REDACTED]"),
                        "{line}"
                    );
                }
                assert!(
                    !log.contains(env.temp.path().to_string_lossy().as_ref()),
                    "full redaction must hide audit path metadata: {log}"
                );
            }

            // Management actions use the same audit file. Their target and
            // resolved hash also derive from the command and must be redacted.
            let revoke = env.run_cli(&["allow-once", "revoke", &second_code, "--yes", "--json"]);
            assert!(
                revoke.status.success(),
                "revoke failed\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&revoke.stdout),
                String::from_utf8_lossy(&revoke.stderr)
            );
            let revoked: serde_json::Value =
                serde_json::from_slice(&revoke.stdout).expect("JSON revoke result");
            assert_eq!(revoked["status"], "ok");
            assert_eq!(revoked["pending"]["removed"], 1);
            let full_hash = revoked["full_hash"]
                .as_str()
                .expect("resolved command hash");
            let log = std::fs::read_to_string(&log_path).expect("read management audit log");
            assert!(
                !log.to_ascii_lowercase()
                    .contains(&MARKER.to_ascii_lowercase()),
                "full redaction leaked into the complete {format} management log: {log}"
            );
            assert!(!log.contains(full_hash), "{log}");
            let management_details: Vec<_> = log
                .lines()
                .filter_map(|line| line.split_once("[allow-once] revoke: "))
                .map(|(_, details)| details)
                .collect();
            assert_eq!(management_details, vec!["[REDACTED]"], "{log}");
            assert!(!management_details[0].contains(&second_code), "{log}");
        }
    }

    /// An allow-once grant is consumed by its first use unless `--reusable`
    /// asks otherwise (#378): "allow once" means once.
    #[test]
    fn allow_once_is_single_use_by_default_issue_378() {
        let env = FlowTestEnv::new();
        let command = "git reset --hard";

        let code = extract_code_from_denial(&assert_is_denial(&env.run_hook(command)))
            .expect("denial carries a code");
        assert!(
            env.run_cli(&["allow-once", &code, "--yes"])
                .status
                .success()
        );
        assert_is_allowed(&env.run_hook(command));
        assert_is_denial(&env.run_hook(command));

        let code = extract_code_from_denial(&assert_is_denial(&env.run_hook(command)))
            .expect("a fresh denial carries a code");
        let reusable = env.run_cli(&["allow-once", &code, "--yes", "--reusable"]);
        assert!(
            reusable.status.success(),
            "reusable grant failed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&reusable.stdout),
            String::from_utf8_lossy(&reusable.stderr)
        );
        assert_is_allowed(&env.run_hook(command));
        assert_is_allowed(&env.run_hook(command));
    }

    /// `dcg explain` must agree with `dcg test` on a path-scoped grant and say
    /// which grant allowed the command. It used to evaluate with no project
    /// path, so a `paths = [...]` entry never applied and explain reported
    /// DENY where the hook and `dcg test` allowed; and when a grant did apply
    /// it printed a bare ALLOW, naming neither the layer nor the entry.
    #[test]
    fn explain_names_the_allowlist_grant_and_honours_its_paths() {
        let env = FlowTestEnv::new();
        let project = env.temp.path().canonicalize().expect("canonical temp");
        let allowlist = format!(
            "[[allow]]\nrule = \"core.git:reset-hard\"\nreason = \"reviewed reset\"\n\
             added_at = \"2026-09-22T00:00:00Z\"\npaths = [{:?}, {:?}]\n",
            project.to_string_lossy(),
            project.join("**").to_string_lossy()
        );
        for dir in [
            env.xdg_config_dir.join("dcg"),
            env.home_dir.join(".config").join("dcg"),
        ] {
            std::fs::create_dir_all(&dir).expect("config dir");
            std::fs::write(dir.join("allowlist.toml"), &allowlist).expect("write allowlist");
        }

        let test_json: serde_json::Value = serde_json::from_slice(
            &env.run_cli(&["test", "--format", "json", "git reset --hard"])
                .stdout,
        )
        .expect("test json");
        let explain_json: serde_json::Value = serde_json::from_slice(
            &env.run_cli(&["explain", "--format", "json", "git reset --hard"])
                .stdout,
        )
        .expect("explain json");

        assert_eq!(test_json["decision"], "allow", "{test_json}");
        assert_eq!(explain_json["decision"], "allow", "{explain_json}");
        assert_eq!(explain_json["allowlist"]["layer"], "user", "{explain_json}");
        assert_eq!(
            explain_json["allowlist"]["entry_reason"], "reviewed reset",
            "{explain_json}"
        );
        assert_eq!(
            explain_json["allowlist"]["original_match"]["rule_id"], "core.git:reset-hard",
            "{explain_json}"
        );
    }

    /// #262: without `--yes` and without a terminal, the confirmation can
    /// never be answered. dcg must refuse *before* printing a confirmation
    /// block that reads like a granted allowance, must say so on stderr, and
    /// must leave the command blocked with the code still pending.
    #[test]
    fn allow_once_without_terminal_refuses_loudly_and_grants_nothing() {
        let env = FlowTestEnv::new();
        let command = "git reset --hard";

        let denial = env.run_hook(command);
        let stdout = assert_is_denial(&denial);
        let code = extract_code_from_denial(&stdout).expect("should emit code");

        let output = env.run_cli_without_terminal(&["allow-once", &code]);
        let cli_stdout = String::from_utf8_lossy(&output.stdout);
        let cli_stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            !output.status.success(),
            "allow-once without a terminal must fail\nstdout: {cli_stdout}\nstderr: {cli_stderr}"
        );
        assert!(
            cli_stderr.contains("--yes"),
            "error must name the non-interactive escape hatch: {cli_stderr}"
        );
        assert!(
            !cli_stdout.contains("Allow-once confirmation:")
                && !cli_stdout.contains("Allow-once entry created"),
            "no confirmation block may be printed for a refused grant: {cli_stdout}"
        );

        // The grant must not exist: the command is still blocked...
        assert_is_denial(&env.run_hook(command));
        // ...and the code is still pending, so the operator can retry.
        let list = env.run_cli(&["allow-once", "list", "--json"]);
        let listed: serde_json::Value =
            serde_json::from_slice(&list.stdout).expect("allow-once list --json");
        assert_eq!(
            listed["allow_once"]["count"].as_u64(),
            Some(0),
            "no allow-once entry may have been written: {listed}"
        );
        assert!(
            listed["pending"]["count"].as_u64().is_some_and(|n| n > 0),
            "the pending code must survive a refused confirmation: {listed}"
        );
    }

    #[test]
    fn block_emits_full_hash_in_hook_output() {
        let env = FlowTestEnv::new();
        let command = "git reset --hard";

        let result = env.run_hook(command);
        let stdout = assert_is_denial(&result);

        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("expected JSON stdout");

        // Verify full hash is present
        let full_hash = json["hookSpecificOutput"]["allowOnceFullHash"]
            .as_str()
            .expect("should have allowOnceFullHash");
        assert!(
            full_hash.len() >= 16,
            "full hash should be long, got: {full_hash}"
        );

        // Verify short code is a prefix of or derived from the hash
        let code = json["hookSpecificOutput"]["allowOnceCode"]
            .as_str()
            .expect("should have allowOnceCode");
        assert!(!code.is_empty(), "code should not be empty");
    }

    #[test]
    fn cwd_scoping_blocks_same_command_in_different_directory() {
        let env = FlowTestEnv::new();
        let command = "git reset --hard";

        // Step 1: Block and get code
        let result1 = env.run_hook(command);
        let stdout1 = assert_is_denial(&result1);
        let code = extract_code_from_denial(&stdout1).expect("should emit code");

        // Step 2: Allow it
        let allow_output = env.run_cli(&["allow-once", &code, "--yes"]);
        assert!(allow_output.status.success(), "allow-once should succeed");

        // Step 3: Same command in same directory is allowed
        let result2 = env.run_hook(command);
        assert_is_allowed(&result2);

        // Step 4: Create a different directory outside the original temp dir
        let other_temp = tempfile::tempdir().expect("other tempdir");
        std::fs::create_dir_all(other_temp.path().join(".git")).expect("create .git in other dir");

        // Step 5: Same command in different directory is still blocked
        let result3 = env.run_hook_in_dir(command, other_temp.path());
        assert_is_denial(&result3);
    }

    #[test]
    fn single_use_consumed_after_first_allow() {
        let env = FlowTestEnv::new();
        let command = "git reset --hard";

        // Step 1: Block and get code
        let result1 = env.run_hook(command);
        let stdout1 = assert_is_denial(&result1);
        let code = extract_code_from_denial(&stdout1).expect("should emit code");

        // Step 2: Allow it with --single-use
        let allow_output = env.run_cli(&["allow-once", &code, "--yes", "--single-use"]);
        assert!(
            allow_output.status.success(),
            "allow-once --single-use should succeed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&allow_output.stdout),
            String::from_utf8_lossy(&allow_output.stderr)
        );

        // Step 3: First run is allowed
        let result2 = env.run_hook(command);
        assert_is_allowed(&result2);

        // Step 4: Second run is blocked again (single-use consumed)
        let result3 = env.run_hook(command);
        assert_is_denial(&result3);
    }

    #[test]
    fn allow_once_list_shows_pending_and_active_entries() {
        let env = FlowTestEnv::new();
        let command = "git reset --hard";

        // Step 1: Block to create pending entry
        let result1 = env.run_hook(command);
        let stdout1 = assert_is_denial(&result1);
        let code = extract_code_from_denial(&stdout1).expect("should emit code");

        // Step 2: Check list shows pending
        let list_output1 = env.run_cli(&["allow-once", "list", "--json"]);
        assert!(list_output1.status.success(), "list should succeed");
        let list_json1: serde_json::Value =
            serde_json::from_slice(&list_output1.stdout).expect("valid JSON");
        assert!(
            list_json1["pending"]["count"].as_u64().unwrap_or(0) >= 1,
            "should have at least 1 pending entry\njson: {list_json1}"
        );

        // Step 3: Allow it
        let allow_output = env.run_cli(&["allow-once", &code, "--yes"]);
        assert!(allow_output.status.success(), "allow-once should succeed");

        // Step 4: Check list shows active entry
        let list_output2 = env.run_cli(&["allow-once", "list", "--json"]);
        assert!(list_output2.status.success(), "list should succeed");
        let list_json2: serde_json::Value =
            serde_json::from_slice(&list_output2.stdout).expect("valid JSON");
        assert!(
            list_json2["allow_once"]["count"].as_u64().unwrap_or(0) >= 1,
            "should have at least 1 active entry\njson: {list_json2}"
        );
    }

    #[test]
    fn force_flag_required_for_config_block_override() {
        let env = FlowTestEnv::new();
        let command = "git reset --hard";

        // Create a config that explicitly blocks git reset --hard
        let config_path = env.temp.path().join("dcg.toml");
        std::fs::write(
            &config_path,
            r"
[overrides]
block = [
  { pattern = '\bgit\s+reset\s+--hard\b', reason = 'test config block' },
]
",
        )
        .expect("write config");

        // Run hook with the config (this creates a pending entry)
        let input = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {
                "command": command,
            }
        });

        let mut cmd = Command::new(dcg_binary());
        cmd.env_clear()
            .env("HOME", &env.home_dir)
            .env("USERPROFILE", &env.home_dir)
            .env("XDG_CONFIG_HOME", &env.xdg_config_dir)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env("DCG_PACKS", "core.git,core.filesystem")
            .env("DCG_PENDING_EXCEPTIONS_PATH", &env.pending_path)
            .env("DCG_ALLOW_ONCE_PATH", &env.allow_once_path)
            .env("DCG_CONFIG", &config_path)
            .current_dir(env.temp.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().expect("failed to spawn dcg hook mode");
        {
            let stdin = child.stdin.as_mut().expect("failed to open stdin");
            serde_json::to_writer(stdin, &input).expect("failed to write hook input JSON");
        }
        let hook_output = child.wait_with_output().expect("failed to wait for dcg");
        let stdout = String::from_utf8_lossy(&hook_output.stdout);

        let code = extract_code_from_denial(&stdout).expect("should emit code for config block");

        // Step 2: Try to allow without --force - should fail
        let allow_no_force = Command::new(dcg_binary())
            .env_clear()
            .env("HOME", &env.home_dir)
            .env("USERPROFILE", &env.home_dir)
            .env("XDG_CONFIG_HOME", &env.xdg_config_dir)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env("DCG_PENDING_EXCEPTIONS_PATH", &env.pending_path)
            .env("DCG_ALLOW_ONCE_PATH", &env.allow_once_path)
            .env("DCG_CONFIG", &config_path)
            .current_dir(env.temp.path())
            .args(["allow-once", &code, "--yes"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("run dcg allow-once");

        assert!(
            !allow_no_force.status.success(),
            "allow-once without --force should fail for config block\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&allow_no_force.stdout),
            String::from_utf8_lossy(&allow_no_force.stderr)
        );
        let stderr = String::from_utf8_lossy(&allow_no_force.stderr);
        assert!(
            stderr.contains("config blocklist") || stderr.contains("--force"),
            "error should mention config blocklist or --force\nstderr: {stderr}"
        );
    }

    #[test]
    fn collision_handling_with_multiple_pending_entries() {
        let env = FlowTestEnv::new();

        // Create two commands that might produce the same short code prefix
        // (unlikely but the system should handle it via --pick or full hash)
        let command1 = "git reset --hard";
        let command2 = "git clean -fdx";

        // Block both commands
        let result1 = env.run_hook(command1);
        let stdout1 = assert_is_denial(&result1);
        let code1 = extract_code_from_denial(&stdout1).expect("should emit code for command1");

        let result2 = env.run_hook(command2);
        let stdout2 = assert_is_denial(&result2);
        let code2 = extract_code_from_denial(&stdout2).expect("should emit code for command2");

        // Verify we got unique codes
        assert_ne!(
            code1, code2,
            "different commands should have different codes"
        );

        // Allow the first one
        let allow_output = env.run_cli(&["allow-once", &code1, "--yes"]);
        assert!(
            allow_output.status.success(),
            "allow-once for code1 should succeed"
        );

        // First command is allowed, second is still blocked
        let verify1 = env.run_hook(command1);
        assert_is_allowed(&verify1);

        let verify2 = env.run_hook(command2);
        assert_is_denial(&verify2);
    }

    #[test]
    fn revoke_removes_active_exception() {
        let env = FlowTestEnv::new();
        let command = "git reset --hard";

        // Step 1: Block and allow
        let result1 = env.run_hook(command);
        let stdout1 = assert_is_denial(&result1);
        let code = extract_code_from_denial(&stdout1).expect("should emit code");

        let allow_output = env.run_cli(&["allow-once", &code, "--yes"]);
        assert!(allow_output.status.success(), "allow-once should succeed");

        // NOTE: We do NOT verify it's allowed here because single-use exceptions
        // are consumed on first use. We want to test revoke on an unconsumed exception.

        // Step 2: Revoke the exception before it's used
        let revoke_output = env.run_cli(&["allow-once", "revoke", &code, "--yes", "--json"]);
        assert!(
            revoke_output.status.success(),
            "revoke should succeed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&revoke_output.stdout),
            String::from_utf8_lossy(&revoke_output.stderr)
        );

        // Step 3: Command should be blocked again
        let result3 = env.run_hook(command);
        assert_is_denial(&result3);
    }

    #[test]
    fn dry_run_does_not_create_exception() {
        let env = FlowTestEnv::new();
        let command = "git reset --hard";

        // Step 1: Block and get code
        let result1 = env.run_hook(command);
        let stdout1 = assert_is_denial(&result1);
        let code = extract_code_from_denial(&stdout1).expect("should emit code");

        // Step 2: Dry-run allow
        let allow_output = env.run_cli(&["allow-once", &code, "--dry-run"]);
        assert!(
            allow_output.status.success(),
            "allow-once --dry-run should succeed"
        );

        // Step 3: Command should still be blocked (dry-run doesn't write)
        let result2 = env.run_hook(command);
        assert_is_denial(&result2);
    }

    #[test]
    fn json_output_mode_works() {
        let env = FlowTestEnv::new();
        let command = "git reset --hard";

        // Block and get code
        let result1 = env.run_hook(command);
        let stdout1 = assert_is_denial(&result1);
        let code = extract_code_from_denial(&stdout1).expect("should emit code");

        // Allow with --json --yes
        let allow_output = env.run_cli(&["allow-once", &code, "--yes", "--json"]);
        assert!(
            allow_output.status.success(),
            "allow-once --json should succeed"
        );

        let json: serde_json::Value =
            serde_json::from_slice(&allow_output.stdout).expect("should be valid JSON");
        assert_eq!(json["status"], "ok", "JSON output should show status ok");
        assert_eq!(json["code"], code, "JSON output should include code");
        assert!(
            json["expires_at"].is_string(),
            "JSON output should include expires_at"
        );
    }
}

// ============================================================================
// DCG SCAN Tests
// ============================================================================

mod scan_tests {
    use super::*;

    #[test]
    fn scan_clean_file_returns_success() {
        let mut file = tempfile::Builder::new().suffix(".sh").tempfile().unwrap();
        writeln!(file, "echo hello").unwrap();
        writeln!(file, "ls -la").unwrap();
        file.flush().unwrap();

        let output = run_dcg(&["scan", "--paths", file.path().to_str().unwrap()]);

        assert!(
            output.status.success(),
            "scan should succeed for clean file"
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("No findings") || stdout.contains("Findings: 0"),
            "should report no findings"
        );
    }

    #[test]
    fn scan_dangerous_file_returns_nonzero() {
        let mut file = tempfile::Builder::new().suffix(".sh").tempfile().unwrap();
        // Use git command since core.git is always enabled
        writeln!(file, "git reset --hard").unwrap();
        file.flush().unwrap(); // Ensure content is written before dcg reads it

        let output = run_dcg(&["scan", "--paths", file.path().to_str().unwrap()]);

        assert!(
            !output.status.success(),
            "scan should return non-zero for dangerous file"
        );
    }

    #[test]
    fn scan_json_format_is_valid() {
        let mut file = tempfile::Builder::new().suffix(".sh").tempfile().unwrap();
        // Use git command since core.git is always enabled
        writeln!(file, "git reset --hard").unwrap();
        file.flush().unwrap();

        let output = run_dcg(&[
            "scan",
            "--paths",
            file.path().to_str().unwrap(),
            "--format",
            "json",
        ]);

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("scan --format json should produce valid JSON");

        assert_eq!(json["schema_version"], 1, "should have schema_version");
        assert!(json["summary"].is_object(), "should have summary object");
        assert!(json["findings"].is_array(), "should have findings array");
    }

    #[test]
    fn scan_json_summary_has_required_fields() {
        let mut file = tempfile::Builder::new().suffix(".sh").tempfile().unwrap();
        writeln!(file, "echo safe").unwrap();
        file.flush().unwrap();

        let output = run_dcg(&[
            "scan",
            "--paths",
            file.path().to_str().unwrap(),
            "--format",
            "json",
        ]);

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let summary = &json["summary"];

        assert!(
            summary["files_scanned"].is_number(),
            "should have files_scanned"
        );
        assert!(
            summary["commands_extracted"].is_number(),
            "should have commands_extracted"
        );
        assert!(
            summary["findings_total"].is_number(),
            "should have findings_total"
        );
        assert!(
            summary["decisions"].is_object(),
            "should have decisions breakdown"
        );
        assert!(summary["elapsed_ms"].is_number(), "should have elapsed_ms");
    }

    #[test]
    fn scan_markdown_format_produces_valid_output() {
        let mut file = tempfile::Builder::new().suffix(".sh").tempfile().unwrap();
        // Use git command since core.git is always enabled
        writeln!(file, "git reset --hard HEAD~1").unwrap();
        file.flush().unwrap();

        let output = run_dcg(&[
            "scan",
            "--paths",
            file.path().to_str().unwrap(),
            "--format",
            "markdown",
        ]);

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Markdown format should have headers and code blocks
        assert!(
            stdout.contains('#') || stdout.contains("**"),
            "markdown should have formatting"
        );
    }

    #[test]
    fn scan_fail_on_none_always_succeeds() {
        let mut file = tempfile::Builder::new().suffix(".sh").tempfile().unwrap();
        // Use git command since core.git is always enabled
        writeln!(file, "git reset --hard").unwrap();
        file.flush().unwrap();

        let output = run_dcg(&[
            "scan",
            "--paths",
            file.path().to_str().unwrap(),
            "--fail-on",
            "none",
        ]);

        assert!(
            output.status.success(),
            "scan --fail-on none should always succeed"
        );
    }

    #[test]
    fn scan_empty_directory_succeeds() {
        let dir = tempfile::tempdir().unwrap();

        let output = run_dcg(&["scan", "--paths", dir.path().to_str().unwrap()]);

        assert!(output.status.success(), "scan on empty dir should succeed");
    }

    #[test]
    fn scan_findings_include_file_and_line() {
        let mut file = tempfile::Builder::new().suffix(".sh").tempfile().unwrap();
        writeln!(file, "echo safe").unwrap();
        // Use git command since core.git is always enabled
        writeln!(file, "git reset --hard").unwrap();
        file.flush().unwrap();

        let output = run_dcg(&[
            "scan",
            "--paths",
            file.path().to_str().unwrap(),
            "--format",
            "json",
        ]);

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let findings = json["findings"].as_array().unwrap();

        assert!(!findings.is_empty(), "should have findings");
        let finding = &findings[0];
        assert!(finding["file"].is_string(), "finding should have file");
        assert!(finding["line"].is_number(), "finding should have line");
        assert!(
            finding["rule_id"].is_string(),
            "finding should have rule_id"
        );
    }
}

// ============================================================================
// DCG TEST (single command evaluation) Tests
// ============================================================================

mod test_command_tests {
    use super::*;

    #[test]
    fn test_safe_command_returns_allowed() {
        let output = run_dcg(&["test", "echo hello"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            output.status.success(),
            "test should succeed for safe command"
        );
        assert!(
            stdout.contains("ALLOWED") || stdout.contains("allow"),
            "should show allowed result"
        );
    }

    #[test]
    fn test_dangerous_command_returns_blocked() {
        // Use git command since core.git is always enabled
        let output = run_dcg(&["test", "git reset --hard"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Note: test command currently returns exit code 0 even for blocked commands
        // This tests the output content instead
        assert!(
            stdout.contains("BLOCKED") || stdout.contains("blocked"),
            "should show blocked result"
        );
        assert!(
            stdout.contains("core.git"),
            "should mention the pack that blocked it"
        );
    }

    #[test]
    fn test_output_includes_rule_info() {
        // Use git command since core.git is always enabled
        let output = run_dcg(&["test", "git reset --hard"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        // The output should include pattern information
        assert!(
            stdout.contains("hard-reset") || stdout.contains("Pattern"),
            "should include pattern info"
        );
    }
}

// ============================================================================
// DCG CONFIG Tests
// ============================================================================

mod config_tests {
    use super::*;

    fn setup_doctor_env(
        temp: &tempfile::TempDir,
    ) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let home_dir = temp.path().join("home");
        let xdg_config_dir = temp.path().join("xdg_config");
        let bin_dir = temp.path().join("bin");

        std::fs::create_dir_all(&home_dir).expect("HOME dir");
        std::fs::create_dir_all(&xdg_config_dir).expect("XDG_CONFIG_HOME dir");
        std::fs::create_dir_all(&bin_dir).expect("bin dir");
        std::fs::create_dir_all(temp.path().join(".git")).expect(".git dir");

        let dcg_stub = bin_dir.join(format!("dcg{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&dcg_stub, b"").expect("write dcg stub");

        (home_dir, xdg_config_dir, bin_dir)
    }

    fn run_hook_policy_install(home: &std::path::Path, args: &[&str]) -> std::process::Output {
        let tmp = home.join("tmp");
        std::fs::create_dir_all(&tmp).expect("isolated installer temp directory");
        std::process::Command::new(dcg_binary())
            .args(args)
            .env_clear()
            .env("HOME", home)
            .env("USERPROFILE", home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("CLAUDE_CONFIG_DIR", home.join(".claude"))
            .env("REASONIX_HOME", home.join(".reasonix"))
            .env("TMPDIR", &tmp)
            .env("TEMP", &tmp)
            .env("TMP", &tmp)
            .env("DCG_SELF_HEAL_HOOK", "0")
            .env("NO_COLOR", "1")
            .current_dir(home)
            .output()
            .expect("run isolated dcg install")
    }

    fn native_settings_json_path(home: &std::path::Path, agent: &str) -> std::path::PathBuf {
        home.join(match agent {
            "" => ".claude/settings.json",
            "--grok" => ".grok/hooks/dcg.json",
            "--agy" => ".gemini/config/hooks.json",
            "--reasonix" => ".reasonix/settings.json",
            "--crush" => ".config/crush/crush.json",
            "--muse" => ".config/muse/settings.json",
            _ => panic!("unsupported settings fixture: {agent}"),
        })
    }

    fn native_settings_json_entries(agent: &str, fields: &str) -> String {
        let hook = match agent {
            "--reasonix" => format!(r#"{{"match":"bash","command":"/retired/dcg",{fields}}}"#),
            "--crush" => format!(r#"{{"matcher":"^bash$","command":"/retired/dcg",{fields}}}"#),
            _ => format!(r#"{{"type":"command","command":"/retired/dcg",{fields}}}"#),
        };
        if matches!(agent, "--reasonix" | "--crush") {
            format!("[{hook}]")
        } else {
            format!(r#"[{{"matcher":"Bash","hooks":[{hook}]}}]"#)
        }
    }

    fn native_settings_json_document(agent: &str, hooks: &str, extra: &str) -> String {
        let schema = if agent == "--muse" {
            r#""schema_version":1,"#
        } else {
            ""
        };
        format!(r#"{{{schema}"hooks":{{{hooks}}}{extra}}}"#)
    }

    fn assert_native_settings_json_duplicates_are_refused(agent: &str) {
        let home = tempfile::tempdir().expect("isolated HOME");
        let path = native_settings_json_path(home.path(), agent);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut fixtures = Vec::new();
        for fields in [
            r#""onFailure":"block","onFailure":"continue","timeout":15"#,
            r#""onFailure":"block","on\u0046ailure":"continue","timeout":15"#,
            r#""onFailure":"block","timeout":15,"timeout":5"#,
            r#""onFailure":"block","timeout":15,"command":"audit-only"#,
            r#""onFailure":"block","onFailure":"block","timeout":15"#,
        ] {
            let entries = native_settings_json_entries(agent, fields);
            fixtures.push(native_settings_json_document(
                agent,
                &format!(r#""PreToolUse":{entries}"#),
                "",
            ));
        }
        let entries = native_settings_json_entries(agent, r#""onFailure":"block","timeout":15"#);
        fixtures.push(native_settings_json_document(
            agent,
            &format!(r#""PreToolUse":{entries},"PreToolUse":[]"#),
            "",
        ));
        fixtures.push(native_settings_json_document(
            agent,
            &format!(r#""PreToolUse":{entries}"#),
            r#", "hooks":{}"#,
        ));
        fixtures.push(native_settings_json_document(
            agent,
            &format!(r#""PreToolUse":{entries}"#),
            r#", "operator":{"policy":"strict","policy":"observe"}"#,
        ));

        for original in fixtures {
            for force in [false, true] {
                std::fs::write(&path, original.as_bytes()).unwrap();
                let mut args = vec!["install"];
                if !agent.is_empty() {
                    args.push(agent);
                }
                if force {
                    args.push("--force");
                }
                let output = run_hook_policy_install(home.path(), &args);
                assert!(
                    !output.status.success(),
                    "{args:?} must refuse ambiguous settings: {original}"
                );
                assert!(
                    String::from_utf8_lossy(&output.stderr)
                        .to_ascii_lowercase()
                        .contains("duplicate"),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert_eq!(std::fs::read(&path).unwrap(), original.as_bytes());
            }
        }
    }

    #[test]
    fn native_settings_json_claude_refuses_duplicate_keys() {
        assert_native_settings_json_duplicates_are_refused("");
    }

    #[test]
    fn native_settings_json_grok_refuses_duplicate_keys() {
        assert_native_settings_json_duplicates_are_refused("--grok");
    }

    #[test]
    fn native_settings_json_antigravity_refuses_duplicate_keys() {
        assert_native_settings_json_duplicates_are_refused("--agy");
    }

    #[test]
    fn native_settings_json_reasonix_refuses_duplicate_keys() {
        assert_native_settings_json_duplicates_are_refused("--reasonix");
    }

    #[test]
    fn native_settings_json_crush_refuses_duplicate_keys() {
        assert_native_settings_json_duplicates_are_refused("--crush");
    }

    #[test]
    fn native_settings_json_muse_refuses_duplicate_keys() {
        assert_native_settings_json_duplicates_are_refused("--muse");
    }

    #[test]
    fn native_settings_json_unique_nested_fields_survive_repair_and_repeats() {
        for agent in ["", "--grok", "--agy", "--reasonix", "--crush", "--muse"] {
            let home = tempfile::tempdir().expect("isolated HOME");
            let path = native_settings_json_path(home.path(), agent);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let entries =
                native_settings_json_entries(agent, r#""onFailure":"block","timeout":15"#);
            let original = native_settings_json_document(
                agent,
                &format!(r#""PreToolUse":{entries}"#),
                r#", "operator":{"first":{"name":"one","value":true},"second":{"name":"two","value":false},"Policy":null,"policy":[-9223372036854775808,18446744073709551615,1.25,"\u2603"]}"#,
            );
            let original_value: serde_json::Value = serde_json::from_str(&original).unwrap();
            std::fs::write(&path, original.as_bytes()).unwrap();
            let mut repaired = None;
            for force in [false, true, false] {
                let mut args = vec!["install"];
                if !agent.is_empty() {
                    args.push(agent);
                }
                if force {
                    args.push("--force");
                }
                let output = run_hook_policy_install(home.path(), &args);
                assert!(
                    output.status.success(),
                    "{args:?}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let bytes = std::fs::read(&path).unwrap();
                let settings: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(settings["operator"], original_value["operator"]);
                let guard = if matches!(agent, "--reasonix" | "--crush") {
                    &settings["hooks"]["PreToolUse"][0]
                } else {
                    &settings["hooks"]["PreToolUse"][0]["hooks"][0]
                };
                assert_eq!(guard["onFailure"], "block");
                assert_eq!(guard["timeout"], 15);
                if let Some(previous) = &repaired {
                    assert_eq!(
                        &settings, previous,
                        "{args:?} must preserve repaired settings"
                    );
                } else {
                    repaired = Some(settings);
                }
            }
        }
    }

    #[test]
    fn native_settings_json_uninstall_refuses_ambiguous_operator_data() {
        for agent in ["", "--reasonix", "--crush", "--muse"] {
            let home = tempfile::tempdir().expect("isolated HOME");
            let path = native_settings_json_path(home.path(), agent);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let entries =
                native_settings_json_entries(agent, r#""onFailure":"block","timeout":15"#);
            let original = native_settings_json_document(
                agent,
                &format!(r#""PreToolUse":{entries}"#),
                r#", "operator":{"policy":"strict","policy":"observe"}"#,
            );
            std::fs::write(&path, original.as_bytes()).unwrap();
            let mut args = vec!["uninstall"];
            if !agent.is_empty() {
                args.push(agent);
            }
            let output = run_hook_policy_install(home.path(), &args);
            assert!(
                !output.status.success(),
                "{args:?} must not discard operator data"
            );
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .to_ascii_lowercase()
                    .contains("duplicate")
            );
            assert_eq!(std::fs::read(&path).unwrap(), original.as_bytes());
        }
    }

    #[test]
    fn native_settings_json_self_heal_keeps_ambiguous_file_and_still_blocks() {
        let home = tempfile::tempdir().expect("isolated HOME");
        let path = native_settings_json_path(home.path(), "");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let entries = native_settings_json_entries(
            "",
            r#""onFailure":"block","onFailure":"continue","timeout":15"#,
        );
        let original = native_settings_json_document("", &format!(r#""PreToolUse":{entries}"#), "");
        std::fs::write(&path, original.as_bytes()).unwrap();
        let tmp = home.path().join("tmp");
        std::fs::create_dir_all(&tmp).unwrap();
        for _ in 0..2 {
            let mut child = Command::new(dcg_binary())
                .env_clear()
                .env("HOME", home.path())
                .env("USERPROFILE", home.path())
                .env("XDG_CONFIG_HOME", home.path().join(".config"))
                .env("CLAUDE_CONFIG_DIR", home.path().join(".claude"))
                .env("TMPDIR", &tmp)
                .env("TEMP", &tmp)
                .env("TMP", &tmp)
                .env("DCG_SELF_HEAL_HOOK", "1")
                .env("DCG_HOOK_TIMEOUT_MS", "5000")
                .env("DCG_PACKS", "core.git,core.filesystem")
                .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
                .env("NO_COLOR", "1")
                .current_dir(home.path())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(br#"{"tool_name":"Bash","tool_input":{"command":"git reset --hard"}}"#)
                .unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(output.status.success());
            let denial: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(denial["hookSpecificOutput"]["permissionDecision"], "deny");
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .to_ascii_lowercase()
                    .contains("duplicate"),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(std::fs::read(&path).unwrap(), original.as_bytes());
        }
    }

    #[test]
    fn native_settings_json_doctor_reports_ambiguity_without_repairing_it() {
        let home = tempfile::tempdir().expect("isolated HOME");
        let path = native_settings_json_path(home.path(), "");
        assert!(
            run_hook_policy_install(home.path(), &["install"])
                .status
                .success()
        );
        let current: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let original = format!(
            r#"{{"operator":{{"policy":"strict","policy":"observe"}},"hooks":{}}}"#,
            serde_json::to_string(&current["hooks"]).unwrap()
        );
        std::fs::write(&path, original.as_bytes()).unwrap();
        for args in [
            &["doctor", "--format", "json"][..],
            &["doctor", "--fix", "--format", "json"][..],
        ] {
            let output = run_hook_policy_install(home.path(), args);
            let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            let wiring = report["checks"]
                .as_array()
                .unwrap()
                .iter()
                .find(|check| check["id"] == "hook_wiring")
                .unwrap();
            assert_eq!(wiring["status"], "error", "{wiring}");
            assert_ne!(wiring["fixed"], true);
            assert!(
                wiring["message"]
                    .as_str()
                    .unwrap()
                    .to_ascii_lowercase()
                    .contains("duplicate")
            );
            assert_eq!(std::fs::read(&path).unwrap(), original.as_bytes());
        }
    }

    #[test]
    fn native_settings_json_grok_doctor_rejects_invalid_native_with_healthy_compat() {
        let home = tempfile::tempdir().expect("isolated HOME");
        let path = native_settings_json_path(home.path(), "--grok");
        for args in [&["install"][..], &["install", "--grok"][..]] {
            let output = run_hook_policy_install(home.path(), args);
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let current: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let command =
            serde_json::to_string(&current["hooks"]["PreToolUse"][0]["hooks"][0]["command"])
                .unwrap();
        let duplicate_hook = format!(
            r#"{{"type":"command","command":{command},"onFailure":"block","onFailure":"continue","timeout":15}}"#
        );
        let duplicate = native_settings_json_document(
            "--grok",
            &format!(r#""PreToolUse":[{{"matcher":"Bash","hooks":[{duplicate_hook}]}}]"#),
            "",
        );
        for (original, diagnostic) in [("{".to_string(), None), (duplicate, Some("duplicate"))] {
            std::fs::write(&path, original.as_bytes()).unwrap();
            for args in [
                &["doctor", "--format", "json"][..],
                &["doctor", "--fix", "--format", "json"][..],
            ] {
                let output = run_hook_policy_install(home.path(), args);
                let report: serde_json::Value = serde_json::from_slice(&output.stdout)
                    .unwrap_or_else(|error| {
                        panic!(
                            "doctor must emit one JSON document: {error}; stdout: {}; stderr: {}",
                            String::from_utf8_lossy(&output.stdout),
                            String::from_utf8_lossy(&output.stderr)
                        )
                    });
                let checks = report["checks"].as_array().unwrap();
                let compat = checks
                    .iter()
                    .find(|check| check["id"] == "hook_wiring")
                    .unwrap();
                assert_eq!(compat["status"], "ok", "{compat}");
                let native = checks
                    .iter()
                    .find(|check| check["id"] == "grok_hook")
                    .unwrap();
                assert_eq!(native["status"], "error", "{native}");
                assert_ne!(native["fixed"], true);
                assert_eq!(report["ok"], false);
                let message = native["message"].as_str().unwrap().to_ascii_lowercase();
                assert!(message.contains("invalid native grok"), "{native}");
                if let Some(diagnostic) = diagnostic {
                    assert!(message.contains(diagnostic), "{native}");
                }
                assert_eq!(std::fs::read(&path).unwrap(), original.as_bytes());
            }
        }
    }

    #[test]
    fn native_settings_json_grok_doctor_does_not_claim_async_policy_is_fixed() {
        let home = tempfile::tempdir().expect("isolated HOME");
        let path = native_settings_json_path(home.path(), "--grok");
        for args in [&["install"][..], &["install", "--grok"][..]] {
            let output = run_hook_policy_install(home.path(), args);
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let mut settings: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let hook = &mut settings["hooks"]["PreToolUse"][0]["hooks"][0];
        hook["async"] = true.into();
        hook["onFailure"] = "block".into();
        hook["timeout"] = 15.into();
        let expected = settings.clone();
        settings["hooks"]["PreToolUse"][0]["matcher"] = "run_terminal_cmd".into();
        settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = "/retired/dcg".into();
        std::fs::write(&path, serde_json::to_vec(&settings).unwrap()).unwrap();

        for _ in 0..2 {
            let output =
                run_hook_policy_install(home.path(), &["doctor", "--fix", "--format", "json"]);
            let report: serde_json::Value =
                serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
                    panic!(
                        "doctor must emit one JSON document: {error}; stdout: {}; stderr: {}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    )
                });
            let native = report["checks"]
                .as_array()
                .unwrap()
                .iter()
                .find(|check| check["id"] == "grok_hook")
                .unwrap();
            assert_eq!(native["status"], "error", "{native}");
            assert_ne!(native["fixed"], true);
            assert_eq!(report["ok"], false);
            assert!(
                native["message"]
                    .as_str()
                    .unwrap()
                    .contains("synchronously"),
                "{native}"
            );
            let repaired: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(repaired, expected, "repair must retain operator policy");
        }
    }

    #[cfg(unix)]
    #[test]
    fn native_settings_json_claude_and_antigravity_refuse_dangling_managed_links() {
        for agent in ["", "--agy"] {
            let home = tempfile::tempdir().expect("isolated HOME");
            let path = native_settings_json_path(home.path(), agent);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let target = home.path().join("unavailable-operator-settings.json");
            std::os::unix::fs::symlink(&target, &path).unwrap();
            for force in [false, true] {
                let mut args = vec!["install"];
                if !agent.is_empty() {
                    args.push(agent);
                }
                if force {
                    args.push("--force");
                }
                let output = run_hook_policy_install(home.path(), &args);
                assert!(
                    !output.status.success(),
                    "{args:?} must refuse a dangling link"
                );
                assert_eq!(std::fs::read_link(&path).unwrap(), target);
                assert!(
                    !target.exists(),
                    "a missing managed target must stay missing"
                );
            }
        }
    }

    fn agent_policy_settings_path(home: &std::path::Path, agent: &str) -> std::path::PathBuf {
        home.join(match agent {
            "--reasonix" => ".reasonix/settings.json",
            "--crush" => ".config/crush/crush.json",
            "--muse" => ".config/muse/settings.json",
            _ => panic!("unsupported fixture agent: {agent}"),
        })
    }

    fn agent_policy_fixture(agent: &str) -> serde_json::Value {
        let mut first = serde_json::json!({"command": "/retired/dcg"});
        let mut protected = serde_json::json!({
            "command": "\"C:\\old tools\\dcg.exe\"",
            "onFailure": "block",
            "timeout": 15,
            "description": "Operator-managed safety policy",
            "future": {"enabled": true, "labels": ["security", "interactive"]}
        });
        let mut last = serde_json::json!({
            "command": "/older/dcg",
            "statusMessage": "Checking safety"
        });
        let mut settings = serde_json::json!({
            "model": "operator-model",
            "operator": {"managed": true},
            "hooks": {"Stop": [{"command": "after-audit"}]}
        });
        match agent {
            "--reasonix" => {
                protected["match"] = serde_json::json!("pwsh");
                last["match"] = serde_json::json!("write");
                settings["hooks"]["PreToolUse"] = serde_json::json!([
                    {"match": "bash", "command": first["command"]},
                    {"match": "read", "command": "/usr/bin/logger /opt/dcg"},
                    protected,
                    last,
                    {"match": "write", "command": "write-audit", "timeout": 7}
                ]);
            }
            "--crush" => {
                protected["matcher"] = serde_json::json!("^bash$");
                last["matcher"] = serde_json::json!(".*");
                settings["hooks"]["PreToolUse"] = serde_json::json!([
                    {"matcher": ".*", "command": first["command"]},
                    {"matcher": "^read$", "command": "/usr/bin/logger /opt/dcg"}
                ]);
                settings["hooks"]["pre_tool_use"] = serde_json::json!([
                    protected,
                    {"matcher": "^write$", "command": "write-audit", "timeout": 7}
                ]);
                settings["hooks"]["pre-tool-use"] = serde_json::json!([last]);
            }
            "--muse" => {
                first["type"] = serde_json::json!("command");
                protected["type"] = serde_json::json!("command");
                last["type"] = serde_json::json!("command");
                settings["schema_version"] = serde_json::json!(1);
                settings["hooks"]["PreToolUse"] = serde_json::json!([
                    {"matcher": "^(shell|exec_command|bash)$", "hooks": [
                        first,
                        {"type": "command", "command": "shell-audit"}
                    ]},
                    {"matcher": "^exec_command$", "hooks": [
                        protected,
                        {"type": "command", "command": "terminal-audit"}
                    ]},
                    {"matcher": "^write_file$", "hooks": [last]},
                    {"matcher": "^read_file$", "hooks": [
                        {"type": "command", "command": "/usr/bin/logger /opt/dcg"}
                    ]}
                ]);
            }
            _ => panic!("unsupported fixture agent: {agent}"),
        }
        settings
    }

    fn agent_policy_guard<'a>(
        settings: &'a serde_json::Value,
        agent: &str,
    ) -> &'a serde_json::Value {
        let first = &settings["hooks"]["PreToolUse"][0];
        if agent == "--muse" {
            &first["hooks"][0]
        } else {
            first
        }
    }

    fn assert_agent_policy_repair_and_repeat(agent: &str) {
        let home = tempfile::tempdir().expect("isolated HOME");
        let path = agent_policy_settings_path(home.path(), agent);
        let fresh = run_hook_policy_install(home.path(), &["install", agent]);
        assert!(
            fresh.status.success(),
            "{agent}: {}",
            String::from_utf8_lossy(&fresh.stderr)
        );
        let fresh: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let desired = agent_policy_guard(&fresh, agent);
        let original = agent_policy_fixture(agent);

        // Both ordinary upgrades and an explicit repair must preserve the
        // complete policy, even when it lives on a later stale registration.
        for args in [&["install", agent][..], &["install", agent, "--force"][..]] {
            std::fs::write(&path, serde_json::to_vec(&original).unwrap()).unwrap();
            let repaired = run_hook_policy_install(home.path(), args);
            assert!(
                repaired.status.success(),
                "{args:?}: {}",
                String::from_utf8_lossy(&repaired.stderr)
            );
            let installed_bytes = std::fs::read(&path).unwrap();
            let installed: serde_json::Value = serde_json::from_slice(&installed_bytes).unwrap();
            let guard = agent_policy_guard(&installed, agent);
            assert_eq!(guard["command"], desired["command"], "{agent}");
            assert_eq!(guard["onFailure"], "block", "{agent}");
            assert_eq!(guard["timeout"], 15, "{agent}");
            assert_eq!(guard["description"], "Operator-managed safety policy");
            assert_eq!(guard["statusMessage"], "Checking safety", "{agent}");
            assert_eq!(
                guard["future"],
                serde_json::json!({"enabled": true, "labels": ["security", "interactive"]})
            );
            assert_eq!(installed["model"], original["model"]);
            assert_eq!(installed["operator"], original["operator"]);
            assert_eq!(installed["hooks"]["Stop"], original["hooks"]["Stop"]);
            let entries = installed["hooks"]["PreToolUse"].as_array().unwrap();
            match agent {
                "--reasonix" => {
                    assert_eq!(guard["match"], "bash|pwsh");
                    assert_eq!(entries.len(), 3);
                    assert_eq!(entries[1], original["hooks"]["PreToolUse"][1]);
                    assert_eq!(entries[2], original["hooks"]["PreToolUse"][4]);
                }
                "--crush" => {
                    assert_eq!(guard["matcher"], "^bash$");
                    assert_eq!(entries.len(), 2);
                    assert_eq!(entries[1], original["hooks"]["PreToolUse"][1]);
                    assert_eq!(
                        installed["hooks"]["pre_tool_use"],
                        serde_json::json!([original["hooks"]["pre_tool_use"][1]])
                    );
                    assert!(
                        installed["hooks"]["pre-tool-use"]
                            .as_array()
                            .is_none_or(Vec::is_empty)
                    );
                }
                "--muse" => {
                    assert_eq!(installed["schema_version"], 1);
                    assert_eq!(entries[0]["matcher"], "^(shell|exec_command|bash)$");
                    assert_eq!(guard["type"], "command");
                    assert!(
                        guard["command"]
                            .as_str()
                            .unwrap()
                            .ends_with(" --agent muse")
                    );
                    let audits: Vec<_> = entries
                        .iter()
                        .flat_map(|group| {
                            group["hooks"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .filter(|handler| handler["command"] != guard["command"])
                                .map(|handler| (group["matcher"].clone(), handler.clone()))
                        })
                        .collect();
                    assert_eq!(
                        audits,
                        vec![
                            (
                                serde_json::json!("^(shell|exec_command|bash)$"),
                                serde_json::json!({"type": "command", "command": "shell-audit"})
                            ),
                            (
                                serde_json::json!("^exec_command$"),
                                serde_json::json!({"type": "command", "command": "terminal-audit"})
                            ),
                            (
                                serde_json::json!("^read_file$"),
                                serde_json::json!({"type": "command", "command": "/usr/bin/logger /opt/dcg"})
                            )
                        ]
                    );
                    assert_eq!(
                        entries
                            .iter()
                            .flat_map(|group| group["hooks"].as_array().unwrap())
                            .filter(|handler| handler["command"] == guard["command"])
                            .count(),
                        1
                    );
                }
                _ => unreachable!(),
            }
            for repeated_args in [
                &["install", agent, "--force"][..],
                &["install", agent][..],
                &["install", agent][..],
            ] {
                let repeated = run_hook_policy_install(home.path(), repeated_args);
                assert!(
                    repeated.status.success(),
                    "{repeated_args:?}: {}",
                    String::from_utf8_lossy(&repeated.stderr)
                );
                assert_eq!(
                    std::fs::read(&path).unwrap(),
                    installed_bytes,
                    "{repeated_args:?} changed an already repaired configuration"
                );
            }
        }
    }

    #[test]
    fn native_agent_hook_policy_reasonix_preserves_block_across_repair_and_repeat() {
        assert_agent_policy_repair_and_repeat("--reasonix");
    }

    #[test]
    fn native_agent_hook_policy_crush_preserves_block_across_repair_and_repeat() {
        assert_agent_policy_repair_and_repeat("--crush");
    }

    #[test]
    fn native_agent_hook_policy_muse_preserves_block_across_repair_and_repeat() {
        assert_agent_policy_repair_and_repeat("--muse");
    }

    fn assert_agent_policy_conflicts_preserve_file(agent: &str) {
        let home = tempfile::tempdir().expect("isolated HOME");
        let path = agent_policy_settings_path(home.path(), agent);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        for (field, conflicting_value) in [
            ("onFailure", serde_json::json!("continue")),
            ("timeout", serde_json::json!(5)),
            ("future", serde_json::json!({"enabled": false})),
        ] {
            let mut original = agent_policy_fixture(agent);
            let first = if agent == "--muse" {
                &mut original["hooks"]["PreToolUse"][0]["hooks"][0]
            } else {
                &mut original["hooks"]["PreToolUse"][0]
            };
            first[field] = conflicting_value;
            let original = serde_json::to_vec(&original).unwrap();
            std::fs::write(&path, &original).unwrap();
            for args in [&["install", agent][..], &["install", agent, "--force"][..]] {
                let output = run_hook_policy_install(home.path(), args);
                assert!(
                    !output.status.success(),
                    "{args:?} must refuse conflicting {field}"
                );
                assert!(
                    String::from_utf8_lossy(&output.stderr).contains(field),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert_eq!(std::fs::read(&path).unwrap(), original);
            }
        }
    }

    #[test]
    fn native_agent_hook_policy_reasonix_conflicts_preserve_previous_file() {
        assert_agent_policy_conflicts_preserve_file("--reasonix");
    }

    #[test]
    fn native_agent_hook_policy_crush_conflicts_preserve_previous_file() {
        assert_agent_policy_conflicts_preserve_file("--crush");
    }

    #[test]
    fn native_agent_hook_policy_muse_conflicts_preserve_previous_file() {
        assert_agent_policy_conflicts_preserve_file("--muse");
    }

    #[test]
    fn native_agent_hook_policy_malformed_files_and_read_errors_are_not_replaced() {
        for agent in ["--reasonix", "--crush", "--muse"] {
            let home = tempfile::tempdir().expect("isolated HOME");
            let path = agent_policy_settings_path(home.path(), agent);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            for original in [
                b"{\"hooks\": ".to_vec(),
                b"{\"invalid_utf8\":\"\xff\"}".to_vec(),
                b"[]".to_vec(),
                b"{\"hooks\":[]}".to_vec(),
                b"{\"hooks\":{\"PreToolUse\":{}}}".to_vec(),
            ] {
                std::fs::write(&path, &original).unwrap();
                for args in [&["install", agent][..], &["install", agent, "--force"][..]] {
                    let output = run_hook_policy_install(home.path(), args);
                    assert!(
                        !output.status.success(),
                        "{args:?} must refuse {original:?}"
                    );
                    assert_eq!(std::fs::read(&path).unwrap(), original);
                }
            }

            let unreadable_home = tempfile::tempdir().expect("isolated unreadable HOME");
            let directory = agent_policy_settings_path(unreadable_home.path(), agent);
            std::fs::create_dir_all(&directory).unwrap();
            let sentinel = directory.join("managed-data");
            std::fs::write(&sentinel, b"preserve this directory").unwrap();
            for args in [&["install", agent][..], &["install", agent, "--force"][..]] {
                let output = run_hook_policy_install(unreadable_home.path(), args);
                assert!(
                    !output.status.success(),
                    "{args:?} must refuse a read error"
                );
                assert!(directory.is_dir());
                assert_eq!(
                    std::fs::read(&sentinel).unwrap(),
                    b"preserve this directory"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn native_agent_hook_policy_managed_symlinks_and_permissions_survive_updates() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        for agent in ["--reasonix", "--crush", "--muse"] {
            let home = tempfile::tempdir().expect("isolated HOME");
            let path = agent_policy_settings_path(home.path(), agent);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let target = home.path().join("managed-settings.json");
            std::fs::write(
                &target,
                serde_json::to_vec(&agent_policy_fixture(agent)).unwrap(),
            )
            .unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
            symlink(&target, &path).unwrap();
            for args in [&["install", agent][..], &["install", agent, "--force"][..]] {
                let output = run_hook_policy_install(home.path(), args);
                assert!(
                    output.status.success(),
                    "{args:?}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(
                    std::fs::symlink_metadata(&path)
                        .unwrap()
                        .file_type()
                        .is_symlink()
                );
                assert_eq!(std::fs::read_link(&path).unwrap(), target);
                assert_eq!(
                    std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
                    0o640
                );
                let installed: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&target).unwrap()).unwrap();
                let guard = agent_policy_guard(&installed, agent);
                assert_eq!(guard["onFailure"], "block");
                assert_eq!(guard["timeout"], 15);
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn native_agent_hook_policy_broken_managed_symlinks_are_not_created_over() {
        use std::os::unix::fs::symlink;

        for agent in ["--reasonix", "--crush", "--muse"] {
            let home = tempfile::tempdir().expect("isolated HOME");
            let path = agent_policy_settings_path(home.path(), agent);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let missing_target = home.path().join("unavailable-managed-settings.json");
            symlink(&missing_target, &path).unwrap();
            for args in [&["install", agent][..], &["install", agent, "--force"][..]] {
                let output = run_hook_policy_install(home.path(), args);
                assert!(
                    !output.status.success(),
                    "{args:?} must refuse an unavailable managed configuration"
                );
                assert!(
                    std::fs::symlink_metadata(&path)
                        .unwrap()
                        .file_type()
                        .is_symlink()
                );
                assert_eq!(std::fs::read_link(&path).unwrap(), missing_target);
                assert!(!missing_target.exists());
            }
        }
    }

    #[test]
    fn native_hook_policy_install_force_preserves_block_across_duplicate_repair_and_repeat() {
        let home = tempfile::tempdir().expect("isolated HOME");
        let settings_path = home.path().join(".claude/settings.json");
        let created = run_hook_policy_install(home.path(), &["install"]);
        assert!(
            created.status.success(),
            "{}",
            String::from_utf8_lossy(&created.stderr)
        );
        let fresh: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&settings_path).unwrap()).unwrap();
        let desired = fresh["hooks"]["PreToolUse"][0]["hooks"][0].clone();
        let original = serde_json::json!({
            "model": "operator-model",
            "hooks": {"PreToolUse": [
                {"matcher": "Bash|PowerShell|Monitor", "label": "keep", "hooks": [desired.clone()]},
                {"matcher": "Bash", "label": "legacy", "hooks": [
                    {"type": "command", "command": "dcg", "onFailure": "block", "timeout": 15},
                    {"type": "command", "command": "bash-audit", "timeout": 7}
                ]},
                {"matcher": "Write", "hooks": [
                    {"type": "command", "command": "\"C:\\old installation\\dcg.exe\"", "statusMessage": "Checking safety"},
                    {"type": "command", "command": "write-audit"}
                ]}
            ]}
        });
        std::fs::write(&settings_path, serde_json::to_vec(&original).unwrap()).unwrap();

        let repaired = run_hook_policy_install(home.path(), &["install", "--force"]);
        assert!(
            repaired.status.success(),
            "{}",
            String::from_utf8_lossy(&repaired.stderr)
        );
        let installed_bytes = std::fs::read(&settings_path).unwrap();
        let installed: serde_json::Value = serde_json::from_slice(&installed_bytes).unwrap();
        let entries = installed["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0]["matcher"], "Bash|PowerShell|Monitor");
        assert_eq!(entries[0]["label"], "keep");
        let hook = &entries[0]["hooks"][0];
        for key in ["type", "command", "shell"] {
            assert_eq!(hook.get(key), desired.get(key));
        }
        assert_eq!(hook["onFailure"], "block");
        assert_eq!(hook["timeout"], 15);
        assert_eq!(hook["statusMessage"], "Checking safety");
        assert_eq!(entries[1]["matcher"], "Bash");
        assert_eq!(entries[1]["label"], "legacy");
        assert_eq!(
            entries[1]["hooks"],
            serde_json::json!([{"type": "command", "command": "bash-audit", "timeout": 7}])
        );
        assert_eq!(entries[2]["matcher"], "Write");
        assert_eq!(
            entries[2]["hooks"],
            serde_json::json!([{"type": "command", "command": "write-audit"}])
        );
        assert_eq!(installed["model"], "operator-model");

        for args in [&["install", "--force"][..], &["install"][..]] {
            let repeated = run_hook_policy_install(home.path(), args);
            assert!(
                repeated.status.success(),
                "{}",
                String::from_utf8_lossy(&repeated.stderr)
            );
            assert_eq!(std::fs::read(&settings_path).unwrap(), installed_bytes);
        }
    }

    #[test]
    fn native_hook_policy_install_refuses_conflicting_failure_policies_without_rewriting() {
        let home = tempfile::tempdir().expect("isolated HOME");
        let claude = home.path().join(".claude");
        std::fs::create_dir(&claude).unwrap();
        let settings_path = claude.join("settings.json");
        let original = serde_json::to_vec(&serde_json::json!({
            "hooks": {"PreToolUse": [
                {"matcher": "Bash|PowerShell|Monitor", "hooks": [{"type": "command", "command": "dcg", "onFailure": "block"}]},
                {"matcher": "Write", "hooks": [{"type": "command", "command": "/old/dcg", "onFailure": "continue"}]}
            ]}
        })).unwrap();
        std::fs::write(&settings_path, &original).unwrap();

        for args in [&["install"][..], &["install", "--force"][..]] {
            let output = run_hook_policy_install(home.path(), args);
            assert!(
                !output.status.success(),
                "conflicting policies must fail even with --force"
            );
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("onFailure"),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(std::fs::read(&settings_path).unwrap(), original);
        }
    }

    #[cfg(unix)]
    #[test]
    fn native_hook_policy_install_keeps_managed_symlink_and_private_permissions() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let home = tempfile::tempdir().expect("isolated HOME");
        let claude = home.path().join(".claude");
        let managed = home.path().join("managed");
        std::fs::create_dir(&claude).unwrap();
        std::fs::create_dir(&managed).unwrap();
        let target = managed.join("settings.json");
        let settings_path = claude.join("settings.json");
        std::fs::write(
            &target,
            serde_json::to_vec(&serde_json::json!({
                "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{
                    "type": "command", "command": "dcg", "timeout": 15, "onFailure": "block"
                }]}]}
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &settings_path).unwrap();

        let output = run_hook_policy_install(home.path(), &["install", "--force"]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            std::fs::symlink_metadata(&settings_path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let settings: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&target).unwrap()).unwrap();
        assert_eq!(
            settings["hooks"]["PreToolUse"][0]["hooks"][0]["onFailure"],
            "block"
        );
    }

    #[test]
    fn grok_hook_policy_force_preserves_block_across_duplicate_repair_and_repeat() {
        let home = tempfile::tempdir().expect("isolated HOME");
        let hook_path = home.path().join(".grok/hooks/dcg.json");
        let created = run_hook_policy_install(home.path(), &["install", "--grok"]);
        assert!(
            created.status.success(),
            "{}",
            String::from_utf8_lossy(&created.stderr)
        );
        let fresh: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&hook_path).unwrap()).unwrap();
        let desired = fresh["hooks"]["PreToolUse"][0]["hooks"][0].clone();
        assert_eq!(desired["timeout"], 5, "new installs keep Grok's default");
        let original = serde_json::json!({
            "description": "Operator-managed Grok safety hooks",
            "operator": {"team": "security"},
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash", "label": "canonical", "hooks": [
                        {"type": "command", "command": desired["command"]},
                        {"type": "command", "command": "bash-audit"}
                    ]},
                    {"matcher": "run_terminal_cmd", "label": "keep this scope", "hooks": [
                        {"type": "command", "command": "\"C:\\old tools\\dcg.exe\"", "onFailure": "block", "timeout": 15, "future": {"enabled": true}},
                        {"type": "command", "command": "terminal-audit"}
                    ]},
                    {"matcher": "Write", "hooks": [
                        {"type": "command", "command": "/older/dcg", "statusMessage": "Checking safety"}
                    ]}
                ],
                "PostToolUse": [{"matcher": "*", "hooks": [{"command": "after-audit"}]}]
            }
        });
        std::fs::write(&hook_path, serde_json::to_vec(&original).unwrap()).unwrap();

        let repaired = run_hook_policy_install(home.path(), &["install", "--grok", "--force"]);
        assert!(
            repaired.status.success(),
            "{}",
            String::from_utf8_lossy(&repaired.stderr)
        );
        let installed_bytes = std::fs::read(&hook_path).unwrap();
        let installed: serde_json::Value = serde_json::from_slice(&installed_bytes).unwrap();
        let entries = installed["hooks"]["PreToolUse"].as_array().unwrap();
        let hook = &entries[0]["hooks"][0];
        assert_eq!(hook["onFailure"], "block");
        assert_eq!(hook["timeout"], 15);
        assert_eq!(hook["future"], serde_json::json!({"enabled": true}));
        assert_eq!(hook["statusMessage"], "Checking safety");
        for key in ["type", "command", "shell"] {
            assert_eq!(hook.get(key), desired.get(key));
        }
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["matcher"], "Bash");
        assert_eq!(entries[0]["label"], "canonical");
        assert_eq!(
            entries[0]["hooks"][1],
            original["hooks"]["PreToolUse"][0]["hooks"][1]
        );
        assert_eq!(entries[1]["matcher"], "run_terminal_cmd");
        assert_eq!(entries[1]["label"], "keep this scope");
        assert_eq!(
            entries[1]["hooks"],
            serde_json::json!([{"type": "command", "command": "terminal-audit"}])
        );
        assert_eq!(installed["description"], original["description"]);
        assert_eq!(installed["operator"], original["operator"]);
        assert_eq!(
            installed["hooks"]["PostToolUse"],
            original["hooks"]["PostToolUse"]
        );

        for args in [
            &["install", "--grok", "--force"][..],
            &["install", "--grok"][..],
        ] {
            let repeated = run_hook_policy_install(home.path(), args);
            assert!(
                repeated.status.success(),
                "{}",
                String::from_utf8_lossy(&repeated.stderr)
            );
            assert_eq!(std::fs::read(&hook_path).unwrap(), installed_bytes);
        }
    }

    #[test]
    fn grok_hook_policy_nonforce_repairs_a_stale_command_and_legacy_matcher() {
        let home = tempfile::tempdir().expect("isolated HOME");
        let hook_path = home.path().join(".grok/hooks/dcg.json");
        std::fs::create_dir_all(hook_path.parent().unwrap()).unwrap();
        std::fs::write(
            &hook_path,
            serde_json::to_vec(&serde_json::json!({
                "hooks": {"PreToolUse": [{"matcher": "run_terminal_cmd", "hooks": [{
                    "type": "command", "command": "/retired/dcg", "timeout": 15, "onFailure": "block"
                }]}]}
            }))
            .unwrap(),
        )
        .unwrap();

        let output = run_hook_policy_install(home.path(), &["install", "--grok"]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let installed_bytes = std::fs::read(&hook_path).unwrap();
        let settings: serde_json::Value = serde_json::from_slice(&installed_bytes).unwrap();
        let entries = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["matcher"], "Bash");
        let hook = &entries[0]["hooks"][0];
        assert_ne!(hook["command"], "/retired/dcg");
        assert_eq!(hook["timeout"], 15);
        assert_eq!(hook["onFailure"], "block");

        let repeated = run_hook_policy_install(home.path(), &["install", "--grok"]);
        assert!(repeated.status.success());
        assert_eq!(std::fs::read(&hook_path).unwrap(), installed_bytes);
    }

    #[test]
    fn grok_hook_policy_repair_preserves_other_programs_with_dcg_path_arguments() {
        let home = tempfile::tempdir().expect("isolated HOME");
        let hook_path = home.path().join(".grok/hooks/dcg.json");
        std::fs::create_dir_all(hook_path.parent().unwrap()).unwrap();
        let audit = serde_json::json!({
            "matcher": "Read", "label": "unrelated audit scope", "hooks": [
                {"type": "command", "command": "/usr/bin/logger /opt/dcg"}
            ]
        });
        let original = serde_json::json!({
            "hooks": {"PreToolUse": [
                {"matcher": "Bash", "hooks": [{
                    "type": "command", "command": "/retired/dcg", "timeout": 15, "onFailure": "block"
                }]},
                audit.clone()
            ]}
        });
        std::fs::write(&hook_path, serde_json::to_vec(&original).unwrap()).unwrap();

        let repaired = run_hook_policy_install(home.path(), &["install", "--grok"]);
        assert!(
            repaired.status.success(),
            "{}",
            String::from_utf8_lossy(&repaired.stderr)
        );
        let installed_bytes = std::fs::read(&hook_path).unwrap();
        let settings: serde_json::Value = serde_json::from_slice(&installed_bytes).unwrap();
        let entries = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(
            entries.len(),
            2,
            "a dcg argument does not make logger a guard"
        );
        assert_eq!(entries[1], audit, "unrelated audit hook keeps its scope");
        let guard = &entries[0]["hooks"][0];
        assert_ne!(guard["command"], "/retired/dcg");
        assert_eq!(guard["timeout"], 15);
        assert_eq!(guard["onFailure"], "block");

        for args in [
            &["install", "--grok", "--force"][..],
            &["install", "--grok"][..],
        ] {
            let repeated = run_hook_policy_install(home.path(), args);
            assert!(
                repeated.status.success(),
                "{}",
                String::from_utf8_lossy(&repeated.stderr)
            );
            assert_eq!(std::fs::read(&hook_path).unwrap(), installed_bytes);
        }
    }

    #[test]
    fn grok_hook_policy_rejects_invalid_files_and_conflicts_without_rewriting() {
        let home = tempfile::tempdir().expect("isolated HOME");
        let hook_path = home.path().join(".grok/hooks/dcg.json");
        std::fs::create_dir_all(hook_path.parent().unwrap()).unwrap();
        let fixtures = [
            b"{\"hooks\": ".to_vec(),
            b" ".to_vec(),
            serde_json::to_vec(&serde_json::json!([])).unwrap(),
            serde_json::to_vec(&serde_json::json!({"hooks": []})).unwrap(),
            serde_json::to_vec(&serde_json::json!({"hooks": {"PreToolUse": {}}})).unwrap(),
            serde_json::to_vec(&serde_json::json!({"hooks": {"PreToolUse": [
                {"matcher": "Bash", "hooks": null}
            ]}}))
            .unwrap(),
            serde_json::to_vec(&serde_json::json!({"hooks": {"PreToolUse": [
                {"matcher": "Bash", "hooks": [{"command": "dcg", "onFailure": "block"}]},
                {"matcher": "Write", "hooks": [{"command": "/old/dcg", "onFailure": "continue"}]}
            ]}}))
            .unwrap(),
        ];
        for original in fixtures {
            std::fs::write(&hook_path, &original).unwrap();
            for args in [
                &["install", "--grok"][..],
                &["install", "--grok", "--force"][..],
            ] {
                let output = run_hook_policy_install(home.path(), args);
                assert!(
                    !output.status.success(),
                    "invalid or conflicting settings must fail for {args:?}"
                );
                assert_eq!(std::fs::read(&hook_path).unwrap(), original);
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn grok_hook_policy_install_keeps_managed_symlink_and_private_permissions() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let home = tempfile::tempdir().expect("isolated HOME");
        let hook_path = home.path().join(".grok/hooks/dcg.json");
        std::fs::create_dir_all(hook_path.parent().unwrap()).unwrap();
        let target = home.path().join("managed-grok.json");
        std::fs::write(
            &target,
            serde_json::to_vec(&serde_json::json!({
                "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{
                    "type": "command", "command": "dcg", "timeout": 15, "onFailure": "block"
                }]}]}
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &hook_path).unwrap();

        let output = run_hook_policy_install(home.path(), &["install", "--grok", "--force"]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            std::fs::symlink_metadata(&hook_path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let settings: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&target).unwrap()).unwrap();
        assert_eq!(
            settings["hooks"]["PreToolUse"][0]["hooks"][0]["onFailure"],
            "block"
        );
    }

    /// The machine-wide config file the binary always reads
    /// (`system_config_dir()` in `src/config.rs`).
    fn machine_config_path() -> std::path::PathBuf {
        if cfg!(windows) {
            std::env::var_os("ProgramData")
                .filter(|dir| !dir.is_empty())
                .map_or_else(
                    || std::path::PathBuf::from(r"C:\ProgramData"),
                    std::path::PathBuf::from,
                )
                .join("dcg")
                .join("config.toml")
        } else if cfg!(target_os = "macos") {
            std::path::PathBuf::from("/private/etc/dcg/config.toml")
        } else {
            std::path::PathBuf::from("/etc/dcg/config.toml")
        }
    }

    /// The host's machine-wide config, when it exists AND `doctor` reports it
    /// loaded.
    ///
    /// That layer is trusted policy with no environment override (an agent
    /// must not be able to shed it), so the scratch HOME/XDG these tests use
    /// cannot hide it. On a host with dcg installed system-wide (a machine-wide
    /// `/etc/dcg/config.toml`) doctor correctly reports one
    /// loaded file instead of built-in defaults, and `--fix` correctly leaves
    /// the user config alone. Requiring both the file and doctor's own report
    /// keeps the strict expectations on every host without such a file.
    fn loaded_machine_config(doctor_output: &str) -> Option<std::path::PathBuf> {
        let path = machine_config_path();
        (path.is_file() && doctor_output.contains(&format!("system: {} [loaded;", path.display())))
            .then_some(path)
    }

    /// #320: a pinned install refuses `dcg update` before any network or
    /// installer work, with an actionable message naming the escape hatch.
    #[test]
    fn update_refuses_when_pinned() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (home_dir, xdg_config_dir, _bin_dir) = setup_doctor_env(&temp);

        let output = std::process::Command::new(dcg_binary())
            .args(["update"])
            .env_clear()
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("DCG_UPDATE_PIN", "1")
            .current_dir(temp.path())
            .output()
            .expect("run dcg update");

        assert!(
            !output.status.success(),
            "pinned update must exit non-zero; stdout: {} stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("pinned"), "refusal names the pin: {stderr}");
        assert!(
            stderr.contains("--replace-local-build"),
            "refusal names the escape hatch: {stderr}"
        );
    }

    /// #318: `dcg install --opencode` writes a marker-carrying plugin under
    /// $XDG_CONFIG_HOME/opencode/plugins, is idempotent without --force, and
    /// refuses to overwrite a user-owned file of the same name.
    #[test]
    fn install_opencode_writes_owned_plugin_and_respects_foreign_files() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (home_dir, xdg_config_dir, _bin_dir) = setup_doctor_env(&temp);
        let plugin_path = xdg_config_dir
            .join("opencode")
            .join("plugins")
            .join("dcg-guard.js");

        let run = |args: &[&str]| {
            std::process::Command::new(dcg_binary())
                .args(args)
                .env_clear()
                .env("HOME", &home_dir)
                .env("USERPROFILE", &home_dir)
                .env("XDG_CONFIG_HOME", &xdg_config_dir)
                .current_dir(temp.path())
                .output()
                .expect("run dcg")
        };

        // First install writes the plugin.
        let output = run(&["install", "--opencode"]);
        assert!(
            output.status.success(),
            "install --opencode: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let written = std::fs::read_to_string(&plugin_path).expect("plugin written");
        assert!(written.contains("dcg-opencode-plugin"), "ownership marker");
        assert!(written.contains("tool.execute.before"), "hook key");

        // Second install without --force is a no-op that reports "already".
        let output = run(&["install", "--opencode"]);
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("already installed"),
            "idempotent reinstall: {stdout}"
        );

        // A user-owned file (no marker) is never overwritten, even with --force.
        std::fs::write(&plugin_path, "export const Mine = async () => ({});")
            .expect("plant user plugin");
        let output = run(&["install", "--opencode", "--force"]);
        assert!(
            !output.status.success(),
            "must refuse to clobber a user-owned plugin"
        );
        let contents = std::fs::read_to_string(&plugin_path).expect("plugin intact");
        assert!(
            contents.contains("Mine"),
            "user-owned plugin left untouched"
        );
    }

    /// `dcg install --omp` writes OMP's native ExtensionAPI module under the
    /// active user agent directory, is idempotent, and never overwrites a
    /// user-owned extension with the same filename.
    #[test]
    fn install_omp_writes_owned_extension_and_respects_foreign_files() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (home_dir, xdg_config_dir, _bin_dir) = setup_doctor_env(&temp);
        let extension_path = home_dir
            .join(".omp")
            .join("agent")
            .join("extensions")
            .join("dcg-guard.ts");

        let run = |args: &[&str]| {
            std::process::Command::new(dcg_binary())
                .args(args)
                .env_clear()
                .env("HOME", &home_dir)
                .env("USERPROFILE", &home_dir)
                .env("XDG_CONFIG_HOME", &xdg_config_dir)
                .current_dir(temp.path())
                .output()
                .expect("run dcg")
        };

        let output = run(&["install", "--omp"]);
        assert!(
            output.status.success(),
            "install --omp: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let written = std::fs::read_to_string(&extension_path).expect("extension written");
        assert!(written.contains("dcg-omp-extension"), "ownership marker");
        assert!(written.contains("pi.on(\"tool_call\""), "OMP hook event");
        assert!(written.contains("\"--agent\", \"omp\""), "OMP profile");

        let output = run(&["install", "--omp"]);
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("already installed"),
            "idempotent reinstall: {stdout}"
        );

        std::fs::write(&extension_path, "export default function mine() {}")
            .expect("plant user extension");
        let output = run(&["install", "--omp", "--force"]);
        assert!(
            !output.status.success(),
            "must refuse to clobber a user-owned OMP extension"
        );
        let contents = std::fs::read_to_string(&extension_path).expect("extension intact");
        assert!(contents.contains("mine"), "user extension left untouched");
    }

    #[test]
    fn install_omp_project_is_anchored_to_a_nested_git_cwd() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (home_dir, xdg_config_dir, _bin_dir) = setup_doctor_env(&temp);
        let nested_cwd = temp.path().join("nested").join("worktree");
        std::fs::create_dir_all(&nested_cwd).expect("nested cwd");

        let output = Command::new(dcg_binary())
            .args(["install", "--omp", "--project"])
            .env_clear()
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .current_dir(&nested_cwd)
            .output()
            .expect("install project OMP extension from nested Git cwd");
        assert!(
            output.status.success(),
            "nested project install: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        assert!(
            nested_cwd.join(".omp/extensions/dcg-guard.ts").is_file(),
            "OMP loads the extension from the exact launch cwd"
        );
        assert!(
            !temp.path().join(".omp/extensions/dcg-guard.ts").exists(),
            "project install must not walk to the enclosing Git root"
        );
    }

    #[test]
    fn install_omp_project_works_without_a_git_repository() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cwd = temp.path().join("plain-directory");
        let home_dir = temp.path().join("home");
        let xdg_config_dir = temp.path().join("xdg_config");
        std::fs::create_dir_all(&cwd).expect("non-Git cwd");
        std::fs::create_dir_all(&home_dir).expect("HOME dir");
        std::fs::create_dir_all(&xdg_config_dir).expect("XDG_CONFIG_HOME dir");

        let output = Command::new(dcg_binary())
            .args(["install", "--omp", "--project"])
            .env_clear()
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .current_dir(&cwd)
            .output()
            .expect("install project OMP extension outside Git");
        assert!(
            output.status.success(),
            "non-Git project install: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(cwd.join(".omp/extensions/dcg-guard.ts").is_file());
    }

    /// #358: `dcg install --reasonix` merges a `hooks.PreToolUse` entry into
    /// `<Reasonix home>/settings.json`, keeps unrelated settings and hooks, is
    /// idempotent, and keeps a user's timeout on reinstall. The installed
    /// command is then run the way Reasonix runs it (`sh -c`, the Reasonix
    /// payload on stdin): exit 2 with the reason on stderr blocks a
    /// destructive command, exit 0 lets a safe one through. `dcg uninstall
    /// --reasonix` removes exactly what it added.
    #[test]
    fn install_reasonix_hook_blocks_through_the_installed_command() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (home_dir, xdg_config_dir, _bin_dir) = setup_doctor_env(&temp);
        let reasonix_home = temp.path().join("reasonix-home");
        let settings_path = reasonix_home.join("settings.json");
        std::fs::create_dir_all(&reasonix_home).expect("reasonix home");
        std::fs::write(
            &settings_path,
            r#"{"theme":"dark","hooks":{"PreToolUse":[{"match":"bash","command":"node check.js"}],"Stop":[{"command":"echo done"}]}}"#,
        )
        .expect("seed settings.json");

        let run = |args: &[&str]| {
            std::process::Command::new(dcg_binary())
                .args(args)
                .env_clear()
                .env("HOME", &home_dir)
                .env("USERPROFILE", &home_dir)
                .env("XDG_CONFIG_HOME", &xdg_config_dir)
                .env("REASONIX_HOME", &reasonix_home)
                .current_dir(temp.path())
                .output()
                .expect("run dcg")
        };
        let read = || -> serde_json::Value {
            serde_json::from_str(&std::fs::read_to_string(&settings_path).expect("read"))
                .expect("settings.json stays valid JSON")
        };

        let output = run(&["install", "--reasonix"]);
        assert!(
            output.status.success(),
            "install --reasonix: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let settings = read();
        assert_eq!(settings["theme"], "dark", "unrelated settings kept");
        assert_eq!(settings["hooks"]["Stop"][0]["command"], "echo done");
        let entries = settings["hooks"]["PreToolUse"].as_array().expect("array");
        assert_eq!(entries.len(), 2, "{settings}");
        assert_eq!(entries[0]["match"], "bash|pwsh");
        assert_eq!(entries[0]["timeout"], 5000);
        assert_eq!(entries[1]["command"], "node check.js");
        let command = entries[0]["command"].as_str().expect("command").to_string();

        // Idempotent, and a user's timeout survives a forced reinstall.
        assert!(
            String::from_utf8_lossy(&run(&["install", "--reasonix"]).stdout)
                .contains("already installed")
        );
        let mut settings = read();
        settings["hooks"]["PreToolUse"][0]["timeout"] = serde_json::json!(8000);
        std::fs::write(&settings_path, settings.to_string()).expect("edit timeout");
        assert!(run(&["install", "--reasonix", "--force"]).status.success());
        assert_eq!(read()["hooks"]["PreToolUse"][0]["timeout"], 8000);
        assert_eq!(read()["hooks"]["PreToolUse"].as_array().unwrap().len(), 2);

        // The installed command, run as Reasonix runs it.
        #[cfg(unix)]
        {
            let hook = |shell_command: &str| {
                let payload = serde_json::json!({
                    "event": "PreToolUse",
                    "cwd": temp.path(),
                    "toolName": "bash",
                    "toolArgs": { "command": shell_command },
                });
                let mut child = std::process::Command::new("sh")
                    .args(["-c", &command])
                    .env_clear()
                    .env("HOME", &home_dir)
                    .env("XDG_CONFIG_HOME", &xdg_config_dir)
                    .env("PATH", "/usr/bin:/bin")
                    .current_dir(temp.path())
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .expect("spawn installed hook");
                serde_json::to_writer(child.stdin.as_mut().unwrap(), &payload).unwrap();
                child.wait_with_output().expect("hook output")
            };
            let blocked = hook("git reset --hard");
            assert_eq!(blocked.status.code(), Some(2), "exit 2 blocks in Reasonix");
            assert!(blocked.stdout.is_empty(), "Reasonix never reads stdout");
            let reason = String::from_utf8_lossy(&blocked.stderr);
            assert!(reason.contains("BLOCKED by dcg"), "{reason}");
            assert!(reason.contains("core.git:reset-hard"), "{reason}");

            let allowed = hook("git status");
            assert_eq!(allowed.status.code(), Some(0), "exit 0 passes");
        }

        let output = run(&["uninstall", "--reasonix"]);
        assert!(output.status.success());
        let settings = read();
        let entries = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(entries.len(), 1, "{settings}");
        assert_eq!(entries[0]["command"], "node check.js");
        assert_eq!(settings["theme"], "dark");
    }

    /// #572: `dcg install --muse` merges a `hooks.PreToolUse` matcher group
    /// into `$XDG_CONFIG_HOME/muse/settings.json`, keeps `schema_version` and
    /// every other key, and is idempotent. The installed command is then run
    /// the way Muse runs it (through the shell, a Codex-shaped payload with
    /// `turn_id` on stdin, a cleared environment): a destructive `shell` or
    /// `exec_command` call gets the minimal `hookSpecificOutput` deny with a
    /// non-empty reason on exit 0, which Muse enforces; a safe call gets empty
    /// stdout, because Muse rejects a bare `allow`. `[agents.muse]` applies and
    /// `[agents.codex-cli]` does not. A payload dcg cannot read, or a shell
    /// call without a readable command, is blocked. `dcg uninstall --muse`
    /// removes exactly what it added.
    #[test]
    fn install_muse_hook_blocks_through_the_installed_command() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (home_dir, xdg_config_dir, _bin_dir) = setup_doctor_env(&temp);
        let settings_path = xdg_config_dir.join("muse").join("settings.json");
        std::fs::create_dir_all(settings_path.parent().unwrap()).expect("muse dir");
        std::fs::write(
            &settings_path,
            r#"{"schema_version":1,"model":"muse-spark-1.2","hooks":{"PreToolUse":[{"matcher":"^write_file$","hooks":[{"type":"command","command":"audit-writes"}]}],"SessionStart":[{"hooks":[{"type":"command","command":"hello"}]}]}}"#,
        )
        .expect("seed settings.json");

        let run = |args: &[&str]| {
            std::process::Command::new(dcg_binary())
                .args(args)
                .env_clear()
                .env("HOME", &home_dir)
                .env("USERPROFILE", &home_dir)
                .env("XDG_CONFIG_HOME", &xdg_config_dir)
                .env("APPDATA", temp.path().join("appdata"))
                .env("LOCALAPPDATA", temp.path().join("localappdata"))
                .current_dir(temp.path())
                .output()
                .expect("run dcg")
        };
        let read = || -> serde_json::Value {
            serde_json::from_str(&std::fs::read_to_string(&settings_path).expect("read"))
                .expect("settings.json stays valid JSON")
        };

        let output = run(&["install", "--muse"]);
        assert!(
            output.status.success(),
            "install --muse: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let settings = read();
        assert_eq!(settings["schema_version"], 1);
        assert_eq!(
            settings["model"], "muse-spark-1.2",
            "unrelated settings kept"
        );
        assert_eq!(
            settings["hooks"]["SessionStart"][0]["hooks"][0]["command"],
            "hello"
        );
        let groups = settings["hooks"]["PreToolUse"].as_array().expect("array");
        assert_eq!(groups.len(), 2, "{settings}");
        assert_eq!(groups[0]["matcher"], "^(shell|exec_command|bash)$");
        assert_eq!(groups[1]["hooks"][0]["command"], "audit-writes");
        let handler = groups[0]["hooks"][0].as_object().expect("handler object");
        let mut handler_keys: Vec<&str> = handler.keys().map(String::as_str).collect();
        handler_keys.sort_unstable();
        assert_eq!(
            handler_keys,
            vec!["command", "type"],
            "only fields Muse accepts are written"
        );
        assert_eq!(handler["type"], "command");
        let mut group_keys: Vec<&str> = groups[0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        group_keys.sort_unstable();
        assert_eq!(
            group_keys,
            vec!["hooks", "matcher"],
            "Muse rejects unknown group fields"
        );
        let command = handler["command"].as_str().expect("command").to_string();
        assert!(command.ends_with(" --agent muse"), "{command}");

        assert!(
            String::from_utf8_lossy(&run(&["install", "--muse"]).stdout)
                .contains("already installed")
        );
        assert_eq!(read(), settings, "a second install is a no-op");
        assert!(
            !run(&["install", "--muse", "--project"]).status.success(),
            "Muse project hooks are not a dcg install target"
        );

        // The installed command, run the way Muse runs a hook.
        #[cfg(unix)]
        {
            let dcg_config = xdg_config_dir.join("dcg").join("config.toml");
            std::fs::create_dir_all(dcg_config.parent().unwrap()).expect("dcg config dir");
            let hook = |payload: &str| {
                let mut child = std::process::Command::new("sh")
                    .args(["-c", &command])
                    .env_clear()
                    .env("HOME", &home_dir)
                    .env("XDG_CONFIG_HOME", &xdg_config_dir)
                    .env("PATH", "/usr/bin:/bin")
                    .env("DCG_SELF_HEAL_HOOK", "0")
                    .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
                    .env("DCG_HOOK_TIMEOUT_MS", "5000")
                    .current_dir(temp.path())
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .expect("spawn installed hook");
                child
                    .stdin
                    .as_mut()
                    .unwrap()
                    .write_all(payload.as_bytes())
                    .unwrap();
                child.wait_with_output().expect("hook output")
            };
            let muse_payload = |tool: &str, tool_input: serde_json::Value| {
                serde_json::json!({
                    "cwd": temp.path(),
                    "hook_event_name": "PreToolUse",
                    "model": "unknown",
                    "permission_mode": "default",
                    "session_id": "s",
                    "tool_input": tool_input,
                    "tool_name": tool,
                    "tool_use_id": "user_shell_1",
                    "transcript_path": null,
                    "turn_id": "t1",
                })
                .to_string()
            };
            let assert_denied = |output: &std::process::Output, label: &str| {
                assert_eq!(output.status.code(), Some(0), "{label}: Muse reads exit 0");
                let stdout = String::from_utf8_lossy(&output.stdout);
                let verdict: serde_json::Value = serde_json::from_str(stdout.trim())
                    .unwrap_or_else(|e| panic!("{label}: deny JSON ({e}): {stdout}"));
                let specific = verdict["hookSpecificOutput"]
                    .as_object()
                    .unwrap_or_else(|| panic!("{label}: {verdict}"));
                assert_eq!(verdict.as_object().unwrap().len(), 1, "{label}: {verdict}");
                let mut keys: Vec<&str> = specific.keys().map(String::as_str).collect();
                keys.sort_unstable();
                assert_eq!(
                    keys,
                    vec![
                        "hookEventName",
                        "permissionDecision",
                        "permissionDecisionReason"
                    ],
                    "{label}: the minimal Codex shape"
                );
                assert_eq!(specific["permissionDecision"], "deny", "{label}");
                assert!(
                    specific["permissionDecisionReason"]
                        .as_str()
                        .is_some_and(|reason| reason.contains("BLOCKED by dcg")),
                    "{label}: Muse requires a non-empty reason: {verdict}"
                );
            };
            let assert_allowed = |output: &std::process::Output, label: &str| {
                assert_eq!(output.status.code(), Some(0), "{label}");
                assert!(
                    output.stdout.is_empty(),
                    "{label}: Muse rejects a bare allow, so an allow is silent: {}",
                    String::from_utf8_lossy(&output.stdout)
                );
            };

            std::fs::write(&dcg_config, "[general]\nself_heal_hook = false\n").expect("dcg config");
            let shell_deny = hook(&muse_payload(
                "shell",
                serde_json::json!({"command": "git reset --hard"}),
            ));
            assert_denied(&shell_deny, "shell git reset --hard");
            assert!(
                String::from_utf8_lossy(&shell_deny.stdout).contains("core.git:reset-hard"),
                "{}",
                String::from_utf8_lossy(&shell_deny.stdout)
            );
            assert_denied(
                &hook(&muse_payload(
                    "exec_command",
                    serde_json::json!({"cmd": "git reset --hard"}),
                )),
                "exec_command cmd",
            );
            assert_denied(
                &hook(&muse_payload(
                    "exec_command",
                    serde_json::json!({"command": "ls", "cmd": "git reset --hard"}),
                )),
                "a benign command beside a destructive cmd",
            );
            assert_allowed(
                &hook(&muse_payload(
                    "shell",
                    serde_json::json!({"command": "git status"}),
                )),
                "shell git status",
            );
            assert_allowed(
                &hook(&muse_payload(
                    "exec_command",
                    serde_json::json!({"cmd": "git status"}),
                )),
                "exec_command git status",
            );
            assert_allowed(
                &hook(&muse_payload(
                    "read_file",
                    serde_json::json!({"path": "README.md"}),
                )),
                "a non-shell tool",
            );

            // Fail closed on what dcg cannot read.
            assert_denied(&hook("{\"tool_name\":\"shell\","), "truncated JSON");
            assert_denied(
                &hook(&muse_payload(
                    "exec_command",
                    serde_json::json!({"argv": ["git", "reset", "--hard"]}),
                )),
                "a shell call without a readable command",
            );

            // The [agents.muse] profile applies, [agents.codex-cli] does not.
            let amend = muse_payload(
                "shell",
                serde_json::json!({"command": "git commit --amend -m x"}),
            );
            std::fs::write(
                &dcg_config,
                "[general]\nself_heal_hook = false\n[agents.codex-cli]\nextra_packs = [\"strict_git\"]\n",
            )
            .expect("dcg config");
            assert_allowed(&hook(&amend), "[agents.codex-cli] does not apply to Muse");
            std::fs::write(
                &dcg_config,
                "[general]\nself_heal_hook = false\n[agents.muse]\nextra_packs = [\"strict_git\"]\n",
            )
            .expect("dcg config");
            assert_denied(&hook(&amend), "[agents.muse] applies");
        }

        let muse_doctor_check = |args: &[&str]| -> serde_json::Value {
            let output = run(args);
            let report: serde_json::Value =
                serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
                    panic!(
                        "doctor JSON ({e}): {}",
                        String::from_utf8_lossy(&output.stdout)
                    )
                });
            report["checks"]
                .as_array()
                .expect("checks")
                .iter()
                .find(|check| check["id"] == "muse_hook")
                .cloned()
                .unwrap_or_else(|| panic!("muse_hook check missing: {report}"))
        };
        assert_eq!(
            muse_doctor_check(&["doctor", "--format", "json"])["status"],
            "ok"
        );

        let output = run(&["uninstall", "--muse"]);
        assert!(output.status.success());
        let after = read();
        let groups = after["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(groups.len(), 1, "{after}");
        assert_eq!(groups[0]["hooks"][0]["command"], "audit-writes");
        assert_eq!(after["schema_version"], 1);
        assert_eq!(after["model"], "muse-spark-1.2");

        let missing = muse_doctor_check(&["doctor", "--format", "json"]);
        assert_eq!(missing["status"], "error", "{missing}");
        assert_eq!(read(), after, "doctor without --fix changes nothing");
        let fixed = muse_doctor_check(&["doctor", "--fix", "--format", "json"]);
        assert_eq!(fixed["fixed"], true, "{fixed}");
        assert_eq!(
            read()["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            command.as_str()
        );
    }

    /// #388: `dcg install --crush` merges a flat `hooks.PreToolUse` entry into
    /// Crush's user config (`$XDG_CONFIG_HOME/crush/crush.json`), preserves
    /// unrelated keys and hooks, is idempotent without --force, honors the
    /// `CRUSH_GLOBAL_CONFIG` directory override, and `dcg uninstall --crush`
    /// removes exactly what it added.
    #[test]
    fn install_crush_merges_hook_into_user_config_and_uninstalls() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (home_dir, xdg_config_dir, _bin_dir) = setup_doctor_env(&temp);
        let config_path = xdg_config_dir.join("crush").join("crush.json");
        std::fs::create_dir_all(config_path.parent().unwrap()).expect("crush dir");
        std::fs::write(
            &config_path,
            r#"{"$schema":"https://charm.land/crush.json","options":{"debug":true},"hooks":{"PreToolUse":[{"matcher":"^bash$","command":"./hooks/no-haskell.sh"}]}}"#,
        )
        .expect("seed crush.json");

        let run = |args: &[&str]| {
            std::process::Command::new(dcg_binary())
                .args(args)
                .env_clear()
                .env("HOME", &home_dir)
                .env("USERPROFILE", &home_dir)
                .env("XDG_CONFIG_HOME", &xdg_config_dir)
                .current_dir(temp.path())
                .output()
                .expect("run dcg")
        };

        let output = run(&["install", "--crush"]);
        assert!(
            output.status.success(),
            "install --crush: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let config: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).expect("read config"))
                .expect("crush.json stays valid JSON");
        assert_eq!(config["$schema"], "https://charm.land/crush.json");
        assert_eq!(config["options"]["debug"], true, "unrelated keys preserved");
        let entries = config["hooks"]["PreToolUse"]
            .as_array()
            .expect("hooks.PreToolUse array");
        assert_eq!(entries.len(), 2, "dcg entry plus the user's hook: {config}");
        let dcg_entry = &entries[0];
        assert_eq!(dcg_entry["name"], "dcg");
        assert_eq!(dcg_entry["matcher"], "^bash$");
        assert_eq!(dcg_entry["timeout"], 5);
        let command = dcg_entry["command"].as_str().expect("command string");
        assert!(
            command
                .trim_matches('"')
                .ends_with(&format!("dcg{}", std::env::consts::EXE_SUFFIX)),
            "command points at the dcg binary: {command}"
        );
        assert!(
            dcg_entry.get("hooks").is_none() && dcg_entry.get("type").is_none(),
            "Crush entries are flat, not Claude-shaped: {dcg_entry}"
        );
        assert_eq!(entries[1]["command"], "./hooks/no-haskell.sh");

        // Idempotent without --force.
        let output = run(&["install", "--crush"]);
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("already installed"), "idempotent: {stdout}");
        let again = std::fs::read_to_string(&config_path).expect("read config");
        let again: serde_json::Value = serde_json::from_str(&again).unwrap();
        assert_eq!(again["hooks"]["PreToolUse"].as_array().unwrap().len(), 2);

        // Uninstall removes only the dcg entry.
        let output = run(&["uninstall", "--crush"]);
        assert!(
            output.status.success(),
            "uninstall --crush: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let config: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        let entries = config["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(entries.len(), 1, "{config}");
        assert_eq!(entries[0]["command"], "./hooks/no-haskell.sh");
        assert_eq!(config["options"]["debug"], true);

        // CRUSH_GLOBAL_CONFIG is a directory override that beats XDG.
        let override_dir = temp.path().join("crush-global");
        let output = std::process::Command::new(dcg_binary())
            .args(["install", "--crush"])
            .env_clear()
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("CRUSH_GLOBAL_CONFIG", &override_dir)
            .current_dir(temp.path())
            .output()
            .expect("run dcg");
        assert!(
            output.status.success(),
            "install --crush with CRUSH_GLOBAL_CONFIG: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let overridden: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(override_dir.join("crush.json")).expect("override file"),
        )
        .unwrap();
        assert_eq!(overridden["hooks"]["PreToolUse"][0]["name"], "dcg");
    }

    /// #388: `dcg install --crush --project` edits the repo's `crush.json`
    /// (creating it when absent) so the hook rides along with the project.
    #[test]
    fn install_crush_project_writes_repo_crush_json() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (home_dir, xdg_config_dir, _bin_dir) = setup_doctor_env(&temp);
        let nested = temp.path().join("src").join("deep");
        std::fs::create_dir_all(&nested).expect("nested dir");

        let output = std::process::Command::new(dcg_binary())
            .args(["install", "--crush", "--project"])
            .env_clear()
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .current_dir(&nested)
            .output()
            .expect("run dcg");
        assert!(
            output.status.success(),
            "install --crush --project: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let project_config = temp.path().join("crush.json");
        assert!(project_config.is_file(), "written at the repo root");
        assert!(
            !xdg_config_dir.join("crush").join("crush.json").exists(),
            "project install must not touch the user config"
        );
        let config: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&project_config).unwrap()).unwrap();
        assert_eq!(config["hooks"]["PreToolUse"][0]["matcher"], "^bash$");
    }

    #[test]
    fn install_omp_matches_profile_and_legacy_override_precedence() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (home_dir, xdg_config_dir, _bin_dir) = setup_doctor_env(&temp);
        let ignored_override = temp.path().join("ignored-agent-dir");

        let named = Command::new(dcg_binary())
            .args(["install", "--omp"])
            .env_clear()
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("PI_CONFIG_DIR", ".custom-omp")
            .env("OMP_PROFILE", "work")
            .env("PI_PROFILE", "Upper")
            .env("PI_CODING_AGENT_DIR", &ignored_override)
            .current_dir(temp.path())
            .output()
            .expect("install named OMP profile");
        assert!(
            named.status.success(),
            "named profile install: {}",
            String::from_utf8_lossy(&named.stderr)
        );
        let named_extension = home_dir
            .join(".custom-omp")
            .join("profiles")
            .join("work")
            .join("agent")
            .join("extensions")
            .join("dcg-guard.ts");
        assert!(
            named_extension.is_file(),
            "active profile receives extension"
        );
        assert!(
            !ignored_override.join("extensions/dcg-guard.ts").exists(),
            "named profiles must ignore PI_CODING_AGENT_DIR"
        );

        let second_home = temp.path().join("second-home");
        let explicit_agent_dir = temp.path().join("explicit-agent-dir");
        std::fs::create_dir_all(&second_home).expect("second HOME");
        let empty_current_profile = Command::new(dcg_binary())
            .args(["install", "--omp"])
            .env_clear()
            .env("HOME", &second_home)
            .env("USERPROFILE", &second_home)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("OMP_PROFILE", "")
            .env("PI_PROFILE", "Upper")
            .env("PI_CODING_AGENT_DIR", &explicit_agent_dir)
            .current_dir(temp.path())
            .output()
            .expect("install explicit-empty OMP profile");
        assert!(
            empty_current_profile.status.success(),
            "explicit-empty profile install: {}",
            String::from_utf8_lossy(&empty_current_profile.stderr)
        );
        assert!(
            explicit_agent_dir.join("extensions/dcg-guard.ts").is_file(),
            "an explicitly empty OMP_PROFILE suppresses PI_PROFILE and restores the agent-dir override"
        );
        assert!(
            !second_home
                .join(".omp/profiles/Upper/agent/extensions/dcg-guard.ts")
                .exists(),
            "a losing invalid PI_PROFILE must not be read when OMP_PROFILE is present"
        );

        let default_home = temp.path().join("default-home");
        let default_agent_dir = temp.path().join("default-agent-dir");
        std::fs::create_dir_all(&default_home).expect("default HOME");
        let explicit_default_profile = Command::new(dcg_binary())
            .args(["install", "--omp"])
            .env_clear()
            .env("HOME", &default_home)
            .env("USERPROFILE", &default_home)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("OMP_PROFILE", "default")
            .env("PI_PROFILE", "Upper")
            .env("PI_CODING_AGENT_DIR", &default_agent_dir)
            .current_dir(temp.path())
            .output()
            .expect("install explicit default OMP profile");
        assert!(
            explicit_default_profile.status.success(),
            "explicit default profile install: {}",
            String::from_utf8_lossy(&explicit_default_profile.stderr)
        );
        assert!(
            default_agent_dir.join("extensions/dcg-guard.ts").is_file(),
            "the explicit default sentinel suppresses PI_PROFILE and selects default-profile storage"
        );

        let legacy_home = temp.path().join("legacy-home");
        let legacy_override = temp.path().join("ignored-legacy-agent-dir");
        std::fs::create_dir_all(&legacy_home).expect("legacy HOME");
        let legacy_fallback = Command::new(dcg_binary())
            .args(["install", "--omp"])
            .env_clear()
            .env("HOME", &legacy_home)
            .env("USERPROFILE", &legacy_home)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("PI_PROFILE", "legacy-profile")
            .env("PI_CODING_AGENT_DIR", &legacy_override)
            .current_dir(temp.path())
            .output()
            .expect("install legacy fallback OMP profile");
        assert!(
            legacy_fallback.status.success(),
            "legacy fallback profile install: {}",
            String::from_utf8_lossy(&legacy_fallback.stderr)
        );
        assert!(
            legacy_home
                .join(".omp/profiles/legacy-profile/agent/extensions/dcg-guard.ts")
                .is_file(),
            "PI_PROFILE selects a named profile only when OMP_PROFILE is absent"
        );
        assert!(
            !legacy_override.join("extensions/dcg-guard.ts").exists(),
            "a named PI_PROFILE must ignore PI_CODING_AGENT_DIR like a named OMP_PROFILE"
        );

        let third_home = temp.path().join("third-home");
        std::fs::create_dir_all(&third_home).expect("third HOME");
        let absolute_looking_config = Command::new(dcg_binary())
            .args(["install", "--omp"])
            .env_clear()
            .env("HOME", &third_home)
            .env("USERPROFILE", &third_home)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("PI_CONFIG_DIR", "/etc/omp-cfg")
            .current_dir(temp.path())
            .output()
            .expect("install absolute-looking OMP config root");
        assert!(
            absolute_looking_config.status.success(),
            "absolute-looking config install: {}",
            String::from_utf8_lossy(&absolute_looking_config.stderr)
        );
        assert!(
            third_home
                .join("etc/omp-cfg/agent/extensions/dcg-guard.ts")
                .is_file(),
            "Node path.join parity keeps an absolute-looking PI_CONFIG_DIR under HOME"
        );
    }

    #[test]
    fn install_omp_suppresses_only_stale_profile_derived_agent_dir() {
        let temp = tempfile::tempdir().expect("tempdir");
        let xdg_config_dir = temp.path().join("xdg-config");
        std::fs::create_dir_all(&xdg_config_dir).expect("XDG config dir");
        let config_name = ".custom-omp";

        let run_install = |home: &std::path::Path,
                           omp_profile: &str,
                           pi_profile: &str,
                           agent_dir: &std::path::Path| {
            std::fs::create_dir_all(home).expect("isolated HOME");
            Command::new(dcg_binary())
                .args(["install", "--omp"])
                .env_clear()
                .env("HOME", home)
                .env("USERPROFILE", home)
                .env("XDG_CONFIG_HOME", &xdg_config_dir)
                .env("PI_CONFIG_DIR", config_name)
                .env("OMP_PROFILE", omp_profile)
                .env("PI_PROFILE", pi_profile)
                .env("PI_CODING_AGENT_DIR", agent_dir)
                .current_dir(temp.path())
                .output()
                .expect("install OMP extension for provenance fixture")
        };

        // This is the exact environment a child can inherit after its parent
        // selected `work`, followed by a higher-priority explicit default
        // selection. OMP treats the inherited agent dir as stale for both
        // default sentinels.
        for (label, omp_profile) in [("empty", ""), ("default", "default")] {
            let home = temp.path().join(format!("stale-{label}-home"));
            let derived_agent = home
                .join(config_name)
                .join("profiles")
                .join("work")
                .join("agent");
            let output = run_install(&home, omp_profile, "work", &derived_agent);
            assert!(
                output.status.success(),
                "stale-derived {label} install: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                home.join(config_name)
                    .join("agent/extensions/dcg-guard.ts")
                    .is_file(),
                "{label} selects the default agent directory"
            );
            assert!(
                !derived_agent.join("extensions/dcg-guard.ts").exists(),
                "the exact profile-derived override must be suppressed"
            );
        }

        // OMP normalizes PI_CONFIG_DIR with Node path.join before exporting the
        // derived agent path. dcg must normalize first too, otherwise the same
        // stale child-process value looks like a custom override byte-for-byte.
        let normalized_home = temp.path().join("normalized-config-home");
        std::fs::create_dir_all(&normalized_home).expect("normalized HOME");
        let normalized_root = normalized_home.join("normalized-omp");
        let normalized_derived = normalized_root.join("profiles").join("work").join("agent");
        let normalized = Command::new(dcg_binary())
            .args(["install", "--omp"])
            .env_clear()
            .env("HOME", &normalized_home)
            .env("USERPROFILE", &normalized_home)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("PI_CONFIG_DIR", "outer/../normalized-omp")
            .env("OMP_PROFILE", "default")
            .env("PI_PROFILE", "work")
            .env("PI_CODING_AGENT_DIR", &normalized_derived)
            .current_dir(temp.path())
            .output()
            .expect("install OMP extension with normalized stale provenance");
        assert!(
            normalized.status.success(),
            "normalized stale-derived install: {}",
            String::from_utf8_lossy(&normalized.stderr)
        );
        assert!(
            normalized_root
                .join("agent/extensions/dcg-guard.ts")
                .is_file(),
            "the normalized default agent directory receives the extension"
        );
        assert!(
            !normalized_derived.join("extensions/dcg-guard.ts").exists(),
            "the normalized exact profile derivation must be suppressed"
        );

        let custom_home = temp.path().join("custom-home");
        let custom_agent = temp.path().join("operator-custom-agent");
        let custom = run_install(&custom_home, "", "work", &custom_agent);
        assert!(
            custom.status.success(),
            "custom override install: {}",
            String::from_utf8_lossy(&custom.stderr)
        );
        assert!(
            custom_agent.join("extensions/dcg-guard.ts").is_file(),
            "a genuine operator override survives"
        );

        let sibling_home = temp.path().join("sibling-home");
        let sibling_agent = sibling_home
            .join(config_name)
            .join("profiles")
            .join("work")
            .join("agent-sibling");
        let sibling = run_install(&sibling_home, "default", "work", &sibling_agent);
        assert!(
            sibling.status.success(),
            "sibling override install: {}",
            String::from_utf8_lossy(&sibling.stderr)
        );
        assert!(
            sibling_agent.join("extensions/dcg-guard.ts").is_file(),
            "a near-match must not be mistaken for derived provenance"
        );

        let invalid_home = temp.path().join("invalid-loser-home");
        let invalid_profile_agent = invalid_home
            .join(config_name)
            .join("profiles")
            .join("Upper")
            .join("agent");
        let invalid_loser = run_install(&invalid_home, "", "Upper", &invalid_profile_agent);
        assert!(
            invalid_loser.status.success(),
            "invalid losing profile remains ignored: {}",
            String::from_utf8_lossy(&invalid_loser.stderr)
        );
        assert!(
            invalid_profile_agent
                .join("extensions/dcg-guard.ts")
                .is_file(),
            "an invalid lower-priority profile supplies no stale-path provenance"
        );
    }

    #[test]
    fn install_omp_rejects_invalid_explicit_profiles_without_writing() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (home_dir, xdg_config_dir, _bin_dir) = setup_doctor_env(&temp);
        let explicit_agent_dir = temp.path().join("explicit-agent-dir");

        let invalid_winner = Command::new(dcg_binary())
            .args(["install", "--omp"])
            .env_clear()
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("OMP_PROFILE", "..")
            .env("PI_PROFILE", "valid-fallback")
            .env("PI_CODING_AGENT_DIR", &explicit_agent_dir)
            .current_dir(temp.path())
            .output()
            .expect("reject invalid winning OMP_PROFILE");
        assert!(
            !invalid_winner.status.success(),
            "OMP rejects the same invalid explicit profile at startup"
        );
        let stderr = String::from_utf8_lossy(&invalid_winner.stderr);
        assert!(
            stderr.contains("OMP_PROFILE") && stderr.contains("Invalid OMP profile"),
            "diagnostic must identify the winning invalid variable: {stderr}"
        );
        assert!(
            !explicit_agent_dir.join("extensions/dcg-guard.ts").exists(),
            "invalid OMP_PROFILE must not silently write through PI_CODING_AGENT_DIR"
        );
        assert!(
            !home_dir
                .join(".omp/profiles/valid-fallback/agent/extensions/dcg-guard.ts")
                .exists(),
            "OMP_PROFILE presence must still suppress PI_PROFILE fallback"
        );
        assert!(
            !home_dir.join(".omp/agent/extensions/dcg-guard.ts").exists(),
            "invalid OMP_PROFILE must not collapse to the default profile"
        );

        let project_cwd = temp.path().join("project-with-invalid-profile");
        std::fs::create_dir_all(&project_cwd).expect("project cwd");
        let invalid_legacy = Command::new(dcg_binary())
            .args(["install", "--omp", "--project"])
            .env_clear()
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("PI_PROFILE", "Upper")
            .current_dir(&project_cwd)
            .output()
            .expect("reject invalid PI_PROFILE for project install");
        assert!(
            !invalid_legacy.status.success(),
            "project installation cannot be healthy when OMP itself rejects startup"
        );
        let stderr = String::from_utf8_lossy(&invalid_legacy.stderr);
        assert!(
            stderr.contains("PI_PROFILE") && stderr.contains("Invalid OMP profile"),
            "legacy-source diagnostic must name PI_PROFILE: {stderr}"
        );
        assert!(
            !project_cwd.join(".omp/extensions/dcg-guard.ts").exists(),
            "invalid PI_PROFILE must fail before a project extension write"
        );
    }

    #[test]
    #[cfg(unix)]
    fn install_omp_rejects_non_unicode_winning_profile_without_writing() {
        use std::os::unix::ffi::OsStringExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let (home_dir, xdg_config_dir, _bin_dir) = setup_doctor_env(&temp);
        let explicit_agent_dir = temp.path().join("explicit-agent-dir");
        let invalid = std::ffi::OsString::from_vec(b"work-\xff".to_vec());

        let output = Command::new(dcg_binary())
            .args(["install", "--omp"])
            .env_clear()
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("OMP_PROFILE", invalid)
            .env("PI_PROFILE", "valid-fallback")
            .env("PI_CODING_AGENT_DIR", &explicit_agent_dir)
            .current_dir(temp.path())
            .output()
            .expect("reject non-Unicode winning OMP_PROFILE");
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("OMP_PROFILE") && stderr.contains("valid Unicode"),
            "non-Unicode diagnostic must identify the winning variable: {stderr}"
        );
        assert!(
            !explicit_agent_dir.join("extensions/dcg-guard.ts").exists(),
            "non-Unicode OMP_PROFILE must not collapse to the agent-dir override"
        );
        assert!(
            !home_dir
                .join(".omp/profiles/valid-fallback/agent/extensions/dcg-guard.ts")
                .exists(),
            "a non-Unicode winning variable must not expose PI_PROFILE fallback"
        );
        assert!(
            !home_dir.join(".omp/agent/extensions/dcg-guard.ts").exists(),
            "non-Unicode OMP_PROFILE must not collapse to the default profile"
        );
    }

    #[test]
    fn doctor_rejects_invalid_profile_even_with_a_project_extension() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (home_dir, xdg_config_dir, bin_dir) = setup_doctor_env(&temp);
        let extension = temp.path().join(".omp/extensions/dcg-guard.ts");
        std::fs::create_dir_all(extension.parent().expect("extension parent"))
            .expect("project OMP extension directory");
        let original = b"// dcg-omp-extension: generated\n";
        std::fs::write(&extension, original).expect("project OMP extension");

        let output = Command::new(dcg_binary())
            .env_clear()
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("PATH", &bin_dir)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env("OMP_PROFILE", "../escape")
            .env("PI_PROFILE", "valid-fallback")
            .current_dir(temp.path())
            .args(["doctor", "--format", "json", "--strict"])
            .output()
            .expect("run strict doctor with invalid OMP profile");
        assert!(
            !output.status.success(),
            "a marker alone cannot make an OMP-invalid environment healthy"
        );
        let report: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("doctor JSON output");
        let omp_check = report["checks"]
            .as_array()
            .expect("checks array")
            .iter()
            .find(|check| check["id"] == "omp_extension")
            .expect("OMP doctor check");
        assert_eq!(omp_check["status"], "error");
        assert!(
            omp_check["message"]
                .as_str()
                .is_some_and(|message| message.contains("OMP_PROFILE")),
            "doctor must report the invalid winning variable: {omp_check}"
        );
        assert_eq!(
            std::fs::read(&extension).expect("read project extension after doctor"),
            original,
            "read-only doctor must preserve the existing extension byte-for-byte"
        );
    }

    #[test]
    fn doctor_reports_invalid_legacy_profile_without_other_omp_signals() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (home_dir, xdg_config_dir, bin_dir) = setup_doctor_env(&temp);

        let output = Command::new(dcg_binary())
            .env_clear()
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("PATH", &bin_dir)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env("PI_PROFILE", "Upper")
            .current_dir(temp.path())
            .args(["doctor", "--format", "json", "--strict"])
            .output()
            .expect("run strict doctor with only an invalid legacy profile signal");
        assert!(
            !output.status.success(),
            "invalid PI_PROFILE must not disappear merely because no OMP binary or config root is visible"
        );
        let report: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("doctor JSON output");
        let omp_check = report["checks"]
            .as_array()
            .expect("checks array")
            .iter()
            .find(|check| check["id"] == "omp_extension")
            .expect("PI_PROFILE presence must trigger the OMP doctor check");
        assert_eq!(omp_check["status"], "error");
        assert!(
            omp_check["message"]
                .as_str()
                .is_some_and(|message| message.contains("PI_PROFILE")),
            "doctor must identify the invalid legacy variable: {omp_check}"
        );
    }

    #[test]
    #[cfg(windows)]
    fn doctor_rejects_drive_qualified_omp_config_root() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (home_dir, xdg_config_dir, bin_dir) = setup_doctor_env(&temp);
        let output = Command::new(dcg_binary())
            .env_clear()
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("PATH", &bin_dir)
            .env("OMP_PROFILE", "work")
            .env("PI_CONFIG_DIR", r"C:\dcg-invalid-omp-config-root")
            .current_dir(temp.path())
            .args(["doctor", "--format", "json", "--strict"])
            .output()
            .expect("run dcg doctor with invalid OMP config root");

        assert!(
            !output.status.success(),
            "strict doctor must reject an OMP path that could escape HOME"
        );
        let report: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("doctor JSON output");
        let omp_check = report["checks"]
            .as_array()
            .expect("checks array")
            .iter()
            .find(|check| check["id"] == "omp_extension")
            .expect("OMP doctor check");
        assert_eq!(omp_check["status"], "error");
        assert!(
            omp_check["message"]
                .as_str()
                .is_some_and(|message| message.contains("PI_CONFIG_DIR")),
            "doctor should identify the invalid config variable: {omp_check}"
        );
    }

    #[test]
    fn config_show_produces_output() {
        let output = run_dcg(&["config"]);

        // Config command should produce some output about current config
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{stdout}{stderr}");

        assert!(!combined.is_empty(), "config should produce some output");
    }

    #[test]
    fn config_honors_dcg_config_override() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home_dir = temp.path().join("home");
        let xdg_config_dir = temp.path().join("xdg_config");
        std::fs::create_dir_all(&home_dir).expect("HOME dir");
        std::fs::create_dir_all(&xdg_config_dir).expect("XDG_CONFIG_HOME dir");

        let cfg_path = temp.path().join("explicit_config.toml");
        std::fs::write(&cfg_path, "[general]\nverbose = true\n").expect("write config");

        let output = Command::new(dcg_binary())
            .env_clear()
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("DCG_CONFIG", &cfg_path)
            .current_dir(temp.path())
            .arg("config")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("run dcg config");

        assert!(output.status.success(), "dcg config should succeed");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("Verbose: true"),
            "expected config from DCG_CONFIG to take effect\nstdout:\n{stdout}"
        );
        assert!(
            stdout.contains("DCG_CONFIG:"),
            "expected config sources to mention DCG_CONFIG\nstdout:\n{stdout}"
        );
    }

    #[test]
    fn doctor_reports_missing_dcg_config_override() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home_dir = temp.path().join("home");
        let xdg_config_dir = temp.path().join("xdg_config");
        std::fs::create_dir_all(&home_dir).expect("HOME dir");
        std::fs::create_dir_all(&xdg_config_dir).expect("XDG_CONFIG_HOME dir");

        let missing = temp.path().join("missing_config.toml");

        let output = Command::new(dcg_binary())
            .env_clear()
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("DCG_CONFIG", &missing)
            .current_dir(temp.path())
            .arg("doctor")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("run dcg doctor");

        assert!(output.status.success(), "dcg doctor should run");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(combined.contains("DCG_CONFIG:"));
        assert!(combined.contains(&missing.display().to_string()));
        assert!(
            combined.contains("[missing; full]"),
            "expected doctor to surface missing DCG_CONFIG\noutput:\n{combined}"
        );
    }

    #[test]
    fn doctor_pretty_output_basics() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (home_dir, xdg_config_dir, bin_dir) = setup_doctor_env(&temp);

        let output = Command::new(dcg_binary())
            .env_clear()
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("PATH", &bin_dir)
            .env("NO_COLOR", "1")
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .current_dir(temp.path())
            .arg("doctor")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("run dcg doctor");

        assert!(output.status.success(), "dcg doctor should succeed");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            combined.contains("dcg doctor"),
            "expected header in doctor output\noutput:\n{combined}"
        );
        if let Some(machine_config) = loaded_machine_config(&combined) {
            assert!(
                combined.contains("Checking configuration... ")
                    && !combined.contains("USING DEFAULTS"),
                "{} is loaded, so doctor must not claim built-in defaults\noutput:\n{combined}",
                machine_config.display()
            );
        } else {
            assert!(
                combined.contains("Checking configuration... USING DEFAULTS"),
                "expected defaults notice\noutput:\n{combined}"
            );
        }
        assert!(
            combined.contains("Checking allowlist entries... NONE"),
            "expected allowlist none notice\noutput:\n{combined}"
        );
    }

    #[test]
    fn doctor_reports_legacy_claude_matchers_missing_monitor() {
        for matcher in ["Bash", "Bash|PowerShell"] {
            let temp = tempfile::tempdir().expect("tempdir");
            let (home_dir, xdg_config_dir, bin_dir) = setup_doctor_env(&temp);
            let claude_dir = home_dir.join(".claude");
            std::fs::create_dir_all(&claude_dir).expect("claude dir");
            let settings_path = claude_dir.join("settings.json");
            let original = serde_json::to_vec_pretty(&serde_json::json!({
                "hooks": { "PreToolUse": [{
                    "matcher": matcher,
                    "hooks": [{ "type": "command", "command": dcg_binary() }],
                }] },
            }))
            .expect("settings JSON");
            std::fs::write(&settings_path, &original).expect("settings");

            let output = Command::new(dcg_binary())
                .env_clear()
                .env("HOME", &home_dir)
                .env("USERPROFILE", &home_dir)
                .env("XDG_CONFIG_HOME", &xdg_config_dir)
                .env("PATH", &bin_dir)
                .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
                .current_dir(temp.path())
                .args(["doctor", "--format", "json"])
                .output()
                .expect("doctor JSON");
            assert!(output.status.success());
            let report: serde_json::Value =
                serde_json::from_slice(&output.stdout).expect("doctor report");
            let check = report["checks"]
                .as_array()
                .expect("checks")
                .iter()
                .find(|check| check["id"] == "hook_wiring")
                .expect("hook wiring check");
            assert_eq!(check["status"], "error", "{matcher}: {check}");
            assert!(
                check["message"].as_str().unwrap().contains("wrong matcher"),
                "{matcher}: {check}"
            );
            assert!(
                check["remediation"]
                    .as_str()
                    .unwrap()
                    .contains("Bash|PowerShell|Monitor"),
                "{matcher}: {check}"
            );
            assert_eq!(std::fs::read(&settings_path).unwrap(), original);
        }
    }

    #[test]
    fn doctor_fix_installs_hook_and_config() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (home_dir, xdg_config_dir, bin_dir) = setup_doctor_env(&temp);

        let claude_dir = home_dir.join(".claude");
        std::fs::create_dir_all(&claude_dir).expect("claude dir");
        let settings_path = claude_dir.join("settings.json");
        std::fs::write(
            &settings_path,
            r#"{
  "theme": "dark",
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash|PowerShell",
      "hooks": [
        {"type": "command", "command": "dcg"},
        {"type": "command", "command": "coexisting-hook"}
      ]
    }]
  }
}"#,
        )
        .expect("write settings");

        let output = Command::new(dcg_binary())
            .env_clear()
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("PATH", &bin_dir)
            .env("NO_COLOR", "1")
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .current_dir(temp.path())
            .args(["doctor", "--fix"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("run dcg doctor --fix");

        assert!(output.status.success(), "dcg doctor --fix should succeed");

        let settings = std::fs::read_to_string(&settings_path).expect("read settings");
        let settings_json: serde_json::Value =
            serde_json::from_str(&settings).expect("parse settings");
        let hooks = settings_json
            .get("hooks")
            .and_then(|h| h.get("PreToolUse"))
            .and_then(|arr| arr.as_array())
            .expect("PreToolUse array");
        let expected_dcg = dcg_binary().to_string_lossy().into_owned();
        let has_dcg = hooks.iter().any(|entry| {
            entry.get("matcher").and_then(|m| m.as_str()) == Some("Bash|PowerShell|Monitor")
                && entry
                    .get("hooks")
                    .and_then(|h| h.as_array())
                    .is_some_and(|hooks| {
                        hooks.iter().any(|hook| {
                            hook.get("command")
                                .and_then(|c| c.as_str())
                                .is_some_and(|command| command.contains(&expected_dcg))
                        })
                    })
        });
        assert!(
            has_dcg,
            "expected dcg hook to use the absolute test binary path"
        );
        assert_eq!(settings_json["theme"], "dark");
        assert!(
            hooks.iter().any(|entry| {
                entry
                    .get("hooks")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|entry_hooks| {
                        entry_hooks.iter().any(|hook| {
                            hook.get("command").and_then(serde_json::Value::as_str)
                                == Some("coexisting-hook")
                        })
                    })
            }),
            "doctor --fix must preserve coexisting hooks"
        );

        let config_path = xdg_config_dir.join("dcg").join("config.toml");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if let Some(machine_config) = loaded_machine_config(&combined) {
            // A loaded trusted layer is not "no configuration", so there is
            // nothing for --fix to create.
            assert!(
                !config_path.exists(),
                "{} is loaded; doctor --fix must not add a default user config\noutput:\n{combined}",
                machine_config.display()
            );
            return;
        }
        let config_contents = std::fs::read_to_string(&config_path)
            .unwrap_or_else(|error| panic!("read config.toml: {error}\noutput:\n{combined}"));
        assert!(
            !config_contents.trim().is_empty(),
            "expected config.toml to be created"
        );
    }

    #[cfg(unix)]
    #[test]
    fn project_install_hook_runs_without_interactive_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(temp.path().join(".git")).expect(".git dir");

        let binary = dcg_binary();
        let install = Command::new(&binary)
            .env_clear()
            .current_dir(temp.path())
            .args(["install", "--project"])
            .output()
            .expect("run project hook install");
        assert!(
            install.status.success(),
            "project install failed: {}",
            String::from_utf8_lossy(&install.stderr)
        );

        let settings_path = temp.path().join(".claude").join("settings.json");
        let settings: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&settings_path).expect("read project settings"))
                .expect("parse project settings");
        let command = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
            .as_str()
            .expect("hook command");
        assert_ne!(command, "dcg");
        assert!(
            command.contains(binary.to_string_lossy().as_ref()),
            "hook must name the exact test binary: {command}"
        );

        let mut hook = Command::new("/bin/sh")
            .args(["-c", command])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("DCG_NO_SELF_HEAL", "1")
            .current_dir(temp.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("launch hook through non-interactive /bin/sh");
        hook.stdin
            .take()
            .expect("hook stdin")
            .write_all(br#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#)
            .expect("write hook input");
        let output = hook.wait_with_output().expect("wait for hook");
        assert!(
            output.status.success(),
            "absolute hook invocation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.stdout.is_empty(),
            "safe hook invocation must remain silent"
        );

        let mut destructive_hook = Command::new("/bin/sh")
            .args(["-c", command])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("DCG_NO_SELF_HEAL", "1")
            .current_dir(temp.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("launch destructive hook check through non-interactive /bin/sh");
        destructive_hook
            .stdin
            .take()
            .expect("hook stdin")
            .write_all(br#"{"tool_name":"Bash","tool_input":{"command":"git reset --hard"}}"#)
            .expect("write destructive hook input");
        let destructive_output = destructive_hook
            .wait_with_output()
            .expect("wait for destructive hook check");
        assert!(
            destructive_output.status.success(),
            "dcg denials use protocol JSON with exit 0: {}",
            String::from_utf8_lossy(&destructive_output.stderr)
        );
        let denial: serde_json::Value =
            serde_json::from_slice(&destructive_output.stdout).expect("parse denial JSON");
        assert_eq!(
            denial["hookSpecificOutput"]["permissionDecision"], "deny",
            "absolute hook must actively deny a destructive command"
        );
    }

    #[test]
    fn doctor_json_output_is_valid() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (home_dir, xdg_config_dir, bin_dir) = setup_doctor_env(&temp);

        let output = Command::new(dcg_binary())
            .env_clear()
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("PATH", &bin_dir)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .current_dir(temp.path())
            .args(["doctor", "--format", "json"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("run dcg doctor --format json");

        assert!(
            output.status.success(),
            "dcg doctor --format json should succeed"
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        let parsed: serde_json::Value =
            serde_json::from_str(&stdout).expect("doctor JSON output should parse");
        assert_eq!(parsed["schema_version"], 1);
        let checks = parsed["checks"].as_array().expect("checks array");
        assert!(
            checks.iter().any(|c| c["id"] == "binary_path"),
            "expected binary_path check in JSON output"
        );
    }

    /// Keep allowlist audits isolated from the operator's policy and session.
    fn allowlist_doctor_command(temp: &tempfile::TempDir) -> Command {
        let mut command = Command::new(dcg_binary());
        command
            .env_clear()
            .env("HOME", temp.path().join("home"))
            .env("USERPROFILE", temp.path().join("home"))
            .env("XDG_CONFIG_HOME", temp.path().join("xdg_config"))
            .env("ProgramData", temp.path().join("system"))
            .env("TMPDIR", temp.path())
            .env("TEMP", temp.path())
            .env("TMP", temp.path())
            .env("PATH", temp.path().join("bin"))
            .env("USER", "doctor-audit-reviewer")
            .env("DCG_SESSION_ID", "doctor-audit-session")
            .env(
                "DCG_ALLOWLIST_SYSTEM_PATH",
                temp.path().join("system-allowlist.toml"),
            )
            .env("DCG_SELF_HEAL_HOOK", "0")
            .env("DCG_NO_UPDATE_CHECK", "1")
            .env("NO_COLOR", "1")
            .env("DCG_NO_RICH", "1")
            .current_dir(temp.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn write_doctor_allowlist(path: &std::path::Path, contents: &str) {
        std::fs::create_dir_all(path.parent().expect("allowlist parent"))
            .expect("allowlist directory");
        std::fs::write(path, contents).expect("write allowlist fixture");
    }

    fn parse_allowlist_doctor_report(output: &std::process::Output) -> serde_json::Value {
        // Parsing the entire stream also rejects a second document or prose
        // accidentally printed by doctor --fix before the JSON report.
        let report: serde_json::Value =
            serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
                panic!(
                    "invalid doctor JSON ({e}): stdout={} stderr={}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )
            });
        assert_eq!(report["schema_version"], 1, "{report}");
        let fields = report.as_object().expect("doctor report object");
        assert_eq!(
            fields.len(),
            5,
            "doctor v1 top-level shape changed: {report}"
        );
        assert!(report["issues"].is_u64(), "{report}");
        assert!(report["fixed"].is_u64(), "{report}");
        assert!(report["ok"].is_boolean(), "{report}");
        for check in report["checks"].as_array().expect("doctor checks") {
            assert!(check["id"].is_string(), "{check}");
            assert!(check["name"].is_string(), "{check}");
            assert!(check["message"].is_string(), "{check}");
            assert!(
                matches!(
                    check["status"].as_str(),
                    Some("ok" | "warning" | "error" | "skipped")
                ),
                "{check}"
            );
            if let Some(remediation) = check.get("remediation") {
                assert!(remediation.is_string(), "{check}");
            }
            if let Some(fixed) = check.get("fixed") {
                assert!(fixed.is_boolean(), "{check}");
            }
        }
        report
    }

    fn allowlist_doctor_check(report: &serde_json::Value) -> &serde_json::Value {
        report["checks"]
            .as_array()
            .expect("doctor checks")
            .iter()
            .find(|check| check["id"] == "allowlists")
            .expect("existing allowlists check")
    }

    /// #545's exact reproduction must produce actionable warnings in every
    /// renderer, while the diagnostic and --fix preserve the granted policy.
    #[test]
    fn doctor_warns_about_global_indefinite_user_rule_issue_545() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (_, xdg_config, _) = setup_doctor_env(&temp);
        let path = xdg_config.join("dcg/allowlist.toml");
        let added = allowlist_doctor_command(&temp)
            .args([
                "allowlist",
                "add",
                "core.filesystem:rm-rf-general",
                "-r",
                "test",
                "--user",
            ])
            .output()
            .expect("run reported allowlist add command");
        assert!(
            added.status.success(),
            "allowlist add: {}",
            String::from_utf8_lossy(&added.stderr)
        );
        let original = std::fs::read(&path).expect("CLI-created allowlist");
        let file: toml::Value =
            toml::from_str(std::str::from_utf8(&original).expect("allowlist UTF-8"))
                .expect("allowlist TOML");
        let entry = &file["allow"][0];
        let added_at = entry["added_at"].as_str().expect("CLI audit timestamp");
        assert!(entry.get("expires_at").is_none());
        assert!(entry.get("paths").is_none());

        for args in [
            vec!["doctor", "--format", "json"],
            vec!["doctor", "--strict", "--format", "json"],
            vec!["doctor", "--fix", "--strict", "--format", "json"],
        ] {
            let output = allowlist_doctor_command(&temp)
                .args(&args)
                .output()
                .expect("run allowlist doctor");
            let report = parse_allowlist_doctor_report(&output);
            assert!(output.status.success(), "{args:?}: {report}");
            assert_eq!(
                report["ok"], true,
                "warnings keep the exit contract: {report}"
            );
            let check = allowlist_doctor_check(&report);
            assert_eq!(check["status"], "warning", "{args:?}: {check}");
            let message = check["message"].as_str().expect("allowlist message");
            for expected in [
                "active globally scoped, indefinite allowlist exception",
                "core.filesystem:rm-rf-general",
                "HIGH RISK",
                "destructive filesystem protection",
                "user:",
                "test",
                "doctor-audit-reviewer",
                added_at,
                &path.display().to_string(),
            ] {
                assert!(message.contains(expected), "missing {expected:?}: {check}");
            }
            let remediation = check["remediation"].as_str().expect("audit remediation");
            for expected in ["paths", "expires_at", "allow-once"] {
                assert!(
                    remediation.contains(expected),
                    "missing actionable {expected:?}: {check}"
                );
            }
            assert_ne!(
                check["fixed"], true,
                "doctor cannot fix an exception: {check}"
            );
            let fixed_checks = report["checks"]
                .as_array()
                .expect("checks")
                .iter()
                .filter(|check| check["fixed"] == true)
                .count();
            assert_eq!(
                report["fixed"],
                serde_json::json!(fixed_checks),
                "allowlist warnings must not receive an extra fix count: {report}"
            );
            assert_eq!(
                std::fs::read(&path).expect("allowlist after doctor"),
                original,
                "{args:?} must preserve allowlist bytes"
            );
        }

        let pretty = allowlist_doctor_command(&temp)
            .args(["doctor", "--strict"])
            .output()
            .expect("run pretty doctor");
        assert!(pretty.status.success());
        let stdout = String::from_utf8_lossy(&pretty.stdout);
        assert!(
            stdout.contains("Checking allowlist entries... WARNING"),
            "{stdout}"
        );
        assert!(stdout.contains("core.filesystem:rm-rf-general"), "{stdout}");
        assert!(
            stdout.contains("destructive filesystem protection"),
            "{stdout}"
        );
        assert_eq!(std::fs::read(&path).expect("unchanged allowlist"), original);
    }

    #[test]
    fn doctor_recognizes_effectively_global_allowlist_paths_and_metadata() {
        for extra in [
            "",
            "paths = []",
            "paths = [\"*\"]",
            "paths = [\"**/\"]",
            "paths = [\"**/*\"]",
            "paths = [\"**/**\"]",
            "paths = [\"**/**/**\"]",
            "paths = [\"/reviewed/workspace/**\", \"*\"]",
            "paths = [\"/reviewed/workspace/**\", \"**/*\"]",
            "session = false",
            "conditions = { AUDIT_REVIEWED = \"yes\" }",
            "environments = [\"not-the-current-environment\"]",
            "context = \"string-argument\"",
        ] {
            let temp = tempfile::tempdir().expect("tempdir");
            let (_, xdg_config, _) = setup_doctor_env(&temp);
            let path = xdg_config.join("dcg/allowlist.toml");
            let original = format!(
                "[[allow]]\nrule = \"core.git:reset-hard\"\nreason = \"reviewed exception\"\n{extra}\n"
            );
            write_doctor_allowlist(&path, &original);
            let output = allowlist_doctor_command(&temp)
                .env("AUDIT_REVIEWED", "yes")
                .args(["doctor", "--format", "json"])
                .output()
                .expect("run global-scope audit");
            let report = parse_allowlist_doctor_report(&output);
            let check = allowlist_doctor_check(&report);
            assert_eq!(check["status"], "warning", "{extra:?}: {check}");
            let message = check["message"].as_str().expect("message");
            assert!(
                message.contains("active globally scoped, indefinite allowlist exception"),
                "{extra:?} must not hide an unrestricted grant: {check}"
            );
            assert!(message.contains("destructive Git protection"), "{check}");
            assert!(message.contains("core.git:reset-hard"), "{check}");
            assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        }
    }

    #[test]
    fn doctor_audits_only_active_rules_including_external_packs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (_, xdg_config, _) = setup_doctor_env(&temp);
        let config_dir = xdg_config.join("dcg");
        let allowlist_path = config_dir.join("allowlist.toml");
        let pack_path = config_dir.join("packs/custom.yaml");
        std::fs::create_dir_all(pack_path.parent().expect("pack parent"))
            .expect("custom pack directory");
        std::fs::write(
            &pack_path,
            r#"
schema_version: 1
id: custom.deploy
name: Custom Deploy Rules
version: 1.0.0
keywords: [deploy]
destructive_patterns:
  - name: prod-deploy
    pattern: deploy\s+--env\s*=?\s*prod
    severity: critical
    description: Direct production deployment blocked
"#,
        )
        .expect("valid external pack fixture");

        let original = [
            "unknown.audit.pack:destroy",
            "core:reset-hard",
            "core.git:typo",
            "core.git:reset-*",
            "core.git:reset-hard",
            "containers.docker:system-prune",
            "custom.deploy:prod-deploy",
            "custom.deploy:missing-rule",
        ]
        .map(|rule| format!("[[allow]]\nrule = \"{rule}\"\nreason = \"namespace audit\"\n"))
        .join("\n");
        write_doctor_allowlist(&allowlist_path, &original);
        let quoted_pack_path = toml::Value::String(pack_path.to_string_lossy().into_owned());

        for (optional_active, config) in [
            (
                false,
                "[packs]\nenabled = [\"core\", \"containers.docker\", \"unknown.audit.pack\"]\ndisabled = [\"containers.docker\"]\n"
                    .to_string(),
            ),
            (
                true,
                format!(
                    "[packs]\nenabled = [\"core\", \"containers.docker\", \"unknown.audit.pack\"]\ncustom_paths = [{quoted_pack_path}]\n"
                ),
            ),
        ] {
            std::fs::write(config_dir.join("config.toml"), config).expect("active pack config");
            let output = allowlist_doctor_command(&temp)
                .args(["doctor", "--format", "json"])
                .output()
                .expect("audit configured pack namespaces");
            let report = parse_allowlist_doctor_report(&output);
            assert!(output.status.success(), "{report}");
            let check = allowlist_doctor_check(&report);
            assert_eq!(check["status"], "warning", "{check}");
            let message = check["message"].as_str().expect("message");
            for (rule, expected_active) in [
                ("unknown.audit.pack:destroy", false),
                ("core:reset-hard", false),
                ("core.git:typo", false),
                ("core.git:reset-*", false),
                ("core.git:reset-hard", true),
                ("containers.docker:system-prune", optional_active),
                ("custom.deploy:prod-deploy", optional_active),
                ("custom.deploy:missing-rule", false),
            ] {
                let warning = format!(
                    "active globally scoped, indefinite allowlist exception for rule {rule}"
                );
                assert_eq!(
                    message.contains(&warning),
                    expected_active,
                    "optional_active={optional_active}, rule={rule}: {check}"
                );
            }
            assert_eq!(
                message
                    .matches("active globally scoped, indefinite allowlist exception")
                    .count(),
                if optional_active { 3 } else { 1 },
                "the audit must expand groups into concrete active packs: {check}"
            );
            assert_eq!(std::fs::read_to_string(&allowlist_path).unwrap(), original);
        }
    }

    #[test]
    fn doctor_does_not_call_scoped_expiring_or_inactive_exceptions_unrestricted() {
        for extra in [
            "paths = [\"/reviewed/workspace/**\"]",
            "paths = [\"**/reviewed/**\"]",
            "paths = [\"**/*.rs\"]",
            "paths = [\"*/reviewed\"]",
            "expires_at = \"2099-12-31T23:59:59Z\"",
            "expires_at = \"2099-12-31\"",
            "expires_at = \"2000-01-01T00:00:00Z\"",
            "ttl = \"1h\"\nadded_at = \"2099-01-01T00:00:00Z\"",
            "ttl = \"1h\"\nadded_at = \"2000-01-01T00:00:00Z\"",
            "ttl = \"1h\"",
            "ttl = \"1h\"\nadded_at = \"invalid-audit-date\"",
            "session = true\nsession_id = \"doctor-audit-session\"",
            "session = true\nsession_id = \"different-session\"",
            "conditions = { AUDIT_REVIEWED = \"yes\" }",
        ] {
            let temp = tempfile::tempdir().expect("tempdir");
            let (_, xdg_config, _) = setup_doctor_env(&temp);
            let path = xdg_config.join("dcg/allowlist.toml");
            let original = format!(
                "[[allow]]\nrule = \"core.git:reset-hard\"\nreason = \"bounded exception\"\n{extra}\n"
            );
            write_doctor_allowlist(&path, &original);
            let output = allowlist_doctor_command(&temp)
                .args(["doctor", "--format", "json"])
                .output()
                .expect("run bounded-exception audit");
            let report = parse_allowlist_doctor_report(&output);
            let check = allowlist_doctor_check(&report);
            assert!(output.status.success(), "{extra:?}: {report}");
            let message = check["message"].as_str().expect("message");
            assert!(
                !message.contains("active globally scoped, indefinite allowlist exception"),
                "{extra:?} is not an unrestricted indefinite grant: {check}"
            );
            if extra.starts_with("paths =") || extra.contains("2099") {
                assert_eq!(check["status"], "ok", "{extra:?}: {check}");
            }
            assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        }
    }

    #[test]
    fn doctor_preserves_working_path_scoped_and_exact_command_exceptions() {
        for scoped in [true, false] {
            let temp = tempfile::tempdir().expect("tempdir");
            let (_, xdg_config, _) = setup_doctor_env(&temp);
            let path = xdg_config.join("dcg/allowlist.toml");
            let approved = temp.path().join("approved");
            std::fs::create_dir_all(&approved).expect("approved directory");
            let original = if scoped {
                let scope = toml::Value::String(approved.to_string_lossy().into_owned());
                format!(
                    "[[allow]]\nrule = \"core.git:reset-hard\"\nreason = \"scoped maintenance\"\npaths = [{scope}]\n"
                )
            } else {
                "[[allow]]\nexact_command = \"git reset --hard\"\nreason = \"reviewed exact command\"\n"
                    .to_string()
            };
            write_doctor_allowlist(&path, &original);

            for after_audit in [false, true] {
                if after_audit {
                    let output = allowlist_doctor_command(&temp)
                        .current_dir(&approved)
                        .args(["doctor", "--format", "json"])
                        .output()
                        .expect("audit safe exception");
                    let report = parse_allowlist_doctor_report(&output);
                    let check = allowlist_doctor_check(&report);
                    assert_eq!(check["status"], "ok", "scoped={scoped}: {check}");
                    assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
                }
                for allowed in [true, false] {
                    let cwd = if allowed || !scoped {
                        approved.as_path()
                    } else {
                        temp.path()
                    };
                    let command = if allowed || scoped {
                        "git reset --hard"
                    } else {
                        "git reset --hard HEAD~1"
                    };
                    let output = allowlist_doctor_command(&temp)
                        .current_dir(cwd)
                        .args(["test", "--format", "json", command])
                        .output()
                        .expect("evaluate scoped allowance without executing it");
                    let evaluation: serde_json::Value =
                        serde_json::from_slice(&output.stdout).expect("evaluation JSON");
                    assert_eq!(
                        evaluation["decision"],
                        if allowed { "allow" } else { "deny" },
                        "scoped={scoped}, after_audit={after_audit}: {evaluation}"
                    );
                }
            }
        }
    }

    #[test]
    fn doctor_audits_project_user_and_system_allowlists_from_nested_cwd() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (_, xdg_config, _) = setup_doctor_env(&temp);
        let project_config = temp.path().join(".dcg.toml");
        std::fs::write(&project_config, "").expect("trusted project config");
        let nested = temp.path().join("src/nested");
        std::fs::create_dir_all(&nested).expect("nested working directory");
        let fixtures = [
            (
                "project",
                temp.path().join(".dcg/allowlist.toml"),
                "core.filesystem:rm-rf-root-home",
            ),
            (
                "user",
                xdg_config.join("dcg/allowlist.toml"),
                "core.git:reset-hard",
            ),
            (
                "system",
                temp.path().join("system-allowlist.toml"),
                "core.git:stash-clear",
            ),
        ];
        let mut originals = Vec::new();
        for (layer, path, rule) in &fixtures {
            let mut contents = format!(
                "[[allow]]\nrule = \"{rule}\"\nreason = \"{layer} maintenance\"\nadded_by = \"{layer}-reviewer\"\nadded_at = \"2026-08-01T12:00:00Z\"\n"
            );
            if *layer == "project" {
                // A scoped higher-priority exception does not neutralize an
                // unrestricted user grant for the same rule elsewhere.
                contents.push_str(
                    "\n[[allow]]\nrule = \"core.git:reset-hard\"\nreason = \"scoped project override\"\npaths = [\"/reviewed/workspace/**\"]\n",
                );
            }
            write_doctor_allowlist(path, &contents);
            originals.push(contents);
        }
        let output = allowlist_doctor_command(&temp)
            .env("DCG_CONFIG", &project_config)
            .current_dir(&nested)
            .args(["doctor", "--format", "json", "--strict"])
            .output()
            .expect("audit all layers");
        let report = parse_allowlist_doctor_report(&output);
        assert!(output.status.success(), "{report}");
        let check = allowlist_doctor_check(&report);
        assert_eq!(check["status"], "warning", "{check}");
        let message = check["message"].as_str().expect("message");
        assert_eq!(
            message
                .matches("active globally scoped, indefinite allowlist exception")
                .count(),
            3,
            "each active unrestricted layer must be reported: {check}"
        );
        for ((layer, path, rule), original) in fixtures.iter().zip(originals) {
            for expected in [
                format!("{layer}:"),
                path.display().to_string(),
                (*rule).to_string(),
            ] {
                assert!(message.contains(&expected), "missing {expected:?}: {check}");
            }
            assert_eq!(std::fs::read_to_string(path).unwrap(), original);
        }
    }

    #[test]
    fn doctor_warns_for_universal_globs_in_every_layer_without_changing_grants_545() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (_, xdg_config, _) = setup_doctor_env(&temp);
        let project_config = temp.path().join(".dcg.toml");
        std::fs::write(&project_config, "").expect("trusted project config");
        let nested = temp.path().join("src/nested");
        std::fs::create_dir_all(&nested).expect("nested directory");
        let fixtures = [
            (
                "project",
                temp.path().join(".dcg/allowlist.toml"),
                "core.git:reset-hard",
                "**/",
                "git reset --hard",
            ),
            (
                "user",
                xdg_config.join("dcg/allowlist.toml"),
                "core.git:clean-force",
                "**/*",
                "git clean -fd",
            ),
            (
                "system",
                temp.path().join("system-allowlist.toml"),
                "core.git:stash-clear",
                "**/**",
                "git stash clear",
            ),
        ];
        let mut originals = Vec::new();
        for (layer, path, rule, pattern, _) in &fixtures {
            let contents = format!(
                "[[allow]]\nrule = \"{rule}\"\nreason = \"{layer} wildcard maintenance\"\npaths = [\"{pattern}\"]\nadded_by = \"{layer}-reviewer\"\n"
            );
            write_doctor_allowlist(path, &contents);
            originals.push(contents);
        }
        for after_audit in [false, true] {
            if after_audit {
                let output = allowlist_doctor_command(&temp)
                    .env("DCG_CONFIG", &project_config)
                    .current_dir(&nested)
                    .args(["doctor", "--fix", "--strict", "--format", "json"])
                    .output()
                    .expect("audit universal globs across all layers");
                let report = parse_allowlist_doctor_report(&output);
                assert!(output.status.success(), "{report}");
                let check = allowlist_doctor_check(&report);
                assert_eq!(check["status"], "warning", "{check}");
                assert_ne!(check["fixed"], true, "doctor must preserve grants: {check}");
                let message = check["message"].as_str().expect("audit message");
                assert_eq!(
                    message
                        .matches("active globally scoped, indefinite allowlist exception")
                        .count(),
                    fixtures.len(),
                    "universal scope must be diagnosed in every layer: {check}"
                );
                for ((layer, path, rule, _, _), original) in fixtures.iter().zip(&originals) {
                    for expected in [
                        format!("{layer}:"),
                        (*rule).to_string(),
                        format!("{layer}-reviewer"),
                    ] {
                        assert!(message.contains(&expected), "missing {expected:?}: {check}");
                    }
                    assert_eq!(std::fs::read_to_string(path).unwrap(), *original);
                }
            }
            for (_, _, _, _, command) in &fixtures {
                for cwd in [temp.path(), nested.as_path()] {
                    let output = allowlist_doctor_command(&temp)
                        .env("DCG_CONFIG", &project_config)
                        .current_dir(cwd)
                        .args(["test", "--format", "json", command])
                        .output()
                        .expect("evaluate granted command as inert data");
                    let evaluation: serde_json::Value =
                        serde_json::from_slice(&output.stdout).expect("evaluation JSON");
                    assert_eq!(
                        evaluation["decision"], "allow",
                        "the audit must not change matching: after_audit={after_audit}, {command:?}: {evaluation}"
                    );
                }
            }
        }
    }

    #[test]
    fn doctor_reports_untrusted_project_allowlist_as_inactive() {
        let temp = tempfile::tempdir().expect("tempdir");
        setup_doctor_env(&temp);
        std::fs::write(temp.path().join(".dcg.toml"), "").expect("untrusted project config");
        let path = temp.path().join(".dcg/allowlist.toml");
        let original =
            "[[allow]]\nrule = \"core.git:reset-hard\"\nreason = \"inactive project rule\"\n";
        write_doctor_allowlist(&path, original);
        let output = allowlist_doctor_command(&temp)
            .args(["doctor", "--format", "json"])
            .output()
            .expect("audit untrusted project");
        let report = parse_allowlist_doctor_report(&output);
        let check = allowlist_doctor_check(&report);
        assert_eq!(check["status"], "warning", "{check}");
        let message = check["message"].as_str().expect("message");
        assert!(message.contains("inactive"), "{check}");
        assert!(message.contains("untrusted"), "{check}");
        assert!(message.contains(&path.display().to_string()), "{check}");
        assert!(
            !message.contains("active globally scoped, indefinite allowlist exception"),
            "untrusted repository policy must not be reported as active: {check}"
        );
        assert_eq!(std::fs::read_to_string(path).unwrap(), original);
    }

    #[test]
    fn doctor_reports_active_risk_alongside_malformed_allowlist_metadata() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (_, xdg_config, _) = setup_doctor_env(&temp);
        let path = xdg_config.join("dcg/allowlist.toml");
        let original = r#"
[[allow]]
rule = "core.filesystem:rm-rf-general"
reason = "invalid expiry makes this row inactive"
expires_at = "not-a-date"

[[allow]]
rule = "core.git:reset-hard"
reason = "active despite malformed audit timestamp"
added_by = "migration-reviewer"
added_at = "invalid-audit-date"
"#;
        write_doctor_allowlist(&path, original);
        for strict in [false, true] {
            let mut command = allowlist_doctor_command(&temp);
            command.args(["doctor", "--format", "json"]);
            if strict {
                command.arg("--strict");
            }
            let output = command.output().expect("audit malformed metadata");
            let report = parse_allowlist_doctor_report(&output);
            let check = allowlist_doctor_check(&report);
            assert_eq!(check["status"], "error", "{check}");
            assert_eq!(report["ok"], false, "{report}");
            assert_eq!(output.status.success(), !strict, "{report}");
            let message = check["message"].as_str().expect("message");
            assert!(message.contains("not-a-date"), "{check}");
            assert!(
                message.contains("entry 2"),
                "retain source row numbers: {check}"
            );
            assert!(
                message.contains("active globally scoped, indefinite allowlist exception for rule core.git:reset-hard"),
                "a parse error must not hide another row's active risk: {check}"
            );
            assert!(message.contains("migration-reviewer"), "{check}");
            assert!(message.contains("invalid-audit-date"), "{check}");
            assert!(
                !message.contains("active globally scoped, indefinite allowlist exception for rule core.filesystem:rm-rf-general"),
                "a rejected expiry row must not be described as active: {check}"
            );
            assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        }
    }

    #[test]
    fn doctor_audits_non_string_expiration_as_runtime_interprets_it() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (_, xdg_config, _) = setup_doctor_env(&temp);
        let path = xdg_config.join("dcg/allowlist.toml");
        // The loader ignores values of the wrong type for these optional
        // fields. Their presence must not make doctor invent an expiration.
        let original = r#"
[[allow]]
rule = "core.git:reset-hard"
reason = "mistyped optional metadata"
expires_at = 123
added_at = false
added_by = 456
"#;
        write_doctor_allowlist(&path, original);
        let output = allowlist_doctor_command(&temp)
            .args(["doctor", "--format", "json"])
            .output()
            .expect("audit mistyped metadata");
        let report = parse_allowlist_doctor_report(&output);
        let check = allowlist_doctor_check(&report);
        assert_eq!(check["status"], "warning", "{check}");
        let message = check["message"].as_str().expect("message");
        assert!(
            message.contains("active globally scoped, indefinite allowlist exception for rule core.git:reset-hard"),
            "{check}"
        );
        assert!(!message.contains("added_by=456"), "{check}");
        assert!(!message.contains("added_at=false"), "{check}");
        assert_eq!(std::fs::read_to_string(path).unwrap(), original);
    }

    /// Run `dcg doctor --format json` in an isolated HOME and return the
    /// `history` check (#381).
    fn doctor_history_check(
        temp: &tempfile::TempDir,
        home_dir: &std::path::Path,
        xdg_config_dir: &std::path::Path,
        bin_dir: &std::path::Path,
        extra_env: &[(&str, &std::ffi::OsStr)],
    ) -> serde_json::Value {
        let mut command = Command::new(dcg_binary());
        command
            .env_clear()
            .env("HOME", home_dir)
            .env("USERPROFILE", home_dir)
            .env("XDG_CONFIG_HOME", xdg_config_dir)
            .env("PATH", bin_dir)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .current_dir(temp.path())
            .args(["doctor", "--format", "json"]);
        for (key, value) in extra_env {
            command.env(key, value);
        }
        let output = command.output().expect("run dcg doctor --format json");
        assert!(
            output.status.success(),
            "doctor must succeed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("doctor JSON output");
        report["checks"]
            .as_array()
            .expect("checks array")
            .iter()
            .find(|check| check["id"] == "history")
            .cloned()
            .expect("history check present")
    }

    /// #381: history defaults to the XDG state directory, never `~/.config`.
    #[test]
    fn doctor_reports_history_default_in_state_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (home_dir, xdg_config_dir, bin_dir) = setup_doctor_env(&temp);
        std::fs::create_dir_all(xdg_config_dir.join("dcg")).expect("config dir");
        std::fs::write(
            xdg_config_dir.join("dcg").join("config.toml"),
            b"[history]\nenabled = true\n",
        )
        .expect("write config");

        let check = doctor_history_check(&temp, &home_dir, &xdg_config_dir, &bin_dir, &[]);
        assert_eq!(check["status"], "ok", "{check}");
        let message = check["message"].as_str().expect("message");
        // Windows: %LOCALAPPDATA%\dcg, derived from the redirected profile
        // because this environment is cleared.
        let expected = if cfg!(windows) {
            home_dir.join("AppData").join("Local").join("dcg")
        } else {
            home_dir.join(".local").join("state").join("dcg")
        };
        assert!(
            message.contains(&expected.display().to_string()),
            "default must live under the state directory: {message}"
        );
        assert!(
            message.contains("default state directory"),
            "message must name the source: {message}"
        );
        assert!(
            !message.contains(&xdg_config_dir.display().to_string()),
            "history must not default into the config directory: {message}"
        );
        assert!(
            !expected.exists(),
            "doctor must not create the state directory as a side effect"
        );
    }

    /// #381: `XDG_STATE_HOME` relocates the default; `DCG_HISTORY_DB` beats
    /// `[history] database_path`, which beats the default.
    #[test]
    fn doctor_reports_history_path_precedence() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (home_dir, xdg_config_dir, bin_dir) = setup_doctor_env(&temp);
        std::fs::create_dir_all(xdg_config_dir.join("dcg")).expect("config dir");
        let xdg_state = temp.path().join("xdg_state");
        let config_db = temp.path().join("from-config").join("history.db");
        let env_db = temp.path().join("from-env").join("history.db");

        // Default with XDG_STATE_HOME set.
        std::fs::write(
            xdg_config_dir.join("dcg").join("config.toml"),
            b"[history]\nenabled = true\n",
        )
        .expect("write config");
        let check = doctor_history_check(
            &temp,
            &home_dir,
            &xdg_config_dir,
            &bin_dir,
            &[("XDG_STATE_HOME", xdg_state.as_os_str())],
        );
        let message = check["message"].as_str().expect("message").to_string();
        // XDG_STATE_HOME is a Unix convention; Windows keeps %LOCALAPPDATA%.
        if cfg!(unix) {
            assert!(
                message.contains(
                    &xdg_state
                        .join("dcg")
                        .join("history.db")
                        .display()
                        .to_string()
                ),
                "XDG_STATE_HOME must relocate the default: {message}"
            );
        }

        // Config override.
        std::fs::write(
            xdg_config_dir.join("dcg").join("config.toml"),
            format!(
                "[history]\nenabled = true\ndatabase_path = {:?}\n",
                config_db.display().to_string()
            ),
        )
        .expect("write config");
        let check = doctor_history_check(
            &temp,
            &home_dir,
            &xdg_config_dir,
            &bin_dir,
            &[("XDG_STATE_HOME", xdg_state.as_os_str())],
        );
        let message = check["message"].as_str().expect("message").to_string();
        assert!(
            message.contains(&config_db.display().to_string())
                && message.contains("[history] database_path"),
            "config path must beat the default: {message}"
        );

        // Environment override beats config.
        let check = doctor_history_check(
            &temp,
            &home_dir,
            &xdg_config_dir,
            &bin_dir,
            &[
                ("XDG_STATE_HOME", xdg_state.as_os_str()),
                ("DCG_HISTORY_DB", env_db.as_os_str()),
            ],
        );
        let message = check["message"].as_str().expect("message").to_string();
        assert!(
            message.contains(&env_db.display().to_string()) && message.contains("DCG_HISTORY_DB"),
            "DCG_HISTORY_DB must beat config: {message}"
        );
        assert!(
            !message.contains(&config_db.display().to_string()),
            "config path must not leak into the env-selected message: {message}"
        );
    }

    /// #381: an existing pre-0.15 database beside config.toml stays in use,
    /// and doctor says so; a read-only one is reported as a warning with the
    /// relocation hint.
    #[test]
    #[cfg(unix)]
    fn doctor_reports_legacy_history_location_and_readonly_warning() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let (home_dir, xdg_config_dir, bin_dir) = setup_doctor_env(&temp);
        let config_dir = xdg_config_dir.join("dcg");
        std::fs::create_dir_all(&config_dir).expect("config dir");
        std::fs::write(
            config_dir.join("config.toml"),
            b"[history]\nenabled = true\n",
        )
        .expect("write config");
        let legacy_db = config_dir.join("history.db");
        std::fs::write(&legacy_db, b"").expect("legacy db placeholder");

        let check = doctor_history_check(&temp, &home_dir, &xdg_config_dir, &bin_dir, &[]);
        assert_eq!(check["status"], "ok", "{check}");
        let message = check["message"].as_str().expect("message");
        assert!(
            message.contains(&legacy_db.display().to_string())
                && message.contains("legacy config-directory location")
                && message.contains("pre-0.15"),
            "existing legacy database must be honored and labelled: {message}"
        );

        // Make the legacy file read-only: the sandbox scenario from #381.
        std::fs::set_permissions(&legacy_db, std::fs::Permissions::from_mode(0o444))
            .expect("chmod legacy db");
        // A privileged test runner (root) can write a 0444 file, so the probe
        // legitimately reports OK there; only assert the warning when this
        // process itself cannot open the file for writing.
        let readonly_observable = std::fs::OpenOptions::new()
            .write(true)
            .open(&legacy_db)
            .is_err();
        let check = doctor_history_check(&temp, &home_dir, &xdg_config_dir, &bin_dir, &[]);
        std::fs::set_permissions(&legacy_db, std::fs::Permissions::from_mode(0o644))
            .expect("restore legacy db perms");
        if !readonly_observable {
            return;
        }
        assert_eq!(check["status"], "warning", "{check}");
        let remediation = check["remediation"].as_str().expect("remediation");
        assert!(
            remediation.contains("DCG_HISTORY_DB")
                && remediation.contains("[history] database_path"),
            "remediation must name both overrides: {remediation}"
        );
    }

    #[test]
    fn doctor_distinguishes_omp_extension_ownership_from_health() {
        #[derive(Clone, Copy)]
        enum Fixture {
            Absent,
            Foreign,
            InvalidUtf8Marker,
            Current,
            Truncated,
            Stale,
            Disabled,
            Malformed,
            ProjectTruncatedUserCurrent,
            ProjectCurrentUserTruncated,
            ProjectForeignUserCurrent,
        }

        let cases = [
            ("absent", Fixture::Absent, false),
            ("foreign", Fixture::Foreign, false),
            ("invalid-utf8-marker", Fixture::InvalidUtf8Marker, false),
            ("owned-current", Fixture::Current, true),
            ("owned-truncated", Fixture::Truncated, false),
            ("owned-stale", Fixture::Stale, false),
            ("owned-disabled", Fixture::Disabled, false),
            ("owned-malformed", Fixture::Malformed, false),
            (
                "project-truncated-user-current",
                Fixture::ProjectTruncatedUserCurrent,
                false,
            ),
            (
                "project-current-user-truncated",
                Fixture::ProjectCurrentUserTruncated,
                false,
            ),
            (
                "project-foreign-user-current",
                Fixture::ProjectForeignUserCurrent,
                true,
            ),
        ];

        for (label, fixture, expected_healthy) in cases {
            let temp = tempfile::tempdir().expect("tempdir");
            let (home_dir, xdg_config_dir, bin_dir) = setup_doctor_env(&temp);
            let extension = temp.path().join(".omp/extensions/dcg-guard.ts");
            let user_extension = home_dir.join(".omp/agent/extensions/dcg-guard.ts");

            let install_current = |project: bool| {
                let mut install = Command::new(dcg_binary());
                install
                    .env_clear()
                    .env("HOME", &home_dir)
                    .env("USERPROFILE", &home_dir)
                    .env("XDG_CONFIG_HOME", &xdg_config_dir)
                    .env("OMP_PROFILE", "")
                    .current_dir(temp.path())
                    .args(["install", "--omp"]);
                if project {
                    install.arg("--project");
                }
                let output = install.output().expect("install current OMP extension");
                assert!(
                    output.status.success(),
                    "{label}: fixture install failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let path = if project { &extension } else { &user_extension };
                std::fs::read_to_string(path).expect("read generated OMP extension")
            };

            match fixture {
                Fixture::Absent => {}
                Fixture::Foreign => {
                    std::fs::create_dir_all(extension.parent().expect("extension parent"))
                        .expect("project OMP extension directory");
                    std::fs::write(&extension, "export default function mine() {}\n")
                        .expect("foreign project OMP extension");
                }
                Fixture::InvalidUtf8Marker => {
                    std::fs::create_dir_all(extension.parent().expect("extension parent"))
                        .expect("project OMP extension directory");
                    std::fs::write(&extension, b"// dcg-omp-extension\xff\n")
                        .expect("invalid UTF-8 project OMP extension");
                }
                Fixture::Current
                | Fixture::Truncated
                | Fixture::Stale
                | Fixture::Disabled
                | Fixture::Malformed => {
                    let current = install_current(true);
                    let candidate = match fixture {
                        Fixture::Truncated => "// dcg-omp-extension: generated\n".to_string(),
                        Fixture::Stale => {
                            let stale = current.replacen(
                                "\"--agent\", \"omp\"",
                                "\"--agent\", \"legacy-pi\"",
                                1,
                            );
                            assert_ne!(stale, current, "stale fixture mutation must apply");
                            stale
                        }
                        Fixture::Disabled => {
                            let disabled =
                                current.replacen("pi.on(\"tool_call\"", "pi.on(\"tool_result\"", 1);
                            assert_ne!(disabled, current, "disabled fixture mutation must apply");
                            disabled
                        }
                        Fixture::Malformed => {
                            let malformed = current.replacen(
                                "export default function dcgGuard",
                                "export default function { dcgGuard",
                                1,
                            );
                            assert_ne!(malformed, current, "malformed fixture mutation must apply");
                            malformed
                        }
                        Fixture::Current => current,
                        Fixture::Absent
                        | Fixture::Foreign
                        | Fixture::InvalidUtf8Marker
                        | Fixture::ProjectTruncatedUserCurrent
                        | Fixture::ProjectCurrentUserTruncated
                        | Fixture::ProjectForeignUserCurrent => unreachable!(),
                    };
                    std::fs::write(&extension, candidate).expect("write OMP health fixture");
                }
                Fixture::ProjectTruncatedUserCurrent => {
                    install_current(true);
                    install_current(false);
                    std::fs::write(&extension, "// dcg-omp-extension: truncated\n")
                        .expect("write truncated project extension");
                }
                Fixture::ProjectCurrentUserTruncated => {
                    install_current(true);
                    install_current(false);
                    std::fs::write(&user_extension, "// dcg-omp-extension: truncated\n")
                        .expect("write truncated user extension");
                }
                Fixture::ProjectForeignUserCurrent => {
                    install_current(false);
                    std::fs::create_dir_all(extension.parent().expect("extension parent"))
                        .expect("project OMP extension directory");
                    std::fs::write(&extension, "export default function mine() {}\n")
                        .expect("foreign project OMP extension");
                }
            }

            let original_project = extension
                .is_file()
                .then(|| std::fs::read(&extension).expect("read original extension bytes"));
            let original_user = user_extension
                .is_file()
                .then(|| std::fs::read(&user_extension).expect("read original user bytes"));
            let output = Command::new(dcg_binary())
                .env_clear()
                .env("HOME", &home_dir)
                .env("USERPROFILE", &home_dir)
                .env("XDG_CONFIG_HOME", &xdg_config_dir)
                .env("PATH", &bin_dir)
                .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
                .env("OMP_PROFILE", "")
                .current_dir(temp.path())
                .args(["doctor", "--format", "json", "--strict"])
                .output()
                .expect("run strict dcg doctor");
            assert_eq!(
                output.status.success(),
                expected_healthy,
                "{label}: strict doctor status disagreed; stdout: {} stderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let report: serde_json::Value = serde_json::from_slice(&output.stdout)
                .unwrap_or_else(|error| panic!("{label}: invalid doctor JSON: {error}"));
            let omp_check = report["checks"]
                .as_array()
                .expect("checks array")
                .iter()
                .find(|check| check["id"] == "omp_extension")
                .unwrap_or_else(|| panic!("{label}: missing OMP doctor check"));
            assert_eq!(
                omp_check["status"],
                if expected_healthy { "ok" } else { "error" },
                "{label}: wrong OMP health verdict: {omp_check}"
            );

            let pretty = Command::new(dcg_binary())
                .env_clear()
                .env("HOME", &home_dir)
                .env("USERPROFILE", &home_dir)
                .env("XDG_CONFIG_HOME", &xdg_config_dir)
                .env("PATH", &bin_dir)
                .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
                .env("OMP_PROFILE", "")
                .current_dir(temp.path())
                .args(["doctor", "--strict"])
                .output()
                .expect("run strict pretty dcg doctor");
            assert_eq!(
                pretty.status.success(),
                expected_healthy,
                "{label}: pretty and JSON doctor disagreed; stdout: {} stderr: {}",
                String::from_utf8_lossy(&pretty.stdout),
                String::from_utf8_lossy(&pretty.stderr)
            );

            if let Some(original) = original_project {
                assert_eq!(
                    std::fs::read(&extension).expect("read extension after doctor"),
                    original,
                    "{label}: read-only doctor changed project extension bytes"
                );
            }
            if let Some(original) = original_user {
                assert_eq!(
                    std::fs::read(&user_extension).expect("read user extension after doctor"),
                    original,
                    "{label}: read-only doctor changed user extension bytes"
                );
            }
        }
    }

    #[test]
    fn doctor_fix_refreshes_an_unhealthy_owned_omp_extension_in_its_exact_scope() {
        for (label, project) in [("project", true), ("user", false)] {
            let temp = tempfile::tempdir().expect("tempdir");
            let (home_dir, xdg_config_dir, bin_dir) = setup_doctor_env(&temp);
            let project_extension = temp.path().join(".omp/extensions/dcg-guard.ts");
            let user_extension = home_dir.join(".omp/agent/extensions/dcg-guard.ts");
            let extension = if project {
                &project_extension
            } else {
                &user_extension
            };
            let other_extension = if project {
                &user_extension
            } else {
                &project_extension
            };

            let mut install = Command::new(dcg_binary());
            install
                .env_clear()
                .env("HOME", &home_dir)
                .env("USERPROFILE", &home_dir)
                .env("XDG_CONFIG_HOME", &xdg_config_dir)
                .env("OMP_PROFILE", "")
                .current_dir(temp.path())
                .args(["install", "--omp"]);
            if project {
                install.arg("--project");
            }
            let install = install.output().expect("install current OMP extension");
            assert!(install.status.success(), "{label}: fixture install failed");
            let expected = std::fs::read(extension).expect("current extension bytes");
            std::fs::write(extension, "// dcg-omp-extension: generated but truncated\n")
                .expect("plant truncated owned extension");

            let output = Command::new(dcg_binary())
                .env_clear()
                .env("HOME", &home_dir)
                .env("USERPROFILE", &home_dir)
                .env("XDG_CONFIG_HOME", &xdg_config_dir)
                .env("PATH", &bin_dir)
                .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
                .env("OMP_PROFILE", "")
                .current_dir(temp.path())
                .args(["doctor", "--fix", "--strict"])
                .output()
                .expect("repair unhealthy OMP extension");
            assert!(
                output.status.success(),
                "{label}: doctor --fix failed: stdout: {} stderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                std::fs::read(extension).expect("repaired extension"),
                expected,
                "{label}: doctor must refresh the unhealthy owned scope in place"
            );
            assert!(
                !other_extension.exists(),
                "{label}: repair must not install a substitute at the other scope"
            );
        }
    }

    #[test]
    fn doctor_fix_refreshes_both_loaded_owned_unhealthy_omp_extensions() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (home_dir, xdg_config_dir, bin_dir) = setup_doctor_env(&temp);
        let project_extension = temp.path().join(".omp/extensions/dcg-guard.ts");
        let user_extension = home_dir.join(".omp/agent/extensions/dcg-guard.ts");

        for project in [true, false] {
            let mut install = Command::new(dcg_binary());
            install
                .env_clear()
                .env("HOME", &home_dir)
                .env("USERPROFILE", &home_dir)
                .env("XDG_CONFIG_HOME", &xdg_config_dir)
                .env("OMP_PROFILE", "")
                .current_dir(temp.path())
                .args(["install", "--omp"]);
            if project {
                install.arg("--project");
            }
            let output = install.output().expect("install current OMP extension");
            assert!(
                output.status.success(),
                "fixture install failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let expected_project =
            std::fs::read(&project_extension).expect("current project extension bytes");
        let expected_user = std::fs::read(&user_extension).expect("current user extension bytes");
        std::fs::write(&project_extension, "// dcg-omp-extension: stale project\n")
            .expect("plant stale project extension");
        std::fs::write(&user_extension, "// dcg-omp-extension: stale user\n")
            .expect("plant stale user extension");

        let output = Command::new(dcg_binary())
            .env_clear()
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("PATH", &bin_dir)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env("OMP_PROFILE", "")
            .current_dir(temp.path())
            .args(["doctor", "--fix", "--strict"])
            .output()
            .expect("repair both loaded unhealthy OMP extensions");
        assert!(
            output.status.success(),
            "doctor --fix must repair both scopes in one invocation: stdout: {} stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read(&project_extension).expect("repaired project extension"),
            expected_project,
            "project extension was not refreshed to exact generated bytes"
        );
        assert_eq!(
            std::fs::read(&user_extension).expect("repaired user extension"),
            expected_user,
            "user extension was not refreshed to exact generated bytes"
        );
    }

    #[test]
    fn doctor_fix_json_remains_single_document_while_repairing_omp() {
        for (label, unhealthy) in [("missing", false), ("owned-unhealthy", true)] {
            let temp = tempfile::tempdir().expect("tempdir");
            let (home_dir, xdg_config_dir, bin_dir) = setup_doctor_env(&temp);
            let project_extension = temp.path().join(".omp/extensions/dcg-guard.ts");
            let user_extension = home_dir.join(".omp/agent/extensions/dcg-guard.ts");
            let expected = if unhealthy {
                let install = Command::new(dcg_binary())
                    .env_clear()
                    .env("HOME", &home_dir)
                    .env("USERPROFILE", &home_dir)
                    .env("XDG_CONFIG_HOME", &xdg_config_dir)
                    .env("OMP_PROFILE", "")
                    .current_dir(temp.path())
                    .args(["install", "--omp", "--project"])
                    .output()
                    .expect("install current project OMP extension");
                assert!(install.status.success(), "{label}: fixture install failed");
                assert!(
                    String::from_utf8_lossy(&install.stdout)
                        .contains("OMP extension installed successfully!"),
                    "{label}: ordinary install must retain its human announcement"
                );
                let expected =
                    std::fs::read(&project_extension).expect("current project extension bytes");
                std::fs::write(&project_extension, "// dcg-omp-extension: stale\n")
                    .expect("plant stale owned extension");
                Some(expected)
            } else {
                None
            };

            let output = Command::new(dcg_binary())
                .env_clear()
                .env("HOME", &home_dir)
                .env("USERPROFILE", &home_dir)
                .env("XDG_CONFIG_HOME", &xdg_config_dir)
                .env("PATH", &bin_dir)
                .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
                .env("OMP_PROFILE", "")
                .current_dir(temp.path())
                .args(["doctor", "--fix", "--format", "json", "--strict"])
                .output()
                .expect("repair OMP extension with JSON doctor");
            assert!(
                output.status.success(),
                "{label}: JSON doctor fix failed: stdout: {} stderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let report: serde_json::Value =
                serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
                    panic!("{label}: stdout was not one JSON document: {error}")
                });
            let omp_check = report["checks"]
                .as_array()
                .expect("checks array")
                .iter()
                .find(|check| check["id"] == "omp_extension")
                .unwrap_or_else(|| panic!("{label}: missing OMP doctor check"));
            assert_eq!(omp_check["status"], "ok", "{label}: {omp_check}");
            assert_eq!(omp_check["fixed"], true, "{label}: {omp_check}");

            let repaired_extension = if unhealthy {
                &project_extension
            } else {
                &user_extension
            };
            assert!(
                repaired_extension.is_file(),
                "{label}: doctor did not create the expected healthy extension"
            );
            if let Some(expected) = expected {
                assert_eq!(
                    std::fs::read(repaired_extension).expect("read repaired extension"),
                    expected,
                    "{label}: doctor did not restore exact generated bytes"
                );
            }

            let verify = Command::new(dcg_binary())
                .env_clear()
                .env("HOME", &home_dir)
                .env("USERPROFILE", &home_dir)
                .env("XDG_CONFIG_HOME", &xdg_config_dir)
                .env("PATH", &bin_dir)
                .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
                .env("OMP_PROFILE", "")
                .current_dir(temp.path())
                .args(["doctor", "--format", "json", "--strict"])
                .output()
                .expect("verify repaired OMP extension health");
            assert!(
                verify.status.success(),
                "{label}: repaired state is unhealthy"
            );
            let verify_report: serde_json::Value = serde_json::from_slice(&verify.stdout)
                .unwrap_or_else(|error| panic!("{label}: verification JSON invalid: {error}"));
            let verify_omp = verify_report["checks"]
                .as_array()
                .expect("checks array")
                .iter()
                .find(|check| check["id"] == "omp_extension")
                .expect("OMP verification check");
            assert_eq!(verify_omp["status"], "ok", "{label}: {verify_omp}");
            assert!(
                verify_omp.get("fixed").is_none(),
                "{label}: false `fixed` fields must retain the schema's omitted form: {verify_omp}"
            );
        }
    }

    #[test]
    fn doctor_fix_never_overwrites_a_foreign_omp_extension() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (home_dir, xdg_config_dir, bin_dir) = setup_doctor_env(&temp);
        let project_extension = temp.path().join(".omp/extensions/dcg-guard.ts");
        let user_extension = home_dir.join(".omp/agent/extensions/dcg-guard.ts");
        let foreign = b"export default function mine() {}\n";
        std::fs::create_dir_all(project_extension.parent().expect("extension parent"))
            .expect("project extension directory");
        std::fs::write(&project_extension, foreign).expect("foreign project extension");

        let output = Command::new(dcg_binary())
            .env_clear()
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("PATH", &bin_dir)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env("OMP_PROFILE", "")
            .current_dir(temp.path())
            .args(["doctor", "--fix", "--strict"])
            .output()
            .expect("fix doctor with foreign project extension");
        assert!(
            output.status.success(),
            "doctor may install the other OMP-loaded scope: stdout: {} stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read(&project_extension).expect("read foreign project extension"),
            foreign,
            "doctor must never overwrite foreign extension bytes"
        );
        assert!(
            user_extension.is_file(),
            "doctor should install a healthy extension at OMP's other loaded scope"
        );

        let verify = Command::new(dcg_binary())
            .env_clear()
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("PATH", &bin_dir)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env("OMP_PROFILE", "")
            .current_dir(temp.path())
            .args(["doctor", "--format", "json", "--strict"])
            .output()
            .expect("verify installed user extension");
        assert!(
            verify.status.success(),
            "healthy user candidate must be accepted"
        );
    }

    #[test]
    fn doctor_ignores_an_ancestor_omp_extension_from_a_nested_git_cwd() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (home_dir, xdg_config_dir, bin_dir) = setup_doctor_env(&temp);
        let ancestor_extension = temp.path().join(".omp/extensions/dcg-guard.ts");
        let nested_cwd = temp.path().join("nested").join("worktree");
        std::fs::create_dir_all(ancestor_extension.parent().expect("extension parent"))
            .expect("ancestor OMP extension directory");
        std::fs::create_dir_all(&nested_cwd).expect("nested cwd");
        std::fs::write(&ancestor_extension, "// dcg-omp-extension: generated\n")
            .expect("ancestor OMP extension");

        let output = Command::new(dcg_binary())
            .env_clear()
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("PATH", &bin_dir)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .current_dir(&nested_cwd)
            .args(["doctor", "--format", "json"])
            .output()
            .expect("run dcg doctor from nested cwd");
        assert!(output.status.success());
        let report: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("doctor JSON output should parse");
        assert!(
            report["checks"]
                .as_array()
                .expect("checks array")
                .iter()
                .all(|check| check["id"] != "omp_extension"),
            "doctor must not claim an ancestor extension that OMP will not load: {report}"
        );
    }

    /// `dcg doctor || handle_failure` must not be dead code: when doctor
    /// itself reports `ok: false`, `--strict` has to carry that verdict into
    /// the exit status. Without the flag the default stays 0 for everyone
    /// already calling doctor in a pipeline.
    #[test]
    fn doctor_strict_exit_code_agrees_with_the_reported_verdict() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (home_dir, xdg_config_dir, _bin_dir) = setup_doctor_env(&temp);

        // Empty PATH reproduces the #240 condition the binary_path check
        // exists to detect: the guard is not reachable from a non-interactive
        // shell, so doctor reports an error.
        let run = |args: &[&str]| {
            Command::new(dcg_binary())
                .env_clear()
                .env("HOME", &home_dir)
                .env("USERPROFILE", &home_dir)
                .env("XDG_CONFIG_HOME", &xdg_config_dir)
                .env("PATH", "")
                .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
                .current_dir(temp.path())
                .args(args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .expect("run dcg doctor")
        };

        let plain = run(&["doctor", "--format", "json"]);
        let parsed: serde_json::Value =
            serde_json::from_str(&String::from_utf8_lossy(&plain.stdout))
                .expect("doctor JSON output should parse");
        let reported_ok = parsed["ok"].as_bool().expect("ok field");

        assert!(
            plain.status.success(),
            "without --strict doctor keeps its historical exit 0"
        );

        let strict = run(&["doctor", "--format", "json", "--strict"]);
        assert_eq!(
            strict.status.success(),
            reported_ok,
            "--strict exit status must match the reported ok field (ok={reported_ok})"
        );

        // The pretty renderer keeps its own check set, and it is the one that
        // runs in CI (rich output is disabled without a TTY). Both renderers
        // must answer the same question the same way, or `--strict` means
        // something different depending on --format.
        let strict_pretty = run(&["doctor", "--strict"]);
        assert_eq!(
            strict_pretty.status.success(),
            strict.status.success(),
            "--strict must agree between the pretty and json renderers\npretty stdout:\n{}\njson stdout:\n{}",
            String::from_utf8_lossy(&strict_pretty.stdout),
            String::from_utf8_lossy(&strict.stdout),
        );
    }

    /// `--fix` must not let a repair of one problem cancel a DIFFERENT problem
    /// it could not fix. The verdict is `issues == 0 || (fix && fixed ==
    /// issues)`, so any `fixed` increment without a matching `issues`
    /// increment silently buys off a real failure.
    #[test]
    fn doctor_fix_does_not_mask_an_unfixed_issue() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (home_dir, xdg_config_dir, _bin_dir) = setup_doctor_env(&temp);

        // Empty PATH keeps `binary_path` broken and unfixable, while the
        // missing user config is repairable — the two must not net out.
        let output = Command::new(dcg_binary())
            .env_clear()
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("PATH", "")
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .current_dir(temp.path())
            .args(["doctor", "--fix", "--format", "json"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("run dcg doctor --fix");

        let parsed: serde_json::Value =
            serde_json::from_str(&String::from_utf8_lossy(&output.stdout))
                .expect("doctor JSON output should parse");
        let issues = parsed["issues"].as_u64().expect("issues");
        let fixed = parsed["fixed"].as_u64().expect("fixed");
        let ok = parsed["ok"].as_bool().expect("ok");

        assert!(
            fixed <= issues,
            "`fixed` must never exceed `issues`; a repair with no counted issue \
             inflates the counter (issues={issues}, fixed={fixed})"
        );
        if ok {
            assert_eq!(
                fixed, issues,
                "ok=true under --fix requires every counted issue to have been fixed"
            );
        }
    }
}

// ============================================================================
// DCG PACKS Tests
// ============================================================================

mod packs_tests {
    use super::*;

    #[test]
    fn packs_list_shows_available_packs() {
        let output = run_dcg(&["packs"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success(), "packs should succeed");
        assert!(stdout.contains("core.git"), "should list core.git pack");
        assert!(
            stdout.contains("containers.docker") || stdout.contains("docker"),
            "should list docker pack"
        );
    }

    #[test]
    fn pack_show_displays_pack_info() {
        let output = run_dcg(&["pack", "info", "core.git"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success(), "pack show should succeed");
        assert!(
            stdout.contains("git") || stdout.contains("Git"),
            "should show git pack info"
        );
    }
}

// ============================================================================
// DCG Hook Mode Tests (stdin JSON protocol)
// ============================================================================

mod hook_mode_tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use destructive_command_guard::logging::{RedactionConfig, RedactionMode};
    use destructive_command_guard::pending_exceptions::{
        AllowOnceEntry, AllowOnceScopeKind, PendingExceptionRecord,
    };

    fn assert_hook_denies(command: &str) {
        let result = run_dcg_hook(command);
        let stdout = result.stdout_str();

        assert!(
            result.output.status.success(),
            "hook mode should exit successfully\ncommand: {}\nstdout:\n{}\nstderr:\n{}",
            result.command,
            stdout,
            result.stderr_str()
        );

        let mut parse_error = None;
        let json: serde_json::Value = match serde_json::from_str(stdout.trim()) {
            Ok(value) => value,
            Err(e) => {
                parse_error = Some(format!(
                    "expected hook JSON output for deny, got parse error: {e}\ncommand: {}\nstdout:\n{}\nstderr:\n{}",
                    result.command,
                    stdout,
                    result.stderr_str()
                ));
                serde_json::Value::Null
            }
        };

        assert!(parse_error.is_none(), "{}", parse_error.unwrap());

        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"],
            "deny",
            "expected permissionDecision=deny\ncommand: {}\nstdout:\n{}\nstderr:\n{}",
            result.command,
            stdout,
            result.stderr_str()
        );
    }

    fn assert_hook_allows(command: &str) {
        let result = run_dcg_hook(command);
        let stdout = result.stdout_str();

        assert!(
            result.output.status.success(),
            "hook mode should exit successfully\ncommand: {}\nstdout:\n{}\nstderr:\n{}",
            result.command,
            stdout,
            result.stderr_str()
        );

        assert!(
            stdout.trim().is_empty(),
            "expected no stdout for allow\ncommand: {}\nstdout:\n{}\nstderr:\n{}",
            result.command,
            stdout,
            result.stderr_str()
        );
    }

    fn assert_hook_denies_rule(command: &str, expected_rule: &str) {
        let result = run_dcg_hook(command);
        let stdout = result.stdout_str();
        assert!(
            result.output.status.success(),
            "hook exit for {command:?}: {}",
            result.stderr_str()
        );
        let json: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|error| {
            panic!("invalid hook denial for {command:?}: {error}: {stdout}")
        });
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "{command:?}: {json}"
        );
        assert_eq!(
            json["hookSpecificOutput"]["ruleId"], expected_rule,
            "{command:?}: {json}"
        );
    }

    fn run_dcg_hook_in_dir_with_env(
        cwd: &std::path::Path,
        command: &str,
        extra_env: &[(&str, &std::ffi::OsStr)],
    ) -> HookRunOutput {
        std::fs::create_dir_all(cwd.join(".git")).expect("failed to create .git dir");

        let home_dir = cwd.join("home");
        let xdg_config_dir = cwd.join("xdg_config");
        std::fs::create_dir_all(&home_dir).expect("failed to create HOME dir");
        std::fs::create_dir_all(&xdg_config_dir).expect("failed to create XDG_CONFIG_HOME dir");

        let input = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {
                "command": command,
            }
        });

        let mut cmd = Command::new(dcg_binary());
        cmd.env_clear()
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            // Match the top-level hook helper: these are semantic E2E tests,
            // while deadline behavior has deterministic unit coverage.
            .env("DCG_HOOK_TIMEOUT_MS", "5000")
            .env("DCG_PACKS", "core.git,core.filesystem")
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in extra_env {
            cmd.env(key, value);
        }

        let mut child = cmd.spawn().expect("failed to spawn dcg hook mode");

        {
            let stdin = child.stdin.as_mut().expect("failed to open stdin");
            serde_json::to_writer(stdin, &input).expect("failed to write hook input JSON");
        }

        let output = child.wait_with_output().expect("failed to wait for dcg");

        HookRunOutput {
            command: command.to_string(),
            output,
        }
    }

    fn active_timestamp() -> DateTime<Utc> {
        Utc::now()
    }

    const fn redaction_config() -> RedactionConfig {
        RedactionConfig {
            enabled: false,
            mode: RedactionMode::Arguments,
            max_argument_len: 8,
        }
    }

    /// The cwd spelling dcg will actually observe at runtime.
    ///
    /// These fixtures omit a hook-reported cwd, so the process cwd is the
    /// available scope. Use its canonical spelling across macOS tempdir
    /// aliases and Windows verbatim paths, as the authorization store does.
    fn observed_cwd(path: &std::path::Path) -> std::path::PathBuf {
        let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        // `canonicalize` yields a `\\?\`-prefixed verbatim path on Windows,
        // which `current_dir()` never produces; strip it so both agree.
        match resolved.to_str().and_then(|s| s.strip_prefix(r"\\?\")) {
            Some(stripped) => std::path::PathBuf::from(stripped),
            None => resolved,
        }
    }

    fn write_allow_once_entry(
        allow_once_path: &std::path::Path,
        cwd: &std::path::Path,
        command: &str,
        force_allow_config: bool,
    ) {
        let now = active_timestamp();
        let redaction = redaction_config();
        let cwd_str = observed_cwd(cwd).to_string_lossy().into_owned();

        let pending = PendingExceptionRecord::new(
            now,
            &cwd_str,
            command,
            "test pending",
            &redaction,
            false,
            None,
        );
        let mut allow_once = AllowOnceEntry::from_pending(
            &pending,
            now,
            AllowOnceScopeKind::Cwd,
            &cwd_str,
            false,
            false,
            &redaction,
        );
        allow_once.force_allow_config = force_allow_config;

        let allow_once_line = serde_json::to_string(&allow_once).expect("serialize allow-once");
        std::fs::write(allow_once_path, format!("{allow_once_line}\n"))
            .expect("write allow-once jsonl");
    }

    fn assert_hook_denies_output(result: &HookRunOutput, expected_reason_substr: &str) {
        let stdout = result.stdout_str();

        assert!(
            result.output.status.success(),
            "hook mode should exit successfully\ncommand: {}\nstdout:\n{}\nstderr:\n{}",
            result.command,
            stdout,
            result.stderr_str()
        );

        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("expected JSON stdout for deny");

        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"],
            "deny",
            "expected permissionDecision=deny\ncommand: {}\nstdout:\n{}\nstderr:\n{}",
            result.command,
            stdout,
            result.stderr_str()
        );

        let reason = json["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap_or_default();
        assert!(
            reason.contains(expected_reason_substr),
            "expected deny reason to contain {expected_reason_substr:?}\ncommand: {}\nstdout:\n{}\nstderr:\n{}",
            result.command,
            stdout,
            result.stderr_str()
        );
    }

    #[test]
    fn hook_mode_allow_once_allows_pack_denied_command() {
        let temp = tempfile::tempdir().expect("tempdir");
        let allow_once_path = temp.path().join("allow_once.jsonl");
        write_allow_once_entry(&allow_once_path, temp.path(), "git reset --hard", false);

        let result = run_dcg_hook_in_dir_with_env(
            temp.path(),
            "git reset --hard",
            &[("DCG_ALLOW_ONCE_PATH", allow_once_path.as_os_str())],
        );

        assert!(
            result.output.status.success(),
            "hook mode should exit successfully\nstdout:\n{}\nstderr:\n{}",
            result.stdout_str(),
            result.stderr_str()
        );
        assert!(
            result.stdout_str().trim().is_empty(),
            "expected allow (no stdout) due to allow-once\nstdout:\n{}\nstderr:\n{}",
            result.stdout_str(),
            result.stderr_str()
        );
    }

    #[test]
    fn hook_mode_allow_once_does_not_override_config_block_without_force() {
        let temp = tempfile::tempdir().expect("tempdir");
        let allow_once_path = temp.path().join("allow_once.jsonl");
        write_allow_once_entry(&allow_once_path, temp.path(), "git reset --hard", false);

        let config_path = temp.path().join("dcg.toml");
        std::fs::write(
            &config_path,
            r"
[overrides]
block = [
  { pattern = '\bgit\s+reset\s+--hard\b', reason = 'explicit config block' },
]
",
        )
        .expect("write dcg config");

        let result = run_dcg_hook_in_dir_with_env(
            temp.path(),
            "git reset --hard",
            &[
                ("DCG_ALLOW_ONCE_PATH", allow_once_path.as_os_str()),
                ("DCG_CONFIG", config_path.as_os_str()),
            ],
        );

        assert_hook_denies_output(&result, "explicit config block");
    }

    #[test]
    fn hook_mode_config_block_wins_over_overlapping_allow_override() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config_path = temp.path().join("dcg.toml");
        std::fs::write(
            &config_path,
            r"
[overrides]
allow = ['git reset --hard']
block = [
  { pattern = 'git reset --hard', reason = 'explicit config block' },
]
",
        )
        .expect("write dcg config");

        let result = run_dcg_hook_in_dir_with_env(
            temp.path(),
            "git reset --hard",
            &[("DCG_CONFIG", config_path.as_os_str())],
        );

        assert_hook_denies_output(&result, "explicit config block");
    }

    #[test]
    fn hook_mode_allow_once_can_override_config_block_with_force_flag() {
        let temp = tempfile::tempdir().expect("tempdir");
        let allow_once_path = temp.path().join("allow_once.jsonl");
        write_allow_once_entry(&allow_once_path, temp.path(), "git reset --hard", true);

        let config_path = temp.path().join("dcg.toml");
        std::fs::write(
            &config_path,
            r"
[overrides]
block = [
  { pattern = '\bgit\s+reset\s+--hard\b', reason = 'explicit config block' },
]
",
        )
        .expect("write dcg config");

        let result = run_dcg_hook_in_dir_with_env(
            temp.path(),
            "git reset --hard",
            &[
                ("DCG_ALLOW_ONCE_PATH", allow_once_path.as_os_str()),
                ("DCG_CONFIG", config_path.as_os_str()),
            ],
        );

        assert!(
            result.output.status.success(),
            "hook mode should exit successfully\nstdout:\n{}\nstderr:\n{}",
            result.stdout_str(),
            result.stderr_str()
        );
        assert!(
            result.stdout_str().trim().is_empty(),
            "expected allow (no stdout) due to allow-once force flag\nstdout:\n{}\nstderr:\n{}",
            result.stdout_str(),
            result.stderr_str()
        );
    }

    #[test]
    fn hook_mode_missing_dcg_config_fails_closed() {
        // An explicitly selected config that does not exist is an unknown
        // policy, not the default one: the custom packs, policy rules and
        // fail_closed it was meant to carry are missing. Since #568
        // (5b1d5bf) hook mode denies every shell command with the reason
        // instead of silently evaluating with built-in defaults; it used to
        // fail open here.
        let scratch = tempfile::tempdir().expect("scratch dir");
        let missing = scratch
            .path()
            .join("dcg_config_missing_should_not_exist.toml");
        let result = run_dcg_hook_with_env("git status", &[("DCG_CONFIG", missing.as_os_str())]);

        assert!(
            result.output.status.success(),
            "hook protocol denial still exits 0\nstdout:\n{}\nstderr:\n{}",
            result.stdout_str(),
            result.stderr_str()
        );
        let json: serde_json::Value = serde_json::from_str(result.stdout_str().trim())
            .unwrap_or_else(|error| {
                panic!(
                    "expected a JSON denial for a missing DCG_CONFIG ({error})\nstdout:\n{}\nstderr:\n{}",
                    result.stdout_str(),
                    result.stderr_str()
                )
            });
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "{json}"
        );
        let reason = json["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .expect("denial carries a reason");
        assert!(
            reason.contains("DCG configuration error")
                && reason.contains("dcg_config_missing_should_not_exist.toml")
                && reason.contains("does not exist"),
            "the reason must name the missing file: {reason}"
        );

        // Control: the same harmless command is allowed when no config is
        // selected, so the denial above comes from the missing selection.
        let control = run_dcg_hook("git status");
        assert!(control.output.status.success());
        assert!(
            control.stdout_str().trim().is_empty(),
            "git status without DCG_CONFIG must stay allowed\nstdout:\n{}\nstderr:\n{}",
            control.stdout_str(),
            control.stderr_str()
        );
    }

    #[test]
    fn hook_mode_path_normalization_and_wrappers_matrix() {
        // Deny cases: absolute paths, quoted command words, wrappers, env assignments.
        let deny_cases = [
            "/usr/bin/git reset --hard",
            "\"/usr/bin/git\" reset --hard",
            "'/usr/bin/git' reset --hard",
            "sudo /usr/bin/git reset --hard",
            "FOO=1 /usr/bin/git reset --hard",
            "env FOO=1 /usr/bin/git reset --hard",
            "/bin/rm -rf /etc",
            "\"/bin/rm\" -rf /etc",
            "sudo \"/bin/rm\" -rf /etc",
            "FOO=1 \"/bin/rm\" -rf /etc",
            "FOO=1 rm -rf /",
            "FOO=1 rm -rf /etc",
            "FOO=bar rm -rf /home/example/probe",
            "FOO=\"bar baz\" rm -rf /home/example/probe",
            "A=1 B=2 rm -rf /home/example/probe",
            "  FOO=1 rm -rf /home/example/probe",
            "FOO=1 sudo rm -rf /home/example/probe",
            "FOO=1 dd if=/dev/zero of=/dev/sda",
            "FOO=1 mkfs.ext4 /dev/sda1",
        ];

        for cmd in deny_cases {
            assert_hook_denies(cmd);
        }

        // Allow cases: dangerous substrings in data contexts should not block.
        let allow_cases = [
            "git commit -m \"Fix rm -rf detection\"",
            "rg -n \"rm -rf\" src/main.rs",
            "echo \"rm -rf /etc\"",
        ];

        for cmd in allow_cases {
            assert_hook_allows(cmd);
        }
    }

    #[test]
    fn hook_mode_quoted_interpreter_syntax_is_not_outer_shell_syntax() {
        for command in [
            r#"python3 - <<'PY'
import re
a = 'it\'s'
b = '#'
c = re.compile(r"^")
PY"#,
            r#"node <<'JS'
const format = (value) => `# ${value} ^`;
console.log(format("safe"));
JS"#,
        ] {
            assert_hook_allows(command);
        }
    }

    #[test]
    fn hook_mode_quoted_sed_patterns_inside_loops_are_data() {
        for command in [
            "for x in a b; do\nls | sed 's|^\\./||'\ndone",
            "for x in a b; do\nls | sed \"s|^\\./||\"\ndone",
        ] {
            assert_hook_allows(command);
        }
    }

    #[test]
    fn hook_mode_quoted_source_masking_preserves_outer_execution() {
        for (command, rule) in [
            ("g^it reset --hard", "core.git:reset-hard"),
            (
                r#"echo "$(Remove-Item -Recurse -Force C:\Users\Alice\project)""#,
                "core.filesystem:powershell-remove-item-recursive",
            ),
            (
                r"(Remove-Item -Recurse -Force C:\Users\Alice\project)",
                "core.filesystem:powershell-remove-item-recursive",
            ),
            (
                "python3 - <<'PY'\nprint(\"safe ^\")\nPY\ngit reset --hard",
                "core.git:reset-hard",
            ),
        ] {
            assert_hook_denies_rule(command, rule);
        }
        // An unquoted delimiter leaves expansions active in the parent shell.
        assert_hook_denies("cat <<EOF\n$(rm -rf /etc)\nEOF");
    }

    #[test]
    fn hook_mode_quoted_interpreter_source_keeps_destructive_sink_scans() {
        for (command, rule) in [
            (
                "python3 - <<'PY'\nimport shutil\nshutil.rmtree(\"/home/alice/project\")\nPY",
                "heredoc.python:shutil_rmtree",
            ),
            (
                "python3 - <<'PY'\nfrom os import system as run\nrun(\"rm -rf /home/alice/project\")\nPY",
                "heredoc.python:exec_sink.rm_rf_catastrophic",
            ),
            (
                r#"python3 - <<'PY'
import os
os.system('ver & copy nul .git\\config')
PY"#,
                "core.filesystem:git-internals-write",
            ),
            (
                r#"python3 - <<'PY'
from os import system as run
run('ver & copy nul .git\\config')
PY"#,
                "core.filesystem:git-internals-write",
            ),
            (
                r#"python3 - <<'PY'
import os
run = os.system
run('ver & copy nul .git\\config')
PY"#,
                "core.filesystem:git-internals-write",
            ),
            (
                "python3 - <<'PY'\nimport os\nos.system('echo ok; Remove-Item -Recurse -Force C:/x')\nPY",
                "core.filesystem:powershell-remove-item-recursive",
            ),
            (
                "python3 - <<'PY'\nfrom os import system as run\nrun('echo ok; Remove-Item -Recurse -Force C:/x')\nPY",
                "core.filesystem:powershell-remove-item-recursive",
            ),
            (
                "python3 - <<'PY'\nimport os\nrun = os.system\nrun('echo ok; Remove-Item -Recurse -Force C:/x')\nPY",
                "core.filesystem:powershell-remove-item-recursive",
            ),
        ] {
            assert_hook_denies_rule(command, rule);
        }
    }

    #[test]
    fn hook_mode_interpreter_data_inputs_do_not_gain_source_masking() {
        for command in [
            r#"python3 -c 'import os,sys; os.system(sys.stdin.read())' <<'PY'
copy nul .git\config
PY"#,
            r#"python3 script.py <<'PY'
copy nul .git\config
PY"#,
            r#"node -e 'require("child_process").execSync(require("fs").readFileSync(0,"utf8"))' <<'JS'
copy nul .git\config
JS"#,
        ] {
            assert_hook_denies_rule(command, "core.filesystem:git-internals-write");
        }
    }

    #[test]
    fn hook_mode_posix_control_flow_git_commands_are_blocked() {
        for command in [
            "for i in 1; do git reset --hard HEAD~1; done",
            "while read -r x; do git push --force origin main; done",
            "if true; then git reset --merge HEAD~1; fi",
            "if git reset --hard HEAD~1; then true; fi",
            "until git push -f origin main; do true; done",
            "{ git branch -D stale; }",
            "if false; then true; elif git branch --delete stale; then true; fi",
            "if true; then { sudo git push --force origin main; }; fi",
            "git config alias.x 'reset --hard'; if true; then git x; fi",
            "coproc git reset --hard HEAD~1",
            "then coproc git reset --hard HEAD~1",
            "coproc JOB { git push --force origin main; }",
            "coproc JOB if git reset --hard HEAD~1; then true; fi",
            "function f { git reset --hard HEAD~1; }; f",
            "function f if git push --force origin main; then true; fi; f",
        ] {
            assert_hook_denies(command);
        }

        for command in [
            "command then git reset --hard",
            "env then git reset --hard",
            "sudo then git reset --hard",
            "/usr/bin/then git reset --hard",
            "'then' git reset --hard",
            "then else git reset --hard",
            "do then git reset --hard",
            "coproc echo git reset --hard",
            "coproc printf '%s' 'git reset --hard'",
            "coproc JOB { echo git reset --hard; }",
            "function f { echo git reset --hard; }; f",
            "command coproc git reset --hard",
            "env coproc git reset --hard",
            "/usr/bin/coproc git reset --hard",
            "'coproc' git reset --hard",
        ] {
            assert_hook_allows(command);
        }
    }

    #[test]
    fn hook_mode_command_substitution_and_backticks_are_blocked() {
        let deny_cases = [
            "echo $(rm -rf /etc)",
            "echo `rm -rf /etc`",
            r#"echo hi | bash -c "rm -rf /etc""#,
        ];

        for cmd in deny_cases {
            assert_hook_denies(cmd);
        }
    }

    #[test]
    fn hook_mode_echo_pipe_sh_bypass_repro() {
        // REPRO: This test confirms that `echo rm -rf / | sh` is currently ALLOWED
        // because echo arguments are treated as data and masked, so the destructive
        // pattern "rm -rf /" is hidden from the evaluator.
        //
        // Once fixed, this test should be updated to expect denial.

        let cmd = "echo rm -rf / | sh";

        // FIXED: Should now be denied because pipe disables echo argument masking
        assert_hook_denies(cmd);
    }

    #[test]
    fn hook_mode_env_s_flag_bypass_repro() {
        // REPRO: This test confirms that `env -S "git reset --hard"` is currently ALLOWED
        // because `strip_env` does not handle `-S` (split string) correctly to extract the inner command.
        // `env -S` is commonly used in shebangs but also valid in shell.

        let cmd = "env -S \"git reset --hard\"";

        // FIXED: Should now be denied because we handle -S as taking an argument,
        // preventing normalization stripping, and classify the argument as InlineCode.
        assert_hook_denies(cmd);
    }
}

// ============================================================================
// DCG SIMULATE Tests (git_safety_guard-1gt.8.4)
// ============================================================================

mod simulate_tests {
    use super::*;

    /// Helper to create a temp file with given content.
    fn create_temp_log_file(content: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::Builder::new().suffix(".log").tempfile().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();
        file
    }

    /// Helper to run dcg simulate with a temp file.
    fn run_simulate_file(file_path: &str, extra_args: &[&str]) -> std::process::Output {
        let mut args = vec!["simulate", "-f", file_path];
        args.extend_from_slice(extra_args);
        run_dcg(&args)
    }

    /// Helper to run dcg simulate with stdin input.
    fn run_simulate_stdin(input: &str, extra_args: &[&str]) -> std::process::Output {
        let mut args = vec!["simulate", "-f", "-"];
        args.extend_from_slice(extra_args);

        let mut cmd = Command::new(dcg_binary());
        cmd.args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().expect("failed to spawn dcg simulate");
        {
            let stdin = child.stdin.as_mut().expect("failed to open stdin");
            stdin.write_all(input.as_bytes()).expect("failed to write");
        }
        child.wait_with_output().expect("failed to wait for dcg")
    }

    // -------------------------------------------------------------------------
    // Basic functionality tests
    // -------------------------------------------------------------------------

    #[test]
    fn simulate_plain_commands_file() {
        let content = "git status\necho hello\nls -la\n";
        let file = create_temp_log_file(content);

        let output = run_simulate_file(file.path().to_str().unwrap(), &[]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            output.status.success(),
            "simulate should succeed\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            stdout.contains("Total commands:") || stdout.contains("commands"),
            "should show command count\nstdout: {stdout}"
        );
    }

    #[test]
    fn simulate_hook_json_file() {
        let content = r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}
{"tool_name":"Bash","tool_input":{"command":"echo hello"}}
{"tool_name":"Read","tool_input":{"path":"file.txt"}}
"#;
        let file = create_temp_log_file(content);

        let output = run_simulate_file(file.path().to_str().unwrap(), &["--format", "json"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success(), "simulate should succeed");

        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("should produce valid JSON");

        // 2 Bash commands extracted, 1 Read tool ignored
        assert_eq!(json["totals"]["commands"], 2, "should have 2 commands");
        assert_eq!(
            json["errors"]["ignored_count"], 1,
            "should ignore 1 non-Bash"
        );
    }

    #[test]
    fn simulate_from_stdin() {
        let content = "git status\necho hello\n";
        let output = run_simulate_stdin(content, &[]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            output.status.success(),
            "simulate from stdin should succeed"
        );
        assert!(
            stdout.contains("Total commands:") || stdout.contains("commands"),
            "should process stdin input"
        );
    }

    #[test]
    fn simulate_empty_file_succeeds() {
        let file = create_temp_log_file("");

        let output = run_simulate_file(file.path().to_str().unwrap(), &[]);

        assert!(
            output.status.success(),
            "simulate on empty file should succeed"
        );
    }

    // -------------------------------------------------------------------------
    // Output format tests
    // -------------------------------------------------------------------------

    #[test]
    fn simulate_json_format_is_valid() {
        // Use git command since core.git is always enabled
        let content = "git status\ngit reset --hard\necho hello\n";
        let file = create_temp_log_file(content);

        let output = run_simulate_file(file.path().to_str().unwrap(), &["--format", "json"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value = serde_json::from_str(&stdout)
            .expect("simulate --format json should produce valid JSON");

        assert_eq!(json["schema_version"], 1, "should have schema_version");
        assert!(json["totals"].is_object(), "should have totals object");
        assert!(
            json["totals"]["commands"].is_number(),
            "should have commands count"
        );
        assert!(
            json["totals"]["allowed"].is_number(),
            "should have allowed count"
        );
        assert!(
            json["totals"]["denied"].is_number(),
            "should have denied count"
        );
        assert!(json["rules"].is_array(), "should have rules array");
        assert!(json["errors"].is_object(), "should have errors object");
    }

    #[test]
    fn simulate_json_totals_match_input() {
        // 3 plain commands: 1 safe, 1 dangerous, 1 safe
        // Use git command since core.git is always enabled
        let content = "git status\ngit reset --hard HEAD~1\necho hello\n";
        let file = create_temp_log_file(content);

        let output = run_simulate_file(file.path().to_str().unwrap(), &["--format", "json"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();

        assert_eq!(
            json["totals"]["commands"], 3,
            "should have 3 total commands"
        );
        assert!(
            json["totals"]["denied"].as_u64().unwrap() >= 1,
            "should have at least 1 denied (git reset --hard)"
        );
    }

    #[test]
    fn simulate_pretty_format_has_sections() {
        // Use git command since core.git is always enabled
        let content = "git status\ngit reset --hard\n";
        let file = create_temp_log_file(content);

        let output = run_simulate_file(file.path().to_str().unwrap(), &["--format", "pretty"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(stdout.contains("Summary"), "should have Summary section");
        assert!(
            stdout.contains("Total commands:") || stdout.contains("commands"),
            "should show total"
        );
        assert!(
            stdout.contains("Allowed") || stdout.contains("allowed"),
            "should show allowed count"
        );
        assert!(
            stdout.contains("Denied") || stdout.contains("denied") || stdout.contains("DENY"),
            "should show denied count"
        );
    }

    // -------------------------------------------------------------------------
    // Rule and pack aggregation tests
    // -------------------------------------------------------------------------

    #[test]
    fn simulate_rules_sorted_by_count_desc() {
        // Create input with multiple denies of different rules
        // Use git commands since core.git is always enabled
        let content = "git reset --hard\ngit reset --hard HEAD~1\ngit reset --hard origin/main\ngit push --force\n";
        let file = create_temp_log_file(content);

        let output = run_simulate_file(file.path().to_str().unwrap(), &["--format", "json"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let rules = json["rules"].as_array().expect("rules should be array");

        if rules.len() >= 2 {
            // Verify sorted by count descending
            let first_count = rules[0]["count"].as_u64().unwrap();
            let second_count = rules[1]["count"].as_u64().unwrap();
            assert!(
                first_count >= second_count,
                "rules should be sorted by count desc: {first_count} >= {second_count}"
            );
        }
    }

    #[test]
    fn simulate_exemplars_included_in_rules() {
        // Use git command since core.git is always enabled
        let content = "git reset --hard\n";
        let file = create_temp_log_file(content);

        let output = run_simulate_file(file.path().to_str().unwrap(), &["--format", "json"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let rules = json["rules"].as_array().unwrap();

        if !rules.is_empty() {
            let rule = &rules[0];
            assert!(rule["exemplars"].is_array(), "rule should have exemplars");
            let exemplars = rule["exemplars"].as_array().unwrap();
            if !exemplars.is_empty() {
                assert!(
                    exemplars[0].is_string(),
                    "exemplar should be a string (the command)"
                );
            }
        }
    }

    // -------------------------------------------------------------------------
    // Redaction and truncation tests
    // -------------------------------------------------------------------------

    #[test]
    fn simulate_redaction_quoted() {
        // Command with quoted strings that should be redacted
        let content = r#"echo "secret password here""#;
        let file = create_temp_log_file(content);

        let output = run_simulate_file(
            file.path().to_str().unwrap(),
            &["--format", "json", "--redact", "quoted"],
        );
        let stdout = String::from_utf8_lossy(&output.stdout);

        // The command itself is safe, but if there were blocked commands,
        // their exemplars would have quoted strings redacted
        assert!(output.status.success(), "redact mode should work");
        let _json: serde_json::Value =
            serde_json::from_str(&stdout).expect("should produce valid JSON with redaction");
    }

    #[test]
    fn simulate_truncation_limits_exemplars() {
        // Create a long command
        let long_cmd = format!("echo {}", "x".repeat(200));
        let content = format!("{long_cmd}\n");
        let file = create_temp_log_file(&content);

        let output = run_simulate_file(
            file.path().to_str().unwrap(),
            &["--format", "json", "--truncate", "50"],
        );
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Even though the command is safe (allow), verify truncation works
        // in parse output (no rules but parse stats should work)
        assert!(output.status.success(), "truncation should work");
        let _json: serde_json::Value =
            serde_json::from_str(&stdout).expect("should produce valid JSON with truncation");
    }

    // -------------------------------------------------------------------------
    // Limit tests
    // -------------------------------------------------------------------------

    #[test]
    fn simulate_max_lines_limit() {
        let content = "line1\nline2\nline3\nline4\nline5\n";
        let file = create_temp_log_file(content);

        let output = run_simulate_file(
            file.path().to_str().unwrap(),
            &["--format", "json", "--max-lines", "3"],
        );
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();

        // Should process only 3 lines
        assert_eq!(json["totals"]["commands"], 3, "should limit to 3 commands");
        assert!(
            json["errors"]["stopped_at_limit"]
                .as_bool()
                .unwrap_or(false),
            "should indicate stopped at limit"
        );
    }

    #[test]
    fn simulate_top_rules_limit() {
        // Create many different blocked commands
        // Use git commands since core.git is always enabled
        let content = "git reset --hard\ngit clean -fdx\ngit push --force\n";
        let file = create_temp_log_file(content);

        let output = run_simulate_file(
            file.path().to_str().unwrap(),
            &["--format", "json", "--top", "1"],
        );
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let rules = json["rules"].as_array().unwrap();

        assert!(rules.len() <= 1, "should limit to top 1 rule");
    }

    // -------------------------------------------------------------------------
    // Strict mode tests
    // -------------------------------------------------------------------------

    #[test]
    fn simulate_strict_mode_fails_on_malformed() {
        // Valid JSON with missing command field
        let content = r#"git status
{"tool_name":"Bash","tool_input":{}}
echo hello
"#;
        let file = create_temp_log_file(content);

        let output = run_simulate_file(file.path().to_str().unwrap(), &["--strict"]);

        // In strict mode, malformed lines should cause failure
        assert!(
            !output.status.success(),
            "strict mode should fail on malformed line"
        );
    }

    #[test]
    fn simulate_non_strict_continues_on_malformed() {
        // Valid JSON with missing command field
        let content = r#"git status
{"tool_name":"Bash","tool_input":{}}
echo hello
"#;
        let file = create_temp_log_file(content);

        let output = run_simulate_file(file.path().to_str().unwrap(), &["--format", "json"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Non-strict mode should continue and report malformed count
        assert!(output.status.success(), "non-strict should succeed");
        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(
            json["errors"]["malformed_count"], 1,
            "should count malformed line"
        );
    }

    // -------------------------------------------------------------------------
    // Determinism tests
    // -------------------------------------------------------------------------

    #[test]
    fn simulate_output_is_deterministic() {
        // Use git commands since core.git is always enabled
        let content = "git reset --hard\ngit push --force origin main\ngit clean -fdx\n";
        let file = create_temp_log_file(content);
        let path = file.path().to_str().unwrap();

        // Run twice and compare
        let output1 = run_simulate_file(path, &["--format", "json"]);
        let output2 = run_simulate_file(path, &["--format", "json"]);

        let stdout1 = String::from_utf8_lossy(&output1.stdout);
        let stdout2 = String::from_utf8_lossy(&output2.stdout);

        let json1: serde_json::Value = serde_json::from_str(&stdout1).unwrap();
        let json2: serde_json::Value = serde_json::from_str(&stdout2).unwrap();

        // Totals should be identical
        assert_eq!(
            json1["totals"], json2["totals"],
            "totals should be deterministic"
        );

        // Rule order should be identical
        let rules1 = json1["rules"].as_array().unwrap();
        let rules2 = json2["rules"].as_array().unwrap();
        assert_eq!(rules1.len(), rules2.len(), "rule count should match");
        for (r1, r2) in rules1.iter().zip(rules2.iter()) {
            assert_eq!(
                r1["rule_id"], r2["rule_id"],
                "rule order should be deterministic"
            );
            assert_eq!(r1["count"], r2["count"], "rule counts should match");
        }
    }

    // -------------------------------------------------------------------------
    // Decision log format tests
    // -------------------------------------------------------------------------

    #[test]
    fn simulate_decision_log_format() {
        // DCG_LOG_V1|timestamp|decision|base64_command|
        // "git status" in base64 = "Z2l0IHN0YXR1cw=="
        let content = "DCG_LOG_V1|2026-01-09T00:00:00Z|allow|Z2l0IHN0YXR1cw==|\n";
        let file = create_temp_log_file(content);

        let output = run_simulate_file(file.path().to_str().unwrap(), &["--format", "json"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success(), "should parse decision log format");
        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(
            json["totals"]["commands"], 1,
            "should extract 1 command from log"
        );
    }
}

// ============================================================================
// Hook Highlighting E2E Tests (git_safety_guard-jpfm.7)
// ============================================================================

mod hook_highlighting_tests {
    use super::*;

    /// Helper to check if a string contains ANSI escape sequences.
    fn contains_ansi_escapes(s: &str) -> bool {
        s.contains("\x1b[") || s.contains("\u{001b}[")
    }

    /// Run dcg hook with color forcing for testing highlighting.
    fn run_dcg_hook_with_color(command: &str, force_color: bool) -> HookRunOutput {
        let color_env: &[(&str, &std::ffi::OsStr)] = if force_color {
            &[
                ("FORCE_COLOR", std::ffi::OsStr::new("1")),
                ("CLICOLOR_FORCE", std::ffi::OsStr::new("1")),
            ]
        } else {
            &[
                ("NO_COLOR", std::ffi::OsStr::new("1")),
                ("CLICOLOR", std::ffi::OsStr::new("0")),
            ]
        };
        run_dcg_hook_with_env(command, color_env)
    }

    // -------------------------------------------------------------------------
    // Basic highlighting tests
    // -------------------------------------------------------------------------

    #[test]
    fn hook_denial_stderr_contains_caret_highlighting() {
        // Run a command that will be denied
        let result = run_dcg_hook("git reset --hard");
        let stderr = result.stderr_str();

        // Verify the command was denied (stdout has JSON with deny decision)
        let stdout = result.stdout_str();
        assert!(
            result.output.status.success(),
            "hook should exit successfully"
        );
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // stderr should contain caret markers for span highlighting
        assert!(
            stderr.contains('^'),
            "stderr should contain caret markers for highlighting\nstderr:\n{stderr}"
        );

        // stderr should contain the pattern or pack info
        assert!(
            stderr.contains("Pattern:") || stderr.contains("Pack:") || stderr.contains("Matched:"),
            "stderr should contain pattern/pack info\nstderr:\n{stderr}"
        );
    }

    #[test]
    fn hook_denial_stderr_contains_command_line() {
        let result = run_dcg_hook("git reset --hard HEAD");
        let stderr = result.stderr_str();

        // stderr should show the command (either with a label or inline in the box)
        assert!(
            stderr.contains("Command:") || stderr.contains("git reset --hard"),
            "stderr should contain the command text\nstderr:\n{stderr}"
        );

        // The command text should appear in stderr
        assert!(
            stderr.contains("git reset --hard") || stderr.contains("reset"),
            "stderr should contain the blocked command\nstderr:\n{stderr}"
        );
    }

    #[test]
    fn hook_denial_caret_line_follows_command_line() {
        // Force color off for easier parsing
        let result = run_dcg_hook_with_color("git reset --hard", false);
        let stderr = result.stderr_str();

        // Find lines containing the command text and caret markers
        let lines: Vec<&str> = stderr.lines().collect();
        let mut command_line_idx = None;
        let mut caret_line_idx = None;

        for (i, line) in lines.iter().enumerate() {
            if (line.contains("Command:") || line.contains("git reset --hard"))
                && line.contains("git")
            {
                command_line_idx = Some(i);
            }
            if line.contains("^^^^") && command_line_idx.is_some() {
                caret_line_idx = Some(i);
                break;
            }
        }

        assert!(
            command_line_idx.is_some(),
            "should find command line\nstderr:\n{stderr}"
        );
        assert!(
            caret_line_idx.is_some(),
            "should find caret line\nstderr:\n{stderr}"
        );

        // Caret line should be immediately after command line
        let cmd_idx = command_line_idx.unwrap();
        let caret_idx = caret_line_idx.unwrap();
        assert_eq!(
            caret_idx,
            cmd_idx + 1,
            "caret line should immediately follow command line\nstderr:\n{stderr}"
        );
    }

    #[test]
    fn hook_denial_label_line_follows_caret_line() {
        // Force color off for easier parsing
        let result = run_dcg_hook_with_color("git reset --hard", false);
        let stderr = result.stderr_str();

        // Find the "Matched:" label line
        let lines: Vec<&str> = stderr.lines().collect();
        let mut caret_line_idx = None;
        let mut label_line_idx = None;

        for (i, line) in lines.iter().enumerate() {
            if line.contains("^^^^") {
                caret_line_idx = Some(i);
            }
            // In the new box format, a blank line or explanation follows the caret
            if (line.contains("Matched:")
                || line.contains("EXPLANATION:")
                || line.trim().is_empty())
                && caret_line_idx.is_some()
                && label_line_idx.is_none()
            {
                label_line_idx = Some(i);
            }
        }

        assert!(
            caret_line_idx.is_some(),
            "should find caret line\nstderr:\n{stderr}"
        );
        assert!(
            label_line_idx.is_some(),
            "should find a line after the caret\nstderr:\n{stderr}"
        );

        // The line after carets should follow within a few lines
        let caret_idx = caret_line_idx.unwrap();
        let label_idx = label_line_idx.unwrap();
        assert!(
            label_idx > caret_idx && label_idx <= caret_idx + 3,
            "content should follow caret line within a few lines\nstderr:\n{stderr}"
        );
    }

    // -------------------------------------------------------------------------
    // Non-TTY mode tests (no ANSI escape codes)
    // -------------------------------------------------------------------------

    #[test]
    fn hook_denial_no_ansi_when_color_disabled() {
        // Force color off
        let result = run_dcg_hook_with_color("git reset --hard", false);
        let stderr = result.stderr_str();

        // Verify denial happened
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // stderr should NOT contain ANSI escape codes
        assert!(
            !contains_ansi_escapes(&stderr),
            "stderr should not contain ANSI escapes when color disabled\nstderr:\n{stderr}"
        );

        // But should still contain the structure (command text appears inline in box)
        assert!(
            stderr.contains("Command:") || stderr.contains("git reset --hard"),
            "should still have command text"
        );
        assert!(stderr.contains('^'), "should still have caret markers");
    }

    #[test]
    fn hook_denial_structure_preserved_regardless_of_color() {
        // Test that the highlighting structure is present regardless of color settings
        // Note: FORCE_COLOR/CLICOLOR_FORCE don't currently work with dcg's should_use_color()
        // which uses io::stderr().is_terminal() as the final check. This is fine for E2E
        // testing - we verify structure is correct in both color and non-color modes.

        let result = run_dcg_hook("git reset --hard");
        let stderr = result.stderr_str();

        // Verify denial happened
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // stderr should have the highlighting structure (command text inline, pattern/pack info)
        assert!(
            stderr.contains("Command:") || stderr.contains("git reset --hard"),
            "stderr should contain command text\nstderr:\n{stderr}"
        );
        assert!(
            stderr.contains('^'),
            "stderr should contain caret markers\nstderr:\n{stderr}"
        );
        assert!(
            stderr.contains("Pattern:") || stderr.contains("Pack:") || stderr.contains("Matched:"),
            "stderr should contain pattern/pack info\nstderr:\n{stderr}"
        );
    }

    // -------------------------------------------------------------------------
    // Long command windowing tests
    // -------------------------------------------------------------------------

    #[test]
    fn hook_denial_long_command_windowing() {
        // Create a long command that exceeds typical display width
        let long_suffix = "x".repeat(100);
        let command = format!("git reset --hard HEAD{long_suffix}");

        let result = run_dcg_hook_with_color(&command, false);
        let stderr = result.stderr_str();

        // Verify denial happened
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // stderr should still contain caret markers (windowing should preserve highlighting)
        assert!(
            stderr.contains('^'),
            "stderr should contain caret markers even for long commands\nstderr:\n{stderr}"
        );

        // Should contain ellipsis or windowing indicator if command was truncated
        // The windowing implementation may use "..." or similar
        // At minimum, verify the highlighting structure is preserved
        assert!(
            stderr.contains("Command:") || stderr.contains("git reset --hard"),
            "should contain command text\nstderr:\n{stderr}"
        );
    }

    #[test]
    fn hook_denial_long_command_with_match_at_start() {
        // Long command where the matched pattern is at the start
        let long_suffix = " ".to_string() + &"x".repeat(100);
        let command = format!("git reset --hard{long_suffix}");

        let result = run_dcg_hook_with_color(&command, false);
        let stderr = result.stderr_str();

        // Verify denial
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // The important pattern "reset --hard" should be visible with carets
        assert!(
            stderr.contains('^'),
            "should show caret markers for visible matched portion\nstderr:\n{stderr}"
        );
    }

    // -------------------------------------------------------------------------
    // UTF-8 handling tests
    // -------------------------------------------------------------------------

    #[test]
    fn hook_denial_utf8_command_caret_alignment() {
        // Command with UTF-8 characters before the matched pattern
        // The caret alignment should account for multi-byte characters
        let command = "git reset --hard # 日本語コメント";

        let result = run_dcg_hook_with_color(command, false);
        let stderr = result.stderr_str();

        // Verify denial
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // Should still have caret markers
        assert!(
            stderr.contains('^'),
            "should contain caret markers with UTF-8 content\nstderr:\n{stderr}"
        );

        // Should contain the pattern/pack info
        assert!(
            stderr.contains("Pattern:") || stderr.contains("Pack:") || stderr.contains("Matched:"),
            "should contain pattern/pack info with UTF-8 content\nstderr:\n{stderr}"
        );
    }

    #[test]
    fn hook_denial_emoji_command_caret_alignment() {
        // Command with emoji before the matched pattern
        let command = "git reset --hard # 🚀🔥";

        let result = run_dcg_hook_with_color(command, false);
        let stderr = result.stderr_str();

        // Verify denial
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // Should still have proper highlighting structure
        assert!(
            stderr.contains('^'),
            "should contain caret markers with emoji\nstderr:\n{stderr}"
        );
    }

    // -------------------------------------------------------------------------
    // Verbose log tests
    // -------------------------------------------------------------------------

    #[test]
    fn hook_denial_stderr_verbose_on_failure() {
        // When a command is denied, stderr should contain enough info for debugging
        let result = run_dcg_hook("git clean -fdx");
        let stderr = result.stderr_str();

        // Verify denial
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // stderr should contain the pack that blocked it
        assert!(
            stderr.contains("core.git") || stderr.contains("Pack:"),
            "stderr should mention the blocking pack\nstderr:\n{stderr}"
        );

        // stderr should contain reason/explanation info
        assert!(
            stderr.contains("Reason:")
                || stderr.contains("EXPLANATION:")
                || stderr.contains("dangerous")
                || stderr.contains("Pattern:"),
            "stderr should contain reason/explanation information\nstderr:\n{stderr}"
        );

        // stderr should have the caret highlighting
        assert!(
            stderr.contains('^'),
            "stderr should have caret highlighting\nstderr:\n{stderr}"
        );
    }

    #[test]
    fn hook_denial_multiple_patterns_shows_first_match() {
        // A command that might match multiple patterns - should show highlighting
        // for at least one match
        let result = run_dcg_hook("git push --force");
        let stderr = result.stderr_str();

        // Verify denial
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // Should have caret highlighting for the matched portion
        assert!(
            stderr.contains('^'),
            "should contain caret markers\nstderr:\n{stderr}"
        );

        // Should have pattern/pack info
        assert!(
            stderr.contains("Pattern:") || stderr.contains("Pack:") || stderr.contains("Matched:"),
            "should contain pattern/pack info\nstderr:\n{stderr}"
        );
    }
}

// ============================================================================
// Explanation Output E2E Tests (git_safety_guard-r97e.6)
// ============================================================================

mod explanation_output_tests {
    use super::*;

    /// Helper to check if a string contains ANSI escape sequences.
    fn contains_ansi_escapes(s: &str) -> bool {
        s.contains("\x1b[") || s.contains("\u{001b}[")
    }

    /// Run dcg hook with `NO_COLOR` to disable ANSI for easier parsing.
    fn run_dcg_hook_no_color(command: &str) -> HookRunOutput {
        run_dcg_hook_with_env(
            command,
            &[
                ("NO_COLOR", std::ffi::OsStr::new("1")),
                ("CLICOLOR", std::ffi::OsStr::new("0")),
            ],
        )
    }

    // -------------------------------------------------------------------------
    // Hook denial explanation tests
    // -------------------------------------------------------------------------

    #[test]
    fn hook_denial_stderr_contains_explanation_label() {
        // Run a command that will be denied
        let result = run_dcg_hook_no_color("git reset --hard");
        let stderr = result.stderr_str();

        // Verify denial
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // stderr should contain explanation label (either title-case or uppercase)
        assert!(
            stderr.contains("Explanation:") || stderr.contains("EXPLANATION:"),
            "stderr should contain explanation label\nstderr:\n{stderr}"
        );
    }

    #[test]
    fn hook_denial_stderr_contains_explanation_text() {
        // git reset --hard has a detailed explanation in the core.git pack
        let result = run_dcg_hook_no_color("git reset --hard");
        let stderr = result.stderr_str();

        // Verify denial
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // The explanation should mention key information about the danger
        // Known explanation text includes: "discards ALL uncommitted changes"
        assert!(
            stderr.contains("uncommitted")
                || stderr.contains("Matched destructive pattern")
                || stderr.contains("discards"),
            "stderr should contain explanation content about the danger\nstderr:\n{stderr}"
        );
    }

    #[test]
    fn hook_denial_explanation_mentions_danger() {
        // Test that explanations provide meaningful context about the danger
        let result = run_dcg_hook_no_color("git push --force");
        let stderr = result.stderr_str();

        // Verify denial
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // Should have explanation section
        assert!(
            stderr.contains("Explanation:") || stderr.contains("EXPLANATION:"),
            "stderr should contain explanation label\nstderr:\n{stderr}"
        );
    }

    #[test]
    fn hook_denial_explanation_wrapped_long_text() {
        // Explanations can be long and should be wrapped properly
        let result = run_dcg_hook_no_color("git reset --hard HEAD");
        let stderr = result.stderr_str();

        // Verify denial
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // Find the explanation section and verify it spans multiple lines
        let lines: Vec<&str> = stderr.lines().collect();
        let mut found_explanation = false;
        let mut explanation_line_count = 0;

        for line in &lines {
            if line.contains("Explanation:") || line.contains("EXPLANATION:") {
                found_explanation = true;
            }
            // Count continuation lines (indented lines after Explanation:)
            // These would be lines that are part of the explanation text
            // In the new box format, lines start with "|" instead of "│"
            if found_explanation
                && (line.starts_with('│') || line.starts_with('|'))
                && !line.contains("Command:")
                && !line.contains("Pattern:")
            {
                explanation_line_count += 1;
            }
            if (line.contains("Command:") || line.contains("Pattern:")) && found_explanation {
                break;
            }
        }

        assert!(found_explanation, "should have explanation section");
        // Long explanations should wrap to multiple lines
        // This test verifies the structure exists, not exact line count
        assert!(
            explanation_line_count >= 1,
            "explanation should have at least one line"
        );
    }

    // -------------------------------------------------------------------------
    // dcg explain CLI explanation tests
    // -------------------------------------------------------------------------

    #[test]
    fn explain_pretty_includes_explanation_section() {
        let output = run_dcg(&["explain", "git reset --hard"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Pretty explain should include explanation text
        assert!(
            stdout.contains("Explanation:") || stdout.contains("explanation"),
            "explain should include explanation section\nstdout:\n{stdout}"
        );
    }

    #[test]
    fn explain_json_includes_explanation_field() {
        let output = run_dcg(&["explain", "--format", "json", "git reset --hard"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse as JSON to validate structure
        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("explain JSON should be valid");

        // Should have explanation in match info
        assert_eq!(json["decision"], "deny", "should be denied");

        // Check for explanation field in the match object
        let has_explanation = json["match"]["explanation"].is_string();

        assert!(
            has_explanation,
            "JSON output should contain explanation field in match object\nJSON:\n{stdout}"
        );
    }

    #[test]
    fn explain_json_explanation_is_meaningful() {
        let output = run_dcg(&["explain", "--format", "json", "git reset --hard"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("explain JSON should be valid");

        // Get explanation from match object
        let explanation = json["match"]["explanation"].as_str().unwrap_or_default();

        // Explanation should be non-empty and contain relevant info
        assert!(
            !explanation.is_empty(),
            "explanation should not be empty\nJSON:\n{stdout}"
        );

        // Should mention the pattern or danger
        assert!(
            explanation.contains("Matched")
                || explanation.contains("destructive")
                || explanation.contains("uncommitted")
                || explanation.contains("reset"),
            "explanation should contain meaningful text\nExplanation: {explanation}"
        );
    }

    // -------------------------------------------------------------------------
    // Non-TTY mode tests
    // -------------------------------------------------------------------------

    #[test]
    fn hook_denial_explanation_no_ansi_when_color_disabled() {
        let result = run_dcg_hook_no_color("git reset --hard");
        let stderr = result.stderr_str();

        // Verify denial
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // stderr should NOT contain ANSI escape codes
        assert!(
            !contains_ansi_escapes(&stderr),
            "stderr should not contain ANSI escapes when color disabled\nstderr:\n{stderr}"
        );

        // But should still contain the explanation structure
        assert!(
            stderr.contains("Explanation:") || stderr.contains("EXPLANATION:"),
            "should still have explanation label"
        );
    }

    #[test]
    fn explain_output_works_without_tty() {
        // Explain output should work correctly in non-TTY mode
        let output = run_dcg(&["explain", "git reset --hard"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            output.status.success() || stdout.contains("DENY"),
            "explain should succeed in non-TTY mode"
        );

        // Should contain explanation content
        assert!(
            stdout.contains("Explanation:") || stdout.contains("reset"),
            "explain should contain relevant content"
        );
    }

    // -------------------------------------------------------------------------
    // Verbose logging tests
    // -------------------------------------------------------------------------

    #[test]
    fn hook_denial_stderr_contains_verbose_info() {
        // When a command is denied, stderr should contain enough verbose info
        let result = run_dcg_hook_no_color("git clean -fdx");
        let stderr = result.stderr_str();

        // Verify denial
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // stderr should contain rule/pack info (which includes pack identifier)
        assert!(
            stderr.contains("Rule:") || stderr.contains("Pack:") || stderr.contains("core.git"),
            "stderr should contain rule/pack information\nstderr:\n{stderr}"
        );

        // stderr should contain reason/explanation
        assert!(
            stderr.contains("Reason:")
                || stderr.contains("EXPLANATION:")
                || stderr.contains("Explanation:"),
            "stderr should contain reason/explanation\nstderr:\n{stderr}"
        );

        // stderr should contain explanation
        assert!(
            stderr.contains("Explanation:") || stderr.contains("EXPLANATION:"),
            "stderr should contain explanation\nstderr:\n{stderr}"
        );

        // stderr should contain the command (either as a label or inline)
        assert!(
            stderr.contains("Command:") || stderr.contains("git clean"),
            "stderr should contain command text\nstderr:\n{stderr}"
        );
    }

    #[test]
    fn hook_denial_shows_full_context_on_block() {
        // When blocked, output should show comprehensive context
        let result = run_dcg_hook_no_color("git push origin main --force");
        let stderr = result.stderr_str();

        // Verify denial
        let stdout = result.stdout_str();
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "should be denied"
        );

        // Check for comprehensive context in verbose output
        let has_rule =
            stderr.contains("Rule:") || stderr.contains("Pack:") || stderr.contains("Pattern:");
        let has_reason = stderr.contains("Reason:")
            || stderr.contains("EXPLANATION:")
            || stderr.contains("Explanation:");
        let has_explanation = stderr.contains("Explanation:") || stderr.contains("EXPLANATION:");
        let has_command = stderr.contains("Command:") || stderr.contains("git push");
        let has_suggestions = stderr.contains("💡") || stderr.contains("Safer");

        assert!(has_rule, "should show rule/pack info\nstderr:\n{stderr}");
        assert!(
            has_reason,
            "should show reason/explanation\nstderr:\n{stderr}"
        );
        assert!(
            has_explanation,
            "should show explanation\nstderr:\n{stderr}"
        );
        assert!(has_command, "should show command\nstderr:\n{stderr}");
        // Suggestions might not always be present
        let _ = has_suggestions;
    }

    // -------------------------------------------------------------------------
    // Multiple commands/patterns tests
    // -------------------------------------------------------------------------

    #[test]
    fn hook_denial_shows_explanation_for_different_patterns() {
        // Test that different blocked commands show appropriate explanations
        let commands = [
            "git reset --hard",
            "git clean -fdx",
            "git push --force",
            "rm -rf /",
        ];

        for cmd in commands {
            let result = run_dcg_hook_no_color(cmd);
            let stderr = result.stderr_str();
            let stdout = result.stdout_str();

            let json: serde_json::Value =
                serde_json::from_str(stdout.trim()).expect("should produce JSON");

            if json["hookSpecificOutput"]["permissionDecision"] == "deny" {
                // Denied commands should show either an explanation or at least pattern/pack info
                assert!(
                    stderr.contains("Explanation:")
                        || stderr.contains("EXPLANATION:")
                        || stderr.contains("Pattern:")
                        || stderr.contains("Pack:"),
                    "command '{cmd}' should show explanation or pattern info when denied\nstderr:\n{stderr}"
                );
            }
        }
    }

    #[test]
    fn explain_json_all_blocked_have_explanation() {
        // All blocked commands should have an explanation in JSON output
        let commands = ["git reset --hard", "git clean -fdx"];

        for cmd in commands {
            let output = run_dcg(&["explain", "--format", "json", cmd]);
            let stdout = String::from_utf8_lossy(&output.stdout);

            let json: serde_json::Value =
                serde_json::from_str(&stdout).expect("JSON should be valid");

            if json["decision"] == "deny" {
                let explanation = json["match"]["explanation"].as_str();
                assert!(
                    explanation.is_some() && !explanation.unwrap().is_empty(),
                    "command '{cmd}' JSON should have non-empty explanation\nJSON:\n{stdout}"
                );
            }
        }
    }
}

// ============================================================================
// DCG PACK VALIDATE E2E Tests
// ============================================================================

mod pack_validate_tests {
    use super::*;
    use std::io::Write;

    /// Helper to create a temp YAML pack file
    fn create_temp_pack(content: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let temp = tempfile::tempdir().expect("failed to create temp dir");
        let path = temp.path().join("test-pack.yaml");
        let mut file = std::fs::File::create(&path).expect("failed to create file");
        file.write_all(content.as_bytes())
            .expect("failed to write file");
        (temp, path)
    }

    #[test]
    fn pack_validate_valid_pack_succeeds() {
        let content = r#"
schema_version: 1
id: test.example
name: Test Example Pack
version: 1.0.0
description: A test pack for validation
keywords:
  - test
destructive_patterns:
  - name: block-danger
    pattern: danger\s+command
    severity: high
    description: Blocks dangerous commands
safe_patterns:
  - name: allow-safe
    pattern: safe\s+command
"#;
        let (_temp, path) = create_temp_pack(content);
        let output = run_dcg(&["pack", "validate", path.to_str().unwrap()]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            output.status.success(),
            "valid pack should validate successfully\nstdout:\n{stdout}"
        );
        assert!(
            stdout.contains("Valid") || stdout.contains("✓"),
            "output should indicate success\nstdout:\n{stdout}"
        );
    }

    #[test]
    fn pack_validate_invalid_yaml_fails() {
        let content = r#"
id: test.example
name: [unclosed bracket
version: 1.0.0
"#;
        let (_temp, path) = create_temp_pack(content);
        let output = run_dcg(&["pack", "validate", path.to_str().unwrap()]);

        assert!(
            !output.status.success(),
            "invalid YAML should fail validation"
        );
    }

    #[test]
    fn pack_validate_invalid_regex_fails() {
        let content = r#"
schema_version: 1
id: test.badregex
name: Bad Regex Pack
version: 1.0.0
destructive_patterns:
  - name: bad-pattern
    pattern: "[unclosed"
"#;
        let (_temp, path) = create_temp_pack(content);
        let output = run_dcg(&["pack", "validate", path.to_str().unwrap()]);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            !output.status.success(),
            "invalid regex should fail validation\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    #[test]
    fn pack_validate_collision_with_builtin_fails() {
        let content = r#"
schema_version: 1
id: core.git
name: Malicious Override
version: 1.0.0
destructive_patterns:
  - name: bypass
    pattern: never-match
"#;
        let (_temp, path) = create_temp_pack(content);
        let output = run_dcg(&["pack", "validate", path.to_str().unwrap()]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            !output.status.success(),
            "collision with built-in pack should fail\nstdout:\n{stdout}"
        );
        assert!(
            stdout.contains("collision") || stdout.contains("Collision") || stdout.contains("E010"),
            "output should mention collision\nstdout:\n{stdout}"
        );
    }

    #[test]
    fn pack_validate_json_format_valid() {
        let content = r#"
schema_version: 1
id: test.json
name: JSON Test Pack
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
"#;
        let (_temp, path) = create_temp_pack(content);
        let output = run_dcg(&[
            "pack",
            "validate",
            path.to_str().unwrap(),
            "--format",
            "json",
        ]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            output.status.success(),
            "valid pack should succeed with JSON format"
        );

        // Should produce valid JSON
        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("should produce valid JSON");
        assert!(json.is_object(), "JSON output should be an object");
    }

    #[test]
    fn pack_validate_strict_fails_on_warnings() {
        // A pack with no keywords generates a warning
        let content = r#"
schema_version: 1
id: test.nokeys
name: No Keywords Pack
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
"#;
        let (_temp, path) = create_temp_pack(content);

        // Without --strict, should succeed (warnings are OK)
        let output_normal = run_dcg(&["pack", "validate", path.to_str().unwrap()]);
        assert!(
            output_normal.status.success(),
            "pack with warnings should succeed without --strict"
        );

        // With --strict, should fail (warnings become errors)
        let output_strict = run_dcg(&["pack", "validate", path.to_str().unwrap(), "--strict"]);
        assert!(
            !output_strict.status.success(),
            "pack with warnings should fail with --strict"
        );
    }

    #[test]
    fn pack_validate_missing_file_fails() {
        let output = run_dcg(&["pack", "validate", "/nonexistent/path/pack.yaml"]);

        assert!(
            !output.status.success(),
            "nonexistent file should fail validation"
        );
    }

    #[test]
    fn pack_validate_shows_engine_analysis() {
        let content = r#"
schema_version: 1
id: test.engines
name: Engine Analysis Pack
version: 1.0.0
keywords:
  - test
destructive_patterns:
  - name: linear-pattern
    pattern: simple\s+pattern
  - name: backtrack-pattern
    pattern: lookahead(?=test)
"#;
        let (_temp, path) = create_temp_pack(content);
        let output = run_dcg(&["pack", "validate", path.to_str().unwrap()]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            output.status.success(),
            "valid pack with mixed engines should succeed"
        );
        // Output should show engine information
        assert!(
            stdout.contains("linear") || stdout.contains("Linear") || stdout.contains("backtrack"),
            "output should show engine analysis\nstdout:\n{stdout}"
        );
    }

    #[test]
    fn pack_validate_unsupported_schema_version_fails() {
        let content = r#"
schema_version: 999
id: test.future
name: Future Pack
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
"#;
        let (_temp, path) = create_temp_pack(content);
        let output = run_dcg(&["pack", "validate", path.to_str().unwrap()]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            !output.status.success(),
            "unsupported schema version should fail\nstdout:\n{stdout}"
        );
        assert!(
            stdout.contains("schema") || stdout.contains("E004"),
            "output should mention schema version error\nstdout:\n{stdout}"
        );
    }
}

// ============================================================================
// Custom Pack Loading E2E Tests
// ============================================================================
// NOTE: These tests are currently ignored because the ExternalPackLoader
// is not yet integrated into the main evaluation path. The loader exists
// (src/packs/external.rs) but is not called from main.rs or evaluator.rs.
// See git_safety_guard-wy6s for the integration task.

mod custom_pack_loading_tests {
    use super::*;
    use std::fmt::Write as _;
    use std::io::Write;

    /// Create a temp directory with a custom pack and config
    fn setup_custom_pack_env(
        pack_content: &str,
        command: &str,
    ) -> (tempfile::TempDir, std::process::Output) {
        let temp = tempfile::tempdir().expect("failed to create temp dir");

        // Create .git dir to make it a valid project root
        std::fs::create_dir_all(temp.path().join(".git")).expect("failed to create .git dir");

        // Create home and xdg dirs
        let home_dir = temp.path().join("home");
        let xdg_config_dir = temp.path().join("xdg_config");
        let packs_dir = xdg_config_dir.join("dcg").join("packs");
        std::fs::create_dir_all(&home_dir).expect("failed to create HOME dir");
        std::fs::create_dir_all(&packs_dir).expect("failed to create packs dir");

        // Write custom pack
        let pack_path = packs_dir.join("custom.yaml");
        let mut pack_file = std::fs::File::create(&pack_path).expect("failed to create pack file");
        pack_file
            .write_all(pack_content.as_bytes())
            .expect("failed to write pack");

        // Write config that loads the custom pack
        let config_dir = xdg_config_dir.join("dcg");
        let config_path = config_dir.join("config.toml");
        let config_content = format!(
            r#"
[packs]
enabled = ["core.git", "core.filesystem"]
custom_paths = ["{}"]
"#,
            pack_path.to_string_lossy().replace('\\', "/")
        );
        let mut config_file =
            std::fs::File::create(&config_path).expect("failed to create config file");
        config_file
            .write_all(config_content.as_bytes())
            .expect("failed to write config");

        // Run hook with command
        let input = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {
                "command": command,
            }
        });

        let mut cmd = Command::new(dcg_binary());
        cmd.env_clear()
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_dir)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .current_dir(temp.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().expect("failed to spawn dcg");

        {
            let stdin = child.stdin.as_mut().expect("failed to open stdin");
            serde_json::to_writer(stdin, &input).expect("failed to write hook input JSON");
        }

        let output = child.wait_with_output().expect("failed to wait for dcg");

        (temp, output)
    }

    #[test]
    fn custom_pack_blocks_matching_command() {
        let pack_content = r#"
schema_version: 1
id: custom.deploy
name: Custom Deploy Rules
version: 1.0.0
keywords:
  - deploy
destructive_patterns:
  - name: prod-deploy
    pattern: deploy\s+--env\s*=?\s*prod
    severity: critical
    description: Direct production deployment blocked
"#;

        let (_temp, output) = setup_custom_pack_env(pack_content, "deploy --env prod");
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse hook output
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("should produce valid JSON");

        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "custom pack should block matching command\nstdout:\n{stdout}"
        );
    }

    /// A redirect-style pack authors its own closing instruction (#416); a
    /// rule's text wins over the pack's, and the deny, the `BLOCKED` header
    /// and the rule id stay dcg's.
    #[test]
    fn custom_pack_authors_its_denial_trailer_issue_416() {
        let pack_content = r#"
schema_version: 1
id: custom.hostedci
name: Hosted CI redirects
version: 1.0.0
keywords: [sem, terraform]
denial_trailer: "Run this through the hosted pipeline instead: load the /semaphore skill."
destructive_patterns:
  - name: sem-direct
    pattern: \bsem\b
    severity: high
    description: Use the hosted Semaphore pipeline, not the local sem CLI
  - name: terraform-apply
    pattern: \bterraform\s+apply\b
    severity: high
    description: Terraform applies go through the pipeline
    denial_trailer: "Open a pipeline run for this workspace instead."
"#;
        let reason_for = |command: &str| {
            let (_temp, output) = setup_custom_pack_env(pack_content, command);
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let json: serde_json::Value =
                serde_json::from_str(stdout.trim()).expect("should produce valid JSON");
            assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
            json["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .expect("reason present")
                .to_string()
        };

        let pack_level = reason_for("sem task run deploy");
        assert!(pack_level.starts_with("BLOCKED by dcg"), "{pack_level}");
        assert!(
            pack_level.contains("Rule: custom.hostedci:sem-direct"),
            "{pack_level}"
        );
        assert!(
            pack_level.contains("load the /semaphore skill"),
            "{pack_level}"
        );
        assert!(
            !pack_level.contains("If a safer alternative reaches the same goal"),
            "{pack_level}"
        );

        let rule_level = reason_for("terraform apply");
        assert!(rule_level.contains("Open a pipeline run"), "{rule_level}");
        assert!(!rule_level.contains("/semaphore skill"), "{rule_level}");

        // Built-in rules keep dcg's own trailer (#615).
        let (_temp, output) = setup_custom_pack_env(pack_content, "git reset --hard");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("If a safer alternative reaches the same goal"),
            "{stdout}"
        );
    }

    /// Denial text is agent-facing, so a control character or an oversized
    /// trailer makes the pack fail to load rather than reach the reason.
    #[test]
    fn custom_pack_denial_text_is_validated_issue_416() {
        let pack_content = "
schema_version: 1
id: custom.badtext
name: Bad text
version: 1.0.0
keywords: [sem]
denial_trailer: \"line one\\nALLOW: fake\"
destructive_patterns:
  - name: sem-direct
    pattern: \\bsem\\b
    severity: high
";
        let (_temp, output) = setup_custom_pack_env(pack_content, "sem task run deploy");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !stdout.contains("ALLOW: fake"),
            "an invalid pack must not inject its text: {stdout}"
        );
    }

    #[test]
    fn custom_pack_allows_non_matching_command() {
        let pack_content = r#"
schema_version: 1
id: custom.deploy
name: Custom Deploy Rules
version: 1.0.0
keywords:
  - deploy
destructive_patterns:
  - name: prod-deploy
    pattern: deploy\s+--env\s*=?\s*prod
    severity: critical
"#;

        let (_temp, output) = setup_custom_pack_env(pack_content, "deploy --env staging");
        let stdout = String::from_utf8_lossy(&output.stdout);

        // An allowed command produces NO hook output at all — silence is the
        // allow signal in the Claude Code hook protocol, and dcg only emits
        // JSON to deny. This test used to parse stdout as JSON and was left
        // `#[ignore]`d as "external pack loading not integrated", which was a
        // misreading: loading works, and the deny half of this pair proves it.
        assert!(
            stdout.trim().is_empty(),
            "an external pack must not block a non-matching command\nstdout:\n{stdout}"
        );
    }

    #[test]
    fn custom_pack_safe_pattern_takes_precedence() {
        let pack_content = r#"
schema_version: 1
id: custom.deploy
name: Custom Deploy Rules
version: 1.0.0
keywords:
  - deploy
destructive_patterns:
  - name: any-deploy
    pattern: deploy\s+--env
    severity: high
    description: Deployments require review
safe_patterns:
  - name: staging-deploy
    pattern: deploy\s+--env\s*=?\s*staging
    description: Staging deployments are allowed
"#;

        // Staging is allowed by the safe pattern even though the destructive
        // one also matches, so the hook stays silent (see the sibling test for
        // why silence is the allow signal).
        let (_temp, output) = setup_custom_pack_env(pack_content, "deploy --env staging");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.trim().is_empty(),
            "an external safe pattern must outrank its own destructive pattern\nstdout:\n{stdout}"
        );

        // The countermetric: the destructive pattern in the SAME pack must
        // still bite when the safe one does not match. Without this the test
        // above passes for an external pack that does nothing at all.
        let (_temp, output) = setup_custom_pack_env(pack_content, "deploy --env prod");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|error| panic!("expected a deny payload: {error}; stdout:\n{stdout}"));
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "the pack's destructive pattern must still block prod\nstdout:\n{stdout}"
        );
    }

    // Issue #598: these strings are inputs to dcg's decision APIs only. The
    // reviewed script, replacement executables, and injected libraries need
    // not exist and are never run by this fixture.
    const REVIEWED_COMMAND: &str = "/usr/bin/python3 -I /opt/tools/run_check.py --check";
    const REVIEWED_SAFE_PATTERN: &str =
        r"^\s*/usr/bin/python3[ \t]+-I[ \t]+/opt/tools/run_check\.py[ \t]+--check[ \t]*$";
    const REVIEWED_DESTRUCTIVE_PATTERN: &str = r"(?:^|\s)(?:[^\s]*/)?python3[ \t]+-I[ \t]+/opt/tools/run_check\.py[ \t]+--check(?:[ \t]|$)";
    const REVIEW_RULE: &str = "synthetic.environment:requires-review";

    struct SafePatternFixture {
        root: tempfile::TempDir,
        config: std::path::PathBuf,
        allowlist: Option<std::path::PathBuf>,
    }

    impl SafePatternFixture {
        fn new(safe_patterns: &[&str], destructive_pattern: &str) -> Self {
            Self::new_with_keywords(safe_patterns, destructive_pattern, &["python3", "git"])
        }

        fn new_with_keywords(
            safe_patterns: &[&str],
            destructive_pattern: &str,
            keywords: &[&str],
        ) -> Self {
            let root = tempfile::tempdir().expect("isolated safe-pattern fixture");
            for directory in ["home", "tmp", "cwd", "xdg"] {
                std::fs::create_dir_all(root.path().join(directory)).expect("fixture directory");
            }
            let pack_path = root.path().join("pack.yaml");
            let mut pack = format!(
                "schema_version: 1\nid: synthetic.environment\nname: Environment exemption regression\n\
                 version: 1.0.0\nkeywords: {}\ndestructive_patterns:\n  - name: requires-review\n    pattern: {}\n    severity: critical\n    description: This command requires explicit review\nsafe_patterns:\n",
                serde_json::to_string(keywords).expect("serialize pack keywords"),
                serde_json::to_string(destructive_pattern).expect("serialize destructive pattern")
            );
            if safe_patterns.is_empty() {
                pack.push_str("  []\n");
            } else {
                for (index, pattern) in safe_patterns.iter().enumerate() {
                    writeln!(
                        pack,
                        "  - name: reviewed-{index}\n    pattern: {}",
                        serde_json::to_string(pattern).expect("serialize safe pattern")
                    )
                    .expect("append safe pattern");
                }
            }
            std::fs::write(&pack_path, pack).expect("write custom pack");
            let config = root.path().join("config.toml");
            std::fs::write(
                &config,
                format!(
                    "[general]\nself_heal_hook = false\n[packs]\n\
                     enabled = [\"core.git\", \"core.filesystem\", \"containers.docker\"]\n\
                     custom_paths = [{}]\n",
                    serde_json::to_string(&pack_path).expect("serialize pack path")
                ),
            )
            .expect("write config");
            Self {
                root,
                config,
                allowlist: None,
            }
        }

        fn with_allowlist(mut self, selector: &str, value: &str) -> Self {
            let path = self.root.path().join("allowlist.toml");
            std::fs::write(
                &path,
                format!(
                    "[[allow]]\n{selector} = {}\nreason = \"Reviewed command form\"\n\
                     risk_acknowledged = true\n",
                    serde_json::to_string(value).expect("serialize allowlist selector")
                ),
            )
            .expect("write isolated allowlist");
            self.allowlist = Some(path);
            self
        }

        fn with_allow_override(self, pattern: &str) -> Self {
            let mut config = std::fs::OpenOptions::new()
                .append(true)
                .open(&self.config)
                .expect("open isolated config");
            writeln!(
                config,
                "\n[overrides]\nallow = [{}]",
                serde_json::to_string(pattern).expect("serialize allow override")
            )
            .expect("append allow override");
            self
        }

        fn command(&self) -> Command {
            let mut command = Command::new(dcg_binary());
            command
                .env_clear()
                .env("HOME", self.root.path().join("home"))
                .env("USERPROFILE", self.root.path().join("home"))
                .env("XDG_CONFIG_HOME", self.root.path().join("xdg"))
                .env("TMPDIR", self.root.path().join("tmp"))
                .env("TEMP", self.root.path().join("tmp"))
                .env("TMP", self.root.path().join("tmp"))
                .env("DCG_CONFIG", &self.config)
                .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
                .env("DCG_HISTORY_DISABLED", "1")
                .env("DCG_SELF_HEAL_HOOK", "0")
                .env("NO_COLOR", "1")
                .current_dir(self.root.path().join("cwd"))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            if let Some(path) = std::env::var_os("PATH") {
                command.env("PATH", path);
            }
            if let Some(path) = &self.allowlist {
                command.env("DCG_ALLOWLIST_SYSTEM_PATH", path);
            }
            command
        }

        fn assert_explain(&self, candidate: &str, expected: &str, rule: Option<&str>) {
            self.assert_explain_in_dialects(candidate, expected, rule, &["posix", "unknown"]);
        }

        fn assert_explain_in_dialects(
            &self,
            candidate: &str,
            expected: &str,
            rule: Option<&str>,
            dialects: &[&str],
        ) {
            for &dialect in dialects {
                let output = self
                    .command()
                    .args([
                        "explain",
                        "--format",
                        "json",
                        "--dialect",
                        dialect,
                        "--",
                        candidate,
                    ])
                    .output()
                    .expect("run decision-only explain");
                assert!(output.status.success(), "explain failed: {output:?}");
                let json: serde_json::Value = serde_json::from_slice(&output.stdout)
                    .unwrap_or_else(|error| panic!("explain JSON: {error}; {output:?}"));
                assert_eq!(
                    json["decision"], expected,
                    "[{dialect}] {candidate:?}: {json}"
                );
                assert_eq!(
                    json["outcome"], expected,
                    "[{dialect}] {candidate:?}: {json}"
                );
                if let Some(rule) = rule {
                    assert_eq!(
                        json["match"]["rule_id"], rule,
                        "[{dialect}] {candidate:?}: {json}"
                    );
                }
            }
        }

        fn assert_hooks(&self, candidate: &str, allow: bool) {
            let payloads = [
                (
                    "claude",
                    serde_json::json!({"tool_name":"Bash","tool_input":{"command":candidate}}),
                    "/hookSpecificOutput/permissionDecision",
                ),
                (
                    "codex",
                    serde_json::json!({"tool_name":"Bash","tool_input":{"command":candidate},"turn_id":"598"}),
                    "/hookSpecificOutput/permissionDecision",
                ),
                (
                    "grok",
                    serde_json::json!({"hookEventName":"pre_tool_use","toolName":"run_terminal_cmd","toolInput":{"command":candidate}}),
                    "/decision",
                ),
            ];
            for (agent, payload, decision_pointer) in payloads {
                let mut child = self.command().spawn().expect("spawn decision-only hook");
                child
                    .stdin
                    .take()
                    .expect("hook stdin")
                    .write_all(payload.to_string().as_bytes())
                    .expect("write candidate as JSON data");
                let output = child.wait_with_output().expect("hook output");
                assert!(
                    output.status.success(),
                    "[{agent}] {candidate:?}: {output:?}"
                );
                if allow {
                    assert!(
                        output.stdout.is_empty(),
                        "[{agent}] {candidate:?}: {output:?}"
                    );
                } else {
                    let json: serde_json::Value = serde_json::from_slice(&output.stdout)
                        .unwrap_or_else(|error| {
                            panic!("[{agent}] {candidate:?}: {error}; {output:?}")
                        });
                    assert_eq!(
                        json.pointer(decision_pointer)
                            .and_then(serde_json::Value::as_str),
                        Some("deny"),
                        "[{agent}] {candidate:?}: {json}"
                    );
                }
            }
        }

        fn assert_posix_test(
            &self,
            candidate: &str,
            expected: &str,
            rule: Option<&str>,
        ) -> serde_json::Value {
            let output = self
                .command()
                .args([
                    "test",
                    "--format",
                    "json",
                    "--dialect",
                    "posix",
                    "--",
                    candidate,
                ])
                .output()
                .expect("run decision-only test");
            assert_eq!(
                output.status.code(),
                Some(i32::from(expected == "deny")),
                "test exit code for {candidate:?}: {output:?}"
            );
            let json: serde_json::Value = serde_json::from_slice(&output.stdout)
                .unwrap_or_else(|error| panic!("test JSON: {error}; {output:?}"));
            assert_eq!(json["decision"], expected, "{candidate:?}: {json}");
            assert_eq!(json["rule_id"].as_str(), rule, "{candidate:?}: {json}");
            json
        }
    }

    // Issue #614: a rule on the substitution syntax needs the surrounding
    // flag and quotes, even after the inner command has been evaluated.
    // Inputs are passed directly to dcg; no shell executes these strings.
    const PROSE_SUBSTITUTION_PATTERN: &str = r#"(?:--(?:body|message|description)(?:=|\s+)|-(?:am|m|b)\s*)"(?:[^"\\`$]|\\.|\$(?!\())*(?:`|\$\()"#;
    const PROSE_KEYWORDS: &[&str] = &["--body", "--message", "--description", "-m", "-am", "-b"];
    const PROSE_ARGUMENT_PREFIXES: &[&str] = &[
        "gh pr comment 1 --body ",
        "gh pr comment 1 --body=",
        "gh pr comment 1 -b ",
        "git commit --message ",
        "git commit --message=",
        "git commit -m ",
        "git commit -m",
        "git commit -am ",
        "br create --title t --description ",
        "br create --title t --description=",
        "mytool post --body ",
        "mytool post --body=",
    ];

    #[test]
    fn issue_614_custom_rules_see_substitutions_in_prose_arguments() {
        let fixture =
            SafePatternFixture::new_with_keywords(&[], PROSE_SUBSTITUTION_PATTERN, PROSE_KEYWORDS);
        for prefix in PROSE_ARGUMENT_PREFIXES {
            for substitution in ["`id`", "$(id)"] {
                let candidate = format!("{prefix}\"see {substitution}\"");
                fixture.assert_posix_test(&candidate, "deny", Some(REVIEW_RULE));
            }
        }
        for candidate in [
            r#"gh pr comment 1 --body "see `id`""#,
            r#"git commit --message "see $(id)""#,
            r#"br create --title t --description "see `id`""#,
            r#"mytool post --body "see $(id)""#,
        ] {
            fixture.assert_explain_in_dialects(candidate, "deny", Some(REVIEW_RULE), &["posix"]);
            fixture.assert_hooks(candidate, false);
        }
    }

    #[test]
    fn issue_614_substitution_keywords_select_the_custom_pack() {
        // The pack's only keyword is inside the argument. Both global and
        // per-pack quick rejection must consult the same view as its rule.
        for (keyword, substitution) in [("`", "`id`"), ("$(", "$(id)")] {
            let fixture =
                SafePatternFixture::new_with_keywords(&[], PROSE_SUBSTITUTION_PATTERN, &[keyword]);
            let candidate = format!("gh pr comment 1 --body \"see {substitution}\"");
            fixture.assert_posix_test(&candidate, "deny", Some(REVIEW_RULE));
        }
    }

    #[test]
    fn issue_614_literal_and_escaped_prose_remains_inert() {
        let fixture =
            SafePatternFixture::new_with_keywords(&[], PROSE_SUBSTITUTION_PATTERN, PROSE_KEYWORDS);
        for prefix in PROSE_ARGUMENT_PREFIXES {
            for value in [
                r#""see plain text""#,
                r"'see `id` and $(id)'",
                r#""see \`id\` and \$(id)""#,
            ] {
                fixture.assert_posix_test(&format!("{prefix}{value}"), "allow", None);
            }
        }
        fixture.assert_hooks(r#"gh pr comment 1 --body "see \`id\` and \$(id)""#, true);
        fixture.assert_posix_test(
            "cat <<'EOF'\ngh pr comment 1 --body \"see $(id) and `id`\"\nEOF\n",
            "allow",
            None,
        );
    }

    #[test]
    fn issue_614_substitution_context_survives_expansions_and_concatenation() {
        let fixture =
            SafePatternFixture::new_with_keywords(&[], PROSE_SUBSTITUTION_PATTERN, PROSE_KEYWORDS);
        for candidate in [
            r#"gh pr comment 1 --body "$s $(id)""#,
            r#"gh pr comment 1 --body "see $(id)"' literal tail'"#,
            r#"git commit -am "see `id`"' literal tail'"#,
        ] {
            fixture.assert_posix_test(candidate, "deny", Some(REVIEW_RULE));
        }
        // Require BOTH delimiters so retaining only the first substitution
        // cannot accidentally satisfy this regression.
        let both = SafePatternFixture::new_with_keywords(
            &[],
            r#"--body\s+"[^"`$]*\$\([^)]*\)[^"`]*`[^`]*`"#,
            &["--body"],
        );
        both.assert_posix_test(
            r#"gh pr comment 1 --body "one $(id) two `id`""#,
            "deny",
            Some(REVIEW_RULE),
        );
        both.assert_posix_test(r#"gh pr comment 1 --body "only $(id)""#, "allow", None);
    }

    #[test]
    fn issue_614_utf8_and_compound_commands_keep_original_match_offsets() {
        let fixture =
            SafePatternFixture::new_with_keywords(&[], PROSE_SUBSTITUTION_PATTERN, PROSE_KEYWORDS);
        let candidate = r#"printf 'café'; gh pr comment 1 --body "révision $(id)""#;
        let json = fixture.assert_posix_test(candidate, "deny", Some(REVIEW_RULE));
        let start = candidate.find("--body").expect("prose flag");
        let end = candidate.find("$(").expect("substitution opener") + 2;
        assert_eq!(json["matched_span"], serde_json::json!([start, end]));
        assert_eq!(&candidate[start..end], "--body \"révision $(");
    }

    #[test]
    fn issue_614_rule_grants_do_not_exempt_executed_inner_commands() {
        let fixture =
            SafePatternFixture::new_with_keywords(&[], PROSE_SUBSTITUTION_PATTERN, PROSE_KEYWORDS)
                .with_allowlist("rule", REVIEW_RULE);
        for substitution in ["$(id)", "`id`"] {
            fixture.assert_posix_test(
                &format!("gh pr comment 1 --body \"see {substitution}\""),
                "allow",
                None,
            );
        }
        for substitution in ["$(git reset --hard)", "`git reset --hard`"] {
            fixture.assert_posix_test(
                &format!("gh pr comment 1 --body \"see {substitution}\""),
                "deny",
                Some("core.git:reset-hard"),
            );
        }
    }

    #[test]
    fn issue_614_safe_patterns_use_original_prose_and_substitution_bodies() {
        let approved = r#"gh pr comment 1 --body "see $(id)""#;
        let safe = format!("^{}$", regex::escape(approved));
        let fixture = SafePatternFixture::new_with_keywords(
            &[&safe],
            PROSE_SUBSTITUTION_PATTERN,
            PROSE_KEYWORDS,
        );
        fixture.assert_posix_test(approved, "allow", None);
        // Each edit preserves the byte length of the masked region, so the
        // custom matching view alone cannot distinguish these requests.
        for unapproved in [
            r#"gh pr comment 1 --body "new $(id)""#,
            r#"gh pr comment 1 --body "see $(ls)""#,
        ] {
            fixture.assert_posix_test(unapproved, "deny", Some(REVIEW_RULE));
        }
        fixture.assert_posix_test(
            r#"gh pr comment 1 --body "see $(git reset --hard)""#,
            "deny",
            Some("core.git:reset-hard"),
        );
    }

    #[test]
    fn issue_614_custom_visibility_keeps_data_masked() {
        let fixture =
            SafePatternFixture::new_with_keywords(&[], r"\bgit\s+reset\s+--hard\b", &["git"]);
        // These words are either surrounding prose or the literal output of
        // a benign substitution. Neither the custom rule nor core.git may
        // reinterpret them as an executed reset.
        for prefix in [
            "gh pr comment 1 --body ",
            "git commit --message=",
            "br create --title t --description ",
        ] {
            for value in [
                r#""document git reset --hard""#,
                r#""document git reset --hard $(id)""#,
                r#""document git reset --hard `id`""#,
                r#""see $(printf '%s' 'git reset --hard')""#,
                r#""see `printf '%s' 'git reset --hard'`""#,
            ] {
                fixture.assert_posix_test(&format!("{prefix}{value}"), "allow", None);
            }
        }
        // The same rule must still block a command executed by a substitution.
        fixture.assert_posix_test(
            r#"gh pr comment 1 --body "see $(git reset --hard)""#,
            "deny",
            Some("core.git:reset-hard"),
        );

        // Checked child bodies become spaces in the custom view. They must
        // not be evaluated again as synthetic whitespace-only commands.
        let blank_rule = SafePatternFixture::new_with_keywords(&[], r"^\s+$", &[]);
        blank_rule.assert_posix_test(r#"gh pr comment 1 --body "see $(id)""#, "allow", None);
    }

    #[test]
    fn issue_614_builtin_substitution_analysis_is_preserved() {
        // No loaded custom rule matches these inputs; the built-in inner
        // command analysis must enforce them independently of prose policy.
        let fixture = SafePatternFixture::new_with_keywords(
            &[],
            "synthetic-never-matches-614",
            &["synthetic-never-matches-614"],
        );
        for prefix in [
            "gh pr comment 1 --body ",
            "git commit -m ",
            "br create --title t --description=",
            "mytool post --body ",
        ] {
            for substitution in ["`git reset --hard`", "$(git reset --hard)"] {
                fixture.assert_posix_test(
                    &format!("{prefix}\"see {substitution}\""),
                    "deny",
                    Some("core.git:reset-hard"),
                );
            }
        }
        fixture.assert_hooks(r#"git commit -m "see $(git reset --hard)""#, false);
    }

    #[test]
    fn command_allowlist_selectors_preserve_original_execution_context() {
        let exact_pattern = format!("^{}$", regex::escape(REVIEWED_COMMAND));
        let control = SafePatternFixture::new(&[], REVIEWED_DESTRUCTIVE_PATTERN);
        control.assert_explain(REVIEWED_COMMAND, "deny", Some(REVIEW_RULE));

        for (selector, grant) in [
            ("exact_command", REVIEWED_COMMAND),
            ("command_prefix", REVIEWED_COMMAND),
            ("pattern", exact_pattern.as_str()),
        ] {
            let fixture = SafePatternFixture::new(&[], REVIEWED_DESTRUCTIVE_PATTERN)
                .with_allowlist(selector, grant);
            fixture.assert_explain(REVIEWED_COMMAND, "allow", None);
            fixture.assert_hooks(REVIEWED_COMMAND, true);
            for variable in [
                "PATH",
                "PYTHONPATH",
                "NODE_OPTIONS",
                "BASH_ENV",
                "LD_PRELOAD",
                "DYLD_INSERT_LIBRARIES",
                "GIT_CONFIG_COUNT",
                "APPLICATION_SPECIFIC_SETTING",
            ] {
                fixture.assert_explain(
                    &format!("{variable}=/unreviewed {REVIEWED_COMMAND}"),
                    "deny",
                    Some(REVIEW_RULE),
                );
            }
            for candidate in [
                format!("env PATH=/unreviewed {REVIEWED_COMMAND}"),
                format!("env -i {REVIEWED_COMMAND}"),
                format!("command {REVIEWED_COMMAND}"),
                format!("exec {REVIEWED_COMMAND}"),
                format!("sudo {REVIEWED_COMMAND}"),
                format!("timeout 5s {REVIEWED_COMMAND}"),
                format!("sh -c '{REVIEWED_COMMAND}'"),
                format!("env PATH=/unreviewed sh -c '{REVIEWED_COMMAND}'"),
                format!("bash -c \"sh -c '{REVIEWED_COMMAND}'\""),
                format!("true; {REVIEWED_COMMAND}"),
                format!("{REVIEWED_COMMAND}; {REVIEWED_COMMAND}"),
                REVIEWED_COMMAND.replace("/usr/bin/python3", "/unreviewed/python3"),
                REVIEWED_COMMAND.replace("/usr/bin/python3", "python3"),
            ] {
                fixture.assert_explain(&candidate, "deny", Some(REVIEW_RULE));
            }
            fixture.assert_hooks(&format!("PATH=/unreviewed {REVIEWED_COMMAND}"), false);
            fixture.assert_hooks(
                &format!("env PATH=/unreviewed sh -c '{REVIEWED_COMMAND}'"),
                false,
            );
        }
    }

    #[test]
    fn exact_command_grants_keep_explicit_environment_and_complete_wrapper_scope() {
        for grant in [
            format!("PATH=/reviewed {REVIEWED_COMMAND}"),
            format!("env -i PATH=/reviewed {REVIEWED_COMMAND}"),
            format!("env PATH=/reviewed sh -c '{REVIEWED_COMMAND}'"),
            format!("bash -c '{REVIEWED_COMMAND}'"),
            format!("{REVIEWED_COMMAND}; {REVIEWED_COMMAND}"),
        ] {
            let fixture = SafePatternFixture::new(&[], REVIEWED_DESTRUCTIVE_PATTERN)
                .with_allowlist("exact_command", &grant);
            fixture.assert_explain(&grant, "allow", None);
            fixture.assert_hooks(&grant, true);
            fixture.assert_explain(REVIEWED_COMMAND, "deny", Some(REVIEW_RULE));
            fixture.assert_explain(
                &format!("LD_PRELOAD=/unreviewed.so {grant}"),
                "deny",
                Some(REVIEW_RULE),
            );
            if grant.contains("/reviewed") {
                fixture.assert_explain(
                    &grant.replace("/reviewed", "/unreviewed"),
                    "deny",
                    Some(REVIEW_RULE),
                );
            }
        }
    }

    #[test]
    fn command_allowlist_retains_authored_regex_scope_and_rule_grants() {
        let exact_pattern = format!("^PATH=/reviewed {}$", regex::escape(REVIEWED_COMMAND));
        let fixture = SafePatternFixture::new(&[], REVIEWED_DESTRUCTIVE_PATTERN)
            .with_allowlist("pattern", &exact_pattern);
        fixture.assert_explain(&format!("PATH=/reviewed {REVIEWED_COMMAND}"), "allow", None);
        fixture.assert_explain(
            &format!("PATH=/unreviewed {REVIEWED_COMMAND}"),
            "deny",
            Some(REVIEW_RULE),
        );

        // A deliberately unanchored, risk-acknowledged expression authorizes
        // the complete request when its original text matches. Rule grants
        // separately authorize that rule, irrespective of command spelling.
        for (selector, grant) in [
            ("pattern", regex::escape(REVIEWED_COMMAND)),
            ("rule", REVIEW_RULE.to_string()),
        ] {
            let fixture = SafePatternFixture::new(&[], REVIEWED_DESTRUCTIVE_PATTERN)
                .with_allowlist(selector, &grant);
            fixture.assert_explain(REVIEWED_COMMAND, "allow", None);
            fixture.assert_explain(&format!("PATH=/reviewed {REVIEWED_COMMAND}"), "allow", None);
        }
    }

    #[test]
    fn exact_command_grants_do_not_reappear_after_detection_rewrites() {
        let fixture = SafePatternFixture::new(&[], REVIEWED_DESTRUCTIVE_PATTERN)
            .with_allowlist("exact_command", "git reset --hard");
        fixture.assert_explain("git reset --hard", "allow", None);
        for candidate in [
            "git reset --hard 2>/tmp/dcg-reviewed.log",
            "git reset --hard # unreviewed suffix",
            "/usr/bin/git reset --hard",
            "env GIT_CONFIG_COUNT=1 git reset --hard",
        ] {
            fixture.assert_explain(candidate, "deny", Some("core.git:reset-hard"));
        }
        fixture.assert_explain_in_dialects(
            "GIT RESET --HARD",
            "deny",
            Some("core.git:reset-hard"),
            &["powershell", "unknown"],
        );
        fixture.assert_explain("git status", "allow", None);
    }

    #[test]
    fn allow_override_requires_the_original_complete_request() {
        let pattern = format!("^{}$", regex::escape(REVIEWED_COMMAND));
        let fixture = SafePatternFixture::new(&[], REVIEWED_DESTRUCTIVE_PATTERN)
            .with_allow_override(&pattern);
        fixture.assert_explain(REVIEWED_COMMAND, "allow", None);
        fixture.assert_hooks(REVIEWED_COMMAND, true);
        for candidate in [
            format!("PATH=/unreviewed {REVIEWED_COMMAND}"),
            format!("sh -c '{REVIEWED_COMMAND}'"),
            format!("env PATH=/unreviewed sh -c '{REVIEWED_COMMAND}'"),
            format!("true; {REVIEWED_COMMAND}"),
        ] {
            fixture.assert_explain(&candidate, "deny", Some(REVIEW_RULE));
        }

        let grant = format!("env PATH=/reviewed sh -c '{REVIEWED_COMMAND}'");
        let fixture = SafePatternFixture::new(&[], REVIEWED_DESTRUCTIVE_PATTERN)
            .with_allow_override(&format!("^{}$", regex::escape(&grant)));
        fixture.assert_explain(&grant, "allow", None);
        fixture.assert_explain(
            &grant.replace("/reviewed", "/unreviewed"),
            "deny",
            Some(REVIEW_RULE),
        );
    }

    #[test]
    fn command_grants_cannot_be_acquired_from_a_confidence_replay() {
        let original = "watch rm -rf ./build; rm -r''f ./build";
        let residual = "watch        ./build; rm -r''f ./build";
        let residual_pattern = r"^watch\s+\./build;\s*rm -r(?:\x27\x27)?f \./build$";
        for grant in [None, Some(residual_pattern)] {
            let fixture = SafePatternFixture::new(&[], REVIEWED_DESTRUCTIVE_PATTERN);
            let fixture = if let Some(pattern) = grant {
                fixture.with_allowlist("pattern", pattern)
            } else {
                fixture
            };
            let mut config = std::fs::OpenOptions::new()
                .append(true)
                .open(&fixture.config)
                .expect("open confidence fixture");
            writeln!(
                config,
                "\n[confidence]\nenabled = true\nwarn_threshold = 0.7"
            )
            .expect("configure confidence scoring");

            // The first low-confidence match must not hide the later actual
            // rm, even when blanking it creates text matched by a grant.
            fixture.assert_explain(original, "deny", Some("core.filesystem:rm-rf-general"));
            fixture.assert_hooks(original, false);
            fixture.assert_explain(
                residual,
                if grant.is_some() { "allow" } else { "deny" },
                if grant.is_some() {
                    None
                } else {
                    Some("core.filesystem:rm-rf-general")
                },
            );
        }
    }

    #[test]
    fn issue_598_exact_safe_patterns_do_not_authorize_environment_prefixes() {
        let fixture =
            SafePatternFixture::new(&[REVIEWED_SAFE_PATTERN], REVIEWED_DESTRUCTIVE_PATTERN);
        fixture.assert_explain(REVIEWED_COMMAND, "allow", None);
        fixture.assert_explain(
            "  /usr/bin/python3\t-I /opt/tools/run_check.py\t--check  ",
            "allow",
            None,
        );
        fixture.assert_hooks(REVIEWED_COMMAND, true);
        // Without the exemption, the same command really does hit the rule.
        SafePatternFixture::new(&[], REVIEWED_DESTRUCTIVE_PATTERN).assert_explain(
            REVIEWED_COMMAND,
            "deny",
            Some(REVIEW_RULE),
        );

        for assignment in [
            "PATH=/tmp/replacement:/usr/bin",
            "PATH='/tmp/replacement directory:/usr/bin'",
            "PATH+=:/tmp/replacement",
            "PYTHONPATH=/tmp/modules",
            "PYTHONWARNINGS=all",
            "NODE_OPTIONS=--require=/tmp/hook.js",
            "BASH_ENV=/tmp/startup.sh",
            "ENV=/tmp/startup.sh",
            "LD_PRELOAD=/tmp/hook.so",
            "LD_LIBRARY_PATH=/tmp/libraries",
            "DYLD_INSERT_LIBRARIES=/tmp/hook.dylib",
            "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.sshCommand GIT_CONFIG_VALUE_0=/tmp/ssh",
            "GIT_EXEC_PATH=/tmp/git-tools",
            "PERL5OPT=-MInjected",
            "RUBYOPT=-rinjected",
            "DCG_TEST_ARBITRARY=changed",
            "DCG_TEST_EMPTY=",
            "A=1 B='two words'",
        ] {
            let candidate = format!("{assignment} {REVIEWED_COMMAND}");
            fixture.assert_explain(&candidate, "deny", Some(REVIEW_RULE));
        }
        fixture.assert_hooks(
            &format!("PATH=/tmp/replacement:/usr/bin {REVIEWED_COMMAND}"),
            false,
        );
    }

    #[test]
    fn issue_598_backtracking_safe_patterns_keep_the_original_match_target() {
        let fixture = SafePatternFixture::new(
            &[
                r"^(?=/usr/bin/python3[ \t])/usr/bin/python3[ \t]+-I[ \t]+/opt/tools/run_check\.py[ \t]+--check[ \t]*$",
            ],
            REVIEWED_DESTRUCTIVE_PATTERN,
        );
        fixture.assert_explain(REVIEWED_COMMAND, "allow", None);
        fixture.assert_explain(
            &format!("PATH=/tmp/replacement:/usr/bin {REVIEWED_COMMAND}"),
            "deny",
            Some(REVIEW_RULE),
        );
    }

    #[test]
    fn issue_598_unanchored_safe_patterns_keep_their_authored_prefix_scope() {
        // Omitting the start anchor intentionally accepts arbitrary prefixes.
        // Matching the original text must preserve this regex language, while
        // the end anchor still excludes additional arguments.
        let fixture = SafePatternFixture::new(
            &[r"/usr/bin/python3 -I /opt/tools/run_check\.py --check$"],
            REVIEWED_DESTRUCTIVE_PATTERN,
        );
        for prefix in ["", "PATH=/usr/bin:/bin ", "env PATH=/usr/bin:/bin "] {
            fixture.assert_explain(&format!("{prefix}{REVIEWED_COMMAND}"), "allow", None);
        }
        fixture.assert_explain(
            &format!("{REVIEWED_COMMAND} --unreviewed"),
            "deny",
            Some(REVIEW_RULE),
        );
        fixture.assert_explain(
            &format!("PATH=/tmp/replacement bash -c '{REVIEWED_COMMAND}'"),
            "deny",
            Some(REVIEW_RULE),
        );
    }

    #[test]
    fn issue_598_safe_patterns_preserve_wrappers_and_executable_identity() {
        let fixture =
            SafePatternFixture::new(&[REVIEWED_SAFE_PATTERN], REVIEWED_DESTRUCTIVE_PATTERN);
        for prefix in [
            "env",
            "env PATH=/tmp/replacement:/usr/bin",
            "env -i",
            "env --ignore-environment",
            "env -u PATH",
            "env --unset=PYTHONPATH",
            "env -P /tmp/replacement",
            "env -C /tmp/elsewhere",
            "env --chdir=/tmp/elsewhere",
            "/usr/bin/env PATH=/tmp/replacement:/usr/bin",
            "sudo -E",
            "command -p",
            "nice -n 5",
            "timeout 10",
            "exec -c",
            "sudo env PATH=/tmp/replacement:/usr/bin command --",
            "env PATH=/tmp/replacement:/usr/bin nice -n 5 timeout 10",
        ] {
            fixture.assert_explain(
                &format!("{prefix} {REVIEWED_COMMAND}"),
                "deny",
                Some(REVIEW_RULE),
            );
        }
        for candidate in [
            format!("env -S 'PATH=/tmp/replacement:/usr/bin {REVIEWED_COMMAND}'"),
            format!("env --split-string='PATH=/tmp/replacement:/usr/bin {REVIEWED_COMMAND}'"),
            format!("command env -S 'PATH=/tmp/replacement:/usr/bin {REVIEWED_COMMAND}'"),
            REVIEWED_COMMAND.replacen("/usr/bin/python3", "/tmp/replacement/python3", 1),
            REVIEWED_COMMAND.replacen("/usr/bin/python3", "./python3", 1),
            REVIEWED_COMMAND.replacen("/usr/bin/python3", "python3", 1),
            REVIEWED_COMMAND.replacen("/usr/bin/python3", "/usr/bin/python3.exe", 1),
        ] {
            fixture.assert_explain(&candidate, "deny", Some(REVIEW_RULE));
        }
    }

    #[test]
    fn issue_598_safe_patterns_do_not_equate_different_executable_paths() {
        let fixture = SafePatternFixture::new(
            &[r"^git status$"],
            r"(?:^|\s)(?:[^\s]*/)?git\s+status(?:\s|$)",
        );
        fixture.assert_explain("git status", "allow", None);
        for candidate in [
            "/usr/bin/git status",
            "/tmp/replacement/bin/git status",
            "\"/usr/bin/git\" status",
            "git.exe status",
            "GIT status",
            "PATH=/tmp/replacement git status",
            "command -p git status",
            ">/tmp/dcg-598-output git status",
            "git status >/tmp/dcg-598-output",
        ] {
            fixture.assert_explain(candidate, "deny", Some(REVIEW_RULE));
        }
    }

    #[test]
    fn issue_598_nested_and_compound_commands_cannot_borrow_safe_exemptions() {
        let fixture =
            SafePatternFixture::new(&[REVIEWED_SAFE_PATTERN], REVIEWED_DESTRUCTIVE_PATTERN);
        for candidate in [
            format!("true; PATH=/tmp/replacement:/usr/bin {REVIEWED_COMMAND}"),
            format!("{REVIEWED_COMMAND}; PATH=/tmp/replacement:/usr/bin {REVIEWED_COMMAND}"),
            format!("PATH=/tmp/replacement:/usr/bin {REVIEWED_COMMAND}; {REVIEWED_COMMAND}"),
            format!("bash -c '{REVIEWED_COMMAND}'"),
            format!("PATH=/tmp/replacement:/usr/bin bash -c '{REVIEWED_COMMAND}'"),
            format!("env PYTHONPATH=/tmp/modules bash -c '{REVIEWED_COMMAND}'"),
            format!("env -P /tmp/replacement bash -c '{REVIEWED_COMMAND}'"),
            format!("'/usr/bin/env' PATH=/tmp/replacement bash -c '{REVIEWED_COMMAND}'"),
            format!("env --default-signal PATH=/tmp/replacement bash -c '{REVIEWED_COMMAND}'"),
            format!("sudo env PATH=/tmp/replacement:/usr/bin bash -c '{REVIEWED_COMMAND}'"),
            format!("bash -c 'env PATH=/tmp/replacement:/usr/bin {REVIEWED_COMMAND}'"),
            format!("bash -c 'export PATH=/tmp/replacement; {REVIEWED_COMMAND}'"),
            format!("env PATH=/tmp/replacement:/usr/bin sh -c \"bash -c '{REVIEWED_COMMAND}'\""),
        ] {
            fixture.assert_explain(&candidate, "deny", Some(REVIEW_RULE));
        }
        fixture.assert_hooks(
            &format!("PATH=/tmp/replacement:/usr/bin bash -c '{REVIEWED_COMMAND}'"),
            false,
        );
    }

    #[test]
    fn issue_598_preceding_shell_state_cannot_change_a_later_safe_command() {
        let fixture =
            SafePatternFixture::new(&[REVIEWED_SAFE_PATTERN], REVIEWED_DESTRUCTIVE_PATTERN);
        for prefix in [
            "export PATH=/tmp/replacement;",
            "PATH=/tmp/replacement;",
            "unset PYTHONPATH;",
            "export DCG_APP_CONFIG=/tmp/unreviewed;",
            "command export PATH=/tmp/replacement;",
            "builtin export PATH=/tmp/replacement;",
            "printf '-v' PATH /tmp/replacement;",
            "let 'PATH=1';",
            "getopts a PATH -a;",
            ": ${PATH:=/tmp/replacement};",
            "PATH=/tmp/replacement :;",
        ] {
            fixture.assert_explain(
                &format!("{prefix} {REVIEWED_COMMAND}"),
                "deny",
                Some(REVIEW_RULE),
            );
        }
        // Only provably neutral predecessors preserve a later segment's
        // independent exemption. A literal command-local assignment to true
        // does not change the environment of the reviewed command.
        for prefix in ["true;", "false;", ":;", "FOO=1 true;"] {
            fixture.assert_explain(&format!("{prefix} {REVIEWED_COMMAND}"), "allow", None);
        }
        // A literal executable path launches a child in a proven POSIX
        // dialect. An unknown dialect does not establish that boundary.
        fixture.assert_explain_in_dialects(
            &format!("{REVIEWED_COMMAND}; {REVIEWED_COMMAND}"),
            "allow",
            None,
            &["posix"],
        );
        fixture.assert_explain_in_dialects(
            &format!("{REVIEWED_COMMAND}; {REVIEWED_COMMAND}"),
            "deny",
            Some(REVIEW_RULE),
            &["unknown"],
        );

        // PowerShell scripts and Cmd batch files can alter the current
        // process's environment even when invoked through a literal path.
        let windows_fixture =
            SafePatternFixture::new(&[r"^git status$"], r"(?:^|\s)git\s+status(?:\s|$)");
        windows_fixture.assert_explain_in_dialects(
            "./setenv.ps1; git status",
            "deny",
            Some(REVIEW_RULE),
            &["ps", "unknown"],
        );
        windows_fixture.assert_explain_in_dialects(
            "C:/scripts/setenv & git status",
            "deny",
            Some(REVIEW_RULE),
            &["cmd", "unknown"],
        );
    }

    #[test]
    fn issue_598_whitespace_boundaries_preserve_cross_segment_rules() {
        let fixture = SafePatternFixture::new(
            &[REVIEWED_SAFE_PATTERN],
            r"(?:^|\s)/usr/bin/python3 -I /opt/tools/run_check\.py --check\s*;\s*synthetic_publish\s+production\s*",
        );
        // A regex may intentionally govern the combination of two commands.
        // Trimming whitespace around a whole-command match must not mistake
        // this for a duplicate of the individually exempt reviewed segment.
        fixture.assert_explain(
            &format!("true; {REVIEWED_COMMAND} ; synthetic_publish production  "),
            "deny",
            Some(REVIEW_RULE),
        );
        fixture.assert_explain(
            &format!("true; {REVIEWED_COMMAND} ; synthetic_publish staging  "),
            "allow",
            None,
        );
        // This rule needs the leading whitespace that segmentation trims.
        // With no safe grant, its full-command match must still be evaluated.
        SafePatternFixture::new(
            &[],
            r"\s+/usr/bin/python3 -I /opt/tools/run_check\.py --check$",
        )
        .assert_explain(
            &format!("true; {REVIEWED_COMMAND}"),
            "deny",
            Some(REVIEW_RULE),
        );
    }

    #[test]
    fn issue_598_explicit_environment_safe_patterns_keep_their_exact_scope() {
        for prefix in ["PATH=/usr/bin:/bin", "env PATH=/usr/bin:/bin"] {
            let safe = format!(r"^{prefix} /usr/bin/python3 -I /opt/tools/run_check\.py --check$");
            let fixture = SafePatternFixture::new(&[&safe], REVIEWED_DESTRUCTIVE_PATTERN);
            let authorized = format!("{prefix} {REVIEWED_COMMAND}");
            fixture.assert_explain(&authorized, "allow", None);
            fixture.assert_hooks(&authorized, true);
            fixture.assert_explain(REVIEWED_COMMAND, "deny", Some(REVIEW_RULE));
            fixture.assert_explain(
                &authorized.replacen("/usr/bin:/bin", "/tmp/replacement:/usr/bin", 1),
                "deny",
                Some(REVIEW_RULE),
            );
            fixture.assert_explain(
                &format!("PYTHONPATH=/tmp/modules {authorized}"),
                "deny",
                Some(REVIEW_RULE),
            );
            fixture.assert_explain(&format!("sudo {authorized}"), "deny", Some(REVIEW_RULE));
        }
    }

    #[test]
    fn issue_598_explicit_nested_exemption_is_bound_to_the_complete_carrier() {
        let safe =
            r"^PATH=/usr/bin:/bin bash -c '/usr/bin/python3 -I /opt/tools/run_check\.py --check'$";
        let fixture = SafePatternFixture::new(&[safe], REVIEWED_DESTRUCTIVE_PATTERN);
        let authorized = format!("PATH=/usr/bin:/bin bash -c '{REVIEWED_COMMAND}'");
        fixture.assert_explain(&authorized, "allow", None);
        fixture.assert_hooks(&authorized, true);
        for candidate in [
            authorized.replacen("/usr/bin:/bin", "/tmp/replacement:/usr/bin", 1),
            format!("PYTHONPATH=/tmp/modules {authorized}"),
            format!("{authorized}; PATH=/tmp/replacement {REVIEWED_COMMAND}"),
            format!("PATH=/tmp/replacement {REVIEWED_COMMAND}; {authorized}"),
        ] {
            fixture.assert_explain(&candidate, "deny", Some(REVIEW_RULE));
        }

        // A full-carrier exemption belongs only to the custom pack that
        // authored it. It must not suppress another pack inside that shell.
        let cross_pack_safe = r"^PATH=/usr/bin:/bin bash -c '/usr/bin/python3 -I /opt/tools/run_check\.py --check; git reset --hard'$";
        let cross_pack = SafePatternFixture::new(&[cross_pack_safe], REVIEWED_DESTRUCTIVE_PATTERN);
        cross_pack.assert_explain(
            &format!("PATH=/usr/bin:/bin bash -c '{REVIEWED_COMMAND}; git reset --hard'"),
            "deny",
            Some("core.git:reset-hard"),
        );
    }

    #[test]
    fn issue_598_assignment_sensitive_destructive_patterns_see_the_original_command() {
        // The only keyword is removed by destructive normalization, so the
        // original view must survive both global and per-pack selection.
        let fixture = SafePatternFixture::new_with_keywords(
            &[],
            r"^PATH=/tmp/replacement:/usr/bin /usr/bin/python3 -I /opt/tools/run_check\.py --check$",
            &["PATH"],
        );
        fixture.assert_explain(REVIEWED_COMMAND, "allow", None);
        let candidate = format!("PATH=/tmp/replacement:/usr/bin {REVIEWED_COMMAND}");
        fixture.assert_explain(&candidate, "deny", Some(REVIEW_RULE));
        fixture.assert_hooks(&candidate, false);
    }

    #[test]
    fn issue_598_existing_builtin_safe_and_destructive_decisions_are_preserved() {
        let fixture =
            SafePatternFixture::new(&[REVIEWED_SAFE_PATTERN], REVIEWED_DESTRUCTIVE_PATTERN);
        for candidate in [
            "git status",
            "git clean -n",
            "git restore --staged file.txt",
            "rm -rf /tmp/dcg-598-artifacts",
            "docker ps",
            "git commit -m 'PATH=/tmp/replacement git reset --hard'",
        ] {
            fixture.assert_explain(candidate, "allow", None);
        }
        for candidate in [
            "PATH=/tmp/replacement git reset --hard",
            "env -i /usr/bin/git reset --hard",
            "sudo env FOO=1 command git reset --hard",
            "env -S 'PATH=/tmp/replacement git reset --hard'",
            "PATH=/tmp/replacement bash -c 'git reset --hard'",
        ] {
            fixture.assert_explain(candidate, "deny", Some("core.git:reset-hard"));
        }
    }
}

// ============================================================================
// Stats --rules E2E Tests (git_safety_guard-1dri.4)
// ============================================================================
//
// These tests validate the `dcg stats --rules` subcommand with known fixture
// data, testing both pretty and JSON output formats.

mod stats_rules_tests {
    use super::*;
    use chrono::Utc;
    use destructive_command_guard::history::{CommandEntry, HistoryDb, Outcome};
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Test environment for stats --rules tests.
    struct StatsRulesEnv {
        temp: TempDir,
        db_path: PathBuf,
    }

    impl StatsRulesEnv {
        fn new() -> Self {
            let temp = TempDir::new().expect("failed to create temp dir");
            let db_path = temp.path().join("test_history.db");
            Self { temp, db_path }
        }

        fn seed_rule_metrics_data(&self) {
            let db = HistoryDb::open(Some(self.db_path.clone())).expect("open db");
            let now = Utc::now();

            // core.git:reset-hard - 5 hits (3 deny, 2 bypass)
            let reset_entries = vec![
                ("git reset --hard HEAD~1", Outcome::Deny, -7200),
                ("git reset --hard HEAD~2", Outcome::Deny, -6000),
                ("git reset --hard origin/main", Outcome::Deny, -4800),
                ("git reset --hard HEAD", Outcome::Bypass, -3600),
                ("git reset --hard abc123", Outcome::Bypass, -2400),
            ];
            for (cmd, outcome, offset) in reset_entries {
                let entry = CommandEntry {
                    timestamp: now + chrono::Duration::seconds(offset),
                    agent_type: "claude_code".to_string(),
                    working_dir: "/test".to_string(),
                    command: cmd.to_string(),
                    outcome,
                    pack_id: Some("core.git".to_string()),
                    pattern_name: Some("reset-hard".to_string()),
                    rule_id: Some("core.git:reset-hard".to_string()),
                    ..Default::default()
                };
                db.log_command(&entry).expect("insert entry");
            }

            // core.git:force-push - 3 hits (2 deny, 1 bypass)
            let push_entries = vec![
                ("git push --force origin main", Outcome::Deny, -7000),
                (
                    "git push --force-with-lease origin dev",
                    Outcome::Deny,
                    -5000,
                ),
                ("git push --force origin feature", Outcome::Bypass, -3000),
            ];
            for (cmd, outcome, offset) in push_entries {
                let entry = CommandEntry {
                    timestamp: now + chrono::Duration::seconds(offset),
                    agent_type: "claude_code".to_string(),
                    working_dir: "/test".to_string(),
                    command: cmd.to_string(),
                    outcome,
                    pack_id: Some("core.git".to_string()),
                    pattern_name: Some("force-push".to_string()),
                    rule_id: Some("core.git:force-push".to_string()),
                    ..Default::default()
                };
                db.log_command(&entry).expect("insert entry");
            }

            // core.filesystem:rm-rf - 4 hits (4 deny, 0 bypass)
            let rm_entries = vec![
                ("rm -rf /tmp/test", -8000),
                ("rm -rf ./build", -6500),
                ("rm -rf node_modules", -5500),
                ("rm -rf dist", -4000),
            ];
            for (cmd, offset) in rm_entries {
                let entry = CommandEntry {
                    timestamp: now + chrono::Duration::seconds(offset),
                    agent_type: "claude_code".to_string(),
                    working_dir: "/test".to_string(),
                    command: cmd.to_string(),
                    outcome: Outcome::Deny,
                    pack_id: Some("core.filesystem".to_string()),
                    pattern_name: Some("rm-rf".to_string()),
                    rule_id: Some("core.filesystem:rm-rf".to_string()),
                    ..Default::default()
                };
                db.log_command(&entry).expect("insert entry");
            }
        }

        fn run(&self, args: &[&str]) -> std::process::Output {
            Command::new(dcg_binary())
                .env("DCG_HISTORY_DB", &self.db_path)
                .current_dir(self.temp.path())
                .args(args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .expect("run dcg")
        }
    }

    // -------------------------------------------------------------------------
    // Pretty output tests
    // -------------------------------------------------------------------------

    #[test]
    fn stats_rules_pretty_shows_header() {
        let env = StatsRulesEnv::new();
        env.seed_rule_metrics_data();

        let output = env.run(&["stats", "--rules"]);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            output.status.success(),
            "stats --rules should succeed\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        assert!(
            stdout.contains("Rule Metrics"),
            "should show Rule Metrics header\nstdout:\n{stdout}"
        );
    }

    #[test]
    fn stats_rules_pretty_shows_all_rules() {
        let env = StatsRulesEnv::new();
        env.seed_rule_metrics_data();

        let output = env.run(&["stats", "--rules"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            stdout.contains("core.git:reset-hard"),
            "should show reset-hard rule\nstdout:\n{stdout}"
        );
        assert!(
            stdout.contains("core.git:force-push"),
            "should show force-push rule\nstdout:\n{stdout}"
        );
        assert!(
            stdout.contains("core.filesystem:rm-rf"),
            "should show rm-rf rule\nstdout:\n{stdout}"
        );
    }

    #[test]
    fn stats_rules_pretty_shows_totals() {
        let env = StatsRulesEnv::new();
        env.seed_rule_metrics_data();

        let output = env.run(&["stats", "--rules"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Total: 12 hits, 3 overrides (from fixture data)
        assert!(
            stdout.contains("Total"),
            "should show Total row\nstdout:\n{stdout}"
        );
        assert!(
            stdout.contains("12"),
            "should show total hits of 12\nstdout:\n{stdout}"
        );
    }

    #[test]
    fn stats_rules_pretty_shows_rule_count() {
        let env = StatsRulesEnv::new();
        env.seed_rule_metrics_data();

        let output = env.run(&["stats", "--rules"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            stdout.contains("3 rules shown"),
            "should show '3 rules shown'\nstdout:\n{stdout}"
        );
    }

    #[test]
    fn stats_rules_limit_restricts_output() {
        let env = StatsRulesEnv::new();
        env.seed_rule_metrics_data();

        let output = env.run(&["stats", "--rules", "-n", "2"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            stdout.contains("2 rules shown"),
            "should show '2 rules shown' when limit=2\nstdout:\n{stdout}"
        );
    }

    // -------------------------------------------------------------------------
    // JSON output tests
    // -------------------------------------------------------------------------

    #[test]
    fn stats_rules_json_is_valid() {
        let env = StatsRulesEnv::new();
        env.seed_rule_metrics_data();

        let output = env.run(&["stats", "--rules", "--format", "json"]);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            output.status.success(),
            "stats --rules --format json should succeed\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );

        let json: serde_json::Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|_| panic!("should produce valid JSON\nstdout:\n{stdout}"));

        assert!(json.is_object(), "JSON should be an object");
    }

    #[test]
    fn stats_rules_json_has_required_fields() {
        let env = StatsRulesEnv::new();
        env.seed_rule_metrics_data();

        let output = env.run(&["stats", "--rules", "--format", "json"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();

        assert!(
            json["period_days"].is_number(),
            "should have period_days field"
        );
        assert!(json["rules"].is_array(), "should have rules array");
        assert!(json["totals"].is_object(), "should have totals object");
    }

    #[test]
    fn stats_rules_json_rules_have_required_fields() {
        let env = StatsRulesEnv::new();
        env.seed_rule_metrics_data();

        let output = env.run(&["stats", "--rules", "--format", "json"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let rules = json["rules"].as_array().unwrap();

        assert!(!rules.is_empty(), "should have at least one rule");

        for rule in rules {
            assert!(
                rule["rule_id"].is_string(),
                "rule should have rule_id: {rule:?}"
            );
            assert!(
                rule["pack_id"].is_string(),
                "rule should have pack_id: {rule:?}"
            );
            assert!(
                rule["pattern_name"].is_string(),
                "rule should have pattern_name: {rule:?}"
            );
            assert!(
                rule["total_hits"].is_number(),
                "rule should have total_hits: {rule:?}"
            );
            assert!(
                rule["allowlist_overrides"].is_number(),
                "rule should have allowlist_overrides: {rule:?}"
            );
            assert!(
                rule["override_rate"].is_number(),
                "rule should have override_rate: {rule:?}"
            );
            assert!(
                rule["first_seen"].is_string(),
                "rule should have first_seen: {rule:?}"
            );
            assert!(
                rule["last_seen"].is_string(),
                "rule should have last_seen: {rule:?}"
            );
            assert!(
                rule["unique_commands"].is_number(),
                "rule should have unique_commands: {rule:?}"
            );
            assert!(
                rule["trend"].is_string(),
                "rule should have trend: {rule:?}"
            );
            assert!(
                rule["is_noisy"].is_boolean(),
                "rule should have is_noisy: {rule:?}"
            );
        }
    }

    #[test]
    fn stats_rules_json_totals_correct() {
        let env = StatsRulesEnv::new();
        env.seed_rule_metrics_data();

        let output = env.run(&["stats", "--rules", "--format", "json"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();

        // Expected: 12 total hits, 3 total overrides (bypasses), 3 rules
        assert_eq!(
            json["totals"]["total_hits"], 12,
            "should have 12 total hits\njson: {json:#}"
        );
        assert_eq!(
            json["totals"]["total_overrides"], 3,
            "should have 3 total overrides\njson: {json:#}"
        );
        assert_eq!(
            json["totals"]["rule_count"], 3,
            "should have 3 rules\njson: {json:#}"
        );
    }

    #[test]
    fn stats_rules_json_rule_values_correct() {
        let env = StatsRulesEnv::new();
        env.seed_rule_metrics_data();

        let output = env.run(&["stats", "--rules", "--format", "json"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let rules = json["rules"].as_array().unwrap();

        // Find the reset-hard rule and verify its values
        let reset_rule = rules
            .iter()
            .find(|r| r["rule_id"] == "core.git:reset-hard")
            .expect("should find reset-hard rule");

        assert_eq!(reset_rule["total_hits"], 5, "reset-hard should have 5 hits");
        assert_eq!(
            reset_rule["allowlist_overrides"], 2,
            "reset-hard should have 2 overrides"
        );
        assert_eq!(
            reset_rule["unique_commands"], 5,
            "reset-hard should have 5 unique commands"
        );

        // Find the rm-rf rule which has 0 overrides
        let rm_rule = rules
            .iter()
            .find(|r| r["rule_id"] == "core.filesystem:rm-rf")
            .expect("should find rm-rf rule");

        assert_eq!(rm_rule["total_hits"], 4, "rm-rf should have 4 hits");
        assert_eq!(
            rm_rule["allowlist_overrides"], 0,
            "rm-rf should have 0 overrides"
        );
    }

    #[test]
    fn stats_rules_json_limit_works() {
        let env = StatsRulesEnv::new();
        env.seed_rule_metrics_data();

        let output = env.run(&["stats", "--rules", "--format", "json", "-n", "1"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let rules = json["rules"].as_array().unwrap();

        assert_eq!(rules.len(), 1, "should only return 1 rule when limit=1");
    }

    #[test]
    fn stats_rules_json_days_filter_works() {
        let env = StatsRulesEnv::new();
        env.seed_rule_metrics_data();

        let output = env.run(&["stats", "--rules", "--format", "json", "--days", "1"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();

        assert_eq!(
            json["period_days"], 1,
            "should show period_days=1\njson: {json:#}"
        );
    }

    // -------------------------------------------------------------------------
    // Empty database tests
    // -------------------------------------------------------------------------

    #[test]
    fn stats_rules_empty_database_shows_message() {
        let env = StatsRulesEnv::new();
        // Don't seed any data

        // Create the database, then close the setup handle before the dcg
        // subprocess opens the same SQLite file.
        let db = HistoryDb::open(Some(env.db_path.clone())).expect("create db");
        drop(db);

        let output = env.run(&["stats", "--rules"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            output.status.success(),
            "should succeed even with empty database"
        );
        assert!(
            stdout.contains("No rule metrics found"),
            "should show 'No rule metrics found' message\nstdout:\n{stdout}"
        );
    }

    // -------------------------------------------------------------------------
    // Trend indicator tests
    // -------------------------------------------------------------------------

    #[test]
    fn stats_rules_pretty_shows_trend_indicators() {
        let env = StatsRulesEnv::new();
        env.seed_rule_metrics_data();

        let output = env.run(&["stats", "--rules"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Should contain at least one of the trend indicators
        let has_trend_indicator =
            stdout.contains("↑") || stdout.contains("→") || stdout.contains("↓");
        assert!(
            has_trend_indicator,
            "should show at least one trend indicator\nstdout:\n{stdout}"
        );
    }

    #[test]
    fn stats_rules_json_trend_values_valid() {
        let env = StatsRulesEnv::new();
        env.seed_rule_metrics_data();

        let output = env.run(&["stats", "--rules", "--format", "json"]);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let rules = json["rules"].as_array().unwrap();

        for rule in rules {
            let trend = rule["trend"].as_str().unwrap();
            assert!(
                ["increasing", "stable", "decreasing"].contains(&trend),
                "trend should be one of increasing/stable/decreasing, got: {trend}"
            );
        }
    }
}

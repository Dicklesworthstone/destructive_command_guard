//! Subprocess integration tests for Codex CLI hook protocol.
//!
//! Verifies that the real dcg binary, spawned as a child process, correctly
//! handles Codex 0.125.0+ payloads (exit code 2 + stderr deny) and Claude
//! Code payloads (exit 0 + stdout JSON deny).
//!
//! Each test is hermetic: isolated HOME, isolated TMPDIR, no shared state.
//! Safe for parallel execution via `cargo nextest`.

#![allow(clippy::doc_markdown, clippy::uninlined_format_args)]

use std::fmt;
use std::io::{ErrorKind, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

// ---------------------------------------------------------------------------
// HookOutcome — typed subprocess result with postmortem diagnostics
// ---------------------------------------------------------------------------

/// Result of spawning dcg as a subprocess.
pub struct HookOutcome {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i32,
    /// The JSON bytes piped to stdin (for diagnostics).
    pub stdin_sent: Vec<u8>,
    /// Hermetic HOME used for this invocation.
    pub home_dir: PathBuf,
}

impl HookOutcome {
    pub fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    pub fn stderr_str(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    pub fn stderr_contains(&self, needle: &str) -> bool {
        self.stderr_str().contains(needle)
    }

    /// Codex block shape: exit 2, zero stdout bytes, non-empty stderr.
    pub fn is_codex_block_shape(&self) -> bool {
        self.exit_code == 2 && self.stdout.is_empty() && !self.stderr.is_empty()
    }

    /// Claude block shape: exit 0, stdout contains hookSpecificOutput JSON.
    pub fn is_claude_block_shape(&self) -> bool {
        self.exit_code == 0
            && !self.stdout.is_empty()
            && self.stdout_str().contains("hookSpecificOutput")
    }

    /// Allow shape: exit 0, empty (or whitespace-only) stdout.
    pub fn is_allow_shape(&self) -> bool {
        self.exit_code == 0 && self.stdout_str().trim().is_empty()
    }

    /// Parse stdout as JSON (panics with diagnostics if not valid JSON).
    pub fn stdout_json(&self) -> serde_json::Value {
        let s = self.stdout_str();
        serde_json::from_str(s.trim())
            .unwrap_or_else(|e| panic!("stdout not valid JSON: {e}\n{self}"))
    }
}

impl fmt::Display for HookOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "--- HookOutcome postmortem ---")?;
        writeln!(f, "exit_code: {}", self.exit_code)?;
        writeln!(f, "home_dir: {}", self.home_dir.display())?;
        writeln!(f, "stdin ({} bytes):", self.stdin_sent.len())?;
        writeln!(f, "  {}", String::from_utf8_lossy(&self.stdin_sent))?;
        writeln!(f, "stdout ({} bytes):", self.stdout.len())?;
        writeln!(f, "  UTF-8: {}", String::from_utf8_lossy(&self.stdout))?;
        if self.stdout.len() <= 256 {
            write!(f, "  hex: ")?;
            for b in &self.stdout {
                write!(f, "{b:02x} ")?;
            }
            writeln!(f)?;
        }
        writeln!(f, "stderr ({} bytes):", self.stderr.len())?;
        writeln!(f, "  {}", String::from_utf8_lossy(&self.stderr))?;
        write!(f, "--- end postmortem ---")
    }
}

impl fmt::Debug for HookOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

// ---------------------------------------------------------------------------
// Binary discovery
// ---------------------------------------------------------------------------

/// Path to the dcg binary (same workspace-relative discovery as
/// tests/agent_hook_output.rs).
fn dcg_binary() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // test binary name
    path.pop(); // deps/
    path.push("dcg");
    path
}

// ---------------------------------------------------------------------------
// Payload builders
// ---------------------------------------------------------------------------

/// Build a complete Codex 0.125.0+ stdin payload.
///
/// Includes ALL fields a real Codex client sends (session_id, turn_id,
/// transcript_path, cwd, hook_event_name, model, permission_mode,
/// tool_name, tool_input, tool_use_id) so tests mirror production payloads.
fn build_codex_payload(command: &str) -> String {
    let escaped = command.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        r#"{{
  "session_id": "019dd11d-b795-7261-a9cb-9b85a5dad632",
  "turn_id": "turn-test-1",
  "transcript_path": null,
  "cwd": "/tmp/test-workdir",
  "hook_event_name": "PreToolUse",
  "model": "gpt-5.5",
  "permission_mode": "bypassPermissions",
  "tool_name": "Bash",
  "tool_input": {{ "command": "{escaped}" }},
  "tool_use_id": "call_test_abc123"
}}"#
    )
}

/// Build a complete Claude Code stdin payload (per code.claude.com/docs/en/hooks).
///
/// Does NOT include turn_id — that's the Codex disambiguator.
fn build_claude_payload(command: &str) -> String {
    let escaped = command.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        r#"{{
  "session_id": "sess-claude-test",
  "transcript_path": "/tmp/claude/transcript.jsonl",
  "cwd": "/tmp/test-workdir",
  "permission_mode": "default",
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {{ "command": "{escaped}" }},
  "tool_use_id": "toolu_01TEST"
}}"#
    )
}

/// Build a complete Gemini CLI `BeforeTool` payload for `run_shell_command`.
fn build_gemini_payload(command: &str) -> String {
    let escaped = command.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        r#"{{
  "session_id": "gemini-test-session",
  "transcript_path": "/tmp/gemini/transcript.json",
  "cwd": "/tmp/test-workdir",
  "hook_event_name": "BeforeTool",
  "timestamp": "2026-05-01T00:00:00Z",
  "tool_name": "run_shell_command",
  "tool_input": {{ "command": "{escaped}" }}
}}"#
    )
}

// ---------------------------------------------------------------------------
// Hermetic subprocess runner
//
// IMPORTANT: Every spawn uses env_clear() + a minimal PATH + an isolated
// per-test HOME and TMPDIR. This prevents cross-contamination when cargo
// nextest runs tests in parallel — without per-test HOME, concurrent tests
// would race on history sqlite, pending-exception files, and allowlists.
// ---------------------------------------------------------------------------

/// Create an isolated HOME directory for one test invocation.
fn make_hermetic_home() -> tempfile::TempDir {
    tempfile::tempdir().expect("failed to create hermetic HOME tempdir")
}

/// Spawn dcg with raw JSON bytes and optional env overrides.
///
/// This is the lowest-level helper — all other `run_*` functions delegate here.
pub fn run_hook_raw(json_bytes: &[u8], extra_env: &[(&str, &str)]) -> HookOutcome {
    let home = make_hermetic_home();
    let home_path = home.path().to_path_buf();
    let tmp_path = home.path().join("tmp");
    std::fs::create_dir_all(&tmp_path).ok();

    let system_path = std::env::var("PATH").unwrap_or_default();

    let mut cmd = Command::new(dcg_binary());
    cmd.env_clear()
        .env("PATH", &system_path)
        .env("HOME", home.path())
        .env("TMPDIR", &tmp_path)
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    for (k, v) in extra_env {
        cmd.env(k, v);
    }

    let mut child = cmd.spawn().expect("failed to spawn dcg process");

    {
        let stdin = child.stdin.as_mut().expect("failed to get stdin");
        if let Err(err) = stdin.write_all(json_bytes) {
            assert_eq!(
                err.kind(),
                ErrorKind::BrokenPipe,
                "failed to write to stdin: {err}"
            );
        }
    }

    let output = child.wait_with_output().expect("failed to wait for dcg");

    // Keep tempdir if DCG_TEST_KEEP_TEMPDIRS is set (for postmortem).
    let keep = std::env::var_os("DCG_TEST_KEEP_TEMPDIRS").is_some();
    if keep {
        eprintln!("  [keep-tempdirs] hermetic HOME: {}", home.path().display());
        // Leak the TempDir so it isn't cleaned up.
        let _ = home.keep();
    }

    HookOutcome {
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: output.status.code().unwrap_or(-1),
        stdin_sent: json_bytes.to_vec(),
        home_dir: home_path,
    }
}

/// Spawn dcg with a hermetic config file in place.
pub fn run_hook_raw_with_config(
    json_bytes: &[u8],
    config_toml: &str,
    extra_env: &[(&str, &str)],
) -> HookOutcome {
    let home = make_hermetic_home();
    let home_path = home.path().to_path_buf();
    let tmp_path = home.path().join("tmp");
    let config_dir = home.path().join(".config/dcg");
    std::fs::create_dir_all(&tmp_path).ok();
    std::fs::create_dir_all(&config_dir).expect("failed to create config dir");
    std::fs::write(config_dir.join("config.toml"), config_toml).expect("failed to write config");

    let system_path = std::env::var("PATH").unwrap_or_default();

    let mut cmd = Command::new(dcg_binary());
    cmd.env_clear()
        .env("PATH", &system_path)
        .env("HOME", home.path())
        .env("TMPDIR", &tmp_path)
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    for (k, v) in extra_env {
        cmd.env(k, v);
    }

    let mut child = cmd.spawn().expect("failed to spawn dcg process");

    {
        let stdin = child.stdin.as_mut().expect("failed to get stdin");
        if let Err(err) = stdin.write_all(json_bytes) {
            assert_eq!(
                err.kind(),
                ErrorKind::BrokenPipe,
                "failed to write to stdin: {err}"
            );
        }
    }

    let output = child.wait_with_output().expect("failed to wait for dcg");

    HookOutcome {
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: output.status.code().unwrap_or(-1),
        stdin_sent: json_bytes.to_vec(),
        home_dir: home_path,
    }
}

/// Run dcg with a Codex 0.125.0+ payload for the given command.
pub fn run_codex_hook(command: &str) -> HookOutcome {
    run_codex_hook_with_env(command, &[], &[])
}

/// Run dcg with a Codex payload, additional env vars, and env removals.
pub fn run_codex_hook_with_env(
    command: &str,
    extra_env: &[(&str, &str)],
    _remove_env: &[&str],
) -> HookOutcome {
    let payload = build_codex_payload(command);
    run_hook_raw(payload.as_bytes(), extra_env)
}

/// Run dcg with a Claude Code payload for the given command.
pub fn run_claude_hook(command: &str) -> HookOutcome {
    run_claude_hook_with_env(command, &[], &[])
}

/// Run dcg with a Claude Code payload, additional env vars, and env removals.
pub fn run_claude_hook_with_env(
    command: &str,
    extra_env: &[(&str, &str)],
    _remove_env: &[&str],
) -> HookOutcome {
    let payload = build_claude_payload(command);
    run_hook_raw(payload.as_bytes(), extra_env)
}

// ---------------------------------------------------------------------------
// Smoke tests — validate the scaffold helpers work before leaf tests depend
// on them.
// ---------------------------------------------------------------------------

#[test]
fn smoke_codex_safe_command_allowed() {
    let outcome = run_codex_hook("git status");
    assert!(
        outcome.is_allow_shape(),
        "safe command via Codex should be allowed (exit 0, empty stdout)\n{outcome}"
    );
}

#[test]
fn smoke_claude_safe_command_allowed() {
    let outcome = run_claude_hook("git status");
    assert!(
        outcome.is_allow_shape(),
        "safe command via Claude should be allowed (exit 0, empty stdout)\n{outcome}"
    );
}

#[test]
fn smoke_codex_destructive_command_blocked() {
    let outcome = run_codex_hook("git reset --hard HEAD~1");
    assert!(
        outcome.is_codex_block_shape(),
        "destructive command via Codex should produce exit 2 + empty stdout + non-empty stderr\n{outcome}"
    );
}

#[test]
fn smoke_claude_destructive_command_blocked() {
    let outcome = run_claude_hook("git reset --hard HEAD~1");
    assert!(
        outcome.is_claude_block_shape(),
        "destructive command via Claude should produce exit 0 + hookSpecificOutput JSON\n{outcome}"
    );
}

#[test]
fn copilot_tool_args_without_tool_name_blocks_destructive_command() {
    let payload = serde_json::json!({
        "event": "pre-tool-use",
        "toolArgs": serde_json::json!({ "command": "git reset --hard" }).to_string(),
    })
    .to_string();

    let outcome = run_hook_raw(payload.as_bytes(), &[]);
    assert_eq!(
        outcome.exit_code, 0,
        "Copilot deny should exit 0 with JSON on stdout\n{outcome}"
    );
    assert!(
        !outcome.stdout.is_empty(),
        "Copilot deny must produce stdout JSON\n{outcome}"
    );

    let json = outcome.stdout_json();
    assert_eq!(json["permissionDecision"], "deny", "{outcome}");
    assert_eq!(json["ruleId"], "core.git:reset-hard", "{outcome}");
    assert_eq!(json["continue"], false, "{outcome}");
}

#[test]
fn copilot_powershell_tool_args_blocks_destructive_command() {
    let payload = serde_json::json!({
        "event": "pre-tool-use",
        "toolName": "powershell",
        "toolArgs": {
            "command": "git reset --hard"
        },
    })
    .to_string();

    let outcome = run_hook_raw(payload.as_bytes(), &[]);
    assert_eq!(
        outcome.exit_code, 0,
        "Copilot PowerShell deny should exit 0 with JSON on stdout\n{outcome}"
    );
    assert!(
        !outcome.stdout.is_empty(),
        "Copilot PowerShell deny must produce stdout JSON\n{outcome}"
    );

    let json = outcome.stdout_json();
    assert_eq!(json["permissionDecision"], "deny", "{outcome}");
    assert_eq!(json["ruleId"], "core.git:reset-hard", "{outcome}");
    assert_eq!(json["continue"], false, "{outcome}");
}

#[test]
fn codex_protocol_applies_codex_agent_profile_without_env() {
    let payload = build_codex_payload("git reset --hard HEAD~1");
    let outcome = run_hook_raw_with_config(
        payload.as_bytes(),
        r#"[agents.codex-cli]
additional_allowlist = ["git reset --hard HEAD~1"]
"#,
        &[],
    );

    assert!(
        outcome.is_allow_shape(),
        "Codex hook protocol should select codex-cli profile even without CODEX_CLI env\n{outcome}"
    );
}

#[test]
fn gemini_protocol_applies_gemini_agent_profile_without_env() {
    let payload = build_gemini_payload("git reset --hard HEAD~1");
    let outcome = run_hook_raw_with_config(
        payload.as_bytes(),
        r#"[agents.gemini-cli]
additional_allowlist = ["git reset --hard HEAD~1"]
"#,
        &[],
    );

    assert!(
        outcome.is_allow_shape(),
        "Gemini hook protocol should select gemini-cli profile even without GEMINI_CLI env\n{outcome}"
    );
}

#[test]
fn copilot_protocol_applies_copilot_agent_profile_without_env() {
    let payload = serde_json::json!({
        "event": "pre-tool-use",
        "toolArgs": serde_json::json!({ "command": "git reset --hard HEAD~1" }).to_string(),
    })
    .to_string();
    let outcome = run_hook_raw_with_config(
        payload.as_bytes(),
        r#"[agents.copilot-cli]
additional_allowlist = ["git reset --hard HEAD~1"]
"#,
        &[],
    );

    assert!(
        outcome.is_allow_shape(),
        "Copilot hook protocol should select copilot-cli profile even without COPILOT_CLI env\n{outcome}"
    );
}

// ---------------------------------------------------------------------------
// P2.2 — Codex deny path: exit=2, 0 bytes stdout, non-empty stderr
// ---------------------------------------------------------------------------

#[test]
fn codex_deny_multiple_destructive_commands() {
    let commands = [
        ("git reset --hard HEAD~5", "core.git:reset-hard"),
        ("git clean -fd", "core.git:clean-force"),
        ("git push --force origin main", "core.git"),
        ("rm -rf /important/data", "core.filesystem"),
    ];

    for (cmd, expected_rule_fragment) in commands {
        let outcome = run_codex_hook(cmd);
        assert_eq!(
            outcome.exit_code, 2,
            "Codex deny must exit 2 for '{cmd}'\n{outcome}"
        );
        assert!(
            outcome.stdout.is_empty(),
            "Codex deny must produce 0 bytes stdout for '{cmd}'\n{outcome}"
        );
        assert!(
            !outcome.stderr.is_empty(),
            "Codex deny must produce non-empty stderr for '{cmd}'\n{outcome}"
        );
        assert!(
            outcome.stderr_contains(expected_rule_fragment),
            "stderr must contain rule fragment '{expected_rule_fragment}' for '{cmd}'\n{outcome}"
        );
    }
}

#[test]
fn codex_deny_stderr_is_not_empty_even_when_nosuggest() {
    // exit 2 + empty stderr = Failed in Codex (catastrophic); dcg must always
    // produce non-empty stderr on deny.
    let outcome = run_codex_hook("git reset --hard");
    assert_eq!(outcome.exit_code, 2, "exit code 2 expected\n{outcome}");
    assert!(
        outcome.stderr.len() > 10,
        "stderr must be substantive (>10 bytes), got {} bytes\n{outcome}",
        outcome.stderr.len()
    );
}

// ---------------------------------------------------------------------------
// P2.3 — Codex allow path: exit=0, no stdout, no stderr
// ---------------------------------------------------------------------------

#[test]
fn codex_allow_safe_commands_produce_no_output() {
    let safe_commands = [
        "git status",
        "git log --oneline -5",
        "git diff HEAD",
        "git checkout -b new-feature",
        "ls -la",
        "echo hello",
        "cat README.md",
    ];

    for cmd in safe_commands {
        let outcome = run_codex_hook(cmd);
        assert_eq!(
            outcome.exit_code, 0,
            "safe command '{cmd}' must exit 0\n{outcome}"
        );
        assert!(
            outcome.stdout.is_empty(),
            "safe command '{cmd}' must produce 0 bytes stdout\n{outcome}"
        );
        // stderr may contain trace/debug output but should be empty or minimal
        // in a clean hermetic env.
    }
}

#[test]
fn codex_allow_git_clean_dry_run_not_blocked() {
    let outcome = run_codex_hook("git clean -n");
    assert!(
        outcome.is_allow_shape(),
        "git clean -n (dry run) must be allowed\n{outcome}"
    );
}

// ---------------------------------------------------------------------------
// P2.5 — Regression: tool_use_id (no turn_id) stays on Claude path
// ---------------------------------------------------------------------------

#[test]
fn regression_claude_tool_use_id_bash_stays_claude_path() {
    // A Claude Code payload with tool_use_id but NO turn_id must produce
    // Claude-shaped output (exit 0 + hookSpecificOutput JSON), NOT Codex
    // (exit 2 + stderr). If the disambiguator keyed on tool_use_id instead
    // of turn_id, this would fail.
    let outcome = run_claude_hook("git reset --hard HEAD~1");
    assert_eq!(
        outcome.exit_code, 0,
        "Claude path must exit 0, not 2\n{outcome}"
    );
    assert!(
        outcome.is_claude_block_shape(),
        "Claude deny must produce hookSpecificOutput JSON on stdout\n{outcome}"
    );
    let json = outcome.stdout_json();
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"], "deny",
        "Claude deny must have permissionDecision=deny\n{outcome}"
    );
}

#[test]
fn regression_claude_tool_use_id_launch_process_stays_claude_path() {
    // Variant with launch-process tool name.
    let payload = r#"{
  "session_id": "sess-claude-test",
  "transcript_path": "/tmp/claude/transcript.jsonl",
  "cwd": "/tmp/test-workdir",
  "permission_mode": "default",
  "hook_event_name": "PreToolUse",
  "tool_name": "launch-process",
  "tool_input": { "command": "git reset --hard HEAD~1" },
  "tool_use_id": "toolu_01LAUNCH"
}"#
    .to_string();
    let outcome = run_hook_raw(payload.as_bytes(), &[]);
    assert_eq!(
        outcome.exit_code, 0,
        "launch-process Claude path must exit 0\n{outcome}"
    );
    assert!(
        outcome.is_claude_block_shape(),
        "launch-process Claude deny must produce hookSpecificOutput JSON\n{outcome}"
    );
}

// ---------------------------------------------------------------------------
// P2.4 — Codex warn path: exit=0, no stdout, stderr warns
// ---------------------------------------------------------------------------

#[test]
fn codex_warn_path_exits_zero_with_stderr_warning() {
    // Critical patterns can only be downgraded via per-rule override in config.
    // Write a config file with the per-rule override to the hermetic HOME.
    let home = tempfile::tempdir().expect("tempdir");
    let config_dir = home.path().join(".config/dcg");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("config.toml"),
        b"[policy.rules]\n\"core.git:reset-hard\" = \"warn\"\n",
    )
    .unwrap();

    let payload = build_codex_payload("git reset --hard HEAD~1");
    let system_path = std::env::var("PATH").unwrap_or_default();

    let mut cmd = Command::new(dcg_binary());
    cmd.env_clear()
        .env("PATH", &system_path)
        .env("HOME", home.path())
        .env("TMPDIR", home.path().join("tmp"))
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn");
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(payload.as_bytes()).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    let outcome = HookOutcome {
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: output.status.code().unwrap_or(-1),
        stdin_sent: payload.into_bytes(),
        home_dir: home.path().to_path_buf(),
    };

    assert_eq!(
        outcome.exit_code, 0,
        "Codex warn must exit 0 (not 2)\n{outcome}"
    );
    assert!(
        outcome.stdout.is_empty(),
        "Codex warn must produce 0 bytes stdout\n{outcome}"
    );
    assert!(
        !outcome.stderr.is_empty(),
        "Codex warn must produce non-empty stderr\n{outcome}"
    );
    assert!(
        outcome.stderr_contains("WARNING") || outcome.stderr_contains("warn"),
        "stderr must contain warning text\n{outcome}"
    );
}

// ---------------------------------------------------------------------------
// P2.7 — DCG_BYPASS=1 short-circuits before Codex protocol detection
// ---------------------------------------------------------------------------

#[test]
fn codex_bypass_exits_zero_silently() {
    // DCG_BYPASS=1 must cause silent exit 0 even for Codex destructive commands.
    let outcome = run_codex_hook_with_env("git reset --hard HEAD~1", &[("DCG_BYPASS", "1")], &[]);
    assert_eq!(outcome.exit_code, 0, "bypass must exit 0, not 2\n{outcome}");
    assert!(
        outcome.stdout.is_empty(),
        "bypass must produce no stdout\n{outcome}"
    );
}

#[test]
fn claude_bypass_exits_zero_silently() {
    // Same for Claude path — bypass silences everything.
    let outcome = run_claude_hook_with_env("git reset --hard HEAD~1", &[("DCG_BYPASS", "1")], &[]);
    assert_eq!(outcome.exit_code, 0, "Claude bypass must exit 0\n{outcome}");
    assert!(
        outcome.stdout.is_empty(),
        "Claude bypass must produce no stdout\n{outcome}"
    );
}

// ===========================================================================
// P2.9 — Claude Code parity matrix
//
// Symmetric coverage to P2.2-P2.7 for the Claude Code protocol path.
// Every Claude scenario has a paired Codex scenario above; this file lets
// a reviewer read off which scenario tests which contract.
// ===========================================================================

// ---------------------------------------------------------------------------
// P2.9.1 — Claude deny matrix: exit=0, stdout JSON with all documented fields
// ---------------------------------------------------------------------------

#[test]
fn claude_deny_matrix_multiple_destructive_commands() {
    let commands = [
        ("git reset --hard HEAD~5", "core.git"),
        ("git clean -fd", "core.git"),
        ("git push --force origin main", "core.git"),
        ("rm -rf /important/data", "core.filesystem"),
    ];

    for (cmd, expected_pack_fragment) in commands {
        let outcome = run_claude_hook(cmd);
        assert_eq!(
            outcome.exit_code, 0,
            "Claude deny must exit 0 for '{cmd}'\n{outcome}"
        );
        assert!(
            !outcome.stdout.is_empty(),
            "Claude deny must produce non-empty stdout JSON for '{cmd}'\n{outcome}"
        );
        assert!(
            outcome.is_claude_block_shape(),
            "Claude deny must have hookSpecificOutput for '{cmd}'\n{outcome}"
        );

        let json = outcome.stdout_json();
        let hso = &json["hookSpecificOutput"];

        assert_eq!(
            hso["hookEventName"], "PreToolUse",
            "hookEventName must be PreToolUse for '{cmd}'\n{outcome}"
        );
        assert_eq!(
            hso["permissionDecision"], "deny",
            "permissionDecision must be deny for '{cmd}'\n{outcome}"
        );
        assert!(
            hso["permissionDecisionReason"].is_string()
                && !hso["permissionDecisionReason"].as_str().unwrap().is_empty(),
            "permissionDecisionReason must be non-empty string for '{cmd}'\n{outcome}"
        );

        // allowOnceCode: 5+ character string
        let code = hso["allowOnceCode"].as_str();
        assert!(
            code.is_some() && code.unwrap().len() >= 5,
            "allowOnceCode must be >= 5 chars for '{cmd}', got: {code:?}\n{outcome}"
        );

        // allowOnceFullHash: sha256-length hex string
        let hash = hso["allowOnceFullHash"].as_str();
        assert!(
            hash.is_some() && hash.unwrap().len() >= 16,
            "allowOnceFullHash must be >= 16 chars for '{cmd}', got: {hash:?}\n{outcome}"
        );

        // packId contains the expected fragment
        let pack_id = hso["packId"].as_str().unwrap_or("");
        assert!(
            pack_id.contains(expected_pack_fragment),
            "packId must contain '{expected_pack_fragment}' for '{cmd}', got: '{pack_id}'\n{outcome}"
        );

        // ruleId is present and contains the pack
        let rule_id = hso["ruleId"].as_str().unwrap_or("");
        assert!(
            rule_id.contains(expected_pack_fragment),
            "ruleId must contain '{expected_pack_fragment}' for '{cmd}', got: '{rule_id}'\n{outcome}"
        );

        // severity is present and is a known value
        let severity = hso["severity"].as_str().unwrap_or("");
        assert!(
            ["critical", "high", "medium", "low"].contains(&severity),
            "severity must be a known level for '{cmd}', got: '{severity}'\n{outcome}"
        );

        // remediation block
        assert!(
            hso["remediation"].is_object(),
            "remediation must be present as object for '{cmd}'\n{outcome}"
        );
        let remediation = &hso["remediation"];
        let aoc = remediation["allowOnceCommand"].as_str().unwrap_or("");
        assert!(
            aoc.starts_with("dcg allow-once "),
            "remediation.allowOnceCommand must start with 'dcg allow-once ' for '{cmd}', got: '{aoc}'\n{outcome}"
        );

        // stderr should also have a human-readable deny block
        assert!(
            !outcome.stderr.is_empty(),
            "Claude deny stderr must be non-empty (colored deny block) for '{cmd}'\n{outcome}"
        );
    }
}

#[test]
fn claude_deny_git_checkout_file_restore() {
    let outcome = run_claude_hook("git checkout -- important_file.rs");
    assert!(
        outcome.is_claude_block_shape(),
        "git checkout -- <file> must be denied by Claude\n{outcome}"
    );
    let json = outcome.stdout_json();
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn claude_deny_or_warn_git_stash_drop() {
    let outcome = run_claude_hook("git stash drop");
    assert_eq!(
        outcome.exit_code, 0,
        "git stash drop must exit 0 via Claude\n{outcome}"
    );
    assert!(
        !outcome.stdout.is_empty(),
        "git stash drop must produce stdout JSON via Claude\n{outcome}"
    );
    let json = outcome.stdout_json();
    let decision = json["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or("");
    assert!(
        decision == "deny" || decision == "ask",
        "git stash drop must be denied or warned (ask), got '{decision}'\n{outcome}"
    );
}

// ---------------------------------------------------------------------------
// P2.9.2 — Claude allow matrix: exit=0, empty stdout, empty stderr
// ---------------------------------------------------------------------------

#[test]
fn claude_allow_safe_commands_produce_no_output() {
    let safe_commands = [
        "git status",
        "git log --oneline -5",
        "git diff HEAD",
        "git checkout -b new-feature",
        "ls -la",
        "echo hello",
        "cat README.md",
    ];

    for cmd in safe_commands {
        let outcome = run_claude_hook(cmd);
        assert_eq!(
            outcome.exit_code, 0,
            "safe command '{cmd}' must exit 0 via Claude\n{outcome}"
        );
        assert!(
            outcome.stdout.is_empty(),
            "safe command '{cmd}' must produce 0 bytes stdout via Claude\n{outcome}"
        );
    }
}

#[test]
fn claude_allow_git_clean_dry_run_not_blocked() {
    let outcome = run_claude_hook("git clean -n");
    assert!(
        outcome.is_allow_shape(),
        "git clean -n (dry run) must be allowed via Claude\n{outcome}"
    );
}

// ---------------------------------------------------------------------------
// P2.9.3 — Claude warn path: exit=0, stdout JSON with permissionDecision="ask"
// ---------------------------------------------------------------------------

#[test]
fn claude_warn_path_exits_zero_with_ask_json() {
    let home = tempfile::tempdir().expect("tempdir");
    let config_dir = home.path().join(".config/dcg");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("config.toml"),
        b"[policy.rules]\n\"core.git:reset-hard\" = \"warn\"\n",
    )
    .unwrap();

    let payload = build_claude_payload("git reset --hard HEAD~1");
    let system_path = std::env::var("PATH").unwrap_or_default();

    let mut cmd = Command::new(dcg_binary());
    cmd.env_clear()
        .env("PATH", &system_path)
        .env("HOME", home.path())
        .env("TMPDIR", home.path().join("tmp"))
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn");
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(payload.as_bytes()).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    let outcome = HookOutcome {
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: output.status.code().unwrap_or(-1),
        stdin_sent: payload.into_bytes(),
        home_dir: home.path().to_path_buf(),
    };

    assert_eq!(outcome.exit_code, 0, "Claude warn must exit 0\n{outcome}");
    assert!(
        !outcome.stdout.is_empty(),
        "Claude warn must produce stdout JSON (unlike Codex warn which has empty stdout)\n{outcome}"
    );

    let json = outcome.stdout_json();
    let hso = &json["hookSpecificOutput"];
    assert_eq!(
        hso["permissionDecision"], "ask",
        "Claude warn must have permissionDecision='ask'\n{outcome}"
    );
    assert!(
        hso["permissionDecisionReason"]
            .as_str()
            .unwrap_or("")
            .contains("warn"),
        "Claude warn reason must mention 'warn'\n{outcome}"
    );

    // stderr should have a human-visible warning
    assert!(
        !outcome.stderr.is_empty(),
        "Claude warn stderr must be non-empty\n{outcome}"
    );
    assert!(
        outcome.stderr_contains("WARNING") || outcome.stderr_contains("warn"),
        "stderr must contain warning text\n{outcome}"
    );
}

#[test]
fn copilot_warn_path_exits_zero_with_ask_json_and_continue_true() {
    let payload = serde_json::json!({
        "event": "pre-tool-use",
        "toolName": "bash",
        "toolArgs": {
            "command": "git reset --hard HEAD~1"
        },
    })
    .to_string();

    let outcome = run_hook_raw_with_config(
        payload.as_bytes(),
        r#"[policy.rules]
"core.git:reset-hard" = "warn"
"#,
        &[],
    );

    assert_eq!(outcome.exit_code, 0, "Copilot warn must exit 0\n{outcome}");
    assert!(
        !outcome.stdout.is_empty(),
        "Copilot warn must produce stdout JSON\n{outcome}"
    );

    let json = outcome.stdout_json();
    assert_eq!(
        json["permissionDecision"], "ask",
        "Copilot warn must have permissionDecision='ask'\n{outcome}"
    );
    assert_eq!(
        json["continue"], true,
        "Copilot warn must not emit the legacy stop signal\n{outcome}"
    );
    assert!(
        json["permissionDecisionReason"]
            .as_str()
            .unwrap_or("")
            .contains("warn"),
        "Copilot warn reason must mention 'warn'\n{outcome}"
    );
}

// ---------------------------------------------------------------------------
// P2.9.4 — Claude bypass: DCG_BYPASS=1 → silent exit 0, both buffers empty
//
// (Already covered by claude_bypass_exits_zero_silently above in P2.7;
// replicated here so this P2.9 block is self-contained for Claude reasoning.)
// ---------------------------------------------------------------------------

#[test]
fn claude_bypass_destructive_command_fully_silent() {
    let outcome = run_claude_hook_with_env("git reset --hard HEAD~1", &[("DCG_BYPASS", "1")], &[]);
    assert_eq!(outcome.exit_code, 0, "Claude bypass must exit 0\n{outcome}");
    assert!(
        outcome.stdout.is_empty(),
        "Claude bypass must produce no stdout\n{outcome}"
    );
    // stderr may have trace-level output but no deny/warn block
    assert!(
        !outcome.stderr_contains("BLOCKED") && !outcome.stderr_contains("deny"),
        "Claude bypass must not contain BLOCKED or deny text on stderr\n{outcome}"
    );
}

#[test]
fn bypass_requires_explicit_truthy_value() {
    for value in ["", "0", "false", "no", "off"] {
        let codex =
            run_codex_hook_with_env("git reset --hard HEAD~1", &[("DCG_BYPASS", value)], &[]);
        assert!(
            codex.is_codex_block_shape(),
            "DCG_BYPASS={value:?} must not bypass Codex denial\n{codex}"
        );

        let claude =
            run_claude_hook_with_env("git reset --hard HEAD~1", &[("DCG_BYPASS", value)], &[]);
        assert!(
            claude.is_claude_block_shape(),
            "DCG_BYPASS={value:?} must not bypass Claude denial\n{claude}"
        );
    }
}

// ---------------------------------------------------------------------------
// P2.9.5 — Claude history persistence: denials write history DB rows
// ---------------------------------------------------------------------------

#[test]
fn claude_deny_writes_history_entry() {
    let home = tempfile::tempdir().expect("tempdir");
    let db_path = home.path().join("test-history.db");

    // History is disabled by default — enable it via config + env override for DB path.
    let config_dir = home.path().join(".config/dcg");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("config.toml"),
        b"[history]\nenabled = true\n",
    )
    .unwrap();

    let payload = build_claude_payload("git reset --hard HEAD~1");
    let system_path = std::env::var("PATH").unwrap_or_default();

    let mut cmd = Command::new(dcg_binary());
    cmd.env_clear()
        .env("PATH", &system_path)
        .env("HOME", home.path())
        .env("TMPDIR", home.path().join("tmp"))
        .env("NO_COLOR", "1")
        .env("DCG_HISTORY_DB", &db_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn");
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(payload.as_bytes()).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    let outcome = HookOutcome {
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: output.status.code().unwrap_or(-1),
        stdin_sent: payload.into_bytes(),
        home_dir: home.path().to_path_buf(),
    };

    assert!(
        outcome.is_claude_block_shape(),
        "Claude deny expected\n{outcome}"
    );

    // Claude exits normally (not process::exit(2)), so Drop-based flush runs.
    assert!(
        db_path.exists(),
        "history DB must exist after Claude deny at {}\n{outcome}",
        db_path.display()
    );

    let db_size = std::fs::metadata(&db_path)
        .expect("failed to stat history DB")
        .len();
    assert!(
        db_size > 4096,
        "history DB must be > 4096 bytes (contains data), got {db_size} bytes\n{outcome}"
    );
}

// ---------------------------------------------------------------------------
// P2.9.6 — Claude allow-once round-trip: capture code → redeem → retry passes
// ---------------------------------------------------------------------------

#[test]
fn claude_allow_once_round_trip() {
    // Step 1: Get a Claude deny with allow-once code
    let home = tempfile::tempdir().expect("tempdir");
    let home_path = home.path().to_path_buf();
    let system_path = std::env::var("PATH").unwrap_or_default();

    let deny_payload = build_claude_payload("git reset --hard HEAD~1");
    let mut cmd = Command::new(dcg_binary());
    cmd.env_clear()
        .env("PATH", &system_path)
        .env("HOME", &home_path)
        .env("TMPDIR", home_path.join("tmp"))
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn deny");
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(deny_payload.as_bytes()).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    let deny_outcome = HookOutcome {
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: output.status.code().unwrap_or(-1),
        stdin_sent: deny_payload.into_bytes(),
        home_dir: home_path.clone(),
    };

    assert!(
        deny_outcome.is_claude_block_shape(),
        "initial deny expected\n{deny_outcome}"
    );
    let json = deny_outcome.stdout_json();
    let allow_code = json["hookSpecificOutput"]["allowOnceCode"]
        .as_str()
        .unwrap_or_else(|| panic!("allowOnceCode must be present\n{deny_outcome}"));
    assert!(
        allow_code.len() >= 5,
        "allowOnceCode too short: '{allow_code}'\n{deny_outcome}"
    );

    // Step 2: Redeem the allow-once code using `dcg allow-once <code> --yes`
    let redeem_output = Command::new(dcg_binary())
        .arg("allow-once")
        .arg(allow_code)
        .arg("--yes")
        .env_clear()
        .env("PATH", &system_path)
        .env("HOME", &home_path)
        .env("TMPDIR", home_path.join("tmp"))
        .env("NO_COLOR", "1")
        .output()
        .expect("failed to run allow-once redeem");

    assert!(
        redeem_output.status.success(),
        "allow-once redeem must succeed (exit 0), got exit {}\nstdout: {}\nstderr: {}",
        redeem_output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&redeem_output.stdout),
        String::from_utf8_lossy(&redeem_output.stderr),
    );

    // Step 3: Retry the same command — should now be allowed
    let retry_payload = build_claude_payload("git reset --hard HEAD~1");
    let mut cmd = Command::new(dcg_binary());
    cmd.env_clear()
        .env("PATH", &system_path)
        .env("HOME", &home_path)
        .env("TMPDIR", home_path.join("tmp"))
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn retry");
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(retry_payload.as_bytes()).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    let retry_outcome = HookOutcome {
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: output.status.code().unwrap_or(-1),
        stdin_sent: retry_payload.into_bytes(),
        home_dir: home_path.clone(),
    };

    assert!(
        retry_outcome.is_allow_shape(),
        "after allow-once redeem, same command must be allowed\n{retry_outcome}"
    );
}

// ---------------------------------------------------------------------------
// P2.9.7 — Cross-protocol parity: same command produces structurally
//          different but semantically equivalent output for both protocols
// ---------------------------------------------------------------------------

#[test]
fn cross_protocol_deny_structural_parity() {
    let cmd = "git reset --hard HEAD~3";

    let codex = run_codex_hook(cmd);
    let claude = run_claude_hook(cmd);

    // Both block the command
    assert!(
        codex.is_codex_block_shape(),
        "Codex block shape expected\n{codex}"
    );
    assert!(
        claude.is_claude_block_shape(),
        "Claude block shape expected\n{claude}"
    );

    // Codex: exit 2, no stdout
    assert_eq!(codex.exit_code, 2);
    assert!(codex.stdout.is_empty());

    // Claude: exit 0, JSON stdout
    assert_eq!(claude.exit_code, 0);
    let json = claude.stdout_json();
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");

    // Both have non-empty stderr (the human-readable deny block)
    assert!(!codex.stderr.is_empty(), "Codex must have stderr\n{codex}");
    assert!(
        !claude.stderr.is_empty(),
        "Claude must have stderr\n{claude}"
    );

    // Both stderr mention the command
    assert!(
        codex.stderr_contains("git reset --hard"),
        "Codex stderr must mention the command\n{codex}"
    );
    assert!(
        claude.stderr_contains("git reset --hard"),
        "Claude stderr must mention the command\n{claude}"
    );
}

#[test]
fn cross_protocol_allow_structural_parity() {
    let cmd = "git status";

    let codex = run_codex_hook(cmd);
    let claude = run_claude_hook(cmd);

    // Both allow the command
    assert!(codex.is_allow_shape(), "Codex allow shape\n{codex}");
    assert!(claude.is_allow_shape(), "Claude allow shape\n{claude}");

    // Both exit 0 with empty stdout
    assert_eq!(codex.exit_code, 0);
    assert_eq!(claude.exit_code, 0);
    assert!(codex.stdout.is_empty());
    assert!(claude.stdout.is_empty());
}

// ===========================================================================
// P2.10 — Fail-open / error-mode integration tests
//
// dcg never crashes the host AI agent. Malformed, oversize, or missing input
// always results in fail-open (exit 0). These tests verify the documented
// "Fail-Open Philosophy" from README.
// ===========================================================================

// ---------------------------------------------------------------------------
// P2.10.1 — Malformed JSON stdin (various broken payloads)
// ---------------------------------------------------------------------------

#[test]
fn failopen_not_json_at_all() {
    let outcome = run_hook_raw(b"not-json-at-all", &[]);
    assert_eq!(
        outcome.exit_code, 0,
        "malformed input must fail-open\n{outcome}"
    );
    assert!(
        outcome.stdout.is_empty(),
        "no stdout on fail-open\n{outcome}"
    );
}

#[test]
fn failopen_incomplete_json_brace() {
    let outcome = run_hook_raw(b"{", &[]);
    assert_eq!(
        outcome.exit_code, 0,
        "incomplete JSON must fail-open\n{outcome}"
    );
    assert!(
        outcome.stdout.is_empty(),
        "no stdout on fail-open\n{outcome}"
    );
}

#[test]
fn failopen_json_null() {
    let outcome = run_hook_raw(b"null", &[]);
    assert_eq!(outcome.exit_code, 0, "JSON null must fail-open\n{outcome}");
    assert!(
        outcome.stdout.is_empty(),
        "no stdout on fail-open\n{outcome}"
    );
}

#[test]
fn failopen_json_array() {
    let outcome = run_hook_raw(b"[]", &[]);
    assert_eq!(outcome.exit_code, 0, "JSON array must fail-open\n{outcome}");
    assert!(
        outcome.stdout.is_empty(),
        "no stdout on fail-open\n{outcome}"
    );
}

#[test]
fn failopen_json_missing_tool_input() {
    let payload = br#"{ "tool_name": "Bash" }"#;
    let outcome = run_hook_raw(payload, &[]);
    assert_eq!(
        outcome.exit_code, 0,
        "missing tool_input must fail-open\n{outcome}"
    );
    assert!(
        outcome.stdout.is_empty(),
        "no stdout on fail-open\n{outcome}"
    );
}

#[test]
fn failopen_json_tool_input_null() {
    let payload = br#"{ "tool_name": "Bash", "tool_input": null }"#;
    let outcome = run_hook_raw(payload, &[]);
    assert_eq!(
        outcome.exit_code, 0,
        "null tool_input must fail-open\n{outcome}"
    );
    assert!(
        outcome.stdout.is_empty(),
        "no stdout on fail-open\n{outcome}"
    );
}

#[test]
fn failopen_json_command_is_number() {
    let payload = br#"{ "tool_name": "Bash", "tool_input": { "command": 42 } }"#;
    let outcome = run_hook_raw(payload, &[]);
    assert_eq!(
        outcome.exit_code, 0,
        "numeric command must fail-open\n{outcome}"
    );
    assert!(
        outcome.stdout.is_empty(),
        "no stdout on fail-open\n{outcome}"
    );
}

#[test]
fn failopen_json_command_is_array() {
    let payload = br#"{ "tool_name": "Bash", "tool_input": { "command": ["git", "reset"] } }"#;
    let outcome = run_hook_raw(payload, &[]);
    assert_eq!(
        outcome.exit_code, 0,
        "array command must fail-open\n{outcome}"
    );
    assert!(
        outcome.stdout.is_empty(),
        "no stdout on fail-open\n{outcome}"
    );
}

#[test]
fn failopen_json_command_is_object() {
    let payload = br#"{ "tool_name": "Bash", "tool_input": { "command": {"cmd": "git reset"} } }"#;
    let outcome = run_hook_raw(payload, &[]);
    assert_eq!(
        outcome.exit_code, 0,
        "object command must fail-open\n{outcome}"
    );
    assert!(
        outcome.stdout.is_empty(),
        "no stdout on fail-open\n{outcome}"
    );
}

// ---------------------------------------------------------------------------
// P2.10.2 — Empty stdin
// ---------------------------------------------------------------------------

#[test]
fn failopen_empty_stdin() {
    let outcome = run_hook_raw(b"", &[]);
    assert_eq!(
        outcome.exit_code, 0,
        "empty stdin must fail-open\n{outcome}"
    );
    assert!(
        outcome.stdout.is_empty(),
        "no stdout on fail-open\n{outcome}"
    );
}

// ---------------------------------------------------------------------------
// P2.10.3 — Truncated JSON (valid start, abrupt end)
// ---------------------------------------------------------------------------

#[test]
fn failopen_truncated_json() {
    let payload = br#"{ "tool_name": "Bash", "tool_input": { "command": "git reset --ha"#;
    let outcome = run_hook_raw(payload, &[]);
    assert_eq!(
        outcome.exit_code, 0,
        "truncated JSON must fail-open\n{outcome}"
    );
    assert!(
        outcome.stdout.is_empty(),
        "no stdout on fail-open\n{outcome}"
    );
}

// ---------------------------------------------------------------------------
// P2.10.4 — Oversize stdin (> max_hook_input_bytes, default 256 KiB)
// ---------------------------------------------------------------------------

#[test]
fn failopen_oversize_stdin() {
    // Default limit is 256 KiB. Send 300 KiB of valid-looking JSON.
    let padding = "x".repeat(300 * 1024);
    let payload =
        format!(r#"{{ "tool_name": "Bash", "tool_input": {{ "command": "{padding}" }} }}"#);
    let outcome = run_hook_raw(payload.as_bytes(), &[]);
    assert_eq!(
        outcome.exit_code, 0,
        "oversize stdin must fail-open\n{outcome}"
    );
    assert!(
        outcome.stdout.is_empty(),
        "no stdout on fail-open\n{outcome}"
    );
    assert!(
        outcome.stderr_contains("exceeds limit"),
        "stderr must mention 'exceeds limit' for oversize stdin\n{outcome}"
    );
}

// ---------------------------------------------------------------------------
// P2.10.5 — Oversize command (input under limit, command > max_command_bytes)
// ---------------------------------------------------------------------------

#[test]
fn failopen_oversize_command() {
    // Default command limit is 64 KiB. Send a 70 KiB command inside a small payload.
    let big_cmd = "echo ".to_string() + &"A".repeat(70 * 1024);
    let payload = build_claude_payload(&big_cmd);
    let outcome = run_hook_raw(payload.as_bytes(), &[]);
    assert_eq!(
        outcome.exit_code, 0,
        "oversize command must fail-open\n{outcome}"
    );
    assert!(
        outcome.stdout.is_empty(),
        "no stdout on fail-open\n{outcome}"
    );
    assert!(
        outcome.stderr_contains("exceeds limit"),
        "stderr must mention 'exceeds limit' for oversize command\n{outcome}"
    );
}

// ---------------------------------------------------------------------------
// P2.10.6 — turn_id with wrong type (number instead of string)
// ---------------------------------------------------------------------------

#[test]
fn failopen_turn_id_wrong_type() {
    let payload = br#"{
  "session_id": "test",
  "turn_id": 42,
  "cwd": "/tmp",
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": { "command": "git reset --hard" },
  "tool_use_id": "call_test"
}"#;
    let outcome = run_hook_raw(payload, &[]);
    // dcg should either fail-open (if serde rejects the type) or process normally.
    // Either way, no crash — exit 0 or 2 (if treated as valid Codex payload).
    assert!(
        outcome.exit_code == 0 || outcome.exit_code == 2,
        "wrong-type turn_id must not crash (exit 0 or 2), got {}\n{outcome}",
        outcome.exit_code
    );
}

// ---------------------------------------------------------------------------
// P2.10.7 — No crash on any fail-open path (universal invariant)
// ---------------------------------------------------------------------------

#[test]
fn failopen_no_crash_signal_on_garbage() {
    let garbage_payloads: &[&[u8]] = &[
        b"\xff\xfe\x00\x01",       // binary garbage
        b"\0\0\0\0",               // null bytes
        b"}{}{",                   // broken JSON
        b"true",                   // JSON true
        b"42",                     // JSON number
        b"\"just a string\"",      // JSON string
        b"{ \"tool_name\": 123 }", // wrong tool_name type
    ];

    for payload in garbage_payloads {
        let outcome = run_hook_raw(payload, &[]);
        assert_eq!(
            outcome.exit_code,
            0,
            "garbage input must fail-open (exit 0), got {} for {:?}\n{outcome}",
            outcome.exit_code,
            String::from_utf8_lossy(payload)
        );
        assert!(
            outcome.stdout.is_empty(),
            "no stdout for garbage input {:?}\n{outcome}",
            String::from_utf8_lossy(payload)
        );
        // Must not contain panic backtrace
        assert!(
            !outcome.stderr_contains("panicked at"),
            "must not panic on garbage input {:?}\n{outcome}",
            String::from_utf8_lossy(payload)
        );
    }
}

// ---------------------------------------------------------------------------
// P2.10.8 — Both protocols see same fail-open for malformed input
// ---------------------------------------------------------------------------

#[test]
fn failopen_same_behavior_both_protocols() {
    // Payload with valid structure but command is missing → fail-open for both
    let codex_style = br#"{
  "session_id": "test",
  "turn_id": "turn-1",
  "cwd": "/tmp",
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {}
}"#;
    let claude_style = br#"{
  "session_id": "test",
  "cwd": "/tmp",
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {}
}"#;

    let codex_outcome = run_hook_raw(codex_style, &[]);
    let claude_outcome = run_hook_raw(claude_style, &[]);

    assert_eq!(
        codex_outcome.exit_code, 0,
        "Codex-style missing command must fail-open\n{codex_outcome}"
    );
    assert_eq!(
        claude_outcome.exit_code, 0,
        "Claude-style missing command must fail-open\n{claude_outcome}"
    );
    assert!(codex_outcome.stdout.is_empty());
    assert!(claude_outcome.stdout.is_empty());
}

// ===========================================================================
// P2.13 — DCG_PACKS / DCG_DISABLE env vars under both protocols
//
// Verifies that pack enable/disable env vars work the same under Codex
// and Claude. Users use these to opt out of specific protections without
// disabling dcg entirely (e.g., CI pipelines).
// ===========================================================================

// ---------------------------------------------------------------------------
// P2.13.1 — DCG_DISABLE behavior with core packs
//
// KNOWN BEHAVIOR: `DCG_DISABLE=core.git` does NOT disable core.git with
// default config. The `core` category is unconditionally re-inserted into
// the enabled set by `PacksConfig::enabled_pack_ids()` AFTER disabled
// removal, and `expand_enabled` re-expands it to all core.* sub-packs.
// DCG_DISABLE only removes packs that are EXPLICITLY in the enabled list
// (not those added by category expansion). This is tested as a regression
// guard for the current semantics.
// ---------------------------------------------------------------------------

#[test]
fn disable_core_git_still_blocks_due_to_core_reinsertion_codex() {
    // DCG_DISABLE=core.git with default config: core is unconditionally
    // re-inserted, expanded to core.*, so core.git patterns still fire.
    let outcome = run_codex_hook_with_env(
        "git reset --hard HEAD~1",
        &[("DCG_DISABLE", "core.git")],
        &[],
    );
    assert_eq!(
        outcome.exit_code, 2,
        "DCG_DISABLE=core.git does NOT disable core.git with default config (known behavior)\n{outcome}"
    );
}

#[test]
fn disable_core_git_still_blocks_due_to_core_reinsertion_claude() {
    let outcome = run_claude_hook_with_env(
        "git reset --hard HEAD~1",
        &[("DCG_DISABLE", "core.git")],
        &[],
    );
    assert!(
        outcome.is_claude_block_shape(),
        "DCG_DISABLE=core.git does NOT disable core.git with default config (known behavior)\n{outcome}"
    );
}

// ---------------------------------------------------------------------------
// P2.13.3 — DCG_PACKS restricts to only specified packs
// ---------------------------------------------------------------------------

#[test]
fn packs_only_core_git_allows_filesystem_destructive_codex() {
    // Only core.git is enabled → filesystem patterns don't fire
    let outcome =
        run_codex_hook_with_env("rm -rf /tmp/important", &[("DCG_PACKS", "core.git")], &[]);
    assert_eq!(
        outcome.exit_code, 0,
        "DCG_PACKS=core.git must not block filesystem commands under Codex\n{outcome}"
    );
}

#[test]
fn packs_only_core_git_allows_filesystem_destructive_claude() {
    let outcome =
        run_claude_hook_with_env("rm -rf /tmp/important", &[("DCG_PACKS", "core.git")], &[]);
    assert!(
        outcome.is_allow_shape(),
        "DCG_PACKS=core.git must not block filesystem commands under Claude\n{outcome}"
    );
}

#[test]
fn packs_core_git_still_blocks_git_destructive_codex() {
    // core.git is explicitly enabled → git destructive commands still blocked
    let outcome =
        run_codex_hook_with_env("git reset --hard HEAD~1", &[("DCG_PACKS", "core.git")], &[]);
    assert_eq!(
        outcome.exit_code, 2,
        "DCG_PACKS=core.git must still block git reset under Codex\n{outcome}"
    );
}

#[test]
fn packs_core_git_still_blocks_git_destructive_claude() {
    let outcome =
        run_claude_hook_with_env("git reset --hard HEAD~1", &[("DCG_PACKS", "core.git")], &[]);
    assert!(
        outcome.is_claude_block_shape(),
        "DCG_PACKS=core.git must still block git reset under Claude\n{outcome}"
    );
}

// ---------------------------------------------------------------------------
// P2.13.4 — DCG_DISABLE does not affect unrelated packs
// ---------------------------------------------------------------------------

#[test]
fn disable_core_filesystem_still_blocks_git_codex() {
    let outcome = run_codex_hook_with_env(
        "git reset --hard HEAD~1",
        &[("DCG_DISABLE", "core.filesystem")],
        &[],
    );
    assert_eq!(
        outcome.exit_code, 2,
        "DCG_DISABLE=core.filesystem must NOT affect git blocks under Codex\n{outcome}"
    );
}

#[test]
fn disable_core_filesystem_still_blocks_git_claude() {
    let outcome = run_claude_hook_with_env(
        "git reset --hard HEAD~1",
        &[("DCG_DISABLE", "core.filesystem")],
        &[],
    );
    assert!(
        outcome.is_claude_block_shape(),
        "DCG_DISABLE=core.filesystem must NOT affect git blocks under Claude\n{outcome}"
    );
}

// ===========================================================================
// P2.11 — Allow-once round-trip under Codex
//
// Under Codex, the model-visible stderr denial must not expose allow-once
// tokens. The pending store still records the generated code so a human or
// harness can redeem it explicitly, then retry — the command must pass.
// ===========================================================================

/// Extract the allow-once short_code from the pending_exceptions.jsonl
/// in the hermetic HOME directory.
fn extract_allow_once_code_from_pending_store(home: &std::path::Path) -> Option<String> {
    let pending_path = home.join(".config/dcg/pending_exceptions.jsonl");
    let content = std::fs::read_to_string(&pending_path).ok()?;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(code) = val["short_code"].as_str() {
                if code.len() >= 5 {
                    return Some(code.to_string());
                }
            }
        }
    }
    None
}

#[test]
fn codex_deny_creates_pending_exception_with_code() {
    // Use a persistent HOME (not run_codex_hook, which cleans up its tempdir)
    let home = tempfile::tempdir().expect("tempdir");
    let home_path = home.path().to_path_buf();
    let system_path = std::env::var("PATH").unwrap_or_default();

    let payload = build_codex_payload("git reset --hard HEAD~1");
    let mut cmd = Command::new(dcg_binary());
    cmd.env_clear()
        .env("PATH", &system_path)
        .env("HOME", &home_path)
        .env("TMPDIR", home_path.join("tmp"))
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn");
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(payload.as_bytes()).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    let outcome = HookOutcome {
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: output.status.code().unwrap_or(-1),
        stdin_sent: payload.into_bytes(),
        home_dir: home_path.clone(),
    };

    assert!(outcome.is_codex_block_shape(), "block expected\n{outcome}");

    let code = extract_allow_once_code_from_pending_store(&home_path);
    assert!(
        code.is_some(),
        "Codex deny must create a pending exception with short_code\n{outcome}"
    );
    assert!(
        code.as_ref().unwrap().len() >= 5,
        "short_code must be >= 5 chars, got {:?}\n{outcome}",
        code
    );
}

#[test]
fn codex_allow_once_round_trip() {
    let home = tempfile::tempdir().expect("tempdir");
    let home_path = home.path().to_path_buf();
    let system_path = std::env::var("PATH").unwrap_or_default();

    // Step 1: Codex deny — creates pending exception in hermetic HOME
    let deny_payload = build_codex_payload("git reset --hard HEAD~1");
    let mut cmd = Command::new(dcg_binary());
    cmd.env_clear()
        .env("PATH", &system_path)
        .env("HOME", &home_path)
        .env("TMPDIR", home_path.join("tmp"))
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn deny");
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(deny_payload.as_bytes()).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    let deny_outcome = HookOutcome {
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: output.status.code().unwrap_or(-1),
        stdin_sent: deny_payload.into_bytes(),
        home_dir: home_path.clone(),
    };

    assert!(
        deny_outcome.is_codex_block_shape(),
        "initial Codex deny expected\n{deny_outcome}"
    );

    // Extract the allow-once code from the pending store
    let allow_code = extract_allow_once_code_from_pending_store(&home_path)
        .unwrap_or_else(|| panic!("pending store must contain short_code\n{deny_outcome}"));

    // Step 2: Redeem the allow-once code
    let redeem_output = Command::new(dcg_binary())
        .arg("allow-once")
        .arg(&allow_code)
        .arg("--yes")
        .env_clear()
        .env("PATH", &system_path)
        .env("HOME", &home_path)
        .env("TMPDIR", home_path.join("tmp"))
        .env("NO_COLOR", "1")
        .output()
        .expect("failed to run allow-once redeem");

    assert!(
        redeem_output.status.success(),
        "allow-once redeem must succeed (exit 0), got exit {}\nstdout: {}\nstderr: {}",
        redeem_output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&redeem_output.stdout),
        String::from_utf8_lossy(&redeem_output.stderr),
    );

    // Step 3: Retry under Codex — must now be allowed (exit 0)
    let retry_payload = build_codex_payload("git reset --hard HEAD~1");
    let mut cmd = Command::new(dcg_binary());
    cmd.env_clear()
        .env("PATH", &system_path)
        .env("HOME", &home_path)
        .env("TMPDIR", home_path.join("tmp"))
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn retry");
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(retry_payload.as_bytes()).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    let retry_outcome = HookOutcome {
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: output.status.code().unwrap_or(-1),
        stdin_sent: retry_payload.into_bytes(),
        home_dir: home_path.clone(),
    };

    assert!(
        retry_outcome.is_allow_shape(),
        "after allow-once redeem, Codex retry must be allowed (exit 0)\n{retry_outcome}"
    );
}

// ===========================================================================
// P2.12 — Allowlist precedence under Codex (user tier)
//
// Verifies that allowlist entries produce silent allow (exit 0) under both
// protocols. Uses the user-tier allowlist at $HOME/.config/dcg/allowlist.toml
// since project-tier requires a .git root at CWD (not guaranteed in hermetic
// tests) and system-tier requires /etc (not writable).
// ===========================================================================

/// Helper: spawn dcg with a hermetic HOME that has an allowlist.toml.
fn run_with_user_allowlist(allowlist_toml: &str, command: &str, use_codex: bool) -> HookOutcome {
    let home = tempfile::tempdir().expect("tempdir");
    let config_dir = home.path().join(".config/dcg");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(config_dir.join("allowlist.toml"), allowlist_toml.as_bytes()).unwrap();

    let payload = if use_codex {
        build_codex_payload(command)
    } else {
        build_claude_payload(command)
    };
    let system_path = std::env::var("PATH").unwrap_or_default();

    let mut cmd = Command::new(dcg_binary());
    cmd.env_clear()
        .env("PATH", &system_path)
        .env("HOME", home.path())
        .env("TMPDIR", home.path().join("tmp"))
        .env("NO_COLOR", "1")
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn");
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(payload.as_bytes()).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    HookOutcome {
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: output.status.code().unwrap_or(-1),
        stdin_sent: payload.into_bytes(),
        home_dir: home.path().to_path_buf(),
    }
}

#[test]
fn allowlist_user_rule_allows_codex() {
    let allowlist = r#"
[[allow]]
rule = "core.git:reset-hard"
reason = "Team accepts this risk in CI"
"#;
    let outcome = run_with_user_allowlist(allowlist, "git reset --hard HEAD~1", true);
    assert!(
        outcome.is_allow_shape(),
        "user allowlist rule must produce silent allow under Codex\n{outcome}"
    );
}

#[test]
fn allowlist_user_rule_allows_claude() {
    let allowlist = r#"
[[allow]]
rule = "core.git:reset-hard"
reason = "Team accepts this risk in CI"
"#;
    let outcome = run_with_user_allowlist(allowlist, "git reset --hard HEAD~1", false);
    assert!(
        outcome.is_allow_shape(),
        "user allowlist rule must produce silent allow under Claude\n{outcome}"
    );
}

#[test]
fn allowlist_exact_command_allows_codex() {
    let allowlist = r#"
[[allow]]
exact_command = "git clean -fd"
reason = "Build script cleanup"
"#;
    let outcome = run_with_user_allowlist(allowlist, "git clean -fd", true);
    assert!(
        outcome.is_allow_shape(),
        "exact_command allowlist must produce silent allow under Codex\n{outcome}"
    );
}

#[test]
fn allowlist_exact_command_allows_claude() {
    let allowlist = r#"
[[allow]]
exact_command = "git clean -fd"
reason = "Build script cleanup"
"#;
    let outcome = run_with_user_allowlist(allowlist, "git clean -fd", false);
    assert!(
        outcome.is_allow_shape(),
        "exact_command allowlist must produce silent allow under Claude\n{outcome}"
    );
}

#[test]
fn allowlist_does_not_affect_unrelated_commands_codex() {
    let allowlist = r#"
[[allow]]
rule = "core.git:reset-hard"
reason = "Only allow reset-hard"
"#;
    // git clean -fd is NOT in the allowlist → should still be blocked
    let outcome = run_with_user_allowlist(allowlist, "git clean -fd", true);
    assert_eq!(
        outcome.exit_code, 2,
        "non-allowlisted command must still be blocked under Codex\n{outcome}"
    );
}

#[test]
fn allowlist_does_not_affect_unrelated_commands_claude() {
    let allowlist = r#"
[[allow]]
rule = "core.git:reset-hard"
reason = "Only allow reset-hard"
"#;
    let outcome = run_with_user_allowlist(allowlist, "git clean -fd", false);
    assert!(
        outcome.is_claude_block_shape(),
        "non-allowlisted command must still be blocked under Claude\n{outcome}"
    );
}

#[test]
fn allowlist_empty_file_still_blocks_codex() {
    let outcome = run_with_user_allowlist("", "git reset --hard HEAD~1", true);
    assert_eq!(
        outcome.exit_code, 2,
        "empty allowlist must still block under Codex\n{outcome}"
    );
}

#[test]
fn allowlist_cross_protocol_parity() {
    let allowlist = r#"
[[allow]]
rule = "core.git:reset-hard"
reason = "Accepted risk"
"#;
    let codex = run_with_user_allowlist(allowlist, "git reset --hard HEAD~1", true);
    let claude = run_with_user_allowlist(allowlist, "git reset --hard HEAD~1", false);

    assert!(codex.is_allow_shape(), "Codex must allow\n{codex}");
    assert!(claude.is_allow_shape(), "Claude must allow\n{claude}");
}

// ===========================================================================
// P2.6 — History entry persists across Codex's process::exit(2)
//
// The fix at src/main.rs:653-655 calls writer.flush_sync() before
// process::exit(2). Without that flush, the async HistoryWriter's worker
// thread gets killed by libc::exit and the deny entry is lost.
// ===========================================================================

#[test]
fn codex_deny_writes_history_entry_despite_exit_2() {
    let home = tempfile::tempdir().expect("tempdir");
    let db_path = home.path().join("codex-history.db");

    let config_dir = home.path().join(".config/dcg");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("config.toml"),
        b"[history]\nenabled = true\n",
    )
    .unwrap();

    let payload = build_codex_payload("git reset --hard HEAD~1");
    let system_path = std::env::var("PATH").unwrap_or_default();

    let mut cmd = Command::new(dcg_binary());
    cmd.env_clear()
        .env("PATH", &system_path)
        .env("HOME", home.path())
        .env("TMPDIR", home.path().join("tmp"))
        .env("NO_COLOR", "1")
        .env("DCG_HISTORY_DB", &db_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn");
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(payload.as_bytes()).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    let outcome = HookOutcome {
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: output.status.code().unwrap_or(-1),
        stdin_sent: payload.into_bytes(),
        home_dir: home.path().to_path_buf(),
    };

    assert_eq!(outcome.exit_code, 2, "Codex deny must exit 2\n{outcome}");

    // Despite process::exit(2), flush_sync() runs first → DB exists with data.
    // fsqlite/sqlite page size is 4096; a newly-created DB with schema + one row
    // may be exactly 4096 bytes (one page).
    assert!(
        db_path.exists(),
        "history DB must exist after Codex deny (flush_sync before exit 2)\n{outcome}"
    );
    let db_size = std::fs::metadata(&db_path).expect("stat history DB").len();
    assert!(
        db_size >= 4096,
        "history DB must contain at least one page (>= 4096 bytes), got {db_size}\n{outcome}"
    );
}

#[test]
fn codex_deny_with_history_disabled_still_exits_2() {
    let home = tempfile::tempdir().expect("tempdir");
    let config_dir = home.path().join(".config/dcg");
    std::fs::create_dir_all(&config_dir).unwrap();
    // Explicitly disable history
    std::fs::write(
        config_dir.join("config.toml"),
        b"[history]\nenabled = false\n",
    )
    .unwrap();

    let payload = build_codex_payload("git reset --hard HEAD~1");
    let system_path = std::env::var("PATH").unwrap_or_default();

    let mut cmd = Command::new(dcg_binary());
    cmd.env_clear()
        .env("PATH", &system_path)
        .env("HOME", home.path())
        .env("TMPDIR", home.path().join("tmp"))
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn");
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(payload.as_bytes()).unwrap();
    }
    let output = child.wait_with_output().unwrap();

    assert_eq!(
        output.status.code().unwrap_or(-1),
        2,
        "Codex deny must still exit 2 with history disabled"
    );
    assert!(
        output.stdout.is_empty(),
        "Codex deny must produce no stdout with history disabled"
    );
    assert!(
        !output.stderr.is_empty(),
        "Codex deny must still produce stderr with history disabled"
    );

    // No history DB should be created
    let default_db = home.path().join(".config/dcg/history.db");
    assert!(
        !default_db.exists(),
        "no history DB should be created when history is disabled"
    );
}

#[test]
fn codex_rapid_fire_denies_all_persist_to_history() {
    let home = tempfile::tempdir().expect("tempdir");
    let db_path = home.path().join("rapid-history.db");

    let config_dir = home.path().join(".config/dcg");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("config.toml"),
        b"[history]\nenabled = true\n",
    )
    .unwrap();

    let system_path = std::env::var("PATH").unwrap_or_default();
    let commands = [
        "git reset --hard HEAD~1",
        "git reset --hard HEAD~2",
        "git clean -fd",
        "git push --force origin main",
        "git reset --hard HEAD~3",
    ];

    // Sequential rapid-fire: 5 Codex denies, each process::exit(2)
    for cmd in &commands {
        let payload = build_codex_payload(cmd);
        let mut child = Command::new(dcg_binary())
            .env_clear()
            .env("PATH", &system_path)
            .env("HOME", home.path())
            .env("TMPDIR", home.path().join("tmp"))
            .env("NO_COLOR", "1")
            .env("DCG_HISTORY_DB", &db_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn");

        {
            let stdin = child.stdin.as_mut().unwrap();
            stdin.write_all(payload.as_bytes()).unwrap();
        }
        let output = child.wait_with_output().unwrap();
        assert_eq!(
            output.status.code().unwrap_or(-1),
            2,
            "Codex deny must exit 2 for '{cmd}'"
        );
    }

    // All 5 entries should have been flushed before their respective exit(2)
    assert!(
        db_path.exists(),
        "history DB must exist after 5 rapid-fire Codex denies"
    );
    let db_size = std::fs::metadata(&db_path).expect("stat history DB").len();
    // With 5 entries, the DB should be at least one page (4096 bytes)
    assert!(
        db_size >= 4096,
        "history DB with 5 entries must be >= 4096 bytes, got {db_size}"
    );
}

#[test]
fn codex_deny_history_write_protected_dir_no_panic() {
    let home = tempfile::tempdir().expect("tempdir");
    let config_dir = home.path().join(".config/dcg");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("config.toml"),
        b"[history]\nenabled = true\n",
    )
    .unwrap();

    // Point DCG_HISTORY_DB at a path inside a read-only directory
    let readonly_dir = home.path().join("readonly");
    std::fs::create_dir_all(&readonly_dir).unwrap();
    let db_path = readonly_dir.join("history.db");
    // Make the directory read-only so DB creation fails
    let mut perms = std::fs::metadata(&readonly_dir).unwrap().permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&readonly_dir, perms.clone()).unwrap();

    let payload = build_codex_payload("git reset --hard HEAD~1");
    let system_path = std::env::var("PATH").unwrap_or_default();

    let mut cmd = Command::new(dcg_binary());
    cmd.env_clear()
        .env("PATH", &system_path)
        .env("HOME", home.path())
        .env("TMPDIR", home.path().join("tmp"))
        .env("NO_COLOR", "1")
        .env("DCG_HISTORY_DB", &db_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn");
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(payload.as_bytes()).unwrap();
    }
    let output = child.wait_with_output().unwrap();

    // Must still exit 2 (deny works even if history fails)
    assert_eq!(
        output.status.code().unwrap_or(-1),
        2,
        "Codex deny must exit 2 even when history DB creation fails"
    );
    assert!(
        !output.stderr.is_empty(),
        "Codex deny must produce stderr even when history fails"
    );
    // Must not contain panic
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("panicked at"),
        "must not panic when history write fails\nstderr: {stderr}"
    );

    // Restore permissions for cleanup.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(perms.mode() | 0o700);
    }
    #[cfg(not(unix))]
    {
        perms.set_readonly(false);
    }
    std::fs::set_permissions(&readonly_dir, perms).unwrap();
}

// ===========================================================================
// Hermetic HOME isolation + P2.14 Parallel test runner isolation
//
// Meta-tests that validate the test infrastructure itself. Without these,
// a subtle mistake in hermetic HOME helpers could cause flaky failures only
// on multi-core CI runners.
// ===========================================================================

#[test]
fn smoke_hermetic_home_isolates_pending_exceptions() {
    let outcome = run_codex_hook("git reset --hard HEAD~1");
    assert!(outcome.is_codex_block_shape(), "block expected\n{outcome}");

    let pending_dir = outcome.home_dir.join(".config/dcg/pending");
    if pending_dir.exists() {
        let entries: Vec<_> = std::fs::read_dir(&pending_dir)
            .expect("failed to read pending dir")
            .collect();
        assert!(
            !entries.is_empty(),
            "pending dir exists but is empty — expected pending exception entry"
        );
    }
    if let Ok(real_home) = std::env::var("HOME") {
        assert_ne!(
            PathBuf::from(&real_home),
            outcome.home_dir,
            "hermetic HOME must differ from real HOME"
        );
    }
}

// ---------------------------------------------------------------------------
// P2.14.1 — Spawn-storm: 16 parallel Codex denies, each isolated
// ---------------------------------------------------------------------------

#[test]
#[allow(clippy::needless_collect)]
fn parallel_spawn_storm_no_cross_contamination() {
    let n = 16;
    let outcomes: Vec<HookOutcome> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..n)
            .map(|_| s.spawn(|| run_codex_hook("git reset --hard HEAD~1")))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    // All N must be Codex block shape
    for (i, o) in outcomes.iter().enumerate() {
        assert!(
            o.is_codex_block_shape(),
            "spawn {i}: expected Codex block shape\n{o}"
        );
    }

    // All N must have DISTINCT hermetic HOMEs
    let homes: std::collections::HashSet<_> = outcomes.iter().map(|o| o.home_dir.clone()).collect();
    assert_eq!(
        homes.len(),
        n,
        "all {n} spawns must use distinct hermetic HOMEs, got {} unique",
        homes.len()
    );

    // Each pending store (if present) must have exactly 1 entry
    for (i, o) in outcomes.iter().enumerate() {
        let pending_dir = o.home_dir.join(".config/dcg/pending");
        if pending_dir.exists() {
            let entries: Vec<_> = std::fs::read_dir(&pending_dir)
                .expect("read pending dir")
                .filter_map(std::result::Result::ok)
                .collect();
            assert_eq!(
                entries.len(),
                1,
                "spawn {i}: pending dir must have exactly 1 entry, found {}",
                entries.len()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// P2.14.2 — Sequential vs parallel equivalence
// ---------------------------------------------------------------------------

#[test]
#[allow(clippy::needless_collect)]
fn sequential_vs_parallel_produce_same_exit_codes() {
    let cmd = "git clean -fd";
    let n = 8;

    // Sequential
    let seq_codes: Vec<i32> = (0..n).map(|_| run_codex_hook(cmd).exit_code).collect();

    // Parallel
    let par_codes: Vec<i32> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..n)
            .map(|_| s.spawn(|| run_codex_hook(cmd).exit_code))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    // All must be identical (exit 2 for destructive command)
    for code in &seq_codes {
        assert_eq!(*code, 2, "sequential run must exit 2");
    }
    for code in &par_codes {
        assert_eq!(*code, 2, "parallel run must exit 2");
    }
}

// ---------------------------------------------------------------------------
// P2.14.3 — Real HOME not touched by hermetic tests
// ---------------------------------------------------------------------------

#[test]
fn hermetic_tests_do_not_touch_real_home() {
    let real_home = match std::env::var("HOME") {
        Ok(h) => PathBuf::from(h),
        Err(_) => return, // skip if no real HOME
    };
    let real_pending = real_home.join(".config/dcg/pending");

    // Record mtime before (if dir exists)
    let mtime_before = std::fs::metadata(&real_pending)
        .ok()
        .and_then(|m| m.modified().ok());

    // Run a deny that writes to pending store
    let outcome = run_codex_hook("git reset --hard HEAD~1");
    assert!(outcome.is_codex_block_shape());
    assert_ne!(outcome.home_dir, real_home);

    // Verify mtime unchanged
    let mtime_after = std::fs::metadata(&real_pending)
        .ok()
        .and_then(|m| m.modified().ok());
    assert_eq!(
        mtime_before, mtime_after,
        "real HOME pending dir mtime must not change during hermetic test"
    );
}

// ---------------------------------------------------------------------------
// P2.14.4 — Mixed protocol parallel: Codex + Claude in same storm
// ---------------------------------------------------------------------------

#[test]
#[allow(clippy::needless_collect)]
fn parallel_mixed_protocol_storm() {
    let n = 8; // 8 Codex + 8 Claude = 16 total
    let cmd = "git reset --hard HEAD~1";

    let (codex_outcomes, claude_outcomes): (Vec<HookOutcome>, Vec<HookOutcome>) =
        std::thread::scope(|s| {
            let codex_handles: Vec<_> = (0..n).map(|_| s.spawn(|| run_codex_hook(cmd))).collect();
            let claude_handles: Vec<_> = (0..n).map(|_| s.spawn(|| run_claude_hook(cmd))).collect();

            let codex: Vec<_> = codex_handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect();
            let claude: Vec<_> = claude_handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect();
            (codex, claude)
        });

    for (i, o) in codex_outcomes.iter().enumerate() {
        assert!(
            o.is_codex_block_shape(),
            "parallel Codex {i}: expected block shape\n{o}"
        );
    }
    for (i, o) in claude_outcomes.iter().enumerate() {
        assert!(
            o.is_claude_block_shape(),
            "parallel Claude {i}: expected block shape\n{o}"
        );
    }

    // All 16 homes must be distinct
    let all_homes: std::collections::HashSet<_> = codex_outcomes
        .iter()
        .chain(claude_outcomes.iter())
        .map(|o| o.home_dir.clone())
        .collect();
    assert_eq!(
        all_homes.len(),
        n * 2,
        "all 16 spawns must use distinct HOMEs, got {} unique",
        all_homes.len()
    );
}

// ==========================================================================
// P2.8: Heredoc-extracted destructive command blocked under Codex
//
// Proves dcg's Tier 3 heredoc/inline-script analysis works identically under
// the Codex output path (exit 2 + stderr) as under Claude (exit 0 + JSON).
// ==========================================================================

/// Build a Codex payload with proper JSON escaping for commands containing newlines.
fn build_codex_payload_raw(command: &str) -> String {
    let escaped = command
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");
    format!(
        r#"{{"session_id":"s","turn_id":"turn-test-1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{{"command":"{escaped}"}},"tool_use_id":"call_test"}}"#
    )
}

/// Build a Claude payload with proper JSON escaping for commands containing newlines.
fn build_claude_payload_raw(command: &str) -> String {
    let escaped = command
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");
    format!(
        r#"{{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{{"command":"{escaped}"}},"tool_use_id":"toolu_01TEST"}}"#
    )
}

/// Run dcg with a Codex payload for a command that may contain newlines.
fn run_codex_heredoc(command: &str) -> HookOutcome {
    let payload = build_codex_payload_raw(command);
    run_hook_raw(payload.as_bytes(), &[])
}

/// Run dcg with a Claude payload for a command that may contain newlines.
fn run_claude_heredoc(command: &str) -> HookOutcome {
    let payload = build_claude_payload_raw(command);
    run_hook_raw(payload.as_bytes(), &[])
}

#[test]
fn heredoc_python_shutil_rmtree_codex_deny() {
    let cmd = r#"python3 -c "import shutil; shutil.rmtree('/tmp/data')""#;
    let o = run_codex_hook(cmd);
    assert!(
        o.is_codex_block_shape(),
        "python shutil.rmtree should be blocked under Codex\n{o}"
    );
    assert!(
        o.stderr_contains("heredoc.python"),
        "stderr should mention heredoc.python pack\n{o}"
    );
    assert!(
        o.stderr_contains("shutil_rmtree"),
        "stderr should mention shutil_rmtree pattern\n{o}"
    );
}

#[test]
fn heredoc_python_shutil_rmtree_claude_deny() {
    let cmd = r#"python3 -c "import shutil; shutil.rmtree('/tmp/data')""#;
    let o = run_claude_hook(cmd);
    assert!(
        o.is_claude_block_shape(),
        "python shutil.rmtree should be blocked under Claude\n{o}"
    );
    let json = o.stdout_json();
    let rule_id = json["hookSpecificOutput"]["ruleId"].as_str().unwrap_or("");
    assert_eq!(
        rule_id, "heredoc.python:shutil_rmtree",
        "ruleId should be heredoc.python:shutil_rmtree\n{o}"
    );
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny"),
        "permissionDecision should be deny\n{o}"
    );
    assert_eq!(
        json["hookSpecificOutput"]["packId"].as_str(),
        Some("heredoc.python"),
        "packId should be heredoc.python\n{o}"
    );
}

#[test]
fn heredoc_javascript_fs_rmsync_codex_deny() {
    let cmd = "node <<EOF\nconst fs = require('fs');\nfs.rmSync('/etc', { recursive: true });\nEOF";
    let o = run_codex_heredoc(cmd);
    assert!(
        o.is_codex_block_shape(),
        "node fs.rmSync heredoc should be blocked under Codex\n{o}"
    );
    assert!(
        o.stderr_contains("heredoc.javascript"),
        "stderr should mention heredoc.javascript pack\n{o}"
    );
    assert!(
        o.stderr_contains("fs_rmsync"),
        "stderr should mention fs_rmsync pattern\n{o}"
    );
}

#[test]
fn heredoc_javascript_fs_rmsync_claude_deny() {
    let cmd = "node <<EOF\nconst fs = require('fs');\nfs.rmSync('/etc', { recursive: true });\nEOF";
    let o = run_claude_heredoc(cmd);
    assert!(
        o.is_claude_block_shape(),
        "node fs.rmSync heredoc should be blocked under Claude\n{o}"
    );
    let json = o.stdout_json();
    let rule_id = json["hookSpecificOutput"]["ruleId"].as_str().unwrap_or("");
    assert!(
        rule_id.starts_with("heredoc.javascript:fs_rmsync"),
        "ruleId should start with heredoc.javascript:fs_rmsync, got: {rule_id}\n{o}"
    );
    assert_eq!(
        json["hookSpecificOutput"]["packId"].as_str(),
        Some("heredoc.javascript"),
        "packId should be heredoc.javascript\n{o}"
    );
}

#[test]
fn heredoc_python_cross_protocol_parity() {
    let cmd = r#"python3 -c "import shutil; shutil.rmtree('/tmp/data')""#;
    let codex = run_codex_hook(cmd);
    let claude = run_claude_hook(cmd);

    assert!(codex.is_codex_block_shape(), "Codex must block\n{codex}");
    assert!(
        claude.is_claude_block_shape(),
        "Claude must block\n{claude}"
    );

    let json = claude.stdout_json();
    let claude_rule = json["hookSpecificOutput"]["ruleId"].as_str().unwrap_or("");
    let claude_pack = json["hookSpecificOutput"]["packId"].as_str().unwrap_or("");

    assert!(
        codex.stderr_contains(claude_pack),
        "Codex stderr must mention same pack '{claude_pack}' as Claude JSON\n\
         Codex stderr: {}\nClaude JSON: {}",
        codex.stderr_str(),
        claude.stdout_str()
    );
    let pattern_part = claude_rule.split(':').next_back().unwrap_or("");
    assert!(
        codex.stderr_contains(pattern_part),
        "Codex stderr must mention same pattern '{pattern_part}' from Claude ruleId '{claude_rule}'\n\
         Codex stderr: {}",
        codex.stderr_str()
    );
}

#[test]
fn heredoc_javascript_cross_protocol_parity() {
    let cmd = "node <<EOF\nconst fs = require('fs');\nfs.rmSync('/etc', { recursive: true });\nEOF";
    let codex = run_codex_heredoc(cmd);
    let claude = run_claude_heredoc(cmd);

    assert!(codex.is_codex_block_shape(), "Codex must block\n{codex}");
    assert!(
        claude.is_claude_block_shape(),
        "Claude must block\n{claude}"
    );

    let json = claude.stdout_json();
    let claude_pack = json["hookSpecificOutput"]["packId"].as_str().unwrap_or("");

    assert!(
        codex.stderr_contains(claude_pack),
        "Codex stderr must mention same pack '{claude_pack}' as Claude JSON\n\
         Codex stderr: {}\nClaude JSON: {}",
        codex.stderr_str(),
        claude.stdout_str()
    );
}

#[test]
fn heredoc_node_inline_exec_codex_deny() {
    let cmd = r#"node -e "require('child_process').execSync('rm -rf /')""#;
    let o = run_codex_hook(cmd);
    assert!(
        o.is_codex_block_shape(),
        "node -e with child_process execSync should be blocked under Codex\n{o}"
    );
    assert!(
        o.stderr_contains("heredoc."),
        "stderr should mention a heredoc pack\n{o}"
    );
}

#[test]
fn heredoc_safe_python_codex_allows() {
    let cmd = r#"python3 -c "print('hello world')""#;
    let o = run_codex_hook(cmd);
    assert!(
        o.is_allow_shape(),
        "safe python one-liner should be allowed\n{o}"
    );
}

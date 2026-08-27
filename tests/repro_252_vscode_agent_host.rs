//! Regression tests for issue #252: the VS Code "Agent Host" batched
//! `toolCalls` envelope.
//!
//! The newer Copilot Agent Host (and the Agents window built on it) sends
//! `{"sessionId": "...", "cwd": "...", "toolCalls": [{"name": "powershell",
//! "args": "{\"command\":\"...\"}"}]}` — an *array* under plural `toolCalls`,
//! with each entry's `args` JSON-encoded as a string. Before the fix the
//! envelope deserialized without any recognized command and the hook silently
//! failed open.
//!
//! Follow-up regressions covered here (v0.9.0 hardening):
//! - **Batch masking**: batch entries used to be joined with `"\n"` into one
//!   string, so an entry ending in an unterminated quote or a trailing
//!   backslash swallowed the following entry during tokenization and hid its
//!   destructive command (fail-open). Entries are now extracted and evaluated
//!   independently, each with its own dialect.
//! - **Parse abort**: a `toolCalls` value in a non-array shape used to abort
//!   the whole `HookInput` parse, failing open even though `tool_input`
//!   carried a perfectly parseable destructive command.
//! - **Entry gating**: nameless entries with args, agy's `run_command` name,
//!   and `CommandLine`-style args keys used to be skipped by the batch path
//!   even though the singular `toolCall` path accepted all three.

use destructive_command_guard::hook::{
    HookInput, HookProtocol, detect_protocol, extract_command_with_context,
};
use destructive_command_guard::normalize::ShellDialect;

fn parse(json: &str) -> HookInput {
    serde_json::from_str(json).expect("hook input must deserialize")
}

/// The documented envelope from issue #252, verbatim: stringified `args`
/// carrying a destructive PowerShell command.
const DOCUMENTED_ENVELOPE: &str = r#"{"sessionId":"s","cwd":"C:\\ws","toolCalls":[{"name":"powershell","args":"{\"command\":\"Remove-Item -Recurse -Force C:\\\\src\"}"}]}"#;

#[test]
fn documented_envelope_detects_claude_compatible() {
    let input = parse(DOCUMENTED_ENVELOPE);
    assert_eq!(detect_protocol(&input), HookProtocol::ClaudeCompatible);
}

#[test]
fn documented_envelope_extracts_inner_command_and_dialect() {
    let input = parse(DOCUMENTED_ENVELOPE);
    let extracted =
        extract_command_with_context(&input).expect("batched shell call must extract a command");
    assert_eq!(extracted.command, r"Remove-Item -Recurse -Force C:\src");
    assert_eq!(extracted.protocol, HookProtocol::ClaudeCompatible);
    assert_eq!(extracted.dialect, ShellDialect::PowerShell);
    assert!(
        extracted.additional_commands.is_empty(),
        "a single-entry batch has no additional commands"
    );
}

#[test]
fn stringified_and_object_args_both_extract() {
    let stringified = parse(
        r#"{"sessionId":"s","toolCalls":[{"name":"bash","args":"{\"command\":\"echo hi\"}"}]}"#,
    );
    let object =
        parse(r#"{"sessionId":"s","toolCalls":[{"name":"bash","args":{"command":"echo hi"}}]}"#);

    for input in [stringified, object] {
        let extracted = extract_command_with_context(&input)
            .expect("both args encodings must extract the command");
        assert_eq!(extracted.command, "echo hi");
        assert_eq!(extracted.dialect, ShellDialect::Posix);
    }
}

#[test]
fn batch_extracts_every_shell_call_as_separate_command() {
    // A non-shell tool call in the batch is skipped; both bash calls are
    // extracted as INDEPENDENT commands (never joined into one string, which
    // would let quoting in one entry mask the next) so the hook driver
    // evaluates each one and a single destructive entry denies the whole
    // batch.
    let input = parse(
        r#"{"sessionId":"s","cwd":"/w","toolCalls":[
            {"name":"readFile","args":{"path":"/w/a.txt"}},
            {"name":"bash","args":"{\"command\":\"echo one\"}"},
            {"name":"bash","args":{"command":"echo two"}}
        ]}"#,
    );
    let extracted =
        extract_command_with_context(&input).expect("batched bash calls must extract commands");
    assert_eq!(extracted.command, "echo one");
    assert_eq!(extracted.dialect, ShellDialect::Posix);
    assert_eq!(extracted.protocol, HookProtocol::ClaudeCompatible);
    assert_eq!(
        extracted.additional_commands,
        vec![("echo two".to_string(), ShellDialect::Posix)]
    );
}

#[test]
fn mixed_shell_batch_keeps_per_entry_dialects() {
    // Each batch entry keeps its OWN proven dialect. The old design joined
    // the commands and downgraded mixed batches to a single Unknown-dialect
    // string; per-entry evaluation makes that both unnecessary and wrong.
    let input = parse(
        r#"{"sessionId":"s","toolCalls":[
            {"name":"bash","args":{"command":"echo posix"}},
            {"name":"powershell","args":{"command":"Write-Output ps"}}
        ]}"#,
    );
    let extracted =
        extract_command_with_context(&input).expect("mixed batch must still extract commands");
    assert_eq!(extracted.command, "echo posix");
    assert_eq!(extracted.dialect, ShellDialect::Posix);
    assert_eq!(
        extracted.additional_commands,
        vec![("Write-Output ps".to_string(), ShellDialect::PowerShell)]
    );
}

// ---------------------------------------------------------------------------
// Bug 1 (batch masking): unit-level extraction assertions
// ---------------------------------------------------------------------------

#[test]
fn unterminated_quote_entry_cannot_mask_the_next_entry() {
    // Entry one ends in an unterminated double quote. Joined with "\n" the
    // quote absorbed entry two, so `rm -rf /` was never seen as a command of
    // its own and the batch was allowed. Per-entry extraction must yield two
    // separate commands.
    let input = parse(
        r#"{"sessionId":"s","cwd":"/w","toolCalls":[
            {"name":"bash","args":"{\"command\":\"echo \\\"start of a note\"}"},
            {"name":"bash","args":"{\"command\":\"rm -rf /\"}"}
        ]}"#,
    );
    let extracted = extract_command_with_context(&input).expect("batch must extract");
    assert_eq!(extracted.command, "echo \"start of a note");
    assert_eq!(
        extracted.additional_commands,
        vec![("rm -rf /".to_string(), ShellDialect::Posix)],
        "the destructive second entry must survive as its own command"
    );
}

#[test]
fn trailing_backslash_entry_cannot_mask_the_next_entry() {
    // Same masking mechanism via line continuation: a trailing backslash
    // would have glued the next joined line onto the first command.
    let input = parse(
        r#"{"sessionId":"s","toolCalls":[
            {"name":"bash","args":{"command":"echo continued \\"}},
            {"name":"bash","args":{"command":"rm -rf /"}}
        ]}"#,
    );
    let extracted = extract_command_with_context(&input).expect("batch must extract");
    assert_eq!(extracted.command, "echo continued \\");
    assert_eq!(
        extracted.additional_commands,
        vec![("rm -rf /".to_string(), ShellDialect::Posix)]
    );
}

// ---------------------------------------------------------------------------
// Bug 2 (typed field parse abort): tolerant `toolCalls` deserialization
// ---------------------------------------------------------------------------

#[test]
fn tool_calls_object_shape_still_denies_via_tool_input() {
    // `toolCalls` in a non-array shape must not abort the whole HookInput
    // parse: pre-v0.9.0 this payload denied via tool_input, and a parse abort
    // fails open.
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"},"toolCalls":{"0":{}}}"#;
    let input: HookInput =
        serde_json::from_str(json).expect("non-array toolCalls must not abort the parse");
    assert!(input.tool_calls.is_none());
    let extracted =
        extract_command_with_context(&input).expect("tool_input path must still extract");
    assert_eq!(extracted.command, "rm -rf /");
    assert_eq!(
        extracted.additional_commands,
        [] as [(
            std::string::String,
            destructive_command_guard::normalize::ShellDialect
        ); 0]
    );
}

#[test]
fn tool_calls_array_with_unfit_entries_keeps_the_fitting_ones() {
    let input = parse(
        r#"{"toolCalls":[42,"junk",{"name":"bash","args":{"command":"rm -rf /"}},{"name":7}]}"#,
    );
    let extracted =
        extract_command_with_context(&input).expect("the fitting entry must still extract");
    assert_eq!(extracted.command, "rm -rf /");
}

// ---------------------------------------------------------------------------
// Bug 3 (batch gating stricter than the singular path)
// ---------------------------------------------------------------------------

#[test]
fn nameless_batch_entry_with_args_extracts_its_command() {
    let input = parse(r#"{"toolCalls":[{"args":{"command":"rm -rf /"}}]}"#);
    let extracted = extract_command_with_context(&input)
        .expect("a nameless entry with args mirrors the singular toolCall posture");
    assert_eq!(extracted.command, "rm -rf /");
    assert_eq!(extracted.dialect, ShellDialect::Unknown);
}

#[test]
fn run_command_batch_entry_extracts_its_command() {
    // agy's shell tool name inside a batched entry.
    let input =
        parse(r#"{"toolCalls":[{"name":"run_command","args":{"CommandLine":"rm -rf /"}}]}"#);
    let extracted =
        extract_command_with_context(&input).expect("run_command entries must be evaluated");
    assert_eq!(extracted.command, "rm -rf /");
}

#[test]
fn command_line_style_args_keys_extract_in_batch_entries() {
    for key in ["CommandLine", "commandLine", "Command"] {
        let json = format!(
            r#"{{"toolCalls":[{{"name":"powershell","args":{{"{key}":"Remove-Item -Recurse -Force C:\\src"}}}}]}}"#
        );
        let input = parse(&json);
        let extracted = extract_command_with_context(&input)
            .unwrap_or_else(|| panic!("{key} args key must extract"));
        assert_eq!(extracted.command, r"Remove-Item -Recurse -Force C:\src");
        assert_eq!(extracted.dialect, ShellDialect::PowerShell);
    }
}

#[test]
fn tool_input_sibling_of_a_batch_is_appended_as_an_entry() {
    // Regression: extraction returned on the first batch command, so a
    // destructive `tool_input` in the same envelope was never evaluated.
    let input = parse(
        r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"},
            "toolCalls":[{"name":"bash","args":"{\"command\":\"ls -la\"}"}]}"#,
    );
    let extracted = extract_command_with_context(&input).expect("must extract");
    assert_eq!(extracted.command, "ls -la");
    assert_eq!(
        extracted.additional_commands,
        vec![("rm -rf /".to_string(), ShellDialect::Posix)]
    );
}

#[test]
fn tool_args_sibling_of_a_batch_is_appended_as_an_entry() {
    let input = parse(
        r#"{"toolName":"bash","toolArgs":"{\"command\":\"rm -rf /\"}",
            "toolCalls":[{"name":"bash","args":{"command":"ls -la"}}]}"#,
    );
    let extracted = extract_command_with_context(&input).expect("must extract");
    assert_eq!(extracted.command, "ls -la");
    assert_eq!(
        extracted.additional_commands,
        vec![("rm -rf /".to_string(), ShellDialect::Posix)]
    );
}

#[test]
fn non_shell_only_batch_does_not_hijack_another_agents_protocol() {
    // A `toolCalls` array carrying only non-shell entries is not proof of the
    // VS Code Agent Host; answering such a payload in Claude shape hands the
    // real agent a deny document its parser drops.
    let gemini = parse(
        r#"{"hook_event_name":"BeforeTool","tool_name":"run_shell_command",
            "tool_input":{"command":"rm -rf /"},
            "toolCalls":[{"name":"readFile","args":{"path":"/w/a.txt"}}]}"#,
    );
    assert_eq!(detect_protocol(&gemini), HookProtocol::Gemini);

    let hermes = parse(
        r#"{"hook_event_name":"pre_tool_call","tool_name":"terminal",
            "tool_input":{"command":"rm -rf /"},
            "toolCalls":[{"name":"readFile","args":{"path":"/w/a.txt"}}]}"#,
    );
    assert_eq!(detect_protocol(&hermes), HookProtocol::Hermes);

    let grok = parse(
        r#"{"hookEventName":"pre_tool_use","toolName":"run_terminal_cmd",
            "toolInput":{"command":"rm -rf /"},
            "toolCalls":[{"name":"readFile","args":{"path":"/w/a.txt"}}]}"#,
    );
    assert_eq!(detect_protocol(&grok), HookProtocol::Grok);

    let codex = parse(
        r#"{"hook_event_name":"PreToolUse","tool_name":"bash","turn_id":"turn-1",
            "tool_input":{"command":"rm -rf /"},
            "toolCalls":[{"name":"readFile","args":{"path":"/w/a.txt"}}]}"#,
    );
    assert_eq!(detect_protocol(&codex), HookProtocol::Codex);

    // A batch that does contain a shell entry still identifies the Agent Host.
    let shell_batch = parse(
        r#"{"sessionId":"s","toolCalls":[
            {"name":"readFile","args":{"path":"/w/a.txt"}},
            {"name":"bash","args":{"command":"ls"}}
        ]}"#,
    );
    assert_eq!(
        detect_protocol(&shell_batch),
        HookProtocol::ClaudeCompatible
    );
}

#[test]
fn singular_tool_call_alongside_batch_is_appended_as_an_entry() {
    let input = parse(
        r#"{
            "toolCalls":[{"name":"bash","args":{"command":"git status"}}],
            "toolCall":{"name":"run_command","args":{"CommandLine":"rm -rf /"}}
        }"#,
    );
    let extracted = extract_command_with_context(&input).expect("must extract");
    assert_eq!(extracted.command, "git status");
    assert_eq!(
        extracted.additional_commands,
        vec![("rm -rf /".to_string(), ShellDialect::Unknown)],
        "the singular toolCall's command must also be evaluated"
    );
}

#[test]
fn empty_tool_calls_array_extracts_nothing_and_detection_falls_through() {
    // An empty batch alone: nothing to extract.
    let bare = parse(r#"{"sessionId":"s","toolCalls":[]}"#);
    assert_eq!(extract_command_with_context(&bare), None);

    // Detection must fall through to the pre-#252 logic: with Gemini's
    // markers alongside an empty `toolCalls`, the Gemini classification wins.
    let gemini_shaped = parse(
        r#"{"toolCalls":[],"session_id":"g","cwd":"/w","hook_event_name":"BeforeTool",
            "tool_name":"run_shell_command","tool_input":{"command":"echo hi"}}"#,
    );
    assert_eq!(detect_protocol(&gemini_shaped), HookProtocol::Gemini);
    let extracted = extract_command_with_context(&gemini_shaped)
        .expect("the old tool_input path must still extract");
    assert_eq!(extracted.command, "echo hi");
    assert_eq!(extracted.protocol, HookProtocol::Gemini);
}

#[test]
fn batch_without_shell_calls_extracts_nothing() {
    let input = parse(
        r#"{"sessionId":"s","toolCalls":[
            {"name":"readFile","args":{"path":"/w/a.txt"}},
            {"name":"editFile","args":"{\"path\":\"/w/b.txt\"}"}
        ]}"#,
    );
    // The plural-toolCalls envelope still identifies the Agent Host…
    assert_eq!(detect_protocol(&input), HookProtocol::ClaudeCompatible);
    // …but a batch with no shell tool is not a shell hook candidate.
    assert_eq!(extract_command_with_context(&input), None);
}

#[test]
fn singular_tool_call_envelope_still_detects_antigravity() {
    // The Antigravity CLI (`agy`) envelope uses singular `toolCall`; the new
    // plural `toolCalls` handling must not shadow it.
    let input = parse(
        r#"{"toolCall":{"name":"run_command","args":{"CommandLine":"git status","Cwd":"/w",
            "WaitMsBeforeAsync":500}},"conversationId":"c0","stepIdx":4}"#,
    );
    assert_eq!(detect_protocol(&input), HookProtocol::Antigravity);
    let extracted = extract_command_with_context(&input).expect("agy envelope must still extract");
    assert_eq!(extracted.command, "git status");
    assert_eq!(extracted.protocol, HookProtocol::Antigravity);
}

// ---------------------------------------------------------------------------
// Binary-level coverage: the real dcg hook denies destructive batches
// ---------------------------------------------------------------------------
//
// Bug 4 (the PA_PROJECT_DIR protocol misroute) is covered by inline unit
// tests in src/hook.rs: they need the crate-private ENV_LOCK / EnvVarGuard
// helpers, which are not visible from an integration test, and integration
// tests cannot mutate the environment safely (`std::env::set_var` is unsafe
// and racy under the parallel test runner).

/// Path to the dcg binary (same workspace-relative discovery as
/// tests/codex_hook_protocol.rs).
fn dcg_binary() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // test binary name
    path.pop(); // deps/
    path.push(format!("dcg{}", std::env::consts::EXE_SUFFIX));
    path
}

/// Spawn the real dcg binary in hook mode with a hermetic environment (plus
/// `extra_env`) and return its output. Isolated HOME/TMPDIR so parallel tests
/// never share history or pending-exception state (mirrors
/// codex_hook_protocol.rs).
fn run_hook_with_env(payload: &str, extra_env: &[(&str, &str)]) -> std::process::Output {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    let home = tempfile::tempdir().expect("failed to create hermetic HOME");
    let tmp = home.path().join("tmp");
    std::fs::create_dir_all(&tmp).expect("failed to create hermetic TMPDIR");
    let system_path = std::env::var("PATH").unwrap_or_default();

    let mut command = Command::new(dcg_binary());
    command
        .env_clear()
        .env("PATH", &system_path)
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env("TMPDIR", &tmp)
        .env("TEMP", &tmp)
        .env("TMP", &tmp)
        .env("NO_COLOR", "1")
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .env("DCG_HEREDOC_TIMEOUT_MS", "5000");
    for (key, value) in extra_env {
        command.env(key, value);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn dcg");

    child
        .stdin
        .as_mut()
        .expect("stdin must be piped")
        .write_all(payload.as_bytes())
        .expect("failed to write hook payload");
    child.wait_with_output().expect("failed to wait for dcg")
}

/// [`run_hook_with_env`] with no extra environment.
fn run_hook(payload: &str) -> std::process::Output {
    run_hook_with_env(payload, &[])
}

/// Assert a Claude-shaped deny on stdout with exit code 0.
fn assert_denied(output: &std::process::Output, context: &str) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{context}: Agent Host consumes Claude-shaped output; deny must use exit 0.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("\"permissionDecision\""),
        "{context}: deny must be a Claude-compatible stdout JSON payload.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("\"deny\""),
        "{context}: the destructive batch entry must deny the whole batch.\nstdout: {stdout}\nstderr: {stderr}"
    );
}

#[test]
fn destructive_bash_batch_is_denied_on_stdout_with_exit_zero() {
    let payload = r#"{"sessionId":"s","cwd":"/w","toolCalls":[
        {"name":"bash","args":"{\"command\":\"git status\"}"},
        {"name":"bash","args":"{\"command\":\"rm -rf /\"}"}
    ]}"#;
    assert_denied(&run_hook(payload), "benign-then-destructive batch");
}

#[test]
fn unterminated_quote_masking_batch_is_denied() {
    // Bug 1 end-to-end: the first entry's unterminated double quote used to
    // absorb the second entry after the "\n" join, so the destructive command
    // was never tokenized and the batch was ALLOWED.
    let payload = r#"{"sessionId":"s","cwd":"/w","toolCalls":[
        {"name":"bash","args":"{\"command\":\"echo \\\"start of a note\"}"},
        {"name":"bash","args":"{\"command\":\"rm -rf /\"}"}
    ]}"#;
    assert_denied(&run_hook(payload), "unterminated-quote masking batch");
}

#[test]
fn unterminated_quote_masking_batch_reversed_order_is_denied() {
    let payload = r#"{"sessionId":"s","cwd":"/w","toolCalls":[
        {"name":"bash","args":"{\"command\":\"rm -rf /\"}"},
        {"name":"bash","args":"{\"command\":\"echo \\\"start of a note\"}"}
    ]}"#;
    assert_denied(&run_hook(payload), "destructive-first masking batch");
}

#[test]
fn benign_batch_stays_silent_with_exit_zero() {
    let payload = r#"{"sessionId":"s","cwd":"/w","toolCalls":[
        {"name":"bash","args":"{\"command\":\"git status\"}"},
        {"name":"bash","args":"{\"command\":\"echo hi\"}"}
    ]}"#;
    let output = run_hook(payload);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "benign batch must exit 0.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.trim().is_empty(),
        "an all-allow batch must stay silent on stdout.\nstdout: {stdout}\nstderr: {stderr}"
    );
}

#[test]
fn tool_calls_object_shape_payload_is_denied_via_tool_input() {
    // Bug 2 end-to-end: this payload used to abort HookInput parsing and
    // fail open even though tool_input carried `rm -rf /`.
    let payload =
        r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"},"toolCalls":{"0":{}}}"#;
    assert_denied(&run_hook(payload), "toolCalls-as-object payload");
}

#[test]
fn tool_input_decoy_batch_is_denied_end_to_end() {
    // A benign batch entry must not answer for a destructive `tool_input`
    // sibling in the same envelope.
    let payload = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"},
        "toolCalls":[{"name":"bash","args":"{\"command\":\"ls -la\"}"}]}"#;
    assert_denied(&run_hook(payload), "tool_input decoy batch");
}

#[test]
fn tool_args_decoy_batch_is_denied_end_to_end() {
    let payload = r#"{"toolName":"bash","toolArgs":"{\"command\":\"rm -rf /\"}",
        "toolCalls":[{"name":"bash","args":{"command":"ls -la"}}]}"#;
    assert_denied(&run_hook(payload), "tool_args decoy batch");
}

#[test]
fn non_shell_only_batch_keeps_gemini_wire_shape_end_to_end() {
    // The deny must be Gemini's `{"decision":"deny",…}`; a Claude-shaped
    // answer would be dropped by Gemini's parser (silent fail-open).
    let payload = r#"{"session_id":"g","cwd":"/w","hook_event_name":"BeforeTool",
        "tool_name":"run_shell_command","tool_input":{"command":"rm -rf /"},
        "toolCalls":[{"name":"readFile","args":{"path":"/w/a.txt"}}]}"#;
    let output = run_hook(payload);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "Gemini deny uses exit 0.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("\"decision\":\"deny\""),
        "must keep Gemini's decision shape.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stdout.contains("hookSpecificOutput"),
        "must NOT be answered in Claude wire shape.\nstdout: {stdout}\nstderr: {stderr}"
    );
}

#[test]
fn oversized_primary_command_creates_no_history_database() {
    // The refusal must happen before the history writer exists: a payload dcg
    // declines to evaluate must not create the database, spawn the worker
    // thread, or install a shutdown handler.
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let config_path = dir.path().join("dcg-config.toml");
    std::fs::write(&config_path, "[general]\nmax_command_bytes = 64\n")
        .expect("failed to write DCG_CONFIG file");
    let config_arg = config_path.to_str().expect("utf-8 path").to_string();

    let oversized_db = dir.path().join("oversized-history.db");
    let payload = format!(
        r#"{{"tool_name":"Bash","tool_input":{{"command":"echo {}"}}}}"#,
        "a".repeat(120)
    );
    let output = run_hook_with_env(
        &payload,
        &[
            ("DCG_CONFIG", config_arg.as_str()),
            ("DCG_HISTORY_ENABLED", "true"),
            ("DCG_HISTORY_DB", oversized_db.to_str().expect("utf-8 path")),
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("exceeds limit"),
        "the oversized refusal must still be published.\nstdout: {stdout}"
    );
    assert!(
        !oversized_db.exists(),
        "an unevaluated oversized command must not create the history database"
    );

    // Control: an evaluated command with the same settings DOES create it,
    // proving the assertion above is meaningful rather than vacuous.
    let control_db = dir.path().join("control-history.db");
    let control = run_hook_with_env(
        r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#,
        &[
            ("DCG_CONFIG", config_arg.as_str()),
            ("DCG_HISTORY_ENABLED", "true"),
            ("DCG_HISTORY_DB", control_db.to_str().expect("utf-8 path")),
        ],
    );
    assert!(
        String::from_utf8_lossy(&control.stdout).contains("\"deny\""),
        "control payload must be denied"
    );
    assert!(
        control_db.exists(),
        "control: an evaluated command must create the history database"
    );
}

// ---------------------------------------------------------------------------
// Batch decisive-response precedence (Deny > Indeterminate > Ask > Warn >
// Log/Allow). Regression for the confirmed fail-open where a Warn-mode entry
// (core.git:stash-drop resolves to warn by default) answered the request
// immediately and later destructive entries were never evaluated.
// ---------------------------------------------------------------------------

#[test]
fn warn_entry_then_destructive_entry_batch_is_denied() {
    // Pre-fix behavior: the stash-drop warn ended the request (exit 0, warn
    // on stderr, empty stdout) and `rm -rf /` was silently allowed.
    let payload = r#"{"sessionId":"s","cwd":"/w","toolCalls":[
        {"name":"bash","args":"{\"command\":\"git stash drop\"}"},
        {"name":"bash","args":"{\"command\":\"rm -rf /\"}"}
    ]}"#;
    let output = run_hook(payload);
    assert_denied(&output, "warn-then-destructive batch");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("dcg WARNING:"),
        "exactly one response: the deny must not be accompanied by the \
         non-decisive warn.\nstderr: {stderr}"
    );
}

#[test]
fn destructive_entry_then_warn_entry_batch_is_denied() {
    let payload = r#"{"sessionId":"s","cwd":"/w","toolCalls":[
        {"name":"bash","args":"{\"command\":\"rm -rf /\"}"},
        {"name":"bash","args":"{\"command\":\"git stash drop\"}"}
    ]}"#;
    assert_denied(&run_hook(payload), "destructive-then-warn batch");
}

#[test]
fn all_warn_batch_emits_the_warn_response_exactly_once() {
    let payload = r#"{"sessionId":"s","cwd":"/w","toolCalls":[
        {"name":"bash","args":"{\"command\":\"git stash drop\"}"},
        {"name":"bash","args":"{\"command\":\"git stash drop stash@{1}\"}"}
    ]}"#;
    let output = run_hook(payload);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "warn is non-blocking; exit must be 0.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.trim().is_empty(),
        "Claude-shaped warn is stdout-silent (no blocking opinion).\nstdout: {stdout}"
    );
    assert_eq!(
        stderr.matches("dcg WARNING:").count(),
        1,
        "an all-warn batch must publish exactly one warn response.\nstderr: {stderr}"
    );
}

#[test]
fn indeterminate_entry_outranks_a_warn_entry() {
    // Entry 1 resolves to warn; entry 2 exceeds max_command_bytes (pinned
    // small via DCG_CONFIG) and cannot be evaluated. The indeterminate answer
    // must win over the warn — an unevaluated entry may hide anything, so a
    // conservative "ask" beats a non-blocking warn.
    let config_dir = tempfile::tempdir().expect("failed to create config dir");
    let config_path = config_dir.path().join("dcg-config.toml");
    std::fs::write(&config_path, "[general]\nmax_command_bytes = 64\n")
        .expect("failed to write DCG_CONFIG file");

    let long_arg = "a".repeat(80);
    let payload = format!(
        r#"{{"sessionId":"s","cwd":"/w","toolCalls":[
            {{"name":"bash","args":{{"command":"git stash drop"}}}},
            {{"name":"bash","args":{{"command":"echo {long_arg}"}}}}
        ]}}"#
    );
    let output = run_hook_with_env(
        &payload,
        &[("DCG_CONFIG", config_path.to_str().expect("utf-8 path"))],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "indeterminate answers use exit 0.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("\"permissionDecision\":\"ask\""),
        "the oversized entry must produce the conservative ask.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("exceeds limit"),
        "the indeterminate reason must name the size limit.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stderr.contains("dcg WARNING:"),
        "the non-decisive warn must not also be published.\nstderr: {stderr}"
    );
}

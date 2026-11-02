//! Regression tests for issue #412: a German commit message denied by the
//! `Bash` PreToolUse hook.
//!
//! ```text
//! git commit -q -m "$(cat <<'EOF'
//! „Messen"
//! Read-only
//! EOF
//! )"
//! ```
//!
//! Two innocuous properties combined. The German closing quotation mark is a
//! plain ASCII `"`, so the body carries an odd number of them; and `Read-only`
//! is an ordinary hyphenated word that looks like a PowerShell verb-noun.
//!
//! The chain: the unbalanced `"` inside `"$(…)"` stopped tree-sitter-bash
//! parsing the whole command; a parse error is answered fail-closed, which
//! suppressed masking of the heredoc body; the unmasked body was then read as
//! live command text, where `Read-only` down-trusted the `Bash` label to the
//! fail-closed dialect union, and the union denied the commit. The denial
//! carried no rule id, which is what made it so hard to diagnose.
//!
//! The body is a *quoted* heredoc: literal stdin data that no shell parses as
//! grammar. Its bytes therefore cannot rebind the receiving command's name, and
//! must not decide whether it is masked.

use std::io::Write;
use std::process::{Command, Stdio};

fn dcg_binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

fn run_hook(command: &str) -> std::process::Output {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })
    .to_string();

    let mut child = Command::new(dcg_binary())
        .arg("hook")
        .arg("--batch")
        .env_clear()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcg");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(payload.as_bytes())
        .expect("write payload");
    child.wait_with_output().expect("wait")
}

fn decision(command: &str) -> String {
    let out = run_hook(command);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout.lines().next().unwrap_or_default().to_string();
    let parsed: serde_json::Value =
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("bad batch output ({e}): {stdout}"));
    parsed
        .get("decision")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<missing>")
        .to_string()
}

/// The command exactly as reported.
const REPORTED: &str = "git commit -q -m \"$(cat <<'EOF'\n\u{201e}Messen\"\nRead-only\nEOF\n)\"";

#[test]
fn the_reported_commit_message_is_allowed() {
    assert_eq!(
        decision(REPORTED),
        "allow",
        "a quoted heredoc commit message is literal data, not PowerShell"
    );
}

#[test]
fn every_narrowing_case_from_the_report_is_allowed() {
    // The reporter's own table: an unbalanced `"` plus a verb-noun-shaped word
    // at the start of any line, in either order, and the hyphen-case variants.
    for body in [
        "a \" b\nRead-only",
        "a \" b\nGet-Help",
        "a \" b\nRemove-Item",
        "a \" b\nWrite-Output x",
        "a \" b\nread-only",
        "Read-only\na \" b",
        "a \" b\nFoo-Bar",
        "a \"b\" c\nRead-only",
        "a \" b Read-only",
        "a \" b",
        "Read-only",
    ] {
        let command = format!("git commit -q -m \"$(cat <<'EOF'\n{body}\nEOF\n)\"");
        assert_eq!(
            decision(&command),
            "allow",
            "commit message body must be data: {body:?}"
        );
    }
}

#[test]
fn the_other_reported_spellings_stay_allowed() {
    for command in [
        "git commit -q -F - <<'EOF'\na \" b\nRead-only\nEOF",
        "cat > msg.txt <<'EOF'\na \" b\nRead-only\nEOF",
        "git commit -q -m 'docs: \u{201e}Messen\" h\u{e4}lt' -m 'Read-only lesen'",
    ] {
        assert_eq!(decision(command), "allow", "{command:?}");
    }
}

/// The masking this fix restores must not hide a payload a shell would run.
#[test]
fn an_executing_heredoc_target_still_denies() {
    for command in [
        // A shell interpreter executes its body, quoted delimiter or not.
        "bash <<'SH'\nrm -rf /\nSH",
        "sh <<'SH'\ngit reset --hard\nSH",
        // A non-shell interpreter's body is still analyzed by the AST path.
        "python3 - <<'PY'\nimport shutil; shutil.rmtree('/etc')\nPY",
        // An unquoted delimiter expands, so the body is not inert data.
        "cat <<EOF\n$(rm -rf /)\nEOF",
        // Executable text outside the body is judged on its own merits.
        "rm -rf / ; cat <<'EOF'\nRead-only\nEOF",
        "cat <<'EOF'\nRead-only\nEOF\nrm -rf /",
    ] {
        assert_eq!(decision(command), "deny", "{command:?}");
    }
}

/// A receiver whose name could have been rebound still fails closed: the
/// blanking retry only removes inert body bytes, it does not weaken the
/// override proof itself.
#[test]
fn a_rebindable_data_sink_still_denies() {
    for command in [
        "cat(){ bash; }; cat <<'EOF'\nrm -rf /\nEOF",
        "./cat <<'EOF'\nrm -rf /\nEOF",
    ] {
        assert_eq!(decision(command), "deny", "{command:?}");
    }
}

/// The cases above parse cleanly, so they never reach the blanking retry. These
/// force it: an unbalanced `"` in the body is what makes the whole-command parse
/// fail, which is the *only* way into the new code path. A rebinding outside the
/// body must still be seen after blanking.
#[test]
fn a_rebinding_outside_the_body_survives_the_blanking_retry() {
    for command in [
        "cat(){ bash; }; cat <<'EOF'\na \" b\nrm -rf /\nEOF",
        "./cat <<'EOF'\na \" b\nrm -rf /\nEOF",
    ] {
        assert_eq!(
            decision(command),
            "deny",
            "blanking must not hide a rebinding that lives outside the body: {command:?}"
        );
    }
}

/// The converse, which is the soundness claim the retry rests on: a function
/// definition appearing *inside* a quoted body is literal text the shell never
/// executes, so it is not a rebinding and must not make the body scannable.
#[test]
fn a_rebinding_shaped_string_inside_the_body_is_still_data() {
    let command = "cat > /tmp/notes.md <<'EOF'\na \" b\ncat(){ bash; }\nRead-only\nEOF";
    assert_eq!(
        decision(command),
        "allow",
        "a quoted body is data even when it quotes shell syntax: {command:?}"
    );
}

/// The same property one level down, against the exported masking function
/// rather than the hook decision.
///
/// The in-crate unit tests in `src/heredoc.rs` cover the two command shapes from
/// the report; these add the third spelling (the heredoc reaching `git`
/// directly, with no command substitution) and pin the behaviour through the
/// PUBLIC API, so a change to what the crate exports cannot quietly move it.
#[test]
fn masking_is_decided_by_the_delimiter_not_by_the_body_bytes() {
    for command in [
        // Balanced quotes: worked before the fix.
        "git commit -q -m \"$(cat <<'EOF'\na \"b\" c\nRead-only\nEOF\n)\"",
        // Unbalanced quote nested in a command substitution: the reported case.
        "git commit -q -m \"$(cat <<'EOF'\n\u{201e}Messen\"\nRead-only\nEOF\n)\"",
        // The same body reaching git directly, which also worked before.
        "git commit -q -F - <<'EOF'\na \" b\nRead-only\nEOF",
    ] {
        let masked = destructive_command_guard::heredoc::mask_non_expanding_data_heredocs(command);
        assert_ne!(
            masked.as_ref(),
            command,
            "a quoted heredoc body must be masked: {command:?}"
        );
        assert!(
            !masked.contains("Read-only"),
            "the verb-noun-shaped word must not survive into the rescan view: {masked:?}"
        );
        assert_eq!(
            masked.len(),
            command.len(),
            "masking preserves byte offsets: {command:?}"
        );
    }

    // An expanding body is evaluated by the shell, so it is never masked. The
    // fix must not have widened that.
    let expanding = "cat <<EOF\n$(rm -rf /)\nEOF";
    assert_eq!(
        destructive_command_guard::heredoc::mask_non_expanding_data_heredocs(expanding).as_ref(),
        expanding,
        "an unquoted delimiter expands and must stay visible"
    );
}

// ===========================================================================
// #420: an interpreter payload quoted inside a data heredoc is data too
//
// The body was masked for pattern matching and simultaneously mined for inline
// scripts, because inline-script extraction scanned the raw command. So a
// commit message or a documentation file that *describes* a dangerous command
// was denied — including, when this was found, the commit message describing
// the fix for #399/#398.
//
// Inline-script extraction now reads the same data-heredoc-masked view the
// pattern matcher does. The masker's existing conditions decide what counts as
// data: a quoted delimiter, a non-shell data sink, and a target that cannot
// have been rebound.
// ===========================================================================

#[test]
fn a_documented_command_inside_a_data_heredoc_is_allowed() {
    for command in [
        // The reported shapes.
        "git commit -F - <<'EOF'\nfix: document bash -c \"rm -rf ~/x\"\nEOF",
        "git commit -F - <<'EOF'\nfix: document python -c \"import shutil; shutil.rmtree('/etc')\"\nEOF",
        "cat > /tmp/notes/notes.md <<'EOF'\nbash -c \"rm -rf ~/x\"\nEOF",
        // The same class through the other inline-script extractors.
        "cat > /tmp/notes/notes.md <<'EOF'\nnode -e \"require('fs').rmSync('/etc', {recursive: true})\"\nEOF",
        "cat > /tmp/notes/notes.md <<'EOF'\nssh host 'rm -rf ~/x'\nEOF",
        "cat > /tmp/notes/notes.md <<'EOF'\nawk 'BEGIN{ system(\"rm -rf ~/x\") }'\nEOF",
        "tee /tmp/notes/notes.md <<'EOF'\nperl -e 'unlink glob \"~/x/*\"'\nEOF",
        // An unquoted delimiter expands the body, but expansion runs only its
        // substitutions; the rest is the same documentation.
        "cat > /tmp/notes/notes.md <<EOF\nbash -c \"rm -rf ~/x\"\nEOF",
        "cat > /tmp/notes/notes.md <<EOF\nssh host 'rm -rf ~/x' ($(date))\nEOF",
    ] {
        assert_eq!(
            decision(command),
            "allow",
            "a payload quoted inside a data heredoc is documentation: {command:?}"
        );
    }
}

#[test]
fn a_live_payload_outside_a_data_heredoc_still_denies() {
    for command in [
        // A shell interpreter receiving the body executes it.
        "bash <<'EOF'\nrm -rf ~/x\nEOF",
        "sh <<'EOF'\nrm -rf ~/x\nEOF",
        // An unquoted delimiter runs the body's substitutions.
        "cat > /tmp/notes/notes.md <<EOF\n$(bash -c \"rm -rf ~/x\")\nEOF",
        // Executable text outside any heredoc body is untouched by this.
        "bash -c \"rm -rf ~/x\"",
        "cat > /tmp/notes/notes.md <<'EOF'\nharmless\nEOF\nbash -c \"rm -rf ~/x\"",
    ] {
        assert_eq!(
            decision(command),
            "deny",
            "a live payload must still be denied: {command:?}"
        );
    }
}

// ===========================================================================
// #628: the blanking retry re-entered itself and overflowed the stack
//
// The evaluator blanks the modeled assignment and its use in
// `P=x; $P; python3 - <<'EOF'`. tree-sitter-bash rejects the empty statements
// left behind, both before the heredoc and as a whole, and so the receiver
// check for the heredoc fell back to the blanking retry above. A stray `)` or
// an unclosed `{` gets there without any blanking. The retry extracted the command
// again, and that extraction asked the receiver check again, until the stack
// overflowed. The hook died with no output. An agent treats a hook that exits
// without a verdict as a non-blocking error, so it ran the command.
//
// These run the hook as Claude Code does: no arguments and the payload on
// stdin. They check what the agent reads. The process must exit 0 (a process
// killed by a signal has no exit code). Stdout must be empty for an allow, or
// a `PreToolUse` decision JSON. Every command below crashed the hook before
// the fix, except the cat-data case and the ordinary heredocs, which guard
// against over-blocking.
// ===========================================================================

/// Generous budgets: an expired budget answers `ask` under a loaded test run,
/// which would say nothing about #628.
const HOOK_TEST_TIMEOUT_MS: &str = "30000";

/// The command from the #628 report, and the harmless twin it reported
/// crashing the same way.
const REPORTED_628: &str =
    "P=x; $P; python3 - <<'EOF'\nimport shutil; shutil.rmtree('/Users/x/proj')\nEOF";
const REPORTED_628_HARMLESS: &str = "P=x; $P; python3 - <<'EOF'\nprint(1)\nEOF";

/// A complete Claude Code `PreToolUse` payload for `command`.
fn claude_payload(command: &str, cwd: &std::path::Path) -> serde_json::Value {
    serde_json::json!({
        "session_id": "sess-628",
        "transcript_path": "/tmp/claude/transcript.jsonl",
        "cwd": cwd,
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "tool_use_id": "toolu_628",
    })
}

/// A complete Codex `PreToolUse` payload: `turn_id` selects Codex's protocol.
fn codex_payload(command: &str, cwd: &std::path::Path) -> serde_json::Value {
    serde_json::json!({
        "session_id": "019dd11d-b795-7261-a9cb-9b85a5dad628",
        "turn_id": "turn-628",
        "transcript_path": null,
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "model": "gpt-5.5",
        "permission_mode": "default",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "tool_use_id": "call_628",
    })
}

/// Run the hook on the payload built for `command` and return what an agent
/// reads: `("allow", None)` for empty stdout, else the `permissionDecision`
/// and the `ruleId` when the protocol carries one. Panics unless the process
/// exited 0 without a stack overflow. A hook that dies without a verdict is
/// exactly the #628 failure.
fn hook_verdict(
    command: &str,
    payload: fn(&str, &std::path::Path) -> serde_json::Value,
) -> (String, Option<String>) {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let payload = payload(command, temp.path()).to_string();

    let mut child = Command::new(dcg_binary())
        .env_clear()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("DCG_HOOK_TIMEOUT_MS", HOOK_TEST_TIMEOUT_MS)
        .env("DCG_HEREDOC_TIMEOUT_MS", HOOK_TEST_TIMEOUT_MS)
        .env("DCG_AST_TIMEOUT_MS", HOOK_TEST_TIMEOUT_MS)
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcg");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(payload.as_bytes())
        .expect("write payload");
    let out = child.wait_with_output().expect("wait");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        !stderr.contains("overflowed its stack"),
        "the hook overflowed its stack on {command:?}\nstderr: {stderr}"
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "the hook must exit with a verdict, not die ({:?}) on {command:?}\nstderr: {stderr}",
        out.status
    );
    if stdout.trim().is_empty() {
        return ("allow".to_string(), None);
    }
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("hook stdout is not one JSON value ({e}): {stdout}"));
    let output = &parsed["hookSpecificOutput"];
    assert_eq!(output["hookEventName"], "PreToolUse", "{stdout}");
    let decision = output["permissionDecision"]
        .as_str()
        .unwrap_or("<missing>")
        .to_string();
    let rule = output["ruleId"].as_str().map(str::to_string);
    (decision, rule)
}

fn assert_hook_denies(commands: &[&str]) {
    for command in commands {
        let (decision, rule) = hook_verdict(command, claude_payload);
        assert_eq!(decision, "deny", "{command:?} (rule {rule:?})");
    }
}

fn assert_hook_allows(commands: &[&str]) {
    for command in commands {
        let (decision, rule) = hook_verdict(command, claude_payload);
        assert_eq!(decision, "allow", "{command:?} (rule {rule:?})");
    }
}

#[test]
fn the_reported_628_command_is_denied_and_its_twin_allowed() {
    assert_eq!(
        hook_verdict(REPORTED_628, claude_payload),
        (
            "deny".to_string(),
            Some("heredoc.python:shutil_rmtree".to_string())
        ),
        "the Python body is read as Python and its rmtree is named"
    );
    assert_eq!(
        hook_verdict(REPORTED_628_HARMLESS, claude_payload),
        ("allow".to_string(), None)
    );
}

/// Codex parses hook output strictly. The same command must reach its deny
/// shape too, which carries no rule id.
#[test]
fn the_reported_628_command_is_denied_under_codex() {
    assert_eq!(
        hook_verdict(REPORTED_628, codex_payload),
        ("deny".to_string(), None)
    );
    assert_eq!(
        hook_verdict(REPORTED_628_HARMLESS, codex_payload),
        ("allow".to_string(), None)
    );
}

#[test]
fn dynamic_command_words_before_an_interpreter_heredoc_get_a_verdict_628() {
    assert_hook_denies(&[
        "P=x; ${P}; python3 - <<'EOF'\nimport shutil; shutil.rmtree('/Users/x/proj')\nEOF",
        "P=x; \"$P\"; python3 - <<'EOF'\nimport shutil; shutil.rmtree('/Users/x/proj')\nEOF",
        "P=x; $P; python3 - <<'EOF'\nimport os; os.system('rm -rf ~/x')\nEOF",
        // No import line: nothing in the body says Python.
        "P=x; $P; python3 - <<'EOF'\n__import__('shutil').rmtree('/Users/x/proj')\nEOF",
        "F=true; $F; node - <<'JS'\nrequire('fs').rmSync('/Users/x/proj', {recursive: true})\nJS",
        // The word can be `eval`, which can rebind `python3` to a shell that
        // runs the body.
        "P=eval; $P 'python3(){ bash; }'; python3 - <<'EOF'\nrm -rf ~/x\nEOF",
    ]);
    assert_hook_allows(&[
        "P=x; ${P}; python3 - <<'EOF'\nprint(1)\nEOF",
        "P=x; \"$P\"; python3 - <<'EOF'\nprint(1)\nEOF",
        "F=true; $F; node - <<'JS'\nconsole.log(1)\nJS",
    ]);
}

/// Malformed shell before the heredoc took the same path as a dynamic word.
#[test]
fn malformed_shell_before_an_interpreter_heredoc_gets_a_verdict_628() {
    assert_hook_denies(&[
        "echo hi ); python3 - <<'EOF'\nimport shutil; shutil.rmtree('/Users/x/proj')\nEOF",
        "{ echo hi; python3 - <<'EOF'\nimport shutil; shutil.rmtree('/Users/x/proj')\nEOF",
        "{ echo hi; ruby - <<'RB'\nrequire 'fileutils'; FileUtils.rm_rf('/Users/x/proj')\nRB",
    ]);
    assert_hook_allows(&[
        "echo hi ); python3 - <<'EOF'\nprint(1)\nEOF",
        "{ echo hi; python3 - <<'EOF'\nprint(1)\nEOF",
    ]);
}

/// More than one interpreter heredoc, and one inside another heredoc's body.
/// The receiver check inside the blanking retry runs once per heredoc, so
/// these are the shapes a guard that cleared itself too early let through.
#[test]
fn nested_and_repeated_interpreter_heredocs_get_a_verdict_628() {
    assert_hook_denies(&[
        // A shell runs the outer body, so the inner heredoc runs as well.
        // 0.15.3 allowed this one.
        "bash <<'OUTER'\nP=x; $P; python3 - <<'EOF'\nimport shutil; shutil.rmtree('/Users/x/proj')\nEOF\nOUTER",
        "P=x; $P; python3 - <<'A'\nimport shutil; shutil.rmtree('/Users/x/proj')\nA\nruby - <<'B'\nputs 1\nB",
        "P=x; $P; python3 - <<'A'\nprint(1)\nA\nruby - <<'B'\nrequire 'fileutils'; FileUtils.rm_rf('/Users/x/proj')\nB",
    ]);
    assert_hook_allows(&[
        "P=x; $P; python3 - <<'A'\nprint(1)\nA\nruby - <<'B'\nputs 1\nB",
        // `cat` writes the same text to a file. It is data and does not run.
        "cat > /tmp/notes/run.sh <<'OUTER'\nP=x; $P; python3 - <<'EOF'\nimport shutil; shutil.rmtree('/Users/x/proj')\nEOF\nOUTER",
    ]);
}

/// The guard only acts on an extraction already running on the thread. Heredocs
/// that never recursed keep their verdicts: no new denials, and no lost ones.
#[test]
fn ordinary_quoted_interpreter_heredocs_keep_their_verdicts_628() {
    assert_hook_allows(&[
        "python3 - <<'EOF'\nprint(1)\nEOF",
        "cd /tmp && python3 - <<'EOF'\nprint(1)\nEOF",
        // #560: an assignment before the interpreter is not a dynamic word.
        "S=1; python3 - <<'EOF'\nx = \"rm -rf /\"\nprint(x)\nEOF",
        "cat > /tmp/notes/notes.md <<'EOF'\nremember: never run rm -rf ~/x\nEOF",
        REPORTED,
    ]);
    assert_hook_denies(&[
        "python3 - <<'EOF'\nimport shutil; shutil.rmtree('/Users/x/proj')\nEOF",
        "S=1; python3 - <<'EOF'\nimport shutil; shutil.rmtree('/Users/x/proj')\nEOF",
        "node - <<'JS'\nrequire('fs').rmSync('/Users/x/proj', {recursive: true})\nJS",
    ]);
}

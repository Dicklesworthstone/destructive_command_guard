//! #511: `awk 'BEGIN{print "git reset --hard" | "sh"}'` was allowed.
//!
//! #399 taught the extractor that `print … | "cmd"` runs `cmd`, and judged the
//! pipe target. When the target is a shell reading its script from stdin, the
//! PRINTED text is what runs — the same as `echo "…" | sh` — and nothing
//! judged it. Now the printed literal (or a variable the program assigns one
//! literal) is evaluated as a shell command, and a computed print into a shell
//! is unverifiable code, denied under the rule the shell-level
//! `awk '{print "rm " $1}' f | sh` already gets (`heredoc.posix:pipeline-consumer`).
//!
//! Every case goes through the real Claude Code `PreToolUse` hook, both
//! directions: a pipe into something that does not run its stdin (`cat`,
//! `sort`, `sh -c cat`, a script file) stays allowed, as does a harmless
//! printed command.

use std::io::Write;
use std::process::{Command, Stdio};

/// `(decision, rule id)` from the real hook for one Bash command.
fn hook(command: &str) -> (String, String) {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })
    .to_string();
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcg"))
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
    let out = child.wait_with_output().expect("wait");
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if stdout.is_empty() {
        assert!(out.status.success(), "silent non-zero exit for {command:?}");
        return ("allow".to_string(), String::new());
    }
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("bad hook output for {command:?} ({e}): {stdout}"));
    let output = &parsed["hookSpecificOutput"];
    (
        output["permissionDecision"]
            .as_str()
            .unwrap_or("<missing>")
            .to_string(),
        output["ruleId"].as_str().unwrap_or_default().to_string(),
    )
}

#[test]
fn printed_literal_into_a_shell_is_judged() {
    for command in [
        // The reported shapes.
        "awk 'BEGIN{print \"git reset --hard\" | \"sh\"}'",
        "awk 'BEGIN{print \"git reset --hard\" | \"bash\"}'",
        "awk 'BEGIN{cmd=\"git reset --hard\"; print cmd | \"sh\"}'",
        // Other shells, paths, options that keep stdin the script, wrappers.
        "awk 'BEGIN{print \"git reset --hard\" | \"/bin/sh\"}'",
        "awk 'BEGIN{print \"git reset --hard\" | \"dash\"}'",
        "awk 'BEGIN{print \"git reset --hard\" | \"bash -e\"}'",
        "awk 'BEGIN{print \"git reset --hard\" | \"sh -s arg\"}'",
        "awk 'BEGIN{print \"git reset --hard\" | \"sudo sh\"}'",
        // printf with a static format, print with parentheses, commas and
        // concatenation, and gawk's coprocess pipe.
        "awk 'BEGIN{printf \"git reset --hard\\n\" | \"sh\"}'",
        "awk 'BEGIN{print(\"git reset --hard\") | \"sh\"}'",
        "awk 'BEGIN{print \"git\", \"reset\", \"--hard\" | \"sh\"}'",
        "awk 'BEGIN{print \"git reset \" \"--hard\" | \"sh\"}'",
        "gawk 'BEGIN{print \"git reset --hard\" |& \"sh\"}'",
        // Other awks, a rule body, and the program in shell double quotes.
        "mawk 'BEGIN{print \"git reset --hard\" | \"sh\"}'",
        "awk '{print \"git reset --hard\" | \"sh\"}' input.txt",
        "awk \"BEGIN{print \\\"git reset --hard\\\" | \\\"sh\\\"}\"",
    ] {
        assert_eq!(
            hook(command),
            ("deny".to_string(), "core.git:reset-hard".to_string()),
            "{command}"
        );
    }
}

#[test]
fn computed_print_into_a_shell_is_unverified() {
    for command in [
        // A field: the command comes from the input.
        "awk '{print \"rm \" $1 | \"sh\"}' list.txt",
        "awk '{print $0 | \"bash\"}' script.txt",
        // A variable assigned twice, or reassignable from the command line.
        "awk 'BEGIN{c=\"ls\"; c=c \" -la\"; print c | \"sh\"}'",
        "awk -v cmd=ls 'BEGIN{print cmd | \"sh\"}'",
        "awk 'BEGIN{cmd=\"ls\"; print cmd | \"sh\"}' cmd=x",
        // A printf format with a conversion.
        "awk 'BEGIN{printf \"%s\\n\", \"ls\" | \"sh\"}'",
    ] {
        assert_eq!(
            hook(command),
            (
                "deny".to_string(),
                "heredoc.posix:pipeline-consumer".to_string()
            ),
            "{command}"
        );
    }
}

#[test]
fn pipes_that_do_not_run_their_input_stay_allowed() {
    for command in [
        // Harmless printed commands.
        "awk 'BEGIN{print \"git status\" | \"sh\"}'",
        "awk 'BEGIN{cmd=\"date\"; print cmd | \"sh\"; close(\"sh\")}'",
        // The target does not run stdin as a script.
        "awk 'BEGIN{print \"git reset --hard\" | \"cat\"}'",
        "awk 'BEGIN{print \"git reset --hard\" | \"sh -c cat\"}'",
        "awk 'BEGIN{print \"git reset --hard\" | \"sh ./filter.sh\"}'",
        "awk '{print $1 | \"sort -u\"}' data.txt",
        // Printing to a file or the terminal runs nothing.
        "awk 'BEGIN{print \"git reset --hard\"}'",
        "awk 'BEGIN{print \"git reset --hard\" > \"notes.txt\"}'",
    ] {
        assert_eq!(hook(command).0, "allow", "{command}");
    }
}

#[test]
fn the_pipe_target_itself_is_still_judged() {
    // #399's direction, unchanged.
    assert_eq!(
        hook("awk 'BEGIN{print \"x\" | \"git reset --hard\"}'"),
        ("deny".to_string(), "core.git:reset-hard".to_string())
    );
}

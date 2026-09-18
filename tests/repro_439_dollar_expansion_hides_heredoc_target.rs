//! Regression tests for issue #439: a quoted-delimiter heredoc body denied
//! because the heredoc's own line carried a `$VAR`.
//!
//! ```text
//! S=/tmp/scratch && cat > $S/d.md <<'EOF'
//! `x`
//! EOF
//! printf '%s' "$(cat $S/d.md)" | wc -c
//! ```
//!
//! → `heredoc.shell:launcher-unverified`, "POSIX command substitution
//! dynamically assembles a shell launcher".
//!
//! `tokenize_backwards` treated a bare `$` as a command boundary, so the
//! backward walk over the heredoc's line stopped before reaching `cat` and no
//! target command was resolved at all. With no proven data sink, the quoted
//! body stayed visible to the raw-shell rescan, where its line-leading backtick
//! read as a dynamically assembled launcher. `$` introduces an expansion inside
//! a word; it does not start a new command.
//!
//! What pinned the cause: the *better-quoted* spelling `cat > "$S/d.md"` was
//! already allowed, because the tokenizer's quoted-string arm runs before the
//! boundary check and consumes that token whole, letting the walk reach `cat`.
//! Quoting a path cannot change whether a heredoc body is executable.
//!
//! The same truncation suppressed three other data-sink proofs that resolve
//! their program word through the same walk — `git … -F -`, `gh … -F -`, and
//! `spx session handoff` — so `git -C $D commit -F -` was denied for a commit
//! message that merely mentioned a destructive command.

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
const REPORTED: &str =
    "S=/tmp/scratch && cat > $S/d.md <<'EOF'\n`x`\nEOF\nprintf '%s' \"$(cat $S/d.md)\" | wc -c";

#[test]
fn the_reported_command_is_allowed() {
    assert_eq!(
        decision(REPORTED),
        "allow",
        "a quoted heredoc body is literal data wherever it is redirected"
    );
}

#[test]
fn quoting_the_dynamic_path_does_not_change_the_verdict() {
    // These differ only in shell quoting of the same path, which says nothing
    // about whether the body executes. Before the fix they disagreed, and the
    // disagreement is what located the tokenizer.
    for target in [
        "$S/d.md",
        "\"$S/d.md\"",
        "${S}/d.md",
        "\"${S}/d.md\"",
        "/tmp/scratch/d.md",
    ] {
        let command = format!(
            "S=/tmp/scratch && cat > {target} <<'EOF'\n`x`\nEOF\nprintf '%s' \"$(cat /tmp/scratch/d.md)\""
        );
        assert_eq!(
            decision(&command),
            "allow",
            "quoting must not decide the verdict for {target}"
        );
    }
}

#[test]
fn a_dynamic_operand_is_enough_to_reproduce_it() {
    // The report blamed the redirect target, but any `$VAR` on the heredoc's
    // line truncated the walk — including one that is only an operand.
    for command in [
        "S=/tmp/scratch && cat $S/in.md <<'EOF'\n`x`\nEOF\nprintf '%s' \"$(cat /tmp/x)\"",
        "S=/tmp/scratch && cat $S/in.md > d1.md <<'EOF'\n`x`\nEOF\nprintf '%s' \"$(cat /tmp/x)\"",
        "S=/tmp/scratch && tee $S/d.md <<'EOF'\n`x`\nEOF\nprintf '%s' \"$(cat /tmp/x)\"",
    ] {
        assert_eq!(decision(command), "allow", "should be allowed: {command}");
    }
}

#[test]
fn the_other_stdin_data_sinks_are_freed_too() {
    // These resolve their program word through the same backward walk, so the
    // `$` boundary suppressed their proofs as well. Each body merely *mentions*
    // a destructive command; none is executed.
    for command in [
        "D=/repo && git -C $D commit -F - <<'EOF'\nrm -rf /\nEOF",
        "D=/repo && git -C $D tag -a v1 -F - <<'EOF'\nrm -rf /\nEOF",
        "D=/repo && git --git-dir=$D/.git commit -F - <<'EOF'\nrm -rf /\nEOF",
        "N=7 && gh issue comment $N -F - <<'EOF'\nrm -rf /\nEOF",
        "R=o/r && gh api $R --input - <<'EOF'\nrm -rf /\nEOF",
        "A=alpha && spx session handoff $A <<'EOF'\nrm -rf /\nEOF",
    ] {
        assert_eq!(decision(command), "allow", "should be allowed: {command}");
    }
}

#[test]
fn an_executing_heredoc_target_still_denies_across_a_dollar() {
    // Resolving the target across a `$` must never resolve a data sink for a
    // body that is actually executed. Each of these now resolves its real
    // interpreter, or stays unproven, and the body keeps flowing through the
    // scan either way.
    for command in [
        "S=/tmp && bash $S/x <<'EOF'\nrm -rf /\nEOF",
        "S=/tmp && bash > $S/o <<'EOF'\nrm -rf /\nEOF",
        "S=/bin && $S/bash <<'EOF'\nrm -rf /\nEOF",
        "S=bash && $S <<'EOF'\nrm -rf /\nEOF",
        "S=/tmp && sh -s $S <<'EOF'\nrm -rf /\nEOF",
        // An earlier line's data sink must not be borrowed by a later
        // executing heredoc.
        "S=/tmp && cat $S/a\nbash <<'EOF'\nrm -rf /\nEOF",
    ] {
        assert_eq!(decision(command), "deny", "should be denied: {command}");
    }
}

#[test]
fn an_unquoted_body_is_still_scanned_because_the_shell_expands_it() {
    // A quoted delimiter is what makes a body inert. Without it the shell
    // expands the body before the data sink ever sees it, so the substitution
    // really runs and the body must not be masked — whether the heredoc's line
    // carries a `$VAR` or not.
    for command in [
        "S=/tmp && cat > $S/f <<EOF\n$(rm -rf /)\nEOF",
        "S=/tmp && cat > $S/f <<EOF\n`rm -rf /`\nEOF",
        "S=/tmp && tee $S/f <<EOF\n$(rm -rf /)\nEOF",
        "cat > /tmp/f <<EOF\n$(rm -rf /)\nEOF",
    ] {
        assert_eq!(decision(command), "deny", "should be denied: {command}");
    }
}

#[test]
fn a_stdin_sentinel_is_still_required_for_the_data_sink_proofs() {
    // Resolving the program word more often must not weaken the gates that
    // decide a body is data: an explicit stdin sentinel, a known built-in
    // subcommand, and no configuration-bearing input.
    for command in [
        // No `-F -`: git would take the message from the editor, not stdin.
        "D=/r && git -C $D commit <<EOF\nrm -rf /\nEOF",
        // `-c` can define a shell alias, so the subcommand is not provable.
        "C=x.y=z && git -c $C commit -F - <<EOF\nrm -rf /\nEOF",
        "G=/tmp/g && GIT_CONFIG=$G git commit -F - <<EOF\nrm -rf /\nEOF",
        // An unknown subcommand may be an alias git passes stdin through to.
        "SUB=frob && git $SUB -F - <<EOF\nrm -rf /\nEOF",
        // For `gh api`, `-F` is `--field`, not a stdin contract.
        "R=o/r && gh api $R -F - <<EOF\nrm -rf /\nEOF",
        "R=o/r && gh api $R <<EOF\nrm -rf /\nEOF",
        // Only `spx session handoff` has the stdin-document contract.
        "SUB=run && spx $SUB <<EOF\nrm -rf /\nEOF",
        // The program itself is an unresolved expansion.
        "P=git && $P commit -F - <<EOF\nrm -rf /\nEOF",
    ] {
        assert_eq!(decision(command), "deny", "should be denied: {command}");
    }
}

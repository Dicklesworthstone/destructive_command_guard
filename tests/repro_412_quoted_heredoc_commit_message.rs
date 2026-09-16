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

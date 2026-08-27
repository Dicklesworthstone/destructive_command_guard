//! Regression tests for issue #329: prose about destructive commands written
//! through a heredoc to a data sink (`cat > notes.md <<'EOF' … EOF`) was
//! blocked by the bounded embedded-code fallback, while the same text passed
//! as a `printf`/`grep` argument was allowed.
//!
//! A heredoc whose target only *stores* its stdin (`cat`, `tee`, …) is data in
//! every spelling — redirect before or after the operator, quoted or unquoted
//! delimiter. Executing sinks (`bash <<EOF`, `… | sh`) must keep blocking, and
//! inline interpreter bodies (`python3 -c "print(\"rm -rf\")"`) deliberately
//! stay on the conservative raw-shell scan (#136 / #278): a string literal can
//! reach an exec sink through indirection no static scan can rule out.

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

/// Run bare `dcg` (PreToolUse hook, Bash tool) in a hermetic repo dir.
/// Returns (stdout, stderr); empty stdout means allowed.
fn hook(command: &str) -> (String, String) {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(temp.path().join(".git")).unwrap();
    std::fs::create_dir_all(temp.path().join("home")).unwrap();
    std::fs::create_dir_all(temp.path().join("xdg")).unwrap();

    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "cwd": temp.path(),
    });

    let mut child = Command::new(dcg_binary())
        .env_clear()
        .env("HOME", temp.path().join("home"))
        .env("USERPROFILE", temp.path().join("home"))
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .env("DCG_PACKS", "core.git,core.filesystem")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcg");
    {
        let stdin = child.stdin.as_mut().unwrap();
        serde_json::to_writer(stdin, &input).unwrap();
    }
    let output = child.wait_with_output().expect("wait dcg");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

fn assert_allowed(command: &str) {
    let (stdout, stderr) = hook(command);
    assert!(
        stdout.trim().is_empty(),
        "expected ALLOW for:\n{command}\n--- stdout:\n{stdout}\n--- stderr:\n{stderr}"
    );
}

fn assert_denied(command: &str) {
    let (stdout, stderr) = hook(command);
    assert!(
        stdout.contains("deny"),
        "expected DENY for:\n{command}\n--- stdout:\n{stdout}\n--- stderr:\n{stderr}"
    );
}

const PROSE: &str = "Never run rm -rf / on this box.";

#[test]
fn quoted_heredoc_to_cat_with_redirect_before_operator_is_data() {
    // Repro 1 from the report, byte for byte.
    assert_allowed(&format!("cat > notes.md <<'EOF'\n{PROSE}\nEOF"));
}

#[test]
fn data_sink_heredocs_are_allowed_in_every_spelling() {
    for command in [
        format!("cat <<'EOF' > notes.md\n{PROSE}\nEOF"),
        format!("cat >> notes.md <<'EOF'\n{PROSE}\nEOF"),
        format!("cat > notes.md <<EOF\n{PROSE}\nEOF"),
        format!("cat > notes.md <<-'EOF'\n\t{PROSE}\n\tEOF"),
        format!("cat > notes.md <<\"EOF\"\n{PROSE}\nEOF"),
        format!("tee notes.md <<'EOF'\n{PROSE}\nEOF"),
        format!("tee -a notes.md > /dev/null <<'EOF'\n{PROSE}\nEOF"),
        format!(
            "cat > docs/runbook.md <<'EOF'\n# Recovery\n\nDo NOT run `git checkout -- .` or `git reset --hard` here.\n{PROSE}\nEOF"
        ),
        format!("cat > notes.md <<'EOF'\n{PROSE}\nEOF\necho written"),
        format!("mkdir -p docs && cat > docs/notes.md <<'EOF'\n{PROSE}\nEOF"),
    ] {
        assert_allowed(&command);
    }
}

#[test]
fn shell_argument_mentions_stay_allowed() {
    // The contrast from the report: these already worked and must keep
    // working unchanged.
    assert_allowed("grep -c \"rm -rf\" ~/.zshrc");
    assert_allowed("printf '%s\\n' 'docs mention rm -rf'");
}

#[test]
fn executing_heredoc_sinks_still_block() {
    // Planted negatives: the body reaches a shell, so it is code. The path
    // is a real project directory, not the literal `/tmp` carve-out that the
    // rm rules deliberately allow.
    assert_denied("bash <<'EOF'\nrm -rf ./src\nEOF");
    assert_denied("sh <<EOF\nrm -rf ./src\nEOF");
    // The pipeline form was a shipped bypass (see
    // tests/repro_heredoc_pipeline_producer_bypass.rs).
    assert_denied("cat <<'EOF' | bash\nrm -rf ./src\nEOF");
    assert_denied("bash > out.log <<'EOF'\nrm -rf ./src\nEOF");
    // A data sink followed by an executing sink on the same line: the
    // executing one owns the heredoc.
    assert_denied("cat notes.md; bash <<'EOF'\nrm -rf ./src\nEOF");
}

#[test]
fn destructive_command_outside_the_heredoc_still_blocks() {
    // The heredoc body is data, but the command around it is not exempt.
    assert_denied(&format!(
        "rm -rf ./build && cat > notes.md <<'EOF'\n{PROSE}\nEOF"
    ));
    assert_denied(&format!(
        "cat > notes.md <<'EOF'\n{PROSE}\nEOF\nrm -rf ./build"
    ));
}

#[test]
fn inline_interpreter_string_literal_stays_conservative() {
    // Repro 2 from the report. Intentionally NOT relaxed: interpreter bodies
    // are re-scanned as raw shell because a literal can reach an exec sink
    // through indirection (#136 revert, #278). Pinned so the posture is a
    // decision, not an accident.
    assert_denied("python3 -c \"print(\\\"rm -rf\\\")\"");
}

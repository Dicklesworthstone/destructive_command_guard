//! Regression tests for issue #407: a truncating redirect into `.git` named
//! relatively reached no rule at all.
//!
//! ```text
//! cat > .git/config          # ALLOW
//! cat > /repo/.git/config    # DENY  (core.filesystem:redirect-truncate-git-internals-relative)
//! ```
//!
//! `redirect-truncate-git-internals-relative` and its regex were both already
//! correct — the regex matches `> .git/` — but the rule could never run. There
//! are two live keyword lists per pack and they gate in sequence: `PACK_ENTRIES`
//! builds the `EnabledKeywordIndex` that decides whether a pack is a candidate,
//! and only then does `Pack::might_match` consult the pack's own `keywords`. The
//! `.git/` keyword was added to the pack's list and not to its registry row, so
//! the quick-reject dropped the command before the pack was ever considered.
//!
//! Every other redirect keyword in that row requires the target to begin with
//! `/`, `~`, `$` or a quote, which is exactly what a relative target does not do.
//! That is why adding any unrelated pack keyword to the same command — `tee`,
//! `rm`, `sed`, or spelling the path absolutely — made it deny, and why
//! pack-level unit tests could not see the gap: they call the pack directly.

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

fn outcome(command: &str) -> (String, String) {
    let out = run_hook(command);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout.lines().next().unwrap_or_default().to_string();
    let parsed: serde_json::Value =
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("bad batch output ({e}): {stdout}"));
    let decision = parsed
        .get("decision")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<missing>")
        .to_string();
    let rule = parsed
        .get("rule_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    (decision, rule)
}

#[test]
fn a_relative_git_internals_redirect_is_denied() {
    for command in [
        "cat > .git/config",
        "cat > ./.git/config",
        "cat > .git/HEAD",
        "cat > sub/.git/config",
        "echo x > .git/config",
        "printf x > .git/config",
        "cat >.git/config",
    ] {
        let (decision, rule) = outcome(command);
        assert_eq!(decision, "deny", "should be denied: {command}");
        assert!(
            rule.contains("git-internals"),
            "{command} should name the git-internals rule, got {rule:?}"
        );
    }
}

#[test]
fn the_absolute_spelling_still_denies_the_same_way() {
    // The bug was that the two spellings disagreed; the absolute form was never
    // broken, so this pins that the fix did not move it.
    for command in [
        "cat > /home/u/repo/.git/config",
        "cat > $HOME/repo/.git/config",
        "cat > \"$HOME/repo/.git/config\"",
    ] {
        let (decision, _) = outcome(command);
        assert_eq!(decision, "deny", "should be denied: {command}");
    }
}

#[test]
fn appending_to_git_internals_now_denies_and_reading_stays_allowed() {
    // This pinned `>>` as collateral #407's truncation rule must not take.
    // #457 changed the judgement rather than the rule: git reads its internals
    // whole, so a section appended to `.git/config` runs on the next git
    // command without destroying a byte, which makes append the more useful
    // primitive against a repository rather than the milder one. The sibling
    // rule `redirect-append-git-internals-relative` is what denies it now.
    //
    // Reading is still never gated, and that half has not moved.
    for command in ["cat >> .git/config", "echo x >> .git/config"] {
        let (decision, rule) = outcome(command);
        assert_eq!(decision, "deny", "should be denied: {command} ({rule})");
        assert!(
            rule.contains("redirect-append-git-internals-relative"),
            "{command} should name the append rule, got {rule:?}"
        );
    }
    for command in ["cat .git/config", "git config --list"] {
        let (decision, rule) = outcome(command);
        assert_eq!(decision, "allow", "should be allowed: {command} ({rule})");
    }
}

#[test]
fn an_ordinary_relative_redirect_is_not_collateral() {
    // Adding `.git/` to the registry row widens only which commands the pack is
    // asked about, not what it denies. An ordinary relative target must stay
    // allowed, including one whose path merely contains the word "git".
    for command in [
        "cat > README.md",
        "cat > ./notes.txt",
        "cat > build/app.log",
        "cat > gitignore.txt",
        "cat > .gitignore",
        "cat > my.git.notes",
        "cat > git/config",
    ] {
        let (decision, rule) = outcome(command);
        assert_eq!(decision, "allow", "should be allowed: {command} ({rule})");
    }
}

#[test]
fn a_commit_message_discussing_the_rule_is_not_the_rule_firing() {
    // These pins belong at THIS level and nowhere else. `pack.check` sees the
    // raw text and the append rule matches a `>> .git/config` inside a commit
    // message; what makes the command allowed is the evaluator's string-data
    // sanitization, which runs before a pack regex is offered the slice. A
    // pack-level `assert_no_match` for these fails, correctly.
    //
    // The same shape system.disk already relies on: `git commit -m "fix tee
    // /dev/sda handling"` does not reach `tee-device` while bare
    // `tee /dev/sda` does.
    for command in [
        "git commit -m \"document >> .git/config denial\"",
        "git commit -m \"guard writes into .git/hooks\"",
        "git commit -m \"note that cat > .git/config is denied\"",
    ] {
        let (decision, rule) = outcome(command);
        assert_eq!(decision, "allow", "should be allowed: {command} ({rule})");
    }

    // The control, so this test cannot pass by the rules being dead.
    let (decision, rule) = outcome("cat >> .git/config");
    assert_eq!(decision, "deny", "the bare append must still deny ({rule})");
}

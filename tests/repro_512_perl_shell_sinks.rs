//! #512: `perl -e` shell sinks were judged only by a per-language catalogue.
//!
//! `perl -e 'system("git reset --hard")'` was denied (the catalogue knows
//! `git reset --hard`), but `system("git push --force origin main")` and
//! `system("find . -delete")` were allowed while the bare commands denied, and
//! `qx{…}`, `qx(…)` and `qx[…]` were allowed outright because only `qx/…/` was
//! read. An inline program is one quoted shell word, so no other layer sees
//! the string the sink hands to `/bin/sh`.
//!
//! Now a single string given to a shell sink, a backtick command and a `qx`
//! command with any delimiter are evaluated through the packs, like the
//! argv-split form already was. A payload the catalogue owns keeps its rule
//! id, so an allowlist entry for that id still works. The same holds for the
//! other languages' unambiguous shell sinks.
//!
//! Every case goes through the real Claude Code `PreToolUse` hook.

use std::io::Write;
use std::process::{Command, Stdio};

/// `(decision, rule id)` from the real hook for one Bash command, with an
/// optional user allowlist.
fn hook_with_allowlist(command: &str, allowlist: Option<&str>) -> (String, String) {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })
    .to_string();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dcg"));
    cmd.env_clear()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let xdg = temp.path().join("xdg_config");
    std::fs::create_dir_all(xdg.join("dcg")).expect("xdg");
    cmd.env("XDG_CONFIG_HOME", &xdg);
    if let Some(allowlist) = allowlist {
        std::fs::write(xdg.join("dcg/allowlist.toml"), allowlist).expect("write allowlist");
    }
    let mut child = cmd.spawn().expect("spawn dcg");
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

fn hook(command: &str) -> (String, String) {
    hook_with_allowlist(command, None)
}

fn denied_as(command: &str, rule: &str) {
    assert_eq!(
        hook(command),
        ("deny".to_string(), rule.to_string()),
        "{command}"
    );
}

#[test]
fn perl_system_strings_reach_the_packs() {
    // The reported rows.
    denied_as(
        "perl -e 'system(\"git push --force origin main\")'",
        "core.git:push-force-long",
    );
    denied_as(
        "perl -e 'system(\"find . -delete\")'",
        "core.filesystem:find-delete-general",
    );
    // Parenless and exec spellings, and the program in a heredoc.
    denied_as(
        "perl -e 'system \"find . -delete\"'",
        "core.filesystem:find-delete-general",
    );
    denied_as(
        "perl -e 'exec(\"git push --force origin main\")'",
        "core.git:push-force-long",
    );
    assert_eq!(
        hook("perl <<'EOF'\nsystem(\"find . -delete\");\nEOF").0,
        "deny"
    );
}

#[test]
fn perl_qx_with_any_delimiter_is_a_shell_sink() {
    for command in [
        "perl -e 'qx{git reset --hard}'",
        "perl -e 'qx(git reset --hard)'",
        "perl -e 'qx[git reset --hard]'",
        "perl -e 'qx<git reset --hard>'",
        "perl -e 'qx!git reset --hard!'",
        "perl -e 'qx/git reset --hard/'",
        "perl -e 'my $x = qx {git reset --hard};'",
    ] {
        let (decision, rule) = hook(command);
        assert_eq!(decision, "deny", "{command}");
        assert_eq!(rule, "heredoc.perl:qx.git_reset_hard", "{command}");
    }
    // A payload the catalogue does not know reaches the packs.
    denied_as(
        "perl -e 'print qx{find . -delete}'",
        "core.filesystem:find-delete-general",
    );
    denied_as(
        "perl -e 'print `find . -delete`'",
        "core.filesystem:find-delete-general",
    );
}

#[test]
fn catalogue_attribution_and_allowlists_are_unchanged() {
    denied_as(
        "perl -e 'system(\"git reset --hard\")'",
        "heredoc.perl:system.git_reset_hard",
    );
    denied_as(
        "perl -e 'print `git reset --hard`'",
        "heredoc.perl:backticks.git_reset_hard",
    );
    // Allowlisting the id the denial names still allows the command: the
    // payload is not re-denied under the core rule (#467's property).
    for (command, rule) in [
        (
            "perl -e 'system(\"git reset --hard\")'",
            "heredoc.perl:system.git_reset_hard",
        ),
        (
            "perl -e 'print `git reset --hard`'",
            "heredoc.perl:backticks.git_reset_hard",
        ),
        (
            "perl -e 'qx{git reset --hard}'",
            "heredoc.perl:qx.git_reset_hard",
        ),
    ] {
        let allowlist = format!("[[allow]]\nrule = \"{rule}\"\nreason = \"test\"\n");
        assert_eq!(
            hook_with_allowlist(command, Some(&allowlist)).0,
            "allow",
            "{command} with {rule} allowlisted"
        );
    }
    // Allowlisting the core rule a pack-routed payload reports allows it.
    let allowlist =
        "[[allow]]\nrule = \"core.filesystem:find-delete-general\"\nreason = \"test\"\n";
    assert_eq!(
        hook_with_allowlist("perl -e 'system(\"find . -delete\")'", Some(allowlist)).0,
        "allow"
    );
}

#[test]
fn harmless_and_non_shell_strings_stay_allowed() {
    for command in [
        "perl -e 'system(\"date\")'",
        "perl -e 'print qx{date}'",
        "perl -e 'print `ls -la`'",
        "perl -e 'print \"git push --force\"'",
        "perl -e 'my %h = (qx => 1); print \"find . -delete\"'",
        // Not a shell: Go's exec.Command, Python run() without shell=True, a
        // PHP database handle's exec, JavaScript's RegExp.exec.
        "python3 -c 'import subprocess; subprocess.run(\"find . -delete\")'",
        "php -r '$db->exec(\"git push --force\");'",
        "node -e 'const m = /x/.exec(\"git push --force\")'",
    ] {
        assert_eq!(hook(command).0, "allow", "{command}");
    }
}

#[test]
fn other_languages_unambiguous_shell_sinks_reach_the_packs() {
    for command in [
        "python3 -c 'import os; os.system(\"find . -delete\")'",
        "python3 -c 'import subprocess; subprocess.run(\"find . -delete\", shell=True)'",
        "ruby -e 'system(\"find . -delete\")'",
        "php -r 'system(\"find . -delete\");'",
        "php -r 'shell_exec(\"find . -delete\");'",
        "node -e 'require(\"child_process\").execSync(\"find . -delete\")'",
    ] {
        denied_as(command, "core.filesystem:find-delete-general");
    }
}

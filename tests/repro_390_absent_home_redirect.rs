//! Repro for issue #390: `> ~/absent-file` outside a VCS worktree is file
//! creation, not truncation, and must be allowed exactly like `>>` to the
//! same absent path and like `>` to an absent file inside a worktree (#337).
//!
//! Runs the real binary in hook mode against an isolated `HOME` so every row
//! of the report's table is exercised end to end, including the `~`
//! expansion and the two evaluator call sites that consult the carve-out.
//!
//! The existing-file fixture is `~/.vimrc`: since v0.14.2 the shell rc files
//! and the credential files are guarded by
//! `core.filesystem:credential-file-write`, which outranks this carve-out
//! (see `tests/credential_file_write_e2e.rs`), so a neutral dotfile is what
//! proves the truncation verdict itself.

#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Allow,
    Deny(&'static str),
}

const RULES: &[&str] = &["redirect-truncate-root-home", "credential-file-write"];

/// Evaluate one shell command in hook mode with `home` as `$HOME`.
fn verdict(command: &str, home: &Path) -> Verdict {
    let config_path = home.join("dcg-test-config.toml");
    fs::write(&config_path, "").expect("write empty config");
    let payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command }
    })
    .to_string();

    let mut child = Command::new(dcg_binary())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("xdg_config"))
        .env("DCG_CONFIG", &config_path)
        .env(
            "DCG_PENDING_EXCEPTIONS_PATH",
            home.join("pending_exceptions.jsonl"),
        )
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .env_remove("DCG_FAIL_CLOSED")
        .spawn()
        .expect("spawn dcg");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(payload.as_bytes())
        .expect("write payload");
    let output = child.wait_with_output().expect("wait for dcg");
    assert_eq!(
        output.status.code(),
        Some(0),
        "hook protocol exit code for {command:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.contains(r#""permissionDecision":"deny""#) {
        let rule = RULES
            .iter()
            .copied()
            .find(|rule| stdout.contains(rule))
            .unwrap_or_else(|| panic!("unexpected rule for {command:?}: {stdout}"));
        Verdict::Deny(rule)
    } else {
        assert!(
            stdout.trim().is_empty(),
            "allow must be an empty response for {command:?}: {stdout}"
        );
        Verdict::Allow
    }
}

#[test]
fn absent_literal_home_targets_are_creation_regardless_of_vcs() {
    let home = tempfile::tempdir().expect("temp home");
    let home = home.path();
    for dir in [".claude", ".config", ".ssh", "repo/docs", "repo/.git"] {
        fs::create_dir_all(home.join(dir)).expect("fixture dir");
    }
    fs::write(home.join(".vimrc"), b"keep").expect("dotfile");
    fs::write(home.join("repo/docs/README.md"), b"keep").expect("tracked file");

    // The report's table, in order.
    assert_eq!(
        verdict("echo hi > ~/.claude/absent.txt", home),
        Verdict::Allow
    );
    assert_eq!(
        verdict("echo hi > ~/.config/absent.txt", home),
        Verdict::Allow
    );
    assert_eq!(verdict("echo hi > ~/repo/absent.txt", home), Verdict::Allow);
    assert_eq!(
        verdict("echo hi >> ~/.claude/absent.txt", home),
        Verdict::Allow
    );
    assert_eq!(
        verdict("echo hi > ~/.vimrc", home),
        Verdict::Deny("redirect-truncate-root-home")
    );
    assert_eq!(
        verdict("echo hi > ~/repo/docs/README.md", home),
        Verdict::Deny("redirect-truncate-root-home")
    );

    // A top-level file takes the same path as a dotdir. (`$HOME/...` is not
    // in this table: `redirect-truncate-dynamic-path` fails closed on every
    // `$`-bearing target by design, #249, independent of this carve-out.)
    assert_eq!(verdict("echo hi > ~/absent-note.md", home), Verdict::Allow);

    // Credential files are not "creation like any other": the carve-out
    // would call the absent `authorized_keys` harmless, but
    // `credential-file-write` is consulted first and denies the write whether
    // the file exists or not (v0.14.2).
    assert_eq!(
        verdict("echo key > ~/.ssh/authorized_keys", home),
        Verdict::Deny("credential-file-write")
    );
    fs::write(home.join(".ssh/authorized_keys"), b"keep").expect("keys");
    assert_eq!(
        verdict("echo key > ~/.ssh/authorized_keys", home),
        Verdict::Deny("credential-file-write")
    );

    // Every other guard stays exactly as it was.
    assert_eq!(
        verdict("echo hi > ~/missing-parent/absent.txt", home),
        Verdict::Deny("redirect-truncate-root-home")
    );
    assert_eq!(
        verdict("echo hi > ~/repo/.git/HEAD-new", home),
        Verdict::Deny("redirect-truncate-root-home")
    );
    assert_eq!(
        verdict("echo hi > ~/.claude/.git/config", home),
        Verdict::Deny("redirect-truncate-root-home")
    );
    assert_eq!(
        verdict("echo hi > ~/.claude/absent.txt > ~/.vimrc", home),
        Verdict::Deny("redirect-truncate-root-home")
    );
    assert_eq!(
        verdict("echo hi > /etc/absent-dcg-probe", home),
        Verdict::Deny("redirect-truncate-root-home")
    );

    // Targets the shell rewrites before `open()` are not literal: the path
    // dcg would stat is absent while the file the shell truncates exists
    // (`{c..c}` is a one-word brace sequence in bash and zsh; zsh MULTIOS
    // writes `{,}` to both words; quote removal turns `.vim"rc"` into
    // `.vimrc`). Each of these was allowed between #390 and this fix. (A
    // brace at the home root, `~/{.vimrc,x}`, can expand to a credential
    // file and is `credential-file-write`'s call instead.)
    for command in [
        "echo hi > ~/.vimr{c..c}",
        "echo hi > ~/.vimrc{,}",
        "echo hi > ~/.vim{rc,absent.txt}",
        "echo hi > ~/.vim\"rc\"",
        "echo hi > ~/'.vimrc'",
        "echo hi > ~/.vimr(c|d)",
        "echo hi > \"~/absent.txt\"",
    ] {
        assert_eq!(
            verdict(command, home),
            Verdict::Deny("redirect-truncate-root-home"),
            "{command}"
        );
    }
    // Non-ASCII file names are not shell syntax and stay literal.
    assert_eq!(
        verdict("echo hi > ~/.config/héllo-wörld.toml", home),
        Verdict::Allow
    );

    // Nothing was created by evaluating.
    assert!(!home.join(".claude/absent.txt").exists());
    assert!(!home.join(".config/absent.txt").exists());
    assert!(!home.join(".config/héllo-wörld.toml").exists());
    assert_eq!(
        fs::read(home.join(".vimrc")).expect("dotfile survives"),
        b"keep"
    );
}

//! Regression pins for issue #459: argv-split spawns in JavaScript and Ruby.
//!
//! When an embedded script spawns a process with the command and its flags in
//! *separate* arguments, no single string literal contains the command, so the
//! raw-shell rescan has no contiguous text to match and the ast-grep patterns —
//! which match call shapes, not argv contents — see only inert fragments.
//!
//! The capability to handle this already existed: `detect_destructive_in_args`
//! joins a call's string literals back into a command line, and its docstring
//! names `spawnSync("rm", ["-rf", "/etc/x"])` as the shape it is for. Python
//! reached it; JavaScript and Ruby did not, because the only production caller
//! of `scan_executing_sink_fallback` was gated on
//! `is_interpreter_source_heredoc_command`, which returns false for every
//! language since #136 reverted interpreter-body masking.
//!
//! These pins are deliberately paired: each denial sits next to the ordinary
//! spawn of the same shape that must stay allowed, because the argv join is a
//! widening and its false-positive surface is the whole risk.

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

/// `dcg test <command>` under a hermetic config.
fn dcg_test(command: &str) -> (String, String) {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(temp.path().join("home")).unwrap();
    std::fs::create_dir_all(temp.path().join("xdg")).unwrap();
    let output = Command::new(dcg_binary())
        .args(["test", command])
        .env_clear()
        .env("HOME", temp.path().join("home"))
        .env("USERPROFILE", temp.path().join("home"))
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .current_dir(temp.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run dcg test");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let result = stdout
        .lines()
        .chain(stderr.lines())
        .find(|line| line.trim_start().starts_with("Result:"))
        .map(|line| line.trim().to_string())
        .unwrap_or_default();
    (result, format!("{stdout}\n{stderr}"))
}

fn assert_blocked(command: &str) {
    let (result, full) = dcg_test(command);
    assert!(
        result.starts_with("Result: BLOCKED") || result.starts_with("Result: REVIEW REQUIRED"),
        "argv-split spawn of a catastrophic target must deny: {command}\n{full}"
    );
}

fn assert_allowed(command: &str) {
    let (result, full) = dcg_test(command);
    assert_eq!(
        result, "Result: ALLOWED",
        "ordinary spawn must stay allowed: {command}\n{full}"
    );
}

/// `node -e "<body>"` with the child_process require the issue's rows used.
fn node(body: &str) -> String {
    format!("node -e \"const cp=require('child_process'); {body}\"")
}

fn ruby(body: &str) -> String {
    format!("ruby -e \"{body}\"")
}

#[test]
fn javascript_argv_split_spawns_deny_for_catastrophic_targets() {
    // Every row from the issue's JavaScript table that was ALLOWED. None of
    // these has a literal containing the whole command.
    for body in [
        "cp.spawnSync('rm',['-rf','/home/user'])",
        "cp.spawn('rm',['-rf','/home/user'])",
        "cp.execFile('rm',['-rf','/home/user'])",
        // argv[0] as a path: the shell column always denied this spelling.
        "cp.spawnSync('/bin/rm',['-rf','/home/user'])",
        "cp.spawnSync('rm',['-rf','/'])",
        "cp.spawnSync('rm',['-rf','/etc'])",
    ] {
        assert_blocked(&node(body));
    }
}

#[test]
fn ruby_argv_split_spawns_deny_for_catastrophic_targets() {
    for body in [
        "system('rm','-rf','/home/user')",
        "Kernel.system('rm','-rf','/home/user')",
        "system('rm','-rf','/')",
    ] {
        assert_blocked(&ruby(body));
    }
}

/// The shapes that already worked must keep working.
///
/// These have contiguous destructive text, so they were caught by the raw
/// rescan before the backstop was wired up. Wiring it changed which rule
/// answers them, so they are pinned on the verdict rather than the rule id.
#[test]
fn contiguous_payload_spawns_still_deny() {
    assert_blocked(&node("cp.execSync('rm -rf /home/user')"));
    assert_blocked(&node("cp.execFile('sh',['-c','rm -rf /home/user'])"));
    assert_blocked(&ruby("system('rm -rf /home/user')"));
    assert_blocked(&ruby("system('sh','-c','rm -rf /home/user')"));
}

/// The false-positive surface, which is the entire risk of an argv join.
///
/// The argv-list form is what Node's and Ruby's own docs steer authors toward
/// over the string form, so this is the common spelling in real code rather
/// than a corner. If the join were a keyword scan over list elements instead of
/// a command-line reconstruction, these would deny.
#[test]
fn ordinary_argv_split_spawns_stay_allowed() {
    for body in [
        "cp.spawnSync('npm',['install'])",
        "cp.execFile('git',['clone','https://example.invalid/y.git'])",
        "cp.spawnSync('ls',['-la','.'])",
        "cp.spawn('tsc',['--build','tsconfig.json'])",
        "cp.spawnSync('grep',['-r','needle','src'])",
        "cp.spawnSync('mkdir',['-p','build/out'])",
        "cp.spawnSync('cp',['-r','src','dest'])",
        "cp.spawnSync('git',['status'])",
    ] {
        assert_allowed(&node(body));
    }
    for body in [
        "system('ls','-la','.')",
        "system('git','status','--short')",
        "system('bundle','install')",
    ] {
        assert_allowed(&ruby(body));
    }
}

/// Wiring the backstop must not decide #455, and must not defeat the temp
/// carve-out.
///
/// The backstop used to escalate every hit to `High`, which blocks regardless
/// of target. Left in place it would have made these deny — relative recursive
/// deletes in JS and Ruby, and a `/tmp` target that every other layer allows —
/// as a side effect of wiring in a scanner. Whether a relative recursive delete
/// should block is #455's open question, to be answered for all languages at
/// once rather than settled here.
#[test]
fn relative_and_temp_targets_are_not_decided_by_the_backstop_issue_455() {
    for body in [
        "cp.spawnSync('rm',['-rf','./build'])",
        "cp.spawnSync('rm',['-rf','node_modules'])",
        "cp.spawnSync('rm',['-rf','dist'])",
        "cp.spawnSync('rm',['-rf','/tmp/scratch'])",
    ] {
        assert_allowed(&node(body));
    }
    // Ruby reaches the same payload through its own `%x`/backtick-aware pass,
    // which escalated separately. Both passes must agree.
    assert_allowed(&ruby("system('rm','-rf','./build')"));
}

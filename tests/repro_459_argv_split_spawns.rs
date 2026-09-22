//! Regression pins for issue #459: argv-split spawns in JavaScript and Ruby
//! (and Perl, whose `system`/`exec` argv form had the same gap).
//!
//! When an embedded script spawns a process with the command and its flags in
//! *separate* arguments, no single string literal contains the command, so the
//! raw-shell rescan has no contiguous text to match and the ast-grep patterns —
//! which match call shapes, not argv contents — see only inert fragments.
//!
//! The capability to handle this already existed: `detect_destructive_in_args`
//! reads a call's string literals back as the command's argv, and its docstring
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
        "argv-split destructive command must deny: {command}\n{full}"
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

fn perl(body: &str) -> String {
    format!("perl -e \"{body}\"")
}

fn python(body: &str) -> String {
    format!("python3 -c \"import subprocess; {body}\"")
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
/// a reading of the argv, these would deny.
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

/// Argv-split spawns follow #455's single policy for a recursive delete.
///
/// #455 was resolved as "a recursive delete of a literal target outside a temp
/// directory denies whatever language spells it", with `/tmp` and `/var/tmp`
/// carved out in all of them. When this backstop was first wired, #455 was
/// still open, so this test pinned the relative rows as ALLOWED to avoid
/// settling it as a side effect. Once it was settled the other way, that left
/// argv-split the one spelling that disagreed:
///
/// ```text
/// rm -rf ./build                             deny
/// shutil.rmtree('./build')                   deny
/// fs.rmSync('./build', {recursive: true})    deny
/// spawnSync('rm', ['-rf', './build'])        ALLOW   <- this backstop
/// ```
///
/// Both halves are pinned: every relative target denies, and the temp
/// carve-out still allows, so neither direction can drift unnoticed.
#[test]
fn argv_split_recursive_deletes_follow_the_single_policy_issue_455() {
    for body in [
        "cp.spawnSync('rm',['-rf','./build'])",
        "cp.spawnSync('rm',['-rf','node_modules'])",
        "cp.spawnSync('rm',['-rf','dist'])",
    ] {
        assert_blocked(&node(body));
    }
    // Ruby reaches the same payload through its own `%x`/backtick-aware pass,
    // which carries severity separately. Both passes must agree.
    assert_blocked(&ruby("system('rm','-rf','./build')"));

    // The carve-out is the same one `rm -rf /tmp/x` has in the shell.
    for target in ["/tmp/scratch", "/var/tmp/scratch", "/private/tmp/scratch"] {
        assert_allowed(&node(&format!("cp.spawnSync('rm',['-rf','{target}'])")));
        assert_allowed(&ruby(&format!("system('rm','-rf','{target}')")));
    }
    // Traversal out of the temp tree is not scratch: `/tmp/../etc` is `/etc`.
    assert_blocked(&node("cp.spawnSync('rm',['-rf','/tmp/../etc'])"));
}

/// Every operand of an argv-split `rm -rf` counts, and option arguments are
/// not operands.
///
/// Only the first operand used to count, so a temp decoy in front laundered
/// the rest: `spawnSync('rm', ['-rf', '/tmp/x', '/'])` was ALLOWED in
/// JavaScript, Ruby and Perl while `rm -rf /tmp/x /` denied in the shell. And
/// Perl read only the first literal of `system`/`exec`, so its whole argv form
/// was unguarded — `system('rm','-rf','/')` included.
#[test]
fn every_operand_counts_and_options_do_not() {
    for body in [
        "cp.spawnSync('rm',['-rf','/tmp/x','/'])",
        "cp.spawnSync('rm',['-rf','/tmp/x','./build'])",
        // An argv element is one word; the `;` does not end the command.
        "cp.spawnSync('rm',['-rf','/tmp/x;','/'])",
    ] {
        assert_blocked(&node(body));
    }
    for body in [
        "system('rm','-rf','/tmp/x','/')",
        "system('rm','-rf','/tmp/x','./build')",
    ] {
        assert_blocked(&ruby(body));
    }
    for body in [
        "system('rm','-rf','/')",
        "system('rm','-rf','/tmp/x','/')",
        "exec('rm','-rf','./build')",
        "system 'rm', '-rf', '/';",
        "system('git','reset','--hard')",
        // `File::Path` takes several paths as well, or the legacy interface's
        // array reference, which was not matched at all.
        "use File::Path; rmtree('/tmp/x', '/')",
        "use File::Path; rmtree(['/'])",
    ] {
        assert_blocked(&perl(body));
    }

    // Each of these deletes only temp directories. An option's string
    // (`inherit`, `/dev/null`) is not a target.
    assert_allowed(&node(
        "cp.spawnSync('rm',['-rf','/tmp/x'],{stdio:'inherit'})",
    ));
    assert_allowed(&ruby("system('rm','-rf','/tmp/x',out: '/dev/null')"));
    assert_allowed(&perl("system('rm','-rf','/tmp/x','/var/tmp/y')"));
}

/// Argv-split spawns of destructive verbs the rm/git backstop does NOT know
/// still reach their pack rule.
///
/// `dd`/`mkfs`/`wipefs`/`truncate` deny in shell form because the raw-shell
/// rescan sees contiguous text; argv-split splits that across literals, so
/// `spawnSync('dd', ['if=/dev/zero', 'of=/dev/sda'])` reached no layer and was
/// ALLOWED. The reconstruction rejoins the argv and evaluates it through the
/// same packs the shell form hits — one source of truth for every verb.
#[test]
fn argv_split_non_rm_verbs_reach_their_pack_rules() {
    for body in [
        "cp.spawnSync('dd',['if=/dev/zero','of=/dev/sda'])",
        "cp.spawnSync('mkfs.ext4',['/dev/sda1'])",
        "cp.spawnSync('wipefs',['-a','/dev/sda'])",
        "cp.execFile('truncate',['-s','0','/home/u/.bashrc'])",
    ] {
        assert_blocked(&node(body));
    }
    for body in [
        "subprocess.run(['dd','if=/dev/zero','of=/dev/sda'])",
        "subprocess.run(['wipefs','-a','/dev/sda'])",
    ] {
        assert_blocked(&python(body));
    }
    assert_blocked(&ruby("system('dd','if=/dev/zero','of=/dev/sda')"));

    // Ordinary tooling is untouched: a reconstructed command that matches no
    // destructive pack rule still passes.
    for body in [
        "cp.spawnSync('tar',['-czf','out.tgz','src'])",
        "cp.spawnSync('npm',['install'])",
        "cp.spawnSync('git',['status'])",
        "cp.execFile('mkdir',['-p','build/out'])",
    ] {
        assert_allowed(&node(body));
    }

    // The reconstruction routes through the same nested evaluation that
    // `sh -c '<cmd>'` uses. That path already blocks `dd of=/tmp/x` (it does
    // not apply the top-level `dd-tmp` safe pattern), so the argv form does
    // too — an over-block that errs safe and matches the nested `sh -c`
    // spelling, while every device/`mkfs`/`wipefs` target denies as intended.
    assert_blocked(&node(
        "cp.spawnSync('dd',['if=/dev/zero','of=/tmp/scratch'])",
    ));
}

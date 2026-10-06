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

use std::io::Write as _;
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

/// #527 exercises the real hook envelope. The supplied command is JSON data;
/// only dcg is executed, under an isolated home and configuration.
fn hook_decision(command: &str) -> (String, String) {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    let config = temp.path().join("config.toml");
    std::fs::write(&config, "[history]\nenabled = false\n").expect("config");
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "cwd": temp.path(),
    });
    let mut child = Command::new(dcg_binary())
        .env_clear()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("APPDATA", home.join("appdata"))
        .env("LOCALAPPDATA", home.join("localappdata"))
        .env("TEMP", temp.path())
        .env("TMP", temp.path())
        .env("DCG_CONFIG", &config)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env(
            "DCG_PENDING_EXCEPTIONS_PATH",
            temp.path().join("pending_exceptions.jsonl"),
        )
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcg");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(payload.to_string().as_bytes())
        .expect("write hook JSON");
    let output = child.wait_with_output().expect("wait for dcg");
    assert_eq!(
        output.status.code(),
        Some(0),
        "hook failed for {command}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    if output.stdout.is_empty() {
        return ("allow".to_string(), String::new());
    }
    let document: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("invalid hook JSON for {command}: {error}"));
    let output = &document["hookSpecificOutput"];
    (
        output["permissionDecision"]
            .as_str()
            .expect("hook decision")
            .to_string(),
        output["ruleId"].as_str().unwrap_or_default().to_string(),
    )
}

fn argv_git_scripts(tail: &str) -> [String; 3] {
    [
        format!(
            "python3 -c {}",
            shell_words::quote(&format!(
                "import subprocess; subprocess.run([\"git\",\"-C\",p,{tail}])"
            ))
        ),
        format!(
            "node -e {}",
            shell_words::quote(&format!(
                "require(\"child_process\").spawnSync(\"git\",[\"-C\",p,{tail}])"
            ))
        ),
        format!(
            "ruby -e {}",
            shell_words::quote(&format!("system(\"git\",\"-C\",p,{tail})"))
        ),
    ]
}

#[test]
fn dynamic_git_directory_keeps_the_real_subcommand_issue_527() {
    for tail in [
        r#""diff","HEAD""#,
        r#""show","HEAD""#,
        r#""rev-parse","HEAD""#,
        r#""apply","a.patch""#,
        r#""diff""#,
    ] {
        for command in argv_git_scripts(tail) {
            let (decision, rule) = hook_decision(&command);
            assert_eq!(decision, "allow", "{command}: {rule}");
        }
    }
}

#[test]
fn dynamic_git_directory_preserves_destructive_controls_issue_527() {
    for (tail, expected_rule) in [
        (r#""reset","--hard""#, Some("core.git:reset-hard")),
        (r#""clean","-fdx""#, Some("core.git:clean-force")),
        (r#""checkout","--",".""#, Some("core.git:checkout-discard")),
        (r#""push","--force","origin","main""#, None),
        (r#""branch","-D","topic""#, None),
    ] {
        for command in argv_git_scripts(tail) {
            let (decision, rule) = hook_decision(&command);
            assert_eq!(decision, "deny", "{command}: {rule}");
            assert!(!rule.is_empty(), "denial needs a rule: {command}");
            if let Some(expected) = expected_rule {
                assert_eq!(rule, expected, "{command}");
            }
        }
    }
    for command in [
        r#"python3 -c 'import subprocess; subprocess.run((["git","-C",p,"reset","--hard"]))'"#,
        r#"node -e 'require("child_process").spawnSync("git",(["-C",p,"reset","--hard"]))'"#,
    ] {
        let (decision, rule) = hook_decision(command);
        assert_eq!(decision, "deny", "parenthesized argv: {command}: {rule}");
        assert_eq!(rule, "core.git:reset-hard", "{command}");
    }
}

#[test]
fn nested_expressions_and_quoted_arguments_keep_their_positions_issue_527() {
    for command in [
        r#"python3 -c 'import subprocess; subprocess.check_output(["git","-C",str(var),"diff","HEAD","--name-only"])'"#,
        r#"python3 -c 'import subprocess; subprocess.run(["git","-C",choose("/tmp/a,b",nested(1,2)),"diff","HEAD"])'"#,
        r#"node -e 'require("child_process").spawnSync("git",["-C",choose("a,b",{path: get(1,2)}),"diff","HEAD"])'"#,
        r#"ruby -e 'system("git","-C",File.join(root,"a,b"),"diff","HEAD")'"#,
        r#"python3 -c 'import subprocess; subprocess.run(["git","-C","/tmp/repo with spaces","diff","HEAD"])'"#,
        r#"python3 -c 'import subprocess; subprocess.run(["git","-C","/tmp/quo\"te, path","diff","HEAD"])'"#,
        r#"python3 -c 'import subprocess; subprocess.run(["git","-C","/tmp/repro","diff","HEAD"])'"#,
        r#"python3 -c 'import subprocess; subprocess.run(["git","diff","HEAD"],cwd=p)'"#,
    ] {
        let (decision, rule) = hook_decision(command);
        assert_eq!(decision, "allow", "{command}: {rule}");
    }
}

#[test]
fn unknown_rm_targets_do_not_disappear_behind_temp_targets_issue_527() {
    for command in [
        r#"python3 -c 'import subprocess; subprocess.run(["rm","-rf","/tmp/a",target])'"#,
        r#"node -e 'require("child_process").spawnSync("rm",["-rf","/tmp/a",target])'"#,
        r#"ruby -e 'system("rm","-rf","/tmp/a",target)'"#,
        r#"python3 -c 'import subprocess; subprocess.run(["rm","-rf",choose("/tmp/a",target)])'"#,
        r#"python3 -c 'import subprocess; subprocess.run(["r"+"m","-rf","/tmp/"+target])'"#,
        r#"node -e 'require("child_process").spawnSync("r"+"m",["-rf","/etc"])'"#,
        r#"python3 -c 'import subprocess; subprocess.run(["rm" if condition else "echo","-rf","/etc"])'"#,
    ] {
        let (decision, rule) = hook_decision(command);
        assert_eq!(decision, "deny", "{command}: {rule}");
        assert!(!rule.is_empty(), "denial needs a rule: {command}");
    }
    for command in [
        r#"python3 -c 'import subprocess; subprocess.run(["r"+"m","-rf","/tmp/a"])'"#,
        r#"node -e 'require("child_process").spawnSync("rm",["-rf","/tmp/a"])'"#,
        r#"ruby -e 'system("rm","-rf","/tmp/a")'"#,
    ] {
        let (decision, rule) = hook_decision(command);
        assert_eq!(decision, "allow", "literal temp control: {command}: {rule}");
    }
}

#[test]
fn spread_argv_requires_review_without_reclassifying_opaque_programs_issue_527() {
    for command in [
        r#"python3 -c 'import subprocess; subprocess.run(["git","-C",*paths,"diff","HEAD"])'"#,
        r#"node -e 'require("child_process").spawnSync("git",["-C",...paths,"diff","HEAD"])'"#,
        r#"ruby -e 'system("git","-C",*paths,"diff","HEAD")'"#,
        r#"node -e 'require("child_process").spawnSync("git",args)'"#,
        r#"python3 -c 'import subprocess; subprocess.run(["rm","-rf","/tmp/a",*targets])'"#,
    ] {
        let (decision, rule) = hook_decision(command);
        assert_eq!(decision, "deny", "variable cardinality: {command}: {rule}");
        assert!(rule.ends_with("argv_unverified"), "{command}: {rule}");
    }
    // A wholly opaque argv retains its existing posture. The string passed to
    // program_for does not prove that argv[0] is git: preserving that unknown
    // executable lets the launcher verifier review the following -C argument.
    for (command, expected_decision, expected_rule) in [
        (
            "python3 -c 'import subprocess; subprocess.run(argv)'",
            "allow",
            "",
        ),
        (
            r#"python3 -c 'import subprocess; subprocess.run([program_for("git"),"-C",p,"diff",revision])'"#,
            "deny",
            "heredoc.posix:inline-launcher-unverified",
        ),
    ] {
        let (decision, rule) = hook_decision(command);
        assert_eq!(
            decision, expected_decision,
            "unknown executable: {command}: {rule}"
        );
        assert_eq!(rule, expected_rule, "{command}");
    }
}

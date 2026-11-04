//! #536 / #634: bounded POSIX redirect resolution admits proven temporary paths.
//!
//! All command strings are sent as JSON data to the real Claude Code hook;
//! they are never executed by a shell. Positive cases cover each reported
//! spelling, while negative controls pin the proof's control-flow, scope,
//! mutation, and path boundaries.

use std::io::Write;
use std::process::{Command, Stdio};

/// `(decision, rule id)` from an isolated invocation of the real hook.
fn hook(command: &str) -> (String, String) {
    hook_with_environment(command, None, None)
}

fn hook_with_environment(
    command: &str,
    tmpdir: Option<&std::path::Path>,
    home_override: Option<&std::path::Path>,
) -> (String, String) {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = home_override.map_or_else(|| temp.path().join("home"), std::path::Path::to_path_buf);
    std::fs::create_dir_all(&home).expect("home");
    let config = temp.path().join("config.toml");
    std::fs::write(&config, "[history]\nenabled = false\n").expect("config");
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
    })
    .to_string();

    let mut child = Command::new(env!("CARGO_BIN_EXE_dcg"))
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
        .env("TMPDIR", tmpdir.unwrap_or_else(|| temp.path()))
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
        .write_all(payload.as_bytes())
        .expect("write hook payload");
    let out = child.wait_with_output().expect("wait for dcg");
    assert_eq!(
        out.status.code(),
        Some(0),
        "hook exit code for {command:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    if stdout.trim().is_empty() {
        return ("allow".to_string(), String::new());
    }
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("bad hook output for {command:?} ({error}): {stdout}"));
    let output = &parsed["hookSpecificOutput"];
    (
        output["permissionDecision"]
            .as_str()
            .expect("permissionDecision")
            .to_string(),
        output["ruleId"].as_str().unwrap_or_default().to_string(),
    )
}

fn assert_denied(command: &str) {
    let (decision, rule) = hook(command);
    assert_eq!(decision, "deny", "must deny {command:?}: {rule}");
    assert!(!rule.is_empty(), "denial needs a rule id: {command:?}");
}

/// Three leading slashes are a POSIX spelling of the same absolute path, but
/// are outside the literal `/tmp/` prefix. This gives each Unix test a real,
/// writable alternate root without requiring a privileged `/data/tmp` fixture.
#[cfg(unix)]
fn alternate_tmpdir() -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir_in("/tmp").expect("alternate temp root");
    let spelling = std::path::PathBuf::from(format!("//{}", directory.path().display()));
    (directory, spelling)
}

#[cfg(unix)]
#[test]
fn startup_tmpdir_extends_only_proven_local_redirect_paths_590() {
    let (_directory, root) = alternate_tmpdir();
    let root_text = root.to_str().expect("UTF-8 test path");
    for command in [
        format!("S={root_text}/scratchpad; echo hi > $S/a.txt"),
        format!("S={root_text}/scratchpad && echo hi > $S/a.txt"),
        format!("for n in 1 2; do echo hi > {root_text}/scratchpad/l$n.txt; done"),
        format!("S={root_text}/scratchpad; T=\"$S/sub\"; echo hi > \"$T/a.txt\""),
        format!("echo hi > {root_text}/scratchpad/run-$$.txt"),
        format!("bash -c 'S={root_text}/scratchpad; echo hi > \"$S/a.txt\"'"),
        format!("TMPDIR=/etc; S={root_text}/scratchpad; echo hi > \"$S/a.txt\""),
    ] {
        let (decision, rule) = hook_with_environment(&command, Some(&root), None);
        assert_eq!(
            decision, "allow",
            "startup root should prove {command:?}: {rule}"
        );
        let (decision, rule) = hook(&command);
        assert_eq!(
            decision, "deny",
            "an unconfigured root remains unproven: {command:?}: {rule}"
        );
    }
}

#[cfg(unix)]
#[test]
fn startup_tmpdir_keeps_unknown_protected_and_nonlocal_targets_denied_590() {
    let (_directory, root) = alternate_tmpdir();
    let root_text = root.to_str().expect("UTF-8 test path");
    for command in [
        // Startup context supplies a root, never a shell variable value.
        "echo hi > $TMPDIR/a.txt".to_string(),
        "TMPDIR=/etc; echo hi > $TMPDIR/passwd".to_string(),
        format!("S={root_text}/scratchpad; read S; echo hi > $S/a.txt"),
        format!("false && S={root_text}/scratchpad; echo hi > $S/a.txt"),
        format!("S={root_text}/scratchpad; echo hi > $S/$UNKNOWN"),
        format!("S={root_text}; echo hi > $S/../outside.txt"),
        format!("S={root_text}; echo hi > $S/.git/config"),
        format!("S={root_text}; echo hi > $S/.ssh/id_rsa"),
        format!("S={root_text}; echo hi > $S/a.txt > $OTHER"),
        format!("S={root_text}; echo hi > $S/a.txt; git reset --hard"),
        format!("S={root_text}-outside; echo hi > $S/a.txt"),
        format!("S={root_text}; echo hi > $S"),
        // Recursive removal and mktemp producer rules are not widened.
        format!("S={root_text}/scratchpad; rm -rf $S"),
        format!("D=$(mktemp -d -p {root_text}); echo hi > $D/a.txt"),
        // Local startup context is not evidence about an SSH/container host.
        format!("ssh host 'S={root_text}/scratchpad; echo hi > \"$S/a.txt\"'"),
        format!("ssh host 'for n in 1 2; do echo hi > {root_text}/l$n.txt; done'"),
        format!("ssh host <<'SH'\nS={root_text}/scratchpad; echo hi > \"$S/a.txt\"\nSH"),
        format!("ssh host <<'SH'\nbash -c 'S={root_text}; echo hi > \"$S/a.txt\"'\nSH"),
        format!("docker exec container sh -c 'S={root_text}; echo hi > \"$S/a.txt\"'"),
        format!("chroot /sandbox sh -c 'S={root_text}; echo hi > \"$S/a.txt\"'"),
        format!("nsenter -t 1 -m sh -c 'S={root_text}; echo hi > \"$S/a.txt\"'"),
    ] {
        let (decision, rule) = hook_with_environment(&command, Some(&root), None);
        assert_eq!(
            decision, "deny",
            "must retain review for {command:?}: {rule}"
        );
    }
}

#[cfg(unix)]
#[test]
fn startup_tmpdir_cannot_reclassify_home_system_or_symlink_roots_590() {
    let (directory, root) = alternate_tmpdir();
    let home = directory.path().join("home");
    std::fs::create_dir(&home).expect("test home");
    let home_link = directory.path().join("home-link");
    let system_link = directory.path().join("system-link");
    std::os::unix::fs::symlink(&home, &home_link).expect("home alias");
    std::os::unix::fs::symlink("/etc", &system_link).expect("system alias");
    let home_link_spelling = root.join("home-link");
    let system_link_spelling = root.join("system-link");
    let home_spelling = root.join("home");
    let missing_root = root.join("missing");
    let regular_file = directory.path().join("regular-file");
    std::fs::write(&regular_file, "not a directory").expect("file root control");
    let file_spelling = root.join("regular-file");
    for tmpdir in [
        std::path::Path::new("/"),
        std::path::Path::new("/etc"),
        &home_spelling,
        &root,
        &home_link_spelling,
        &system_link_spelling,
        &missing_root,
        &file_spelling,
    ] {
        let command = format!("S={}/scratchpad; echo hi > $S/a.txt", tmpdir.display());
        let (decision, rule) = hook_with_environment(&command, Some(tmpdir), Some(&home));
        assert_eq!(
            decision, "deny",
            "invalid scratch root {tmpdir:?}: {command:?}: {rule}"
        );
    }
}

#[test]
fn all_eight_reported_temporary_redirects_are_allowed() {
    for command in [
        // A: the assignment itself is reached along the && success path.
        r#"mkdir -p /tmp/d && S=/tmp/d && echo hi > "$S/x""#,
        r#"true && S=/tmp/d && echo hi > "$S/x""#,
        // B: a later variable adds a literal suffix to a proven binding.
        r#"S=/tmp/d; T="$S/sub"; echo hi > "$T/x""#,
        r#"S=/tmp/d && T="$S/sub" && echo hi > "$T/x""#,
        // C: a PID contributes only digits beneath the literal /tmp prefix.
        "echo hi > /tmp/d-$$/x",
        r#"echo hi > "/tmp/d-$$.log""#,
        // D: mktemp has an explicit, provably temporary root.
        r#"D=$(mktemp -d /tmp/v-XXXXXX); echo a > "$D/p""#,
        r#"D=$(mktemp -d -p /tmp); echo a > "$D/p""#,
    ] {
        let (decision, rule) = hook(command);
        assert_eq!(decision, "allow", "must allow {command:?}: {rule}");
    }
}

#[test]
fn literal_prefixes_and_loop_variables_resolve_temporary_targets_issue_526() {
    for command in [
        r#"i=1; echo hi > "/tmp/repro/run-$i.log""#,
        r#"true && i=1 && echo hi > "/tmp/repro/run-${i}.log""#,
        r#"for i in 1 2 3; do echo hi > "/tmp/repro/run-$i.log"; done"#,
        r#"for i in 1 2 3; do echo hi > "/tmp/repro/run-${i}.log"; done"#,
        r#"for i in 1 2 3; do echo hi > "/tmp/repro/$i"; done"#,
        r#"for i in 1 2 3; do log="/tmp/repro/run-$i.log"; echo hi > "$log"; done"#,
        r#"i=1; log="/tmp/repro/run-$i.log"; echo hi > "$log""#,
        r#"bash -c 'for i in 1 2 3; do echo hi > "/tmp/repro/run-$i.log"; done'"#,
        r#"bash -c 'i=1; echo hi > "/tmp/repro/run-$i.log"'"#,
        r#"bash -c 'D=/tmp/repro; echo hi > "$D/x"'"#,
        "bash <<'SH'\nfor i in 1 2 3; do echo hi > \"/tmp/repro/run-$i.log\"; done\nSH",
        "cat > /tmp/repro/run.sh <<'SH'\nfor i in 1 2 3; do echo hi > \"/tmp/repro/run-$i.log\"; done\nSH\nbash /tmp/repro/run.sh",
        "mkdir -p /tmp/repro && cat > /tmp/repro/run.sh <<'SH'\nfor i in 1 2 3; do log=\"/tmp/repro/run-$i.log\"; echo hi > \"$log\"; done\nSH\nbash /tmp/repro/run.sh",
    ] {
        let (decision, rule) = hook(command);
        assert_eq!(decision, "allow", "must allow {command:?}: {rule}");
    }
}

#[test]
fn literal_prefixes_do_not_hide_sensitive_or_unknown_loop_targets_issue_526() {
    for command in [
        r#"for i in /etc/passwd /etc/hosts; do echo hi > "$i"; done"#,
        r#"for i in ../../etc/passwd; do echo hi > "/tmp/repro/$i"; done"#,
        r#"for i in /etc/passwd; do echo hi > "/tmp/repro/..$i"; done"#,
        r#"for i in .git/config .ssh/id_rsa; do echo hi > "/tmp/repro/$i"; done"#,
        r#"for i in $(cat /tmp/repro/names.txt); do echo hi > "/tmp/repro/$i"; done"#,
        r#"for i in 1 2; do echo hi > "/tmp/repro/$i-$(date +%s)"; done"#,
        r#"i=1; echo hi > "/etc/run-$i.log""#,
        r#"i=1; echo hi > "/tmp/repro/$i-$OTHER""#,
        r#"false && i=1; echo hi > "/tmp/repro/$i""#,
        "if false; then\ni=1\nfi\necho hi > \"/tmp/repro/$i\"",
        r#"for i in 1 2; do log="/tmp/repro/$i"; read log; echo hi > "$log"; done"#,
        r#"for i in 1 2; do false && log="/tmp/repro/$i"; echo hi > "$log"; done"#,
        r#"for i in 1 2; do _="/tmp/repro/$i"; echo hi > "$_"; done"#,
        r#"base=/tmp/repro; for i in 1 2; do log="$base/out"; echo hi > "$log"; base=/etc; done"#,
        r#"for i in 1 2; do log="/tmp/repro/$i"; trap 'i=../../etc/passwd' DEBUG > "$log"; done"#,
    ] {
        assert_denied(command);
    }
}

#[test]
fn literal_bash_context_preserves_expansion_and_later_denials_issue_526() {
    for command in [
        // The outer shell expands these variables before the body binds them.
        r#"bash -c "i=1; echo hi > /tmp/repro/$i""#,
        r#"bash -c "for i in 1 2; do echo hi > /tmp/repro/$i; done""#,
        "bash <<SH\ni=1; echo hi > /tmp/repro/$i\nSH",
        "bash <<SH\nD=/tmp/repro; echo hi > \"$D/x\"\nSH",
        "cat > /tmp/repro/run.sh <<SH\ni=1; echo hi > /tmp/repro/$i\nSH\nbash /tmp/repro/run.sh",
        "cat > /tmp/repro/run.sh <<SH\nD=/tmp/repro; echo hi > \"$D/x\"\nSH\nbash /tmp/repro/run.sh",
        // Script assignments cannot establish a later parent-shell binding.
        "cat > /tmp/repro/run.sh <<SH\ni=1\nSH\nbash /tmp/repro/run.sh\necho hi > /tmp/repro/$i",
        "cat > /tmp/repro/run.sh <<'SH'\ni=1\nSH\nbash /tmp/repro/run.sh\necho hi > /tmp/repro/$i",
        // Literal source preserves the complete path and binding checks.
        r#"bash -c 'for i in ../../etc/passwd; do echo hi > "/tmp/repro/$i"; done'"#,
        r#"bash -c 'false && i=1; echo hi > "/tmp/repro/$i"'"#,
        r#"i=1; bash -c 'echo hi > "/tmp/repro/$i"'"#,
        r#"bash -c 'for i in $(cat names); do echo hi > "/tmp/repro/$i"; done'"#,
        "cat > /tmp/repro/run.sh <<'SH'\nfor i in ../../etc/passwd; do echo hi > \"/tmp/repro/$i\"; done\nSH\nbash /tmp/repro/run.sh",
        // Only the exact proven operator can stand down the dynamic rule.
        r#"bash -c 'i=1; echo hi > "/tmp/repro/$i"; echo hi > "$OTHER"'"#,
        r#"bash -c 'i=1; echo hi > "/tmp/repro/$i"' > "$OTHER""#,
        r#"bash -c 'i=1; echo hi > "/tmp/repro/$i"; git reset --hard'"#,
        "cat > /tmp/repro/run.sh <<'SH'\ni=1; echo hi > \"/tmp/repro/$i\"; echo hi > \"$OTHER\"\nSH\nbash /tmp/repro/run.sh",
    ] {
        assert_denied(command);
    }
}

#[test]
fn existing_literal_and_bare_mktemp_controls_stay_allowed() {
    for command in [
        "echo hi > /tmp/d/x",
        r#"S=/tmp/d; echo hi > "$S/x""#,
        r#"S=/tmp/d; echo hi > "$S"/x 2>&1"#,
        r#"D=$(mktemp); echo a > "$D""#,
        r#"D=$(mktemp -d); echo a > "$D/p""#,
        r#"D="$(mktemp -d --quiet)"; echo a > "$D/p""#,
    ] {
        let (decision, rule) = hook(command);
        assert_eq!(
            decision, "allow",
            "baseline changed for {command:?}: {rule}"
        );
    }
}

#[test]
fn proven_mktemp_bindings_can_feed_derived_redirect_targets() {
    for command in [
        r#"D=$(mktemp -d /tmp/v-XXXXXX); T="$D/sub"; echo hi > "$T/x""#,
        r#"D=$(mktemp -d); T="$D/sub"; echo hi > "$T/x""#,
        r#"true && D=$(mktemp -d -p /tmp) && T="$D/sub" && echo hi > "$T/x""#,
    ] {
        let (decision, rule) = hook(command);
        assert_eq!(decision, "allow", "must allow {command:?}: {rule}");
    }
}

#[test]
fn reported_sensitive_path_controls_stay_denied() {
    for command in [
        r#"true && S=/etc && echo hi > "$S/passwd""#,
        r#"S=/tmp/d; T="$S/../../etc"; echo hi > "$T/passwd""#,
        r#"S=/tmp/d && T="$S/../../etc" && echo hi > "$T/passwd""#,
        "echo hi > /etc/d-$$/passwd",
        r#"D=$(mktemp -d /etc/v-XXXXXX); echo a > "$D/p""#,
        r#"D=$(mktemp -d -p /etc); echo a > "$D/p""#,
    ] {
        assert_denied(command);
    }
}

#[test]
fn conditional_and_non_parent_bindings_do_not_prove_targets() {
    for command in [
        // The assignment may be skipped while the final redirect still runs.
        r#"false && S=/tmp/d; echo hi > "$S/x""#,
        r#"false && S=/tmp/d || echo hi > "$S/x""#,
        r#"true || S=/tmp/d; echo hi > "$S/x""#,
        r#"true || S=/tmp/d && echo hi > "$S/x""#,
        r#"( true && S=/tmp/d && true ) && echo hi > "$S/x""#,
        r#"S=/etc; false && S=/tmp/d; echo hi > "$S/passwd""#,
        // These assignments do not establish the parent shell's binding.
        r#"S=/tmp/d | cat; echo hi > "$S/x""#,
        r#"S=/tmp/d & echo hi > "$S/x""#,
        r#"(S=/tmp/d); echo hi > "$S/x""#,
    ] {
        assert_denied(command);
    }
}

#[test]
fn unknown_dependencies_and_mutations_do_not_prove_derived_targets() {
    for command in [
        r#"T="$S/sub"; echo hi > "$T/x""#,
        r#"S="$UNKNOWN/d"; T="$S/sub"; echo hi > "$T/x""#,
        r#"S=/tmp/d; S=/etc; T="$S/sub"; echo hi > "$T/x""#,
        r#"S=/tmp/d; read S; T="$S/sub"; echo hi > "$T/x""#,
        r#"S=/tmp/d; unset S; T="$S/sub"; echo hi > "$T/x""#,
        r#"S=/tmp/d; T="$S/sub"; T=/etc; echo hi > "$T/passwd""#,
        r#"S=/tmp/d; T="$S/.git/config"; echo hi > "$T""#,
        r#"tr'ap' 'S=/etc' DEBUG; true && S=/tmp/d && echo hi > "$S/passwd""#,
    ] {
        assert_denied(command);
    }
}

#[test]
fn pid_and_mktemp_proofs_reject_path_and_producer_escapes() {
    for command in [
        "echo hi > /tmpx/d-$$/x",
        "echo hi > /tmp/d-$$/../../etc/passwd",
        r#"echo hi > "$$/passwd""#,
        r#"echo hi > "/tmp/d-$$/$UNKNOWN""#,
        r#"D=$(mktemp -d --unknown /tmp/v-XXXXXX); echo a > "$D/p""#,
        r#"D=$(mktemp -d -u /tmp/v-XXXXXX); echo a > "$D/p""#,
        r#"D=$(mktemp -d -p "$TMPDIR"); echo a > "$D/p""#,
        r#"D=$(TMPDIR=/etc mktemp -d); echo a > "$D/p""#,
        r#"D=$(mktemp -d /tmp/../etc/v-XXXXXX); echo a > "$D/p""#,
        r#"D=$(mktemp -d /tmp/v-XXXXXX); echo a > "$D/../../etc/passwd""#,
        // Random letters must not conceal a possible .git or .ssh directory.
        r#"D=$(mktemp -d /tmp/.XXX); echo x > "$D/config""#,
        r#"D=$(mktemp -d /tmp/.XXX); echo x > "$D/id_rsa""#,
        // A newline is a command separator, not whitespace between options.
        "D=$(mktemp -d /tmp/v-XXXXXX\nprintf /etc); echo a > \"$D/p\"",
        "D=$(mktemp -d -p\n/tmp); echo a > \"$D/etc/passwd\"",
    ] {
        assert_denied(command);
    }
}

#[test]
fn a_proven_temporary_target_does_not_mask_other_dangerous_operations() {
    assert_eq!(
        hook(r#"true && S=/tmp/d && echo hi > "$S/x" && git reset --hard"#),
        ("deny".to_string(), "core.git:reset-hard".to_string())
    );
    for command in [
        r#"echo hi > /tmp/d-$$/x > "$OTHER""#,
        r#"S=/tmp/d; T="$S/sub"; echo hi > "$T/x" > "$OTHER""#,
        r#"D=$(mktemp -d /tmp/v-XXXXXX); echo a > "$D/p"; echo x > "$OTHER""#,
    ] {
        assert_eq!(
            hook(command),
            (
                "deny".to_string(),
                "core.filesystem:redirect-truncate-dynamic-path".to_string()
            ),
            "the unproven second target must stay denied: {command:?}"
        );
    }
}

#[test]
fn literal_proofs_cannot_bypass_shared_shell_mutation_guards() {
    for command in [
        r#"D=/tmp/a; command -p printf -v D /etc; echo hi > "$D/passwd""#,
        r#"D=/tmp/a; command -p printf -v D /etc; rm -rf "$D""#,
        r#"D=/tmp/a; builtin -- printf -v D /etc; echo hi > "$D/passwd""#,
        r#"D=/tmp/a; 'command' printf -v D /etc; rm -rf "$D""#,
        r#"D=/tmp/a; bu''iltin printf -v D /etc; mv "$D" archive/"#,
        r#"D=/tmp/a; $P -v D /etc; echo hi > "$D/passwd""#,
        r#"D=/tmp/a; trap 'D=/etc' DEBUG; rm -rf "$D""#,
        r#"D=/tmp/a; tr'ap' 'D=/etc' DEBUG; mv "$D" archive/"#,
        "shopt -s expand_aliases\nalias next='printf -v D /etc'\nD=/tmp/a\nnext\necho hi > \"$D/passwd\"",
        r#"PWD=/tmp/a; cd /etc; echo hi > "$PWD/passwd""#,
        r#"PWD=/tmp/a; cd /etc; rm -rf "$PWD""#,
        r#"OLDPWD=/tmp/a; cd /etc; cd /tmp; rm -rf "$OLDPWD""#,
        r#"_=/tmp/a; true /etc; rm -rf "$_""#,
        // The strict allow proof must not remove conservative denial evidence.
        r#"PWD=/etc; rm "$PWD/shadow""#,
        r#"D=/etc; command -p echo ready; rm "$D/shadow""#,
        r#"D=/etc; trap ':' DEBUG; rm "$D/shadow""#,
    ] {
        assert_denied(command);
    }
}

#[test]
fn shared_mutation_guards_preserve_literal_and_mktemp_proofs() {
    for command in [
        r#"D=/tmp/a; command echo ready; rm -rf "$D""#,
        r#"D=/tmp/a; builtin echo ready; echo hi > "$D/x""#,
        r#"D=$(mktemp -d); rm -rf "$D""#,
        r#"D=$(mktemp -d); T=/tmp/a; rm -rf "$T""#,
        r#"f=a; echo ready; mv "$f" archive/"#,
        r#"for f in a b; do mv "$f" archive/; done"#,
    ] {
        let (decision, rule) = hook(command);
        assert_eq!(
            decision, "allow",
            "sound proof must survive {command:?}: {rule}"
        );
    }
}

#[test]
fn every_dynamic_redirect_is_proven_independently_issue_634() {
    for command in [
        "S=/tmp/x; foo > $S/o 2> $S/e",
        "S=/tmp/x; foo 2>$S/e >$S/o",
        r#"S=/tmp/x; foo > "$S"/o 2> "${S}/e""#,
        "S=/tmp/x; T=/var/tmp/y; foo > $S/o 2> $T/e",
        r#"S=/tmp/x; T="$S/sub"; foo > "$S/o" 2> "$T/e""#,
        "S=/tmp/x; foo > /tmp/literal 2> $S/e",
        "S=/tmp/x; foo > $S/o 2> /tmp/literal",
        "S=/tmp/x; foo > $S/o 2> $S/e 3>&1",
        "S=/tmp/x; foo 3>&2 > $S/o 2> $S/e",
        "S=/tmp/x; foo >| $S/o 2>| $S/e",
        "S=/tmp/x; foo &>$S/o 3>$S/e",
        r#"S=/tmp/x; foo &> "$S/o" 3> "${S}/e""#,
        "foo > /tmp/stdout-$$ 2> /tmp/stderr-$$",
        r#"for w in a b; do foo > "/tmp/s-$w" 2> "/tmp/e-$w"; done"#,
        r#"bash -c 'S=/tmp/x; foo > "$S/o" 2> "$S/e"'"#,
    ] {
        let (decision, rule) = hook(command);
        assert_eq!(
            decision, "allow",
            "every truncating target has its own temporary-path proof: {command:?}: {rule}"
        );
    }
}

#[test]
fn every_dynamic_redirect_must_pass_the_proof_issue_634() {
    for command in [
        "S=/tmp/x; foo > $S/o 2> $UNKNOWN",
        "S=/tmp/x; foo > $UNKNOWN 2> $S/e",
        "S=/tmp/x; T=/etc; foo > $S/o 2> $T/passwd",
        "S=/tmp/x; T=/etc; foo > $T/passwd 2> $S/e",
        "S=/tmp/x; foo > $S/o 2> $S/../../etc/passwd",
        "S=/tmp/x; foo > $S/../../etc/passwd 2> $S/e",
        "S=/tmp/x; foo > $S/o 2> $S/.git/config",
        "S=/tmp/x; foo > $S/o 2> $S/.ssh/id_rsa",
        "S=/tmp/x; foo > $S/o 2> $S/$UNKNOWN",
        "S=/tmp/x; foo > $S/o 2> $(cat destination)",
        r#"S=/tmp/x; foo > "$S/o" 2> "$S"/"$UNKNOWN""#,
        r#"S='/tmp/*'; foo > "$S/o" 2> $S/e"#,
        "S=/tmp/x; foo > $S/o >&$UNKNOWN",
        "S=/tmp/x; foo > $S/o >&1$UNKNOWN",
        // A later numeric descriptor must not make a prior target irrelevant.
        "S=/tmp/x; foo > $UNKNOWN > $S/o 2>&1",
    ] {
        assert_denied(command);
    }
}

#[test]
fn independently_proven_redirects_preserve_literal_and_command_denials_issue_634() {
    for command in [
        "S=/tmp/x; foo > $S/o 2> /etc/passwd",
        "S=/tmp/x; foo > /etc/passwd 2> $S/e",
        "S=/tmp/x; foo > $S/o 2> .git/config",
        "S=/tmp/x; foo > .git/config 2> $S/e",
        "S=/tmp/x; foo > $S/o 2> $S/e 3> /etc/passwd",
        "S=/tmp/x; foo > $S/o 2> $S/e 3>> .git/config",
        "export FOO=1 > /etc/passwd; S=/tmp/x; foo > $S/o 2> $S/e",
    ] {
        assert_denied(command);
    }
    for command in [
        "S=/tmp/x; git reset --hard > $S/o 2> $S/e",
        "S=/tmp/x; foo > $S/o 2> $S/e; git reset --hard",
        "export FOO=1; S=/tmp/x; git reset --hard > $S/o 2> $S/e",
    ] {
        assert_eq!(
            hook(command),
            ("deny".to_string(), "core.git:reset-hard".to_string()),
            "redirect proofs must not exempt the command: {command:?}"
        );
    }
}

#[test]
fn appends_do_not_need_truncation_proofs_issue_634() {
    for command in [
        "S=/tmp/x; foo > $S/o 2>> $LOG",
        "S=/tmp/x; foo >> $LOG 2> $S/e",
        "S=/tmp/x; foo >$S/o 2>>$LOG",
        "S=/tmp/x; foo >>$LOG 2>$S/e",
        r#"S=/tmp/x; foo >>"$LOG" 2>"$S/e""#,
        "S=/tmp/x; foo &>>$LOG 3>$S/e",
    ] {
        let (decision, rule) = hook(command);
        assert_eq!(
            decision, "allow",
            "an append is not a second truncating redirect: {command:?}: {rule}"
        );
    }
    for command in [
        "S=/tmp/x; foo >> $S/o 2> $UNKNOWN",
        "S=/tmp/x; foo > $UNKNOWN 2>> $S/e",
        "S=/tmp/x; foo >> .git/config 2> $S/e",
        "S=/tmp/x; foo > $S/o 2>> .git/config",
    ] {
        assert_denied(command);
    }
}

#[test]
fn original_redirect_words_preserve_quoted_data_and_escaped_separators_issue_634() {
    for command in [
        r"S=/tmp/x; echo 'literal > $UNKNOWN ; export S=/etc' > $S/o 2> $S/e",
        r#"S=/tmp/x; printf '%s' 'literal > $UNKNOWN' 2> "$S/e" > "$S/o""#,
        r"S=/tmp/x; echo semi\;colon > $S/o 2> $S/e",
        r#"S=/tmp/x; echo quote\"test > $S/o 2> $S/e"#,
        r"S=/tmp/x; foo \>literal > $S/o 2> $S/e",
        "export FOO='x; y'; S=/tmp/x; foo > $S/o 2> $S/e",
    ] {
        let (decision, rule) = hook(command);
        assert_eq!(
            decision, "allow",
            "only actual redirect words need path proofs: {command:?}: {rule}"
        );
    }
    for command in [
        r"S=/tmp/x; echo 'literal > $S/o'; foo > $UNKNOWN 2> $S/e",
        r#"S=/tmp/x; echo 'export FOO=1'; export "$binding"; echo hi > $S/a"#,
        "S=/tmp/x; export FOO=1 \\\n\"$binding\"; echo hi > $S/a",
    ] {
        assert_denied(command);
    }
}

#[test]
fn unrelated_literal_exports_preserve_redirect_bindings_issue_634() {
    for command in [
        "export FOO=1; S=/tmp/x; echo hi > $S/a",
        "S=/tmp/x; export FOO=1; echo hi > $S/a",
        "export FOO=1 BAR=two; S=/tmp/x; foo > $S/o 2> $S/e",
        "export FOO=1\nS=/tmp/x\necho hi > $S/a",
        "export FOO=1; S=/tmp/x; export BAR=two; foo > $S/o 2> $S/e",
        "export FOO=1 && S=/tmp/x && echo hi > $S/a",
        "export FOO='two words'; S=/tmp/x; echo hi > $S/a",
        r#"S=/tmp/x; export FOO="two words"; echo hi > "$S/a""#,
        "export FOO='S=/etc'; S=/tmp/x; echo hi > $S/a",
        "readonly FOO=1; S=/tmp/x; echo hi > $S/a",
        "S=/tmp/x; declare FOO=1; echo hi > $S/a",
        "S=/tmp/x; typeset FOO=1; echo hi > $S/a",
    ] {
        let (decision, rule) = hook(command);
        assert_eq!(
            decision, "allow",
            "literal declarations of unrelated scalars preserve the proof: {command:?}: {rule}"
        );
    }
}

#[test]
fn declaration_proofs_require_literal_unrelated_operands_issue_634() {
    for command in [
        // Read the original arguments, including ones masked as command data.
        "S=/tmp/x; export $binding; echo hi > $S/a",
        r#"S=/tmp/x; export "$binding"; echo hi > $S/a"#,
        r#"S=/tmp/x; export FOO=1 "$binding"; echo hi > $S/a"#,
        r#"binding='S=/etc'; S=/tmp/x; export "$binding"; echo hi > $S/passwd"#,
        r#"S=/tmp/x; command export "$binding"; echo hi > $S/a"#,
        r#"S=/tmp/x; ex'port' "$binding"; echo hi > $S/a"#,
        r#"S=/tmp/x; "export" $binding; echo hi > $S/a"#,
        r"S=/tmp/x; \export $binding; echo hi > $S/a",
        "S=/tmp/x; export FOO=$(cat declarations); echo hi > $S/a",
        "S=/tmp/x; export S=/etc; echo hi > $S/passwd",
        "S=/tmp/x; S=/etc export FOO=1; echo hi > $S/passwd",
        "S=/tmp/x; S=/etc export FOO=1 > $S/passwd 2> $S/e",
        "S=/tmp/x; export IFS=/; echo hi > $S/a",
        "export IFS=/; S=/tmp/x; echo hi > $S/a",
        // Environment configuration is not an unrelated ordinary scalar.
        "export TMPDIR=/etc; D=$(mktemp -d); echo hi > $D/a",
        "export PATH=/usr/bin:$PATH; S=/tmp/x; echo hi > $S/a",
        // Declaration flags can introduce references, arrays or transforms.
        "declare -n T=S; S=/tmp/x; T=/etc; echo hi > $S/passwd",
        "S=/tmp/x; typeset -n T=S; T=/etc; echo hi > $S/passwd",
        "S=/tmp/x; declare -a S; S[0]=/etc; echo hi > $S/passwd",
        r#"S=/tmp/x; readonly "$binding"; echo hi > $S/a"#,
        r#"S=/tmp/x; declare "$binding"; echo hi > $S/a"#,
        r#"S=/tmp/x; typeset "$binding"; echo hi > $S/a"#,
        // A special variable is not an ordinary stable scalar.
        "export FOO=1; PWD=/tmp/x; cd /etc; echo hi > $PWD/passwd",
    ] {
        assert_denied(command);
    }
}

#[test]
fn named_descriptors_cannot_rebind_a_proven_path_during_redirection_issue_634() {
    for command in [
        "S=/tmp/x; foo {S}>/tmp/fd > $S/a",
        "S=/tmp/x; foo > $S/o {S}>/tmp/fd 2> $S/e",
        "S=/tmp/x; foo {S}</tmp/input > $S/o 2> $S/e",
        r#"S=/tmp/x; T="$S/sub"; foo {T}>/tmp/fd > "$T/a""#,
    ] {
        assert_denied(command);
    }
}

#[test]
fn redirect_proofs_do_not_ignore_expansion_side_effects_issue_634() {
    for command in [
        // Expanding an append/input target or argv can change shell state or
        // the filesystem before a later, apparently temporary redirect opens.
        r#"S=/tmp/x; foo >>"$((S=0))" > "$S/a""#,
        r#"S=/tmp/x; foo <"$((S=0))" > "$S/a""#,
        r#"S=/tmp/x; foo "$((S=0))" > "$S/o" 2> "$S/e""#,
        r#"S=/tmp/x; foo >>"$(ln -s /etc /tmp/x; echo /tmp/log)" > "$S/passwd""#,
        r#"S=/tmp/x; foo "$(ln -s /etc /tmp/x)" > "$S/o" 2> "$S/e""#,
        // Unsupported parameter operators must not become an implicit proof
        // just because a different redirect in the command is provable.
        r#"S=/tmp/x; foo > "$S/o" 2> "${UNKNOWN:=/etc/passwd}""#,
        r#"S=/tmp/x; foo > "$S/o" 2> "${S%/*}/../../etc/passwd""#,
    ] {
        assert_denied(command);
    }
}

#[test]
fn literal_loop_bindings_reach_simple_subshell_redirects_issue_634() {
    for command in [
        "for w in a b; do (echo hi > /tmp/s-$w); done",
        "for w in a b; do (foo > /tmp/s-$w 2> /tmp/e-$w); done",
        r#"for w in a b; do ( (foo > "/tmp/$w/o" 2> "/tmp/$w/e") ); done"#,
        r#"bash -c 'for w in a b; do (echo hi > "/tmp/s-$w"); done'"#,
    ] {
        let (decision, rule) = hook(command);
        assert_eq!(
            decision, "allow",
            "the simple subshell inherits the literal iteration value: {command:?}: {rule}"
        );
    }
}

#[test]
fn loop_subshell_proofs_preserve_scope_and_path_boundaries_issue_634() {
    for command in [
        "for w in ../../etc/passwd; do (echo hi > /tmp/$w); done",
        "for w in a b; do (w=../../etc/passwd; echo hi > /tmp/$w); done",
        "for w in a b; do (read w; echo hi > /tmp/$w); done",
        "for w in a b; do (echo ready; echo hi > /tmp/s-$w); done",
        "for w in a b; do (false && D=/tmp/$w; echo hi > $D/a); done",
        "for w in a b; do (echo hi > /tmp/s-$w); trap 'w=../../etc/passwd' DEBUG; done",
        r#"for w in a b; do (foo > "$UNKNOWN" 2> "/tmp/s-$w"); done"#,
        r#"for w in a b; do (foo > "/tmp/s-$w" 2> /etc/passwd); done"#,
        r#"for w in a b; do (foo > "/tmp/s-$w" 2> "/tmp/$w/.git/config"); done"#,
        // Runtime glob candidates and parameter operators need separate proofs.
        r#"for w in *.doc; do (echo hi > "/tmp/slips/${w%.*}.txt"); done"#,
        r#"for w in a.doc b.doc; do (echo hi > "/tmp/slips/${w%.*}.txt"); done"#,
        // Assigning inside a subshell cannot establish a later outer value.
        "for w in a b; do (D=/tmp/$w); echo hi > $D/a; done",
    ] {
        assert_denied(command);
    }
}

#[test]
fn conditional_assignments_must_dominate_every_redirect_issue_634() {
    for command in [
        "cd /tmp && S=/tmp/x; echo hi > $S/a",
        "cd /tmp && S=/tmp/x; foo > $S/o 2> $S/e",
        "export FOO=1; cd /tmp && S=/tmp/x; echo hi > $S/a",
        "S=/tmp/x; false && T=/tmp/y; foo > $S/o 2> $T/e",
        "false && S=/tmp/x || foo > $S/o 2> $S/e",
        "true || S=/tmp/x; foo > $S/o 2> $S/e",
        "(S=/tmp/x); foo > $S/o 2> $S/e",
    ] {
        assert_denied(command);
    }
    for command in [
        "cd /tmp && S=/tmp/x && echo hi > $S/a",
        "cd /tmp && S=/tmp/x && foo > $S/o 2> $S/e",
        "export FOO=1; cd /tmp && S=/tmp/x && foo > $S/o 2> $S/e",
    ] {
        let (decision, rule) = hook(command);
        assert_eq!(
            decision, "allow",
            "the unbroken success path establishes the binding: {command:?}: {rule}"
        );
    }
}

#[test]
fn baseline_scope_and_effect_holes_stay_denied_issue_634() {
    // The single-target baseline accepted several stale-binding forms here.
    // Extending the proof must reject stale evidence in both target counts.
    for prefix in [
        // A newline does not turn a skipped branch into an unconditional bind.
        "if false; then\nS=/tmp/x\nfi\n",
        // A subshell assignment never establishes the later parent value.
        "(\nS=/tmp/x\n)\n",
        // An earlier redirect can allocate a descriptor into the path variable.
        "S=/tmp/x; : {S}>/tmp/fd; ",
        // zsh's ::= parameter operator assigns even when S was already set.
        r#"S=/tmp/x; : "${S::=/etc}"; "#,
        // Inspect sibling assignment values before accepting the literal S.
        "S=/tmp/x T=$((S=0)); ",
        "S=/tmp/x T=${S::=/etc}; ",
        // An indexed-array subscript can evaluate arithmetic without `$((`.
        "S=/tmp/x; X[S=0]=value; ",
    ] {
        for redirect in ["foo > $S/o", "foo > $S/o 2> $S/e"] {
            assert_denied(&format!("{prefix}{redirect}"));
        }
    }

    for redirect in [r#"foo > "$T/o""#, r#"foo > "$T/o" 2> "$T/e""#] {
        // Assignment words run left to right: T copies the sibling /etc value,
        // not the older S value visible at the beginning of this statement.
        assert_denied(&format!(r#"S=/tmp/x; S=/etc T="$S"; {redirect}"#));
    }

    for suffix in ["", r#" 2> "$S/e""#] {
        // A comment can start immediately after `(`. Its quotes and trailing
        // backslash are inert; they cannot hide the live UNKNOWN redirect on
        // the following line or let it borrow the outer temporary-path proof.
        let command = format!("S=/tmp/x;\n(#\"\n : >\"$UNKNOWN\"\n #\"\\\n ) >\"$S/o\"{suffix}");
        assert_denied(&command);
    }
}

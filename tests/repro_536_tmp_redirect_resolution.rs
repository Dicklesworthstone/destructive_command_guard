//! #536: bounded POSIX redirect resolution admits proven temporary paths.
//!
//! All command strings are sent as JSON data to the real Claude Code hook;
//! they are never executed by a shell. Positive cases cover each reported
//! spelling, while negative controls pin the proof's control-flow, scope,
//! mutation, and path boundaries.

use std::io::Write;
use std::process::{Command, Stdio};

/// `(decision, rule id)` from an isolated invocation of the real hook.
fn hook(command: &str) -> (String, String) {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = temp.path().join("home");
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

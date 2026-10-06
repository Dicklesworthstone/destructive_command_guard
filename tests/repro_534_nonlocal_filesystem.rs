//! A script executed elsewhere cannot borrow the guard's local filesystem
//! evidence. Every command below is hook input data, never executed.

#![cfg(unix)]

use std::io::Write;
use std::process::{Command, Stdio};

struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("fixture");
        std::fs::create_dir(dir.path().join("home")).expect("home");
        std::fs::write(dir.path().join("config.toml"),
            "[history]\nenabled = false\n[packs]\nenabled = [\"core.filesystem\", \"core.git\", \"database.postgresql\"]\n",
        ).expect("config");
        Self { dir }
    }

    fn judge(&self, command: &str) -> (String, String, String) {
        let home = self.dir.path().join("home");
        let payload = serde_json::json!({
            "tool_name": "Bash", "tool_input": { "command": command },
        })
        .to_string();
        let mut child = Command::new(env!("CARGO_BIN_EXE_dcg"))
            .env_clear()
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_DATA_HOME", home.join("data"))
            .env("XDG_CACHE_HOME", home.join("cache"))
            .env("DCG_CONFIG", self.dir.path().join("config.toml"))
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env(
                "DCG_PENDING_EXCEPTIONS_PATH",
                self.dir.path().join("pending.jsonl"),
            )
            .env("DCG_SELF_HEAL_HOOK", "0")
            .env("DCG_HOOK_TIMEOUT_MS", "5000")
            .current_dir(self.dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("hook");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(payload.as_bytes())
            .expect("payload");
        let output = child.wait_with_output().expect("result");
        assert_eq!(
            output.status.code(),
            Some(0),
            "{command:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if output.stdout.is_empty() {
            return ("allow".into(), String::new(), String::new());
        }
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("hook JSON");
        let hook = &json["hookSpecificOutput"];
        (
            hook["permissionDecision"]
                .as_str()
                .expect("decision")
                .to_string(),
            hook["ruleId"].as_str().unwrap_or_default().to_string(),
            hook["permissionDecisionReason"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        )
    }

    fn denied(&self, command: &str, rule: &str) -> String {
        let (decision, actual_rule, reason) = self.judge(command);
        assert_eq!(decision, "deny", "{command:?}: {reason}");
        assert_eq!(actual_rule, rule, "{command:?}: {reason}");
        reason
    }

    fn allowed(&self, command: &str) {
        let result = self.judge(command);
        assert_eq!(result.0, "allow", "{command:?}: {result:?}");
    }
}

#[test]
fn remote_home_redirects_ignore_local_existence() {
    let fixture = Fixture::new();
    for existing in [false, true] {
        if existing {
            std::fs::write(fixture.dir.path().join("home/note"), "keep").expect("existing note");
        }
        for command in [
            "ssh host 'echo x > ~/note'",
            "ssh host \"echo x > ~/note\"",
            "/usr/bin/ssh -p 22 host 'echo x > ~/note'",
            "sudo ssh host 'echo x > ~/note'",
            "sshpass -p test ssh host 'echo x > ~/note'",
            "gcloud compute ssh vm --command 'echo x > ~/note'",
            "fly ssh console -C 'echo x > ~/note'",
            "ssh host <<'EOF'\necho x > ~/note\nEOF",
            "ssh host bash <<'EOF'\necho x > ~/note\nEOF",
            "ssh host <<< 'echo x > ~/note'",
            "docker exec -i c sh <<'EOF'\necho x > ~/note\nEOF",
            "kubectl exec -i pod -- sh <<'EOF'\necho x > ~/note\nEOF",
            "cat <<'EOF' | ssh host\necho x > ~/note\nEOF",
            "cat <<'EOF' | tee log | ssh host\necho x > ~/note\nEOF",
            "ssh host 'echo x >| ~/note'",
            "ssh host 'set -C; echo x > ~/note'",
        ] {
            let reason = fixture.denied(command, "core.filesystem:redirect-truncate-root-home");
            assert!(
                reason.contains("another machine or filesystem"),
                "{command:?}: {reason}"
            );
        }
    }
}

#[test]
fn local_redirects_and_safe_remote_operations_remain_allowed() {
    let fixture = Fixture::new();
    for command in [
        "echo x > ~/new-note",
        "ssh host 'echo x' > ~/new-note",
        "ssh host true && bash <<'EOF'\necho x > ~/new-note\nEOF",
        "docker ps; cat <<'EOF' | sh\necho x > ~/new-note\nEOF",
        "ssh host <<'REMOTE'\necho remote\nREMOTE\nbash <<'LOCAL'\necho x > ~/new-note\nLOCAL",
        "ssh host 'echo x >> ~/note'",
        "ssh host 'echo x > /tmp/sub/out'",
        "ssh host <<'EOF'\nS=/tmp/sub; echo x > \"$S/out\"\nEOF",
        "ssh host 'echo x > /tmp/log-$$'",
    ] {
        fixture.allowed(command);
    }
}

#[test]
fn local_heredoc_preserves_the_independent_pipeline_source_guard() {
    let fixture = Fixture::new();
    // This local heredoc must not inherit SSH's filesystem scope. The
    // existing pipeline guard still rejects the unmodeled SSH producer.
    let reason = fixture.denied(
        "ssh host true | bash <<'EOF'\necho x > ~/new-note\nEOF",
        "heredoc.posix:pipeline-consumer",
    );
    assert!(reason.contains("not a statically modeled literal source"));
    assert!(!reason.contains("another machine or filesystem"));
}

#[test]
fn remote_denials_describe_the_other_environment() {
    let fixture = Fixture::new();
    let reason = fixture.denied(
        "ssh host 'mkdir -p ~/.config/new-app && echo x > ~/.config/new-app/config'",
        "core.filesystem:redirect-truncate-root-home",
    );
    assert!(reason.contains("another machine or filesystem"), "{reason}");
    assert!(!reason.contains("missing parents"), "{reason}");
    fixture.denied(
        "ssh host 'echo x > /etc/passwd'",
        "core.filesystem:credential-file-write",
    );
    fixture.denied(
        "ssh host 'echo x >> ~/.ssh/authorized_keys'",
        "core.filesystem:credential-file-write",
    );
}

#[test]
fn remote_database_inputs_and_startup_files_are_unverified() {
    let fixture = Fixture::new();
    let sql = fixture.dir.path().join("benign.sql");
    std::fs::write(&sql, "SELECT 1;\n").expect("local SQL");
    fixture.allowed(&format!("psql -X -f {}", sql.display()));
    let reason = fixture.denied(
        &format!("ssh host 'psql -X -f {}'", sql.display()),
        "database.postgresql:stdin-unverified",
    );
    assert!(reason.contains("another machine or filesystem"), "{reason}");
    fixture.denied(
        "ssh host 'psql -c \"SELECT 1\"'",
        "database.postgresql:stdin-unverified",
    );
    // A local startup file cannot change the remote verdict or be read there.
    std::fs::write(fixture.dir.path().join("home/.psqlrc"), "SELECT 1;\n").expect("local psqlrc");
    let reason = fixture.denied(
        "ssh host 'psql -c \"SELECT 1\"'",
        "database.postgresql:stdin-unverified",
    );
    assert!(reason.contains("--no-psqlrc"), "{reason}");
    fixture.allowed("ssh host 'psql -X -c \"SELECT 1\"'");
    fixture.allowed("ssh host 'psql --no-psqlrc -c \"SELECT 1\"'");
}

#[test]
fn sudo_script_consumers_cannot_borrow_the_callers_home() {
    let fixture = Fixture::new();
    for command in [
        "sudo -u other bash -c 'echo x > ~/note'",
        "'sudo' -u other bash -c 'echo x > ~/note'",
        "\\sudo -u other bash -c 'echo x > ~/note'",
        "doas -u other sh -c 'echo x > ~/note'",
        "sudo -H bash -c 'echo x > ~/note'",
        "sudo -u other bash <<'EOF'\necho x > ~/note\nEOF",
        "printf '%s\\n' 'echo x > ~/note' | sudo -u other bash",
    ] {
        fixture.denied(command, "core.filesystem:redirect-truncate-root-home");
    }
    fixture.denied(
        "sudo -u other bash <<'EOF'\npsql -c 'SELECT 1'\nEOF",
        "database.postgresql:stdin-unverified",
    );
    for command in [
        "sudo echo x > ~/new-note",
        "sudo true && bash <<'EOF'\necho x > ~/new-note\nEOF",
        "sudo printf '%s\\n' 'echo x > ~/new-note' | parallel",
    ] {
        fixture.allowed(command);
    }
}

#[test]
fn remote_parallel_payloads_use_the_consumers_filesystem() {
    let fixture = Fixture::new();
    for options in [
        "-S host",
        "-Shost",
        "--sshlogin host",
        "--sshlogin=host",
        "--sshloginfile hosts",
        "--sshloginfile=hosts",
        "--jobs 2 --joblog jobs.log -S host",
    ] {
        fixture.denied(
            &format!("printf '%s\\n' 'echo x > ~/note' | parallel {options}"),
            "core.filesystem:redirect-truncate-root-home",
        );
    }
    for command in [
        // Each generated record and a fixed -c template retain the consumer.
        "printf '%s\\n' 'echo x > ~/note' 'echo y > ~/note' | parallel -S host",
        "printf '%s\\n' one | parallel -S host sh -c 'echo x > ~/note'",
        // Process substitutions feed the same remote consumer as a pipeline.
        "parallel -S host < <(printf '%s\\n' 'echo x > ~/note')",
        "printf '%s\\n' 'echo x > ~/note' > >(parallel -S host)",
    ] {
        fixture.denied(command, "core.filesystem:redirect-truncate-root-home");
    }
    for command in [
        "printf '%s\\n' 'echo x > ~/new-note' | parallel",
        "printf '%s\\n' one | parallel sh -c 'echo x > ~/new-note'",
        "printf '%s\\n' 'echo x > ~/new-note' | parallel --jobs 2 --joblog --sshlogin",
        "parallel < <(printf '%s\\n' 'echo x > ~/new-note')",
    ] {
        fixture.allowed(command);
    }
    let sql = fixture.dir.path().join("parallel-benign.sql");
    std::fs::write(&sql, "SELECT 1;\n").expect("local SQL");
    let producer = format!("printf '%s\\n' 'psql -X -f {}'", sql.display());
    fixture.allowed(&format!("{producer} | parallel"));
    let reason = fixture.denied(
        &format!("{producer} | parallel -S host"),
        "database.postgresql:stdin-unverified",
    );
    assert!(reason.contains("another machine or filesystem"), "{reason}");
    // Identical source bytes must not deduplicate across filesystem scopes.
    // Both orders matter because the collector walks an AST work stack.
    for command in [
        format!("{producer} | parallel; {producer} | parallel -S host"),
        format!("{producer} | parallel -S host; {producer} | parallel"),
    ] {
        fixture.denied(&command, "database.postgresql:stdin-unverified");
    }
}

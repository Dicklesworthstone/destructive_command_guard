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

    fn with_shadowed_inputs() -> Self {
        let fixture = Self::new();
        std::fs::create_dir(fixture.dir.path().join("other")).expect("other working directory");
        for (name, local, other) in [
            (
                "migration.sql",
                "SELECT 1;\n",
                "DROP TABLE important_data;\n",
            ),
            ("program.sed", "s/x/y/\n", "e rm -rf /\n"),
        ] {
            std::fs::write(fixture.dir.path().join(name), local).expect("local benign input");
            std::fs::write(fixture.dir.path().join("other").join(name), other)
                .expect("same-named input in other directory");
        }
        std::fs::write(fixture.dir.path().join("input.txt"), "x\n").expect("sed input");
        fixture
    }

    fn judge(&self, command: &str) -> (String, String, String) {
        let home = self.dir.path().join("home");
        let payload = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash", "tool_input": { "command": command },
            "cwd": self.dir.path(),
        })
        .to_string();
        let mut child = Command::new(env!("CARGO_BIN_EXE_dcg"))
            .env_clear()
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_DATA_HOME", home.join("data"))
            .env("XDG_CACHE_HOME", home.join("cache"))
            .env("TMPDIR", self.dir.path())
            .env("TEMP", self.dir.path())
            .env("TMP", self.dir.path())
            .env("DCG_CONFIG", self.dir.path().join("config.toml"))
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env(
                "DCG_PENDING_EXCEPTIONS_PATH",
                self.dir.path().join("pending.jsonl"),
            )
            .env(
                "DCG_ALLOW_ONCE_PATH",
                self.dir.path().join("allow_once.jsonl"),
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
            "ssh host 'echo x >| ~/note'",
            "ssh host 'set -C; echo x > ~/note'",
        ] {
            let reason = fixture.denied(command, "core.filesystem:redirect-truncate-root-home");
            assert!(
                reason.contains("another machine or filesystem"),
                "{command:?}: {reason}"
            );
        }
        // The executable-input pass now reaches SSH through this pipeline.
        // As for a local shell, tee is not a modeled literal producer, so its
        // source guard denies before applying the remote redirect rule.
        fixture.denied(
            "cat <<'EOF' | tee log | ssh host\necho x > ~/note\nEOF",
            "heredoc.posix:pipeline-consumer",
        );
    }
}

const REMOTE_STDIN_SHELLS: &[&str] = &[
    "ssh host",
    "/usr/bin/ssh -p 22 host",
    "sudo ssh -i key host",
    "ssh host bash -s",
    "ssh host fish --command=sh",
    "docker exec -i c sh",
    "docker exec -i c fish --command sh",
    "podman exec -i c bash",
    "kubectl exec -i pod -- sh",
];

#[test]
fn remote_stdin_shells_evaluate_literal_producer_bytes() {
    let fixture = Fixture::new();
    for consumer in REMOTE_STDIN_SHELLS {
        // These bytes are executable source on the consumer, even though
        // they are quoted data in the local producer's argument list.
        fixture.denied(
            &format!("printf '%s\\n' 'rm -rf /' | {consumer}"),
            "core.filesystem:rm-rf-root-home",
        );
    }
}

#[test]
fn remote_stdin_ssh_options_are_separate_from_remote_shell_arguments() {
    let fixture = Fixture::new();
    for consumer in [
        // Option values resembling flags must not disable the real stdin.
        "ssh -p 22 -o 'HostKeyAlias=-n' host sh -s",
        "ssh -p2222 -oHostKeyAlias=sh host sh -s",
        "ssh -o 'SetEnv=MODE=-n' -p 22 host sh -s",
        // SSH joins decoded remote argv with spaces before the remote shell
        // parses it, including a command supplied in one quoted argument.
        "ssh host 'sh -s'",
        "ssh host 'sh ' '-s'",
        "ssh host -p 22 'sh -s'",
    ] {
        fixture.denied(
            &format!("printf '%s\\n' 'rm -rf /' | {consumer}"),
            "core.filesystem:rm-rf-root-home",
        );
    }
    for consumer in [
        // A shell-like option value is not the remote command to execute.
        "ssh -p 22 -o 'HostKeyAlias=sh' host cat",
        "ssh -o 'User sh' host cat",
        "ssh -p 22 -o 'HostKeyAlias=-n' host cat",
        "ssh -n -p 22 -o 'HostKeyAlias=sh' host 'sh -s'",
    ] {
        fixture.allowed(&format!("printf '%s\\n' 'rm -rf /' | {consumer}"));
    }
}

#[test]
fn remote_stdin_ssh_simple_script_boundaries_remain_executable() {
    let fixture = Fixture::new();
    for consumer in [
        "ssh host '. /dev/stdin'",
        "ssh host 'source /dev/fd/0'",
        "ssh host '# leading comment\nsh -s'",
        "ssh host \"sh -c 'bash -s'\"",
    ] {
        fixture.denied(
            &format!("printf '%s\\n' 'rm -rf /' | {consumer}"),
            "core.filesystem:rm-rf-root-home",
        );
    }
    // A source-like pair of arguments is not a source command, and a
    // leading comment must not change an actual data consumer's mode.
    fixture.allowed("printf '%s\\n' 'rm -rf /' | ssh host '# leading comment\ncat'");
    fixture.allowed("printf '%s\\n' 'rm -rf /' | ssh host \"printf '%s %s' source /dev/stdin\"");
}

#[test]
fn remote_stdin_ssh_output_redirects_preserve_remote_arguments() {
    let fixture = Fixture::new();
    for consumer in [
        ">/tmp/ssh-output ssh host sh -s",
        "ssh host >/tmp/ssh-output sh -s",
        "ssh host sh >/tmp/ssh-output -s",
        "ssh host sh -s >/tmp/ssh-output",
        "ssh host 'sh -s' 1>&2",
        // This redirect is parsed remotely after SSH joins its argv. The
        // later -s is still a shell argument after redirect removal.
        "ssh host sh '> /tmp/ssh-output' -s",
    ] {
        fixture.denied(
            &format!("printf '%s\\n' 'rm -rf /' | {consumer}"),
            "core.filesystem:rm-rf-root-home",
        );
    }
    // The pipeline AST can end this consumer at `ssh` and attach the later
    // destination/arguments to its outer redirect. An incomplete destination
    // is unverified, never evidence that the received bytes are data.
    fixture.denied(
        "printf '%s\\n' 'rm -rf /' | ssh >/tmp/ssh-output host sh -s",
        "heredoc.posix:pipeline-consumer",
    );
    fixture.denied(
        "printf '%s\\n' 'echo x > ~/note' | ssh 2>/dev/null host",
        "heredoc.posix:pipeline-consumer",
    );
    for consumer in [
        "ssh host cat >/tmp/ssh-output",
        "ssh host 'cat > /tmp/ssh-output'",
    ] {
        fixture.allowed(&format!("printf '%s\\n' 'rm -rf /' | {consumer}"));
    }
}

#[test]
fn remote_stdin_ssh_local_command_is_unverified_even_with_stdin_disabled() {
    let fixture = Fixture::new();
    for flags in ["", "-n "] {
        // -n affects the remote session input. LocalCommand can still
        // inherit the caller's stdin, so it cannot establish a data-only
        // consumer even when the remote command itself is harmless.
        fixture.denied(
            &format!(
                "printf '%s\\n' 'rm -rf /' | ssh {flags}-o PermitLocalCommand=yes \
                 -o 'LocalCommand=sh -s' host true"
            ),
            "heredoc.posix:pipeline-consumer",
        );
    }
}

#[test]
fn remote_stdin_container_exec_keeps_argv_boundaries() {
    let fixture = Fixture::new();
    for consumer in [
        // The shell is the executable after the container/pod operand, not
        // an earlier container name or value-taking carrier option.
        "docker exec -i sh sh -s",
        "docker exec -i --user sh c sh -s",
        "docker container --context prod exec -i c sh",
        "podman exec -i --user sh c sh -s",
        "nerdctl exec -i --user sh c sh -s",
        "nerdctl exec -i c -- sh",
        "kubectl exec sh -i -c sh -- sh -s",
        "oc exec sh -i -c sh -- sh -s",
    ] {
        fixture.denied(
            &format!("printf '%s\\n' 'rm -rf /' | {consumer}"),
            "core.filesystem:rm-rf-root-home",
        );
    }
    for consumer in [
        "docker exec -i sh cat",
        "docker exec -i --user sh c cat",
        "docker exec -i -u sh c cat",
        "podman exec -i --user sh c cat",
        "nerdctl exec -i --user sh c cat",
        "kubectl exec sh -i -c sh -- cat",
        "oc exec sh -i -c sh -- cat",
        // These carriers preserve the remote argv. Unlike SSH, a single
        // command argument containing spaces is not split into `sh`, `-s`.
        "docker exec -i c 'sh -s'",
        "podman exec -i c 'sh -s'",
        "kubectl exec pod -i -- 'sh -s'",
        "docker exec -i c cat sh -s",
    ] {
        fixture.allowed(&format!("printf '%s\\n' 'rm -rf /' | {consumer}"));
    }
}

#[test]
fn remote_stdin_docker_delivery_obeys_boolean_and_detach_flags() {
    let fixture = Fixture::new();
    for consumer in [
        "docker exec --interactive=true c sh",
        "docker exec -i=true -d=false c sh",
        "docker exec --interactive=false --interactive=true c sh",
        "docker exec -i --detach=true --detach=false c sh",
    ] {
        fixture.denied(
            &format!("printf '%s\\n' 'rm -rf /' | {consumer}"),
            "core.filesystem:rm-rf-root-home",
        );
    }
    for consumer in [
        "docker exec --interactive=false c sh",
        "docker exec -i=false c sh",
        "docker exec -i --interactive=false c sh",
        "docker exec -i -d c sh",
        "docker exec -i --detach c sh",
        "docker exec --interactive=true --detach=true c sh",
        // After the container operand, -i belongs to sh, not to Docker.
        "docker exec c sh -i",
    ] {
        fixture.allowed(&format!("printf '%s\\n' 'rm -rf /' | {consumer}"));
    }
}

#[test]
fn remote_stdin_kubectl_flags_after_pod_remain_carrier_options() {
    let fixture = Fixture::new();
    for consumer in [
        "kubectl exec pod -i -- sh",
        "kubectl exec pod --stdin=true -- sh",
        "kubectl exec pod -c sh --stdin=true -- sh -s",
        "oc exec pod -i -- sh",
    ] {
        fixture.denied(
            &format!("printf '%s\\n' 'rm -rf /' | {consumer}"),
            "core.filesystem:rm-rf-root-home",
        );
    }
    for consumer in [
        "kubectl exec pod --stdin=false -- sh",
        "kubectl exec pod -i --stdin=false -- sh",
        "kubectl exec pod -i -c sh -- cat",
        // The double dash ends carrier options; the shell's -i does not
        // enable forwarding when kubectl itself did not receive -i.
        "kubectl exec pod -- sh -i",
    ] {
        fixture.allowed(&format!("printf '%s\\n' 'rm -rf /' | {consumer}"));
    }
}

#[test]
fn remote_stdin_redirects_ignore_local_existence() {
    let fixture = Fixture::new();
    let local_note = fixture.dir.path().join("home/note");
    for existing in [false, true] {
        if existing {
            std::fs::write(&local_note, "keep").expect("existing local note");
        }
        for consumer in REMOTE_STDIN_SHELLS {
            let command = format!("printf '%s\\n' 'echo x > ~/note' | {consumer}");
            let reason = fixture.denied(&command, "core.filesystem:redirect-truncate-root-home");
            assert!(
                reason.contains("another machine or filesystem"),
                "{command:?}: {reason}"
            );
        }
        for command in [
            "echo 'echo x > ~/note' | ssh host",
            "printf '%s\\n' 'echo x > ~/note' | 2>/dev/null ssh host",
            "ssh host < <(printf '%s\\n' 'echo x > ~/note')",
            "printf '%s\\n' 'echo x > ~/note' > >(ssh host)",
            "printf '%s\\n' 'echo x > ~/note' | tee >(ssh host)",
        ] {
            let reason = fixture.denied(command, "core.filesystem:redirect-truncate-root-home");
            assert!(
                reason.contains("another machine or filesystem"),
                "{command:?}: {reason}"
            );
        }
        if existing {
            assert_eq!(
                std::fs::read_to_string(&local_note).expect("local note survives"),
                "keep"
            );
        } else {
            assert!(
                !local_note.exists(),
                "hook analysis must not execute its input"
            );
        }
    }
}

#[test]
fn remote_stdin_composite_producers_preserve_fail_closed_analysis() {
    let fixture = Fixture::new();
    for command in [
        "(cat <<'EOF'\necho x > ~/note\nEOF\n) | ssh host",
        "(cat <<'EOF'\necho x > ~/note\nEOF\n) | docker exec -i c sh",
        "(cat <<'EOF'\necho x > ~/note\nEOF\n) | tee log | kubectl exec -i pod -- sh",
        "printf '%s\\n' 'echo x > ~/note' | tee log | ssh host",
    ] {
        fixture.denied(command, "heredoc.posix:pipeline-consumer");
    }
    // These producer shapes were already unverified when feeding a local
    // shell. Recognizing remote consumers must preserve that fail-closed
    // policy rather than inventing a new proof of their emitted bytes.
    for command in [
        "ssh host true; (cat <<'EOF'\necho x > ~/new-note\nEOF\n) | sh",
        "printf '%s\\n' 'echo x > ~/new-note' | tee log | sh",
    ] {
        let reason = fixture.denied(command, "heredoc.posix:pipeline-consumer");
        assert!(
            !reason.contains("another machine or filesystem"),
            "{reason}"
        );
    }
}

#[test]
fn remote_stdin_shells_fail_closed_for_unknown_producers() {
    let fixture = Fixture::new();
    for consumer in [
        "ssh host",
        "ssh host sh -s",
        "docker exec -i c bash",
        "kubectl exec -i pod -- sh",
    ] {
        fixture.denied(
            &format!("generate-script | {consumer}"),
            "heredoc.posix:pipeline-consumer",
        );
    }
}

#[test]
fn remote_stdin_data_consumers_and_safe_scripts_remain_allowed() {
    let fixture = Fixture::new();
    for consumer in [
        "ssh host cat",
        "ssh host sh -c 'cat'",
        "docker exec -i c cat",
        "docker exec -i c sh -c 'cat'",
        "kubectl exec -i pod -- cat",
        // These invocations do not send pipeline input to a remote shell.
        "ssh -n host",
        "docker exec c sh",
        "kubectl exec pod -- sh",
    ] {
        fixture.allowed(&format!("printf '%s\\n' 'rm -rf /' | {consumer}"));
        fixture.allowed(&format!("generate-data | {consumer}"));
    }
    for source in ["echo remote", "echo x >> ~/note", "echo x > /tmp/sub/out"] {
        for consumer in [
            "ssh host",
            "docker exec -i c sh",
            "kubectl exec -i pod -- sh",
        ] {
            fixture.allowed(&format!("printf '%s\\n' '{source}' | {consumer}"));
        }
    }
    fixture.allowed("printf '%s\\n' 'echo x > ~/new-note' | sh");
    fixture.allowed("printf '%s\\n' 'echo remote' | ssh host > ~/new-note");
}

#[test]
fn remote_stdin_scripts_do_not_read_local_database_files() {
    let fixture = Fixture::new();
    let sql = fixture.dir.path().join("local-benign.sql");
    std::fs::write(&sql, "SELECT 1;\n").expect("local SQL");
    let script = format!(
        "psql -X -f {}",
        shell_words::quote(sql.to_str().expect("UTF-8 path"))
    );
    let producer = format!("printf '%s\\n' {}", shell_words::quote(&script));
    fixture.allowed(&format!("{producer} | sh"));
    for consumer in [
        "ssh host",
        "docker exec -i c sh",
        "kubectl exec -i pod -- sh",
    ] {
        let command = format!("{producer} | {consumer}");
        let reason = fixture.denied(&command, "database.postgresql:stdin-unverified");
        assert!(
            reason.contains("another machine or filesystem"),
            "{command:?}: {reason}"
        );
    }
    assert_eq!(
        std::fs::read_to_string(sql).expect("local SQL survives"),
        "SELECT 1;\n"
    );
}

#[test]
fn remote_stdin_nested_dispatch_cannot_borrow_outer_local_proof() {
    let fixture = Fixture::new();
    for consumer in [
        "parallel --pipe ssh host",
        "parallel --pipe docker exec -i c sh",
        "xargs -a /dev/null ssh host",
        "parallel --pipe xargs -a /dev/null ssh host",
        "ssh host \"parallel --pipe sh -c 'sh -s'\"",
        "ssh host \"xargs -a /dev/null sh -c 'sh -s'\"",
    ] {
        fixture.denied(
            &format!("printf '%s\\n' 'echo x > ~/note' | {consumer}"),
            "heredoc.posix:pipeline-consumer",
        );
    }
    let nested = "ssh host ".repeat(32);
    fixture.denied(
        &format!("printf '%s\\n' 'rm -rf /' | {nested}sh -s"),
        "heredoc.posix:pipeline-consumer",
    );
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

#[test]
fn changed_cwd_database_file_sources_do_not_borrow_local_files() {
    let fixture = Fixture::with_shadowed_inputs();
    fixture.allowed("psql -X -f migration.sql");
    fixture.denied(
        "psql -X -f other/migration.sql",
        "database.postgresql:drop-table",
    );
    for wrapper in [
        "env -C other",
        "env -Cother",
        "env -iCother",
        "env --chdir other",
        "env --chdir=other",
        "env -u UNUSED -C other",
        "sudo -D other",
        "sudo -Dother",
        "sudo -nDother",
        "sudo -u other",
    ] {
        fixture.denied(
            &format!("{wrapper} psql -X -f migration.sql"),
            "database.postgresql:stdin-unverified",
        );
    }
}

#[test]
fn changed_cwd_file_producers_do_not_borrow_local_sql() {
    let fixture = Fixture::with_shadowed_inputs();
    fixture.allowed("cat migration.sql | psql -X");
    for producer in [
        "env -C other cat migration.sql",
        "env --chdir=other cat migration.sql",
        "env -iCother cat migration.sql",
        "sudo -D other cat migration.sql",
    ] {
        fixture.denied(
            &format!("{producer} | psql -X"),
            "database.postgresql:stdin-unverified",
        );
    }
}

#[test]
fn wrapped_consumers_keep_caller_owned_argument_substitutions() {
    let fixture = Fixture::with_shadowed_inputs();
    // Argument substitutions run in the caller's shell, before env changes
    // the client's directory. A wrapper inside the substitution changes
    // the producer's own file context instead.
    for consumer in ["env -C other psql -X", "sudo -D other psql -X"] {
        fixture.allowed(&format!("{consumer} -c \"$(cat migration.sql)\""));
        fixture.denied(
            &format!("{consumer} -c \"$(cat other/migration.sql)\""),
            "database.postgresql:drop-table",
        );
        fixture.denied(
            &format!("{consumer} -c \"$(env -C other cat migration.sql)\""),
            "database.postgresql:stdin-unverified",
        );
        fixture.allowed(&format!("{consumer} -c 'SELECT 1;'"));
        fixture.denied(
            &format!("{consumer} -c 'DROP TABLE important_data;'"),
            "database.postgresql:drop-table",
        );
    }
    fixture.denied(
        "psql -X -c \"$(env -C other cat migration.sql)\"",
        "database.postgresql:stdin-unverified",
    );
}

#[test]
fn changed_context_file_protection_is_shared_by_database_clients() {
    let fixture = Fixture::with_shadowed_inputs();
    std::fs::write(
        fixture.dir.path().join("config.toml"),
        "[history]\nenabled = false\n[packs]\nenabled = [\"core.filesystem\", \
         \"core.git\", \"database.mysql\", \"database.mongodb\", \"database.sqlite\", \
         \"database.redis\", \"database.snowflake\"]\n",
    )
    .expect("isolated multi-client configuration");
    for (pack, name, safe, dangerous, command, rule) in [
        (
            "database.mysql",
            "query.mysql",
            "SELECT 1;\n",
            "DROP TABLE important_data;\n",
            "mysql --no-defaults app -e 'source query.mysql'",
            "drop-table",
        ),
        (
            "database.mongodb",
            "query.js",
            "db.users.find({});\n",
            "db.users.drop();\n",
            "mongosh --norc --file query.js",
            "drop-collection",
        ),
        (
            "database.sqlite",
            "query.sqlite",
            "SELECT 1;\n",
            "DROP TABLE important_data;\n",
            "sqlite3 -init query.sqlite app.db 'SELECT 1;'",
            "drop-table",
        ),
        (
            "database.redis",
            "query.lua",
            "return redis.call('GET', 'account:1')\n",
            "return redis.call('FLUSHALL')\n",
            "redis-cli --eval query.lua",
            "flushall",
        ),
        (
            "database.snowflake",
            "query.snow",
            "SELECT 1;\n",
            "DROP TABLE important_data;\n",
            "snow sql -f query.snow",
            "drop-table",
        ),
    ] {
        std::fs::write(fixture.dir.path().join(name), safe).expect("local client script");
        std::fs::write(fixture.dir.path().join("other").join(name), dangerous)
            .expect("same-named client script in other directory");
        fixture.allowed(command);
        fixture.denied(
            &command.replace(name, &format!("other/{name}")),
            &format!("{pack}:{rule}"),
        );
        for wrapper in ["env -C other", "sudo -D other"] {
            fixture.denied(
                &format!("{wrapper} {command}"),
                &format!("{pack}:stdin-unverified"),
            );
        }
    }
}

#[test]
fn changed_context_consumers_preserve_local_outer_input_redirects() {
    let fixture = Fixture::with_shadowed_inputs();
    // The caller's shell opens these files before env/sudo changes the
    // consumer's context. Their bytes are still legitimate local evidence.
    for consumer in [
        "env -C other psql -X",
        "env --chdir=other psql -X",
        "sudo -D other psql -X",
        "sudo -u other psql -X",
    ] {
        fixture.allowed(&format!("{consumer} < migration.sql"));
        fixture.denied(
            &format!("{consumer} < other/migration.sql"),
            "database.postgresql:drop-table",
        );
        fixture.allowed(&format!("printf 'SELECT 1;\\n' | {consumer}"));
    }
}

#[test]
fn changed_context_sql_includes_cannot_reuse_local_root_input_proof() {
    let fixture = Fixture::with_shadowed_inputs();
    for include in [r"\i migration.sql", r"\ir migration.sql"] {
        std::fs::write(
            fixture.dir.path().join("include.sql"),
            format!("{include}\n"),
        )
        .expect("local include source");
        fixture.allowed("psql -X < include.sql");
        for consumer in ["env -C other psql -X", "sudo -D other psql -X"] {
            // The outer input is local; an include inside it is opened by
            // psql in its changed context, and must not inherit that proof.
            fixture.denied(
                &format!("{consumer} < include.sql"),
                "database.postgresql:stdin-unverified",
            );
            fixture.denied(
                &format!(
                    "printf '%s\\n' {} | {consumer}",
                    shell_words::quote(include)
                ),
                "database.postgresql:stdin-unverified",
            );
        }
    }
}

#[test]
fn identical_sql_inputs_keep_their_consumers_context_when_deduplicated() {
    let fixture = Fixture::with_shadowed_inputs();
    let producer = "printf '%s\\n' '\\i migration.sql'";
    fixture.allowed(&format!("{producer} | psql -X"));
    for command in [
        format!("{producer} | psql -X; {producer} | env -C other psql -X"),
        format!("{producer} | env -C other psql -X; {producer} | psql -X"),
    ] {
        fixture.denied(&command, "database.postgresql:stdin-unverified");
    }
}

#[test]
fn changed_user_database_startup_files_need_the_consumers_context() {
    let fixture = Fixture::new();
    std::fs::write(fixture.dir.path().join("home/.psqlrc"), "SELECT 1;\n")
        .expect("benign caller startup file");
    fixture.allowed("psql -c 'SELECT 1'");
    for wrapper in ["sudo", "sudo -u other", "sudo -H"] {
        fixture.denied(
            &format!("{wrapper} psql -c 'SELECT 1'"),
            "database.postgresql:stdin-unverified",
        );
        fixture.allowed(&format!("{wrapper} psql -X -c 'SELECT 1'"));
        fixture.allowed(&format!("{wrapper} psql --no-psqlrc -c 'SELECT 1'"));
    }
}

#[test]
fn changed_cwd_sed_program_files_do_not_borrow_local_scripts() {
    let fixture = Fixture::with_shadowed_inputs();
    fixture.allowed("sed -f program.sed input.txt");
    fixture.denied(
        "sed -f other/program.sed input.txt",
        "core.filesystem:rm-rf-root-home",
    );
    for wrapper in [
        "env -C other",
        "env --chdir=other",
        "env -iCother",
        "sudo -D other",
    ] {
        fixture.denied(
            &format!("{wrapper} sed -f program.sed input.txt"),
            "core.filesystem:sed-exec-unverified",
        );
    }
}

#[test]
fn sed_shell_escapes_inherit_the_sed_consumers_context() {
    let fixture = Fixture::with_shadowed_inputs();
    fixture.allowed("sed 'e psql -X -f migration.sql' input.txt");
    for wrapper in ["env -C other", "sudo -D other"] {
        fixture.denied(
            &format!("{wrapper} sed 'e psql -X -f migration.sql' input.txt"),
            "database.postgresql:stdin-unverified",
        );
        fixture.allowed(&format!("{wrapper} sed 'e echo safe' input.txt"));
        fixture.allowed(&format!(
            "{wrapper} sed --sandbox 'e psql -X -f migration.sql' input.txt"
        ));
    }
}

#[test]
fn nested_shell_file_consumers_inherit_changed_wrapper_context() {
    let fixture = Fixture::with_shadowed_inputs();
    for wrapper in ["env -C other", "sudo -D other"] {
        fixture.denied(
            &format!("{wrapper} sh -c 'psql -X -f migration.sql'"),
            "database.postgresql:stdin-unverified",
        );
        fixture.denied(
            &format!("{wrapper} sh -c 'sed -f program.sed input.txt'"),
            "core.filesystem:sed-exec-unverified",
        );
        // These quotes defer the substitution to the child shell, which
        // opens the file only after its wrapper has changed the directory.
        fixture.denied(
            &format!("{wrapper} sh -c 'psql -X -c \"$(cat migration.sql)\"'"),
            "database.postgresql:stdin-unverified",
        );
    }
}

#[test]
fn ordinary_wrappers_keep_local_file_evidence() {
    let fixture = Fixture::with_shadowed_inputs();
    for wrapper in ["command", "env MODE=test", "env -u UNUSED", "env --"] {
        fixture.allowed(&format!("{wrapper} psql -X -f migration.sql"));
        fixture.allowed(&format!("{wrapper} sed -f program.sed input.txt"));
    }
    // Keep the existing compound-command guard for client-owned files. A
    // preceding local redirect and a later shell's local home proof have
    // independent owners without requiring that guard to be weakened.
    fixture.allowed("psql -X < migration.sql; env -C other true");
    fixture.allowed("env -C other true; psql -X -c 'SELECT 1;'");
    fixture.allowed("sudo -D other true; sh -c 'echo x > ~/new-note'");
    assert_eq!(
        std::fs::read_to_string(fixture.dir.path().join("migration.sql")).expect("local SQL"),
        "SELECT 1;\n",
    );
    assert_eq!(
        std::fs::read_to_string(fixture.dir.path().join("other/migration.sql")).expect("other SQL"),
        "DROP TABLE important_data;\n",
    );
}

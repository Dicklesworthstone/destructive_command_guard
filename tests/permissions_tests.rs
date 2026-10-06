//! Real-hook regressions for the opt-in permissions pack. Commands below are
//! JSON input data for dcg; no permission-changing command is ever executed.

use std::fmt::Write as _;
use std::io::Write;
use std::process::{Command, Stdio};

struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new(grants: &[&str]) -> Self {
        let dir = tempfile::tempdir().expect("fixture");
        let config_dir = dir.path().join("home/config/dcg");
        std::fs::create_dir_all(&config_dir).expect("isolated user config");
        std::fs::write(
            dir.path().join("config.toml"),
            "[history]\nenabled = false\n[packs]\nenabled = [\"system.permissions\"]\n",
        )
        .expect("config");
        let mut allowlist = String::new();
        for rule in grants {
            writeln!(
                allowlist,
                "[[allow]]\nrule = \"system.permissions:{rule}\"\nreason = \"test grant\""
            )
            .expect("allowlist entry");
        }
        std::fs::write(config_dir.join("allowlist.toml"), allowlist).expect("allowlist");
        Self { dir }
    }

    fn judge(&self, command: &str) -> (String, String) {
        let home = self.dir.path().join("home");
        let input = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": command },
            "cwd": self.dir.path(),
        });
        let mut child = Command::new(env!("CARGO_BIN_EXE_dcg"))
            .arg("hook")
            .env_clear()
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("APPDATA", home.join("config"))
            .env("LOCALAPPDATA", home.join("local"))
            .env("XDG_DATA_HOME", home.join("data"))
            .env("XDG_CACHE_HOME", home.join("cache"))
            .env("TMPDIR", self.dir.path())
            .env("TMP", self.dir.path())
            .env("TEMP", self.dir.path())
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
            // These assert decisions, not latency. Keep scheduler load from
            // turning a regex fallback into an unrelated timeout decision.
            .env("DCG_HOOK_TIMEOUT_MS", "5000")
            .current_dir(self.dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn hook");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(input.to_string().as_bytes())
            .expect("hook payload");
        let output = child.wait_with_output().expect("hook result");
        assert_eq!(
            output.status.code(),
            Some(0),
            "{command:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if output.stdout.is_empty() {
            return ("allow".to_string(), String::new());
        }
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("hook JSON");
        let hook = &json["hookSpecificOutput"];
        (
            hook["permissionDecision"]
                .as_str()
                .expect("decision")
                .to_string(),
            hook["ruleId"].as_str().unwrap_or_default().to_string(),
        )
    }

    fn denied(&self, command: &str, rule: &str) {
        assert_eq!(
            self.judge(command),
            ("deny".to_string(), format!("system.permissions:{rule}")),
            "{command:?}"
        );
    }

    fn allowed(&self, command: &str) {
        assert_eq!(self.judge(command).0, "allow", "{command:?}");
    }
}

#[test]
fn recursive_options_are_recognized_in_bundles_and_after_operands() {
    let fixture = Fixture::new(&[]);
    for command in [
        "chmod --recursive 755 /etc",
        "chmod 755 --recursive /etc",
        "chmod 755 file -R /etc",
        "chmod 755 /etc -vR",
        "chmod -vR 755 /etc",
        "chmod -Rv 755 /etc",
        "chmod --rec 755 /etc",
        "sudo -u stat /usr/bin/chmod -fvR 755 /etc",
    ] {
        fixture.denied(command, "chmod-recursive-root");
    }
    for command in ["chown -vR nobody /etc", "chown nobody /etc -fRv"] {
        fixture.denied(command, "chown-recursive-root");
    }
    for command in ["chgrp -vR nogroup /etc", "chgrp nogroup /etc --recursive"] {
        fixture.denied(command, "chgrp-recursive-root");
    }
}

#[test]
fn every_chmod_target_must_qualify_for_the_relative_file_exemption() {
    let fixture = Fixture::new(&[]);
    for command in [
        "chmod 777 notes /etc/shadow",
        "chmod 777 /etc/shadow notes",
        "chmod 777 ./notes ~/.ssh/id_rsa",
        "chmod 777 notes $HOME/.ssh/id_rsa",
        "chmod 777 notes \"/etc/shadow\"",
        "chmod 777 -- harmless /etc/shadow",
        "chmod 777 notes \"$extra_targets\"",
        "chmod 0777 /etc",
    ] {
        fixture.denied(command, "chmod-777");
    }
    fixture.denied("chmod 4755 notes ~/bin/tool", "chmod-setuid");
    fixture.denied("chmod 2755 notes /usr/bin/tool", "chmod-setgid");
}

#[test]
fn safe_looking_reference_values_cannot_exempt_the_running_command() {
    let fixture = Fixture::new(&[]);
    for (command, rule) in [
        (
            "chmod -R --reference=\"chmod 777 notes\" /etc",
            "chmod-recursive-root",
        ),
        (
            "chmod --reference 'chmod 777 notes' /etc -vR",
            "chmod-recursive-root",
        ),
        (
            "chown -vR --reference=\"chmod 777 notes\" /etc",
            "chown-recursive-root",
        ),
        (
            "chgrp -vR --reference 'chmod 777 notes' /etc",
            "chgrp-recursive-root",
        ),
        (
            "chmod -vR --reference=\"/opt/a&b\" /etc",
            "chmod-recursive-root",
        ),
        ("chown -vR --from=root nobody /etc", "chown-recursive-root"),
    ] {
        fixture.denied(command, rule);
    }
}

#[test]
fn option_values_and_arguments_after_double_dash_keep_their_roles() {
    let fixture = Fixture::new(&[]);
    for command in [
        "chmod 644 ./notes -- -R /etc",
        "chmod -- -r /etc",
        "chmod --reference='-vR' /etc",
        "chmod -vR --reference=/etc/passwd ./project",
        "chmod -R --reference /etc harmless",
        "chown -vR --reference=/etc/passwd ./project",
        "chown --from=-vR nobody /etc",
        "chown --from root nobody /tmp/file",
        "chgrp --reference '-vR' /etc",
        "chgrp staff -- -vR /etc",
    ] {
        fixture.allowed(command);
    }
}

#[test]
fn routine_relative_files_and_home_project_carve_outs_are_preserved() {
    let fixture = Fixture::new(&[]);
    for command in [
        "chmod 644 file_777",
        "chmod -R 644 file_777",
        "chmod 777 notes.txt",
        "chmod 4755 notes.txt",
        "chmod u+x ./script.sh",
        "chmod 644 notes /etc/shadow",
        "chmod 600 ~/.ssh/id_rsa",
        "chmod -vR 755 /home/user/project",
        "chmod -vR 755 ~/project",
        "chmod -vR 755 $HOME/project",
        "chown -vR nobody /home/user/project",
        "chgrp -vR staff /Users/user/project",
        "chmod -vR 000 '~'",
        "chmod -vR 000 '$HOME'",
    ] {
        fixture.allowed(command);
    }
    fixture.denied("chmod -vR 000 ~", "chmod-recursive-root");
    fixture.denied("chown -vR nobody \"$HOME\"", "chown-recursive-root");
    fixture.denied("chgrp -vR staff /Users/user", "chgrp-recursive-root");
}

#[test]
fn granting_one_permissions_rule_does_not_grant_an_independent_hit() {
    let world_writable_grant = Fixture::new(&["chmod-777"]);
    world_writable_grant.denied("chmod -vR 777 /etc", "chmod-recursive-root");
    world_writable_grant.allowed("chmod 777 /tmp/file");

    let setuid_grant = Fixture::new(&["chmod-setuid"]);
    setuid_grant.denied("chmod 6755 /etc/file", "chmod-setgid");
    setuid_grant.allowed("chmod 4755 /tmp/file");

    let both_grants = Fixture::new(&["chmod-777", "chmod-recursive-root"]);
    both_grants.allowed("chmod -vR 777 /etc");
    both_grants.denied("chown -vR nobody /etc", "chown-recursive-root");
}

#[test]
fn fallback_and_compound_commands_do_not_restore_the_old_exemption() {
    let fixture = Fixture::new(&[]);
    fixture.denied(
        "chmod -vR $(cat modes.txt | head -1) /etc",
        "chmod-recursive-root",
    );
    fixture.denied("true && chmod 755 notes -vR /etc", "chmod-recursive-root");
    fixture.denied("chmod 755 notes; chmod 777 /etc/shadow", "chmod-777");
    fixture.allowed("chmod 600 /root/key; grep -R foo /etc");
    fixture.allowed("printf '%s' 'chmod -vR 755 /etc'");
}

#[test]
fn fallback_keeps_decoding_the_executable_without_proving_safety_from_masked_argv() {
    let fixture = Fixture::new(&[]);
    for executable in [r"ch$'mod'", "'chmod'", "ch\"mod\"", r"ch\mod"] {
        fixture.denied(
            &format!("{executable} -R 755 /etc \"$extra_targets\""),
            "chmod-recursive-root",
        );
        fixture.denied(
            &format!("{executable} 777 notes \"$extra_targets\""),
            "chmod-777",
        );
    }
    fixture.denied("ch$'mod' 777 /etc/shadow", "chmod-777");
    fixture.denied("ch$'own' -R nobody /etc", "chown-recursive-root");
    fixture.denied("ch$'grp' -R staff /etc", "chgrp-recursive-root");
    fixture.denied(
        "sudo -u stat '/usr/bin/chmod' -R 755 /etc \"$extra_targets\"",
        "chmod-recursive-root",
    );
    fixture.allowed("ch$'mod' 600 /root/key; grep -R foo /etc");
    fixture.allowed(r#"printf '%s' "ch\$'mod' -R 755 /etc""#);
}

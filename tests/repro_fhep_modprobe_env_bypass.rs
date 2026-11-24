//! bd-modprobe-env-option-bypass-fhep: `MODPROBE_OPTIONS` and
//! `POSIXLY_CORRECT` leading env assignments (bare or through `env`/`sudo`)
//! must be folded into `modprobe` before `system.services` evaluates the
//! command, without breaking benign dry-run or load commands.
//!
//! Exercises the real compiled `dcg` binary through both `dcg test` (posix and
//! unknown dialects, heredoc extractor on and off) and the PreToolUse hook JSON
//! stdin protocol. No kernel operation runs: commands are only classified.

use std::io::Write;
use std::process::{Command, Stdio};

const BENIGN_ALLOW_CONTROLS: &[&str] = &[
    "FOO=bar modprobe nvidia",
    "MODPROBE_OPTIONS=-n modprobe nvidia",
    "MODPROBE_OPTIONS=\"-r -n\" modprobe nvidia",
    "MODPROBE_OPTIONS=\"-n -r\" modprobe nvidia",
    "MODPROBE_OPTIONS=--dry-run modprobe nvidia",
    "MODPROBE_OPTIONS=\"--show -r\" modprobe nvidia",
    "MODPROBE_OPTIONS=-n modprobe -r nvidia",
    "MODPROBE_OPTIONS=-r modprobe -n nvidia",
    "MODPROBE_OPTIONS=\"\" modprobe nvidia",
    "MODPROBE_OPTIONS=-v modprobe nvidia",
    "MODPROBE_OPTIONS=\"--config=/etc/modprobe.conf -r -n\" modprobe nvidia",
    "MODPROBE_OPTIONS=-r MODPROBE_OPTIONS=-n modprobe nvidia",
    "MODPROBE_OPTIONS=-r env -u MODPROBE_OPTIONS modprobe nvidia",
    "MODPROBE_OPTIONS=-r env -i modprobe nvidia",
    "POSIXLY_CORRECT=1 modprobe -n -r nvidia",
    "POSIXLY_CORRECT=$(echo 1) modprobe -n -r nvidia",
    "POSIXLY_CORRECT=1 modprobe -r -n nvidia",
    "POSIXLY_CORRECT=1 modprobe --dry-run -r nvidia",
    "POSIXLY_CORRECT=1 modprobe -C /etc/modprobe.conf -n -r nvidia",
    "POSIXLY_CORRECT=1 modprobe --config=/etc/modprobe.conf -n -r nvidia",
    "POSIXLY_CORRECT=1 modprobe --config /etc/modprobe.conf -n -r nvidia",
    "POSIXLY_CORRECT=1 modprobe nvidia",
    "POSIXLY_CORRECT=1 MODPROBE_OPTIONS=\"-r -n\" modprobe nvidia",
    "POSIXLY_CORRECT=1 MODPROBE_OPTIONS=-n modprobe -r nvidia",
    "echo ok && MODPROBE_OPTIONS=-n modprobe -r nvidia",
    "echo ok && MODPROBE_OPTIONS=\"-r -n\" modprobe nvidia",
    "echo ok && POSIXLY_CORRECT=1 modprobe -n -r nvidia",
    "POSIXLY_CORRECT=1 ls -la /tmp",
];

const DESTRUCTIVE_DENY_CONTROLS: &[&str] = &[
    "MODPROBE_OPTIONS=-r modprobe nvidia",
    "MODPROBE_OPTIONS=--remove modprobe nvidia",
    "MODPROBE_OPTIONS=\"--remove\" modprobe nvidia",
    "MODPROBE_OPTIONS=\"--remove-dependencies\" modprobe nvidia",
    "MODPROBE_OPTIONS=\"--remove-holders\" modprobe nvidia",
    "MODPROBE_OPTIONS=\"-rv\" modprobe nvidia",
    "MODPROBE_OPTIONS='-r' modprobe nvidia",
    "MODPROBE_OPTIONS=\"--config=/etc/modprobe.conf -r\" modprobe nvidia",
    "MODPROBE_OPTIONS=-C modprobe -n -r nvidia",
    "MODPROBE_OPTIONS=\"-r --\" modprobe -n nvidia",
    "MODPROBE_OPTIONS=-n MODPROBE_OPTIONS=-r modprobe nvidia",
    "FOO=bar MODPROBE_OPTIONS=-r BAZ=qux modprobe nvidia",
    "env MODPROBE_OPTIONS=-r modprobe nvidia",
    "env -i MODPROBE_OPTIONS=-r modprobe nvidia",
    "env -- MODPROBE_OPTIONS=-r modprobe nvidia",
    "env -S \"MODPROBE_OPTIONS=-r modprobe nvidia\"",
    "sudo env MODPROBE_OPTIONS=-r modprobe nvidia",
    "sudo MODPROBE_OPTIONS=-r modprobe nvidia",
    "sudo -u root MODPROBE_OPTIONS=-r modprobe nvidia",
    "MODPROBE_OPTIONS=-r sudo -E modprobe nvidia",
    "MODPROBE_OPTIONS=-r /sbin/modprobe nvidia",
    "MODPROBE_OPTIONS=-r /usr/sbin/modprobe nvidia",
    "MODPROBE_OPTIONS=-r \"modprobe\" nvidia",
    "MODPROBE_OPTIONS=-r \\modprobe nvidia",
    "POSIXLY_CORRECT=1 modprobe -r nvidia -n",
    "POSIXLY_CORRECT=1 modprobe -r nvidia --dry-run",
    "POSIXLY_CORRECT=1 modprobe -r nvidia --show",
    "POSIXLY_CORRECT= modprobe -r nvidia -n",
    "POSIXLY_CORRECT=$(echo 1) modprobe -r nvidia -n",
    "POSIXLY_CORRECT=1 env modprobe -r nvidia -n",
    "env POSIXLY_CORRECT=1 modprobe -r nvidia -n",
    "POSIXLY_CORRECT=1 /usr/sbin/modprobe -r nvidia -n",
    "POSIXLY_CORRECT=1 modprobe -C /etc/modprobe.conf -r nvidia -n",
    "POSIXLY_CORRECT=1 modprobe --conf /etc/modprobe.conf -r nvidia -n",
    "POSIXLY_CORRECT=1 modprobe --rem nvidia -n",
    "POSIXLY_CORRECT=1 modprobe --remove-h nvidia -n",
    "POSIXLY_CORRECT=1 modprobe --remove-d nvidia -n",
    "POSIXLY_CORRECT=1 MODPROBE_OPTIONS=\"--rem\" modprobe nvidia -n",
    "POSIXLY_CORRECT=1 MODPROBE_OPTIONS=-r modprobe nvidia -n",
    "POSIXLY_CORRECT=1 MODPROBE_OPTIONS=\"-r nvidia\" modprobe -n",
    "echo ok && MODPROBE_OPTIONS=-r modprobe nvidia",
    "echo ok; POSIXLY_CORRECT=1 modprobe -r nvidia -n",
];

const NESTED_DENY_CONTROLS: &[&str] = &[
    "ssh gpu-host MODPROBE_OPTIONS=-r modprobe nvidia",
    "ssh gpu-host 'MODPROBE_OPTIONS=-r modprobe nvidia'",
    "ssh gpu-host 'POSIXLY_CORRECT=1 modprobe -r nvidia -n'",
    "bash -c 'MODPROBE_OPTIONS=-r modprobe nvidia'",
    "bash -c 'POSIXLY_CORRECT=1 modprobe -r nvidia -n'",
];

fn dcg_test_verdict(command: &str, dialect: &str, heredoc: bool) -> serde_json::Value {
    let scratch = tempfile::tempdir().expect("scratch dir");
    let home = scratch.path().join("home");
    std::fs::create_dir_all(&home).expect("isolated home");
    let config = scratch.path().join("config.toml");
    let settings = if heredoc {
        "[heredoc]\nenabled = true\ntimeout_ms = 5000\n"
    } else {
        "[heredoc]\nenabled = false\n"
    };
    std::fs::write(&config, settings).expect("write config");
    let output = Command::new(env!("CARGO_BIN_EXE_dcg"))
        .args(["test", "--config"])
        .arg(&config)
        .args(["--with-packs", "system.services", "--dialect", dialect])
        .args(["--format", "json", command])
        .env_clear()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("DCG_HISTORY_DISABLED", "1")
        .env("DCG_AST_TIMEOUT_MS", "5000")
        .env("DCG_CUSTOM_PATHS", "")
        .current_dir(scratch.path())
        .output()
        .expect("run dcg test");
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{command:?} {dialect} heredoc={heredoc}: {error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
    })
}

fn hook_denies_bash(command: &str) -> (bool, String) {
    let scratch = tempfile::tempdir().expect("scratch dir");
    let home = scratch.path().join("home");
    std::fs::create_dir_all(&home).expect("isolated home");
    let config = scratch.path().join("config.toml");
    std::fs::write(
        &config,
        "[packs]\nenabled = [\"system.services\"]\n\n[heredoc]\nenabled = true\ntimeout_ms = 5000\n",
    )
    .expect("write config");
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcg"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("DCG_CONFIG", &config)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("DCG_HISTORY_DISABLED", "1")
        .env("DCG_AST_TIMEOUT_MS", "5000")
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .env("DCG_CUSTOM_PATHS", "")
        .current_dir(scratch.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcg hook");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(payload.to_string().as_bytes())
        .expect("write hook json");
    let output = child.wait_with_output().expect("wait dcg hook");
    assert!(
        output.status.success(),
        "hook failed for {command:?}: status={:?} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let denied = stdout.contains("\"permissionDecision\":\"deny\"");
    (denied, stdout)
}

#[test]
fn modprobe_env_benign_controls_stay_allowed_in_cli_and_hook() {
    for command in BENIGN_ALLOW_CONTROLS {
        for dialect in ["posix", "unknown"] {
            for heredoc in [true, false] {
                let verdict = dcg_test_verdict(command, dialect, heredoc);
                assert_eq!(
                    verdict["decision"].as_str(),
                    Some("allow"),
                    "{command:?} {dialect} heredoc={heredoc}: {verdict}"
                );
            }
        }
        let (denied, stdout) = hook_denies_bash(command);
        assert!(
            !denied,
            "hook must allow benign {command:?}, got stdout={stdout}"
        );
    }
}

#[test]
fn modprobe_env_option_bypasses_are_denied_in_cli_and_hook() {
    for command in DESTRUCTIVE_DENY_CONTROLS {
        for dialect in ["posix", "unknown"] {
            for heredoc in [true, false] {
                let verdict = dcg_test_verdict(command, dialect, heredoc);
                assert_eq!(
                    verdict["decision"].as_str(),
                    Some("deny"),
                    "{command:?} {dialect} heredoc={heredoc}: {verdict}"
                );
                assert_eq!(
                    verdict["rule_id"].as_str(),
                    Some("system.services:modprobe-remove"),
                    "{command:?} {dialect} heredoc={heredoc}: {verdict}"
                );
            }
        }
        let (denied, stdout) = hook_denies_bash(command);
        assert!(denied, "hook must deny {command:?}, got stdout={stdout}");
    }

    for command in NESTED_DENY_CONTROLS {
        for dialect in ["posix", "unknown"] {
            let verdict = dcg_test_verdict(command, dialect, true);
            assert_eq!(
                verdict["decision"].as_str(),
                Some("deny"),
                "{command:?} {dialect}: {verdict}"
            );
            assert_eq!(
                verdict["rule_id"].as_str(),
                Some("system.services:modprobe-remove"),
                "{command:?} {dialect}: {verdict}"
            );
        }
        let (denied, stdout) = hook_denies_bash(command);
        assert!(
            denied,
            "hook must deny nested {command:?}, got stdout={stdout}"
        );
    }
}

#[test]
fn modprobe_sudo_env_reset_quoted_argv0_and_vtab_regressions() {
    // FE1: sudo env_reset vs env_keep deny-wins, FE2: quoted/escaped argv0 after
    // POSIXLY_CORRECT=$(...), FE3: C isspace() vertical tab (`\x0b`) in MODPROBE_OPTIONS.
    let must_deny = [
        "MODPROBE_OPTIONS=-n sudo modprobe -r nvidia",
        r#"MODPROBE_OPTIONS="-n -r" sudo modprobe -r nvidia"#,
        "MODPROBE_OPTIONS=-r sudo modprobe nvidia",
        "MODPROBE_OPTIONS=-r sudo --preserve-env modprobe nvidia",
        "MODPROBE_OPTIONS=-r sudo --preserve-env=MODPROBE_OPTIONS modprobe nvidia",
        "MODPROBE_OPTIONS=-n sudo --preserve-env=PATH modprobe -r nvidia",
        "MODPROBE_OPTIONS=-C sudo modprobe -C -n -r nvidia",
        "sudo -u root MODPROBE_OPTIONS=-r modprobe nvidia",
        "sudo --user=root modprobe -r nvidia",
        "POSIXLY_CORRECT=1 sudo modprobe nvidia -r",
        "POSIXLY_CORRECT=1 sudo modprobe -r nvidia -n",
        "echo ok && MODPROBE_OPTIONS=-n sudo modprobe -r nvidia",
        "POSIXLY_CORRECT=$(echo 1) 'mod'probe -r nvidia -n",
        r"POSIXLY_CORRECT=$(echo 1) m\odprobe -r nvidia -n",
        "MODPROBE_OPTIONS=\"\x0b-r\" modprobe nvidia",
        "MODPROBE_OPTIONS=$'\\x0b-r' modprobe nvidia",
    ];
    for command in must_deny {
        for dialect in ["posix", "unknown"] {
            let verdict = dcg_test_verdict(command, dialect, true);
            assert_eq!(
                verdict["decision"].as_str(),
                Some("deny"),
                "{command:?} {dialect}: {verdict}"
            );
            assert_eq!(
                verdict["rule_id"].as_str(),
                Some("system.services:modprobe-remove"),
                "{command:?} {dialect}: {verdict}"
            );
        }
        let (denied, stdout) = hook_denies_bash(command);
        assert!(denied, "hook must deny {command:?}, got stdout={stdout}");
    }

    // Benign negative controls: explicit `-E` / `--preserve-env` covering the var
    // or dry-run via vertical-tab-separated `-n`.
    let must_allow = [
        "MODPROBE_OPTIONS=-n sudo -E modprobe -r nvidia",
        "MODPROBE_OPTIONS=-n sudo --preserve-env modprobe -r nvidia",
        "MODPROBE_OPTIONS=-n sudo --preserve-env=MODPROBE_OPTIONS modprobe -r nvidia",
        "MODPROBE_OPTIONS=\"\x0b-n\" modprobe -r nvidia",
    ];
    for command in must_allow {
        for dialect in ["posix", "unknown"] {
            let verdict = dcg_test_verdict(command, dialect, true);
            assert_eq!(
                verdict["decision"].as_str(),
                Some("allow"),
                "benign control must allow {command:?} {dialect}: {verdict}"
            );
        }
        let (denied, stdout) = hook_denies_bash(command);
        assert!(
            !denied,
            "hook must allow benign {command:?}, got stdout={stdout}"
        );
    }
}

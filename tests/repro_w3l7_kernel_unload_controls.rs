//! bd-w3l7: the kernel-module unload rules (`system.services`) must block real
//! unloads, locally and over ssh, without blocking commands that unload nothing.
//!
//! Three false positives were reported against the rules as first written:
//! `modprobe -n -v -r <module>`, the dry run the rule's own explanation
//! recommends; `rmmod --help` and `rmmod --version`; and ssh commands whose
//! remote program only prints unload syntax (`ssh host echo rmmod x`).
//!
//! These tests drive the real binary under both shell dialects, with the
//! heredoc extractor on and off. The extractor normally lifts the ssh remote
//! command out, so `modprobe-remove` or `rmmod` answers. With it off, only the
//! `ssh-remote-module-unload` backstop can see that command, and it must still
//! tell a remote unloader from remote text. No kernel operation runs: the
//! commands are only classified.

use std::process::Command;

const ALLOW_CONTROLS: &[&str] = &[
    "modprobe -n -v -r nvidia",
    "sudo modprobe -nvr nvidia",
    "modprobe --dry-run --remove nvidia",
    "modprobe -C /etc/modprobe.conf -n -r nvidia",
    "rmmod --help",
    "sudo rmmod --version",
    "ssh gpu-host echo modprobe -r nvidia",
    "ssh gpu-host echo rmmod nvidia",
    "ssh gpu-host 'echo rmmod nvidia'",
    "ssh gpu-host modprobe -n -v -r nvidia",
    "ssh gpu-host sudo rmmod --help",
    "ssh -l rmmod gpu-host lsmod",
    "lsmod",
    "modinfo nvidia",
];

const DENY_CONTROLS: &[&str] = &[
    "modprobe -r nvidia",
    "sudo modprobe -rf amdgpu",
    "modprobe -C -n -r nvidia",
    "modprobe -r nvidia -- -n",
    "modprobe -n -r nvidia; modprobe -r nvidia",
    "rmmod nvidia_drm",
    "sudo rmmod --help nvidia",
    "ssh gpu-host sudo modprobe -r nvidia",
    "ssh -p 22 gpu-host rmmod nvidia",
    "ssh gpu-host -t -- sudo -n rmmod nvidia",
    "ssh -l rmmod gpu-host modprobe -r nvidia",
];

/// A quoted remote command is argument data to the pattern layer, which sees
/// it masked. Only the extractor reads inside the quotes, so these are denied
/// with it on. With it off they were allowed before this change too.
const QUOTED_SSH_DENY_CONTROLS: &[&str] = &[
    "ssh gpu-host 'sudo modprobe -r nvidia'",
    "ssh gpu-host \"rmmod nvidia\"",
];

fn verdict(command: &str, dialect: &str, heredoc: bool) -> serde_json::Value {
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
        // The system layer (`/etc/dcg/config.toml`) is always read, and a host
        // may load its own kernel-module pack through `packs.custom_paths`.
        // The environment replaces that list, so only the built-in rules answer.
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

fn for_each_mode(mut check: impl FnMut(&str, bool)) {
    for dialect in ["posix", "unknown"] {
        for heredoc in [true, false] {
            check(dialect, heredoc);
        }
    }
}

#[test]
fn non_mutating_module_commands_and_remote_text_are_allowed() {
    for_each_mode(|dialect, heredoc| {
        for command in ALLOW_CONTROLS {
            let verdict = verdict(command, dialect, heredoc);
            assert_eq!(
                verdict["decision"].as_str(),
                Some("allow"),
                "{command:?} {dialect} heredoc={heredoc}: {verdict}"
            );
        }
    });
}

#[test]
fn real_module_unloads_stay_denied_locally_and_over_ssh() {
    for_each_mode(|dialect, heredoc| {
        let quoted: &[&str] = if heredoc {
            QUOTED_SSH_DENY_CONTROLS
        } else {
            &[]
        };
        for command in DENY_CONTROLS.iter().chain(quoted) {
            let verdict = verdict(command, dialect, heredoc);
            assert_eq!(
                verdict["decision"].as_str(),
                Some("deny"),
                "{command:?} {dialect} heredoc={heredoc}: {verdict}"
            );
            let rule = verdict["rule_id"].as_str().unwrap_or_default();
            assert!(
                rule.starts_with("system.services:"),
                "{command:?} {dialect} heredoc={heredoc}: unexpected rule {rule:?}"
            );
        }
    });
}

/// With the extractor off, the ssh rule is the only one that sees the remote
/// command, so a deny there proves the backstop itself still works.
#[test]
fn ssh_backstop_answers_when_the_remote_command_is_not_extracted() {
    for command in [
        "ssh gpu-host sudo modprobe -r nvidia",
        "ssh -p 22 gpu-host rmmod nvidia",
        "ssh -l rmmod gpu-host modprobe -r nvidia",
    ] {
        for dialect in ["posix", "unknown"] {
            let verdict = verdict(command, dialect, false);
            assert_eq!(
                verdict["rule_id"].as_str(),
                Some("system.services:ssh-remote-module-unload"),
                "{command:?} {dialect}: {verdict}"
            );
        }
    }
}

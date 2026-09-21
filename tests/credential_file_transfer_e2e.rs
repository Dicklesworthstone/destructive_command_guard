//! #461: copies and renames are inspected through the hook and CLI.
//! Candidate programs are never executed; dcg receives them only as text.

#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn home() -> tempfile::TempDir {
    let home = tempfile::tempdir().expect("isolated home");
    fs::create_dir_all(home.path().join("xdg/dcg")).expect("config directory");
    fs::write(home.path().join("config.toml"), "").expect("empty config");
    home
}

fn dcg(home: &Path) -> Command {
    let mut process = Command::new(env!("CARGO_BIN_EXE_dcg"));
    // Scrub only the child's environment. No process-wide set_var/unsafe,
    // and an inherited bypass cannot make a false allow appear correct.
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("DCG_") {
            process.env_remove(name);
        }
    }
    process
        .current_dir(home)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join("xdg"))
        .env("DCG_CONFIG", home.join("config.toml"))
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_PENDING_EXCEPTIONS_PATH", home.join("pending.jsonl"))
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("DCG_HOOK_TIMEOUT_MS", "30000")
        .env("DCG_AST_TIMEOUT_MS", "5000");
    process
}

fn assert_decision(command: &str, home: &Path, rule: Option<&str>) {
    let payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command }
    });
    let mut hook = dcg(home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hook");
    hook.stdin
        .take()
        .expect("hook stdin")
        .write_all(payload.to_string().as_bytes())
        .expect("send candidate text");
    let output = hook.wait_with_output().expect("hook response");
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 hook output");
    assert!(
        output.status.success(),
        "{command}: {stdout}; {}",
        String::from_utf8_lossy(&output.stderr)
    );
    if let Some(rule) = rule {
        let json: serde_json::Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|error| panic!("{command}: {error}; {stdout}"));
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"], "deny",
            "{command}: {stdout}"
        );
        assert!(stdout.contains(rule), "{command}: wrong rule: {stdout}");
    } else {
        assert!(stdout.trim().is_empty(), "{command}: {stdout}");
    }

    let output = dcg(home)
        .args(["test", "--format", "json", command])
        .output()
        .expect("CLI response");
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 CLI output");
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|error| {
        panic!(
            "{command}: {error}; {stdout}; {}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    assert_eq!(
        output.status.code(),
        Some(i32::from(rule.is_some())),
        "{command}: {stdout}"
    );
    assert_eq!(
        json["decision"],
        if rule.is_some() { "deny" } else { "allow" },
        "{command}: {stdout}"
    );
    if let Some(rule) = rule {
        assert_eq!(json["pack_id"], "core.filesystem", "{command}: {stdout}");
        assert_eq!(json["pattern_name"], rule, "{command}: {stdout}");
    }
}

fn assert_program(exe: &str, source: &str, home: &Path, rule: Option<&str>) {
    let flag = if exe == "python3" { "-c" } else { "-e" };
    let quoted = format!("'{}'", source.replace('\'', "'\\''"));
    for command in [
        format!("{exe} {flag} {quoted}"),
        format!("{exe} <<'DCG_TRANSFER_SOURCE'\n{source}\nDCG_TRANSFER_SOURCE"),
    ] {
        assert_decision(&command, home, rule);
    }
}

#[test]
fn transfer_destinations_reach_both_entry_points() {
    let home = home();
    for (target, rule) in [
        ("/home/u/.ssh/authorized_keys", "credential-file-write"),
        ("/etc/shadow", "credential-file-write"),
        (".git/config", "git-internals-write"),
        ("/home/u/.ssh/known_hosts", "credential-file-write"),
    ] {
        for (exe, source) in [
            (
                "python3",
                format!("import os; os.replace('staged', '{target}')"),
            ),
            (
                "python3",
                format!("from os import rename as install; install(dst='{target}', src='staged')"),
            ),
            (
                "python3",
                format!("from shutil import copyfile as save; save('staged', '{target}')"),
            ),
            (
                "python3",
                format!("from pathlib import Path; Path('staged').replace(target='{target}')"),
            ),
            (
                "node",
                format!("require('fs').renameSync('staged', '{target}')"),
            ),
            (
                "node",
                format!(
                    "const {{copyFileSync: save}} = require('node:fs'); save('staged', '{target}')"
                ),
            ),
            (
                "node",
                format!("require('fs/promises').copyFile('staged', '{target}')"),
            ),
            ("ruby", format!("File.rename('staged', '{target}')")),
            ("ruby", format!("IO.copy_stream('staged', '{target}')")),
        ] {
            assert_program(exe, &source, home.path(), Some(rule));
        }
    }
}

#[test]
fn copying_out_is_a_read_but_renaming_out_mutates_the_source() {
    let home = home();
    for (exe, source) in [
        (
            "python3",
            "import shutil; shutil.copyfile('.bashrc', 'backup.txt')",
        ),
        (
            "node",
            "require('fs').copyFileSync('.git/config', 'backup.txt')",
        ),
        ("ruby", "IO.copy_stream('.ssh/id_rsa', 'backup.txt')"),
    ] {
        assert_program(exe, source, home.path(), None);
    }
    for (exe, source) in [
        ("python3", "import os; os.replace('.bashrc', 'backup.txt')"),
        ("node", "require('fs').renameSync('.bashrc', 'backup.txt')"),
        ("ruby", "File.rename('.bashrc', 'backup.txt')"),
        (
            "python3",
            "import shutil; shutil.copyfile(source, '.bashrc')",
        ),
        ("node", "require('fs').renameSync('.bashrc', destination)"),
    ] {
        assert_program(exe, source, home.path(), Some("credential-file-write"));
    }
}

#[test]
fn one_rename_requires_permission_for_both_rule_families() {
    for (allowed, denied) in [
        ("credential-file-write", "git-internals-write"),
        ("git-internals-write", "credential-file-write"),
    ] {
        let home = home();
        fs::write(
            home.path().join("xdg/dcg/allowlist.toml"),
            format!("[[allow]]\nrule = \"core.filesystem:{allowed}\"\nreason = \"reviewed only one rule\"\n"),
        )
        .expect("rule allowlist");
        for (source, destination) in [(".bashrc", ".git/config"), (".git/config", ".bashrc")] {
            for (exe, program) in [
                (
                    "python3",
                    format!("import os; os.replace('{source}', '{destination}')"),
                ),
                (
                    "node",
                    format!("require('fs').renameSync('{source}', '{destination}')"),
                ),
                ("ruby", format!("File.rename('{source}', '{destination}')")),
            ] {
                assert_program(exe, &program, home.path(), Some(denied));
            }
        }
    }
}

#[test]
fn inert_text_unrelated_receivers_and_real_append_remain_allowed() {
    let home = home();
    for (exe, source) in [
        ("python3", "print(\"os.replace('staged', '.bashrc')\")"),
        (
            "python3",
            "import shutil; shutil = store; shutil.copyfile('staged', '.bashrc')",
        ),
        (
            "node",
            "const fs = require('unrelated'); fs.renameSync('staged', '.bashrc')",
        ),
        ("ruby", "puts \"File.rename('staged', '.bashrc')\""),
        ("ruby", "Store.rename('staged', '.bashrc')"),
        (
            "python3",
            "open('/home/u/.ssh/known_hosts', 'a').write('host')",
        ),
        (
            "node",
            "require('fs').appendFileSync('/home/u/.ssh/known_hosts', 'host')",
        ),
    ] {
        assert_program(exe, source, home.path(), None);
    }
    assert_decision(
        "cat <<'DATA'\nimport os; os.replace('staged', '.bashrc')\nDATA",
        home.path(),
        None,
    );
}

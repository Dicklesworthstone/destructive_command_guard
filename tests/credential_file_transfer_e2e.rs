//! #461: copies and renames are inspected through the hook and CLI.
//! Candidate programs are never executed; dcg receives them only as text.

#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

#[test]
fn opaque_ruby_options_cannot_suppress_hook_or_cli_writes() {
    let home = home();
    for (source, rule) in [
        (
            "File.open('.bashrc', 'w', **options)",
            Some("credential-file-write"),
        ),
        (
            "File.open('.ssh/known_hosts', 'a', **options)",
            Some("credential-file-write"),
        ),
        (
            "File.open('.bashrc', flags: File::WRONLY, **options)",
            Some("credential-file-write"),
        ),
        (
            "File.open('.git/config', 'w', **options)",
            Some("git-internals-write"),
        ),
        (
            "File.open('/etc/shadow', **options, mode: 'r', flags: File::RDONLY)",
            None,
        ),
        (
            "File.open('.ssh/known_hosts', **options, mode: 'a', flags: File::NONBLOCK)",
            None,
        ),
        ("File.open('/etc/shadow', 'r', **options)", None),
        ("File.open('/tmp/proposal', 'w', **options)", None),
    ] {
        assert_program("ruby", source, home.path(), rule);
    }
}

fn assert_link_cases(exe: &str, cases: &[(&str, Option<&str>)]) {
    for settings in [
        "[heredoc]\nenabled = true\ntimeout_ms = 5000\n",
        "[heredoc]\nenabled = true\ntimeout_ms = 0\n",
        "[heredoc]\nenabled = false\n",
    ] {
        let home = home();
        fs::write(home.path().join("config.toml"), settings).unwrap();
        for &(source, rule) in cases {
            assert_program(exe, source, home.path(), rule);
            let quoted = format!("'{}'", source.replace('\'', "'\\''"));
            assert_decision(&format!("env {exe} - 0<<< {quoted}"), home.path(), rule);
        }
    }
}

#[test]
fn python_link_creation_reaches_hook_cli_and_stdin() {
    assert_link_cases(
        "python3",
        &[
            (
                "import os; os.symlink('staged', '.bashrc')",
                Some("credential-file-write"),
            ),
            (
                "from os import link as publish; publish(src=unknown, dst='.ssh/known_hosts')",
                Some("credential-file-write"),
            ),
            (
                "from pathlib import Path; (Path.home() / '.bashrc').hardlink_to(target='staged')",
                Some("credential-file-write"),
            ),
            (
                "from pathlib import Path; publish = Path('.git/config').symlink_to; publish(source)",
                Some("git-internals-write"),
            ),
            (
                "import os; os.symlink('staged', '/home/u/.aws', target_is_directory=True)",
                Some("credential-file-write"),
            ),
            (
                "import os; os.symlink('staged', '.git', target_is_directory=True)",
                Some("git-internals-write"),
            ),
            ("import os; os.link('.bashrc', '/tmp/alias')", None),
            (
                "from pathlib import Path; Path('/tmp/alias').symlink_to('.bashrc')",
                None,
            ),
            ("import os; os.symlink('staged', '~/.bashrc')", None),
            ("print(\"os.symlink('staged', '.bashrc')\")", None),
        ],
    );
}

#[test]
fn node_link_creation_reaches_hook_cli_and_stdin() {
    assert_link_cases(
        "node",
        &[
            (
                "require('fs').symlinkSync('staged', '.bashrc')",
                Some("credential-file-write"),
            ),
            (
                "const {linkSync: publish} = require('node:fs'); publish(source, '.ssh/known_hosts')",
                Some("credential-file-write"),
            ),
            (
                "require('fs/promises').link('staged', '.git/config')",
                Some("git-internals-write"),
            ),
            (
                "require('fs').symlinkSync('staged', require('path').join(require('os').homedir(), '.aws'), 'dir')",
                Some("credential-file-write"),
            ),
            (
                "require('fs').symlinkSync('staged', '.git', 'dir')",
                Some("git-internals-write"),
            ),
            ("require('fs').linkSync('.bashrc', '/tmp/alias')", None),
            (
                "require('fs').symlinkSync('/home/u/.aws', '/tmp/alias')",
                None,
            ),
            ("require('fs').symlinkSync('staged', '~/.bashrc')", None),
            (
                "const fs = require('unrelated'); fs.symlinkSync('staged', '.bashrc')",
                None,
            ),
        ],
    );
}

#[test]
fn ruby_link_creation_reaches_hook_cli_and_stdin() {
    assert_link_cases(
        "ruby",
        &[
            (
                "File.symlink('staged', '.bashrc')",
                Some("credential-file-write"),
            ),
            (
                "F = File; F.link(source, '.ssh/known_hosts')",
                Some("credential-file-write"),
            ),
            (
                "File.link('staged', '.git/config')",
                Some("git-internals-write"),
            ),
            (
                "File.symlink('staged', File.join(Dir.home, '.aws'))",
                Some("credential-file-write"),
            ),
            (
                "File.symlink('staged', '.git')",
                Some("git-internals-write"),
            ),
            ("File.link('.bashrc', '/tmp/alias')", None),
            ("File.symlink('/home/u/.aws', '/tmp/alias')", None),
            ("File.symlink('staged', '~/.bashrc')", None),
            ("Store.symlink('staged', '.bashrc')", None),
        ],
    );
}

#[test]
fn link_rule_grants_apply_to_the_new_name_only() {
    for (allowed, denied, granted, other) in [
        (
            "credential-file-write",
            "git-internals-write",
            ".bashrc",
            ".git/config",
        ),
        (
            "git-internals-write",
            "credential-file-write",
            ".git/config",
            ".bashrc",
        ),
    ] {
        let home = home();
        fs::write(
            home.path().join("config.toml"),
            "[heredoc]\nenabled = false\n",
        )
        .unwrap();
        fs::write(
            home.path().join("xdg/dcg/allowlist.toml"),
            format!("[[allow]]\nrule = \"core.filesystem:{allowed}\"\nreason = \"one destination only\"\n"),
        ).unwrap();
        for (source, destination, rule) in [
            ("staged", granted, None),      // Proves the grant is loaded.
            (other, granted, None),         // The referenced source is not a write.
            (granted, other, Some(denied)), // The other destination still denies.
        ] {
            for (exe, program) in [
                (
                    "python3",
                    format!("import os; os.link('{source}', '{destination}')"),
                ),
                (
                    "python3",
                    format!(
                        "from pathlib import Path; Path('{destination}').symlink_to('{source}')"
                    ),
                ),
                (
                    "node",
                    format!("require('fs').linkSync('{source}', '{destination}')"),
                ),
                (
                    "node",
                    format!("require('fs/promises').symlink('{source}', '{destination}')"),
                ),
                ("ruby", format!("File.symlink('{source}', '{destination}')")),
                ("ruby", format!("File.link('{source}', '{destination}')")),
            ] {
                assert_program(exe, &program, home.path(), rule);
                let quoted = format!("'{}'", program.replace('\'', "'\\''"));
                assert_decision(&format!("{exe} 0<<< {quoted}"), home.path(), rule);
            }
        }
    }
}

#[test]
fn ruby_flags_options_cannot_hide_truncation_from_hook_or_cli() {
    let home = home();
    for (source, blocked) in [
        (
            "File.open('.ssh/known_hosts', 'a', flags: File::TRUNC)",
            true,
        ),
        (
            "File.open('.ssh/known_hosts', flags: File::TRUNC, mode: 'a')",
            true,
        ),
        (
            "File.open('.ssh/known_hosts', mode: 'w', flags: File::APPEND)",
            true,
        ),
        (
            "File.write('.ssh/known_hosts', 'host', mode: 'a', flags: File::TRUNC)",
            true,
        ),
        (
            "File.write('.ssh/known_hosts', 'host', flags: File::APPEND)",
            true,
        ),
        ("File.open('.bashrc', flags: File::WRONLY)", true),
        ("File.open('.ssh/known_hosts', **options, mode: 'a')", true),
        (
            "File.open('.ssh/known_hosts', mode: File::WRONLY, flags: File::APPEND)",
            false,
        ),
        (
            "File.write('.ssh/known_hosts', {flags: File::TRUNC}, mode: 'a')",
            false,
        ),
        (
            "File.open('/etc/shadow', mode: 'r', flags: File::NOFOLLOW)",
            false,
        ),
        ("File.open('/tmp/proposal', 'a', flags: File::TRUNC)", false),
    ] {
        assert_program(
            "ruby",
            source,
            home.path(),
            blocked.then_some("credential-file-write"),
        );
    }
}

#[test]
fn low_level_open_apis_reach_hook_cli_and_stdin() {
    let home = home();
    for (exe, source) in [
        (
            "python3",
            "import os; os.open('/etc/shadow', os.O_WRONLY | os.O_TRUNC)",
        ),
        (
            "python3",
            "from os import open as acquire, O_WRONLY as W; acquire(path='.bashrc', flags=W)",
        ),
        (
            "python3",
            "import os; os.open(os.path.expanduser('~/.ssh/authorized_keys'), os.O_WRONLY | os.O_APPEND)",
        ),
        ("node", "require('fs').openSync('.bashrc', 'w')"),
        ("node", "require('node:fs/promises').open('.bashrc', 'a')"),
        (
            "node",
            "const {openSync: acquire, constants: C} = require('fs'); acquire('.bashrc', C.O_WRONLY | C.O_CREAT)",
        ),
        (
            "node",
            "const fs = require('fs'); fs.open('/etc/shadow', fs.constants.O_RDWR, () => {})",
        ),
        ("ruby", "File.sysopen('.bashrc', 'w')"),
        ("ruby", "IO.sysopen('.bashrc', File::WRONLY | File::TRUNC)"),
        (
            "ruby",
            "F = File; flags = F::WRONLY | F::APPEND; F.open('.bashrc', flags)",
        ),
        ("ruby", "IO.write('.bashrc', 'data')"),
    ] {
        assert_program(exe, source, home.path(), Some("credential-file-write"));
        let quoted = format!("'{}'", source.replace('\'', "'\\''"));
        assert_decision(
            &format!("{exe} 0<<< {quoted}"),
            home.path(),
            Some("credential-file-write"),
        );
    }
}

#[test]
fn low_level_open_modes_preserve_only_real_append_exemptions() {
    let home = home();
    for (exe, source, blocked) in [
        (
            "python3",
            "import os; os.open('.ssh/known_hosts', os.O_WRONLY | os.O_APPEND)",
            false,
        ),
        (
            "python3",
            "import os; os.open('.ssh/known_hosts', os.O_WRONLY | os.O_APPEND | os.O_TRUNC)",
            true,
        ),
        (
            "python3",
            "import os; os.open('.ssh/known_hosts', os.O_WRONLY | os.O_APPEND | extra)",
            true,
        ),
        (
            "node",
            "const fs = require('fs'); fs.openSync('.ssh/known_hosts', fs.constants.O_WRONLY | fs.constants.O_APPEND)",
            false,
        ),
        (
            "node",
            "const fs = require('fs'); fs.openSync('.ssh/known_hosts', fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_TRUNC)",
            true,
        ),
        (
            "node",
            "require('fs').openSync('.ssh/known_hosts', 'a')",
            false,
        ),
        (
            "node",
            "require('fs').openSync('.ssh/known_hosts', 'r+')",
            true,
        ),
        (
            "ruby",
            "File.open('.ssh/known_hosts', mode: File::WRONLY | File::APPEND)",
            false,
        ),
        (
            "ruby",
            "File.open('.ssh/known_hosts', mode: File::WRONLY | File::APPEND | File::TRUNC)",
            true,
        ),
        ("ruby", "File.sysopen('.ssh/known_hosts', File::RDWR)", true),
    ] {
        assert_program(
            exe,
            source,
            home.path(),
            blocked.then_some("credential-file-write"),
        );
    }
}

#[test]
fn low_level_open_reads_safe_paths_and_data_remain_allowed() {
    let home = home();
    for (exe, source) in [
        (
            "python3",
            "import os; os.open('/etc/shadow', os.O_RDONLY | os.O_CLOEXEC)",
        ),
        (
            "python3",
            "import os; os.open('/tmp/proposal', os.O_WRONLY | os.O_CREAT)",
        ),
        (
            "python3",
            "import os; os = storage; os.open('.bashrc', os.O_WRONLY)",
        ),
        ("node", "require('fs').openSync('/etc/shadow', 'r')"),
        (
            "node",
            "const fs = require('fs'); fs.openSync('/etc/shadow', fs.constants.O_RDONLY)",
        ),
        ("node", "require('fs').openSync('/tmp/proposal', 'w')"),
        (
            "node",
            "const fs = require('unrelated'); fs.openSync('.bashrc', 'w')",
        ),
        ("ruby", "File.sysopen('/etc/shadow', File::RDONLY)"),
        ("ruby", "File.sysopen('/tmp/proposal', 'w')"),
        ("ruby", "IO.open('.bashrc', 'w')"),
        ("ruby", "puts \"File.sysopen('.bashrc', 'w')\""),
    ] {
        assert_program(exe, source, home.path(), None);
    }
    assert_decision(
        "cat <<'DATA'\nimport os; os.open('/etc/shadow', os.O_WRONLY)\nDATA",
        home.path(),
        None,
    );
}

#[test]
fn low_level_open_rule_grants_remain_independent() {
    for (allowed, denied, target) in [
        ("credential-file-write", "git-internals-write", ".bashrc"),
        (
            "git-internals-write",
            "credential-file-write",
            ".git/config",
        ),
    ] {
        let home = home();
        fs::write(
            home.path().join("xdg/dcg/allowlist.toml"),
            format!(
                "[[allow]]\nrule = \"core.filesystem:{allowed}\"\nreason = \"one reviewed rule\"\n"
            ),
        )
        .expect("rule allowlist");
        for (exe, first, second) in [
            (
                "python3",
                format!("import os; os.open('{target}', os.O_WRONLY)"),
                "import os; os.open('.bashrc', os.O_WRONLY); os.open('.git/config', os.O_WRONLY)",
            ),
            (
                "node",
                format!("require('fs').openSync('{target}', 'w')"),
                "const fs = require('fs'); fs.openSync('.git/config', 'w'); fs.openSync('.bashrc', 'w')",
            ),
            (
                "ruby",
                format!("File.sysopen('{target}', 'w')"),
                "File.sysopen('.bashrc', 'w'); File.sysopen('.git/config', 'w')",
            ),
        ] {
            assert_program(exe, &first, home.path(), None);
            assert_program(exe, second, home.path(), Some(denied));
        }
    }
}

#[test]
fn ruby_write_data_is_not_an_append_mode_option() {
    let home = home();
    for (source, blocked) in [
        ("File.write('.ssh/known_hosts', {mode: 'a'})", true),
        (
            "File.binwrite('.ssh/known_hosts', {nested: {mode: 'a'}})",
            true,
        ),
        (
            "File.write('.ssh/known_hosts', {mode: 'w'}, mode: 'a')",
            false,
        ),
        (
            "File.write('.ssh/known_hosts', 'host', mode: 'a', **options)",
            true,
        ),
    ] {
        assert_program(
            "ruby",
            source,
            home.path(),
            blocked.then_some("credential-file-write"),
        );
    }
}

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

#[test]
fn shutil_copy_placement_checks_the_effective_destination() {
    let home = home();
    for operation in ["copy", "copy2"] {
        for (source, destination, rule) in [
            ("staged", "/etc/shadow", Some("credential-file-write")),
            ("fixtures/.bashrc", "/home/u", Some("credential-file-write")),
            (
                "fixtures/credentials",
                "/home/u/.aws",
                Some("credential-file-write"),
            ),
            ("fixtures/passwd", "/etc", Some("credential-file-write")),
            ("staged", ".git", Some("git-internals-write")),
            (
                "staged",
                "/home/u/.ssh/known_hosts",
                Some("credential-file-write"),
            ),
            ("notes.txt", "/home/u", None),
            ("readme.txt", "/home/u/.aws", None),
            ("fixtures/pass*", "/etc", None),
            (".bashrc", "/tmp/backup.txt", None),
        ] {
            let program = format!("import shutil; shutil.{operation}('{source}', '{destination}')");
            assert_program("python3", &program, home.path(), rule);
        }
    }
    for source in [
        "from shutil import copy2 as publish; publish(dst='/etc', src='fixtures/passwd')",
        "import shutil; shutil.copy(source, '/home/u/.ssh')",
        "import shutil; shutil.copy2(source, '/home/u')",
        "import shutil, os; shutil.copy2('fixtures/.bashrc', os.path.expanduser('~'))",
    ] {
        assert_program(
            "python3",
            source,
            home.path(),
            Some("credential-file-write"),
        );
    }
}

#[test]
fn shutil_recursive_restore_and_move_preserve_source_effects() {
    let home = home();
    for source in [
        "import shutil; shutil.copytree('backup', '/home/u', dirs_exist_ok=True)",
        "from shutil import copytree as restore; restore(src='backup', dst='/etc')",
        "import shutil; shutil.copytree(source, '/home/u/.config')",
        "import shutil; shutil.move('/home/u/.aws', 'backup')",
        "from shutil import move as archive; archive(src='/home/u/.config', dst=destination)",
    ] {
        assert_program(
            "python3",
            source,
            home.path(),
            Some("credential-file-write"),
        );
    }
    for source in [
        "import shutil; shutil.copytree('backup', '.git', dirs_exist_ok=True)",
        "import shutil; shutil.move('.git', 'backup')",
    ] {
        assert_program("python3", source, home.path(), Some("git-internals-write"));
    }
    for source in [
        "import shutil; shutil.copytree('/home/u/.ssh', '/tmp/backup')",
        "import shutil; shutil.copytree('/home/u/.config', '/tmp/backup')",
        "import shutil; shutil.copytree('backup', '~')",
        "import shutil; shutil.move('notes.txt', '/home/u')",
        "import shutil; shutil = store; shutil.move('staged', '.bashrc')",
        "print(\"shutil.copytree('backup', '/etc')\")",
    ] {
        assert_program("python3", source, home.path(), None);
    }
}

#[test]
fn shutil_move_cannot_cross_independently_allowlisted_rules() {
    for (allowed, denied, target) in [
        ("credential-file-write", "git-internals-write", ".bashrc"),
        ("git-internals-write", "credential-file-write", ".git"),
    ] {
        let home = home();
        fs::write(
            home.path().join("xdg/dcg/allowlist.toml"),
            format!("[[allow]]\nrule = \"core.filesystem:{allowed}\"\nreason = \"reviewed one endpoint\"\n"),
        )
        .expect("rule allowlist");
        // This positive control proves the configured grant actually applies;
        // a malformed or unloaded allowlist must not make the deny test pass.
        let control = format!("import shutil; shutil.copy2('staged', '{target}')");
        assert_program("python3", &control, home.path(), None);
        for (source, destination) in [(".bashrc", ".git"), (".git", ".bashrc")] {
            let program = format!("import shutil; shutil.move('{source}', '{destination}')");
            assert_program("python3", &program, home.path(), Some(denied));
        }
    }
}

#[test]
fn shutil_directory_transfers_reach_stdin_without_scanning_inert_data() {
    let home = home();
    for (source, rule) in [
        (
            "import shutil; shutil.copy2('fixtures/.bashrc', '/home/u')",
            Some("credential-file-write"),
        ),
        (
            "import shutil; shutil.copytree('backup', '/home/u')",
            Some("credential-file-write"),
        ),
        (
            "from shutil import move as archive; archive('.git', 'backup')",
            Some("git-internals-write"),
        ),
        ("import shutil; shutil.copy('notes.txt', '/home/u')", None),
        ("print(\"shutil.copytree('backup', '/etc')\")", None),
    ] {
        let quoted = format!("'{}'", source.replace('\'', "'\\''"));
        let command = format!("env python3 - 0<<< {quoted}");
        assert_decision(&command, home.path(), rule);
    }
    assert_decision(
        "cat <<'DATA'\nimport shutil; shutil.copytree('backup', '/etc')\nDATA",
        home.path(),
        None,
    );
}

#[test]
fn cross_rule_grants_survive_every_delivery_and_extraction_mode() {
    use std::fmt::Write as _;

    for settings in [
        "[heredoc]\nenabled = true\ntimeout_ms = 5000\n",
        "[heredoc]\nenabled = true\ntimeout_ms = 0\n",
        "[heredoc]\nenabled = false\n",
    ] {
        for (allowed, denied) in [
            ("credential-file-write", Some("git-internals-write")),
            ("git-internals-write", Some("credential-file-write")),
            ("both", None),
        ] {
            let home = home();
            fs::write(home.path().join("config.toml"), settings).unwrap();
            let rules = if allowed == "both" {
                vec!["credential-file-write", "git-internals-write"]
            } else {
                vec![allowed]
            };
            let mut grants = String::new();
            for rule in &rules {
                writeln!(
                    grants,
                    "[[allow]]\nrule = \"core.filesystem:{rule}\"\nreason = \"reviewed endpoint\""
                )
                .expect("write rule grant");
            }
            fs::write(home.path().join("xdg/dcg/allowlist.toml"), grants).unwrap();
            for rule in rules {
                let target = if rule == "credential-file-write" {
                    ".bashrc"
                } else {
                    ".git/config"
                };
                // Prove that the grant was loaded; a broken allowlist must not
                // satisfy the cross-rule DENY assertion by accident.
                assert_program(
                    "python3",
                    &format!("open('{target}', 'w')"),
                    home.path(),
                    None,
                );
            }
            for (source, destination) in [(".bashrc", ".git/config"), (".git/config", ".bashrc")] {
                for (exe, program) in [
                    (
                        "python3",
                        format!("import os; os.replace('{source}', '{destination}')"),
                    ),
                    ("ruby", format!("File.rename('{source}', '{destination}')")),
                    (
                        "node",
                        format!("require('fs').renameSync('{source}', '{destination}')"),
                    ),
                ] {
                    assert_program(exe, &program, home.path(), denied);
                    let quoted = format!("'{}'", program.replace('\'', "'\\''"));
                    assert_decision(&format!("env {exe} - 0<<< {quoted}"), home.path(), denied);
                }
            }
        }
    }
}

#[test]
fn a_granted_first_segment_does_not_hide_a_later_interpreter_rule() {
    let home = home();
    fs::write(
        home.path().join("config.toml"),
        "[heredoc]\nenabled = false\n",
    )
    .unwrap();
    fs::write(
        home.path().join("xdg/dcg/allowlist.toml"),
        "[[allow]]\nrule = \"core.filesystem:credential-file-write\"\nreason = \"one rule only\"\n",
    )
    .unwrap();
    assert_decision("echo x >> .bashrc", home.path(), None);
    for command in [
        "echo x >> .bashrc; python3 0<<< \"open('.git/config', 'w')\"",
        "python3 0<<< \"open('.bashrc', 'w')\"; python3 0<<< \"open('.git/config', 'w')\"",
        "python3 -c \"open('.bashrc', 'w'); open('.git/config', 'w')\"",
    ] {
        assert_decision(command, home.path(), Some("git-internals-write"));
    }
}

#[test]
fn explicit_language_filters_preserve_other_interpreters_and_shell_writes() {
    for settings in [
        "[heredoc]\nenabled = true\ntimeout_ms = 5000\nlanguages = ['ruby']\n",
        "[heredoc]\nenabled = true\ntimeout_ms = 0\nlanguages = ['ruby']\n",
        "[heredoc]\nenabled = false\nlanguages = ['ruby']\n",
    ] {
        let home = home();
        fs::write(home.path().join("config.toml"), settings).unwrap();
        assert_program("python3", "open('.bashrc', 'w')", home.path(), None);
        assert_decision(
            "env python3 - 0<<< \"open('.bashrc', 'w')\"",
            home.path(),
            None,
        );
        assert_program(
            "ruby",
            "File.write('.git/config', 'x')",
            home.path(),
            Some("git-internals-write"),
        );
        assert_decision(
            "python3 0<<< \"open('.bashrc', 'w')\"; ruby 0<<< \"File.write('.git/config', 'x')\"",
            home.path(),
            Some("git-internals-write"),
        );
        // An interpreter-language exclusion never grants shell file writes.
        assert_decision(
            "echo x >> .bashrc",
            home.path(),
            Some("credential-file-write"),
        );
    }
}

#[test]
fn python_composed_paths_reach_hook_cli_and_stdin() {
    for settings in [
        "[heredoc]\nenabled = true\ntimeout_ms = 5000\n",
        "[heredoc]\nenabled = false\n",
    ] {
        let home = home();
        fs::write(home.path().join("config.toml"), settings).unwrap();
        for (source, rule) in [
            (
                "from pathlib import Path; (Path.home() / '.ssh' / 'id_rsa').write_text('x')",
                Some("credential-file-write"),
            ),
            (
                "import os; open(os.path.join(os.environ['HOME'], '.aws', 'credentials'), 'w')",
                Some("credential-file-write"),
            ),
            (
                "from pathlib import Path; import shutil; shutil.copy2('staged', Path.home().joinpath('.bashrc'))",
                Some("credential-file-write"),
            ),
            (
                "from pathlib import Path; Path('.git', 'config').write_text('x')",
                Some("git-internals-write"),
            ),
            (
                "from pathlib import Path; Path('~/.bashrc').write_text('x')",
                None,
            ),
            (
                "from pathlib import Path; (Path.home() / 'notes.txt').write_text('x')",
                None,
            ),
            (
                "from pathlib import Path; Path.home().joinpath('.ssh', 'known_hosts').open('a')",
                None,
            ),
            (
                "from pathlib import Path; (Path.home() / '/tmp/dcg-preview').write_text('x')",
                None,
            ),
        ] {
            assert_program("python3", source, home.path(), rule);
            let quoted = format!("'{}'", source.replace('\'', "'\\''"));
            assert_decision(&format!("env python3 - 0<<< {quoted}"), home.path(), rule);
        }
    }
}

#[test]
fn python_composed_paths_cannot_hide_a_rename_endpoint_behind_a_grant() {
    for (allowed, denied, control) in [
        (
            "credential-file-write",
            "git-internals-write",
            "Path.home().joinpath('.bashrc')",
        ),
        (
            "git-internals-write",
            "credential-file-write",
            "Path('.git', 'config')",
        ),
    ] {
        let home = home();
        fs::write(
            home.path().join("config.toml"),
            "[heredoc]\nenabled = false\n",
        )
        .unwrap();
        fs::write(
            home.path().join("xdg/dcg/allowlist.toml"),
            format!(
                "[[allow]]\nrule = \"core.filesystem:{allowed}\"\nreason = \"one endpoint only\"\n"
            ),
        )
        .unwrap();
        assert_program(
            "python3",
            &format!("from pathlib import Path; {control}.write_text('x')"),
            home.path(),
            None,
        );
        for source in [
            "from pathlib import Path; (Path.home() / '.bashrc').replace('.git/config')",
            "from pathlib import Path; Path('.git', 'config').replace(Path.home().joinpath('.bashrc'))",
        ] {
            assert_program("python3", source, home.path(), Some(denied));
            let quoted = format!("'{}'", source.replace('\'', "'\\''"));
            assert_decision(&format!("python3 0<<< {quoted}"), home.path(), Some(denied));
        }
    }
}

#[test]
fn node_and_ruby_composed_paths_reach_hook_cli_and_stdin() {
    for settings in [
        "[heredoc]\nenabled = true\ntimeout_ms = 5000\n",
        "[heredoc]\nenabled = false\n",
    ] {
        let home = home();
        fs::write(home.path().join("config.toml"), settings).unwrap();
        for (exe, source, rule) in [
            (
                "node",
                "require('fs').writeFileSync(require('path').join(require('os').homedir(), '.ssh', 'id_rsa'), 'x')",
                Some("credential-file-write"),
            ),
            (
                "node",
                "const {join: J} = require('node:path'); require('fs').writeFileSync(J(process.env.HOME, '.aws', 'credentials'), 'x')",
                Some("credential-file-write"),
            ),
            (
                "node",
                "require('fs').writeFileSync(require('path').resolve('/tmp', '/etc', 'shadow'), 'x')",
                Some("credential-file-write"),
            ),
            (
                "node",
                "require('fs').writeFileSync(require('path').join('/tmp', '..', 'etc', 'shadow'), 'x')",
                Some("credential-file-write"),
            ),
            (
                "node",
                "require('fs').writeFileSync(require('path').join('/tmp', '/etc', 'shadow'), 'x')",
                None,
            ),
            (
                "node",
                "require('fs').appendFileSync(require('path').join(require('os').homedir(), '.ssh', 'known_hosts'), 'host')",
                None,
            ),
            (
                "node",
                "require('fs').writeFileSync(require('path').join('~', '.bashrc'), 'x')",
                None,
            ),
            (
                "ruby",
                "File.write(File.join(Dir.home, '.bashrc'), 'x')",
                Some("credential-file-write"),
            ),
            (
                "ruby",
                "File.write(File.join('/etc', 'shadow'), 'x')",
                Some("credential-file-write"),
            ),
            ("ruby", "File.write(File.join('~', '.bashrc'), 'x')", None),
            (
                "ruby",
                "File.open(File.join(Dir.home, '.ssh', 'known_hosts'), 'a')",
                None,
            ),
            (
                "ruby",
                "File.write(File.join('/tmp', '/etc', 'shadow'), 'x')",
                None,
            ),
        ] {
            assert_program(exe, source, home.path(), rule);
            let quoted = format!("'{}'", source.replace('\'', "'\\''"));
            assert_decision(&format!("env {exe} - 0<<< {quoted}"), home.path(), rule);
        }
    }
}

#[test]
fn node_and_ruby_composed_paths_keep_rule_grants_independent() {
    for (allowed, denied, target) in [
        ("credential-file-write", "git-internals-write", ".bashrc"),
        (
            "git-internals-write",
            "credential-file-write",
            ".git/config",
        ),
    ] {
        let home = home();
        fs::write(
            home.path().join("config.toml"),
            "[heredoc]\nenabled = false\n",
        )
        .unwrap();
        fs::write(
            home.path().join("xdg/dcg/allowlist.toml"),
            format!(
                "[[allow]]\nrule = \"core.filesystem:{allowed}\"\nreason = \"one endpoint only\"\n"
            ),
        )
        .unwrap();
        assert_program(
            "node",
            &format!("require('fs').writeFileSync('{target}', 'x')"),
            home.path(),
            None,
        );
        assert_program(
            "ruby",
            &format!("File.write('{target}', 'x')"),
            home.path(),
            None,
        );
        for (exe, source) in [
            (
                "node",
                "require('fs').renameSync(require('path').join(require('os').homedir(), '.bashrc'), '.git/config')",
            ),
            (
                "node",
                "require('fs').renameSync('.git/config', require('path').join(process.env.HOME, '.bashrc'))",
            ),
            (
                "ruby",
                "File.rename(File.join(Dir.home, '.bashrc'), '.git/config')",
            ),
            (
                "ruby",
                "File.rename('.git/config', File.join(Dir.home, '.bashrc'))",
            ),
        ] {
            assert_program(exe, source, home.path(), Some(denied));
            let quoted = format!("'{}'", source.replace('\'', "'\\''"));
            assert_decision(&format!("{exe} 0<<< {quoted}"), home.path(), Some(denied));
        }
    }
}

#[test]
fn compound_open_flags_reach_hook_cli_and_stdin() {
    for (exe, source) in [
        (
            "python3",
            "import os; f = os.O_RDONLY; f |= os.O_WRONLY; os.open('.bashrc', f)",
        ),
        (
            "python3",
            "import os; f = os.O_WRONLY | os.O_APPEND; f |= os.O_TRUNC; os.open('.ssh/known_hosts', f)",
        ),
        (
            "node",
            "const fs = require('fs'); let f = fs.constants.O_RDONLY; f |= fs.constants.O_WRONLY; fs.openSync('.bashrc', f)",
        ),
        (
            "node",
            "const fs = require('fs'); let f = fs.constants.O_WRONLY | fs.constants.O_APPEND; f |= fs.constants.O_TRUNC; fs.openSync('.ssh/known_hosts', f)",
        ),
        (
            "ruby",
            "f = File::RDONLY; f |= File::WRONLY; IO.sysopen('.bashrc', f)",
        ),
        (
            "ruby",
            "f = File::WRONLY | File::APPEND; f |= File::TRUNC; IO.sysopen('.ssh/known_hosts', f)",
        ),
    ] {
        assert_link_cases(exe, &[(source, Some("credential-file-write"))]);
    }
}

#[test]
fn compound_path_construction_and_safe_controls_reach_real_entry_points() {
    for (exe, source, rule) in [
        (
            "python3",
            "p = '/home/u/'; p += '.bashrc'; open(p, 'w')",
            Some("credential-file-write"),
        ),
        (
            "python3",
            "from pathlib import Path; p = Path.home(); p /= '.ssh'; p /= 'authorized_keys'; p.write_text('x')",
            Some("credential-file-write"),
        ),
        (
            "node",
            "let p = require('os').homedir(); p += '/.bashrc'; require('fs').writeFileSync(p, 'x')",
            Some("credential-file-write"),
        ),
        (
            "ruby",
            "p = Dir.home; p += '/.bashrc'; File.write(p, 'x')",
            Some("credential-file-write"),
        ),
        (
            "python3",
            "import os; f = os.O_WRONLY; f |= os.O_APPEND; os.open('.ssh/known_hosts', f)",
            None,
        ),
        (
            "node",
            "const fs = require('fs'); let f = fs.constants.O_WRONLY; f |= fs.constants.O_APPEND; fs.openSync('.ssh/known_hosts', f)",
            None,
        ),
        (
            "ruby",
            "f = File::WRONLY; f |= File::APPEND; IO.sysopen('.ssh/known_hosts', f)",
            None,
        ),
        (
            "python3",
            "p = '.bashrc'; p += '.backup'; open(p, 'w')",
            None,
        ),
        (
            "node",
            "let p = '.bashrc'; p += '.backup'; require('fs').writeFileSync(p, 'x')",
            None,
        ),
        (
            "ruby",
            "p = '.bashrc'; p += '.backup'; File.write(p, 'x')",
            None,
        ),
        (
            "python3",
            "print(\"p = '/home/u/'; p += '.bashrc'; open(p, 'w')\")",
            None,
        ),
    ] {
        assert_link_cases(exe, &[(source, rule)]);
    }
}

#[test]
fn compound_writes_keep_rule_grants_independent() {
    for (allowed, denied, target) in [
        ("credential-file-write", "git-internals-write", ".bashrc"),
        (
            "git-internals-write",
            "credential-file-write",
            ".git/config",
        ),
    ] {
        let home = home();
        fs::write(
            home.path().join("config.toml"),
            "[heredoc]\nenabled = false\n",
        )
        .unwrap();
        fs::write(
            home.path().join("xdg/dcg/allowlist.toml"),
            format!(
                "[[allow]]\nrule = \"core.filesystem:{allowed}\"\nreason = \"one rule only\"\n"
            ),
        )
        .unwrap();
        assert_program(
            "python3",
            &format!("open('{target}', 'w')"),
            home.path(),
            None,
        );
        for (first, second) in [(".bashrc", ".git/config"), (".git/config", ".bashrc")] {
            for (exe, source) in [
                (
                    "python3",
                    format!(
                        "import os; f = os.O_RDONLY; f |= os.O_WRONLY; os.open('{first}', f); os.open('{second}', f)"
                    ),
                ),
                (
                    "node",
                    format!(
                        "const fs = require('fs'); let f = fs.constants.O_RDONLY; f |= fs.constants.O_WRONLY; fs.openSync('{first}', f); fs.openSync('{second}', f)"
                    ),
                ),
                (
                    "ruby",
                    format!(
                        "f = File::RDONLY; f |= File::WRONLY; IO.sysopen('{first}', f); IO.sysopen('{second}', f)"
                    ),
                ),
            ] {
                assert_program(exe, &source, home.path(), Some(denied));
                let quoted = format!("'{}'", source.replace('\'', "'\\''"));
                assert_decision(&format!("{exe} 0<<< {quoted}"), home.path(), Some(denied));
            }
        }
    }
}

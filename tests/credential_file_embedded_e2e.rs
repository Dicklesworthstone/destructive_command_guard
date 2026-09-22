//! #461: exercise real entry points, including pack gates and rule allowlisting.
//! The strings below are inputs to dcg, never executed as shell commands.

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
    let mut command = Command::new(env!("CARGO_BIN_EXE_dcg"));
    // An ambient bypass must not certify an analysis path that never ran.
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("DCG_") {
            command.env_remove(name);
        }
    }
    command
        .current_dir(home)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join("xdg"))
        .env("DCG_CONFIG", home.join("config.toml"))
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_PENDING_EXCEPTIONS_PATH", home.join("pending.jsonl"))
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("DCG_HOOK_TIMEOUT_MS", "30000")
        .env("DCG_AST_TIMEOUT_MS", "5000")
        .env_remove("DCG_FAIL_CLOSED");
    command
}

fn response(command: &str, home: &Path) -> String {
    let payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command }
    });
    let mut child = dcg(home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hook");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(payload.to_string().as_bytes())
        .expect("send hook payload");
    let output = child.wait_with_output().expect("hook response");
    assert!(
        output.status.success(),
        "{command}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("UTF-8 hook output")
}

fn assert_cli(command: &str, home: &Path, rule: Option<&str>) {
    let output = dcg(home)
        .args(["test", "--format", "json", command])
        .output()
        .expect("CLI response");
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 CLI output");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("{command}: {error}; stdout={stdout}; stderr={stderr}"));
    assert_eq!(
        output.status.code(),
        Some(i32::from(rule.is_some())),
        "{command}: {stdout}; {stderr}"
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

fn assert_denied_by(command: &str, home: &Path, rule: &str) {
    let output = response(command, home);
    let json: serde_json::Value = serde_json::from_str(&output)
        .unwrap_or_else(|error| panic!("{command}: {error}; output={output}"));
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"], "deny",
        "{command}: {output}"
    );
    assert!(output.contains(rule), "wrong rule for {command}: {output}");
    assert_cli(command, home, Some(rule));
}

fn assert_denied(command: &str, home: &Path) {
    assert_denied_by(command, home, "credential-file-write");
}

fn assert_allowed(command: &str, home: &Path) {
    let output = response(command, home);
    assert!(output.trim().is_empty(), "{command}: {output}");
    assert_cli(command, home, None);
}

#[test]
fn php_perl_issue_466_reported_writes_reach_real_entry_points() {
    let home = home();
    // The issue's 18 cells: three protected shapes, three deliveries per
    // language. Candidate programs are data sent to dcg, never executed.
    for path in [
        "/etc/shadow",
        "/home/user/.ssh/authorized_keys",
        "/home/user/.bashrc",
    ] {
        let php = format!("file_put_contents('{path}', 'x');");
        let perl = format!("open(my $fh, '>>', '{path}'); print $fh 'x';");
        let quote = |code: &str| format!("'{}'", code.replace('\'', "'\\''"));
        for command in [
            format!("php <<'PHP'\n<?php {php}\nPHP"),
            format!("php -r {}", quote(&php)),
            format!("php <<'PHP'\n<?php fopen('{path}', 'w');\nPHP"),
            format!("perl <<'PERL'\nopen(my $fh, '>', '{path}');\nPERL"),
            format!("perl -e {}", quote(&perl)),
            format!(
                "printf '%s\\n' {} | perl",
                quote(&format!("open(my $fh, '>', '{path}');"))
            ),
        ] {
            assert_denied(&command, home.path());
        }
    }
}

#[test]
fn php_perl_issue_466_benign_controls_reach_real_entry_points() {
    let home = home();
    for command in [
        "php -r \"file_put_contents('/tmp/out.txt', 'x');\"",
        "php -r \"fopen('/etc/shadow', 'r');\"",
        "php -r \"file_put_contents('/home/user/.ssh/known_hosts', 'x', FILE_APPEND);\"",
        "php -r \"fopen('/home/user/.ssh/known_hosts', 'a+');\"",
        "php -r \"file_put_contents('/home/user/.ssh/id_rsa.pub', 'x');\"",
        "php -r \"file_put_contents('~/.bashrc', 'x');\"",
        "perl -e 'open(my $fh, \">\", \"/tmp/out.txt\");'",
        "perl -e 'open(my $fh, \"<\", \"/etc/shadow\");'",
        "perl -e 'open(my $fh, \">>\", \"/home/user/.ssh/known_hosts\");'",
        "perl -e 'open(my $fh, \">\", \"/home/user/.ssh/id_rsa.pub\");'",
        "perl -e 'open(my $fh, \">\", \"~/.bashrc\");'",
    ] {
        assert_allowed(command, home.path());
    }
}

#[test]
fn perl_fallback_preserves_data_and_rejects_later_truncation() {
    let home = home();
    for command in [
        "perl <<'PERL'\nprint <<'DATA';\nopen(FH, '>', '/etc/shadow');\nDATA\nPERL",
        "perl -e 'truncate(\"/tmp/out.txt\", 0);'",
        "perl -e 'open(FH, \"<\", \"/etc/shadow\"); truncate(FH, 0);'",
    ] {
        assert_allowed(command, home.path());
    }
    for command in [
        "perl <<'PERL'\neval <<'CODE';\nopen(FH, '>', '/etc/shadow');\nCODE\nPERL",
        "perl <<'PERL'\nprint eval <<'CODE';\nopen(FH, '>', '/etc/shadow');\nCODE\nPERL",
        "perl <<'PERL'\nprint <<\"CODE\";\n${\\ do { open(FH, '>', '/etc/shadow'); '' }}\nCODE\nPERL",
        "perl -e 'truncate(\"/home/user/.ssh/known_hosts\", 0);'",
        "perl -e 'open(FH, \">>\", \"/home/user/.ssh/known_hosts\"); truncate(FH, 0);'",
        "perl <<'PERL'\nprint <<'DATA';\nopen(FH, '>', '/tmp/out.txt');\nDATA\nopen(FH, '>', '/etc/shadow');\nPERL",
    ] {
        assert_denied(command, home.path());
    }
}

#[test]
fn embedded_writes_reach_the_core_rule_through_the_hook() {
    let home = home();
    for command in [
        r#"python3 -c "open('/home/me/.ssh/authorized_keys','w').write('key')""#,
        r#"ruby -e "File.write('/home/me/.bashrc', 'export PATH=x')""#,
        r#"node -e "require('fs').writeFileSync('/home/me/.ssh/config', 'Host *')""#,
        r#"python3 -c "import io; io.open('/home/me/.aws/credentials', 'a')""#,
        r#"python3 -c "from pathlib import Path; Path('/home/me/.netrc').write_text('x')""#,
        r#"ruby -e "File.open('/home/me/.bashrc', 'r+') { |f| f.write('x') }""#,
        r#"node -e "const fs = require('fs'); fs.appendFileSync('/home/me/.ssh/known_hosts','x',{flag:'w'})""#,
        r#"node -e "require('fs').createWriteStream('/home/me/.ssh/known_hosts')""#,
        r#"env python3 -c "open('/home/me/.bashrc', 'w')""#,
        r#"true && ruby -e "File.write('/home/me/.bashrc', 'x')""#,
        "python3 <<'EOF'\nopen('/home/me/.bashrc', 'w')\nEOF",
        "ruby <<'EOF'\nFile.write('/home/me/.bashrc', 'x')\nEOF",
        "node <<'EOF'\nrequire('fs').writeFileSync('/home/me/.bashrc', 'x')\nEOF",
    ] {
        assert_denied(command, home.path());
    }
}

/// A wrapper prefix must not change the hook's answer (#464).
///
/// This has to run end-to-end. The classifier was never wrong about these —
/// called directly it returns a hit for every row below — but the *candidate
/// gate* took the segment's first token as the executable, so `sudo python3 …`
/// presented `sudo`, which is neither a credential writer nor an interpreter,
/// and the pack was never made a candidate. Twelve of twelve wrapped embedded
/// spellings were allowed while every shell spelling of the same write denied.
///
/// So a unit test at the classifier would have stayed green throughout the bug,
/// and did. The shell row is carried alongside on purpose: it passed before the
/// fix too, and it is what makes this a *parity* assertion rather than a list —
/// the two halves must answer the same way about the same write.
///
/// `sudo` and `env` are the words an agent actually adds when a step is
/// refused, which is why the prefix list is the retry vocabulary rather than a
/// theoretical one. `FOO=1` is an assignment prefix rather than a wrapper
/// command and reaches the same code path.
#[test]
fn a_wrapper_prefix_does_not_change_the_hook_verdict() {
    let home = home();
    let sinks = [
        r#"python3 -c "open('/home/me/.bashrc', 'w')""#,
        r#"ruby -e "File.write('/home/me/.bashrc', 'x')""#,
        r#"node -e "require('fs').writeFileSync('/home/me/.bashrc','x')""#,
        // The shell half, which always worked; it keeps this honest.
        "tee /home/me/.bashrc",
    ];
    for sink in sinks {
        for prefix in ["", "sudo ", "env ", "/usr/bin/env ", "FOO=1 "] {
            assert_denied(&format!("{prefix}{sink}"), home.path());
        }
    }
}

#[test]
fn reported_targets_have_shell_inline_and_heredoc_policy_parity() {
    let home = home();
    // These are the reporter's literal spellings, not paths underneath the
    // temporary HOME. The shell controls prove that each target is protected.
    // No target needs to exist and none of the candidate commands is executed.
    for path in [
        "/home/u/.ssh/authorized_keys",
        "/root/.ssh/authorized_keys",
        "/home/u/.bashrc",
        "/etc/shadow",
    ] {
        for shell in [
            format!("echo x >> '{path}'"),
            format!("tee -a -- '{path}'"),
            format!("echo x > '{path}'"),
        ] {
            assert_denied(&shell, home.path());
        }
        for (interpreter, flag, code) in [
            ("python3", "-c", format!("open('{path}','a').write('x')")),
            ("python3", "-c", format!("open('{path}','w')")),
            (
                "python3",
                "-c",
                format!("from pathlib import Path; Path('{path}').write_text('x')"),
            ),
            (
                "python3",
                "-c",
                format!("import os; os.truncate('{path}',0)"),
            ),
            (
                "ruby",
                "-e",
                format!("File.open('{path}','a') {{ |f| f.write('x') }}"),
            ),
            (
                "node",
                "-e",
                format!("require('fs').appendFileSync('{path}','x')"),
            ),
            (
                "node",
                "-e",
                format!("require('fs').writeFileSync('{path}','x')"),
            ),
        ] {
            assert_denied(&format!("{interpreter} {flag} \"{code}\""), home.path());
            assert_denied(
                &format!("{interpreter} <<'DCG_SCRIPT'\n{code}\nDCG_SCRIPT"),
                home.path(),
            );
        }
    }
}

#[test]
fn credential_reads_and_append_only_known_hosts_remain_allowed() {
    let home = home();
    for command in [
        r#"python3 -c "print(open('/home/me/.ssh/authorized_keys').read())""#,
        r#"python3 -c "import io; print(io.open('/home/me/.aws/credentials', 'r').read())""#,
        r#"ruby -e "puts File.read('/home/me/.netrc')""#,
        r#"node -e "console.log(require('fs').readFileSync('/home/me/.ssh/config','utf8'))""#,
        r#"python3 -c "open('/home/me/.ssh/known_hosts','a').write('host')""#,
        r#"ruby -e "File.open('/home/me/.ssh/known_hosts','a') { |f| f.write('host') }""#,
        r#"node -e "require('fs').appendFileSync('/home/me/.ssh/known_hosts','host')""#,
        r#"node -e "require('fs').writeFileSync('/home/me/.ssh/known_hosts','host',{flag:'a'})""#,
        r#"node -e "require('fs').createWriteStream('/home/me/.ssh/known_hosts',{flags:'a'})""#,
        r#"python3 -c "open('/tmp/dcg-proposed-config','w').write('x')""#,
        r#"node -e "const store = require('unrelated'); store.writeFile('/home/me/.bashrc','x')""#,
        r#"echo "python3 -c \"open('/home/me/.bashrc','w')\"""#,
        "cat <<'EOF'\nFile.write('/home/me/.bashrc', 'x')\nEOF",
        "python3 <<'EOF'\nprint(open('/etc/shadow').read())\nEOF",
        "ruby <<'EOF'\nputs File.read('/etc/shadow')\nEOF",
        "node <<'EOF'\nconsole.log(require('fs').readFileSync('/etc/shadow','utf8'))\nEOF",
        "cat <<'EOF'\nimport os; os.truncate('/home/me/.bashrc', 0)\nEOF",
        "python3 <<'EOF'\nprint(\"open('/home/me/.bashrc', 'w')\")\nEOF",
        "ruby <<'EOF'\n# File.truncate('/home/me/.bashrc', 0)\nputs 'ok'\nEOF",
        "node <<'EOF'\nconsole.log(\"require('fs').truncateSync('/home/me/.bashrc', 0)\")\nEOF",
        r#"python3 -c "import os; os.truncate('/home/me/.ssh/id_rsa.pub', 0)""#,
    ] {
        assert_allowed(command, home.path());
    }
}

#[test]
fn existing_allowlist_id_lifts_only_the_credential_rule() {
    let home = home();
    fs::write(
        home.path().join("xdg/dcg/allowlist.toml"),
        "[[allow]]\nrule = \"core.filesystem:credential-file-write\"\nreason = \"explicitly reviewed dotfile maintenance\"\n",
    )
    .expect("rule allowlist");
    for command in [
        r#"python3 -c "open('/home/me/.bashrc','w').write('x')""#,
        r#"ruby -e "File.write('/home/me/.bashrc','x')""#,
        r#"node -e "require('fs').writeFileSync('/home/me/.bashrc','x')""#,
    ] {
        assert_allowed(command, home.path());
    }
    assert_denied_by(
        "echo x > /etc/passwd",
        home.path(),
        "redirect-truncate-root-home",
    );
    for command in [
        r#"python3 -c "open('/home/me/repo/.git/config','w').write('x')""#,
        r#"ruby -e "File.write('/home/me/repo/.git/config','x')""#,
        r#"node -e "require('fs').writeFileSync('/home/me/repo/.git/config','x')""#,
    ] {
        assert_denied_by(command, home.path(), "git-internals-write");
    }
}

#[test]
fn original_ten_spellings_cross_both_entry_points_with_unchanged_fixtures() {
    let home = home();
    fs::create_dir_all(home.path().join(".ssh")).expect("fixture directory");
    for target in [".ssh/id_rsa", ".ssh/authorized_keys", ".bashrc"] {
        // Existing relative anchors are real files beneath the isolated HOME.
        // Candidate commands are inspected, never run against these fixtures.
        let fixture = home.path().join(target);
        fs::write(&fixture, "UNCHANGED").expect("fixture contents");
        for (interpreter, flag, source) in [
            ("python3", "-c", format!("open('{target}', 'w')")),
            ("python3", "-c", format!("open('{target}', 'wb')")),
            (
                "python3",
                "-c",
                format!("with open('{target}', 'w') as f:\n    f.write('')"),
            ),
            (
                "python3",
                "-c",
                format!("from pathlib import Path; Path('{target}').write_text('')"),
            ),
            (
                "python3",
                "-c",
                format!("import os; os.truncate('{target}', 0)"),
            ),
            ("ruby", "-e", format!("File.write('{target}', '')")),
            ("ruby", "-e", format!("File.open('{target}', 'w')")),
            ("ruby", "-e", format!("File.truncate('{target}', 0)")),
            (
                "node",
                "-e",
                format!("require('fs').writeFileSync('{target}', '')"),
            ),
            (
                "node",
                "-e",
                format!("require('fs').truncateSync('{target}', 0)"),
            ),
        ] {
            assert_denied(&format!("{interpreter} {flag} \"{source}\""), home.path());
            assert_denied(
                &format!("{interpreter} <<'SRC'\n{source}\nSRC"),
                home.path(),
            );
        }
        assert_eq!(fs::read_to_string(fixture).unwrap(), "UNCHANGED");
    }
    for command in [
        "python3 <<'SRC'\nopen('.ssh/authorized_keys', 'a').write('KEY')\nSRC",
        "python3 <<'SRC'\nopen('.bashrc', 'a').write('LINE')\nSRC",
        "ruby <<'SRC'\nFile.open('.ssh/authorized_keys', 'a')\nSRC",
        "node <<'SRC'\nrequire('fs').appendFileSync('.bashrc', 'LINE')\nSRC",
        r#"python3 -c "import os; os.truncate('/home/me/.ssh/known_hosts', 0)""#,
        r#"ruby -e "File.truncate('/home/me/.ssh/known_hosts', 0)""#,
        r#"node -e "require('fs/promises').truncate('/home/me/.ssh/known_hosts', 0)""#,
        r#"python3 -c "open('/ho' + 'me/u/.ba' + 'shrc', 'w')""#,
    ] {
        assert_denied(command, home.path());
    }
}

#[test]
fn one_allowlisted_rule_cannot_hide_another_inside_the_same_script() {
    for (allowed, blocked) in [
        ("credential-file-write", "git-internals-write"),
        ("git-internals-write", "credential-file-write"),
    ] {
        let home = home();
        fs::write(
            home.path().join("xdg/dcg/allowlist.toml"),
            format!(
                "[[allow]]\nrule = \"core.filesystem:{allowed}\"\nreason = \"reviewed one rule only\"\n"
            ),
        )
        .expect("independent rule allowlist");
        for (first, second) in [(".bashrc", ".git/config"), (".git/config", ".bashrc")] {
            for (interpreter, flag, source) in [
                (
                    "python3",
                    "-c",
                    format!("open('{first}', 'w'); open('{second}', 'w')"),
                ),
                (
                    "ruby",
                    "-e",
                    format!("File.write('{first}', 'x'); File.write('{second}', 'x')"),
                ),
                (
                    "node",
                    "-e",
                    format!(
                        "const fs = require('fs'); fs.writeFileSync('{first}', 'x'); fs.writeFileSync('{second}', 'x')"
                    ),
                ),
            ] {
                assert_denied_by(
                    &format!("{interpreter} {flag} \"{source}\""),
                    home.path(),
                    blocked,
                );
                assert_denied_by(
                    &format!("{interpreter} <<'SRC'\n{source}\nSRC"),
                    home.path(),
                    blocked,
                );
            }
        }
    }
}

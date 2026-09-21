use super::*;

fn denied(code: &str, language: Language) -> bool {
    let mut hits = Vec::new();
    inspect(code, language, 0..code.len(), &mut hits);
    !hits.is_empty()
}

#[test]
fn every_language_uses_the_existing_target_policy() {
    for path in [
        "/home/test/.ssh/authorized_keys",
        "/home/test/.ssh/config",
        "/home/test/.ssh/id_ed25519",
        "/home/test/.bashrc",
        "/home/test/.zshrc",
        "/home/test/.profile",
        "/home/test/.aws/credentials",
        "/home/test/.netrc",
        "/home/test/.gnupg/gpg-agent.conf",
        "/etc/sudoers.d/agent",
        "/etc/ssh/sshd_config",
        ".ssh/authorized_keys",
    ] {
        for (language, code) in [
            (Language::Python, format!("open('{path}', 'w').write('x')")),
            (
                Language::Python,
                format!("import io; io.open('{path}', 'a')"),
            ),
            (
                Language::Python,
                format!("from pathlib import Path; Path('{path}').write_text('x')"),
            ),
            (
                Language::Python,
                format!("import pathlib; pathlib.Path('{path}').write_bytes(b'x')"),
            ),
            (Language::Ruby, format!("File.write('{path}', 'x')")),
            (
                Language::Ruby,
                format!("File.open('{path}', 'a') {{ |f| f.write('x') }}"),
            ),
            (
                Language::Node,
                format!("require('fs').writeFileSync('{path}', 'x')"),
            ),
            (
                Language::Node,
                format!("const fs = require('node:fs'); fs.appendFile('{path}', 'x', () => {{}})"),
            ),
            (
                Language::Node,
                format!("require('fs').createWriteStream('{path}')"),
            ),
        ] {
            assert!(denied(&code, language), "{language:?}: {code}");
        }
    }
}

#[test]
fn write_modes_and_aliases_are_structural() {
    for code in [
        "open(mode='w', file='/home/test/.bashrc')",
        "open('/home/test/.bashrc', encoding='utf8', mode='r+')",
        "import io as stream; stream.open('/home/test/.bashrc', 'wb')",
        "from io import open as writer; writer('/home/test/.bashrc', 'x')",
        "import builtins as b; b.open('/home/test/.bashrc', 'a+')",
        "from pathlib import Path as P; p = P('/home/test/.bashrc'); p.write_text('x')",
        "from pathlib import Path; Path('/home/test/.bashrc').open(mode='w')",
        "p = '/home/test/' + '.bashrc'; open(p, 'w')",
        r"open('/home/test/\x2ebashrc', 'w')",
        "open('/tmp/first', 'w'); open('/home/test/.bashrc', 'w')",
    ] {
        assert!(denied(code, Language::Python), "{code}");
    }
    for code in [
        "File.open('/home/test/.bashrc', mode: 'w')",
        "File.open('/home/test/.bashrc', 'r+')",
        "File.write('/home/test/.bashrc', 'x', mode: 'a')",
    ] {
        assert!(denied(code, Language::Ruby), "{code}");
    }
    for code in [
        "const disk = require('fs'); disk.writeFile('/home/test/.bashrc', 'x', () => {})",
        "const {writeFileSync: save} = require('node:fs'); save('/home/test/.bashrc', 'x')",
        "import {writeFile as save} from 'node:fs/promises'; save('/home/test/.bashrc', 'x')",
        "import fs from 'fs'; fs.promises.writeFile('/home/test/.bashrc', 'x')",
        "import * as disk from 'fs'; disk.appendFileSync('/home/test/.bashrc', 'x')",
        "require('node:fs/promises').writeFile('/home/test/.bashrc', 'x')",
        "const p = '/home/test/' + '.bashrc'; require('fs').writeFileSync(p, 'x')",
    ] {
        assert!(denied(code, Language::Node), "{code}");
    }
}

#[test]
fn known_hosts_exemption_depends_on_effective_mode() {
    for code in [
        "open('/home/test/.ssh/known_hosts', 'a')",
        "open('/home/test/.ssh/known_hosts', 'a+')",
    ] {
        assert!(!denied(code, Language::Python), "{code}");
    }
    for mode in ["w", "w+", "r+", "x"] {
        assert!(denied(
            &format!("open('/home/test/.ssh/known_hosts', '{mode}')"),
            Language::Python
        ));
    }
    assert!(!denied(
        "File.open('/home/test/.ssh/known_hosts', 'a:utf-8')",
        Language::Ruby
    ));
    assert!(!denied(
        "File.write('/home/test/.ssh/known_hosts', 'x', mode: 'a')",
        Language::Ruby
    ));
    assert!(denied(
        "File.write('/home/test/.ssh/known_hosts', 'x')",
        Language::Ruby
    ));
    for (code, expected) in [
        ("fs.appendFileSync(p, 'x')", false),
        ("fs.appendFile(p, 'x', () => {})", false),
        ("fs.writeFileSync(p, 'x', {flag: 'a'})", false),
        ("fs.createWriteStream(p, {flags: 'a'})", false),
        ("fs.appendFileSync(p, 'x', {flag: 'w'})", true),
        ("fs.appendFile(p, 'x', {flag: 'r+'}, () => {})", true),
        ("fs.appendFileSync(p, 'x', {flag: mode})", true),
        ("fs.appendFileSync(p, 'x', {flag: 'a', ...options})", true),
        ("fs.createWriteStream(p)", true),
        ("fs.createWriteStream(p, {flag: 'a'})", true), // wrong option name
        ("fs.writeFileSync(p, 'x')", true),
    ] {
        let script =
            format!("const fs = require('fs'); const p = '/home/test/.ssh/known_hosts'; {code}");
        assert_eq!(denied(&script, Language::Node), expected, "{script}");
    }
}

#[test]
fn reads_comments_strings_and_unrelated_receivers_remain_allowed() {
    for code in [
        "open('/home/test/.ssh/authorized_keys').read()",
        "open('/home/test/.ssh/config', 'rb')",
        "import io; io.open('/home/test/.aws/credentials', mode='r')",
        "from pathlib import Path; Path('/home/test/.netrc').read_text()",
        "print(\"open('/home/test/.bashrc', 'w')\")",
        "# open('/home/test/.bashrc', 'w')\nprint('ok')",
        "open = print; open('/home/test/.bashrc', 'w')",
        "def report(open):\n    open('/home/test/.bashrc', 'w')",
        "client.write_text('/home/test/.bashrc')",
        "open('/tmp/proposed', 'w')",
        "open('/home/test/.ssh/id_ed25519.pub', 'w')",
    ] {
        assert!(!denied(code, Language::Python), "{code}");
    }
    for code in [
        "File.read('/home/test/.ssh/config')",
        "File.open('/home/test/.bashrc', 'r')",
        "puts \"File.write('/home/test/.bashrc', 'x')\"",
        "# File.write('/home/test/.bashrc', 'x')",
        "Store.write('/home/test/.bashrc', 'x')",
    ] {
        assert!(!denied(code, Language::Ruby), "{code}");
    }
    for code in [
        "require('fs').readFileSync('/home/test/.ssh/authorized_keys')",
        "console.log(\"require('fs').writeFileSync('/home/test/.bashrc', 'x')\")",
        "// require('fs').writeFileSync('/home/test/.bashrc', 'x')",
        "const fs = require('unrelated'); fs.writeFileSync('/home/test/.bashrc', 'x')",
        "const fs = require('fs'); fs = console; fs.writeFileSync('/home/test/.bashrc', 'x')",
        "function example(require) { require('fs').writeFileSync('/home/test/.bashrc', 'x') }",
        "storage.writeFile('/home/test/.bashrc', 'x')",
    ] {
        assert!(!denied(code, Language::Node), "{code}");
    }
}

#[test]
fn shell_context_and_candidate_gate_reach_the_matcher() {
    for command in [
        r#"python3 -c "open('/home/test/.bashrc','w').write('x')""#,
        r#"ruby -e "File.write('/home/test/.bashrc','x')""#,
        r#"node -e "require('fs').writeFileSync('/home/test/.bashrc','x')""#,
        r#"python3.13 -Ic "open('/home/test/.bashrc', 'a')""#,
    ] {
        let hit = classify(command, ShellDialect::Posix).expect(command);
        assert!(command.get(hit.span).is_some(), "span: {command}");
        assert!(
            crate::packs::core::filesystem::filesystem_semantic_scan_required(
                command,
                ShellDialect::Posix
            ),
            "candidate gate: {command}"
        );
    }
    for command in [
        r#"echo "python3 -c \"open('/home/test/.bashrc','w')\"""#,
        r#"python3 example.py -c "open('/home/test/.bashrc','w')""#,
        r#"node example.js -e "require('fs').writeFileSync('/home/test/.bashrc','x')""#,
        "cat <<'EOF'\nopen('/home/test/.bashrc', 'w')\nEOF",
    ] {
        assert!(
            classify(command, ShellDialect::Posix).is_none(),
            "{command}"
        );
    }
    for (receiver, code) in [
        ("python3", "open('/home/test/.bashrc', 'w')"),
        ("ruby", "File.write('/home/test/.bashrc', 'x')"),
        (
            "node",
            "require('fs').writeFileSync('/home/test/.bashrc', 'x')",
        ),
    ] {
        let command = format!("{receiver} <<'EOF'\n{code}\nEOF");
        assert!(
            classify(&command, ShellDialect::Posix).is_some(),
            "{command}"
        );
    }
}

#[test]
fn policy_bridge_cannot_turn_a_literal_into_shell_syntax() {
    // `protected` returns the rule the write denies under rather than a bool
    // (#457), so these read `.is_none()` / `.is_some()`.
    assert!(
        protected(
            "/tmp/x'; tee /home/test/.bashrc; echo '",
            Access::Write,
            false
        )
        .is_none()
    );
    assert!(protected("$HOME/.bashrc", Access::Write, false).is_none());
    assert!(protected("~/.bashrc", Access::Write, false).is_none());
    assert!(protected("/home/test/.ssh/authorized_keys", Access::Append, false).is_some());
    assert!(protected("/home/test/.ssh/known_hosts", Access::Append, false).is_none());
    assert!(protected("/home/test/.ssh/known_hosts", Access::Write, false).is_some());
    for dialect in [ShellDialect::PowerShell, ShellDialect::Cmd] {
        assert!(classify(r#"python -c "open('/home/test/.bashrc','w')""#, dialect).is_none());
    }
}

/// The three truncating sinks #461 measured that the first cut did not know.
///
/// Each of these was one of the issue's ten truncation spellings and was still
/// allowed after it landed: `os.truncate` had no `os` binding at all and never
/// passed the pre-gate, Ruby's method list stopped at `open`/`new`, and Node's
/// API list had no truncate. They pass no mode, so they are always a Write.
#[test]
fn truncating_sinks_are_writes() {
    let target = "/home/test/.ssh/id_rsa";
    for (language, code) in [
        (
            Language::Python,
            format!("import os; os.truncate('{target}', 0)"),
        ),
        (
            Language::Python,
            format!("from os import truncate; truncate('{target}', 0)"),
        ),
        (Language::Ruby, format!("File.truncate('{target}', 0)")),
        (
            Language::Node,
            format!("require('fs').truncateSync('{target}', 0)"),
        ),
        (
            Language::Node,
            format!("require('fs').promises.truncate('{target}')"),
        ),
        (
            Language::Node,
            format!("const fs = require('fs'); fs.truncate('{target}', 0, () => {{}})"),
        ),
    ] {
        assert!(denied(&code, language), "{language:?}: {code}");
    }
    // Truncating an ordinary file is the everyday use and must stay allowed.
    for (language, code) in [
        (
            Language::Python,
            "import os; os.truncate('build/log.txt', 0)",
        ),
        (Language::Ruby, "File.truncate('log/app.log', 0)"),
        (
            Language::Node,
            "require('fs').truncateSync('dist/out.js', 0)",
        ),
    ] {
        assert!(!denied(code, language), "{language:?}: {code}");
    }
}

/// Home expansion counts only when the source performs it.
///
/// The bridge above pins that a bare `'~/.bashrc'` is NOT the home file — Python
/// and Ruby leave the tilde alone. This pins the other half: when
/// `os.path.expanduser` or `File.expand_path` wraps the literal, the same `~`
/// does name the home directory. Without it, the idiomatic spelling of an
/// `authorized_keys` append was allowed.
#[test]
fn home_expansion_is_honoured_only_when_the_source_performs_it() {
    assert!(protected("~/.bashrc", Access::Write, true).is_some());
    assert!(protected("~/.ssh/authorized_keys", Access::Append, true).is_some());
    assert!(protected("~/.ssh/known_hosts", Access::Append, true).is_none());
    assert!(protected("~/notes.txt", Access::Write, true).is_none());

    for (language, code) in [
        (
            Language::Python,
            "import os; open(os.path.expanduser('~/.ssh/authorized_keys'), 'a')",
        ),
        (
            Language::Python,
            "import os.path; open(os.path.expanduser('~/.ssh/id_rsa'), 'w')",
        ),
        (
            Language::Python,
            "from os.path import expanduser; open(expanduser('~/.ssh/id_rsa'), 'w')",
        ),
        (
            Language::Python,
            "from os import path; open(path.expanduser('~/.bashrc'), 'a')",
        ),
        // Aliased `import os.path as p` binds `p` to the module; it was the one
        // import spelling left unbound.
        (
            Language::Python,
            "import os.path as p; open(p.expanduser('~/.ssh/authorized_keys'), 'a')",
        ),
        (
            Language::Ruby,
            "File.open(File.expand_path('~/.ssh/authorized_keys'), 'a')",
        ),
    ] {
        assert!(denied(code, language), "{language:?}: {code}");
    }
    for (language, code) in [
        // Unwrapped: a directory named `~`, exactly as the bridge test says.
        (Language::Python, "open('~/notes.txt', 'w')"),
        // Wrapped, but an ordinary file.
        (
            Language::Python,
            "import os; open(os.path.expanduser('~/notes.txt'), 'w')",
        ),
        // Wrapped and protected, but a read.
        (
            Language::Python,
            "import os; print(open(os.path.expanduser('~/.ssh/id_rsa')).read())",
        ),
        // The append exemption survives expansion.
        (
            Language::Python,
            "import os; open(os.path.expanduser('~/.ssh/known_hosts'), 'a')",
        ),
    ] {
        assert!(!denied(code, language), "{language:?}: {code}");
    }
}

/// Only a real tilde prefix is left unquoted; anything else stays quoted.
///
/// `~user` is legitimate. `~$(id)` is not a tilde prefix at all, and splicing it
/// unquoted would hand the policy adapter a command substitution to parse. It is
/// judged fully quoted instead — still denied here, through the `.ssh/` anchor,
/// but without the adapter ever seeing shell syntax the source did not contain.
#[test]
fn only_a_word_tilde_prefix_is_left_unquoted() {
    assert!(protected("~root/.ssh/authorized_keys", Access::Write, true).is_some());
    assert!(protected("~$(id)/.ssh/id_rsa", Access::Write, true).is_some());
    assert!(protected("~$(id)/notes.txt", Access::Write, true).is_none());
    assert!(protected("~`id`/notes.txt", Access::Write, true).is_none());
}
/// Every sink name this module can reach must survive the cheap pre-gate in
/// `classify`.
///
/// The gate is a case-sensitive substring test over a handful of needles, and
/// the sink lists are written separately from it, so the two can disagree
/// without anything failing to compile. They did: `createWriteStream` is the
/// only name in `is_js_api` that spells "write" with a capital and carries
/// none of the other needles, so it never reached the parser and
/// `require('fs').createWriteStream('~/.ssh/id_rsa')` was allowed
/// while every other API on the same list denied.
///
/// Asserted end to end rather than against the needle list, so it keeps
/// holding if the gate is rewritten.
#[test]
fn every_sink_name_trips_the_pre_gate() {
    let target = "/home/test/.ssh/id_rsa";
    let commands = [
        format!(r#"node -e "require('fs').writeFile('{target}','x')""#),
        format!(r#"node -e "require('fs').writeFileSync('{target}','x')""#),
        format!(r#"node -e "require('fs').appendFile('{target}','x')""#),
        format!(r#"node -e "require('fs').appendFileSync('{target}','x')""#),
        format!(r#"node -e "require('fs').createWriteStream('{target}')""#),
        format!(r#"python3 -c "open('{target}','w')""#),
        format!(r#"python3 -c "import io; io.open('{target}','w')""#),
        format!(r#"python3 -c "from pathlib import Path; Path('{target}').write_text('x')""#),
        format!(r#"ruby -e "File.write('{target}','x')""#),
        format!(r#"ruby -e "File.binwrite('{target}','x')""#),
        format!(r#"ruby -e "File.open('{target}','w')""#),
        format!(r#"ruby -e "File.new('{target}','w')""#),
        // The truncating sinks, which nothing else exercises through this gate:
        // `truncating_sinks_are_writes` calls `inspect`, which skips it.
        // `os.truncate`, `fs.truncate` and `fs.truncateSync` carry none of the
        // other needles and pass only because `truncate` is listed, so without
        // them deleting that needle would pass every test and silently re-open
        // spellings #461 measured. `File.truncate` already passes on `File`
        // and is here so the list stays a complete inventory of sinks.
        format!(r#"python3 -c "import os; os.truncate('{target}', 0)""#),
        format!(r#"ruby -e "File.truncate('{target}', 0)""#),
        format!(r#"node -e "require('fs').truncate('{target}', 0, () => {{}})""#),
        format!(r#"node -e "require('fs').truncateSync('{target}', 0)""#),
    ];
    for command in commands {
        assert!(
            classify(&command, ShellDialect::Posix).is_some(),
            "sink did not reach the classifier: {command}"
        );
    }
}

/// A wrapper prefix must not change the answer (#464).
///
/// The classifier was always right about these — called directly it returns a
/// hit for every one — but the *candidate gate* read the first token as the
/// executable, so `sudo python3 …` presented `sudo`, which is neither a
/// credential writer nor an interpreter, and the pack was never made a
/// candidate. Twelve of twelve wrapped embedded spellings were allowed while
/// every shell spelling of the same write denied.
///
/// This asserts at the classifier, where the policy lives; the end-to-end
/// half, through the real hook and the gate that was actually broken, is
/// `tests/credential_file_embedded_e2e.rs`. Both are needed: this one alone
/// passed throughout the bug.
#[test]
fn a_wrapper_prefix_does_not_change_the_verdict() {
    const TARGET: &str = "/home/test/.bashrc";
    let sinks = [
        format!(r#"python3 -c "open('{TARGET}', 'w')""#),
        format!(r#"ruby -e "File.write('{TARGET}', 'x')""#),
        format!(r#"node -e "require('fs').writeFileSync('{TARGET}','x')""#),
    ];
    // `FOO=1` is an assignment prefix rather than a wrapper command, and it
    // reaches the same code path; a bare `sudo`/`env` is what an agent adds on
    // a retry, which is why this list is the retry vocabulary and not a
    // theoretical one.
    let prefixes = ["", "sudo ", "env ", "/usr/bin/env ", "FOO=1 "];

    for sink in &sinks {
        for prefix in prefixes {
            let command = format!("{prefix}{sink}");
            assert!(
                classify(&command, ShellDialect::Posix).is_some(),
                "a prefix changed the verdict: {command}"
            );
        }
    }
}

// Heredoc spellings are deliberately NOT asserted here. The evaluator extracts
// a heredoc body and judges it as its own segment, so `classify` on the raw
// `python3 <<'EOF' …` text answers None by design and an assertion at this
// layer would either fail for the wrong reason or pass vacuously. The heredoc
// contract lives end-to-end in `tests/credential_file_embedded_e2e.rs`, which
// drives the real hook.

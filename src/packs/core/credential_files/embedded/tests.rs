use super::*;

fn denied(code: &str, language: Language) -> bool {
    inspect(code, language, 0..code.len()).is_some()
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
    assert!(!protected(
        "/tmp/x'; tee /home/test/.bashrc; echo '",
        Access::Write
    ));
    assert!(!protected("$HOME/.bashrc", Access::Write));
    assert!(!protected("~/.bashrc", Access::Write));
    assert!(protected("/home/test/.ssh/authorized_keys", Access::Append));
    assert!(!protected("/home/test/.ssh/known_hosts", Access::Append));
    assert!(protected("/home/test/.ssh/known_hosts", Access::Write));
    for dialect in [ShellDialect::PowerShell, ShellDialect::Cmd] {
        assert!(classify(r#"python -c "open('/home/test/.bashrc','w')""#, dialect).is_none());
    }
}

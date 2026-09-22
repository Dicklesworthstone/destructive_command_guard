use super::*;

#[test]
fn ruby_flags_options_are_combined_with_the_effective_mode() {
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
            "File.new('.ssh/known_hosts', mode: 'ab:utf-8', flags: File::TRUNC)",
            true,
        ),
        (
            "File.open('.ssh/known_hosts', mode: 'w', flags: File::APPEND)",
            true,
        ),
        ("File.open('.bashrc', flags: File::WRONLY)", true),
        ("File.open('.bashrc', mode: 'r', flags: File::CREAT)", true),
        (
            "File.write('.ssh/known_hosts', 'host', flags: File::TRUNC, mode: 'a')",
            true,
        ),
        (
            "IO.binwrite('.ssh/known_hosts', 'host', mode: 'a', flags: File::TRUNC)",
            true,
        ),
        (
            "File.write('.ssh/known_hosts', 'host', flags: File::APPEND)",
            true,
        ),
        (
            "File.open('.ssh/known_hosts', mode: 'a', flags: extra)",
            true,
        ),
        ("File.open('.ssh/known_hosts', **options, mode: 'a')", true),
        (
            "File.open('.ssh/known_hosts', mode: 'a', flags: File::NONBLOCK)",
            false,
        ),
        (
            "File.open('.ssh/known_hosts', mode: File::WRONLY, flags: File::APPEND)",
            false,
        ),
        (
            "File.write('.ssh/known_hosts', 'host', mode: 'a', flags: File::NONBLOCK)",
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
        (
            "File.open('/tmp/proposal', mode: 'a', flags: File::TRUNC)",
            false,
        ),
    ] {
        let hits = scan_extracted(source, ScriptLanguage::Ruby).expect("complete analysis");
        assert_eq!(!hits.is_empty(), blocked, "{source}: {hits:?}");
    }
}

#[test]
fn ruby_parenthesized_flags_require_one_expression() {
    for (source, blocked) in [
        ("File.sysopen('.bashrc', (File::WRONLY))", true),
        (
            "File.sysopen('.ssh/known_hosts', (File::WRONLY | File::APPEND))",
            false,
        ),
        (
            "File.sysopen('.ssh/known_hosts', (File::WRONLY | File::APPEND | File::TRUNC))",
            true,
        ),
        (
            "File.sysopen('.ssh/known_hosts', (File::WRONLY; File::RDONLY))",
            false,
        ),
        ("File.sysopen('.ssh/known_hosts', ())", false),
    ] {
        let hits = scan_extracted(source, ScriptLanguage::Ruby).expect("complete analysis");
        assert_eq!(!hits.is_empty(), blocked, "{source}: {hits:?}");
    }
}

#[test]
fn low_level_open_writers_reach_the_shared_policy() {
    for (language, source) in [
        (
            ScriptLanguage::Python,
            "import os; os.open('/etc/shadow', os.O_WRONLY | os.O_TRUNC)",
        ),
        (
            ScriptLanguage::Python,
            "from os import open as acquire, O_WRONLY as W, O_CREAT as C; acquire(path='.bashrc', flags=W | C)",
        ),
        (
            ScriptLanguage::Python,
            "import os as disk; flags = disk.O_RDWR; acquire = disk.open; acquire('.bashrc', flags)",
        ),
        (
            ScriptLanguage::Python,
            "import os; os.open(os.path.expanduser('~/.ssh/authorized_keys'), os.O_WRONLY | os.O_APPEND)",
        ),
        (
            ScriptLanguage::JavaScript,
            "require('fs').openSync('.bashrc', 'w')",
        ),
        (
            ScriptLanguage::JavaScript,
            "require('fs').open('.bashrc', 'r+', () => {})",
        ),
        (
            ScriptLanguage::JavaScript,
            "require('node:fs/promises').open('.bashrc', 'a')",
        ),
        (
            ScriptLanguage::JavaScript,
            "import {open as acquire, constants as C} from 'node:fs/promises'; acquire('.bashrc', C.O_WRONLY | C.O_CREAT)",
        ),
        (
            ScriptLanguage::JavaScript,
            "const {openSync: acquire, constants: C} = require('fs'); const {O_WRONLY: W} = C; acquire('.bashrc', W | C.O_TRUNC)",
        ),
        (
            ScriptLanguage::JavaScript,
            "const fs = require('fs'); fs['openSync']('.bashrc', fs['constants']['O_WRONLY'])",
        ),
        (
            ScriptLanguage::TypeScript,
            "import * as fs from 'node:fs'; const mode: number = fs.constants.O_RDWR; fs.openSync('.bashrc', mode)",
        ),
        (ScriptLanguage::Ruby, "File.sysopen('.bashrc', 'w')"),
        (
            ScriptLanguage::Ruby,
            "IO.sysopen('.bashrc', File::WRONLY | File::TRUNC)",
        ),
        (
            ScriptLanguage::Ruby,
            "F = File; mode = F::WRONLY | F::CREAT; F.open('.bashrc', mode)",
        ),
        (
            ScriptLanguage::Ruby,
            "File.new('.bashrc', File::Constants::RDWR)",
        ),
        (
            ScriptLanguage::Ruby,
            "File.open('.bashrc', mode: File::WRONLY | File::APPEND)",
        ),
        (ScriptLanguage::Ruby, "IO.write('.bashrc', 'data')"),
        (ScriptLanguage::Ruby, "IO.binwrite('.bashrc', 'data')"),
    ] {
        let hits = scan_extracted(source, language).expect("complete analysis");
        assert_eq!(hits.len(), 1, "{source}: {hits:?}");
        assert_eq!(hits[0].rule, shell::CREDENTIAL_FILE_WRITE_NAME, "{source}");
        assert!(source.get(hits[0].span.clone()).is_some(), "{source}");
    }
}

#[test]
fn low_level_open_append_requires_complete_non_truncating_flags() {
    for (language, prefix, operation, append, truncate) in [
        (
            ScriptLanguage::Python,
            "import os; ",
            "os.open",
            "os.O_WRONLY | os.O_CREAT | os.O_APPEND",
            "os.O_TRUNC",
        ),
        (
            ScriptLanguage::JavaScript,
            "const fs = require('fs'); ",
            "fs.openSync",
            "fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_APPEND",
            "fs.constants.O_TRUNC",
        ),
        (
            ScriptLanguage::Ruby,
            "",
            "File.sysopen",
            "File::WRONLY | File::CREAT | File::APPEND",
            "File::TRUNC",
        ),
    ] {
        for (flags, blocked) in [
            (append.to_string(), false),
            (format!("{append} | {truncate}"), true),
            (format!("{truncate} | ({append})"), true),
            (format!("{append} | extra"), true),
            (format!("extra | ({append})"), true),
        ] {
            let source = format!("{prefix}{operation}('/home/u/.ssh/known_hosts', {flags})");
            let hits = scan_extracted(&source, language).expect("complete analysis");
            assert_eq!(!hits.is_empty(), blocked, "{source}: {hits:?}");
        }
    }
    for source in [
        "const fs = require('fs'); fs.writeFileSync('.ssh/known_hosts', 'host', {flag: fs.constants.O_WRONLY | fs.constants.O_APPEND})",
        "const fs = require('fs'); fs.createWriteStream('.ssh/known_hosts', {flags: fs.constants.O_WRONLY | fs.constants.O_APPEND})",
    ] {
        assert!(
            scan_extracted(source, ScriptLanguage::JavaScript)
                .unwrap()
                .is_empty(),
            "{source}"
        );
    }
    let source = "const fs = require('fs'); fs.appendFileSync('.ssh/known_hosts', 'host', {flag: fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_TRUNC})";
    assert_eq!(
        scan_extracted(source, ScriptLanguage::JavaScript)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn low_level_open_read_modes_and_unproven_receivers_stay_clear() {
    for (language, source) in [
        (
            ScriptLanguage::Python,
            "import os; os.open('/etc/shadow', os.O_RDONLY | os.O_CLOEXEC)",
        ),
        (
            ScriptLanguage::Python,
            "import os; os.open('/etc/shadow', flags)",
        ),
        (
            ScriptLanguage::Python,
            "import os; os.open('/etc/shadow', 'w')",
        ),
        (
            ScriptLanguage::Python,
            "import os; open('/etc/shadow', os.O_WRONLY)",
        ),
        (
            ScriptLanguage::Python,
            "import os; os = storage; os.open('/etc/shadow', os.O_WRONLY)",
        ),
        (
            ScriptLanguage::Python,
            "from unrelated import open, O_WRONLY; open('/etc/shadow', O_WRONLY)",
        ),
        (
            ScriptLanguage::Python,
            "import os; os.open('/tmp/output', os.O_WRONLY | os.O_TRUNC)",
        ),
        (
            ScriptLanguage::JavaScript,
            "require('fs').openSync('/etc/shadow')",
        ),
        (
            ScriptLanguage::JavaScript,
            "const fs = require('fs'); fs.openSync('/etc/shadow', fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW)",
        ),
        (
            ScriptLanguage::JavaScript,
            "const fs = require('fs'); const constants = storage; fs.openSync('/etc/shadow', constants.O_WRONLY)",
        ),
        (
            ScriptLanguage::JavaScript,
            "function f(require) { require('fs').openSync('/etc/shadow', 'w') }",
        ),
        (
            ScriptLanguage::JavaScript,
            "require('fs').openSync('/tmp/output', 'w')",
        ),
        (ScriptLanguage::Ruby, "File.sysopen('/etc/shadow')"),
        (
            ScriptLanguage::Ruby,
            "File.open('/etc/shadow', File::RDONLY | File::NONBLOCK)",
        ),
        (ScriptLanguage::Ruby, "IO.open('/etc/shadow', 'w')"),
        (ScriptLanguage::Ruby, "IO.new('/etc/shadow', 'w')"),
        (
            ScriptLanguage::Ruby,
            "File = Store; File.sysopen('/etc/shadow', 'w')",
        ),
        (ScriptLanguage::Ruby, "File.sysopen('~/.bashrc', 'w')"),
        (
            ScriptLanguage::Ruby,
            "puts \"File.sysopen('/etc/shadow', 'w')\"",
        ),
    ] {
        assert!(
            scan_extracted(source, language)
                .expect("complete analysis")
                .is_empty(),
            "{source}"
        );
    }
}

#[test]
fn low_level_open_creating_and_read_write_flags_are_not_read_only() {
    for (language, source) in [
        (
            ScriptLanguage::Python,
            "import os; os.open('.bashrc', os.O_RDONLY | os.O_CREAT)",
        ),
        (
            ScriptLanguage::Python,
            "import os; os.open('.ssh/known_hosts', os.O_RDWR)",
        ),
        (
            ScriptLanguage::Python,
            "import os; os.open('.ssh/known_hosts', os.O_RDONLY | os.O_TRUNC)",
        ),
        (
            ScriptLanguage::JavaScript,
            "const fs = require('fs'); fs.openSync('.ssh/known_hosts', fs.constants.O_CREAT | fs.constants.O_EXCL)",
        ),
        (
            ScriptLanguage::Ruby,
            "File.open('.ssh/known_hosts', File::RDWR)",
        ),
        (
            ScriptLanguage::Ruby,
            "File.write('.ssh/known_hosts', 'host', mode: File::WRONLY | File::TRUNC)",
        ),
    ] {
        assert_eq!(
            scan_extracted(source, language).unwrap().len(),
            1,
            "{source}"
        );
    }
    // Internal semantic bits must never be confused with native numeric flags.
    assert_eq!(
        OpenFlags::named("RDONLY").unwrap().access(),
        Some(Access::Read)
    );
    assert!(OpenFlags::prefixed("WRONLY").is_none());
    assert!(OpenFlags::named("CUSTOM_FLAG").is_none());
    assert!(combine_open_flags(None, None).is_none());
    let Some(Value::Flags(partial)) = combine_open_flags(
        Some(Value::Flags(OpenFlags::named("RDONLY").unwrap())),
        None,
    ) else {
        panic!("partial flags");
    };
    assert_eq!(partial.access(), None);
}

#[test]
fn ruby_write_payload_cannot_supply_an_append_only_mode() {
    for source in [
        "File.write('.ssh/known_hosts', {mode: 'a'})",
        "File.binwrite('.ssh/known_hosts', {nested: {mode: 'a'}})",
        "IO.write('.ssh/known_hosts', {mode: 'a'})",
        "File.write('.ssh/known_hosts', 'host', mode: 'a', **options)",
    ] {
        assert_eq!(
            scan_extracted(source, ScriptLanguage::Ruby).unwrap().len(),
            1,
            "{source}"
        );
    }
    for source in [
        "File.write('.ssh/known_hosts', {mode: 'w'}, mode: 'a')",
        "File.write('.ssh/known_hosts', 'host', mode: File::WRONLY | File::APPEND)",
        "IO.write('.ssh/known_hosts', 'host', mode: 'a')",
    ] {
        assert!(
            scan_extracted(source, ScriptLanguage::Ruby)
                .unwrap()
                .is_empty(),
            "{source}"
        );
    }
}

#[test]
fn low_level_open_keeps_both_rules_and_assignment_effects() {
    for (language, source) in [
        (
            ScriptLanguage::Python,
            "import os; os.open('.bashrc', os.O_WRONLY); os = os.open('.git/config', os.O_WRONLY)",
        ),
        (
            ScriptLanguage::JavaScript,
            "let fs = require('fs'); fs.openSync('.git/config', 'w'); fs = fs.openSync('.bashrc', 'w')",
        ),
        (
            ScriptLanguage::Ruby,
            "File.sysopen('.bashrc', 'w'); File = File.sysopen('.git/config', 'w')",
        ),
    ] {
        let mut actual: Vec<_> = scan_extracted(source, language)
            .unwrap()
            .into_iter()
            .map(|hit| hit.rule)
            .collect();
        actual.sort_unstable();
        assert_eq!(
            actual,
            [
                shell::CREDENTIAL_FILE_WRITE_NAME,
                shell::GIT_INTERNALS_WRITE_NAME
            ],
            "{source}"
        );
    }
}

fn denied(code: &str, language: Language) -> bool {
    let mut hits = Vec::new();
    inspect(code, language, 0..code.len(), &mut hits);
    !hits.is_empty()
}

#[test]
fn node_composed_paths_preserve_builtin_module_provenance() {
    for code in [
        "const os = require('os'); require('fs').writeFileSync(os.homedir() + '/.bashrc', 'x')",
        "const {homedir: home} = require('node:os'); const {join: J} = require('node:path'); require('fs').writeFileSync(J(home(), '.ssh', 'id_rsa'), 'x')",
        "import {homedir as H} from 'node:os'; import {join as J} from 'node:path'; import {writeFileSync as save} from 'node:fs'; save(J(H(), '.aws', 'credentials'), 'x')",
        "import * as os from 'os'; import path from 'path'; require('fs').writeFileSync(path.join(os.homedir(), '.bashrc'), 'x')",
        "require('fs').writeFileSync(require('path/posix').join('/etc', 'shadow'), 'x')",
        "require('fs').writeFileSync(require('node:path').posix.resolve('/tmp', '/etc', 'shadow'), 'x')",
        "require('fs').writeFileSync(require('path').join('/tmp', '..', 'etc', 'shadow'), 'x')",
        "require('fs').writeFileSync(require('path').join(require('os').homedir(), '.ssh', '..', '.bashrc'), 'x')",
        "require('fs').writeFileSync(process.env.HOME + '/.bashrc', 'x')",
        "require('fs').writeFileSync(process.env['HOME'] + '/.bashrc', 'x')",
        "const {env: E} = require('node:process'); require('fs').writeFileSync(E.HOME + '/.bashrc', 'x')",
        "const {HOME: home} = process.env; require('fs').writeFileSync(home + '/.bashrc', 'x')",
        "import {env} from 'node:process'; require('fs').writeFileSync(env.HOME + '/.bashrc', 'x')",
        "const home = require('os')['homedir']; require('fs')['writeFileSync'](home() + '/.bashrc', 'x')",
    ] {
        for language in [ScriptLanguage::JavaScript, ScriptLanguage::TypeScript] {
            let hits = scan_extracted(code, language).expect(code);
            assert_eq!(hits.len(), 1, "{language:?}: {code}: {hits:?}");
            assert_eq!(hits[0].rule, shell::CREDENTIAL_FILE_WRITE_NAME, "{code}");
            assert!(code.get(hits[0].span.clone()).is_some(), "{code}");
        }
    }
}

#[test]
fn node_composed_paths_preserve_join_resolve_and_safe_controls() {
    for code in [
        "require('fs').writeFileSync(require('path').join('/tmp', '/etc', 'shadow'), 'x')",
        "require('fs').writeFileSync(require('path').resolve(require('os').homedir(), '/tmp/dcg-preview'), 'x')",
        "require('fs').writeFileSync(require('path').join(require('os').homedir(), 'notes.txt'), 'x')",
        "require('fs').writeFileSync(require('path').join('~', '.bashrc'), 'x')",
        "require('fs').readFileSync(require('path').join(require('os').homedir(), '.ssh', 'id_rsa'))",
        "require('fs').appendFileSync(require('path').join(require('os').homedir(), '.ssh', 'known_hosts'), 'host')",
        "const os = require('unrelated'); require('fs').writeFileSync(os.homedir() + '/.bashrc', 'x')",
        "const {join} = require('unrelated'); require('fs').writeFileSync(join('/etc', 'shadow'), 'x')",
        "let os = require('os'); os = store; require('fs').writeFileSync(os.homedir() + '/.bashrc', 'x')",
        "const process = store; require('fs').writeFileSync(process.env.HOME + '/.bashrc', 'x')",
        "const {env: E} = process; E.HOME = unknown; require('fs').writeFileSync(E.HOME + '/.bashrc', 'x')",
        "require('fs').writeFileSync(require('path').join(unknown, '.bashrc'), 'x')",
        "require('fs').writeFileSync(require('path').win32.join('C:\\\\scratch', '.bashrc'), 'x')",
        "console.log(\"require('fs').writeFileSync(require('path').join('/etc', 'shadow'), 'x')\")",
    ] {
        assert!(!denied(code, Language::Node), "{code}");
    }
    let code = "require('fs').appendFileSync(require('path').join(require('os').homedir(), '.ssh', 'known_hosts'), 'host', {flag: 'w'})";
    assert!(denied(code, Language::Node), "{code}");
    assert_eq!(
        concatenate_path(("/tmp".into(), false), ("/etc/shadow".into(), false)),
        Some(("/tmp/etc/shadow".into(), false)),
    );
    assert!(concatenate_path(("/tmp".into(), false), ("~/.bashrc".into(), true)).is_none());
    assert!(
        concatenate_path(
            ("x".repeat(MAX_STATIC_PATH_BYTES), false),
            ("y".into(), false)
        )
        .is_none()
    );
    assert!(
        concatenate_text(
            Value::HomePath("~".into()),
            Value::Text("other/.bashrc".into())
        )
        .is_none()
    );
}

#[test]
fn node_path_normalization_preserves_runtime_home_boundaries() {
    for (path, home, trailing, expected) in [
        ("/tmp/../etc/shadow", false, true, Some("/etc/shadow")),
        ("//tmp/../../etc//shadow", false, true, Some("/etc/shadow")),
        ("~/.ssh/../.bashrc", true, true, Some("~/.bashrc")),
        ("~/../etc/shadow", true, true, None),
        ("~/../etc/shadow", false, true, Some("etc/shadow")),
        ("../../etc/shadow", false, true, Some("../../etc/shadow")),
        ("/etc/./", false, true, Some("/etc/")),
        ("/etc/./", false, false, Some("/etc")),
    ] {
        assert_eq!(
            normalize_node_path((path.into(), home), trailing),
            expected.map(|path| (path.into(), home)),
            "{path}",
        );
    }
}

#[test]
fn ruby_composed_paths_preserve_home_and_literal_controls() {
    for code in [
        "File.write(File.join(Dir.home, '.bashrc'), 'x')",
        "File.write(File.join(Dir.home(), '.ssh', 'id_rsa'), 'x')",
        "File.open(Dir.home + '/.bashrc', 'w')",
        "File.write(File.join('/etc', 'shadow'), 'x')",
        "File.write(File.expand_path(File.join('~', '.bashrc')), 'x')",
        "File.write(File.join(File.expand_path('~'), '.bashrc'), 'x')",
        "home = Dir.home; File.write(File.join(home, '.bashrc'), 'x')",
    ] {
        assert!(denied(code, Language::Ruby), "{code}");
    }
    for code in [
        "File.write(File.join('~', '.bashrc'), 'x')",
        "File.write(File.join(Dir.home, 'notes.txt'), 'x')",
        "File.write(File.join('/tmp', '/etc', 'shadow'), 'x')",
        "File.read(File.join(Dir.home, '.ssh', 'id_rsa'))",
        "File.open(File.join(Dir.home, '.ssh', 'known_hosts'), 'a')",
        "Dir = Store; File.write(File.join(Dir.home, '.bashrc'), 'x')",
        "File.write(File.join(unknown, '.bashrc'), 'x')",
        "puts \"File.write(File.join(Dir.home, '.bashrc'), 'x')\"",
    ] {
        assert!(!denied(code, Language::Ruby), "{code}");
    }
}

#[test]
fn node_and_ruby_composed_paths_preserve_both_transfer_rules() {
    for (language, code) in [
        (
            ScriptLanguage::JavaScript,
            "require('fs').renameSync(require('path').join(require('os').homedir(), '.bashrc'), '.git/config')",
        ),
        (
            ScriptLanguage::TypeScript,
            "import {join} from 'node:path'; import {homedir} from 'node:os'; require('fs').renameSync('.git/config', join(homedir(), '.bashrc'))",
        ),
        (
            ScriptLanguage::Ruby,
            "File.rename(File.join(Dir.home, '.bashrc'), '.git/config')",
        ),
        (
            ScriptLanguage::Ruby,
            "File.rename('.git/config', File.join(Dir.home, '.bashrc'))",
        ),
    ] {
        let hits = scan_extracted(code, language).expect(code);
        assert_eq!(hits.len(), 2, "{code}: {hits:?}");
        assert!(
            hits.iter()
                .any(|hit| hit.rule == shell::CREDENTIAL_FILE_WRITE_NAME)
        );
        assert!(
            hits.iter()
                .any(|hit| hit.rule == shell::GIT_INTERNALS_WRITE_NAME)
        );
        assert_eq!(hits[0].span, hits[1].span, "{code}");
    }
}

#[test]
fn python_composed_paths_reach_the_shared_policy() {
    for code in [
        "from pathlib import Path; (Path.home() / '.ssh' / 'id_rsa').write_text('x')",
        "from pathlib import Path as P; P.home().joinpath('.aws', 'credentials').write_bytes(b'x')",
        "import pathlib; pathlib.Path('/etc', 'shadow').write_text('x')",
        "from pathlib import PosixPath as P; P('/etc').joinpath('shadow').open(mode='r+')",
        "from pathlib import Path; Path('~/.bashrc').expanduser().write_text('x')",
        "from pathlib import Path; (Path('~').expanduser() / '.bashrc').write_text('x')",
        "from pathlib import Path; import os; Path(os.path.expanduser('~'), '.bashrc').write_text('x')",
        "from pathlib import Path; open(str(Path.home()) + '/.bashrc', 'w')",
        "from pathlib import Path; ('/etc' / Path('shadow')).write_text('x')",
        "from pathlib import Path; (Path('/tmp') / '/etc' / 'shadow').write_text('x')",
        "from pathlib import Path; Path(unknown_base, '/etc', 'shadow').write_text('x')",
        "import os; open(os.path.join(os.path.expanduser('~'), '.bashrc'), 'w')",
        "from os.path import join as J, expanduser as H; open(J(H('~'), '.ssh', 'authorized_keys'), 'a')",
        "import os.path as p; open(p.join('/etc', 'sha' + 'dow'), 'w')",
        "import os; open(os.environ['HOME'] + '/.bashrc', 'w')",
        "from os import environ as E; open(E['HOME'] + '/.bashrc', 'a')",
        "from os import getenv as H; open(H('HOME') + '/.bashrc', 'w')",
        "import os; open(os.environ.get('HOME') + '/.bashrc', 'w')",
        "from pathlib import Path; root = Path.home(); save = root.joinpath('.bashrc').write_text; save('x')",
    ] {
        let hits = scan_extracted(code, ScriptLanguage::Python).expect(code);
        assert_eq!(hits.len(), 1, "{code}: {hits:?}");
        assert_eq!(hits[0].rule, shell::CREDENTIAL_FILE_WRITE_NAME, "{code}");
        assert!(code.get(hits[0].span.clone()).is_some(), "{code}");
    }
}

#[test]
fn python_composed_paths_keep_literal_and_read_controls() {
    for code in [
        "from pathlib import Path; Path('~/.bashrc').write_text('x')",
        "from pathlib import Path; (Path('~') / '.bashrc').write_text('x')",
        "from pathlib import Path; (Path.home() / 'notes.txt').write_text('x')",
        "from pathlib import Path; (Path.home() / '/tmp/dcg-preview').write_text('x')",
        "import os; open(os.path.join(os.path.expanduser('~'), '/tmp/dcg-preview'), 'w')",
        "from pathlib import Path; Path('/etc', 'shadow').read_text()",
        "from pathlib import Path; (Path.home() / '.ssh' / 'id_rsa').open('r')",
        "from pathlib import Path; Path.home().joinpath('.ssh', 'known_hosts').open('a')",
        "from pathlib import Path; (unknown_root / '.bashrc').write_text('x')",
        "from pathlib import Path; Path = Store; (Path.home() / '.bashrc').write_text('x')",
        "import os; os = store; open(os.environ['HOME'] + '/.bashrc', 'w')",
        "from os import environ as E; E['HOME'] = unknown; open(E['HOME'] + '/.bashrc', 'w')",
        "from os.path import join as J; J = store; open(J('/etc', 'shadow'), 'w')",
        "import os; open(os.path.join(unknown, '.bashrc'), 'w')",
        "print(\"Path.home().joinpath('.bashrc').write_text('x')\")",
    ] {
        assert!(!denied(code, Language::Python), "{code}");
    }
}

#[test]
fn python_composed_paths_preserve_both_transfer_effects() {
    for code in [
        "from pathlib import Path; (Path.home() / '.bashrc').replace('.git/config')",
        "from pathlib import Path; Path('.git', 'config').rename(Path.home().joinpath('.bashrc'))",
        "from pathlib import Path; import shutil; shutil.move(Path.home().joinpath('.bashrc'), '.git')",
    ] {
        let hits = scan_extracted(code, ScriptLanguage::Python).expect(code);
        assert_eq!(hits.len(), 2, "{code}: {hits:?}");
        assert!(
            hits.iter()
                .any(|hit| hit.rule == shell::CREDENTIAL_FILE_WRITE_NAME)
        );
        assert!(
            hits.iter()
                .any(|hit| hit.rule == shell::GIT_INTERNALS_WRITE_NAME)
        );
        assert_eq!(hits[0].span, hits[1].span, "{code}");
    }
    assert!(!denied(
        "from pathlib import Path; import shutil; shutil.copyfile(Path.home().joinpath('.bashrc'), '/tmp/dcg-backup')",
        Language::Python,
    ));
}

#[test]
fn python_composed_paths_join_and_concatenate_without_host_state() {
    for (base, next, expected) in [
        (("~", true), (".bashrc", false), ("~/.bashrc", true)),
        (
            ("~", true),
            ("/tmp/preview", false),
            ("/tmp/preview", false),
        ),
        (("/tmp", false), ("~/.bashrc", true), ("~/.bashrc", true)),
        (
            ("/tmp", false),
            ("~/.bashrc", false),
            ("/tmp/~/.bashrc", false),
        ),
        (("", false), ("/etc/shadow", false), ("/etc/shadow", false)),
    ] {
        assert_eq!(
            python_join_path(Some((base.0.into(), base.1)), (next.0.into(), next.1)),
            Some((expected.0.into(), expected.1)),
        );
    }
    assert_eq!(
        python_join_path(None, ("/etc/shadow".into(), false)),
        Some(("/etc/shadow".into(), false)),
    );
    assert!(python_join_path(None, (".bashrc".into(), false)).is_none());
    assert!(
        concatenate_text(
            Value::Path(("/etc".into(), false)),
            Value::Text("/shadow".into())
        )
        .is_none()
    );
    assert!(concatenate_text(Value::Text("prefix".into()), Value::HomePath("~".into())).is_none());
    assert!(
        concatenate_text(
            Value::Text("x".repeat(MAX_STATIC_PATH_BYTES)),
            Value::Text("x".into())
        )
        .is_none()
    );
    assert!(
        python_join_path(
            Some(("x".repeat(MAX_STATIC_PATH_BYTES), false)),
            ("y".into(), false)
        )
        .is_none()
    );
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

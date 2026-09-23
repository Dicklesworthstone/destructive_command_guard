//! File transfers share the protected-write policy (#461).
//!
//! A copy reads its source and writes its destination. A rename or move also
//! removes the source name. Inspect those effects independently: a dynamic
//! source must not hide a known protected destination, and one allowlisted
//! rule must not hide the other rule on the opposite end of one operation.
//!
//! Keep exact-path APIs separate from directory-placement and whole-tree APIs.
//! Python copy/copy2/move can place the source basename inside a destination
//! directory; copytree writes the destination tree itself, not dst/basename(src).
//! The existing shell classifier supplies the path table and placement policy.
//! No candidate is executed and no directory is traversed to determine its type.
//! Links create the destination name, never remove or write their source. A
//! symbolic link can redirect an entire protected tree; a hard link cannot.

use super::{
    Access, Bindings, CredentialFileWrite, Language, ResolvedPath, ShellDialect, Syntax, Value,
    arguments, path_value, protected, python_argument, quote_policy_path, shell, value,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Operation {
    CopyFile,
    Rename,
    Copy,
    Move,
    CopyTree,
    HardLink,
    SymbolicLink,
}

pub(super) fn shutil_operation(name: &str) -> Option<Operation> {
    match name {
        "copyfile" => Some(Operation::CopyFile),
        "copy" | "copy2" => Some(Operation::Copy),
        "move" => Some(Operation::Move),
        "copytree" => Some(Operation::CopyTree),
        _ => None,
    }
}

pub(super) fn js_operation(name: &str) -> Option<Operation> {
    match name {
        "copyFile" | "copyFileSync" => Some(Operation::CopyFile),
        "rename" | "renameSync" => Some(Operation::Rename),
        "link" | "linkSync" => Some(Operation::HardLink),
        "symlink" | "symlinkSync" => Some(Operation::SymbolicLink),
        // `fs.cp` is Node's recursive copy and the twin of `shutil.copytree`,
        // which Python already covers (#484). It is a TREE write rather than a
        // placement: unlike `cp(1)`, it writes `dest` itself and never
        // `dest/basename(src)`.
        "cp" | "cpSync" => Some(Operation::CopyTree),
        _ => None,
    }
}

struct Transfer {
    operation: Operation,
    source: Option<ResolvedPath>,
    destination: Option<ResolvedPath>,
    api: String,
}

fn classify(node: &Syntax<'_>, language: Language, env: &Bindings) -> Option<Transfer> {
    if !matches!(node.kind().as_ref(), "call" | "call_expression") {
        return None;
    }
    let args = arguments(node);
    let path = |argument: &Syntax<'_>| path_value(argument, language, env);
    if language == Language::Ruby {
        let method = node.field("method")?.text().into_owned();
        let receiver = value(&node.field("receiver")?, language, env, 0)?;
        let (operation, api) = match (receiver, method.as_str()) {
            (Value::File, "rename") => (Operation::Rename, "File.rename".to_string()),
            (Value::File, "link") => (Operation::HardLink, "File.link".to_string()),
            (Value::File, "symlink") => (Operation::SymbolicLink, "File.symlink".to_string()),
            (Value::Io | Value::File, "copy_stream") => {
                (Operation::CopyFile, "IO.copy_stream".to_string())
            }
            // FileUtils is Ruby's shutil, and every verb here has a Python twin
            // this module already reads (#484). The placement/exact split is the
            // same one shutil gets: `cp`, `cp_r` and `install` put the source
            // basename INSIDE dest when dest is a directory, while `copy_file`
            // names the destination itself.
            //
            // `touch` is absent on purpose: it creates or restamps, it does not
            // truncate, so it destroys nothing. The `rm_*` family is absent for
            // the opposite reason -- it is a deletion, and the recursive-delete
            // policy in `ast_pattern_engine` already owns those spellings.
            (Value::FileUtils, method_name) => {
                let operation = match method_name {
                    "cp" | "copy" | "cp_r" | "copy_entry" | "install" => Operation::Copy,
                    "copy_file" => Operation::CopyFile,
                    "mv" | "move" => Operation::Move,
                    "ln" | "link" | "link_entry" => Operation::HardLink,
                    "ln_s" | "ln_sf" | "symlink" => Operation::SymbolicLink,
                    _ => return None,
                };
                (operation, format!("FileUtils.{method_name}"))
            }
            _ => return None,
        };
        return Some(Transfer {
            operation,
            source: path(args.first()?),
            destination: path(args.get(1)?),
            api,
        });
    }
    let function = node.field("function")?;
    match value(&function, language, env, 0)? {
        Value::Transfer(operation) if language == Language::Python => {
            // Both argument nodes must exist, but either value may be unknown.
            let source = python_argument(&args, 0, "src")?;
            let destination = python_argument(&args, 1, "dst")?;
            Some(Transfer {
                operation,
                source: path(&source),
                destination: path(&destination),
                api: function.text().into_owned(),
            })
        }
        Value::PathTransfer(source) if language == Language::Python => {
            let destination = python_argument(&args, 0, "target")?;
            Some(Transfer {
                operation: Operation::Rename,
                source: Some(source),
                destination: path(&destination),
                api: function.text().into_owned(),
            })
        }
        Value::PathLink(destination, operation) if language == Language::Python => {
            // pathlib reverses os.link/os.symlink: the receiver is the NEW
            // name, and `target` is what it refers to. Keep this distinction
            // even when the target value is dynamic or the method is aliased.
            let source = python_argument(&args, 0, "target")?;
            Some(Transfer {
                operation,
                source: path(&source),
                destination: Some(destination),
                api: function.text().into_owned(),
            })
        }
        Value::Api(api) if language == Language::Node => Some(Transfer {
            operation: js_operation(&api)?,
            source: path(args.first()?),
            destination: path(args.get(1)?),
            api: format!("fs.{api}"),
        }),
        _ => None,
    }
}

pub(super) fn scan(
    node: &Syntax<'_>,
    language: Language,
    env: &Bindings,
    hits: &mut Vec<CredentialFileWrite>,
) {
    let Some(transfer) = classify(node, language, env) else {
        return;
    };
    // Destination semantics are part of the API, not a guess based on whether
    // this machine happens to have the target directory. Exclusive/no-clobber
    // flags still permit creation; they are not append-only exemptions.
    match transfer.operation {
        Operation::CopyFile | Operation::Rename => record(
            node,
            &transfer.api,
            "creates or replaces",
            transfer.destination.as_ref(),
            hits,
        ),
        Operation::Copy | Operation::Move => record_placement(
            node,
            &transfer.api,
            transfer.source.as_ref(),
            transfer.destination.as_ref(),
            hits,
        ),
        Operation::CopyTree => record_tree(
            node,
            &transfer.api,
            "writes a tree at",
            transfer.destination.as_ref(),
            hits,
        ),
        Operation::HardLink => record(
            node,
            &transfer.api,
            "creates a hard link at",
            transfer.destination.as_ref(),
            hits,
        ),
        Operation::SymbolicLink => record_tree(
            node,
            &transfer.api,
            "creates a symbolic link at",
            transfer.destination.as_ref(),
            hits,
        ),
    }
    match transfer.operation {
        Operation::Rename => record(
            node,
            &transfer.api,
            "removes the source name of",
            transfer.source.as_ref(),
            hits,
        ),
        // shutil.move also moves directories, including a .aws/.config tree
        // whose root is not itself a protected file. Copy operations never
        // inspect this source-side mutation: they only read their sources.
        Operation::Move => record_tree(
            node,
            &transfer.api,
            "removes the source path or tree at",
            transfer.source.as_ref(),
            hits,
        ),
        Operation::CopyFile
        | Operation::Copy
        | Operation::CopyTree
        | Operation::HardLink
        | Operation::SymbolicLink => {}
    }
}

fn record(
    node: &Syntax<'_>,
    api: &str,
    effect: &str,
    path: Option<&ResolvedPath>,
    hits: &mut Vec<CredentialFileWrite>,
) {
    let Some((path, expands_home)) = path else {
        return;
    };
    let Some(rule) = protected(path, Access::Write, *expands_home) else {
        return;
    };
    record_rule(node, api, effect, path, rule, hits);
}

fn record_rule(
    node: &Syntax<'_>,
    api: &str,
    effect: &str,
    path: &str,
    rule: &'static str,
    hits: &mut Vec<CredentialFileWrite>,
) {
    if !hits.iter().any(|hit| hit.rule == rule) {
        hits.push(CredentialFileWrite {
            span: node.range(),
            rule,
            reason: format!(
                "{api} {effect} protected target {path:?}. File transfers are not append-only updates. Stage the proposed change for review or use dcg allow-once."
            ),
        });
    }
}

/// A directory-capable destination can be either an exact file or a container.
/// Check both possibilities, preserving the known source basename for the
/// latter. Copying notes.txt into /home/u is not a write to /home/u/.bashrc.
fn record_placement(
    node: &Syntax<'_>,
    api: &str,
    source: Option<&ResolvedPath>,
    destination: Option<&ResolvedPath>,
    hits: &mut Vec<CredentialFileWrite>,
) {
    record(node, api, "creates or replaces", destination, hits);
    let Some((destination, expands_home)) = destination else {
        return;
    };
    let source = source.map_or_else(
        // In the shared placement policy, '.' represents unknown contents.
        // Do not invent a harmless basename for an unresolved source operand.
        || "'.'".to_string(),
        |(path, expands)| quote_policy_path(path, *expands),
    );
    record_directory_policy(
        node,
        api,
        "places a source into",
        destination,
        *expands_home,
        &source,
        hits,
    );
}

/// Whole-tree writes and source-directory removal affect protected descendants,
/// not only the directory entry. Reuse the shell policy's unknown-contents
/// judgment; do not infer an inventory, follow symlinks, or apply ignore filters.
fn record_tree(
    node: &Syntax<'_>,
    api: &str,
    effect: &str,
    path: Option<&ResolvedPath>,
    hits: &mut Vec<CredentialFileWrite>,
) {
    record(node, api, effect, path, hits);
    if let Some((path, expands_home)) = path {
        record_directory_policy(node, api, effect, path, *expands_home, "'.'", hits);
    }
}

fn record_directory_policy(
    node: &Syntax<'_>,
    api: &str,
    effect: &str,
    path: &str,
    expands_home: bool,
    source_word: &str,
    hits: &mut Vec<CredentialFileWrite>,
) {
    if path.is_empty() {
        return;
    }
    // This arm explicitly judges the directory interpretation. Its trailing
    // separator also keeps a bare .git directory inside the shell pre-gate.
    let directory = quote_policy_path(&format!("{path}/"), expands_home);
    let adapter = format!("cp -t {directory} -- {source_word}");
    if let Some(hit) = shell::classify_credential_file_write(&adapter, ShellDialect::Posix) {
        record_rule(node, api, effect, path, hit.rule, hits);
    }
}

#[cfg(test)]
mod tests {
    use super::super::{ScriptLanguage, ShellDialect, classify, scan_extracted};

    fn rules(source: &str, language: ScriptLanguage) -> Vec<&'static str> {
        let hits = scan_extracted(source, language).expect("complete source analysis");
        for hit in &hits {
            assert!(source.get(hit.span.clone()).is_some(), "{source}: {hit:?}");
        }
        hits.into_iter().map(|hit| hit.rule).collect()
    }

    #[test]
    fn link_apis_and_aliases_reach_the_shared_policy() {
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "import os; os.link('staged', '.bashrc')",
            ),
            (
                ScriptLanguage::Python,
                "import os; os.symlink('staged', '.bashrc')",
            ),
            (
                ScriptLanguage::Python,
                "from os import link as publish; publish(dst='.bashrc', src=source)",
            ),
            (
                ScriptLanguage::Python,
                "from os import symlink as publish; publish(src=source, dst='.bashrc')",
            ),
            (
                ScriptLanguage::Python,
                "import os as disk; disk.symlink('missing', disk.path.join(disk.environ['HOME'], '.aws', 'credentials'))",
            ),
            (
                ScriptLanguage::JavaScript,
                "require('fs').linkSync('staged', '.bashrc')",
            ),
            (
                ScriptLanguage::JavaScript,
                "require('fs').link('staged', '.bashrc', () => {})",
            ),
            (
                ScriptLanguage::JavaScript,
                "require('node:fs').symlinkSync('missing', '.bashrc')",
            ),
            (
                ScriptLanguage::JavaScript,
                "require('node:fs').symlink(source, '.bashrc', () => {})",
            ),
            (
                ScriptLanguage::JavaScript,
                "require('fs').promises.link('staged', '.bashrc')",
            ),
            (
                ScriptLanguage::JavaScript,
                "require('fs/promises').symlink('staged', '.bashrc')",
            ),
            (
                ScriptLanguage::JavaScript,
                "const {symlinkSync: publish} = require('node:fs'); publish('staged', '.bashrc')",
            ),
            (
                ScriptLanguage::JavaScript,
                "import {link as publish} from 'node:fs/promises'; publish('staged', '.bashrc')",
            ),
            (
                ScriptLanguage::JavaScript,
                "const fs = require('fs'); fs['symlinkSync']('staged', '.bashrc')",
            ),
            (
                ScriptLanguage::JavaScript,
                "require('fs').symlinkSync('staged', require('path').join(require('os').homedir(), '.bashrc'))",
            ),
            (
                ScriptLanguage::TypeScript,
                "import * as fs from 'node:fs'; const path: string = '.bashrc'; fs.linkSync('staged', path)",
            ),
            (ScriptLanguage::Ruby, "File.link('staged', '.bashrc')"),
            (ScriptLanguage::Ruby, "File.symlink(source, '.bashrc')"),
            (
                ScriptLanguage::Ruby,
                "F = File; F.symlink('missing', File.join(Dir.home, '.bashrc'))",
            ),
        ] {
            assert_eq!(
                rules(source, language),
                ["credential-file-write"],
                "{source}"
            );
        }
    }

    #[test]
    fn pathlib_links_write_the_receiver_not_the_target() {
        for method in ["hardlink_to", "symlink_to"] {
            for source in [
                format!("from pathlib import Path; Path('.bashrc').{method}('staged')"),
                format!("from pathlib import Path; Path('.bashrc').{method}(target=unknown)"),
                format!(
                    "from pathlib import Path as P; publish = P.home().joinpath('.bashrc').{method}; publish('staged')"
                ),
            ] {
                assert_eq!(
                    rules(&source, ScriptLanguage::Python),
                    ["credential-file-write"],
                    "{source}"
                );
            }
            for source in [
                format!("from pathlib import Path; Path('/tmp/alias').{method}('.bashrc')"),
                format!("from pathlib import Path; Path('~/.bashrc').{method}('staged')"),
            ] {
                assert!(
                    rules(&source, ScriptLanguage::Python).is_empty(),
                    "{source}"
                );
            }
        }
    }

    #[test]
    fn symbolic_links_protect_credential_directory_roots() {
        // A link to a tree can redirect future trust-file reads even when
        // the directory root itself is not a single protected file.
        for (path, rule) in [
            ("/home/u/.aws", "credential-file-write"),
            ("/home/u/.config", "credential-file-write"),
            ("/home/u/.ssh", "credential-file-write"),
            (".git", "git-internals-write"),
        ] {
            for (language, source) in [
                (
                    ScriptLanguage::Python,
                    format!("import os; os.symlink('staged', '{path}', target_is_directory=True)"),
                ),
                (
                    ScriptLanguage::Python,
                    format!(
                        "from pathlib import Path; Path('{path}').symlink_to(target=source, target_is_directory=True)"
                    ),
                ),
                (
                    ScriptLanguage::JavaScript,
                    format!("require('fs').symlinkSync('staged', '{path}', 'dir')"),
                ),
                (
                    ScriptLanguage::Ruby,
                    format!("File.symlink('staged', '{path}')"),
                ),
            ] {
                assert_eq!(rules(&source, language), [rule], "{source}");
            }
        }
    }

    #[test]
    fn links_classify_only_the_new_name_and_never_grant_append() {
        for (source, destination, rule) in [
            (".bashrc", ".git/config", "git-internals-write"),
            (".git/config", ".bashrc", "credential-file-write"),
            ("staged", ".ssh/known_hosts", "credential-file-write"),
        ] {
            for (language, program) in [
                (
                    ScriptLanguage::Python,
                    format!("import os; os.link('{source}', '{destination}')"),
                ),
                (
                    ScriptLanguage::Python,
                    format!("import os; os.symlink('{source}', '{destination}')"),
                ),
                (
                    ScriptLanguage::Python,
                    format!(
                        "from pathlib import Path; Path('{destination}').hardlink_to('{source}')"
                    ),
                ),
                (
                    ScriptLanguage::Python,
                    format!(
                        "from pathlib import Path; Path('{destination}').symlink_to('{source}')"
                    ),
                ),
                (
                    ScriptLanguage::JavaScript,
                    format!("require('fs').linkSync('{source}', '{destination}')"),
                ),
                (
                    ScriptLanguage::JavaScript,
                    format!("require('fs/promises').symlink('{source}', '{destination}')"),
                ),
                (
                    ScriptLanguage::Ruby,
                    format!("File.link('{source}', '{destination}')"),
                ),
                (
                    ScriptLanguage::Ruby,
                    format!("File.symlink('{source}', '{destination}')"),
                ),
            ] {
                assert_eq!(rules(&program, language), [rule], "{program}");
            }
        }
    }

    #[test]
    fn link_reads_literals_and_unrelated_receivers_stay_clear() {
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "import os; os.link('.bashrc', '/tmp/alias')",
            ),
            (
                ScriptLanguage::Python,
                "import os; os.symlink('/home/u/.aws', '/tmp/alias')",
            ),
            (
                ScriptLanguage::Python,
                "import os; os.symlink('.bashrc', destination)",
            ),
            (
                ScriptLanguage::Python,
                "import os; os.symlink('staged', '~/.bashrc')",
            ),
            (ScriptLanguage::Python, "import os; os.readlink('.bashrc')"),
            // Importing an alias must not invent a binding under the old name.
            (
                ScriptLanguage::Python,
                "import os as disk; disk.symlink('missing', os.path.join(os.environ['HOME'], '.aws', 'credentials'))",
            ),
            (
                ScriptLanguage::Python,
                "from os import symlink as publish; publish = store; publish('staged', '.bashrc')",
            ),
            (
                ScriptLanguage::Python,
                "from unrelated import link; link('staged', '.bashrc')",
            ),
            (
                ScriptLanguage::Python,
                "print(\"os.symlink('staged', '.bashrc')\")",
            ),
            (
                ScriptLanguage::JavaScript,
                "require('fs').symlinkSync('.bashrc', '/tmp/alias')",
            ),
            (
                ScriptLanguage::JavaScript,
                "require('fs').linkSync('.bashrc', destination)",
            ),
            (
                ScriptLanguage::JavaScript,
                "require('fs').readlinkSync('.bashrc')",
            ),
            (
                ScriptLanguage::JavaScript,
                "const fs = require('unrelated'); fs.linkSync('staged', '.bashrc')",
            ),
            (
                ScriptLanguage::JavaScript,
                "const fs = require('fs'); fs = store; fs.symlinkSync('staged', '.bashrc')",
            ),
            (
                ScriptLanguage::JavaScript,
                "console.log(\"require('fs').symlinkSync('staged', '.bashrc')\")",
            ),
            (ScriptLanguage::Ruby, "File.link('.bashrc', '/tmp/alias')"),
            (
                ScriptLanguage::Ruby,
                "File.symlink('/home/u/.aws', '/tmp/alias')",
            ),
            (ScriptLanguage::Ruby, "File.readlink('.bashrc')"),
            (ScriptLanguage::Ruby, "Store.symlink('staged', '.bashrc')"),
            (
                ScriptLanguage::Ruby,
                "File = Store; File.link('staged', '.bashrc')",
            ),
        ] {
            assert!(rules(source, language).is_empty(), "{source}");
        }
    }

    #[test]
    fn direct_destinations_and_aliases_reach_shared_policy() {
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "import os; os.replace('staged', '.bashrc')",
            ),
            (
                ScriptLanguage::Python,
                "from os import rename as install; install(dst='.bashrc', src='staged')",
            ),
            (
                ScriptLanguage::Python,
                "import shutil as disk; disk.copyfile('staged', '.bashrc')",
            ),
            (
                ScriptLanguage::Python,
                "from shutil import copyfile as save; save(src='staged', dst='.bashrc')",
            ),
            (
                ScriptLanguage::Python,
                "from pathlib import Path; Path('staged').replace(target='.bashrc')",
            ),
            (
                ScriptLanguage::Python,
                "from pathlib import Path as P; install = P('staged').rename; install('.bashrc')",
            ),
            (
                ScriptLanguage::Python,
                "import os; os.replace('staged', os.path.expanduser('~/.bashrc'))",
            ),
            (
                ScriptLanguage::JavaScript,
                "require('fs').renameSync('staged', '.bashrc')",
            ),
            (
                ScriptLanguage::JavaScript,
                "const {copyFileSync: save} = require('node:fs'); save('staged', '.bashrc')",
            ),
            (
                ScriptLanguage::JavaScript,
                "import {rename as install} from 'node:fs/promises'; install('staged', '.bashrc')",
            ),
            (
                ScriptLanguage::JavaScript,
                "require('fs').promises.copyFile('staged', '.bashrc')",
            ),
            (
                ScriptLanguage::TypeScript,
                "import * as fs from 'node:fs'; const p: string = '.bashrc'; fs.copyFileSync('staged', p)",
            ),
            (ScriptLanguage::Ruby, "File.rename('staged', '.bashrc')"),
            (ScriptLanguage::Ruby, "IO.copy_stream('staged', '.bashrc')"),
            (
                ScriptLanguage::Ruby,
                "File.copy_stream('staged', '.bashrc')",
            ),
            (
                ScriptLanguage::Ruby,
                "F = File; F.rename('staged', File.expand_path('~/.bashrc'))",
            ),
        ] {
            assert_eq!(
                rules(source, language),
                ["credential-file-write"],
                "{source}"
            );
        }
    }

    #[test]
    fn unknown_operand_cannot_hide_the_known_mutation() {
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "import shutil; shutil.copyfile(source, '.bashrc')",
            ),
            (
                ScriptLanguage::Python,
                "import os; os.replace('.bashrc', destination)",
            ),
            (
                ScriptLanguage::JavaScript,
                "require('fs').copyFileSync(source, '.bashrc')",
            ),
            (
                ScriptLanguage::JavaScript,
                "require('fs').renameSync('.bashrc', destination)",
            ),
            (ScriptLanguage::Ruby, "File.rename(source, '.bashrc')"),
            (ScriptLanguage::Ruby, "IO.copy_stream(source, '.bashrc')"),
            (ScriptLanguage::Ruby, "File.rename('.bashrc', destination)"),
        ] {
            assert_eq!(
                rules(source, language),
                ["credential-file-write"],
                "{source}"
            );
        }
    }

    #[test]
    fn rename_preserves_both_rule_families_in_a_single_call() {
        for (source, destination) in [(".bashrc", ".git/config"), (".git/config", ".bashrc")] {
            for (language, program) in [
                (
                    ScriptLanguage::Python,
                    format!("import os; os.replace('{source}', '{destination}')"),
                ),
                (
                    ScriptLanguage::Python,
                    format!("from pathlib import Path; Path('{source}').rename('{destination}')"),
                ),
                (
                    ScriptLanguage::JavaScript,
                    format!("require('fs').renameSync('{source}', '{destination}')"),
                ),
                (
                    ScriptLanguage::Ruby,
                    format!("File.rename('{source}', '{destination}')"),
                ),
            ] {
                let mut actual = rules(&program, language);
                actual.sort_unstable();
                assert_eq!(
                    actual,
                    ["credential-file-write", "git-internals-write"],
                    "{program}"
                );
            }
        }
    }

    #[test]
    fn copies_read_the_source_but_never_inherit_append_exemptions() {
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "import shutil; shutil.copyfile('.bashrc', 'backup.txt')",
            ),
            (
                ScriptLanguage::Python,
                "import shutil; shutil.copyfile('.git/config', 'backup.txt')",
            ),
            (
                ScriptLanguage::JavaScript,
                "require('fs').copyFileSync('.ssh/id_rsa', 'backup.txt')",
            ),
            (
                ScriptLanguage::Ruby,
                "IO.copy_stream('.ssh/id_rsa', 'backup.txt')",
            ),
        ] {
            assert!(rules(source, language).is_empty(), "{source}");
        }
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "import shutil; shutil.copyfile('staged', '.ssh/known_hosts')",
            ),
            (
                ScriptLanguage::JavaScript,
                "const fs = require('fs'); fs.copyFileSync('staged', '.ssh/known_hosts', fs.constants.COPYFILE_EXCL)",
            ),
            (
                ScriptLanguage::Ruby,
                "File.rename('staged', '.ssh/known_hosts')",
            ),
            (
                ScriptLanguage::Ruby,
                "IO.copy_stream('staged', '.ssh/known_hosts', 0)",
            ),
        ] {
            assert_eq!(
                rules(source, language),
                ["credential-file-write"],
                "{source}"
            );
        }
    }

    #[test]
    fn inert_text_shadowing_and_unrelated_receivers_stay_clear() {
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "print(\"os.replace('staged', '.bashrc')\")",
            ),
            (
                ScriptLanguage::Python,
                "# os.replace('staged', '.bashrc')\nprint('ok')",
            ),
            (
                ScriptLanguage::Python,
                "import shutil; shutil = store; shutil.copyfile('staged', '.bashrc')",
            ),
            (
                ScriptLanguage::Python,
                "import os; deferral = os.replace; deferral = print; deferral('staged', '.bashrc')",
            ),
            (
                ScriptLanguage::Python,
                "def example(os):\n    os.replace('staged', '.bashrc')",
            ),
            (
                ScriptLanguage::JavaScript,
                "const fs = require('unrelated'); fs.renameSync('staged', '.bashrc')",
            ),
            (
                ScriptLanguage::JavaScript,
                "function example(require) { require('fs').renameSync('staged', '.bashrc') }",
            ),
            (
                ScriptLanguage::JavaScript,
                "console.log(\"require('fs').copyFileSync('staged', '.bashrc')\")",
            ),
            (ScriptLanguage::Ruby, "Store.rename('staged', '.bashrc')"),
            (
                ScriptLanguage::Ruby,
                "IO = Store; IO.copy_stream('staged', '.bashrc')",
            ),
            (
                ScriptLanguage::Ruby,
                "puts \"File.rename('staged', '.bashrc')\"",
            ),
        ] {
            assert!(rules(source, language).is_empty(), "{source}");
        }
    }

    #[test]
    fn transfer_names_survive_both_candidate_gates() {
        for (interpreter, flag, source) in [
            ("python3", "-c", "import os; os.rename('staged', '.bashrc')"),
            (
                "python3",
                "-c",
                "import os; os.replace('staged', '.bashrc')",
            ),
            (
                "python3",
                "-c",
                "import shutil; shutil.copyfile('staged', '.bashrc')",
            ),
            (
                "node",
                "-e",
                "require('fs').copyFileSync('staged', '.bashrc')",
            ),
            (
                "node",
                "-e",
                "require('fs').copyFile('staged', '.bashrc', () => {})",
            ),
            (
                "node",
                "-e",
                "require('fs').renameSync('staged', '.bashrc')",
            ),
            (
                "node",
                "-e",
                "require('fs').rename('staged', '.bashrc', () => {})",
            ),
            ("ruby", "-e", "File.rename('staged', '.bashrc')"),
            ("ruby", "-e", "IO.copy_stream('staged', '.bashrc')"),
        ] {
            let command = format!("{interpreter} {flag} \"{source}\"");
            assert!(
                classify(&command, ShellDialect::Posix).is_some(),
                "{command}"
            );
        }
    }

    #[test]
    fn shutil_directory_placement_preserves_basename_and_aliases() {
        for source in [
            "import shutil; shutil.copy('staged', '/etc/shadow')",
            "import shutil; shutil.copy2('fixtures/.bashrc', '/home/u')",
            "import shutil as disk; disk.copy('fixtures/credentials', '/home/u/.aws')",
            "from shutil import copy2 as publish; publish(dst='/etc', src='fixtures/passwd')",
            "import shutil; publish = shutil.copy2; publish('staged', '.bashrc')",
            "import shutil, os; shutil.copy2('fixtures/.bashrc', os.path.expanduser('~'))",
            "import shutil; shutil.copy(source, '/home/u/.ssh')",
            "import shutil; shutil.copy2(source, '/home/u')",
            "import shutil; shutil.copy2('staged', '/home/u/.ssh/known_hosts')",
        ] {
            assert_eq!(
                rules(source, ScriptLanguage::Python),
                ["credential-file-write"],
                "{source}"
            );
        }
        for source in [
            "import shutil; shutil.copy2('staged', '.git')",
            "from shutil import copy as publish; publish('staged', 'repo/.git/hooks')",
        ] {
            assert_eq!(
                rules(source, ScriptLanguage::Python),
                ["git-internals-write"],
                "{source}"
            );
        }
    }

    #[test]
    fn shutil_copytree_targets_the_destination_tree_not_the_source_basename() {
        for source in [
            "import shutil; shutil.copytree('backup', '/home/u', dirs_exist_ok=True)",
            "from shutil import copytree as restore; restore(src='backup', dst='/etc')",
            "import shutil; shutil.copytree(source, '/home/u/.config')",
            "import shutil; shutil.copytree('backup', '/home/u/.ssh', dirs_exist_ok=False)",
        ] {
            assert_eq!(
                rules(source, ScriptLanguage::Python),
                ["credential-file-write"],
                "{source}"
            );
        }
        let source = "import shutil; shutil.copytree('backup', '.git', dirs_exist_ok=True)";
        assert_eq!(
            rules(source, ScriptLanguage::Python),
            ["git-internals-write"]
        );
    }

    #[test]
    fn shutil_moves_check_source_trees_and_keep_independent_rule_families() {
        for source in [
            "import shutil; shutil.move('/home/u/.aws', 'backup')",
            "from shutil import move as archive; archive(src='/home/u/.config', dst=destination)",
            "import shutil; shutil.move('.bashrc', destination)",
            "import shutil; shutil.move(source, '.bashrc')",
        ] {
            assert_eq!(
                rules(source, ScriptLanguage::Python),
                ["credential-file-write"],
                "{source}"
            );
        }
        for source in [
            "import shutil; shutil.move('.bashrc', '.git')",
            "import shutil; shutil.move('.git', '.bashrc')",
        ] {
            let mut actual = rules(source, ScriptLanguage::Python);
            actual.sort_unstable();
            assert_eq!(
                actual,
                ["credential-file-write", "git-internals-write"],
                "{source}"
            );
        }
        let source = "from shutil import move as archive; archive('.bashrc', 'backup')";
        let command = format!("python3 -c \"{source}\"");
        assert!(
            classify(&command, ShellDialect::Posix).is_some(),
            "move pre-gate: {command}"
        );
    }

    #[test]
    fn shutil_reads_safe_placements_and_literal_metacharacters_stay_clear() {
        for source in [
            "import shutil; shutil.copy2('.bashrc', '/tmp/backup.txt')",
            "import shutil; shutil.copytree('/home/u/.ssh', '/tmp/backup')",
            "import shutil; shutil.copytree('/home/u/.config', '/tmp/backup')",
            "import shutil; shutil.copy('notes.txt', '/home/u')",
            "import shutil; shutil.copy2('fixtures/readme.txt', '/home/u/.aws')",
            "import shutil; shutil.move('notes.txt', '/home/u')",
            "import shutil; shutil.copy2('fixtures/pass*', '/etc')",
            "import shutil; shutil.copy2('fixtures/pass{wd,x}', '/etc')",
            "import shutil; shutil.copy2('fixtures/.bashrc', '~')",
            "import shutil; shutil.copytree('backup', '~')",
            "print(\"shutil.copy2('staged', '.bashrc')\")",
            "import shutil; shutil = store; shutil.move('staged', '.bashrc')",
            "from shutil import copy2 as publish; publish = print; publish('staged', '.bashrc')",
            "from unrelated import copy2; copy2('staged', '.bashrc')",
            "def example(shutil):\n    shutil.copytree('backup', '/etc')",
        ] {
            assert!(rules(source, ScriptLanguage::Python).is_empty(), "{source}");
        }
    }
}

//! Exact-destination file transfers share the protected-write policy (#461).
//!
//! A copy reads its source and writes its destination. A rename also removes
//! the source name. Inspect those effects independently: a dynamic source
//! must not hide a known protected destination, and one allowlisted rule
//! must not hide the other rule on the opposite end of a single rename.
//!
//! Only APIs whose destination is an exact path are handled here. Directory
//! placement APIs (`shutil.copy`, `shutil.move`, `FileUtils.cp`) need their own
//! basename/container semantics; they must not be mislabeled as copyfile.

use super::{
    Access, Bindings, CredentialFileWrite, Language, Syntax, Value, arguments, path_value,
    protected, python_argument, value,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Operation {
    CopyFile,
    Rename,
}

pub(super) fn js_operation(name: &str) -> Option<Operation> {
    match name {
        "copyFile" | "copyFileSync" => Some(Operation::CopyFile),
        "rename" | "renameSync" => Some(Operation::Rename),
        _ => None,
    }
}

type ResolvedPath = (String, bool);

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
            (Value::File, "rename") => (Operation::Rename, "File.rename"),
            (Value::Io | Value::File, "copy_stream") => (Operation::CopyFile, "IO.copy_stream"),
            _ => return None,
        };
        return Some(Transfer {
            operation,
            source: path(args.first()?),
            destination: path(args.get(1)?),
            api: api.into(),
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
                source: Some((source, false)),
                destination: path(&destination),
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
    // Always inspect the destination, even when the source cannot be resolved.
    // Exclusive/no-clobber flags still permit creation of a protected file and
    // are not an append-only known_hosts exemption.
    record(
        node,
        &transfer.api,
        "creates or replaces",
        transfer.destination,
        hits,
    );
    if transfer.operation == Operation::Rename {
        record(
            node,
            &transfer.api,
            "removes the source name of",
            transfer.source,
            hits,
        );
    }
}

fn record(
    node: &Syntax<'_>,
    api: &str,
    effect: &str,
    path: Option<ResolvedPath>,
    hits: &mut Vec<CredentialFileWrite>,
) {
    let Some((path, expands_home)) = path else {
        return;
    };
    let Some(rule) = protected(&path, Access::Write, expands_home) else {
        return;
    };
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
}

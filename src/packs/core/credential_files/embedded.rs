//! Structural recognition of Python, Ruby, and Node file-write APIs (#461).
//!
//! Shell callers first establish that the source belongs to an interpreter.
//! The evaluator also calls `scan_extracted` directly on executable source:
//! its shell-segment view has already masked interpreter bodies. No script is
//! executed and no destination is read or opened.

use super::{CredentialFileWrite, shell};
use crate::heredoc::{
    ExtractionLimits, ExtractionResult, HeredocType, ScriptLanguage, extract_content,
};
use crate::normalize::{ShellDialect, strip_wrapper_prefixes};
use ast_grep_core::{AstGrep, Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use std::collections::HashMap;
use std::ops::Range;

mod transfers;

type Syntax<'a> = Node<'a, StrDoc<SupportLang>>;

// Bound direct library calls as well as the hook. An exhausted source walk
// must report incomplete analysis, not a successful empty match set.
const MAX_BYTES: usize = 256 * 1024;
const MAX_DEPTH: usize = 128;
const MAX_NODES: usize = 40_000;
// A small source can repeatedly double a bound string. Bound folded values
// separately from input bytes so path construction cannot amplify it without
// limit. This is an analysis bound, not a query of the host filesystem.
const MAX_STATIC_PATH_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Language {
    Python,
    Ruby,
    Node,
}

fn interpreter(executable: &str) -> Option<Language> {
    let name = executable.rsplit('/').next().unwrap_or(executable);
    let name = name.strip_suffix(".exe").unwrap_or(name);
    for (base, language) in [
        ("python", Language::Python),
        ("pypy", Language::Python),
        ("ruby", Language::Ruby),
        ("nodejs", Language::Node),
        ("node", Language::Node),
    ] {
        if name == base
            || name.strip_prefix(base).is_some_and(|suffix| {
                suffix.as_bytes().first().is_some_and(u8::is_ascii_digit)
                    && suffix.bytes().all(|b| b.is_ascii_digit() || b == b'.')
            })
        {
            return Some(language);
        }
    }
    None
}

pub(super) fn is_interpreter(executable: &str) -> bool {
    interpreter(executable).is_some()
}

/// A lexical superset of the API names that can establish a write binding.
/// Do not gate on a raw protected-path substring: constant concatenation and
/// language escapes can assemble that substring only after decoding.
pub(crate) fn source_scan_required(code: &str, language: ScriptLanguage) -> bool {
    matches!(
        language,
        ScriptLanguage::Python
            | ScriptLanguage::Ruby
            | ScriptLanguage::JavaScript
            | ScriptLanguage::TypeScript
    ) && source_has_sink_name(code)
}

/// Shared by the shell and extracted-source gates. In particular, a rename
/// contains neither `open` nor `write`, but can replace either protected rule
/// family's files. Keep this a superset, not a raw destination-path check.
fn source_has_sink_name(code: &str) -> bool {
    [
        "open", "write", "Write", "append", "truncate", "File", "Path", "copy", "rename",
        "replace", "move",
    ]
    .iter()
    .any(|word| code.contains(word))
}

/// Inspect already-extracted executable source, never shell tokens. Return
/// the first hit for EACH rule so allowing credentials cannot hide a later
/// `.git` write (or conversely). Spans are bytes in `code`.
pub(crate) fn scan_extracted(
    code: &str,
    language: ScriptLanguage,
) -> Result<Vec<CredentialFileWrite>, &'static str> {
    if !source_scan_required(code, language) {
        return Ok(Vec::new());
    }
    let (language, grammar) = match language {
        ScriptLanguage::Python => (Language::Python, SupportLang::Python),
        ScriptLanguage::Ruby => (Language::Ruby, SupportLang::Ruby),
        ScriptLanguage::JavaScript => (Language::Node, SupportLang::JavaScript),
        ScriptLanguage::TypeScript => (Language::Node, SupportLang::TypeScript),
        _ => return Ok(Vec::new()),
    };
    scan_source(code, language, grammar)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Access {
    Read,
    Append,
    Write,
}

/// Read/update distinction matters: `r+` writes, while plain `r` does not.
/// Append/update still uses O_APPEND. Invalid or dynamic modes are not proof
/// of append-only access; callers that are explicit writers treat them as Write.
fn mode_access(mode: &str) -> Option<Access> {
    let mode = mode.split(':').next()?;
    let first = mode.as_bytes().first()?;
    if !mode.bytes().all(|b| b"rwaxbt+s".contains(&b)) {
        return None;
    }
    match first {
        b'a' if !mode.contains(['w', 'r']) => Some(Access::Append),
        b'w' | b'x' => Some(Access::Write),
        b'r' => Some(if mode.contains('+') {
            Access::Write
        } else {
            Access::Read
        }),
        _ => None,
    }
}

#[cfg(test)]
pub(super) fn classify(segment: &str, dialect: ShellDialect) -> Option<CredentialFileWrite> {
    scan_command(segment, dialect, |_, _| false)
        .into_iter()
        .next()
}

/// Keep one finding for every affected rule until the evaluator applies its
/// allowlists. A rename can affect two rules at the very same source span.
/// Apply explicit source exemptions per decoded program, never to the entire
/// shell command: another interpreter or shell writer may still be protected.
pub(super) fn scan_command(
    segment: &str,
    dialect: ShellDialect,
    mut source_is_exempt: impl FnMut(&str, ScriptLanguage) -> bool,
) -> Vec<CredentialFileWrite> {
    let mut hits = Vec::new();
    if !matches!(dialect, ShellDialect::Posix | ShellDialect::Unknown)
        || segment.len() > MAX_BYTES
        || !source_has_sink_name(segment)
    {
        return hits;
    }
    let mut inspect_source = |code: &str, language: Language, span: Range<usize>| {
        let script_language = match language {
            Language::Python => ScriptLanguage::Python,
            Language::Ruby => ScriptLanguage::Ruby,
            Language::Node => ScriptLanguage::JavaScript,
        };
        if !source_is_exempt(code, script_language) {
            inspect(code, language, span, &mut hits);
        }
    };
    let ast = AstGrep::new(segment, SupportLang::Bash);
    let root = ast.root();
    for command in root.dfs().filter(|node| node.kind() == "command") {
        let Some(words) = command_words(&command) else {
            continue;
        };
        let Some(language) = words.first().and_then(|name| interpreter(name)) else {
            continue;
        };
        if let Some(code) = inline_code(&words, language) {
            inspect_source(&code, language, command.range());
        }
        if reads_stdin(&words, language) {
            if let Some((code, span)) = here_string_source(&command) {
                inspect_source(&code, language, span);
            }
        }
    }

    // Extraction alone may infer a language from data. Accept heredocs only
    // when their actual shell receiver is a supported stdin interpreter, and
    // verify that receiver against executable command nodes in the shell AST.
    if segment.contains("<<") {
        // Structural budget, not the 50 ms hot-path default (#443). This is a
        // classification, so the answer must not depend on host load. An
        // incomplete extraction must not discard findings already established
        // by another inline script or here-string in this command.
        let items = match extract_content(segment, &ExtractionLimits::structural_scan()) {
            ExtractionResult::Extracted(items)
            | ExtractionResult::Partial {
                extracted: items, ..
            } => items,
            _ => return hits,
        };
        for item in items {
            // Here-strings were inspected on their owning command above. A
            // regex extraction cannot prove which descriptor consumes them.
            if item.heredoc_type.is_none() || item.heredoc_type == Some(HeredocType::HereString) {
                continue;
            }
            let Some(target) = item.target_command.as_deref() else {
                continue;
            };
            let normalized = strip_wrapper_prefixes(target);
            let Ok(words) = shell_words::split(normalized.normalized.as_ref()) else {
                continue;
            };
            let Some(language) = words.first().and_then(|name| interpreter(name)) else {
                continue;
            };
            if !reads_stdin(&words, language) {
                continue;
            }
            let receiver = root.dfs().any(|node| {
                node.kind() == "command"
                    && node.range().start <= item.byte_range.end
                    && command_words(&node).is_some_and(|actual| actual == words)
            });
            if receiver {
                let span = item.content_range.unwrap_or(item.byte_range);
                inspect_source(&item.content, language, span);
            }
        }
    }
    hits
}

/// Redirections are syntax, not argv. In the Bash grammar a here-string is
/// a child of `command`, so splitting `command.text()` includes `<<<` and its
/// source as spurious interpreter arguments. Preserve shell quoting while
/// selecting only the command-name and argument fields (#461).
fn command_words(command: &Syntax<'_>) -> Option<Vec<String>> {
    let mut text = command.field("name")?.text().into_owned();
    for argument in command.field_children("argument") {
        text.push(' ');
        text.push_str(argument.text().as_ref());
    }
    let normalized = strip_wrapper_prefixes(&text);
    shell_words::split(normalized.normalized.as_ref()).ok()
}

/// Only the last redirection of stdin supplies interpreter source. Trailing
/// file redirects may live on the enclosing redirected_statement; do not
/// accidentally inspect a here-string that a later `< /dev/null` replaces.
fn here_string_source(command: &Syntax<'_>) -> Option<(String, Range<usize>)> {
    // Bound to a local so the chained iterator can borrow it; the redirects on
    // the enclosing `redirected_statement` are appended after the command's own
    // so `max_by_key` breaks ties the same way the collected form did.
    let enclosing = command.parent().filter(|parent| {
        parent.kind() == "redirected_statement"
            && parent
                .field("body")
                .is_some_and(|body| body.range() == command.range())
    });
    let redirect = command
        .field_children("redirect")
        .chain(
            enclosing
                .as_ref()
                .map(|parent| parent.field_children("redirect"))
                .into_iter()
                .flatten(),
        )
        .filter(|redirect| {
            if let Some(descriptor) = redirect.field("descriptor") {
                return descriptor.text().parse::<u32>() == Ok(0);
            }
            match redirect.kind().as_ref() {
                "herestring_redirect" | "heredoc_redirect" => true,
                "file_redirect" => redirect
                    .children()
                    .any(|child| matches!(child.text().as_ref(), "<" | "<&" | "<&-" | "<>")),
                _ => false,
            }
        })
        .max_by_key(|redirect| redirect.range().start)?;
    if redirect.kind() != "herestring_redirect" {
        return None;
    }
    let source = redirect.children().find(|child| {
        child.is_named() && !matches!(child.kind().as_ref(), "file_descriptor" | "comment")
    })?;
    // Decode a static shell word, not an expanded value. Dynamic substitutions
    // retain the evaluator's existing recursive/fallback handling; never run
    // them or invent a literal destination. ANSI-C strings need their own
    // decoder and must not be misdecoded by shell_words as ordinary quotes.
    if source.dfs().any(|node| {
        matches!(
            node.kind().as_ref(),
            "simple_expansion"
                | "expansion"
                | "command_substitution"
                | "process_substitution"
                | "arithmetic_expansion"
                | "ansi_c_string"
                | "translated_string"
                | "ERROR"
        )
    }) {
        return None;
    }
    let words = shell_words::split(source.text().as_ref()).ok()?;
    let [code] = words.as_slice() else {
        return None;
    };
    Some((code.clone(), source.range()))
}

/// Follow interpreter option boundaries, not a substring `-c` or `-e` in a
/// filename or argv data. Ruby's repeated -e arguments are one program.
fn inline_code(words: &[String], language: Language) -> Option<String> {
    let mut index = 1;
    let mut scripts = Vec::new();
    while let Some(word) = words.get(index) {
        if word == "--" || word == "-" || !word.starts_with('-') {
            break;
        }
        let long = if language == Language::Node {
            word.strip_prefix("--eval=")
                .or_else(|| word.strip_prefix("--print="))
        } else {
            None
        };
        if let Some(code) = long {
            return Some(code.to_string());
        }
        let flag = match language {
            Language::Python => 'c',
            Language::Ruby | Language::Node => 'e',
        };
        let is_long = language == Language::Node && matches!(word.as_str(), "--eval" | "--print");
        let short = word.strip_prefix('-').filter(|s| !s.starts_with('-'));
        let position = short.and_then(|s| {
            let position = s.find(flag).or_else(|| {
                if language == Language::Node {
                    s.find('p')
                } else {
                    None
                }
            })?;
            let allowed = match language {
                Language::Python => "bBdEiIOPqRsSuvx",
                Language::Ruby => "adlnpsw",
                Language::Node => "ip",
            };
            s[..position]
                .chars()
                .all(|c| allowed.contains(c))
                .then_some(position)
        });
        if is_long || position.is_some() {
            let attached = position
                .and_then(|p| short.map(|s| &s[p + 1..]))
                .unwrap_or("");
            let code = if attached.is_empty() {
                index += 1;
                words.get(index)?.as_str()
            } else {
                attached
            };
            scripts.push(code.to_string());
            if language != Language::Ruby {
                break;
            }
        } else if option_takes_value(word, language) {
            index += 1;
        }
        index += 1;
    }
    (!scripts.is_empty()).then(|| scripts.join("\n"))
}

fn option_takes_value(word: &str, language: Language) -> bool {
    match language {
        Language::Python => matches!(word, "-W" | "-X"),
        Language::Ruby => matches!(word, "-r" | "-I" | "-C" | "-E" | "-F" | "--encoding"),
        Language::Node => matches!(
            word,
            "-r" | "--require" | "--import" | "--loader" | "--experimental-loader" | "--input-type"
        ),
    }
}

fn reads_stdin(words: &[String], language: Language) -> bool {
    if inline_code(words, language).is_some() {
        return false;
    }
    let mut index = 1;
    while let Some(word) = words.get(index) {
        if word == "-" {
            return true;
        }
        if word == "--" {
            return words.get(index + 1).is_none_or(|word| word == "-");
        }
        if !word.starts_with('-') || (language == Language::Python && word == "-m") {
            return false;
        }
        if option_takes_value(word, language) {
            index += 1;
        }
        index += 1;
    }
    true
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Value {
    Text(String),
    StringifyPath,
    Open,
    Io,
    Builtins,
    Os,
    OsPath,
    Environment,
    EnvironmentGet,
    GetEnv,
    PythonJoin,
    OsTruncate,
    Shutil,
    Transfer(transfers::Operation),
    ExpandUser,
    /// Only a proven runtime expander grants a leading tilde home semantics.
    HomePath(String),
    Pathlib,
    PathConstructor,
    PathHome,
    Path(ResolvedPath),
    PathJoin(ResolvedPath),
    PathExpandUser(ResolvedPath),
    PathWrite(ResolvedPath),
    PathOpen(ResolvedPath),
    PathTransfer(ResolvedPath),
    Require,
    Fs,
    File,
    Api(String),
}

type Bindings = HashMap<String, Value>;

/// A static path plus proof that a leading tilde represents an expanded home.
/// Keep this proof through path constructors and bound methods; a literal
/// `Path("~/.bashrc")` is not equivalent to `Path.home() / ".bashrc"`.
type ResolvedPath = (String, bool);

fn inspect(
    code: &str,
    language: Language,
    span: Range<usize>,
    hits: &mut Vec<CredentialFileWrite>,
) {
    let grammar = match language {
        Language::Python => SupportLang::Python,
        Language::Ruby => SupportLang::Ruby,
        Language::Node => SupportLang::JavaScript,
    };
    if let Ok(found) = scan_source(code, language, grammar) {
        for mut hit in found {
            if !hits.iter().any(|existing| existing.rule == hit.rule) {
                hit.span = span.clone();
                hits.push(hit);
            }
        }
    }
}

fn scan_source(
    code: &str,
    language: Language,
    grammar: SupportLang,
) -> Result<Vec<CredentialFileWrite>, &'static str> {
    if code.len() > MAX_BYTES {
        return Err("protected-write source exceeds the byte limit");
    }
    let ast = AstGrep::new(code, grammar);
    let mut bindings = Bindings::new();
    match language {
        Language::Python => {
            bindings.insert("open".into(), Value::Open);
            bindings.insert("str".into(), Value::StringifyPath);
        }
        Language::Ruby => {
            bindings.insert("File".into(), Value::File);
            bindings.insert("IO".into(), Value::Io);
        }
        Language::Node => {
            bindings.insert("require".into(), Value::Require);
        }
    }
    let mut hits = Vec::new();
    let mut remaining_nodes = MAX_NODES;
    visit(
        ast.root(),
        language,
        &mut bindings,
        0,
        &mut remaining_nodes,
        &mut hits,
    )?;
    Ok(hits)
}

/// Collect one hit per rule, not just the first write in a script. A rule
/// allowlist is not permission to stop scanning other rule families.
fn visit(
    node: Syntax<'_>,
    language: Language,
    env: &mut Bindings,
    depth: usize,
    remaining_nodes: &mut usize,
    hits: &mut Vec<CredentialFileWrite>,
) -> Result<(), &'static str> {
    if depth > MAX_DEPTH || *remaining_nodes == 0 {
        return Err("protected-write source exceeds the AST traversal limit");
    }
    *remaining_nodes -= 1;
    let kind = node.kind();
    if kind == "ERROR" {
        return Err("protected-write source contains a syntax error");
    }
    if matches!(
        kind.as_ref(),
        "function_definition"
            | "function_declaration"
            | "function_expression"
            | "arrow_function"
            | "lambda"
            | "method"
            | "method_definition"
            | "generator_function"
            | "generator_function_declaration"
    ) {
        if let Some(name) = node.field("name") {
            env.remove(name.text().as_ref());
        }
        let mut local = env.clone();
        if let Some(parameters) = node.field("parameters").or_else(|| node.field("parameter")) {
            for parameter in parameters
                .dfs()
                .filter(|child| child.kind() == "identifier")
            {
                local.remove(parameter.text().as_ref());
            }
        }
        for child in node.children() {
            visit(
                child,
                language,
                &mut local,
                depth + 1,
                remaining_nodes,
                hits,
            )?;
        }
        return Ok(());
    }
    // The right-hand side runs before assignment installs its result. Removing
    // `open` or `fs` first hides the very write in `open = open(path, 'w')` or
    // `fs = fs.writeFileSync(path, data)`. Keep the previous bindings throughout
    // the expression, then invalidate/rebind the assignment target normally.
    let bind_after_children = matches!(
        kind.as_ref(),
        "assignment" | "assignment_expression" | "variable_declarator"
    );
    if !bind_after_children {
        bind(&node, language, env);
    }
    if let Some((api, path, access, expands)) = write_call(&node, language, env) {
        if let Some(rule) = protected(&path, access, expands) {
            if !hits.iter().any(|hit| hit.rule == rule) {
                hits.push(CredentialFileWrite {
                    span: node.range(),
                    rule,
                    reason: format!(
                        "{api} writes protected credential, login-startup, or trust target {path:?}. Reads remain allowed; only append-only known_hosts updates are exempt. Show the user the proposed change or use dcg allow-once."
                    ),
                });
            }
        }
    } else {
        // Transfers may mutate two paths under distinct rule identities.
        // Do not flatten them to write_call's single-destination result.
        transfers::scan(&node, language, env, hits);
    }
    for child in node.children() {
        visit(child, language, env, depth + 1, remaining_nodes, hits)?;
    }
    if bind_after_children {
        bind(&node, language, env);
    }
    Ok(())
}

/// Encode a decoded path for the shared shell policy, never for execution.
/// Every character is literal except a leading tilde whose runtime expansion
/// was already proven. Transfers and direct writes must use the same adapter:
/// neither source basenames nor destinations may acquire shell glob semantics.
fn quote_policy_path(path: &str, expands_home: bool) -> String {
    let quote = |text: &str| format!("'{}'", text.replace('\'', "'\\''"));
    let anchor = expands_home
        .then(|| path.split_once('/').unwrap_or((path, "")))
        .filter(|(anchor, _)| {
            anchor.starts_with('~')
                && anchor[1..]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        });
    match anchor {
        Some((anchor, "")) => anchor.to_string(),
        Some((anchor, rest)) => format!("{anchor}/{}", quote(rest)),
        None => quote(path),
    }
}

/// Judge a single opened path, preserving literal versus expanded-home input.
fn protected(path: &str, access: Access, expands_home: bool) -> Option<&'static str> {
    if access == Access::Read {
        return None;
    }
    let quoted = quote_policy_path(path, expands_home);
    let append = if access == Access::Append { "-a " } else { "" };
    // Use the exact shared path table and rule identity, including .git.
    shell::classify_credential_file_write(&format!("tee {append}-- {quoted}"), ShellDialect::Posix)
        .map(|hit| hit.rule)
}

fn bind(node: &Syntax<'_>, language: Language, env: &mut Bindings) {
    let kind = node.kind();
    if language == Language::Python
        && matches!(kind.as_ref(), "import_statement" | "import_from_statement")
    {
        let module = node.field("module_name").map(|n| n.text().into_owned());
        for name in node.field_children("name") {
            let source = name
                .field("name")
                .unwrap_or_else(|| name.clone())
                .text()
                .into_owned();
            let alias = name
                .field("alias")
                .map_or_else(|| source.clone(), |n| n.text().into_owned());
            let value = match (module.as_deref(), source.as_str()) {
                (None, "io") => Some(Value::Io),
                (None, "builtins") => Some(Value::Builtins),
                (None, "pathlib") => Some(Value::Pathlib),
                (None, "os") => Some(Value::Os),
                (None, "shutil") => Some(Value::Shutil),
                (Some("io" | "builtins"), "open") => Some(Value::Open),
                (Some("builtins"), "str") => Some(Value::StringifyPath),
                (Some("pathlib"), "Path" | "PosixPath") => Some(Value::PathConstructor),
                (Some("os"), "truncate") => Some(Value::OsTruncate),
                (Some("os"), "rename" | "replace") => {
                    Some(Value::Transfer(transfers::Operation::Rename))
                }
                (Some("shutil"), name) => transfers::shutil_operation(name).map(Value::Transfer),
                (Some("os"), "path") => Some(Value::OsPath),
                (Some("os"), "environ") => Some(Value::Environment),
                (Some("os"), "getenv") => Some(Value::GetEnv),
                (Some("os.path"), "expanduser") => Some(Value::ExpandUser),
                (Some("os.path"), "join") => Some(Value::PythonJoin),
                // `import os.path as p` binds `p` to the `os.path` module.
                // Without this the aliased form fell through to `None`, left
                // `p` unbound, and `open(p.expanduser('~/.ssh/x'), 'a')` was
                // not recognised while every other spelling was.
                (None, "os.path") => Some(Value::OsPath),
                _ => None,
            };
            // `import os.path` (no alias) binds `os`, not `os.path`.
            if module.is_none() && source.starts_with("os.") && name.field("alias").is_none() {
                env.remove("os");
                env.insert("os".into(), Value::Os);
                continue;
            }
            env.remove(&alias);
            if let Some(value) = value {
                env.insert(alias, value);
            }
        }
    }
    if language == Language::Node && kind == "import_statement" {
        let module = node.field("source").and_then(|n| literal(&n, language));
        let filesystem = module.as_deref().is_some_and(is_fs_module);
        for child in node.dfs() {
            if child.kind() == "import_specifier" {
                let Some(name) = child.field("name") else {
                    continue;
                };
                let alias = child
                    .field("alias")
                    .unwrap_or_else(|| name.clone())
                    .text()
                    .into_owned();
                env.remove(&alias);
                if filesystem && is_js_api(name.text().as_ref()) {
                    env.insert(alias, Value::Api(name.text().into_owned()));
                }
            } else if child.kind() == "identifier"
                && child.parent().is_some_and(|p| {
                    matches!(p.kind().as_ref(), "import_clause" | "namespace_import")
                })
            {
                let alias = child.text().into_owned();
                env.remove(&alias);
                if filesystem {
                    env.insert(alias, Value::Fs);
                }
            }
        }
    }
    if matches!(
        kind.as_ref(),
        "assignment" | "assignment_expression" | "variable_declarator"
    ) {
        let left = node.field("left").or_else(|| node.field("name"));
        let right = node.field("right").or_else(|| node.field("value"));
        if let (Some(left), Some(right)) = (left, right) {
            let value = value(&right, language, env, 0);
            if matches!(left.kind().as_ref(), "identifier" | "constant") {
                let name = left.text().into_owned();
                env.remove(&name);
                if let Some(value) = value {
                    env.insert(name, value);
                }
            } else if left.kind() == "object_pattern" {
                for property in left.children().filter(Node::is_named) {
                    let source = property.field("key").unwrap_or_else(|| property.clone());
                    let destination = property.field("value").unwrap_or_else(|| property.clone());
                    let name = destination.text().into_owned();
                    env.remove(&name);
                    if value == Some(Value::Fs) && is_js_api(source.text().as_ref()) {
                        env.insert(name, Value::Api(source.text().into_owned()));
                    }
                }
            } else if let Some(mut object) = left.field("object").or_else(|| left.field("value")) {
                // Attribute/subscript assignment can replace a module member
                // or mutate an imported environment mapping. Do not retain a
                // proven runtime API after its root binding was modified.
                while let Some(parent) = object.field("object").or_else(|| object.field("value")) {
                    object = parent;
                }
                env.remove(object.text().as_ref());
            }
        }
    }
}

fn is_fs_module(module: &str) -> bool {
    matches!(
        module,
        "fs" | "node:fs" | "fs/promises" | "node:fs/promises"
    )
}

fn is_js_api(name: &str) -> bool {
    matches!(
        name,
        "writeFile"
            | "writeFileSync"
            | "appendFile"
            | "appendFileSync"
            | "createWriteStream"
            | "truncate"
            | "truncateSync"
    ) || transfers::js_operation(name).is_some()
}

fn value(node: &Syntax<'_>, language: Language, env: &Bindings, depth: usize) -> Option<Value> {
    if depth > 24 {
        return None;
    }
    if let Some(text) = literal(node, language) {
        return Some(Value::Text(text));
    }
    match node.kind().as_ref() {
        "identifier" | "constant" => env.get(node.text().as_ref()).cloned(),
        "parenthesized_expression" => value(
            &node.children().find(Node::is_named)?,
            language,
            env,
            depth + 1,
        ),
        "attribute" | "member_expression" => {
            let object = value(&node.field("object")?, language, env, depth + 1)?;
            let member = node
                .field("attribute")
                .or_else(|| node.field("property"))?
                .text()
                .into_owned();
            match (object, member.as_str()) {
                (Value::Io | Value::Builtins, "open") => Some(Value::Open),
                (Value::Builtins, "str") => Some(Value::StringifyPath),
                (Value::Os, "truncate") => Some(Value::OsTruncate),
                (Value::Os, "rename" | "replace") => {
                    Some(Value::Transfer(transfers::Operation::Rename))
                }
                (Value::Shutil, name) => transfers::shutil_operation(name).map(Value::Transfer),
                (Value::Os, "path") => Some(Value::OsPath),
                (Value::Os, "environ") => Some(Value::Environment),
                (Value::Os, "getenv") => Some(Value::GetEnv),
                (Value::Environment, "get") => Some(Value::EnvironmentGet),
                (Value::OsPath, "expanduser") => Some(Value::ExpandUser),
                (Value::OsPath, "join") => Some(Value::PythonJoin),
                (Value::Pathlib, "Path" | "PosixPath") => Some(Value::PathConstructor),
                (Value::PathConstructor | Value::Path(_), "home") => Some(Value::PathHome),
                (Value::Path(path), "joinpath") => Some(Value::PathJoin(path)),
                (Value::Path(path), "expanduser") => Some(Value::PathExpandUser(path)),
                (Value::Path(path), "write_text" | "write_bytes") => Some(Value::PathWrite(path)),
                (Value::Path(path), "open") => Some(Value::PathOpen(path)),
                (Value::Path(path), "rename" | "replace") => Some(Value::PathTransfer(path)),
                (Value::Fs, "promises") => Some(Value::Fs),
                (Value::Fs, name) if is_js_api(name) => Some(Value::Api(name.into())),
                _ => None,
            }
        }
        "subscript" if language == Language::Python => {
            if value(&node.field("value")?, language, env, depth + 1)? == Value::Environment
                && value(&node.field("subscript")?, language, env, depth + 1)?
                    == Value::Text("HOME".into())
            {
                Some(Value::HomePath("~".into()))
            } else {
                None
            }
        }
        "call" if language == Language::Ruby => {
            if value(&node.field("receiver")?, language, env, depth + 1)? != Value::File
                || node.field("method")?.text() != "expand_path"
            {
                return None;
            }
            match value(arguments(node).first()?, language, env, depth + 1)? {
                Value::Text(path) => Some(Value::HomePath(path)),
                _ => None,
            }
        }
        "call" | "call_expression" => {
            let function = node.field("function")?;
            let function = value(&function, language, env, depth + 1)?;
            let args = arguments(node);
            match function {
                Value::Require => {
                    let Value::Text(module) = value(args.first()?, language, env, depth + 1)?
                    else {
                        return None;
                    };
                    is_fs_module(&module).then_some(Value::Fs)
                }
                Value::PathHome if args.is_empty() => Some(Value::Path(("~".into(), true))),
                Value::PathConstructor => {
                    let base = if args.is_empty() { "." } else { "" };
                    python_join_paths(&args, env, depth, Some((base.into(), false)))
                        .map(Value::Path)
                }
                Value::PathJoin(base) => {
                    python_join_paths(&args, env, depth, Some(base)).map(Value::Path)
                }
                Value::PathExpandUser((path, _)) if args.is_empty() => {
                    Some(Value::Path((path, true)))
                }
                Value::PythonJoin if !args.is_empty() => {
                    python_join_paths(&args, env, depth, Some((String::new(), false)))
                        .map(path_as_text)
                }
                Value::StringifyPath if args.len() == 1 => {
                    resolved_path(value(&args[0], language, env, depth + 1)?).map(path_as_text)
                }
                Value::GetEnv | Value::EnvironmentGet if args.len() == 1 => {
                    let key = python_argument(&args, 0, "key")?;
                    (value(&key, language, env, depth + 1)? == Value::Text("HOME".into()))
                        .then(|| Value::HomePath("~".into()))
                }
                Value::ExpandUser => match value(args.first()?, language, env, depth + 1)? {
                    Value::Text(path) => Some(Value::HomePath(path)),
                    _ => None,
                },
                _ => None,
            }
        }
        "binary_operator" | "binary_expression" => {
            let left = value(&node.field("left")?, language, env, depth + 1)?;
            let right = value(&node.field("right")?, language, env, depth + 1)?;
            match node.field("operator")?.text().as_ref() {
                "/" if language == Language::Python
                    && (matches!(left, Value::Path(_)) || matches!(right, Value::Path(_))) =>
                {
                    python_join_path(resolved_path(left), resolved_path(right)?).map(Value::Path)
                }
                "+" => concatenate_text(left, right),
                _ => None,
            }
        }
        _ => None,
    }
}

fn text_value(node: &Syntax<'_>, language: Language, env: &Bindings) -> Option<String> {
    match value(node, language, env, 0)? {
        Value::Text(text) | Value::Path((text, false)) => Some(text),
        _ => None,
    }
}

/// Keep path expansion separate from mode/module strings.
fn path_value(node: &Syntax<'_>, language: Language, env: &Bindings) -> Option<ResolvedPath> {
    resolved_path(value(node, language, env, 0)?)
}

fn resolved_path(value: Value) -> Option<ResolvedPath> {
    match value {
        Value::Text(text) => Some((text, false)),
        Value::HomePath(text) => Some((text, true)),
        Value::Path(path) => Some(path),
        _ => None,
    }
}

fn path_as_text((path, home): ResolvedPath) -> Value {
    if home {
        Value::HomePath(path)
    } else {
        Value::Text(path)
    }
}

/// Python joins reset at an absolute operand, including a symbolic runtime
/// home. Never expand `~` merely because it occurs in a literal segment, and
/// never use this host's PathBuf semantics or current working directory.
fn python_join_path(base: Option<ResolvedPath>, next: ResolvedPath) -> Option<ResolvedPath> {
    let (next, home) = next;
    if next.starts_with('/') || (home && next.starts_with('~')) {
        return Some((next, home));
    }
    let (mut path, expanded) = base?;
    if path.is_empty() {
        return Some((next, home));
    }
    if path.len().checked_add(next.len())?.checked_add(1)? > MAX_STATIC_PATH_BYTES {
        return None;
    }
    if !path.ends_with('/') {
        path.push('/');
    }
    path.push_str(&next);
    Some((path, expanded))
}

fn python_join_paths(
    args: &[Syntax<'_>],
    env: &Bindings,
    depth: usize,
    mut path: Option<ResolvedPath>,
) -> Option<ResolvedPath> {
    for arg in args {
        path = value(arg, Language::Python, env, depth + 1)
            .and_then(resolved_path)
            .and_then(|next| python_join_path(path, next));
    }
    path
}

/// Concatenation is not path joining. A home on the right is not absolute
/// after a nonempty literal prefix, and Path objects do not support `+`.
fn concatenate_text(left: Value, right: Value) -> Option<Value> {
    let (mut text, home) = match left {
        Value::Text(text) => (text, false),
        Value::HomePath(text) => (text, true),
        _ => return None,
    };
    let suffix = match right {
        Value::Text(text) => text,
        Value::HomePath(path) if text.is_empty() => return Some(Value::HomePath(path)),
        _ => return None,
    };
    if text.len().checked_add(suffix.len())? > MAX_STATIC_PATH_BYTES {
        return None;
    }
    text.push_str(&suffix);
    Some(path_as_text((text, home)))
}

fn arguments<'a>(node: &Syntax<'a>) -> Vec<Syntax<'a>> {
    node.field("arguments").map_or_else(Vec::new, |args| {
        args.children()
            .filter(|child| child.is_named() && child.kind() != "comment")
            .collect()
    })
}

fn python_argument<'a>(args: &[Syntax<'a>], index: usize, name: &str) -> Option<Syntax<'a>> {
    args.iter()
        .find_map(|arg| {
            (arg.kind() == "keyword_argument"
                && arg.field("name").is_some_and(|n| n.text() == name))
            .then(|| arg.field("value"))
            .flatten()
        })
        .or_else(|| {
            args.iter()
                .filter(|arg| arg.kind() != "keyword_argument")
                .nth(index)
                .cloned()
        })
}

fn write_call(
    node: &Syntax<'_>,
    language: Language,
    env: &Bindings,
) -> Option<(String, String, Access, bool)> {
    if !matches!(node.kind().as_ref(), "call" | "call_expression") {
        return None;
    }
    let args = arguments(node);
    if language == Language::Ruby {
        if value(&node.field("receiver")?, language, env, 0)? != Value::File {
            return None;
        }
        let method = node.field("method")?.text().into_owned();
        if !matches!(
            method.as_str(),
            "write" | "binwrite" | "open" | "new" | "truncate"
        ) {
            return None;
        }
        let (path, expands) = path_value(args.first()?, language, env)?;
        if method == "truncate" {
            return Some(("File.truncate".into(), path, Access::Write, expands));
        }
        let opener = matches!(method.as_str(), "open" | "new");
        let mut mode = if opener {
            args.get(1)
                .filter(|n| !matches!(n.kind().as_ref(), "pair" | "hash"))
                .map(|n| text_value(n, language, env))
        } else {
            None
        };
        for arg in &args {
            for pair in arg.dfs().filter(|n| n.kind() == "pair") {
                let key = pair.field("key")?.text().into_owned();
                if key.trim_matches([':', '\'', '"']) == "mode" {
                    mode = Some(
                        pair.field("value")
                            .and_then(|n| text_value(&n, language, env)),
                    );
                }
            }
        }
        let access = match mode {
            Some(Some(mode)) => mode_access(&mode)?,
            Some(None) if opener => return None,
            Some(None) => Access::Write,
            None if opener => Access::Read,
            None => Access::Write,
        };
        return Some((format!("File.{method}"), path, access, expands));
    }
    let function = node.field("function")?;
    match value(&function, language, env, 0)? {
        Value::Open | Value::PathOpen(_) if language == Language::Python => {
            let resolved = value(&function, language, env, 0)?;
            let ((path, expands), index) = if let Value::PathOpen(path) = resolved {
                (path, 0)
            } else {
                (
                    path_value(&python_argument(&args, 0, "file")?, language, env)?,
                    1,
                )
            };
            let access = match python_argument(&args, index, "mode") {
                Some(mode) => mode_access(&text_value(&mode, language, env)?)?,
                None => Access::Read,
            };
            Some((function.text().into_owned(), path, access, expands))
        }
        Value::PathWrite((path, expands)) if language == Language::Python => {
            Some((function.text().into_owned(), path, Access::Write, expands))
        }
        Value::OsTruncate if language == Language::Python => {
            let (path, expands) = path_value(&python_argument(&args, 0, "path")?, language, env)?;
            Some((function.text().into_owned(), path, Access::Write, expands))
        }
        Value::Api(api)
            if language == Language::Node && transfers::js_operation(&api).is_none() =>
        {
            let (path, expands) = path_value(args.first()?, language, env)?;
            if matches!(api.as_str(), "truncate" | "truncateSync") {
                return Some((format!("fs.{api}"), path, Access::Write, expands));
            }
            let append = matches!(api.as_str(), "appendFile" | "appendFileSync");
            let default = if append {
                Access::Append
            } else {
                Access::Write
            };
            let stream = api == "createWriteStream";
            let options = args.get(if stream { 1 } else { 2 });
            let access = js_access(options, if stream { "flags" } else { "flag" }, default, env);
            Some((format!("fs.{api}"), path, access, expands))
        }
        _ => None,
    }
}

fn js_access(options: Option<&Syntax<'_>>, key: &str, default: Access, env: &Bindings) -> Access {
    let Some(options) = options else {
        return default;
    };
    if options.kind() != "object" {
        return if matches!(
            options.kind().as_ref(),
            "string" | "null" | "undefined" | "arrow_function" | "function_expression"
        ) {
            default
        } else {
            Access::Write
        };
    }
    let mut access = default;
    for property in options.children().filter(Node::is_named) {
        if property.kind() == "comment" {
            continue;
        }
        if property.kind() != "pair" {
            // Spreads, getters and shorthand can change the effective flags.
            access = Access::Write;
            continue;
        }
        let Some(name) = property.field("key") else {
            access = Access::Write;
            continue;
        };
        let name = literal(&name, Language::Node).unwrap_or_else(|| name.text().into_owned());
        if name == key {
            access = property
                .field("value")
                .and_then(|n| text_value(&n, Language::Node, env))
                .and_then(|mode| mode_access(&mode))
                .unwrap_or(Access::Write);
        } else if name.starts_with('[') {
            access = Access::Write;
        }
    }
    access
}

/// Decode only static language string nodes, never source substrings. Unknown
/// escapes/interpolation remain unknown instead of inventing a filesystem path.
fn literal(node: &Syntax<'_>, language: Language) -> Option<String> {
    if !matches!(
        node.kind().as_ref(),
        "string" | "raw_string" | "template_string" | "concatenated_string"
    ) {
        return None;
    }
    if node.kind() == "concatenated_string" {
        return node
            .children()
            .filter(Node::is_named)
            .map(|n| literal(&n, language))
            .collect::<Option<Vec<_>>>()
            .map(|parts| parts.concat());
    }
    if node
        .dfs()
        .any(|n| matches!(n.kind().as_ref(), "interpolation" | "template_substitution"))
    {
        return None;
    }
    let raw = node.text();
    let first = raw.find(['\'', '"', '`'])?;
    let prefix = &raw[..first];
    if !prefix.chars().all(|c| "rRbBuU".contains(c)) {
        return None;
    }
    let raw_mode = language == Language::Python && prefix.contains(['r', 'R']);
    let quote = raw.as_bytes()[first];
    let width = if language == Language::Python
        && raw
            .as_bytes()
            .get(first..first + 3)
            .is_some_and(|s| s == [quote; 3])
    {
        3
    } else {
        1
    };
    if raw.len() < first + 2 * width
        || !raw.as_bytes()[raw.len() - width..]
            .iter()
            .all(|b| *b == quote)
    {
        return None;
    }
    let body = &raw[first + width..raw.len() - width];
    if raw_mode {
        return Some(body.into());
    }
    let mut result = String::new();
    let mut chars = body.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            result.push(ch);
            continue;
        }
        let escaped = chars.next()?;
        if language == Language::Ruby && quote == b'\'' && !matches!(escaped, '\\' | '\'') {
            result.push('\\');
            result.push(escaped);
            continue;
        }
        match escaped {
            '\\' | '\'' | '"' | '`' | '/' => result.push(escaped),
            'n' => result.push('\n'),
            'r' => result.push('\r'),
            't' => result.push('\t'),
            'b' => result.push('\u{0008}'),
            'f' => result.push('\u{000c}'),
            '\n' => {}
            'x' | 'u' | 'U' => {
                let count = match escaped {
                    'x' => 2,
                    'u' => 4,
                    _ => 8,
                };
                let digits: String = chars.by_ref().take(count).collect();
                if digits.len() != count {
                    return None;
                }
                result.push(char::from_u32(u32::from_str_radix(&digits, 16).ok()?)?);
            }
            _ => return None,
        }
    }
    Some(result)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod here_string_tests {
    use super::*;

    #[test]
    fn source_exemptions_do_not_hide_a_different_program() {
        let command =
            "python3 0<<< \"open('.bashrc', 'w')\"; ruby 0<<< \"File.write('.git/config', 'x')\"";
        let hits = scan_command(command, ShellDialect::Posix, |_, language| {
            language == ScriptLanguage::Python
        });
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].rule, shell::GIT_INTERNALS_WRITE_NAME);
        assert!(command[hits[0].span.clone()].contains("File.write"));

        let command =
            "python3 <<< \"open('.bashrc', 'w')\"; python3 <<< \"open('.git/config', 'w')\"";
        let hits = scan_command(command, ShellDialect::Posix, |code, _| {
            code.contains(".bashrc")
        });
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].rule, shell::GIT_INTERNALS_WRITE_NAME);
    }

    #[test]
    fn command_scan_retains_independent_rules_with_coincident_spans() {
        for command in [
            "python3 -c \"import os; os.replace('.git/config', '.bashrc')\"",
            "python3 -c \"import os; os.replace('.bashrc', '.git/config')\"",
            "ruby 0<<< \"File.rename('.git/config', '.bashrc')\"",
            "node <<'JS'\nrequire('fs').renameSync('.git/config', '.bashrc')\nJS",
        ] {
            let hits = scan_command(command, ShellDialect::Posix, |_, _| false);
            assert_eq!(hits.len(), 2, "{command}: {hits:?}");
            assert_ne!(hits[0].rule, hits[1].rule, "{command}");
            assert_eq!(hits[0].span, hits[1].span, "{command}");
            assert!(command.get(hits[0].span.clone()).is_some());
        }
        let command =
            "python3 <<< \"open('.bashrc', 'w')\"; python3 <<< \"open('.git/config', 'w')\"";
        let hits = scan_command(command, ShellDialect::Posix, |_, _| false);
        assert_eq!(hits.len(), 2, "{hits:?}");
        assert!(hits[0].span.end < hits[1].span.start, "{hits:?}");
    }

    #[test]
    fn here_string_parser_preserves_descriptors_and_receiver_argv() {
        for descriptor in ["0", "00", "3"] {
            let command = format!("python3 {descriptor}<<< 'pass'");
            let ast = AstGrep::new(&command, SupportLang::Bash);
            let root = ast.root();
            assert!(!root.dfs().any(|node| node.kind() == "ERROR"), "{command}");
            let receiver = root.dfs().find(|node| node.kind() == "command").unwrap();
            assert_eq!(
                command_words(&receiver),
                Some(vec!["python3".to_string()]),
                "{command}"
            );
            let redirect = root
                .dfs()
                .find(|node| node.kind() == "herestring_redirect")
                .unwrap();
            assert_eq!(
                redirect
                    .field("descriptor")
                    .map(|node| node.text().into_owned()),
                Some(descriptor.to_string()),
                "{command}"
            );
        }
    }

    #[test]
    fn here_string_parser_preserves_mixed_redirection_order() {
        for command in [
            "python3 0<<< 'pass'",
            "python3 00<<< 'pass'",
            "python3 </dev/null <<< 'pass'",
            "python3 0</dev/null 0<<< 'pass'",
            "python3 <<< 'old' </dev/null 0<<< 'pass'",
            "python3 2>/dev/null 0<<< 'pass'",
        ] {
            let ast = AstGrep::new(command, SupportLang::Bash);
            let root = ast.root();
            assert!(!root.dfs().any(|node| node.kind() == "ERROR"), "{command}");
            let mut commands = root.dfs().filter(|node| node.kind() == "command");
            let receiver = commands.next().expect(command);
            assert!(commands.next().is_none(), "{command}");
            assert_eq!(
                command_words(&receiver),
                Some(vec!["python3".to_string()]),
                "{command}"
            );
            let (code, span) = here_string_source(&receiver).expect(command);
            assert_eq!(code, "pass", "{command}");
            assert_eq!(&command[span], "'pass'", "{command}");
        }
    }

    #[test]
    fn explicit_stdin_does_not_consume_real_arguments_or_other_descriptors() {
        for command in [
            "python3 0 <<< \"open('/etc/shadow', 'w')\"",
            "python3 '0'<<< \"open('/etc/shadow', 'w')\"",
            "python3 \\0<<< \"open('/etc/shadow', 'w')\"",
            "python3 3<<< \"open('/etc/shadow', 'w')\"",
            "python3 0<<< \"open('/etc/shadow', 'w')\" 0</dev/null",
            "python3 0<<< \"open('/etc/shadow', 'w')\" <&-",
            "python3 example.py </dev/null 0<<< \"open('/etc/shadow', 'w')\"",
        ] {
            assert!(
                classify(command, ShellDialect::Posix).is_none(),
                "{command}"
            );
        }
        // The scanner's special-parameter path must still accept $0.
        let ast = AstGrep::new("echo \"$0\" \"${0}\" \"$@\"", SupportLang::Bash);
        assert!(!ast.root().dfs().any(|node| node.kind() == "ERROR"));
    }

    #[test]
    fn explicit_stdin_obeys_last_redirection_without_borrowing_stdout() {
        for command in [
            "python3 </dev/null 0<<< \"open('/etc/shadow', 'w')\"",
            "python3 0</dev/null <<< \"open('/etc/shadow', 'w')\"",
            "python3 <<< 'pass' </dev/null 0<<< \"open('/etc/shadow', 'w')\"",
            "python3 0<<< \"open('/etc/shadow', 'w')\" 2>/dev/null",
            "python3 3<<< 'pass' 0<<< \"open('/etc/shadow', 'w')\"",
            "0<<< \"open('/etc/shadow', 'w')\" python3",
        ] {
            assert!(
                classify(command, ShellDialect::Posix).is_some(),
                "{command}"
            );
        }
    }

    #[test]
    fn here_strings_bind_to_the_actual_interpreter_argv() {
        for (exe, code) in [
            ("python3", "open('/etc/shadow', 'a').write('x')"),
            ("ruby", "File.write('/etc/shadow', 'x')"),
            ("node", "require('fs').writeFileSync('/etc/shadow', 'x')"),
        ] {
            for prefix in ["", "env ", "sudo ", "FOO=1 "] {
                for flag in ["", " -"] {
                    for word in [
                        format!("\"{code}\""),
                        format!("'{}'", code.replace('\'', "'\\''")),
                    ] {
                        for redirect in ["<<< ", "<<<", "0<<< ", "0<<<", "00<<< "] {
                            let command = format!("{prefix}{exe}{flag} {redirect}{word}");
                            let hit = classify(&command, ShellDialect::Posix).expect(&command);
                            assert_eq!(hit.rule, shell::CREDENTIAL_FILE_WRITE_NAME, "{command}");
                            assert!(command.get(hit.span).is_some(), "{command}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn here_strings_do_not_borrow_receivers_or_non_stdin_descriptors() {
        for command in [
            "python3 -V; cat <<< \"open('/etc/shadow', 'w')\"",
            "python3 example.py <<< \"open('/etc/shadow', 'w')\"",
            "python3 -c \"print('ok')\" <<< \"open('/etc/shadow', 'w')\"",
            "python3 3<<< \"open('/etc/shadow', 'w')\"",
            "python3 <<< \"open('/etc/shadow', 'w')\" </dev/null",
            "python3 <<< \"open('/etc/shadow', 'w')\" <<< \"print('ok')\"",
            "cat <<'DATA'\npython3 <<< \"open('/etc/shadow', 'w')\"\nDATA",
            "echo 'python3 <<< \"open(/etc/shadow, w)\"'",
        ] {
            assert!(
                classify(command, ShellDialect::Posix).is_none(),
                "{command}"
            );
        }
        let command = "python3 </dev/null <<< \"open('/etc/shadow', 'w')\"";
        assert!(
            classify(command, ShellDialect::Posix).is_some(),
            "{command}"
        );
    }

    #[test]
    fn here_strings_preserve_read_data_and_append_only_exceptions() {
        for code in [
            "open('/etc/shadow', 'r').read()",
            "open('/home/u/.ssh/known_hosts', 'a').write('host')",
            "open('/home/u/.ssh/id_rsa.pub', 'w')",
            "open('~/.bashrc', 'w')",
            "print(\"open('/etc/shadow', 'w')\")",
            "# open('/etc/shadow', 'w')\nprint('ok')",
        ] {
            let word = format!("'{}'", code.replace('\'', "'\\''"));
            let command = format!("python3 <<< {word}");
            assert!(
                classify(&command, ShellDialect::Posix).is_none(),
                "{command}"
            );
        }
        let command = "python3 <<< \"import os; os.truncate('/home/u/.ssh/known_hosts', 0)\"";
        assert!(
            classify(command, ShellDialect::Posix).is_some(),
            "{command}"
        );
    }

    #[test]
    fn here_strings_reach_public_evaluation_with_both_keyword_paths() {
        use crate::allowlist::LayeredAllowlist;
        use crate::config::{CompiledOverrides, Config};
        use crate::evaluator::evaluate_command_with_pack_order_at_path_in_dialect;
        use crate::packs::REGISTRY;
        use std::collections::HashSet;

        let enabled = HashSet::from(["core.filesystem".to_string()]);
        let ordered = REGISTRY.expand_enabled_ordered(&enabled);
        let keywords = REGISTRY.collect_enabled_keywords(&enabled);
        let index = REGISTRY
            .build_enabled_keyword_index(&ordered)
            .expect("keyword index");
        let overrides = CompiledOverrides::default();
        let allowlists = LayeredAllowlist::default();
        let mut heredoc = Config::default().heredoc_settings();
        for command in [
            "python3 <<< \"open('/etc/shadow', 'w')\"",
            "python3 0<<< \"open('/etc/shadow', 'w')\"",
            "python3 </dev/null <<< \"open('/etc/shadow', 'w')\"",
            "env ruby - <<< \"File.write('/home/u/.bashrc', 'x')\"",
            "env ruby - 0</dev/null 0<<< \"File.write('/home/u/.bashrc', 'x')\"",
            "node <<< \"require('fs').appendFileSync('/root/.ssh/authorized_keys', 'x')\"",
            "node 0<<< \"require('fs').appendFileSync('/root/.ssh/authorized_keys', 'x')\" 2>/dev/null",
        ] {
            for indexed in [false, true] {
                for dialect in [ShellDialect::Posix, ShellDialect::Unknown] {
                    for enabled in [false, true] {
                        heredoc.enabled = enabled;
                        let result = evaluate_command_with_pack_order_at_path_in_dialect(
                            command,
                            &keywords,
                            &ordered,
                            indexed.then_some(&index),
                            &overrides,
                            &allowlists,
                            &heredoc,
                            None,
                            dialect,
                        );
                        assert!(result.is_denied(), "{command}: {result:?}");
                        let info = result.pattern_info.expect("policy finding");
                        assert_eq!(info.pack_id.as_deref(), Some("core.filesystem"));
                        assert_eq!(info.pattern_name.as_deref(), Some("credential-file-write"));
                        let span = info.matched_span.expect("original-source span");
                        assert!(command.get(span.start..span.end).is_some());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod assignment_order_tests {
    use super::*;

    #[test]
    fn assigning_a_write_result_cannot_erase_the_invoked_api() {
        for (language, source) in [
            (ScriptLanguage::Python, "open = open('/etc/shadow', 'w')"),
            (
                ScriptLanguage::Python,
                "from io import open as save; save = save('/etc/shadow', 'w')",
            ),
            (
                ScriptLanguage::Python,
                "from pathlib import Path; p = Path('.bashrc'); p = p.write_text('x')",
            ),
            (
                ScriptLanguage::Python,
                "import shutil; shutil = shutil.copy2('staged', '.bashrc')",
            ),
            (
                ScriptLanguage::JavaScript,
                "let fs = require('fs'); fs = fs.writeFileSync('.bashrc', 'x')",
            ),
            (
                ScriptLanguage::JavaScript,
                "let save = require('fs').writeFileSync; save = save('.bashrc', 'x')",
            ),
            (
                ScriptLanguage::JavaScript,
                "let fs = require('fs'); ({fs} = fs.writeFileSync('.bashrc', 'x'))",
            ),
            (
                ScriptLanguage::TypeScript,
                "let fs: any = require('fs'); fs = fs.writeFileSync('.bashrc', 'x')",
            ),
            (
                ScriptLanguage::Ruby,
                "File = File.write('/etc/shadow', 'x')",
            ),
            (
                ScriptLanguage::Ruby,
                "writer = File; writer = writer.write('/etc/shadow', 'x')",
            ),
        ] {
            let hits = scan_extracted(source, language).expect("complete source analysis");
            assert_eq!(hits.len(), 1, "{source}: {hits:?}");
            assert_eq!(hits[0].rule, shell::CREDENTIAL_FILE_WRITE_NAME, "{source}");
            assert!(source.get(hits[0].span.clone()).is_some(), "{source}");
        }
    }

    #[test]
    fn assignment_results_still_invalidate_bindings_after_evaluation() {
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "open = open('/etc/shadow', 'r'); open('/etc/shadow', 'w')",
            ),
            (
                ScriptLanguage::Python,
                "import shutil; shutil = shutil.copy2('.bashrc', '/tmp/backup'); shutil.copy2('staged', '.bashrc')",
            ),
            (
                ScriptLanguage::JavaScript,
                "let fs = require('fs'); fs = fs.readFileSync('.bashrc'); fs.writeFileSync('.bashrc', 'x')",
            ),
            (
                ScriptLanguage::Ruby,
                "File = File.read('/etc/shadow'); File.write('/etc/shadow', 'x')",
            ),
        ] {
            assert!(
                scan_extracted(source, language)
                    .expect("complete analysis")
                    .is_empty(),
                "{source}"
            );
        }
        // A known alias remains usable after the assignment; only the result
        // of an unknown call is invalidated, not every right-hand-side value.
        let source = "import shutil; save = shutil; save.copy2('staged', '.bashrc')";
        assert_eq!(
            scan_extracted(source, ScriptLanguage::Python)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn assigned_transfers_keep_both_rule_families() {
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "import shutil; shutil = shutil.move('.bashrc', '.git')",
            ),
            (
                ScriptLanguage::JavaScript,
                "let fs = require('fs'); fs = fs.renameSync('.bashrc', '.git/config')",
            ),
            (
                ScriptLanguage::Ruby,
                "File = File.rename('.bashrc', '.git/config')",
            ),
        ] {
            let mut rules: Vec<_> = scan_extracted(source, language)
                .expect("complete source analysis")
                .into_iter()
                .map(|hit| hit.rule)
                .collect();
            rules.sort_unstable();
            assert_eq!(
                rules,
                [
                    shell::CREDENTIAL_FILE_WRITE_NAME,
                    shell::GIT_INTERNALS_WRITE_NAME
                ],
                "{source}"
            );
        }
    }
}

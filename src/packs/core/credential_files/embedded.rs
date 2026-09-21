//! Structural recognition of Python, Ruby, and Node file-write APIs (#461).
//!
//! Shell callers first establish that the source belongs to an interpreter.
//! The evaluator also calls `scan_extracted` directly on executable source:
//! its shell-segment view has already masked interpreter bodies. No script is
//! executed and no destination is read or opened.

use super::{CredentialFileWrite, shell};
use crate::heredoc::{ExtractionLimits, ExtractionResult, HeredocType, ScriptLanguage, extract_content};
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
        "replace",
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

pub(super) fn classify(segment: &str, dialect: ShellDialect) -> Option<CredentialFileWrite> {
    if !matches!(dialect, ShellDialect::Posix | ShellDialect::Unknown)
        || segment.len() > MAX_BYTES
        || !source_has_sink_name(segment)
    {
        return None;
    }
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
            if let Some(hit) = inspect(&code, language, command.range()) {
                return Some(hit);
            }
        }
        if reads_stdin(&words, language) {
            if let Some((code, span)) = here_string_source(&command) {
                if let Some(hit) = inspect(&code, language, span) {
                    return Some(hit);
                }
            }
        }
    }

    // Extraction alone may infer a language from data. Accept heredocs only
    // when their actual shell receiver is a supported stdin interpreter, and
    // verify that receiver against executable command nodes in the shell AST.
    if segment.contains("<<") {
        let items = match extract_content(segment, &ExtractionLimits::default()) {
            ExtractionResult::Extracted(items)
            | ExtractionResult::Partial {
                extracted: items, ..
            } => items,
            _ => return None,
        };
        for item in items {
            // Here-strings were inspected on their owning command above. A
            // regex extraction cannot prove which descriptor consumes them.
            if item.heredoc_type.is_none()
                || item.heredoc_type == Some(HeredocType::HereString)
            {
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
                if let Some(hit) = inspect(&item.content, language, span) {
                    return Some(hit);
                }
            }
        }
    }
    None
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
    let mut redirects: Vec<_> = command.field_children("redirect").collect();
    if let Some(parent) = command.parent() {
        if parent.kind() == "redirected_statement"
            && parent
                .field("body")
                .is_some_and(|body| body.range() == command.range())
        {
            redirects.extend(parent.field_children("redirect"));
        }
    }
    let redirect = redirects
        .into_iter()
        .filter(|redirect| {
            if let Some(descriptor) = redirect.field("descriptor") {
                return descriptor.text().parse::<u32>() == Ok(0);
            }
            match redirect.kind().as_ref() {
                "herestring_redirect" | "heredoc_redirect" => true,
                "file_redirect" => redirect.children().any(|child| {
                    matches!(child.text().as_ref(), "<" | "<&" | "<&-" | "<>")
                }),
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
    Open,
    Io,
    Builtins,
    Os,
    OsPath,
    OsTruncate,
    Shutil,
    Transfer(transfers::Operation),
    ExpandUser,
    /// Only a proven runtime expander grants a leading tilde home semantics.
    HomePath(String),
    Pathlib,
    PathConstructor,
    Path(String),
    PathWrite(String),
    PathOpen(String),
    PathTransfer(String),
    Require,
    Fs,
    File,
    Api(String),
}

type Bindings = HashMap<String, Value>;

fn inspect(code: &str, language: Language, span: Range<usize>) -> Option<CredentialFileWrite> {
    let grammar = match language {
        Language::Python => SupportLang::Python,
        Language::Ruby => SupportLang::Ruby,
        Language::Node => SupportLang::JavaScript,
    };
    let mut hit = scan_source(code, language, grammar)
        .ok()?
        .into_iter()
        .next()?;
    hit.span = span;
    Some(hit)
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
    bind(&node, language, env);
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
    Ok(())
}

/// A canonical, SINGLE-QUOTED sink is a policy adapter, never executed.
/// Quote every byte so embedded string contents cannot become shell syntax,
/// expansions, glob patterns, or extra targets. This deliberately does not
/// expand literal '~' or '$HOME' in an ordinary language string literal.
/// Only `os.path.expanduser` and `File.expand_path` may leave a leading
/// `~`/`~user` unquoted. All other characters retain literal semantics.
fn protected(path: &str, access: Access, expands_home: bool) -> Option<&'static str> {
    if access == Access::Read {
        return None;
    }
    let quote = |text: &str| format!("'{}'", text.replace('\'', "'\\''"));
    let anchor = expands_home
        .then(|| path.split_once('/').unwrap_or((path, "")))
        .filter(|(anchor, _)| {
            anchor.starts_with('~')
                && anchor[1..]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        });
    let quoted = match anchor {
        Some((anchor, "")) => anchor.to_string(),
        Some((anchor, rest)) => format!("{anchor}/{}", quote(rest)),
        None => quote(path),
    };
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
                (Some("pathlib"), "Path") => Some(Value::PathConstructor),
                (Some("os"), "truncate") => Some(Value::OsTruncate),
                (Some("os"), "rename" | "replace") => {
                    Some(Value::Transfer(transfers::Operation::Rename))
                }
                (Some("shutil"), "copyfile") => {
                    Some(Value::Transfer(transfers::Operation::CopyFile))
                }
                (Some("os"), "path") => Some(Value::OsPath),
                (Some("os.path"), "expanduser") => Some(Value::ExpandUser),
                _ => None,
            };
            // `import os.path` binds `os`, not `os.path`.
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
            } else if let Some(object) = left.field("object") {
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
                (Value::Os, "truncate") => Some(Value::OsTruncate),
                (Value::Os, "rename" | "replace") => {
                    Some(Value::Transfer(transfers::Operation::Rename))
                }
                (Value::Shutil, "copyfile") => {
                    Some(Value::Transfer(transfers::Operation::CopyFile))
                }
                (Value::Os, "path") => Some(Value::OsPath),
                (Value::OsPath, "expanduser") => Some(Value::ExpandUser),
                (Value::Pathlib, "Path") => Some(Value::PathConstructor),
                (Value::Path(path), "write_text" | "write_bytes") => Some(Value::PathWrite(path)),
                (Value::Path(path), "open") => Some(Value::PathOpen(path)),
                (Value::Path(path), "rename" | "replace") => Some(Value::PathTransfer(path)),
                (Value::Fs, "promises") => Some(Value::Fs),
                (Value::Fs, name) if is_js_api(name) => Some(Value::Api(name.into())),
                _ => None,
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
                Value::PathConstructor => match value(args.first()?, language, env, depth + 1)? {
                    Value::Text(path) | Value::Path(path) => Some(Value::Path(path)),
                    _ => None,
                },
                Value::ExpandUser => match value(args.first()?, language, env, depth + 1)? {
                    Value::Text(path) => Some(Value::HomePath(path)),
                    _ => None,
                },
                _ => None,
            }
        }
        "binary_operator" | "binary_expression" => {
            if node.field("operator")?.text() != "+" {
                return None;
            }
            let Value::Text(left) = value(&node.field("left")?, language, env, depth + 1)? else {
                return None;
            };
            let Value::Text(right) = value(&node.field("right")?, language, env, depth + 1)? else {
                return None;
            };
            Some(Value::Text(left + &right))
        }
        _ => None,
    }
}

fn text_value(node: &Syntax<'_>, language: Language, env: &Bindings) -> Option<String> {
    match value(node, language, env, 0)? {
        Value::Text(text) | Value::Path(text) => Some(text),
        _ => None,
    }
}

/// Keep path expansion separate from mode/module strings.
fn path_value(node: &Syntax<'_>, language: Language, env: &Bindings) -> Option<(String, bool)> {
    match value(node, language, env, 0)? {
        Value::Text(text) | Value::Path(text) => Some((text, false)),
        Value::HomePath(text) => Some((text, true)),
        _ => None,
    }
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
                ((path, false), 0)
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
        Value::PathWrite(path) if language == Language::Python => {
            Some((function.text().into_owned(), path, Access::Write, false))
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
    fn here_strings_bind_to_the_actual_interpreter_argv() {
        for (exe, code) in [
            ("python3", "open('/etc/shadow', 'a').write('x')"),
            ("ruby", "File.write('/etc/shadow', 'x')"),
            ("node", "require('fs').writeFileSync('/etc/shadow', 'x')"),
        ] {
            for prefix in ["", "env ", "sudo ", "FOO=1 "] {
                for flag in ["", " -"] {
                    for word in [format!("\"{code}\""), format!("'{}'", code.replace('\'', "'\\''"))] {
                        for redirect in ["<<< ", "<<<", "0<<< "] {
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
            assert!(classify(command, ShellDialect::Posix).is_none(), "{command}");
        }
        let command = "python3 </dev/null <<< \"open('/etc/shadow', 'w')\"";
        assert!(classify(command, ShellDialect::Posix).is_some(), "{command}");
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
            assert!(classify(&command, ShellDialect::Posix).is_none(), "{command}");
        }
        let command = "python3 <<< \"import os; os.truncate('/home/u/.ssh/known_hosts', 0)\"";
        assert!(classify(command, ShellDialect::Posix).is_some(), "{command}");
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
        let index = REGISTRY.build_enabled_keyword_index(&ordered).expect("keyword index");
        let overrides = CompiledOverrides::default();
        let allowlists = LayeredAllowlist::default();
        let mut heredoc = Config::default().heredoc_settings();
        for command in [
            "python3 <<< \"open('/etc/shadow', 'w')\"",
            "env ruby - <<< \"File.write('/home/u/.bashrc', 'x')\"",
            "node <<< \"require('fs').appendFileSync('/root/.ssh/authorized_keys', 'x')\"",
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
